// sbx-proxy is a local CONNECT-style HTTPS proxy that enforces a
// hostname allowlist. It is designed to be spawned as a child of
// sbx-agent, which wires HTTPS_PROXY in the sandboxed child's
// environment and constrains the sandbox policy to localhost:<port>.
//
// The proxy never inspects TLS. After accepting a CONNECT request
// against an allowed hostname, it opens a TCP connection to the
// upstream server and pipes bytes bidirectionally. TLS negotiates
// end-to-end between the sandboxed client and the real server; the
// proxy only sees ciphertext.
//
// Allowlist matching is exact by default. Wildcards must appear as
// the leftmost label (*.example.com matches any subdomain of
// example.com, but not example.com itself and not fakeexample.com).
// IP literals in the allowlist are rejected at startup — this is a
// hostname-level tool.
//
// Standard library only. No external dependencies.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// allowlist stores the parsed --allow-host entries.
//
// exact holds "host:port" entries for literal matching.
// wild holds ".rest:port" entries for suffix matching (the wildcard's
// leading asterisk has been stripped, keeping the separating dot).
type allowlist struct {
	exact map[string]bool
	wild  []string
}

func newAllowlist(specs []string) (*allowlist, error) {
	a := &allowlist{exact: make(map[string]bool)}
	for _, s := range specs {
		host, port := s, "443"
		if strings.Contains(s, ":") {
			h, p, err := net.SplitHostPort(s)
			if err != nil {
				return nil, fmt.Errorf("invalid --allow-host %q: %w", s, err)
			}
			host, port = h, p
		}
		if host == "" {
			return nil, fmt.Errorf("--allow-host %q: empty host", s)
		}
		if net.ParseIP(host) != nil {
			return nil, fmt.Errorf("--allow-host %q: IP literals not supported; use hostnames only", s)
		}
		if strings.Contains(host, "*") {
			if !strings.HasPrefix(host, "*.") {
				return nil, fmt.Errorf("--allow-host %q: wildcard must be leftmost label (e.g. *.example.com)", s)
			}
			a.wild = append(a.wild, host[1:]+":"+port)
		} else {
			a.exact[host+":"+port] = true
		}
	}
	return a, nil
}

// allows reports whether the given "host:port" target is permitted.
func (a *allowlist) allows(target string) bool {
	if a.exact[target] {
		return true
	}
	for _, w := range a.wild {
		// target must end with ".rest:port" AND have at least one
		// character before the leading dot, so the wildcard doesn't
		// trivially match its own suffix.
		if strings.HasSuffix(target, w) && len(target) > len(w) {
			return true
		}
	}
	return false
}

// summary returns a compact textual form of the allowlist for logging.
func (a *allowlist) summary() string {
	var parts []string
	for k := range a.exact {
		parts = append(parts, k)
	}
	for _, w := range a.wild {
		parts = append(parts, "*"+w)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// eventLogger wraps a log.Logger with a consistent ts= prefix so our
// output matches the flat kv style used by sbx-agent's audit log.
type eventLogger struct{ lg *log.Logger }

func (e *eventLogger) eventf(format string, args ...any) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	e.lg.Printf("ts=%s "+format, append([]any{ts}, args...)...)
}

// handle services a single client connection: parse CONNECT, consult
// the allowlist, dial the upstream, pipe bytes bidirectionally.
func handle(conn net.Conn, a *allowlist, dialTO time.Duration, lg *eventLogger) {
	defer conn.Close()
	start := time.Now()

	// Bounded deadline for the CONNECT line. After we have it, the
	// pipe phase runs without a timeout.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		lg.eventf("event=error reason=set_deadline err=%q", err.Error())
		return
	}

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		lg.eventf("event=reject reason=parse_err err=%q", err.Error())
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if req.Method != http.MethodConnect {
		fmt.Fprint(conn, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
		lg.eventf("event=reject reason=bad_method method=%q target=%q", req.Method, req.Host)
		return
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	if !a.allows(target) {
		fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
		lg.eventf("event=deny target=%q reason=not_in_allowlist", target)
		return
	}

	upstream, err := net.DialTimeout("tcp", target, dialTO)
	if err != nil {
		fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		lg.eventf("event=error target=%q reason=dial_failed err=%q", target, err.Error())
		return
	}
	defer upstream.Close()

	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		lg.eventf("event=error target=%q reason=write_200 err=%q", target, err.Error())
		return
	}

	// Byte pump. Use the bufio.Reader for the client->upstream
	// direction so any bytes already buffered past the CONNECT line
	// (rare but possible when the client pipelines) are forwarded.
	var bytesUp, bytesDown int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, reader)
		bytesUp = n
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, upstream)
		bytesDown = n
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()

	lg.eventf("event=allow target=%q duration_ms=%d bytes_up=%d bytes_down=%d",
		target, time.Since(start).Milliseconds(), bytesUp, bytesDown)
}

// watchParent polls the given PID every 500ms via signal(0) — a
// probe that checks process existence without actually signalling.
// On macOS we can't use PR_SET_PDEATHSIG, so polling is the portable
// way to self-terminate when our parent (sbx-agent's exec'd shell)
// goes away.
func watchParent(pid int, lg *eventLogger) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		if err := syscall.Kill(pid, 0); err != nil {
			lg.eventf("event=parent_exit ppid=%d err=%q", pid, err.Error())
			os.Exit(0)
		}
	}
}

func main() {
	var allowHosts stringSlice
	listen := flag.String("listen", "127.0.0.1:0", "listen address (host:port)")
	flag.Var(&allowHosts, "allow-host", "allowed host[:port], repeatable; wildcards like *.example.com supported")
	portFile := flag.String("port-file", "", "write bound port to this file (default: print to stdout)")
	logPath := flag.String("log", "", "append structured events to this file (default: stderr)")
	ppid := flag.Int("ppid", 0, "exit if this parent PID is no longer alive (0=disabled)")
	dialTO := flag.Duration("dial-timeout", 10*time.Second, "upstream dial timeout")
	flag.Parse()

	var logOut io.Writer = os.Stderr
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sbx-proxy: open log %q: %v\n", *logPath, err)
			os.Exit(1)
		}
		logOut = f
	}
	lg := &eventLogger{lg: log.New(logOut, "", 0)}

	if len(allowHosts) == 0 {
		fmt.Fprintln(os.Stderr, "sbx-proxy: at least one --allow-host is required")
		os.Exit(2)
	}
	a, err := newAllowlist(allowHosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbx-proxy: %v\n", err)
		os.Exit(2)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbx-proxy: listen %q: %v\n", *listen, err)
		os.Exit(1)
	}

	port := ln.Addr().(*net.TCPAddr).Port
	if *portFile != "" {
		if err := os.WriteFile(*portFile, []byte(fmt.Sprintf("%d\n", port)), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "sbx-proxy: write port file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(port)
	}

	lg.eventf("event=start port=%d allowlist=%s", port, a.summary())

	if *ppid > 0 {
		go watchParent(*ppid, lg)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		lg.eventf("event=shutdown signal=%q", sig.String())
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				lg.eventf("event=stop")
				return
			}
			lg.eventf("event=error reason=accept err=%q", err.Error())
			return
		}
		go handle(conn, a, *dialTO, lg)
	}
}
