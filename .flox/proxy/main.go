package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultPort             = "443"
	maxConnectHeaderBytes   = 16 << 10
	maxTLSClientHelloBytes  = 64 << 10
	defaultConnectDeadline  = 10 * time.Second
	defaultAcceptBackoffMin = 5 * time.Millisecond
	defaultAcceptBackoffMax = 1 * time.Second
	defaultTLSSniffTimeout  = 1500 * time.Millisecond
	tcpKeepAlivePeriod      = 30 * time.Second
)

type tlsSNIPolicy string

const (
	tlsSNIPolicyOff            tlsSNIPolicy = "off"
	tlsSNIPolicyMatchIfPresent tlsSNIPolicy = "match-if-present"
	tlsSNIPolicyRequire        tlsSNIPolicy = "require"
)

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

type allowlist struct {
	exact map[string]struct{}
	wild  []string
}

var resolveAndDialFunc = resolveAndDial

func newAllowlist(specs []string) (*allowlist, error) {
	a := &allowlist{exact: make(map[string]struct{})}
	for _, raw := range specs {
		host, port, wildcard, err := parseAllowSpec(raw)
		if err != nil {
			return nil, err
		}
		key := host + ":" + port
		if wildcard {
			a.wild = append(a.wild, "."+host+":"+port)
			continue
		}
		a.exact[key] = struct{}{}
	}
	sort.Strings(a.wild)
	return a, nil
}

func parseAllowSpec(spec string) (host, port string, wildcard bool, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", false, fmt.Errorf("empty --allow-host")
	}
	host, port, err = splitAuthority(spec, defaultPort)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid --allow-host %q: %w", spec, err)
	}
	if strings.Contains(host, "*") {
		if !strings.HasPrefix(host, "*.") || strings.Count(host, "*") != 1 {
			return "", "", false, fmt.Errorf("--allow-host %q: wildcard must be leftmost label (for example *.example.com)", spec)
		}
		wildcard = true
		host = host[2:]
	}
	host, err = normalizeHostname(host)
	if err != nil {
		return "", "", false, fmt.Errorf("--allow-host %q: %w", spec, err)
	}
	if net.ParseIP(host) != nil {
		return "", "", false, fmt.Errorf("--allow-host %q: IP literals not supported; use hostnames only", spec)
	}
	if err := validatePort(port); err != nil {
		return "", "", false, fmt.Errorf("--allow-host %q: %w", spec, err)
	}
	return host, port, wildcard, nil
}

func (a *allowlist) allows(host, port string) bool {
	key := host + ":" + port
	if _, ok := a.exact[key]; ok {
		return true
	}
	for _, w := range a.wild {
		if strings.HasSuffix(key, w) && len(key) > len(w) {
			return true
		}
	}
	return false
}

func (a *allowlist) summary() string {
	parts := make([]string, 0, len(a.exact)+len(a.wild))
	for k := range a.exact {
		parts = append(parts, k)
	}
	for _, w := range a.wild {
		parts = append(parts, "*"+w)
	}
	sort.Strings(parts)
	return "[" + strings.Join(parts, ",") + "]"
}

type eventLogger struct{ lg *log.Logger }

func (e *eventLogger) eventf(format string, args ...any) {
	ts := time.Now().UTC().Format(time.RFC3339)
	e.lg.Printf("ts=%s "+format, append([]any{ts}, args...)...)
}

// rotatingWriter is a size-capped append writer. When the next Write
// would push the underlying file past maxSize, it closes the current
// file, renames it to "<path>.1" (clobbering any prior .1), opens a
// fresh file, and then writes. Best-effort: rename and close errors
// on the rotation path are swallowed, because log rotation must never
// lose the in-flight log line on an unrelated FS hiccup. maxSize <= 0
// disables rotation entirely.
type rotatingWriter struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	f       *os.File
	size    int64
}

func newRotatingWriter(path string, maxSize int64) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &rotatingWriter{path: path, maxSize: maxSize, f: f, size: info.Size()}, nil
}

func (r *rotatingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxSize > 0 && r.size+int64(len(p)) > r.maxSize {
		// Multiple sbx-proxy processes can share one log file (each
		// sbx-agent invocation auto-starts its own proxy, and they
		// all default to $FLOX_ENV_CACHE/sbx-proxy.log). If a sibling
		// proxy already rotated, our r.f is still bound to the old
		// inode — now living at r.path+".1" — while r.path itself
		// points at the sibling's fresh file. Renaming r.path in
		// that state would clobber the sibling's .log.1 and destroy
		// an entire rotation cycle of history.
		//
		// Guard: compare the inode our fd is bound to against the
		// inode currently at r.path, and only rename when we are
		// still the canonical writer of the current .log. Otherwise
		// skip the rename, reopen the path to rejoin whatever the
		// fresh file is, and reset our byte counter.
		ourInfo, _ := r.f.Stat()
		pathInfo, perr := os.Stat(r.path)
		_ = r.f.Close()
		if perr == nil && ourInfo != nil && os.SameFile(ourInfo, pathInfo) {
			_ = os.Rename(r.path, r.path+".1")
		}
		nf, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		r.f = nf
		r.size = 0
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingWriter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

func newConnTracker() *connTracker { return &connTracker{conns: make(map[net.Conn]struct{})} }

func (t *connTracker) add(conn net.Conn) {
	t.mu.Lock()
	t.conns[conn] = struct{}{}
	t.wg.Add(1)
	t.mu.Unlock()
}

func (t *connTracker) done(conn net.Conn) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
	t.wg.Done()
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	conns := make([]net.Conn, 0, len(t.conns))
	for c := range t.conns {
		conns = append(conns, c)
	}
	t.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (t *connTracker) wait() { t.wg.Wait() }

type idleReader struct {
	r    io.Reader
	conn net.Conn
	idle time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	if r.idle > 0 {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.idle))
	}
	return r.r.Read(p)
}

type idleWriter struct {
	w    io.Writer
	conn net.Conn
	idle time.Duration
}

func (w *idleWriter) Write(p []byte) (int, error) {
	if w.idle > 0 {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.idle))
	}
	return w.w.Write(p)
}

type copyResult struct {
	direction string
	bytes     int64
	err       error
}

type closeWriter interface{ CloseWrite() error }

func handle(conn net.Conn, a *allowlist, dialTO, tunnelIdleTO, tunnelMaxLifetime, tlsSniffTimeout time.Duration, sniPolicy tlsSNIPolicy, lg *eventLogger) {
	defer conn.Close()
	setTCPOptions(conn)
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(defaultConnectDeadline))
	reader := bufio.NewReaderSize(conn, maxTLSClientHelloBytes)
	method, authority, err := readConnectRequest(reader, maxConnectHeaderBytes)
	if err != nil {
		writeStatus(conn, 400, "Bad Request")
		lg.eventf("event=reject reason=parse_err err=%q", err.Error())
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if method != "CONNECT" {
		writeStatus(conn, 405, "Method Not Allowed")
		lg.eventf("event=reject reason=bad_method method=%q target=%q", method, authority)
		return
	}
	host, port, err := normalizeTargetAuthority(authority)
	if err != nil {
		writeStatus(conn, 400, "Bad Request")
		lg.eventf("event=reject reason=bad_target target=%q err=%q", authority, err.Error())
		return
	}
	if !a.allows(host, port) {
		writeStatus(conn, 403, "Forbidden")
		lg.eventf("event=deny target=%q reason=not_in_allowlist", host+":"+port)
		return
	}

	var upstream net.Conn
	var remote string
	dialUpstream := func() error {
		if upstream != nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTO)
		defer cancel()
		c, resolvedRemote, err := resolveAndDialFunc(ctx, host, port, dialTO)
		if err != nil {
			return err
		}
		upstream = c
		remote = resolvedRemote
		setTCPOptions(upstream)
		return nil
	}
	defer func() {
		if upstream != nil {
			_ = upstream.Close()
		}
	}()

	if sniPolicy == tlsSNIPolicyOff {
		if err := dialUpstream(); err != nil {
			writeStatus(conn, 502, "Bad Gateway")
			lg.eventf("event=error target=%q reason=dial_failed err=%q", host+":"+port, err.Error())
			return
		}
		if err := writeConnectEstablished(conn); err != nil {
			lg.eventf("event=error target=%q reason=write_200 err=%q", host+":"+port, err.Error())
			return
		}
	} else {
		if err := writeConnectEstablished(conn); err != nil {
			lg.eventf("event=error target=%q reason=write_200 err=%q", host+":"+port, err.Error())
			return
		}
		sni, sawTLS, err := sniffClientHelloSNI(conn, reader, tlsSniffTimeout)
		if err != nil {
			lg.eventf("event=deny target=%q reason=tls_sni_parse err=%q", host+":"+port, err.Error())
			return
		}
		if sawTLS {
			if sni == "" {
				if sniPolicy == tlsSNIPolicyRequire {
					lg.eventf("event=deny target=%q reason=tls_sni_missing", host+":"+port)
					return
				}
			} else if sni != host {
				lg.eventf("event=deny target=%q reason=tls_sni_mismatch got_sni=%q", host+":"+port, sni)
				return
			}
		} else if sniPolicy == tlsSNIPolicyRequire {
			lg.eventf("event=deny target=%q reason=tls_client_hello_missing", host+":"+port)
			return
		}
		if err := dialUpstream(); err != nil {
			lg.eventf("event=error target=%q reason=dial_failed_after_client_ok err=%q", host+":"+port, err.Error())
			return
		}
	}

	var lifetimeTimer *time.Timer
	if tunnelMaxLifetime > 0 {
		lifetimeTimer = time.AfterFunc(tunnelMaxLifetime, func() {
			lg.eventf("event=close target=%q reason=max_lifetime remote_ip=%q", host+":"+port, remote)
			_ = conn.Close()
			_ = upstream.Close()
		})
		defer lifetimeTimer.Stop()
	}
	results := make(chan copyResult, 2)
	go copyHalf(results, "client_to_upstream", upstream, conn, &idleReader{r: reader, conn: conn, idle: tunnelIdleTO}, &idleWriter{w: upstream, conn: upstream, idle: tunnelIdleTO})
	go copyHalf(results, "upstream_to_client", conn, upstream, &idleReader{r: upstream, conn: upstream, idle: tunnelIdleTO}, &idleWriter{w: conn, conn: conn, idle: tunnelIdleTO})
	var up, down copyResult
	for i := 0; i < 2; i++ {
		res := <-results
		if res.direction == "client_to_upstream" {
			up = res
		} else {
			down = res
		}
	}
	lg.eventf("event=allow target=%q remote_ip=%q duration_ms=%d bytes_up=%d bytes_down=%d client_to_upstream=%q upstream_to_client=%q", host+":"+port, remote, time.Since(start).Milliseconds(), up.bytes, down.bytes, classifyIOError(up.err), classifyIOError(down.err))
}

func copyHalf(results chan<- copyResult, direction string, dst net.Conn, src net.Conn, r io.Reader, w io.Writer) {
	n, err := io.Copy(w, r)
	_ = src.SetReadDeadline(time.Time{})
	_ = dst.SetWriteDeadline(time.Time{})
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	results <- copyResult{direction: direction, bytes: n, err: err}
}

func classifyIOError(err error) string {
	if err == nil || errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return "timeout"
		}
		return opErr.Op + ":" + opErr.Err.Error()
	}
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		return syscallErr.Syscall + ":" + syscallErr.Err.Error()
	}
	return err.Error()
}

func readConnectRequest(r *bufio.Reader, maxBytes int64) (method, authority string, err error) {
	var total int64
	line, err := readLineLimited(r, &total, maxBytes)
	if err != nil {
		return "", "", err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return "", "", fmt.Errorf("malformed request line")
	}
	method, authority, version := parts[0], parts[1], parts[2]
	if version != "HTTP/1.1" && version != "HTTP/1.0" {
		return "", "", fmt.Errorf("unsupported HTTP version %q", version)
	}
	for {
		h, err := readLineLimited(r, &total, maxBytes)
		if err != nil {
			return "", "", err
		}
		if h == "" {
			break
		}
	}
	return method, authority, nil
}

func readLineLimited(r *bufio.Reader, total *int64, maxBytes int64) (string, error) {
	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		*total += int64(len(fragment))
		if *total > maxBytes {
			return "", fmt.Errorf("header too large")
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			if int64(len(line)) >= maxBytes {
				return "", fmt.Errorf("header too large")
			}
			continue
		}
		if err != nil {
			return "", err
		}
		break
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	return string(line), nil
}

func sniffClientHelloSNI(conn net.Conn, r *bufio.Reader, timeout time.Duration) (string, bool, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	want := 1
	for want <= maxTLSClientHelloBytes {
		peek, err := r.Peek(want)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && len(peek) == 0 {
				return "", false, nil
			}
			if !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
				return "", false, err
			}
		}
		sni, sawTLS, nextWant, parseErr := parseClientHelloSNI(peek)
		if parseErr != nil {
			return "", sawTLS, parseErr
		}
		if nextWant == 0 || nextWant <= len(peek) {
			return sni, sawTLS, nil
		}
		if nextWant > maxTLSClientHelloBytes {
			return "", sawTLS, fmt.Errorf("tls client hello exceeds %d bytes", maxTLSClientHelloBytes)
		}
		want = nextWant
	}
	return "", false, fmt.Errorf("tls client hello exceeds %d bytes", maxTLSClientHelloBytes)
}

func parseClientHelloSNI(data []byte) (sni string, sawTLS bool, needMore int, err error) {
	if len(data) == 0 {
		return "", false, 1, nil
	}
	if data[0] != 0x16 {
		return "", false, 0, nil
	}
	sawTLS = true

	payload := make([]byte, 0, len(data))
	expectedHandshakeLen := -1
	consumed := 0
	for {
		if len(data)-consumed < 5 {
			return "", true, consumed + 5, nil
		}
		if data[consumed] != 0x16 {
			return "", true, 0, fmt.Errorf("expected TLS handshake record, got content type %d", data[consumed])
		}
		recordLen := int(data[consumed+3])<<8 | int(data[consumed+4])
		recordEnd := consumed + 5 + recordLen
		if len(data) < recordEnd {
			return "", true, recordEnd, nil
		}
		payload = append(payload, data[consumed+5:recordEnd]...)
		if len(payload) >= 4 && expectedHandshakeLen < 0 {
			if payload[0] != 0x01 {
				return "", true, 0, fmt.Errorf("expected TLS ClientHello, got handshake type %d", payload[0])
			}
			expectedHandshakeLen = 4 + int(payload[1])<<16 + int(payload[2])<<8 + int(payload[3])
			if expectedHandshakeLen > maxTLSClientHelloBytes {
				return "", true, 0, fmt.Errorf("tls client hello exceeds %d bytes", maxTLSClientHelloBytes)
			}
		}
		if expectedHandshakeLen >= 0 && len(payload) >= expectedHandshakeLen {
			parsedSNI, err := parseClientHelloSNIFromHandshake(payload[:expectedHandshakeLen])
			if err != nil {
				return "", true, 0, err
			}
			return parsedSNI, true, 0, nil
		}
		consumed = recordEnd
		if consumed == len(data) {
			return "", true, consumed + 5, nil
		}
	}
}

func parseClientHelloSNIFromHandshake(handshake []byte) (string, error) {
	if len(handshake) < 4 {
		return "", fmt.Errorf("short TLS ClientHello")
	}
	body := handshake[4:]
	pos := 0
	need := func(n int) error {
		if len(body)-pos < n {
			return fmt.Errorf("short TLS ClientHello")
		}
		return nil
	}
	if err := need(35); err != nil {
		return "", err
	}
	pos += 2
	pos += 32
	sessLen := int(body[pos])
	pos++
	if err := need(sessLen + 2); err != nil {
		return "", err
	}
	pos += sessLen
	cipherLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if cipherLen == 0 || cipherLen%2 != 0 {
		return "", fmt.Errorf("invalid cipher suite list")
	}
	if err := need(cipherLen + 1); err != nil {
		return "", err
	}
	pos += cipherLen
	compLen := int(body[pos])
	pos++
	if compLen == 0 {
		return "", fmt.Errorf("invalid compression methods")
	}
	if err := need(compLen); err != nil {
		return "", err
	}
	pos += compLen
	if len(body) == pos {
		return "", nil
	}
	if err := need(2); err != nil {
		return "", err
	}
	extLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if err := need(extLen); err != nil {
		return "", err
	}
	exts := body[pos : pos+extLen]
	for i := 0; i+4 <= len(exts); {
		extType := int(exts[i])<<8 | int(exts[i+1])
		extSize := int(exts[i+2])<<8 | int(exts[i+3])
		i += 4
		if i+extSize > len(exts) {
			return "", fmt.Errorf("invalid TLS extension block")
		}
		if extType == 0 {
			ext := exts[i : i+extSize]
			if len(ext) < 2 {
				return "", fmt.Errorf("invalid SNI extension")
			}
			listLen := int(ext[0])<<8 | int(ext[1])
			if listLen != len(ext)-2 {
				return "", fmt.Errorf("invalid SNI list length")
			}
			for j := 2; j+3 <= len(ext); {
				nameType := ext[j]
				nameLen := int(ext[j+1])<<8 | int(ext[j+2])
				j += 3
				if j+nameLen > len(ext) {
					return "", fmt.Errorf("invalid SNI name")
				}
				if nameType == 0 {
					host, err := normalizeHostname(string(ext[j : j+nameLen]))
					if err != nil {
						return "", fmt.Errorf("invalid SNI hostname: %w", err)
					}
					return host, nil
				}
				j += nameLen
			}
			return "", nil
		}
		i += extSize
	}
	return "", nil
}

func normalizeTargetAuthority(authority string) (host, port string, err error) {
	host, port, err = splitAuthority(authority, defaultPort)
	if err != nil {
		return "", "", err
	}
	host, err = normalizeHostname(host)
	if err != nil {
		return "", "", err
	}
	if net.ParseIP(host) != nil {
		return "", "", fmt.Errorf("IP literal targets are not allowed")
	}
	if strings.Contains(host, "*") {
		return "", "", fmt.Errorf("wildcards are not valid CONNECT targets")
	}
	if err := validatePort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}

func splitAuthority(authority, defaultPort string) (host, port string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", fmt.Errorf("empty authority")
	}
	if strings.ContainsAny(authority, "/\\@?# \t\r\n") {
		return "", "", fmt.Errorf("authority must be host[:port] only")
	}
	if strings.HasPrefix(authority, "[") {
		h, p, err := net.SplitHostPort(authority)
		if err != nil {
			return "", "", err
		}
		return h, p, nil
	}
	if strings.Count(authority, ":") == 0 {
		return authority, defaultPort, nil
	}
	if strings.Count(authority, ":") > 1 {
		return "", "", fmt.Errorf("multiple colons in authority")
	}
	h, p, err := net.SplitHostPort(authority)
	if err != nil {
		return "", "", err
	}
	return h, p, nil
}

func normalizeHostname(host string) (string, error) {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if len(host) > 253 {
		return "", fmt.Errorf("hostname too long")
	}
	if strings.ContainsAny(host, "/\\@?# \t\r\n") {
		return "", fmt.Errorf("invalid host characters")
	}
	if strings.Contains(host, "..") {
		return "", fmt.Errorf("invalid hostname")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("invalid hostname")
	}
	if !isValidDNSName(host) {
		return "", fmt.Errorf("invalid hostname")
	}
	return host, nil
}

func isValidDNSName(host string) bool {
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port %q", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port out of range %q", port)
	}
	return nil
}

func resolveAndDial(ctx context.Context, host, port string, dialTO time.Duration) (net.Conn, string, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, "", fmt.Errorf("resolve %q: no addresses returned", host)
	}
	dialer := &net.Dialer{Timeout: dialTO, KeepAlive: tcpKeepAlivePeriod}
	var errs []string
	for _, ip := range ips {
		ipStr := ip.String()
		ipBytes := net.IP(ip.AsSlice())
		if !isSafeRemoteIP(ipBytes) {
			errs = append(errs, ipStr+":blocked")
			continue
		}
		addr := net.JoinHostPort(ipStr, port)
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, ipStr, nil
		}
		errs = append(errs, ipStr+":"+err.Error())
	}
	if len(errs) == 0 {
		return nil, "", fmt.Errorf("no safe remote addresses for %q", host)
	}
	return nil, "", fmt.Errorf("no successful safe dial for %q (%s)", host, strings.Join(errs, "; "))
}

func isSafeRemoteIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if isInCIDRs(ip, blockedCIDRs()) {
		return false
	}
	return true
}

var (
	blockedCIDRsOnce sync.Once
	blockedCIDRsList []*net.IPNet
)

func blockedCIDRs() []*net.IPNet {
	blockedCIDRsOnce.Do(func() {
		for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"} {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil {
				blockedCIDRsList = append(blockedCIDRsList, n)
			}
		}
	})
	return blockedCIDRsList
}

func isInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func writeStatus(w io.Writer, code int, text string) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", code, text)
}

func writeConnectEstablished(w io.Writer) error {
	_, err := io.WriteString(w, "HTTP/1.1 200 Connection established\r\n\r\n")
	return err
}

func watchParent(pid int, lg *eventLogger, stop <-chan struct{}, shutdown func()) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if os.Getppid() != pid || !pidExists(pid) {
				lg.eventf("event=parent_exit ppid=%d current_ppid=%d", pid, os.Getppid())
				shutdown()
				return
			}
		}
	}
}

func pidExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func writePortFileAtomic(path string, port int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sbx-proxy-port-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := fmt.Fprintf(tmp, "%d\n", port); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func setTCPOptions(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	_ = tc.SetNoDelay(true)
}

func validateTLSSNIPolicy(v string) (tlsSNIPolicy, error) {
	switch tlsSNIPolicy(v) {
	case tlsSNIPolicyOff, tlsSNIPolicyMatchIfPresent, tlsSNIPolicyRequire:
		return tlsSNIPolicy(v), nil
	default:
		return "", fmt.Errorf("invalid --tls-sni-policy %q (valid: off, match-if-present, require)", v)
	}
}

// registerLogMaxSize wires --log-max-size onto fs with explicit
// base-10 parsing. Go's flag.Int64 uses strconv.ParseInt(s, 0, 64),
// which auto-detects 0-prefixed literals as octal: "010" → 8,
// "0x10" → 16, "0900" → error ("9" invalid in octal). This trap
// mirrors the bash parse_bytes octal trap on the agent side and
// would let users accidentally get far smaller rotation caps than
// they typed. Using flag.Func with strconv.ParseInt(s, 10, 64) is
// a one-function fix: leading zeros are silently ignored, decimal
// only, explicit errors on malformed input.
//
// Extracted as a helper so Go tests can exercise the exact same
// closure that main() registers, not a reconstructed one.
func registerLogMaxSize(fs *flag.FlagSet, dst *int64) {
	fs.Func("log-max-size", "rotate --log to <path>.1 when it would exceed this many bytes (0 disables; default 10485760 = 10 MiB; decimal only)", func(s string) error {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer: %w", err)
		}
		*dst = v
		return nil
	})
}

func main() {
	var allowHosts stringSlice
	listen := flag.String("listen", "127.0.0.1:0", "loopback listen address (host:port)")
	flag.Var(&allowHosts, "allow-host", "allowed host[:port], repeatable; wildcards like *.example.com supported")
	portFile := flag.String("port-file", "", "write bound port to this file (default: print to stdout)")
	logPath := flag.String("log", "", "append structured events to this file (default: stderr)")
	var logMaxSize int64 = 10 * 1024 * 1024
	registerLogMaxSize(flag.CommandLine, &logMaxSize)
	ppid := flag.Int("ppid", 0, "shut down when this parent PID is no longer alive (0=disabled)")
	dialTO := flag.Duration("dial-timeout", 10*time.Second, "upstream dial timeout")
	tunnelIdleTO := flag.Duration("tunnel-idle-timeout", 2*time.Minute, "per-direction idle timeout once a tunnel is established (0=disabled)")
	tunnelMaxLifetime := flag.Duration("tunnel-max-lifetime", 30*time.Minute, "maximum lifetime of an established tunnel (0=disabled)")
	maxConns := flag.Int("max-conns", 256, "maximum concurrent client connections")
	shutdownGrace := flag.Duration("shutdown-grace", 5*time.Second, "grace period before active tunnels are closed on shutdown")
	tlsSniffTimeout := flag.Duration("tls-sni-timeout", defaultTLSSniffTimeout, "how long to wait for an initial TLS ClientHello when SNI checks are enabled")
	tlsSNIPolicyRaw := flag.String("tls-sni-policy", string(tlsSNIPolicyRequire), "SNI policy for CONNECT tunnels: off, match-if-present, require")
	flag.Parse()
	if len(allowHosts) == 0 {
		fmt.Fprintln(os.Stderr, "sbx-proxy: at least one --allow-host is required")
		os.Exit(2)
	}
	if *maxConns <= 0 {
		fmt.Fprintln(os.Stderr, "sbx-proxy: --max-conns must be > 0")
		os.Exit(2)
	}
	if !isLoopbackListenAddr(*listen) {
		fmt.Fprintf(os.Stderr, "sbx-proxy: listen address %q must be loopback-only\n", *listen)
		os.Exit(2)
	}
	sniPolicy, err := validateTLSSNIPolicy(*tlsSNIPolicyRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbx-proxy: %v\n", err)
		os.Exit(2)
	}
	var logOut io.Writer = os.Stderr
	if *logPath != "" {
		rw, err := newRotatingWriter(*logPath, logMaxSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sbx-proxy: open log %q: %v\n", *logPath, err)
			os.Exit(1)
		}
		defer rw.Close()
		logOut = rw
	}
	lg := &eventLogger{lg: log.New(logOut, "", 0)}
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
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if *portFile != "" {
		if err := writePortFileAtomic(*portFile, port); err != nil {
			fmt.Fprintf(os.Stderr, "sbx-proxy: write port file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(port)
	}
	lg.eventf("event=start port=%d allowlist=%s max_conns=%d idle_timeout=%q max_lifetime=%q tls_sni_policy=%q tls_sni_timeout=%q log_max_size=%d", port, a.summary(), *maxConns, tunnelIdleTO.String(), tunnelMaxLifetime.String(), sniPolicy, tlsSniffTimeout.String(), logMaxSize)
	tracker := newConnTracker()
	sem := make(chan struct{}, *maxConns)
	stopParentWatch := make(chan struct{})
	defer close(stopParentWatch)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			lg.eventf("event=shutdown")
			_ = ln.Close()
			if *shutdownGrace <= 0 {
				tracker.closeAll()
				return
			}
			time.AfterFunc(*shutdownGrace, func() {
				lg.eventf("event=shutdown_force_close")
				tracker.closeAll()
			})
		})
	}
	if *ppid > 0 {
		go watchParent(*ppid, lg, stopParentWatch, shutdown)
	}
	go func() {
		sig := <-sigCh
		lg.eventf("event=shutdown signal=%q", sig.String())
		shutdown()
	}()
	acceptBackoff := defaultAcceptBackoffMin
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			lg.eventf("event=error reason=accept err=%q retry_in=%q", err.Error(), acceptBackoff.String())
			time.Sleep(acceptBackoff)
			acceptBackoff *= 2
			if acceptBackoff > defaultAcceptBackoffMax {
				acceptBackoff = defaultAcceptBackoffMax
			}
			continue
		}
		acceptBackoff = defaultAcceptBackoffMin
		setTCPOptions(conn)
		select {
		case sem <- struct{}{}:
			tracker.add(conn)
			go func(c net.Conn) {
				defer func() {
					tracker.done(c)
					<-sem
				}()
				handle(c, a, *dialTO, *tunnelIdleTO, *tunnelMaxLifetime, *tlsSniffTimeout, sniPolicy, lg)
			}(conn)
		default:
			writeStatus(conn, 503, "Service Unavailable")
			lg.eventf("event=deny reason=max_conns remote=%q", conn.RemoteAddr().String())
			_ = conn.Close()
		}
	}
	tracker.wait()
	lg.eventf("event=stop")
}
