package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAllowlistWildcard(t *testing.T) {
	a, err := newAllowlist([]string{"*.example.com:443", "api.example.net:8443"})
	if err != nil {
		t.Fatalf("newAllowlist: %v", err)
	}
	if !a.allows("foo.example.com", "443") {
		t.Fatalf("wildcard should allow subdomain")
	}
	if a.allows("example.com", "443") {
		t.Fatalf("wildcard must not allow bare domain")
	}
	if !a.allows("api.example.net", "8443") {
		t.Fatalf("exact host should be allowed")
	}
}

func TestNormalizeHostname(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "Example.COM.", want: "example.com"},
		{in: "bad..host", wantErr: true},
		{in: "-bad.example", wantErr: true},
		{in: "bad_host.example", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		got, err := normalizeHostname(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("normalizeHostname(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeHostname(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSafeRemoteIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{ip: "127.0.0.1", want: false},
		{ip: "10.1.2.3", want: false},
		{ip: "169.254.10.20", want: false},
		{ip: "64:ff9b::c0a8:0101", want: false},
		{ip: "8.8.8.8", want: true},
		{ip: "2606:4700:4700::1111", want: true},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := isSafeRemoteIP(ip); got != tc.want {
			t.Fatalf("isSafeRemoteIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestLoopbackListenAddr(t *testing.T) {
	good := []string{"127.0.0.1:0", "localhost:8080", "[::1]:443"}
	for _, addr := range good {
		if !isLoopbackListenAddr(addr) {
			t.Fatalf("expected loopback addr %q to pass", addr)
		}
	}
	bad := []string{":0", "0.0.0.0:8080", "[::]:8080", "192.168.1.2:9000"}
	for _, addr := range bad {
		if isLoopbackListenAddr(addr) {
			t.Fatalf("expected non-loopback addr %q to fail", addr)
		}
	}
}

func TestReadConnectRequestRejectsOversizedLine(t *testing.T) {
	payload := "CONNECT " + strings.Repeat("a", int(maxConnectHeaderBytes)) + ":443 HTTP/1.1\r\n\r\n"
	r := bufio.NewReaderSize(bytes.NewBufferString(payload), 64)
	_, _, err := readConnectRequest(r, maxConnectHeaderBytes)
	if err == nil || err.Error() != "header too large" {
		t.Fatalf("expected header too large, got %v", err)
	}
}

func TestParseClientHelloSNI(t *testing.T) {
	hello := mustTLSClientHelloForTest("api.example.com")
	sni, sawTLS, needMore, err := parseClientHelloSNI(hello)
	if err != nil {
		t.Fatalf("parseClientHelloSNI: %v", err)
	}
	if !sawTLS || needMore != 0 || sni != "api.example.com" {
		t.Fatalf("got sni=%q sawTLS=%v needMore=%d", sni, sawTLS, needMore)
	}
}

func TestParseClientHelloSNIIncomplete(t *testing.T) {
	hello := mustTLSClientHelloForTest("api.example.com")
	_, sawTLS, needMore, err := parseClientHelloSNI(hello[:9])
	if err != nil {
		t.Fatalf("parseClientHelloSNI: %v", err)
	}
	if !sawTLS || needMore <= 9 {
		t.Fatalf("got sawTLS=%v needMore=%d", sawTLS, needMore)
	}
}

func TestParseClientHelloSNIFragmentedAcrossRecords(t *testing.T) {
	hello := mustFragmentedTLSClientHelloForTest("api.example.com", 7)
	sni, sawTLS, needMore, err := parseClientHelloSNI(hello)
	if err != nil {
		t.Fatalf("parseClientHelloSNI: %v", err)
	}
	if !sawTLS || needMore != 0 || sni != "api.example.com" {
		t.Fatalf("got sni=%q sawTLS=%v needMore=%d", sni, sawTLS, needMore)
	}
}

func TestParseClientHelloSNINonTLS(t *testing.T) {
	sni, sawTLS, needMore, err := parseClientHelloSNI([]byte("GET / HTTP/1.1\r\n"))
	if err != nil {
		t.Fatalf("parseClientHelloSNI: %v", err)
	}
	if sni != "" || sawTLS || needMore != 0 {
		t.Fatalf("got sni=%q sawTLS=%v needMore=%d", sni, sawTLS, needMore)
	}
}

func TestWriteConnectEstablished(t *testing.T) {
	var b bytes.Buffer
	if err := writeConnectEstablished(&b); err != nil {
		t.Fatalf("writeConnectEstablished: %v", err)
	}
	got := b.String()
	if got != "HTTP/1.1 200 Connection established\r\n\r\n" {
		t.Fatalf("unexpected CONNECT response %q", got)
	}
	if strings.Contains(strings.ToLower(got), "connection: close") {
		t.Fatalf("CONNECT response must not include Connection: close")
	}
}

func TestWritePortFileAtomicCreatesParentDir(t *testing.T) {
	tmpDir := t.TempDir()
	portFile := filepath.Join(tmpDir, "nested", "proxy.port")
	if err := writePortFileAtomic(portFile, 8443); err != nil {
		t.Fatalf("writePortFileAtomic: %v", err)
	}
	data, err := os.ReadFile(portFile)
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if string(data) != "8443\n" {
		t.Fatalf("unexpected port file contents %q", string(data))
	}
}

func TestHandleConnectTunnelsPayloadAndUsesClean200(t *testing.T) {
	a, err := newAllowlist([]string{"api.example.com:443"})
	if err != nil {
		t.Fatalf("newAllowlist: %v", err)
	}
	origResolveAndDial := resolveAndDialFunc
	defer func() { resolveAndDialFunc = origResolveAndDial }()

	proxyServer, proxyClient := net.Pipe()
	upstreamProxySide, upstreamServerSide := net.Pipe()
	resolveAndDialFunc = func(_ context.Context, host, port string, _ time.Duration) (net.Conn, string, error) {
		if host != "api.example.com" || port != "443" {
			t.Fatalf("unexpected dial target %s:%s", host, port)
		}
		return upstreamProxySide, "93.184.216.34", nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(proxyServer, a, time.Second, time.Second, 0, time.Second, tlsSNIPolicyOff, discardLogger())
	}()
	defer proxyClient.Close()
	defer upstreamServerSide.Close()

	if _, err := io.WriteString(proxyClient, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	statusBlock := readHeaderBlock(t, proxyClient)
	if !strings.HasPrefix(statusBlock, "HTTP/1.1 200 Connection established\r\n") {
		t.Fatalf("unexpected status block %q", statusBlock)
	}
	if strings.Contains(strings.ToLower(statusBlock), "connection: close") {
		t.Fatalf("200 response should not advertise connection close")
	}

	clientPayload := []byte("ping-through-proxy")
	upstreamPayload := []byte("pong-from-upstream")

	if _, err := proxyClient.Write(clientPayload); err != nil {
		t.Fatalf("proxyClient.Write: %v", err)
	}
	gotUpstream := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(upstreamServerSide, gotUpstream); err != nil {
		t.Fatalf("io.ReadFull upstream: %v", err)
	}
	if !bytes.Equal(gotUpstream, clientPayload) {
		t.Fatalf("upstream got %q want %q", gotUpstream, clientPayload)
	}

	if _, err := upstreamServerSide.Write(upstreamPayload); err != nil {
		t.Fatalf("upstreamServerSide.Write: %v", err)
	}
	gotClient := make([]byte, len(upstreamPayload))
	if _, err := io.ReadFull(proxyClient, gotClient); err != nil {
		t.Fatalf("io.ReadFull client: %v", err)
	}
	if !bytes.Equal(gotClient, upstreamPayload) {
		t.Fatalf("client got %q want %q", gotClient, upstreamPayload)
	}

	_ = proxyClient.Close()
	_ = upstreamServerSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handle did not exit")
	}
}

func TestHandleRejectsSNIMismatchBeforeForwardingPayload(t *testing.T) {
	a, err := newAllowlist([]string{"api.example.com:443"})
	if err != nil {
		t.Fatalf("newAllowlist: %v", err)
	}
	origResolveAndDial := resolveAndDialFunc
	defer func() { resolveAndDialFunc = origResolveAndDial }()

	proxyServer, proxyClient := net.Pipe()
	dialed := make(chan struct{}, 1)
	resolveAndDialFunc = func(_ context.Context, host, port string, _ time.Duration) (net.Conn, string, error) {
		dialed <- struct{}{}
		return nil, "", io.EOF
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(proxyServer, a, time.Second, time.Second, 0, time.Second, tlsSNIPolicyRequire, discardLogger())
	}()
	defer proxyClient.Close()

	if _, err := io.WriteString(proxyClient, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	statusBlock := readHeaderBlock(t, proxyClient)
	if !strings.HasPrefix(statusBlock, "HTTP/1.1 200 Connection established\r\n") {
		t.Fatalf("unexpected status block %q", statusBlock)
	}
	if _, err := proxyClient.Write(mustTLSClientHelloForTest("wrong.example.com")); err != nil {
		t.Fatalf("write client hello: %v", err)
	}

	select {
	case <-dialed:
		t.Fatal("unexpected upstream dial on SNI mismatch")
	case <-time.After(200 * time.Millisecond):
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handle did not exit after SNI mismatch")
	}
}

func TestHandleValidFragmentedSNIThenDialsAndTunnelsBufferedHello(t *testing.T) {
	a, err := newAllowlist([]string{"api.example.com:443"})
	if err != nil {
		t.Fatalf("newAllowlist: %v", err)
	}
	origResolveAndDial := resolveAndDialFunc
	defer func() { resolveAndDialFunc = origResolveAndDial }()

	proxyServer, proxyClient := net.Pipe()
	upstreamProxySide, upstreamServerSide := net.Pipe()
	resolveAndDialFunc = func(_ context.Context, host, port string, _ time.Duration) (net.Conn, string, error) {
		if host != "api.example.com" || port != "443" {
			t.Fatalf("unexpected dial target %s:%s", host, port)
		}
		return upstreamProxySide, "93.184.216.34", nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(proxyServer, a, time.Second, time.Second, 0, time.Second, tlsSNIPolicyRequire, discardLogger())
	}()
	defer proxyClient.Close()
	defer upstreamServerSide.Close()

	if _, err := io.WriteString(proxyClient, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	statusBlock := readHeaderBlock(t, proxyClient)
	if !strings.HasPrefix(statusBlock, "HTTP/1.1 200 Connection established\r\n") {
		t.Fatalf("unexpected status block %q", statusBlock)
	}

	hello := mustFragmentedTLSClientHelloForTest("api.example.com", 7)
	payload := append(append([]byte{}, hello...), []byte("after-hello")...)
	if _, err := proxyClient.Write(payload); err != nil {
		t.Fatalf("proxyClient.Write: %v", err)
	}

	gotUpstream := make([]byte, len(payload))
	if _, err := io.ReadFull(upstreamServerSide, gotUpstream); err != nil {
		t.Fatalf("io.ReadFull upstream: %v", err)
	}
	if !bytes.Equal(gotUpstream, payload) {
		t.Fatalf("upstream got %x want %x", gotUpstream, payload)
	}

	_ = proxyClient.Close()
	_ = upstreamServerSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handle did not exit")
	}
}

func readHeaderBlock(t *testing.T, conn net.Conn) string {
	t.Helper()
	reader := bufio.NewReader(conn)
	var b strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("readHeaderBlock: %v", err)
		}
		b.WriteString(line)
		if line == "\r\n" {
			return b.String()
		}
	}
}

func discardLogger() *eventLogger {
	return &eventLogger{lg: log.New(io.Discard, "", 0)}
}

func mustTLSClientHelloForTest(serverName string) []byte {
	serverNameBytes := []byte(serverName)
	sniName := append([]byte{0x00, byte(len(serverNameBytes) >> 8), byte(len(serverNameBytes))}, serverNameBytes...)
	sniList := append([]byte{byte(len(sniName) >> 8), byte(len(sniName))}, sniName...)
	sniExt := append([]byte{0x00, 0x00, byte(len(sniList) >> 8), byte(len(sniList))}, sniList...)
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)
	body = append(body, bytes.Repeat([]byte{0x01}, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(sniExt)>>8), byte(len(sniExt)))
	body = append(body, sniExt...)
	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)
	record := make([]byte, 0, len(handshake)+5)
	record = append(record, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

func mustFragmentedTLSClientHelloForTest(serverName string, firstRecordPayloadLen int) []byte {
	full := mustTLSClientHelloForTest(serverName)
	payload := full[5:]
	if firstRecordPayloadLen <= 0 || firstRecordPayloadLen >= len(payload) {
		panic("invalid fragmentation point")
	}
	first := payload[:firstRecordPayloadLen]
	second := payload[firstRecordPayloadLen:]
	fragmented := make([]byte, 0, len(full)+5)
	fragmented = append(fragmented, 0x16, 0x03, 0x01, byte(len(first)>>8), byte(len(first)))
	fragmented = append(fragmented, first...)
	fragmented = append(fragmented, 0x16, 0x03, 0x01, byte(len(second)>>8), byte(len(second)))
	fragmented = append(fragmented, second...)
	return fragmented
}
