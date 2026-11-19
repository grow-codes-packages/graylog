package graylog

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustMessage(t *testing.T, short string, fields map[string]any) *GelfMessage {
	t.Helper()
	m, err := NewGelfMessage(GelfMessageOptions{Host: "h", ShortMessage: short, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func inflate(t *testing.T, c GelfCompression, data []byte) []byte {
	t.Helper()
	var r io.Reader
	var err error
	switch c {
	case GelfCompressionGzip:
		r, err = gzip.NewReader(bytes.NewReader(data))
	case GelfCompressionZlib:
		r, err = zlib.NewReader(bytes.NewReader(data))
	default:
		return data
	}
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// reassemble joins GELF chunks (or returns a single datagram as is).
func reassemble(t *testing.T, datagrams [][]byte) []byte {
	t.Helper()
	if len(datagrams) == 1 && !bytes.HasPrefix(datagrams[0], []byte{0x1e, 0x0f}) {
		return datagrams[0]
	}
	parts := make([][]byte, len(datagrams))
	for _, d := range datagrams {
		if !bytes.HasPrefix(d, []byte{0x1e, 0x0f}) || int(d[11]) != len(datagrams) {
			t.Fatalf("bad chunk header % x", d[:12])
		}
		parts[d[10]] = d[12:]
	}
	return bytes.Join(parts, nil)
}

func TestEncodeGelfUDP(t *testing.T) {
	payload := bytes.Repeat([]byte(`{"short_message":"abcdefghij"}`), 400) // ~12 KB
	for _, c := range []GelfCompression{GelfCompressionNone, GelfCompressionGzip, GelfCompressionZlib} {
		grams, err := EncodeGelfUDP(payload, c, 200, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		for _, g := range grams {
			if len(g) > 200 {
				t.Fatalf("%s: datagram of %d bytes", c, len(g))
			}
		}
		if got := inflate(t, c, reassemble(t, grams)); !bytes.Equal(got, payload) {
			t.Fatalf("%s: round trip mismatch", c)
		}
	}
	grams, err := EncodeGelfUDP(payload, GelfCompressionNone, 200, []byte{9, 9, 9, 9, 9, 9, 9, 9})
	if err != nil || !bytes.Equal(grams[0][2:10], []byte{9, 9, 9, 9, 9, 9, 9, 9}) || grams[0][10] != 0 || int(grams[0][11]) != len(grams) {
		t.Fatalf("header %v", err)
	}
	// Exactly 128 chunks is allowed, 129 is not.
	per := 64 - GelfChunkHeaderSize
	if g, err := EncodeGelfUDP(make([]byte, per*128), GelfCompressionNone, 64, nil); err != nil || len(g) != 128 {
		t.Fatalf("128 chunks: %d %v", len(g), err)
	}
	if _, err := EncodeGelfUDP(make([]byte, per*128+1), GelfCompressionNone, 64, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("129 chunks: %v", err)
	}
	if g, err := EncodeGelfUDP([]byte("small"), "", 0, nil); err != nil || len(g) != 1 || g[0][0] != 0x1f {
		t.Fatalf("defaults: %v", err)
	}
	if _, err := EncodeGelfUDP([]byte("x"), GelfCompressionNone, 12, nil); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}

func listenUDP(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, conn.LocalAddr().(*net.UDPAddr).Port
}

func TestGelfUDPTransport(t *testing.T) {
	ctx := t.Context()
	conn, port := listenUDP(t)
	tr, err := NewGelfUDPTransport(GelfUDPOptions{Host: "127.0.0.1", Port: port, ChunkSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Protocol() != GelfUDP {
		t.Fatal("protocol")
	}
	small := mustMessage(t, "small", nil)
	big := mustMessage(t, strings.Repeat("big ", 5000)+randomText(4000), nil)
	huge := mustMessage(t, randomText(200_000), nil)
	res, err := tr.Send(ctx, []*GelfMessage{small, big, huge}, GelfSendOptions{})
	if err != nil || res.Sent != 2 || res.Rejected != 1 || !errors.Is(res.Error, ErrValidation) {
		t.Fatalf("send %+v %v", res, err)
	}
	buf := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(inflate(t, GelfCompressionGzip, buf[:n]), &doc); err != nil || doc["short_message"] != "small" {
		t.Fatalf("small datagram: %v %v", doc, err)
	}
	var chunks [][]byte
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, append([]byte(nil), buf[:n]...))
		if len(chunks) == int(chunks[0][11]) {
			break
		}
	}
	doc = nil
	if err := json.Unmarshal(inflate(t, GelfCompressionGzip, reassemble(t, chunks)), &doc); err != nil || doc["short_message"] != big.ShortMessage() {
		t.Fatalf("chunked: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	_ = tr.Close()
	if _, err := tr.Send(ctx, []*GelfMessage{small}, GelfSendOptions{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("closed: %v", err)
	}

	tr2, _ := NewGelfUDPTransport(GelfUDPOptions{Host: "127.0.0.1", Port: port})
	if _, err := tr2.Send(ctx, []*GelfMessage{nil}, GelfSendOptions{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := tr2.Send(cctx, []*GelfMessage{small}, GelfSendOptions{}); !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
	tr3, _ := NewGelfUDPTransport(GelfUDPOptions{Host: "no-such-host.invalid", Port: port})
	if _, err := tr3.Send(ctx, []*GelfMessage{small}, GelfSendOptions{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dns: %v", err)
	}

	for i, o := range []GelfUDPOptions{{}, {Host: "h", Port: 70000}, {Host: "h", Compression: "lz4"}, {Host: "h", ChunkSize: 10}} {
		if _, err := NewGelfUDPTransport(o); !errors.Is(err, ErrConfig) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	d, _ := NewGelfUDPTransport(GelfUDPOptions{Host: "h"})
	if d.addr != "h:12201" || d.compression != GelfCompressionGzip || d.chunkSize != 1420 {
		t.Fatalf("defaults %+v", d)
	}
}

func randomText(n int) string {
	var b strings.Builder
	x := uint32(2463534242)
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteByte(byte('a' + x%26))
	}
	return b.String()
}

// tcpSink accepts connections and collects NUL-terminated frames.
type tcpSink struct {
	ln     net.Listener
	mu     sync.Mutex
	frames []string
	conns  []net.Conn
	got    chan struct{}
}

func newTCPSink(t *testing.T, ln net.Listener) *tcpSink {
	t.Helper()
	s := &tcpSink{ln: ln, got: make(chan struct{}, 1000)}
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			go func() {
				r := bufio.NewReader(c)
				for {
					frame, err := r.ReadString(0)
					if err != nil {
						return
					}
					s.mu.Lock()
					s.frames = append(s.frames, strings.TrimSuffix(frame, "\x00"))
					s.mu.Unlock()
					s.got <- struct{}{}
				}
			}()
		}
	}()
	return s
}

func (s *tcpSink) wait(t *testing.T, n int) []string {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-s.got:
		case <-time.After(5 * time.Second):
			t.Fatalf("waited for %d frames", n)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.frames...)
}

func (s *tcpSink) dropConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

func tcpPort(ln net.Listener) int { return ln.Addr().(*net.TCPAddr).Port }

func TestGelfTCPTransport(t *testing.T) {
	ctx := t.Context()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink := newTCPSink(t, ln)
	tr, err := NewGelfTCPTransport(GelfTCPOptions{Host: "127.0.0.1", Port: tcpPort(ln), Retry: fastRetry(3)})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Protocol() != GelfTCP || tr.Secure() {
		t.Fatal("protocol")
	}
	msgs := []*GelfMessage{mustMessage(t, "one", nil), mustMessage(t, "two", map[string]any{"k": 1})}
	res, err := tr.Send(ctx, msgs, GelfSendOptions{})
	if err != nil || res.Sent != 2 {
		t.Fatalf("send %+v %v", res, err)
	}
	frames := sink.wait(t, 2)
	if !strings.Contains(frames[0], `"short_message":"one"`) || !strings.Contains(frames[1], `"_k":1`) {
		t.Fatalf("frames %v", frames)
	}
	// The server drops the connection: the next batch reconnects.
	sink.dropConnections()
	time.Sleep(20 * time.Millisecond)
	if _, err := tr.Send(ctx, []*GelfMessage{mustMessage(t, "three", nil)}, GelfSendOptions{}); err != nil {
		t.Fatal(err)
	}
	if frames := sink.wait(t, 1); frames[len(frames)-1] == "" || !strings.Contains(frames[len(frames)-1], "three") {
		t.Fatalf("after reconnect %v", frames)
	}
	if tr.Connections() != 2 {
		t.Fatalf("connections %d", tr.Connections())
	}
	if res, err := tr.Send(ctx, nil, GelfSendOptions{}); err != nil || res.Sent != 0 {
		t.Fatal(err)
	}
	if _, err := tr.Send(ctx, []*GelfMessage{nil}, GelfSendOptions{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	_ = tr.Close()
	_ = tr.Close()
	if _, err := tr.Send(ctx, msgs, GelfSendOptions{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("closed: %v", err)
	}
	if !bytes.Equal(FrameGelfTCP(msgs[:1]), append(msgs[0].Encode(), 0)) {
		t.Fatal("frame")
	}

	// Connection refused: retries then UNAVAILABLE; cancel during backoff.
	closed := closedAddr(t)
	_, portText, _ := net.SplitHostPort(closed)
	port, _ := strconv.Atoi(portText)
	bad, _ := NewGelfTCPTransport(GelfTCPOptions{Host: "127.0.0.1", Port: port, Retry: fastRetry(2), ConnectTimeout: time.Second})
	if _, err := bad.Send(ctx, msgs, GelfSendOptions{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("refused: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	bad.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	if _, err := bad.Send(cctx, msgs, GelfSendOptions{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel in backoff: %v", err)
	}
	if _, err := bad.Send(cctx, msgs, GelfSendOptions{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled ctx: %v", err)
	}
	slow, _ := NewGelfTCPTransport(GelfTCPOptions{Host: "127.0.0.1", Port: port, Retry: fastRetry(5)})
	slow.sleep = func(context.Context, time.Duration) error { return errors.New("stop") }
	if _, err := slow.Send(ctx, msgs, GelfSendOptions{}); err == nil {
		t.Fatal("sleep error")
	}
	dctx, dcancel := context.WithTimeout(ctx, time.Nanosecond)
	defer dcancel()
	time.Sleep(time.Millisecond)
	if _, err := slow.Send(dctx, msgs, GelfSendOptions{}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("deadline: %v", err)
	}

	for i, o := range []GelfTCPOptions{{}, {Host: "h", Port: -2}, {Host: "h", ConnectTimeout: -1}, {Host: "h", TLS: true, TLSConfig: TLSConfig{CACertPEM: "junk"}}} {
		if _, err := NewGelfTCPTransport(o); !errors.Is(err, ErrConfig) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	d, _ := NewGelfTCPTransport(GelfTCPOptions{Host: "h"})
	if d.addr != "h:12201" || d.opts.WriteTimeout != DefaultRequestTimeout || d.retry.MaxRetries != DefaultMaxRetries {
		t.Fatalf("defaults %+v", d.opts)
	}
}

func TestGelfTCPTransportTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLS)
	if err != nil {
		t.Fatal(err)
	}
	sink := newTCPSink(t, ln)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	tr, err := NewGelfTCPTransport(GelfTCPOptions{Host: "127.0.0.1", Port: tcpPort(ln), TLS: true, TLSConfig: TLSConfig{CACertPEM: ca}, ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	if !tr.Secure() {
		t.Fatal("secure")
	}
	if _, err := tr.Send(t.Context(), []*GelfMessage{mustMessage(t, "tls", nil)}, GelfSendOptions{}); err != nil {
		t.Fatal(err)
	}
	if frames := sink.wait(t, 1); !strings.Contains(frames[0], `"short_message":"tls"`) {
		t.Fatal(frames)
	}
	// Default server name (the host) does not match the certificate's names
	// when the host is a name the certificate lacks.
	wrong, _ := NewGelfTCPTransport(GelfTCPOptions{Host: "localhost", Port: tcpPort(ln), TLS: true, TLSConfig: TLSConfig{CACertPEM: ca}, Retry: fastRetry(0)})
	t.Cleanup(func() { _ = wrong.Close() })
	if _, err := wrong.Send(t.Context(), []*GelfMessage{mustMessage(t, "x", nil)}, GelfSendOptions{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("hostname mismatch: %v", err)
	}
}

func TestGelfHTTPTransport(t *testing.T) {
	ctx := t.Context()
	var mu sync.Mutex
	type got struct {
		path, encoding, ctype, auth, requestedBy string
		body                                     []byte
	}
	var reqs []got
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			b = inflate(t, GelfCompressionGzip, b)
		}
		mu.Lock()
		reqs = append(reqs, got{r.URL.Path, r.Header.Get("Content-Encoding"), r.Header.Get("Content-Type"), r.Header.Get("X-Gelf-Auth"), r.Header.Get(HeaderRequestedBy), b})
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
	tr, err := NewGelfHTTPTransport(GelfHTTPOptions{URL: ts.URL + "/gelf", Headers: map[string]string{"X-Gelf-Auth": "secret-value"}, Config: CommonConfig{Retry: fastRetry(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Protocol() != GelfHTTP {
		t.Fatal("protocol")
	}
	msgs := []*GelfMessage{mustMessage(t, "a", nil), mustMessage(t, "b", nil), mustMessage(t, "c", nil)}
	res, err := tr.Send(ctx, msgs, GelfSendOptions{})
	if err != nil || res.Sent != 3 {
		t.Fatalf("bulk %+v %v", res, err)
	}
	r0 := reqs[0]
	if r0.path != "/gelf" || r0.encoding != "gzip" || r0.ctype != "application/json" || r0.auth != "secret-value" || r0.requestedBy != DefaultRequestedBy {
		t.Fatalf("request %+v", r0)
	}
	// Every message is newline-terminated, the last one too (Graylog 7.0
	// drops messages on reused connections otherwise).
	if lines := strings.Split(string(r0.body), "\n"); len(lines) != 4 || lines[3] != "" || !strings.Contains(lines[2], `"short_message":"c"`) {
		t.Fatalf("bulk body %q", r0.body)
	}
	off := false
	if _, err := tr.Send(ctx, msgs[:1], GelfSendOptions{Gzip: &off}); err != nil || reqs[1].encoding != "" {
		t.Fatalf("no gzip %v %+v", err, reqs[1])
	}
	if _, err := tr.Send(ctx, nil, GelfSendOptions{}); err != nil || len(reqs) != 2 {
		t.Fatal("empty send must not post")
	}
	single, _ := NewGelfHTTPTransport(GelfHTTPOptions{URL: ts.URL, DisableBulk: true, DisableGzip: true})
	if res, err := single.Send(ctx, msgs, GelfSendOptions{}); err != nil || res.Sent != 3 || len(reqs) != 5 || reqs[2].path != "/gelf" || reqs[4].encoding != "" {
		t.Fatalf("single %+v %v %+v", res, err, reqs)
	}
	if b := string(reqs[2].body); !strings.HasSuffix(b, "}\n") || strings.Count(b, "\n") != 1 {
		t.Fatalf("single body must end with one newline: %q", b)
	}
	if _, err := single.Send(ctx, []*GelfMessage{nil}, GelfSendOptions{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	_ = single.Close()
	_ = single.Close()
	if _, err := single.Send(ctx, msgs, GelfSendOptions{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("closed: %v", err)
	}

	failing := newTestServer(t, statusHandler(http.StatusUnauthorized))
	ft, _ := NewGelfHTTPTransport(GelfHTTPOptions{URL: failing.URL + "/gelf"})
	if res, err := ft.Send(ctx, msgs, GelfSendOptions{}); !errors.Is(err, ErrAuthentication) || res.Sent != 0 {
		t.Fatalf("401: %+v %v", res, err)
	}
	for i, o := range []GelfHTTPOptions{{URL: "ftp://x"}, {URL: ""}, {URL: "http://h", Config: CommonConfig{TotalTimeout: -1}}, {URL: "http://h", Config: CommonConfig{TLS: TLSConfig{CACertPEM: "x"}}}} {
		if _, err := NewGelfHTTPTransport(o); !errors.Is(err, ErrConfig) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}
