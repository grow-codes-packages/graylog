package graylog

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTransport records sends and returns a scripted result.
type fakeTransport struct {
	mu     sync.Mutex
	sent   [][]*GelfMessage
	gzip   []*bool
	res    GelfSendResult
	err    error
	closed int
}

func (f *fakeTransport) Protocol() GelfProtocol { return GelfTCP }

func (f *fakeTransport) Send(_ context.Context, m []*GelfMessage, o GelfSendOptions) (GelfSendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	f.gzip = append(f.gzip, o.Gzip)
	if f.err != nil {
		return f.res, f.err
	}
	if f.res.Sent == 0 && f.res.Rejected == 0 {
		return GelfSendResult{Sent: len(m)}, nil
	}
	return f.res, nil
}

func (f *fakeTransport) Close() error { f.closed++; return nil }

func TestGelfLogExporter(t *testing.T) {
	ctx := t.Context()
	ft := &fakeTransport{}
	exp := NewGelfLogExporter(ft, FromLogRecordOptions{Host: "fallback"})
	if exp.Transport() != ft {
		t.Fatal("transport")
	}
	recs := []LogRecord{{Body: "a"}, {Body: "b", Resource: map[string]AttrValue{"host.name": "h"}}}
	res, err := exp.Export(ctx, recs, ExportOptions{Gzip: true})
	if err != nil || res.Accepted != 2 || ft.sent[0][0].Host() != "fallback" || ft.sent[0][1].Host() != "h" || !*ft.gzip[0] {
		t.Fatalf("%+v %v", res, err)
	}
	ft.res = GelfSendResult{Sent: 1, Rejected: 1, Error: ValidationError("gelf.udp", "too big")}
	res, err = exp.Export(ctx, recs, ExportOptions{})
	if err != nil || res.Accepted != 1 || res.Rejected != 1 || !errors.Is(res.Error, ErrValidation) {
		t.Fatalf("partial %+v %v", res, err)
	}
	ft.res, ft.err = GelfSendResult{Sent: 1}, &Error{Code: ErrorCodeUnavailable, Message: "down", Retryable: true}
	res, err = exp.Export(ctx, recs, ExportOptions{})
	if !errors.Is(err, ErrUnavailable) || res.Accepted != 1 || res.Rejected != 1 || res.Error == nil {
		t.Fatalf("failure %+v %v", res, err)
	}
	ft.err = errors.New("plain")
	if res, err := exp.Export(ctx, recs, ExportOptions{}); err == nil || res.Error != nil {
		t.Fatalf("plain error %+v %v", res, err)
	}
	_ = exp.Shutdown(ctx)
	if ft.closed != 1 {
		t.Fatal("shutdown closes the transport")
	}
}

func TestNewLogClient(t *testing.T) {
	ctx := t.Context()
	// TCP sink, UDP socket, HTTP server and OTLP server for one client config.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink := newTCPSink(t, ln)
	udp, udpPort := listenUDP(t)
	var httpBodies []string
	var mu sync.Mutex
	httpSrv := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			b = inflate(t, GelfCompressionGzip, b)
		}
		mu.Lock()
		httpBodies = append(httpBodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
	fake, otlpEndpoint := startOTLPServer(t)

	c := newTestClient(t, "http://127.0.0.1:9", func(cfg *Config) {
		cfg.GelfPort = tcpPort(ln)
		cfg.GelfHTTPURL = httpSrv.URL + "/gelf"
		cfg.OTLPEndpoint = otlpEndpoint
	})
	resource := map[string]AttrValue{"service.name": "svc"}

	tcp, err := c.NewLogClient(LogOptions{LogClientOptions: LogClientOptions{Resource: resource}, Host: "app-host"})
	if err != nil {
		t.Fatal(err)
	}
	tcp.Logger("main", nil).Info(ctx, "via tcp", "user", "bob", "password", "hunter2")
	if err := tcp.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	frame := sink.wait(t, 1)[0]
	for _, want := range []string{`"short_message":"via tcp"`, `"host":"app-host"`, `"_service.name":"svc"`, `"_user":"bob"`, `"_logger.name":"main"`, `"level":6`} {
		if !strings.Contains(frame, want) {
			t.Fatalf("frame %s lacks %s", frame, want)
		}
	}
	if strings.Contains(frame, "hunter2") {
		t.Fatal("redaction")
	}

	udpClient, err := c.NewLogClient(LogOptions{Protocol: GelfUDP, Compression: GelfCompressionNone, ChunkSize: 1000})
	if err != nil {
		t.Fatal(err)
	}
	_ = udpPort
	udpClient.Send(ctx, LogInput{Message: "via udp"})
	_ = udpClient.Flush(ctx)
	_ = udp // UDP goes to GelfPort (the TCP port here); delivery is best-effort.

	httpClient, err := c.NewLogClient(LogOptions{Protocol: GelfHTTP, Headers: map[string]string{"X-A": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	httpClient.SendBatch(ctx, Entries([]LogInput{{Message: "h1"}, {Message: "h2", Severity: SeverityError}}))
	if err := httpClient.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(httpBodies) != 1 || strings.Count(httpBodies[0], "\n") != 2 || !strings.HasSuffix(httpBodies[0], "\n") || !strings.Contains(httpBodies[0], `"level":3`) {
		t.Fatalf("http bodies %q", httpBodies)
	}
	mu.Unlock()

	otlpClient, err := c.NewLogClient(LogOptions{Protocol: ProtocolOTLP, BearerToken: NewSecret("bearer-1234")})
	if err != nil {
		t.Fatal(err)
	}
	otlpClient.Send(ctx, LogInput{Message: "via otlp"})
	if err := otlpClient.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	if len(fake.requests) != 1 || fake.requests[0].ResourceLogs[0].ScopeLogs[0].LogRecords[0].Body.GetStringValue() != "via otlp" {
		t.Fatalf("otlp %v", fake.requests)
	}
	fake.mu.Unlock()

	ft := &fakeTransport{}
	custom, err := c.NewLogClient(LogOptions{Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	custom.Send(ctx, LogInput{Message: "custom"})

	// Close of the client flushes and closes every log client.
	_ = c.Close()
	if len(ft.sent) != 1 || ft.closed != 1 {
		t.Fatalf("close must flush: sent=%d closed=%d", len(ft.sent), ft.closed)
	}

	// Errors.
	c2 := newTestClient(t, "http://127.0.0.1:9", func(cfg *Config) { cfg.OTLPEndpoint = "https://h:1" })
	if _, err := c2.NewLogClient(LogOptions{Protocol: "smtp"}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := c2.GelfTransport("smtp", GelfTransportOptions{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	ft2 := &fakeTransport{}
	if _, err := c2.NewLogClient(LogOptions{Transport: ft2, LogClientOptions: LogClientOptions{Batch: BatchOptions{MaxQueueSize: -1}}}); !errors.Is(err, ErrConfig) || ft2.closed != 1 {
		t.Fatalf("bad batch options: %v closed=%d", err, ft2.closed)
	}
	if _, err := NewClient(Config{CommonConfig: CommonConfig{TLS: TLSConfig{CACertPath: "/nonexistent"}}}); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	for _, p := range []GelfProtocol{"", GelfUDP, GelfTCP, GelfHTTP} {
		tr, err := c2.GelfTransport(p, GelfTransportOptions{})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		want := p
		if want == "" {
			want = GelfTCP
		}
		if tr.Protocol() != want {
			t.Fatalf("%s: %s", p, tr.Protocol())
		}
		_ = tr.Close()
	}
	badUDP := newTestClient(t, "http://127.0.0.1:9", nil)
	if _, err := badUDP.NewLogClient(LogOptions{Protocol: GelfUDP, ChunkSize: 5}); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	badOTLP := newTestClient(t, "http://127.0.0.1:9", func(cfg *Config) { cfg.OTLPEndpoint = "https://h:" + strconv.Itoa(1) })
	if _, err := badOTLP.NewLogClient(LogOptions{Protocol: ProtocolOTLP}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
}
