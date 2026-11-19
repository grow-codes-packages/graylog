package graylog

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
)

// fakeLogsServer is an in-process OTLP LogsService.
type fakeLogsServer struct {
	collogspb.UnimplementedLogsServiceServer
	mu       sync.Mutex
	requests []*collogspb.ExportLogsServiceRequest
	md       []metadata.MD
	err      error
	rejected int64
}

func (s *fakeLogsServer) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	md, _ := metadata.FromIncomingContext(ctx)
	s.md = append(s.md, md)
	s.requests = append(s.requests, req)
	if s.err != nil {
		return nil, s.err
	}
	resp := &collogspb.ExportLogsServiceResponse{}
	if s.rejected > 0 {
		resp.PartialSuccess = &collogspb.ExportLogsPartialSuccess{RejectedLogRecords: s.rejected, ErrorMessage: "bad record token-SECRET-1"}
	}
	return resp, nil
}

func startOTLPServer(t *testing.T) (*fakeLogsServer, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	fake := &fakeLogsServer{}
	collogspb.RegisterLogsServiceServer(srv, fake)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return fake, "http://" + ln.Addr().String()
}

func TestOTLPGRPCLogExporter(t *testing.T) {
	ctx := t.Context()
	fake, endpoint := startOTLPServer(t)
	exp, err := NewOTLPGRPCLogExporter(OTLPGRPCLogExporterOptions{
		Endpoint: endpoint, BearerToken: NewSecret("token-SECRET-1"), Headers: map[string]string{"X-Extra": "v"},
	})
	if err != nil {
		t.Fatal(err)
	}
	flags := uint8(1)
	now := time.Now()
	recs := []LogRecord{
		{Timestamp: now, ObservedTimestamp: now, Severity: SeverityWarn, Body: "a", TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7", TraceFlags: &flags,
			Attributes: map[string]AttrValue{"s": "x", "b": true, "i": int64(3), "f": 1.5, "arr": []AttrValue{"y", nil}, "m": map[string]AttrValue{"k": "v"}, "nil": nil},
			Resource:   map[string]AttrValue{"service.name": "svc"}},
		{Severity: SeverityError, SeverityText: "Err", Body: "b", TraceID: "short", Resource: map[string]AttrValue{"service.name": "svc"}},
		{Body: "c", Resource: map[string]AttrValue{"service.name": "other"}},
	}
	res, err := exp.Export(ctx, recs, ExportOptions{Gzip: true})
	if err != nil || res.Accepted != 3 || res.Rejected != 0 {
		t.Fatalf("export %+v %v", res, err)
	}
	req := fake.requests[0]
	if len(req.ResourceLogs) != 2 || len(req.ResourceLogs[0].ScopeLogs[0].LogRecords) != 2 || req.ResourceLogs[0].ScopeLogs[0].Scope.Name != OTLPScopeName {
		t.Fatalf("grouping %v", req)
	}
	lr := req.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if hex.EncodeToString(lr.TraceId) != recs[0].TraceID || hex.EncodeToString(lr.SpanId) != recs[0].SpanID || lr.Flags != 1 ||
		lr.SeverityNumber != 13 || lr.SeverityText != "WARN" || lr.Body.GetStringValue() != "a" || len(lr.Attributes) != 6 || lr.TimeUnixNano == 0 || lr.ObservedTimeUnixNano == 0 {
		t.Fatalf("record %v", lr)
	}
	if lr2 := req.ResourceLogs[0].ScopeLogs[0].LogRecords[1]; lr2.TraceId != nil || lr2.SeverityText != "Err" || lr2.TimeUnixNano != 0 {
		t.Fatalf("record 2 %v", lr2)
	}
	if md := fake.md[0]; md.Get("authorization")[0] != "Bearer token-SECRET-1" || md.Get("x-extra")[0] != "v" || !strings.Contains(md.Get("user-agent")[0], "grow-codes-graylog") {
		t.Fatalf("metadata %v", md)
	}
	if res, err := exp.Export(ctx, nil, ExportOptions{}); err != nil || res.Accepted != 0 {
		t.Fatal(err)
	}

	fake.rejected = 5
	res, err = exp.Export(ctx, recs[:2], ExportOptions{})
	if err != nil || res.Accepted != 0 || res.Rejected != 2 || !errors.Is(res.Error, ErrValidation) || strings.Contains(res.Error.Error(), "token-SECRET-1") {
		t.Fatalf("partial %+v %v", res, err)
	}
	fake.rejected = 0
	fake.err = grpcstatus.Error(codes.Unavailable, "down token-SECRET-1")
	res, err = exp.Export(ctx, recs, ExportOptions{})
	var gerr *Error
	if !errors.As(err, &gerr) || gerr.Code != ErrorCodeUnavailable || !gerr.Retryable || res.Rejected != 3 || strings.Contains(err.Error(), "token-SECRET-1") {
		t.Fatalf("unavailable %+v %v", res, err)
	}
	fake.err = grpcstatus.Error(codes.Unauthenticated, "")
	if _, err := exp.Export(ctx, recs, ExportOptions{}); !errors.Is(err, ErrAuthentication) || !strings.Contains(err.Error(), "gRPC status 16") {
		t.Fatalf("unauthenticated %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := exp.Export(cctx, recs, ExportOptions{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled %v", err)
	}
	_ = exp.Shutdown(ctx)
	_ = exp.Shutdown(ctx)
	if _, err := exp.Export(ctx, recs, ExportOptions{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("closed %v", err)
	}

	for i, o := range []OTLPGRPCLogExporterOptions{{Endpoint: "127.0.0.1:4317"}, {Endpoint: "grpc://h:1"}, {Endpoint: "http://h:1", Timeout: -1}, {Endpoint: "https://h:1", TLS: TLSConfig{CACertPEM: "x"}}} {
		if _, err := NewOTLPGRPCLogExporter(o); !errors.Is(err, ErrConfig) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	tlsExp, err := NewOTLPGRPCLogExporter(OTLPGRPCLogExporterOptions{Endpoint: "https://h:4317"})
	if err != nil || tlsExp.timeout != DefaultRequestTimeout {
		t.Fatal(err)
	}
	_ = tlsExp.Shutdown(ctx)
}

func TestOTLPErrorForStatus(t *testing.T) {
	cases := map[codes.Code]struct {
		code      ErrorCode
		retryable bool
	}{
		codes.Canceled: {ErrorCodeCancelled, false}, codes.InvalidArgument: {ErrorCodeValidation, false},
		codes.FailedPrecondition: {ErrorCodeValidation, false}, codes.DeadlineExceeded: {ErrorCodeTimeout, true},
		codes.NotFound: {ErrorCodeNotFound, false}, codes.AlreadyExists: {ErrorCodeConflict, false},
		codes.PermissionDenied: {ErrorCodePermissionDenied, false}, codes.ResourceExhausted: {ErrorCodeRateLimited, true},
		codes.Unimplemented: {ErrorCodeUnsupported, false}, codes.Unauthenticated: {ErrorCodeAuthentication, false},
		codes.Aborted: {ErrorCodeUnavailable, true}, codes.OutOfRange: {ErrorCodeUnavailable, true},
		codes.Unavailable: {ErrorCodeUnavailable, true}, codes.DataLoss: {ErrorCodeUnavailable, true},
		codes.Internal: {ErrorCodeUnavailable, false}, codes.Unknown: {ErrorCodeUnavailable, false},
	}
	for c, want := range cases {
		e := OTLPErrorForStatus(c, "m", nil)
		if e.Code != want.code || e.Retryable != want.retryable || !strings.HasPrefix(e.Message, "otlp.export: m (gRPC ") {
			t.Fatalf("%s: %+v", c, e)
		}
	}
	if e := OTLPErrorForStatus(codes.Unavailable, "", context.Canceled); e.Code != ErrorCodeCancelled {
		t.Fatal(e)
	}
	if otlpAnyValue(nil) != nil {
		t.Fatal("nil any value")
	}
}
