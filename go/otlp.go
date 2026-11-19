package graylog

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
)

// OTLPScopeName is the instrumentation scope written into every OTLP export.
const OTLPScopeName = "grow-codes-graylog"

// OTLPGRPCLogExporterOptions configure NewOTLPGRPCLogExporter.
type OTLPGRPCLogExporterOptions struct {
	// Endpoint is http://host:4317 (plaintext h2c) or https://host:4317 (TLS).
	Endpoint string
	// BearerToken is sent as "authorization: Bearer <token>" (the input's
	// optional bearer_token).
	BearerToken Secret
	// Headers are extra gRPC metadata entries.
	Headers map[string]string
	// TLS settings for https endpoints.
	TLS TLSConfig
	// Timeout is the deadline of one export call (default 30 s).
	Timeout time.Duration
	// ConnectTimeout bounds connection setup (default 10 s).
	ConnectTimeout time.Duration
}

// OTLPGRPCLogExporter is the LogExporter for the Graylog OpenTelemetry (gRPC)
// input (org.graylog.inputs.otel.OTelGrpcInput): OTLP LogsService/Export over
// gRPC, gzip when the batch asks for it. Graylog Open 7.0 has no OTLP/HTTP
// input. Graylog stores otel_* fields; LogRecordFromMessage reads them back.
type OTLPGRPCLogExporter struct {
	conn    *grpc.ClientConn
	client  collogspb.LogsServiceClient
	timeout time.Duration
	md      metadata.MD
	secrets []string

	closed    atomic.Bool
	closeOnce sync.Once
}

var _ LogExporter = (*OTLPGRPCLogExporter)(nil)

// NewOTLPGRPCLogExporter validates opts (CONFIG error) and returns an
// exporter; gRPC connects lazily.
func NewOTLPGRPCLogExporter(opts OTLPGRPCLogExporterOptions) (*OTLPGRPCLogExporter, error) {
	u, err := url.Parse(opts.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ConfigError("otlp: endpoint must be an http(s) URL")
	}
	if opts.Timeout < 0 || opts.ConnectTimeout < 0 {
		return nil, ConfigError("otlp: timeouts must be positive")
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultRequestTimeout
	}
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = DefaultConnectTimeout
	}
	creds := insecure.NewCredentials()
	if u.Scheme == "https" {
		tlsCfg, err := buildTLS(opts.TLS)
		if err != nil {
			return nil, err
		}
		creds = credentials.NewTLS(tlsCfg)
	}
	conn, err := grpc.NewClient("passthrough:///"+u.Host,
		grpc.WithTransportCredentials(creds),
		grpc.WithUserAgent(UserAgent),
		grpc.WithConnectParams(connectParams(opts.ConnectTimeout)),
	)
	if err != nil {
		return nil, ConfigError("otlp: endpoint must be an http(s) URL")
	}
	e := &OTLPGRPCLogExporter{conn: conn, client: collogspb.NewLogsServiceClient(conn), timeout: opts.Timeout, md: metadata.MD{}}
	for k, v := range opts.Headers {
		e.md.Set(strings.ToLower(k), v)
		if len(v) >= 4 {
			e.secrets = append(e.secrets, v)
		}
	}
	if !opts.BearerToken.IsZero() {
		e.md.Set("authorization", "Bearer "+opts.BearerToken.Reveal())
		e.secrets = append(e.secrets, opts.BearerToken.Reveal())
	}
	return e, nil
}

// Export sends records as one ExportLogsServiceRequest. A partial success
// counts the rejected records (VALIDATION error in the result).
func (e *OTLPGRPCLogExporter) Export(ctx context.Context, records []LogRecord, opts ExportOptions) (ExportResult, error) {
	if e.closed.Load() {
		return ExportResult{}, ConfigError("otlp.export: exporter is closed")
	}
	if len(records) == 0 {
		return ExportResult{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	if len(e.md) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, e.md)
	}
	var callOpts []grpc.CallOption
	if opts.Gzip {
		callOpts = append(callOpts, grpc.UseCompressor(gzip.Name))
	}
	resp, err := e.client.Export(ctx, OTLPExportRequest(records), callOpts...)
	if err != nil {
		gerr := e.mapError(err)
		return ExportResult{Rejected: len(records), Error: gerr}, gerr
	}
	rejected := int(min(max(resp.GetPartialSuccess().GetRejectedLogRecords(), 0), int64(len(records))))
	res := ExportResult{Accepted: len(records) - rejected, Rejected: rejected}
	if rejected > 0 {
		msg := "otlp.export: " + strconv.Itoa(rejected) + " records rejected"
		if t := resp.GetPartialSuccess().GetErrorMessage(); t != "" {
			msg += ": " + truncate(RedactText(t, e.secrets), maxVendorText)
		}
		res.Error = &Error{Code: ErrorCodeValidation, Message: msg}
	}
	return res, nil
}

// Shutdown closes the gRPC connection; later exports fail with CONFIG. It is
// idempotent.
func (e *OTLPGRPCLogExporter) Shutdown(context.Context) error {
	e.closeOnce.Do(func() {
		e.closed.Store(true)
		_ = e.conn.Close()
	})
	return nil
}

func (e *OTLPGRPCLogExporter) mapError(err error) *Error {
	st, _ := grpcstatus.FromError(err)
	return OTLPErrorForStatus(st.Code(), RedactText(st.Message(), e.secrets), err)
}

// OTLPErrorForStatus maps a gRPC status to the SDK error: CANCELLED,
// INVALID_ARGUMENT/FAILED_PRECONDITION → VALIDATION, DEADLINE_EXCEEDED →
// TIMEOUT, NOT_FOUND, ALREADY_EXISTS → CONFLICT, PERMISSION_DENIED,
// RESOURCE_EXHAUSTED → RATE_LIMITED, UNIMPLEMENTED → UNSUPPORTED,
// UNAUTHENTICATED → AUTHENTICATION; ABORTED, OUT_OF_RANGE, UNAVAILABLE and
// DATA_LOSS → retryable UNAVAILABLE; anything else → non-retryable UNAVAILABLE.
func OTLPErrorForStatus(code codes.Code, message string, cause error) *Error {
	if message == "" {
		message = "gRPC status " + strconv.Itoa(int(code))
	}
	text := "otlp.export: " + truncate(message, maxVendorText) + " (gRPC " + strconv.Itoa(int(code)) + ")"
	var c ErrorCode
	retryable := false
	switch code {
	case codes.Canceled:
		c = ErrorCodeCancelled
	case codes.InvalidArgument, codes.FailedPrecondition:
		c = ErrorCodeValidation
	case codes.DeadlineExceeded:
		c, retryable = ErrorCodeTimeout, true
	case codes.NotFound:
		c = ErrorCodeNotFound
	case codes.AlreadyExists:
		c = ErrorCodeConflict
	case codes.PermissionDenied:
		c = ErrorCodePermissionDenied
	case codes.ResourceExhausted:
		c, retryable = ErrorCodeRateLimited, true
	case codes.Unimplemented:
		c = ErrorCodeUnsupported
	case codes.Unauthenticated:
		c = ErrorCodeAuthentication
	case codes.Aborted, codes.OutOfRange, codes.Unavailable, codes.DataLoss:
		c, retryable = ErrorCodeUnavailable, true
	default:
		c = ErrorCodeUnavailable
	}
	if errors.Is(cause, context.Canceled) {
		c, retryable = ErrorCodeCancelled, false
	}
	return &Error{Code: c, Message: text, Retryable: retryable, Err: cause}
}

// OTLPExportRequest converts records into one OTLP request: one ResourceLogs
// per distinct resource (first-seen order) with one ScopeLogs each.
func OTLPExportRequest(records []LogRecord) *collogspb.ExportLogsServiceRequest {
	type group struct {
		resource map[string]AttrValue
		logs     []*logspb.LogRecord
	}
	groups := map[string]*group{}
	var order []string
	for _, r := range records {
		b, _ := json.Marshal(NormalizeAttributes(r.Resource)) // normalized values always encode
		key := string(b)
		g, ok := groups[key]
		if !ok {
			g = &group{resource: r.Resource}
			groups[key] = g
			order = append(order, key)
		}
		g.logs = append(g.logs, otlpLogRecord(r))
	}
	req := &collogspb.ExportLogsServiceRequest{}
	for _, k := range order {
		g := groups[k]
		req.ResourceLogs = append(req.ResourceLogs, &logspb.ResourceLogs{
			Resource: &resourcepb.Resource{Attributes: otlpKeyValues(g.resource)},
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope:      &commonpb.InstrumentationScope{Name: OTLPScopeName, Version: Version},
				LogRecords: g.logs,
			}},
		})
	}
	return req
}

func otlpLogRecord(r LogRecord) *logspb.LogRecord {
	lr := &logspb.LogRecord{
		SeverityNumber: logspb.SeverityNumber(r.Severity), // #nosec G115 -- severities are 0..24
		SeverityText:   r.SeverityText,
		Body:           otlpAnyValue(r.Body),
		Attributes:     otlpKeyValues(r.Attributes),
	}
	if lr.SeverityText == "" {
		lr.SeverityText = r.Severity.String()
	}
	if !r.Timestamp.IsZero() {
		lr.TimeUnixNano = uint64(r.Timestamp.UnixNano()) // #nosec G115 -- timestamps after 1970
	}
	if !r.ObservedTimestamp.IsZero() {
		lr.ObservedTimeUnixNano = uint64(r.ObservedTimestamp.UnixNano()) // #nosec G115 -- timestamps after 1970
	}
	if b, err := hex.DecodeString(r.TraceID); err == nil && len(b) == 16 {
		lr.TraceId = b
	}
	if b, err := hex.DecodeString(r.SpanID); err == nil && len(b) == 8 {
		lr.SpanId = b
	}
	if r.TraceFlags != nil {
		lr.Flags = uint32(*r.TraceFlags)
	}
	return lr
}

func otlpKeyValues(m map[string]AttrValue) []*commonpb.KeyValue {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*commonpb.KeyValue, 0, len(keys))
	for _, k := range keys {
		if v := otlpAnyValue(m[k]); v != nil {
			out = append(out, &commonpb.KeyValue{Key: k, Value: v})
		}
	}
	return out
}

func otlpAnyValue(v any) *commonpb.AnyValue {
	switch x := NormalizeAttrValue(v).(type) {
	case string:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: x}}
	case bool:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: x}}
	case int64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: x}}
	case float64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: x}}
	case []AttrValue:
		arr := &commonpb.ArrayValue{}
		for _, e := range x {
			if av := otlpAnyValue(e); av != nil {
				arr.Values = append(arr.Values, av)
			}
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: arr}}
	case map[string]AttrValue:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: otlpKeyValues(x)}}}
	}
	return nil
}

func connectParams(timeout time.Duration) grpc.ConnectParams {
	return grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: timeout}
}
