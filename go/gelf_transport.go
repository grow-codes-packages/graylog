package graylog

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// GelfSendOptions are per-call options of GelfTransport.Send.
type GelfSendOptions struct {
	// Gzip overrides the HTTP transport's compression for this call (nil =
	// the transport default). UDP and TCP ignore it.
	Gzip *bool
}

// GelfSendResult is the outcome of GelfTransport.Send.
type GelfSendResult struct {
	// Sent is the number of messages handed to the network.
	Sent int
	// Rejected is the number of messages rejected client-side (for example
	// too large for UDP).
	Rejected int
	// Error says why messages were rejected.
	Error *Error
}

// GelfTransport sends GELF messages to a Graylog input. Implementations are
// safe for concurrent use.
type GelfTransport interface {
	// Protocol returns udp, tcp or http.
	Protocol() GelfProtocol
	// Send delivers messages in order. Network failures are returned as errors
	// (UNAVAILABLE, TIMEOUT, CANCELLED); client-side rejections are counted in
	// the result. A closed transport returns a CONFIG error.
	Send(ctx context.Context, messages []*GelfMessage, opts GelfSendOptions) (GelfSendResult, error)
	// Close releases sockets. It is idempotent.
	Close() error
}

// GelfCompression is the payload compression of the UDP transport.
type GelfCompression string

// GELF UDP compressions.
const (
	GelfCompressionGzip GelfCompression = "gzip"
	GelfCompressionZlib GelfCompression = "zlib"
	GelfCompressionNone GelfCompression = "none"
)

// GELF UDP chunking constants.
const (
	// GelfChunkHeaderSize is the chunk header: magic 0x1e 0x0f (2), message id
	// (8), sequence number (1), sequence count (1).
	GelfChunkHeaderSize = 12
	// GelfMaxChunks is the GELF limit of chunks per message.
	GelfMaxChunks = 128
	// DefaultUDPChunkSize is the default datagram size including the chunk
	// header (fits a 1500-byte Ethernet MTU).
	DefaultUDPChunkSize = 1420
)

func checkHostPort(op, host string, port int) (string, error) {
	if host == "" {
		return "", ConfigError(op + ": host must not be blank")
	}
	if port < 1 || port > 65535 {
		return "", ConfigError(op + ": port must be an integer 1..65535")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func gelfNetworkError(op string, err error) *Error {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return &Error{Code: ErrorCodeTimeout, Message: op + ": timeout", Retryable: true, Err: err}
	}
	return &Error{Code: ErrorCodeUnavailable, Message: op + ": network error: " + innerMessage(err), Retryable: true, Err: err}
}

func closedError(op string) *Error { return ConfigError(op + ": transport is closed") }

func nonNil(op string, messages []*GelfMessage) error {
	for _, m := range messages {
		if m == nil {
			return ValidationError(op, "message is nil")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// UDP

// GelfUDPOptions configure a GelfUDPTransport.
type GelfUDPOptions struct {
	// Host of the GELF UDP input (required) and Port (default 12201).
	Host string
	Port int
	// Compression is gzip (default), zlib or none; applied before chunking.
	Compression GelfCompression
	// ChunkSize is the datagram size including the 12-byte chunk header
	// (64..65507, default 1420).
	ChunkSize int
}

// GelfUDPTransport sends fire-and-forget datagrams: compressed, chunked up to
// 128 chunks. Delivery is best-effort (UDP has no acknowledgement).
type GelfUDPTransport struct {
	addr        string
	compression GelfCompression
	chunkSize   int

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

var _ GelfTransport = (*GelfUDPTransport)(nil)

// NewGelfUDPTransport validates opts (CONFIG error) and returns a transport;
// the socket is opened on first use.
func NewGelfUDPTransport(opts GelfUDPOptions) (*GelfUDPTransport, error) {
	if opts.Port == 0 {
		opts.Port = DefaultGelfPort
	}
	addr, err := checkHostPort("gelf.udp", opts.Host, opts.Port)
	if err != nil {
		return nil, err
	}
	switch opts.Compression {
	case "":
		opts.Compression = GelfCompressionGzip
	case GelfCompressionGzip, GelfCompressionZlib, GelfCompressionNone:
	default:
		return nil, ConfigError("gelf.udp: compression must be gzip, zlib or none")
	}
	if opts.ChunkSize == 0 {
		opts.ChunkSize = DefaultUDPChunkSize
	}
	if opts.ChunkSize < 64 || opts.ChunkSize > 65507 {
		return nil, ConfigError("gelf.udp: chunkSize must be an integer 64..65507")
	}
	return &GelfUDPTransport{addr: addr, compression: opts.Compression, chunkSize: opts.ChunkSize}, nil
}

// Protocol returns GelfUDP.
func (t *GelfUDPTransport) Protocol() GelfProtocol { return GelfUDP }

func compress(c GelfCompression, payload []byte) []byte {
	var buf bytes.Buffer
	var w io.WriteCloser
	switch c {
	case GelfCompressionGzip:
		w = gzip.NewWriter(&buf)
	case GelfCompressionZlib:
		w = zlib.NewWriter(&buf)
	default:
		return payload
	}
	_, _ = w.Write(payload) // writes to a bytes.Buffer cannot fail
	_ = w.Close()
	return buf.Bytes()
}

// EncodeGelfUDP compresses payload and splits it into datagrams: one datagram
// when it fits chunkSize, else chunks "0x1e 0x0f | id(8) | seq | count | data".
// More than 128 chunks is a VALIDATION error. A nil messageID uses a random id;
// chunkSize 0 means 1420 and compression "" means gzip.
func EncodeGelfUDP(payload []byte, compression GelfCompression, chunkSize int, messageID []byte) ([][]byte, error) {
	if compression == "" {
		compression = GelfCompressionGzip
	}
	if chunkSize == 0 {
		chunkSize = DefaultUDPChunkSize
	}
	if chunkSize <= GelfChunkHeaderSize {
		return nil, ValidationError("gelf.udp", "chunk size must exceed the 12-byte header")
	}
	data := compress(compression, payload)
	if len(data) <= chunkSize {
		return [][]byte{data}, nil
	}
	per := chunkSize - GelfChunkHeaderSize
	count := (len(data) + per - 1) / per
	if count > GelfMaxChunks {
		return nil, ValidationError("gelf.udp", "message needs "+strconv.Itoa(count)+" chunks (max 128); use TCP or HTTP for large messages")
	}
	id := make([]byte, 8)
	if messageID != nil {
		copy(id, messageID)
	} else {
		_, _ = rand.Read(id) // crypto/rand.Read never fails on supported platforms
	}
	out := make([][]byte, 0, count)
	for seq := 0; seq < count; seq++ {
		part := data[seq*per : min((seq+1)*per, len(data))]
		chunk := make([]byte, 0, GelfChunkHeaderSize+len(part))
		chunk = append(chunk, 0x1e, 0x0f)
		chunk = append(chunk, id...)
		chunk = append(chunk, byte(seq), byte(count)) // #nosec G115 -- count <= 128
		chunk = append(chunk, part...)
		out = append(out, chunk)
	}
	return out, nil
}

// Send writes every message as one or more datagrams. Messages that need
// more than 128 chunks are rejected (counted, not sent).
func (t *GelfUDPTransport) Send(ctx context.Context, messages []*GelfMessage, _ GelfSendOptions) (GelfSendResult, error) {
	var res GelfSendResult
	if err := nonNil("gelf.udp", messages); err != nil {
		return res, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return res, closedError("gelf.udp")
	}
	for _, m := range messages {
		if err := ctx.Err(); err != nil {
			return res, ContextError("gelf.udp", err)
		}
		datagrams, err := EncodeGelfUDP(m.Encode(), t.compression, t.chunkSize, nil)
		if err != nil {
			res.Rejected++
			var gerr *Error
			if errors.As(err, &gerr) {
				res.Error = gerr
			}
			continue
		}
		if t.conn == nil {
			d := net.Dialer{}
			conn, err := d.DialContext(ctx, "udp", t.addr)
			if err != nil {
				return res, gelfNetworkError("gelf.udp", err)
			}
			t.conn = conn
		}
		for _, d := range datagrams {
			if _, err := t.conn.Write(d); err != nil {
				_ = t.conn.Close()
				t.conn = nil
				return res, gelfNetworkError("gelf.udp", err)
			}
		}
		res.Sent++
	}
	return res, nil
}

// Close closes the socket. It is idempotent.
func (t *GelfUDPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// TCP

// GelfTCPOptions configure a GelfTCPTransport.
type GelfTCPOptions struct {
	// Host of the GELF TCP input (required) and Port (default 12201).
	Host string
	Port int
	// TLS enables TLS with TLSConfig (the input needs tls_enable). ServerName
	// overrides the SNI / verification name (default Host).
	TLS        bool
	TLSConfig  TLSConfig
	ServerName string
	// ConnectTimeout (default 10 s) and WriteTimeout (default 30 s).
	ConnectTimeout time.Duration
	WriteTimeout   time.Duration
	// Retry controls reconnects: a batch whose connect or write fails is
	// re-sent on a new connection up to Retry.MaxRetries times with
	// full-jitter backoff (nil = DefaultRetryPolicy()).
	Retry *RetryPolicy
}

// GelfTCPTransport sends NUL-terminated JSON frames over one long-lived
// connection (input option use_null_delimiter). Batches never interleave. A
// connection closed by the server is detected before each batch and
// re-opened; a failed batch is re-sent on a new connection (at-least-once).
type GelfTCPTransport struct {
	addr   string
	opts   GelfTCPOptions
	retry  RetryPolicy
	tlsCfg *tls.Config

	mu     sync.Mutex
	conn   net.Conn
	closed bool
	sleep  func(ctx context.Context, d time.Duration) error
	// Connections counts the connections opened so far (diagnostics).
	connections int
}

var _ GelfTransport = (*GelfTCPTransport)(nil)

// NewGelfTCPTransport validates opts (CONFIG error) and returns a transport;
// the connection is opened on first use.
func NewGelfTCPTransport(opts GelfTCPOptions) (*GelfTCPTransport, error) {
	if opts.Port == 0 {
		opts.Port = DefaultGelfPort
	}
	addr, err := checkHostPort("gelf.tcp", opts.Host, opts.Port)
	if err != nil {
		return nil, err
	}
	if opts.ConnectTimeout < 0 || opts.WriteTimeout < 0 {
		return nil, ConfigError("gelf.tcp: timeouts must be positive")
	}
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = DefaultConnectTimeout
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = DefaultRequestTimeout
	}
	retry := DefaultRetryPolicy()
	if opts.Retry != nil {
		retry = opts.Retry.withDefaults()
	}
	t := &GelfTCPTransport{addr: addr, opts: opts, retry: retry, sleep: sleepContext}
	if opts.TLS {
		cfg, err := buildTLS(opts.TLSConfig)
		if err != nil {
			return nil, err
		}
		cfg.ServerName = opts.ServerName
		if cfg.ServerName == "" {
			cfg.ServerName = opts.Host
		}
		t.tlsCfg = cfg
	}
	return t, nil
}

// Protocol returns GelfTCP.
func (t *GelfTCPTransport) Protocol() GelfProtocol { return GelfTCP }

// Secure reports whether the transport uses TLS.
func (t *GelfTCPTransport) Secure() bool { return t.tlsCfg != nil }

// Connections returns the number of connections opened so far.
func (t *GelfTCPTransport) Connections() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connections
}

// FrameGelfTCP encodes messages as NUL-terminated JSON frames.
func FrameGelfTCP(messages []*GelfMessage) []byte {
	var buf bytes.Buffer
	for _, m := range messages {
		buf.Write(m.Encode())
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func (t *GelfTCPTransport) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: t.opts.ConnectTimeout, KeepAlive: 30 * time.Second}
	if t.tlsCfg != nil {
		td := &tls.Dialer{NetDialer: d, Config: t.tlsCfg}
		return td.DialContext(ctx, "tcp", t.addr)
	}
	return d.DialContext(ctx, "tcp", t.addr)
}

// alive reports whether conn is still open: Graylog never writes on a GELF
// TCP connection, so a read that does not time out means EOF or a reset.
func alive(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	var b [1]byte
	_, err := conn.Read(b[:])
	_ = conn.SetReadDeadline(time.Time{})
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

// Send writes all messages as NUL-terminated frames in one write.
func (t *GelfTCPTransport) Send(ctx context.Context, messages []*GelfMessage, _ GelfSendOptions) (GelfSendResult, error) {
	if err := nonNil("gelf.tcp", messages); err != nil {
		return GelfSendResult{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return GelfSendResult{}, closedError("gelf.tcp")
	}
	if len(messages) == 0 {
		return GelfSendResult{}, nil
	}
	data := FrameGelfTCP(messages)
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return GelfSendResult{}, ContextError("gelf.tcp", err)
		}
		err := t.write(ctx, data)
		if err == nil {
			return GelfSendResult{Sent: len(messages)}, nil
		}
		if ctx.Err() != nil {
			return GelfSendResult{}, ContextError("gelf.tcp", ctx.Err())
		}
		if attempt >= t.retry.MaxRetries {
			return GelfSendResult{}, gelfNetworkError("gelf.tcp", err)
		}
		if serr := t.sleep(ctx, t.retry.Backoff(attempt)); serr != nil {
			return GelfSendResult{}, ContextError("gelf.tcp", serr)
		}
	}
}

// write sends data on the current (or a new) connection; on failure the
// connection is dropped.
func (t *GelfTCPTransport) write(ctx context.Context, data []byte) error {
	if t.conn != nil && !alive(t.conn) {
		_ = t.conn.Close()
		t.conn = nil
	}
	if t.conn == nil {
		conn, err := t.dial(ctx)
		if err != nil {
			return err
		}
		t.conn = conn
		t.connections++
	}
	deadline := time.Now().Add(t.opts.WriteTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = t.conn.SetWriteDeadline(deadline)
	if _, err := t.conn.Write(data); err != nil {
		_ = t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

// Close closes the connection. It is idempotent.
func (t *GelfTCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// HTTP

// GelfHTTPOptions configure a GelfHTTPTransport.
type GelfHTTPOptions struct {
	// URL of the GELF HTTP input, for example http://graylog:12202/gelf.
	URL string
	// DisableGzip sends uncompressed bodies (gzip is on by default).
	DisableGzip bool
	// DisableBulk posts one request per message, for inputs without
	// enable_bulk_receiving. By default a batch is one newline-delimited body.
	DisableBulk bool
	// Headers are extra request headers (for example the input's optional
	// authorization header); sensitive values are redacted.
	Headers map[string]string
	// Config supplies timeouts, retries, TLS, proxy, hooks and logger; its URL
	// and Headers are ignored. Zero values mean the defaults.
	Config CommonConfig
}

// GelfHTTPTransport posts GELF messages to a GELF HTTP input (202 Accepted).
// Graylog answers 202 even for invalid JSON or a missing short_message and
// drops the message, so messages are validated when they are built.
type GelfHTTPTransport struct {
	path      string
	transport *httpTransport
	gzip      bool
	bulk      bool
}

var _ GelfTransport = (*GelfHTTPTransport)(nil)

// NewGelfHTTPTransport validates opts (CONFIG error) and returns a transport.
func NewGelfHTTPTransport(opts GelfHTTPOptions) (*GelfHTTPTransport, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ConfigError("gelf.http: url must be an http(s) URL")
	}
	cfg := opts.Config
	cfg.URL = u.Scheme + "://" + u.Host
	cfg.Headers = opts.Headers
	cfg = cfg.withDefaults(cfg.URL)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	t, err := newHTTPTransport(cfg)
	if err != nil {
		return nil, err
	}
	path := u.Path
	if path == "" {
		path = "/gelf"
	}
	return &GelfHTTPTransport{path: path, transport: t, gzip: !opts.DisableGzip, bulk: !opts.DisableBulk}, nil
}

// Protocol returns GelfHTTP.
func (t *GelfHTTPTransport) Protocol() GelfProtocol { return GelfHTTP }

// Send posts messages: one newline-delimited (bulk) body per call, or one
// request per message without bulk. Bodies are gzip-compressed unless
// disabled (opts.Gzip overrides the transport default).
func (t *GelfHTTPTransport) Send(ctx context.Context, messages []*GelfMessage, opts GelfSendOptions) (GelfSendResult, error) {
	var res GelfSendResult
	if err := nonNil("gelf.http", messages); err != nil {
		return res, err
	}
	if t.transport.closed.Load() {
		return res, closedError("gelf.http")
	}
	gz := t.gzip
	if opts.Gzip != nil {
		gz = *opts.Gzip
	}
	groups := make([][]*GelfMessage, 0, len(messages))
	if t.bulk && len(messages) > 0 {
		groups = append(groups, messages)
	} else {
		for _, m := range messages {
			groups = append(groups, []*GelfMessage{m})
		}
	}
	for _, g := range groups {
		parts := make([][]byte, len(g))
		for i, m := range g {
			parts[i] = m.Encode()
		}
		body := bytes.Join(parts, []byte("\n"))
		h := http.Header{HeaderRequestedBy: {DefaultRequestedBy}}
		if gz {
			body = compress(GelfCompressionGzip, body)
			h.Set("Content-Encoding", "gzip")
		}
		if _, err := t.transport.do(ctx, &request{
			Method: http.MethodPost, Path: t.path, Body: body, ContentType: "application/json",
			Header: h, Operation: "gelf.http",
		}); err != nil {
			return res, err
		}
		res.Sent += len(g)
	}
	return res, nil
}

// Close releases idle connections. It is idempotent.
func (t *GelfHTTPTransport) Close() error {
	t.transport.close()
	return nil
}
