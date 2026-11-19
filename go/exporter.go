package graylog

import (
	"context"
	"errors"
	"time"
)

// GelfLogExporter is the LogExporter of the logging category: it converts
// records with GelfMessageFromLogRecord and sends them through a GelfTransport.
type GelfLogExporter struct {
	transport GelfTransport
	opts      FromLogRecordOptions
}

var _ LogExporter = (*GelfLogExporter)(nil)

// NewGelfLogExporter returns an exporter over transport; opts.Host is the
// GELF host of records without Resource["host.name"].
func NewGelfLogExporter(transport GelfTransport, opts FromLogRecordOptions) *GelfLogExporter {
	return &GelfLogExporter{transport: transport, opts: opts}
}

// Transport returns the underlying transport.
func (e *GelfLogExporter) Transport() GelfTransport { return e.transport }

// Export converts and sends records; ExportOptions.Gzip is passed to the
// transport (only HTTP uses it). Client-side rejections are counted.
func (e *GelfLogExporter) Export(ctx context.Context, records []LogRecord, opts ExportOptions) (ExportResult, error) {
	msgs := make([]*GelfMessage, len(records))
	for i, r := range records {
		msgs[i] = GelfMessageFromLogRecord(r, e.opts)
	}
	gz := opts.Gzip
	res, err := e.transport.Send(ctx, msgs, GelfSendOptions{Gzip: &gz})
	if err != nil {
		out := ExportResult{Accepted: res.Sent, Rejected: len(records) - res.Sent}
		var gerr *Error
		if errors.As(err, &gerr) {
			out.Error = gerr
		}
		return out, err
	}
	return ExportResult{Accepted: res.Sent, Rejected: res.Rejected, Error: res.Error}, nil
}

// Shutdown closes the transport.
func (e *GelfLogExporter) Shutdown(context.Context) error { return e.transport.Close() }

// GelfTransportOptions tune the transport built by Client.GelfTransport.
type GelfTransportOptions struct {
	// Compression of UDP payloads (default gzip).
	Compression GelfCompression
	// ChunkSize of UDP datagrams (default 1420).
	ChunkSize int
	// DisableBulk posts one HTTP request per message.
	DisableBulk bool
	// Headers are extra HTTP headers (for example the input's authorization header).
	Headers map[string]string
}

// GelfTransport builds a GELF transport from the configuration for protocol
// ("" = Config.GelfProtocol): host GelfHost, port GelfPortFor(protocol), HTTP
// URL GelfHTTPEndpoint, TLS for TCP with GelfTLS. TCP and HTTP share the
// client's timeouts and retry policy; HTTP also its TLS, proxy, hooks and
// logger. The caller owns the transport (Close it when done).
func (c *Client) GelfTransport(protocol GelfProtocol, opts GelfTransportOptions) (GelfTransport, error) {
	cfg := c.cfg
	if protocol == "" {
		protocol = cfg.GelfProtocol
	}
	switch protocol {
	case GelfUDP:
		return NewGelfUDPTransport(GelfUDPOptions{
			Host: cfg.GelfHost, Port: cfg.GelfPortFor(GelfUDP), Compression: opts.Compression, ChunkSize: opts.ChunkSize,
		})
	case GelfTCP:
		return NewGelfTCPTransport(GelfTCPOptions{
			Host: cfg.GelfHost, Port: cfg.GelfPortFor(GelfTCP), TLS: cfg.GelfTLS, TLSConfig: cfg.TLS,
			ConnectTimeout: cfg.ConnectTimeout, WriteTimeout: cfg.RequestTimeout, Retry: cfg.Retry,
		})
	case GelfHTTP:
		return NewGelfHTTPTransport(GelfHTTPOptions{
			URL: cfg.GelfHTTPEndpoint(), Config: cfg.CommonConfig, DisableBulk: opts.DisableBulk, Headers: opts.Headers,
		})
	}
	return nil, ValidationError("gelfTransport", "protocol must be udp, tcp or http")
}

// LogOptions configure Client.NewLogClient: the batching options plus the
// transport choice.
type LogOptions struct {
	LogClientOptions
	// Protocol is udp, tcp, http or ProtocolOTLP ("" = Config.GelfProtocol).
	Protocol GelfProtocol
	// Host is the GELF host of records without Resource["host.name"]
	// (default: the local host name).
	Host string
	// Transport is used instead of building one (it is closed with the log client).
	Transport GelfTransport
	// Compression of UDP payloads (default gzip).
	Compression GelfCompression
	// ChunkSize of UDP datagrams (default 1420).
	ChunkSize int
	// DisableBulk posts one HTTP request per message.
	DisableBulk bool
	// Headers are extra HTTP headers or OTLP gRPC metadata.
	Headers map[string]string
	// BearerToken is the OTLP input's bearer token.
	BearerToken Secret
}

// NewLogClient returns a batching LogClient that sends through GELF (udp,
// tcp, http) or OTLP/gRPC (ProtocolOTLP, endpoint Config.OTLPGRPCEndpoint).
// Close of the Client flushes and closes it. A closed Client returns a
// CANCELLED error.
func (c *Client) NewLogClient(opts LogOptions) (*BatchingLogClient, error) {
	if c.isClosed() {
		return nil, &Error{Code: ErrorCodeCancelled, Message: "logClient: client is closed"}
	}
	protocol := opts.Protocol
	if protocol == "" {
		protocol = c.cfg.GelfProtocol
	}
	var exporter LogExporter
	if protocol == ProtocolOTLP {
		exp, err := NewOTLPGRPCLogExporter(OTLPGRPCLogExporterOptions{
			Endpoint: c.cfg.OTLPGRPCEndpoint(), Timeout: c.cfg.RequestTimeout, ConnectTimeout: c.cfg.ConnectTimeout,
			TLS: c.cfg.TLS, BearerToken: opts.BearerToken, Headers: opts.Headers,
		})
		if err != nil {
			return nil, err
		}
		exporter = exp
	} else {
		t := opts.Transport
		if t == nil {
			var err error
			t, err = c.GelfTransport(protocol, GelfTransportOptions{
				Compression: opts.Compression, ChunkSize: opts.ChunkSize, DisableBulk: opts.DisableBulk, Headers: opts.Headers,
			})
			if err != nil {
				return nil, err
			}
		}
		exporter = NewGelfLogExporter(t, FromLogRecordOptions{Host: opts.Host})
	}
	lc, err := c.NewLogClientWithExporter(exporter, opts.LogClientOptions)
	if err != nil {
		_ = exporter.Shutdown(context.Background())
		return nil, err
	}
	return lc, nil
}

// NewLogClientWithExporter returns a batching LogClient for any exporter.
// Close of the Client flushes and closes it. A closed Client returns a
// CANCELLED error.
func (c *Client) NewLogClientWithExporter(exporter LogExporter, opts LogClientOptions) (*BatchingLogClient, error) {
	if c.isClosed() {
		return nil, &Error{Code: ErrorCodeCancelled, Message: "logClient: client is closed"}
	}
	lc, err := NewBatchingLogClient(exporter, opts)
	if err != nil {
		return nil, err
	}
	c.onClose(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = lc.Close(ctx)
	})
	return lc, nil
}
