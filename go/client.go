package graylog

import (
	"context"
	"encoding/base64"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Graylog REST paths.
const (
	pathLBStatus    = "/api/system/lbstatus"
	pathSystem      = "/api/system"
	pathInputs      = "/api/system/inputs"
	pathInputTypes  = "/api/system/inputs/types"
	pathInputStates = "/api/system/inputstates"
	pathStreams     = "/api/streams"
	pathStreamsPage = "/api/streams/paginated"
	pathIndexSets   = "/api/system/indices/index_sets"
	pathFields      = "/api/system/fields"
	pathSearchSync  = "/api/views/search/sync"
	pathMessages    = "/api/messages"
)

// HeaderRequestedBy is Graylog's CSRF guard header; it is required on every
// non-GET request (HTTP 400 without it). The client always sends it.
const HeaderRequestedBy = "X-Requested-By"

// HeaderNodeID is the response header that names the Graylog node.
const HeaderNodeID = "X-Graylog-Node-Id"

// Client is the Graylog Open client. It is safe for concurrent use.
//
// REST functions hang off the client directly: SystemInfo, ListInputs,
// GetInput, ListInputTypes, GetInputState, CreateInput, EnsureGelfInput,
// DeleteInput, ListStreams, GetStream, CreateStream, ResumeStream,
// DeleteStream, ListIndexSets, Search, SearchRelative, GetMessage and
// ListFields. GELF
// ingest goes through NewLogClient (the logging category LogClient) or the
// transports (GelfUDPTransport, GelfTCPTransport, GelfHTTPTransport); stored
// logs are read through LogQuery (LogQueryClient).
type Client struct {
	cfg       Config
	transport *httpTransport
	closeOnce sync.Once

	mu      sync.Mutex
	closers []func()
	closed  bool
}

// NewClient validates cfg and returns a client.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withServiceDefaults()
	t, err := newHTTPTransport(cfg.CommonConfig)
	if err != nil {
		return nil, err
	}
	for _, s := range []string{cfg.APIToken.Reveal(), cfg.Password.Reveal()} {
		if len(s) >= 4 {
			t.addSecret(s)
		}
	}
	if auth := cfg.basicCredentials(); auth != "" {
		t.addSecret(auth)
	}
	return &Client{cfg: cfg, transport: t}, nil
}

// NewClientFromEnv builds a client from the environment (see ConfigFromEnv).
func NewClientFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClient(cfg)
}

// Config returns the effective configuration (defaults applied).
func (c *Client) Config() Config { return c.cfg }

// basicCredentials returns the base64 HTTP Basic credentials: "<token>:token"
// for an API token (it wins), "<user>:<password>" otherwise, "" for none.
func (c Config) basicCredentials() string {
	switch {
	case !c.APIToken.IsZero():
		return base64.StdEncoding.EncodeToString([]byte(c.APIToken.Reveal() + ":token"))
	case c.Username != "":
		return base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password.Reveal()))
	}
	return ""
}

// headers returns the auth and CSRF headers of a request with method.
func (c *Client) headers(method string) http.Header {
	h := http.Header{}
	if auth := c.cfg.basicCredentials(); auth != "" {
		h.Set("Authorization", "Basic "+auth)
	}
	if method != http.MethodGet && method != http.MethodHead {
		h.Set(HeaderRequestedBy, c.cfg.RequestedBy)
	}
	return h
}

// send executes req with the client headers (auth, X-Requested-By).
func (c *Client) send(ctx context.Context, req *request) (*response, error) {
	if c.isClosed() {
		return nil, &Error{Code: ErrorCodeCancelled, Message: req.Operation + ": client is closed"}
	}
	h := c.headers(req.Method)
	for k, vs := range req.Header {
		h[k] = vs
	}
	req.Header = h
	return c.transport.do(ctx, req)
}

// sendJSON executes req and decodes a JSON response into out (when non-nil).
func (c *Client) sendJSON(ctx context.Context, req *request, out any) error {
	res, err := c.send(ctx, req)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return res.decodeJSON(req.Operation, out)
}

// Health checks the unauthenticated load-balancer status (GET
// /api/system/lbstatus, text/plain). ALIVE (200) → healthy, status "ok";
// THROTTLED (429) → "degraded"; DEAD (503) or any other answer →
// "unhealthy"; network errors → "unreachable". Details["lb_status"] holds
// Graylog's word. It fails only for CANCELLED and CONFIG.
func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	res, err := c.transport.do(ctx, &request{
		Method: http.MethodGet, Path: pathLBStatus, Operation: "health",
		Header: http.Header{"Accept": {"text/plain"}}, NoRetry: true, RawStatus: true,
	})
	if err != nil {
		switch CodeOf(err) {
		case ErrorCodeCancelled, ErrorCodeConfig:
			return HealthStatus{}, err
		}
		return HealthStatus{Status: "unreachable", Details: map[string]string{"error": err.Error()}}, nil
	}
	word := truncate(strings.ToUpper(strings.TrimSpace(c.transport.redact(firstLine(res.Body)))), maxVendorText)
	switch {
	case res.Status == http.StatusTooManyRequests:
		return HealthStatus{Status: "degraded", Details: map[string]string{"lb_status": "THROTTLED"}}, nil
	case res.Status == http.StatusServiceUnavailable:
		return HealthStatus{Status: "unhealthy", Details: map[string]string{"lb_status": "DEAD"}}, nil
	case res.Status == http.StatusOK && word == "ALIVE":
		return HealthStatus{Healthy: true, Status: "ok", Details: map[string]string{"lb_status": word}}, nil
	}
	if word == "" {
		word = "HTTP " + strconv.Itoa(res.Status)
	}
	return HealthStatus{Status: "unhealthy", Details: map[string]string{"lb_status": word}}, nil
}

// Ping makes an authenticated round trip (GET /api/system) and returns its
// latency. AUTHENTICATION on bad or missing credentials.
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	if _, err := c.send(ctx, &request{Method: http.MethodGet, Path: pathSystem, Operation: "ping"}); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// SystemInfo describes the Graylog node (GET /api/system).
type SystemInfo struct {
	Facility        string    `json:"facility"`
	Codename        string    `json:"codename"`
	NodeID          string    `json:"node_id"`
	ClusterID       string    `json:"cluster_id"`
	Version         string    `json:"version"`
	StartedAt       time.Time `json:"started_at"`
	Hostname        string    `json:"hostname"`
	Lifecycle       string    `json:"lifecycle"`
	LBStatus        string    `json:"lb_status"`
	Timezone        string    `json:"timezone"`
	OperatingSystem string    `json:"operating_system"`
	IsLeader        bool      `json:"is_leader"`
	IsProcessing    bool      `json:"is_processing"`
}

// SystemInfo returns the node's system information (GET /api/system).
// Version is Graylog's full string, for example "7.0.16+58e0f6e".
func (c *Client) SystemInfo(ctx context.Context) (SystemInfo, error) {
	var info SystemInfo
	err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathSystem, Operation: "systemInfo"}, &info)
	return info, err
}

// ServerVersion returns the version as reported by GET /api/system, for
// example "7.0.16+58e0f6e". UNSUPPORTED when the server reports none.
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	info, err := c.SystemInfo(ctx)
	if err != nil {
		return "", err
	}
	if info.Version == "" {
		return "", UnsupportedError("serverVersion", "the service does not report a version")
	}
	return info.Version, nil
}

// ListFields returns every indexed field name (GET /api/system/fields), sorted.
func (c *Client) ListFields(ctx context.Context) ([]string, error) {
	var body struct {
		Fields []string `json:"fields"`
	}
	if err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathFields, Operation: "listFields"}, &body); err != nil {
		return nil, err
	}
	if body.Fields == nil {
		body.Fields = []string{}
	}
	sort.Strings(body.Fields)
	return body.Fields, nil
}

// onClose registers fn to run on Close (immediately when already closed).
func (c *Client) onClose(fn func()) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		fn()
		return
	}
	c.closers = append(c.closers, fn)
	c.mu.Unlock()
}

// Close flushes and closes the log clients created by this client, stops its
// tails and releases the connections. Later calls fail with CANCELLED. Close
// is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		closers := c.closers
		c.closers = nil
		c.mu.Unlock()
		for _, fn := range closers {
			safeCall(fn)
		}
		c.mu.Lock()
		c.closed = true
		late := c.closers
		c.closers = nil
		c.mu.Unlock()
		for _, fn := range late {
			safeCall(fn)
		}
		c.transport.close()
	})
	return nil
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.transport.closed.Load()
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	line, _, _ := strings.Cut(s, "\n")
	return line
}
