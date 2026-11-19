package graylog

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Graylog input type classes used by EnsureGelfInput and the OTLP helper.
const (
	InputTypeGelfUDP  = "org.graylog2.inputs.gelf.udp.GELFUDPInput"
	InputTypeGelfTCP  = "org.graylog2.inputs.gelf.tcp.GELFTCPInput"
	InputTypeGelfHTTP = "org.graylog2.inputs.gelf.http.GELFHttpInput"
	InputTypeOTelGRPC = "org.graylog.inputs.otel.OTelGrpcInput"
)

// Input states reported by GetInputState.
const (
	InputStateRunning = "RUNNING"
	InputStateFailed  = "FAILED"
)

// Input is a Graylog message input.
type Input struct {
	ID            string    `json:"id"`
	Title         string    `json:"title"`
	Type          string    `json:"type"`
	Name          string    `json:"name"`
	Global        bool      `json:"global"`
	Node          string    `json:"node"`
	CreatedAt     time.Time `json:"created_at"`
	CreatorUserID string    `json:"creator_user_id"`
	// Attributes is the input configuration. Secret attributes come back as
	// {"is_set": bool} objects, never as values.
	Attributes   map[string]any    `json:"attributes"`
	StaticFields map[string]string `json:"static_fields"`
}

// Port returns the "port" attribute (0 when absent).
func (in Input) Port() int { return intAttr(in.Attributes["port"]) }

// BindAddress returns the "bind_address" attribute.
func (in Input) BindAddress() string {
	s, _ := in.Attributes["bind_address"].(string)
	return s
}

func intAttr(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

// InputState is the runtime state of an input (GET /api/system/inputstates/{id}).
type InputState struct {
	ID string `json:"id"`
	// State is RUNNING, STARTING, FAILED, STOPPED, …
	State           string    `json:"state"`
	StartedAt       time.Time `json:"started_at"`
	DetailedMessage string    `json:"detailed_message"`
	Input           Input     `json:"message_input"`
}

// ListInputs returns every input (GET /api/system/inputs).
func (c *Client) ListInputs(ctx context.Context) ([]Input, error) {
	var body struct {
		Inputs []Input `json:"inputs"`
	}
	if err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathInputs, Operation: "listInputs"}, &body); err != nil {
		return nil, err
	}
	if body.Inputs == nil {
		body.Inputs = []Input{}
	}
	return body.Inputs, nil
}

// GetInput returns one input; NOT_FOUND when it does not exist.
func (c *Client) GetInput(ctx context.Context, id string) (Input, error) {
	var in Input
	if err := requireID("getInput", "id", id); err != nil {
		return in, err
	}
	err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathInputs + "/" + id, Operation: "getInput " + id}, &in)
	return in, err
}

// ListInputTypes returns the installed input types (class → display name).
func (c *Client) ListInputTypes(ctx context.Context) (map[string]string, error) {
	var body struct {
		Types map[string]string `json:"types"`
	}
	if err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathInputTypes, Operation: "listInputTypes"}, &body); err != nil {
		return nil, err
	}
	if body.Types == nil {
		body.Types = map[string]string{}
	}
	return body.Types, nil
}

// GetInputState returns the runtime state of an input; NOT_FOUND when the
// input is not running on any node.
func (c *Client) GetInputState(ctx context.Context, id string) (InputState, error) {
	var st InputState
	if err := requireID("getInputState", "id", id); err != nil {
		return st, err
	}
	err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathInputStates + "/" + id, Operation: "getInputState " + id}, &st)
	return st, err
}

// CreateInputOptions configure CreateInput.
type CreateInputOptions struct {
	// Title of the input (default "<class short name> (grow-codes)").
	Title string
	// Node starts the input on one node only; empty means a global input.
	Node string
}

// CreateInput creates an input of class inputType with configuration
// (POST /api/system/inputs) and returns its id. An unknown type is NOT_FOUND
// (Graylog answers 404). Graylog does not reject a busy port at create time:
// the input is created and its state becomes FAILED (see GetInputState or
// EnsureGelfInput).
func (c *Client) CreateInput(ctx context.Context, inputType string, configuration map[string]any, opts CreateInputOptions) (string, error) {
	if err := requireID("createInput", "type", inputType); err != nil {
		return "", err
	}
	title := opts.Title
	if title == "" {
		title = inputType[strings.LastIndex(inputType, ".")+1:] + " (grow-codes)"
	}
	if configuration == nil {
		configuration = map[string]any{}
	}
	body := map[string]any{"title": title, "type": inputType, "global": opts.Node == "", "configuration": configuration}
	if opts.Node != "" {
		body["node"] = opts.Node
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.sendJSON(ctx, &request{Method: http.MethodPost, Path: pathInputs, JSON: body, Operation: "createInput"}, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", &Error{Code: ErrorCodeUnavailable, Message: "createInput: response has no input id", Retryable: true}
	}
	return out.ID, nil
}

// DeleteInput deletes an input (DELETE /api/system/inputs/{id}); NOT_FOUND
// when it does not exist.
func (c *Client) DeleteInput(ctx context.Context, id string) error {
	if err := requireID("deleteInput", "id", id); err != nil {
		return err
	}
	_, err := c.send(ctx, &request{Method: http.MethodDelete, Path: pathInputs + "/" + id, Operation: "deleteInput " + id})
	return err
}

// EnsureGelfInputOptions configure EnsureGelfInput. The zero value is valid.
type EnsureGelfInputOptions struct {
	// Title of a newly created input (default "grow-codes GELF <PROTOCOL> <port>").
	Title string
	// BindAddress of a newly created input (default "0.0.0.0"); an existing
	// input matches when its bind address equals this value.
	BindAddress string
	// Configuration is merged over the default configuration of a new input
	// (for example {"tls_enable": true} or {"enable_bulk_receiving": false}).
	Configuration map[string]any
	// Timeout bounds the wait for the RUNNING state (default 30 s).
	Timeout time.Duration
	// Interval between state polls (default 500 ms).
	Interval time.Duration
}

// gelfInputDefaults is the default configuration per protocol (the same as
// the Docker bootstrap).
func gelfInputDefaults(p GelfProtocol) (string, map[string]any, error) {
	switch p {
	case GelfUDP:
		return InputTypeGelfUDP, map[string]any{
			"recv_buffer_size": 262144, "number_worker_threads": 2, "decompress_size_limit": 8388608,
		}, nil
	case GelfTCP:
		return InputTypeGelfTCP, map[string]any{
			"recv_buffer_size": 1048576, "number_worker_threads": 2, "tls_enable": false, "tcp_keepalive": false,
			"use_null_delimiter": true, "max_message_size": 2097152, "decompress_size_limit": 8388608,
		}, nil
	case GelfHTTP:
		return InputTypeGelfHTTP, map[string]any{
			"recv_buffer_size": 1048576, "number_worker_threads": 2, "tls_enable": false, "tcp_keepalive": false,
			"enable_bulk_receiving": true, "enable_cors": true, "max_chunk_size": 8388608, "idle_writer_timeout": 60,
			"decompress_size_limit": 8388608,
		}, nil
	}
	return "", nil, ValidationError("ensureGelfInput", "protocol must be udp, tcp or http")
}

// EnsuredInput is the result of EnsureGelfInput.
type EnsuredInput struct {
	Input
	// Created reports whether this call created the input.
	Created bool
}

// EnsureGelfInput returns a running GELF input of protocol on port: an
// existing input of the same type, port and bind address is reused, otherwise
// one is created. It then waits until the input is RUNNING; a FAILED input
// (for example a port already used by another input type) is a CONFLICT
// error that carries Graylog's message, TIMEOUT after opts.Timeout. An input
// created by this call is deleted again when it does not start.
func (c *Client) EnsureGelfInput(ctx context.Context, protocol GelfProtocol, port int, opts EnsureGelfInputOptions) (EnsuredInput, error) {
	const op = "ensureGelfInput"
	inputType, defaults, err := gelfInputDefaults(protocol)
	if err != nil {
		return EnsuredInput{}, err
	}
	if port < 1 || port > 65535 {
		return EnsuredInput{}, ValidationError(op, "port must be an integer 1..65535")
	}
	bind := opts.BindAddress
	if bind == "" {
		bind = "0.0.0.0"
	}
	find := func() (Input, bool, error) {
		inputs, err := c.ListInputs(ctx)
		if err != nil {
			return Input{}, false, err
		}
		for _, in := range inputs {
			if in.Type == inputType && in.Port() == port && (in.BindAddress() == "" || in.BindAddress() == bind) {
				return in, true, nil
			}
		}
		return Input{}, false, nil
	}
	in, found, err := find()
	if err != nil {
		return EnsuredInput{}, err
	}
	created := false
	if !found {
		cfg := defaults
		for k, v := range opts.Configuration {
			cfg[k] = v
		}
		cfg["bind_address"] = bind
		cfg["port"] = port
		title := opts.Title
		if title == "" {
			title = fmt.Sprintf("grow-codes GELF %s %d", strings.ToUpper(string(protocol)), port)
		}
		id, cerr := c.CreateInput(ctx, inputType, cfg, CreateInputOptions{Title: title})
		if cerr != nil {
			// The create may have reached the server; re-list before failing.
			again, ok, lerr := find()
			if lerr != nil || !ok {
				return EnsuredInput{}, cerr
			}
			in = again
		} else {
			created = true
			if in, err = c.GetInput(ctx, id); err != nil {
				return EnsuredInput{}, err
			}
		}
	}
	timeout, interval := opts.Timeout, opts.Interval
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	_, err = PollUntil(ctx, op, timeout, interval, func(ctx context.Context) (InputState, bool, error) {
		st, err := c.GetInputState(ctx, in.ID)
		switch {
		case CodeOf(err) == ErrorCodeNotFound:
			return st, false, nil // not started yet
		case err != nil:
			return st, false, err
		case st.State == InputStateFailed:
			msg := fmt.Sprintf("%s %s:%d: input failed to start", op, protocol, port)
			if st.DetailedMessage != "" {
				msg += ": " + truncate(c.transport.redact(st.DetailedMessage), maxVendorText)
			}
			return st, false, &Error{Code: ErrorCodeConflict, Message: msg}
		}
		return st, st.State == InputStateRunning, nil
	})
	if err != nil {
		if created && CodeOf(err) != ErrorCodeCancelled {
			_ = c.DeleteInput(context.WithoutCancel(ctx), in.ID)
		}
		return EnsuredInput{}, err
	}
	return EnsuredInput{Input: in, Created: created}, nil
}

// StreamRule is one rule of a stream. Type: 1 exact match, 2 regex, 3 greater
// than, 4 smaller than, 5 field presence, 6 contains, 7 always match,
// 8 match input.
type StreamRule struct {
	ID          string `json:"id,omitempty"`
	Field       string `json:"field"`
	Type        int    `json:"type"`
	Value       string `json:"value"`
	Inverted    bool   `json:"inverted"`
	Description string `json:"description"`
}

// Stream rule types.
const (
	StreamRuleExact       = 1
	StreamRuleRegex       = 2
	StreamRuleGreater     = 3
	StreamRuleSmaller     = 4
	StreamRulePresence    = 5
	StreamRuleContains    = 6
	StreamRuleAlwaysMatch = 7
	StreamRuleMatchInput  = 8
)

// Stream is a Graylog stream.
type Stream struct {
	ID                             string       `json:"id"`
	Title                          string       `json:"title"`
	Description                    string       `json:"description"`
	Rules                          []StreamRule `json:"rules"`
	Disabled                       bool         `json:"disabled"`
	IndexSetID                     string       `json:"index_set_id"`
	IsDefault                      bool         `json:"is_default"`
	MatchingType                   string       `json:"matching_type"`
	RemoveMatchesFromDefaultStream bool         `json:"remove_matches_from_default_stream"`
	CreatedAt                      time.Time    `json:"created_at"`
	CreatorUserID                  string       `json:"creator_user_id"`
}

// ListStreamsOptions page through streams. The zero value is page 1, 50 per
// page, sorted by title ascending.
type ListStreamsOptions struct {
	// Page is 1-based (default 1).
	Page int
	// PerPage is the page size (default 50).
	PerPage int
	// Query filters by Graylog's stream search syntax (for example a title).
	Query string
	// Sort is the sort field (default "title").
	Sort string
	// Order is asc (default) or desc.
	Order SortOrder
}

// StreamPage is one page of streams.
type StreamPage struct {
	Streams []Stream
	// Total is the number of streams matching the query.
	Total   int
	Page    int
	PerPage int
}

// ListStreams returns one page of streams (GET /api/streams/paginated).
func (c *Client) ListStreams(ctx context.Context, opts ListStreamsOptions) (StreamPage, error) {
	if opts.Page <= 0 {
		opts.Page = 1
	}
	if opts.PerPage <= 0 {
		opts.PerPage = 50
	}
	if opts.Sort == "" {
		opts.Sort = "title"
	}
	if opts.Order == "" {
		opts.Order = OrderAsc
	}
	if opts.Order != OrderAsc && opts.Order != OrderDesc {
		return StreamPage{}, ValidationError("listStreams", `order must be "asc" or "desc"`)
	}
	q := url.Values{
		"page": {strconv.Itoa(opts.Page)}, "per_page": {strconv.Itoa(opts.PerPage)},
		"sort": {opts.Sort}, "order": {string(opts.Order)},
	}
	if opts.Query != "" {
		q.Set("query", opts.Query)
	}
	var body struct {
		Pagination struct {
			Total   int `json:"total"`
			Page    int `json:"page"`
			PerPage int `json:"per_page"`
		} `json:"pagination"`
		Elements []Stream `json:"elements"`
	}
	if err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathStreamsPage, Query: q, Operation: "listStreams"}, &body); err != nil {
		return StreamPage{}, err
	}
	page := StreamPage{Streams: body.Elements, Total: body.Pagination.Total, Page: body.Pagination.Page, PerPage: body.Pagination.PerPage}
	if page.Streams == nil {
		page.Streams = []Stream{}
	}
	return page, nil
}

// listAllStreams follows ListStreams pages and returns every stream.
func (c *Client) listAllStreams(ctx context.Context) ([]Stream, error) {
	out := []Stream{}
	for page := 1; ; page++ {
		p, err := c.ListStreams(ctx, ListStreamsOptions{Page: page, PerPage: 100})
		if err != nil {
			return nil, err
		}
		out = append(out, p.Streams...)
		if len(p.Streams) == 0 || len(out) >= p.Total {
			return out, nil
		}
	}
}

// GetStream returns one stream; NOT_FOUND when it does not exist.
func (c *Client) GetStream(ctx context.Context, id string) (Stream, error) {
	var s Stream
	if err := requireID("getStream", "id", id); err != nil {
		return s, err
	}
	err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathStreams + "/" + id, Operation: "getStream " + id}, &s)
	return s, err
}

// CreateStreamOptions describe a new stream. Title is required.
type CreateStreamOptions struct {
	Title       string
	Description string
	// IndexSetID is the target index set (default: the default index set, else
	// the first one).
	IndexSetID string
	Rules      []StreamRule
	// MatchingType is "AND" (default: all rules must match) or "OR".
	MatchingType                   string
	RemoveMatchesFromDefaultStream bool
	// Disabled keeps the new stream paused. Graylog creates streams paused;
	// CreateStream resumes them unless Disabled is set.
	Disabled bool
}

// CreateStream creates a stream (POST /api/streams) and, unless
// opts.Disabled, resumes it so it starts routing messages. It returns the
// stream id.
func (c *Client) CreateStream(ctx context.Context, opts CreateStreamOptions) (string, error) {
	const op = "createStream"
	if strings.TrimSpace(opts.Title) == "" {
		return "", ValidationError(op, "title is required")
	}
	if opts.MatchingType == "" {
		opts.MatchingType = "AND"
	}
	opts.MatchingType = strings.ToUpper(opts.MatchingType)
	if opts.MatchingType != "AND" && opts.MatchingType != "OR" {
		return "", ValidationError(op, `matchingType must be "AND" or "OR"`)
	}
	if opts.IndexSetID == "" {
		sets, err := c.ListIndexSets(ctx)
		if err != nil {
			return "", err
		}
		for _, s := range sets {
			if s.Default {
				opts.IndexSetID = s.ID
				break
			}
		}
		if opts.IndexSetID == "" && len(sets) > 0 {
			opts.IndexSetID = sets[0].ID
		}
		if opts.IndexSetID == "" {
			return "", ValidationError(op, "no index set available")
		}
	}
	rules := make([]StreamRule, len(opts.Rules))
	for i, r := range opts.Rules {
		r.ID = ""
		rules[i] = r
	}
	entity := map[string]any{
		"title": opts.Title, "description": opts.Description, "index_set_id": opts.IndexSetID,
		"matching_type": opts.MatchingType, "remove_matches_from_default_stream": opts.RemoveMatchesFromDefaultStream,
		"rules": rules,
	}
	var out struct {
		StreamID string `json:"stream_id"`
	}
	if err := c.sendJSON(ctx, &request{Method: http.MethodPost, Path: pathStreams, JSON: map[string]any{"entity": entity}, Operation: op}, &out); err != nil {
		return "", err
	}
	if out.StreamID == "" {
		return "", &Error{Code: ErrorCodeUnavailable, Message: op + ": response has no stream id", Retryable: true}
	}
	if !opts.Disabled {
		if err := c.ResumeStream(ctx, out.StreamID); err != nil {
			return out.StreamID, err
		}
	}
	return out.StreamID, nil
}

// ResumeStream starts a paused stream (POST /api/streams/{id}/resume).
func (c *Client) ResumeStream(ctx context.Context, id string) error {
	if err := requireID("resumeStream", "id", id); err != nil {
		return err
	}
	_, err := c.send(ctx, &request{Method: http.MethodPost, Path: pathStreams + "/" + id + "/resume", Idempotent: true, Operation: "resumeStream " + id})
	return err
}

// DeleteStream deletes a stream (DELETE /api/streams/{id}); NOT_FOUND when
// it does not exist.
func (c *Client) DeleteStream(ctx context.Context, id string) error {
	if err := requireID("deleteStream", "id", id); err != nil {
		return err
	}
	_, err := c.send(ctx, &request{Method: http.MethodDelete, Path: pathStreams + "/" + id, Operation: "deleteStream " + id})
	return err
}

// IndexSet is a Graylog index set.
type IndexSet struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IndexPrefix string `json:"index_prefix"`
	Default     bool   `json:"default"`
	Writable    bool   `json:"writable"`
	Shards      int    `json:"shards"`
	Replicas    int    `json:"replicas"`
}

// ListIndexSets returns every index set (GET /api/system/indices/index_sets).
func (c *Client) ListIndexSets(ctx context.Context) ([]IndexSet, error) {
	var body struct {
		IndexSets []IndexSet `json:"index_sets"`
	}
	q := url.Values{"skip_stats": {"true"}}
	if err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathIndexSets, Query: q, Operation: "listIndexSets"}, &body); err != nil {
		return nil, err
	}
	if body.IndexSets == nil {
		body.IndexSets = []IndexSet{}
	}
	return body.IndexSets, nil
}

func requireID(op, name, value string) error {
	if strings.TrimSpace(value) == "" {
		return ValidationError(op, name+" is required")
	}
	if strings.Contains(value, "/") {
		return ValidationError(op, name+" must not contain '/'")
	}
	return nil
}
