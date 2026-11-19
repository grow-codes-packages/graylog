package graylog

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultMessageSortField is the sort field of Search when none is given.
const DefaultMessageSortField = "timestamp"

// MaxSearchLimit is the largest page Search requests (OpenSearch's default
// max_result_window is 10 000 for offset + limit).
const MaxSearchLimit = 10000

// graylogTimeLayout is the ISO-8601 UTC form Graylog uses in REST bodies.
const graylogTimeLayout = "2006-01-02T15:04:05.000Z"

// DefaultSearchRange is the relative range of Search when no range is given.
const DefaultSearchRange = 300 * time.Second

// SearchSort is one sort key of Client.Search.
type SearchSort struct {
	Field string
	// Order is desc (default) or asc.
	Order SortOrder
}

// MessageSearchOptions narrow Client.Search. Give at most one of Range,
// Start/End and Keyword; the zero value searches the last 5 minutes of every
// readable stream, newest first, 100 per page.
type MessageSearchOptions struct {
	// Range is a relative time range ending now (whole seconds, rounded up;
	// default 300 s when no other range is given).
	Range time.Duration
	// Start is the start of an absolute range (default End − 300 s).
	Start time.Time
	// End is the end of an absolute range (default now).
	End time.Time
	// Keyword is a Graylog keyword range such as "last five minutes".
	Keyword string
	// Limit is the page size (default 100, at most 10 000).
	Limit int
	// Offset skips that many matches (pagination).
	Offset int
	// Fields limits the returned message fields (Graylog always adds _id).
	Fields []string
	// Sort lists the sort keys (default timestamp desc); later keys break ties.
	Sort []SearchSort
	// Streams restricts the search to these stream ids (default: every
	// stream the caller may read).
	Streams []string
}

// Message is one search hit or stored message.
type Message struct {
	// ID is the message id (_id), Index the index that stores it; together
	// they identify the message for GetMessage.
	ID    string
	Index string
	// Timestamp is the message timestamp.
	Timestamp time.Time
	// Fields holds every returned field as decoded JSON (numbers are float64).
	Fields map[string]any
}

// Record normalizes the message into a LogRecord (see LogRecordFromMessage).
func (m Message) Record() LogRecord { return LogRecordFromMessage(m.Fields) }

// MessageSearchResult is one page of Client.Search.
type MessageSearchResult struct {
	Messages []Message
	// Total is the number of matches of the whole query.
	Total int
	// From and To are the effective time range Graylog searched.
	From time.Time
	To   time.Time
	// NextOffset is the offset of the next page (0 when there is none).
	NextOffset int
}

// Records normalizes every message into a LogRecord.
func (r MessageSearchResult) Records() []LogRecord {
	out := make([]LogRecord, len(r.Messages))
	for i, m := range r.Messages {
		out[i] = m.Record()
	}
	return out
}

// Search runs a Lucene query through the Views search API (POST
// /api/views/search/sync) and returns one page of messages. An empty query
// matches everything. Query errors (Graylog answers HTTP 200 with errors[])
// are VALIDATION errors.
func (c *Client) Search(ctx context.Context, query string, opts MessageSearchOptions) (MessageSearchResult, error) {
	const op = "search"
	if opts.Limit == 0 {
		opts.Limit = DefaultSearchLimit
	}
	if opts.Limit < 1 || opts.Limit > MaxSearchLimit {
		return MessageSearchResult{}, ValidationError(op, "limit must be an integer 1..10000")
	}
	if opts.Offset < 0 {
		return MessageSearchResult{}, ValidationError(op, "offset must not be negative")
	}
	sorts := opts.Sort
	if len(sorts) == 0 {
		sorts = []SearchSort{{Field: DefaultMessageSortField, Order: OrderDesc}}
	}
	sortBody := make([]map[string]any, len(sorts))
	for i, so := range sorts {
		order := so.Order
		if order == "" {
			order = OrderDesc
		}
		if order != OrderAsc && order != OrderDesc {
			return MessageSearchResult{}, ValidationError(op, `sort order must be "asc" or "desc"`)
		}
		if strings.TrimSpace(so.Field) == "" {
			return MessageSearchResult{}, ValidationError(op, "sort field must not be empty")
		}
		sortBody[i] = map[string]any{"field": so.Field, "order": strings.ToUpper(string(order))}
	}
	if strings.TrimSpace(query) == "" {
		query = "*"
	}
	timerange, err := searchTimerange(op, opts)
	if err != nil {
		return MessageSearchResult{}, err
	}
	st := map[string]any{
		"id": "st1", "type": "messages", "limit": opts.Limit, "offset": opts.Offset, "sort": sortBody,
	}
	if len(opts.Fields) > 0 {
		st["fields"] = opts.Fields
	}
	q := map[string]any{
		"id":           "q1",
		"query":        map[string]any{"type": "elasticsearch", "query_string": query},
		"timerange":    timerange,
		"search_types": []any{st},
	}
	if len(opts.Streams) > 0 {
		filters := make([]map[string]any, len(opts.Streams))
		for i, s := range opts.Streams {
			filters[i] = map[string]any{"type": "stream", "id": s}
		}
		q["filter"] = map[string]any{"type": "or", "filters": filters}
	}
	var body searchResponse
	err = c.sendJSON(ctx, &request{
		Method: http.MethodPost, Path: pathSearchSync, JSON: map[string]any{"queries": []any{q}},
		Idempotent: true, Operation: op,
	}, &body)
	if err != nil {
		return MessageSearchResult{}, err
	}
	return body.result(op, opts.Offset, c.transport.redact)
}

// searchTimerange builds the Views timerange of opts.
func searchTimerange(op string, opts MessageSearchOptions) (map[string]any, error) {
	kinds := 0
	for _, set := range []bool{opts.Range != 0, !opts.Start.IsZero() || !opts.End.IsZero(), opts.Keyword != ""} {
		if set {
			kinds++
		}
	}
	if kinds > 1 {
		return nil, ValidationError(op, "give only one of range, start/end and keyword")
	}
	switch {
	case !opts.Start.IsZero() || !opts.End.IsZero():
		end := opts.End
		if end.IsZero() {
			end = time.Now()
		}
		start := opts.Start
		if start.IsZero() {
			start = end.Add(-DefaultSearchRange)
		}
		if start.After(end) {
			return nil, ValidationError(op, "start is after end")
		}
		return map[string]any{"type": "absolute", "from": formatGraylogTime(start), "to": formatGraylogTime(end)}, nil
	case opts.Keyword != "":
		if strings.TrimSpace(opts.Keyword) == "" {
			return nil, ValidationError(op, "keyword must not be empty")
		}
		return map[string]any{"type": "keyword", "keyword": opts.Keyword}, nil
	}
	rng := opts.Range
	if rng == 0 {
		rng = DefaultSearchRange
	}
	if rng < 0 {
		return nil, ValidationError(op, "range must be positive")
	}
	return map[string]any{"type": "relative", "range": int64(math.Ceil(rng.Seconds()))}, nil
}

// SearchRelative is Search over the last rng (relative range, whole seconds
// rounded up). Start, End and Keyword of opts must be unset.
func (c *Client) SearchRelative(ctx context.Context, query string, rng time.Duration, opts MessageSearchOptions) (MessageSearchResult, error) {
	if rng <= 0 {
		return MessageSearchResult{}, ValidationError("searchRelative", "range must be positive")
	}
	opts.Range = rng
	return c.Search(ctx, query, opts)
}

// GetMessage returns one stored message by index and id (GET
// /api/messages/{index}/{id}); NOT_FOUND when it does not exist or the caller
// may not read it. Search hits carry both values (Message.Index, Message.ID).
func (c *Client) GetMessage(ctx context.Context, index, id string) (Message, error) {
	const op = "getMessage"
	if err := requireID(op, "index", index); err != nil {
		return Message{}, err
	}
	if err := requireID(op, "id", id); err != nil {
		return Message{}, err
	}
	var body struct {
		Message struct {
			Fields map[string]any `json:"fields"`
			ID     string         `json:"id"`
		} `json:"message"`
		Index string `json:"index"`
	}
	if err := c.sendJSON(ctx, &request{Method: http.MethodGet, Path: pathMessages + "/" + index + "/" + id, Operation: op + " " + index + "/" + id}, &body); err != nil {
		return Message{}, err
	}
	m := newMessage(body.Message.Fields, body.Index)
	if m.ID == "" {
		m.ID = body.Message.ID
	}
	return m, nil
}

type searchResponse struct {
	Execution struct {
		Done                   bool `json:"done"`
		CompletedExceptionally bool `json:"completed_exceptionally"`
	} `json:"execution"`
	Results map[string]struct {
		SearchTypes map[string]struct {
			TotalResults       int `json:"total_results"`
			EffectiveTimerange struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"effective_timerange"`
			Messages []struct {
				Message map[string]any `json:"message"`
				Index   string         `json:"index"`
			} `json:"messages"`
		} `json:"search_types"`
		Errors []struct {
			Description string `json:"description"`
		} `json:"errors"`
	} `json:"results"`
	Errors []struct {
		Description string `json:"description"`
	} `json:"errors"`
}

func (r searchResponse) result(op string, offset int, redact func(string) string) (MessageSearchResult, error) {
	q := r.Results["q1"]
	errs := make([]struct {
		Description string `json:"description"`
	}, 0, len(r.Errors)+len(q.Errors))
	errs = append(append(errs, r.Errors...), q.Errors...)
	if len(errs) > 0 || r.Execution.CompletedExceptionally {
		text := "query failed"
		for _, e := range errs {
			if e.Description != "" {
				text = e.Description
				break
			}
		}
		return MessageSearchResult{}, ValidationError(op, truncate(redact(text), maxVendorText))
	}
	st := q.SearchTypes["st1"]
	out := MessageSearchResult{Total: st.TotalResults, Messages: make([]Message, len(st.Messages))}
	out.From, _ = parseGraylogTime(st.EffectiveTimerange.From)
	out.To, _ = parseGraylogTime(st.EffectiveTimerange.To)
	for i, h := range st.Messages {
		out.Messages[i] = newMessage(h.Message, h.Index)
	}
	if len(out.Messages) > 0 && offset+len(out.Messages) < out.Total {
		out.NextOffset = offset + len(out.Messages)
	}
	return out, nil
}

func newMessage(fields map[string]any, index string) Message {
	if fields == nil {
		fields = map[string]any{}
	}
	m := Message{Index: index, Fields: fields}
	m.ID, _ = fields["_id"].(string)
	if ts, ok := fields["timestamp"].(string); ok {
		m.Timestamp, _ = parseGraylogTime(ts)
	}
	return m
}

func formatGraylogTime(t time.Time) string { return t.UTC().Format(graylogTimeLayout) }

// parseGraylogTime parses ISO-8601 timestamps and Graylog's
// "yyyy-MM-dd HH:mm:ss.SSS" (UTC) form.
func parseGraylogTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse("2006-01-02 15:04:05.000", s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// ResourceFields maps stored field names back to OpenTelemetry resource keys
// (OTLP resource attributes arrive as otel_resource_attributes_service_name).
var ResourceFields = map[string]string{
	"service_name":                "service.name",
	"service_version":             "service.version",
	"service_namespace":           "service.namespace",
	"service_instance_id":         "service.instance.id",
	"deployment_environment":      "deployment.environment",
	"deployment_environment_name": "deployment.environment.name",
}

// skippedFields are stored fields that never become attributes.
var skippedFields = map[string]bool{
	"_id": true, "message": true, "timestamp": true, "level": true, "source": true, "streams": true,
	"trace_id": true, "span_id": true, "trace_flags": true,
	"otel_trace_id": true, "otel_span_id": true, "otel_trace_flags": true,
	"otel_severity_number": true, "otel_severity_text": true, "otel_time_unix_nano": true,
	"otel_observed_time_unix_nano": true, "otel_resource_schema_url": true, "otel_scope_schema_url": true,
}

var (
	hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// LogRecordFromMessage normalizes stored Graylog message fields (a search hit
// or GetMessage) into a LogRecord. OTLP fields (otel_*) win over GELF fields:
//   - Body = message, Timestamp = timestamp, Resource["host.name"] = source;
//   - Severity from otel_severity_number (named level of its range), else
//     from the syslog level (0–2 FATAL, 3 ERROR, 4 WARN, 5–6 INFO, 7 DEBUG),
//     else INFO; SeverityText is the severity name;
//   - otel_resource_attributes_<k> → Resource[ResourceFields[k] or k], stored
//     fields named in ResourceFields → Resource (unless already set),
//     otel_attributes_<k> → Attributes[k], attr_id → Attributes["id"], and
//     every other field except gl2_* and the reserved ones → Attributes;
//   - TraceID from otel_trace_id or trace_id (32 lower-hex), and only then
//     SpanID (16 lower-hex) and TraceFlags.
func LogRecordFromMessage(fields map[string]any) LogRecord {
	rec := LogRecord{Attributes: map[string]AttrValue{}, Resource: map[string]AttrValue{}, Severity: SeverityInfo}
	rec.Body = stringField(fields["message"])
	if ts, ok := fields["timestamp"].(string); ok {
		rec.Timestamp, _ = parseGraylogTime(ts)
	}
	if n, ok := numberField(fields["otel_severity_number"]); ok && n >= 1 && n <= 24 {
		rec.Severity = canonicalSeverity(Severity(int(n)))
	} else if n, ok := numberField(fields["level"]); ok {
		rec.Severity = GelfLevelToSeverity(int(n))
	}
	rec.SeverityText = rec.Severity.String()
	if src, ok := fields["source"].(string); ok && src != "" {
		rec.Resource["host.name"] = src
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if skippedFields[k] || strings.HasPrefix(k, "gl2_") {
			continue
		}
		v := NormalizeAttrValue(fields[k])
		if v == nil {
			continue
		}
		switch {
		case strings.HasPrefix(k, "otel_resource_attributes_"):
			name := strings.TrimPrefix(k, "otel_resource_attributes_")
			if rk, ok := ResourceFields[name]; ok {
				name = rk
			}
			rec.Resource[name] = v
		case strings.HasPrefix(k, "otel_attributes_"):
			rec.Attributes[strings.TrimPrefix(k, "otel_attributes_")] = v
		case ResourceFields[k] != "":
			if _, set := rec.Resource[ResourceFields[k]]; !set {
				rec.Resource[ResourceFields[k]] = v
			}
		case k == "attr_id":
			rec.Attributes["id"] = v
		default:
			rec.Attributes[k] = v
		}
	}
	if id := hexID(hex32, fields["otel_trace_id"], fields["trace_id"]); id != "" {
		rec.TraceID = id
		rec.SpanID = hexID(hex16, fields["otel_span_id"], fields["span_id"])
		for _, f := range []any{fields["otel_trace_flags"], fields["trace_flags"]} {
			if n, ok := numberField(f); ok && n >= 0 && n <= 255 {
				flags := uint8(n)
				rec.TraceFlags = &flags
				break
			}
		}
	}
	return rec
}

// canonicalSeverity maps a severity number to the named level of its range
// (10 → INFO).
func canonicalSeverity(s Severity) Severity {
	if s < SeverityTrace || s > 24 {
		return SeverityInfo
	}
	return (s-1)/4*4 + 1
}

func hexID(re *regexp.Regexp, values ...any) string {
	for _, v := range values {
		if s, ok := v.(string); ok {
			if s = strings.ToLower(strings.TrimSpace(s)); re.MatchString(s) {
				return s
			}
		}
	}
	return ""
}

func numberField(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	}
	return 0, false
}

func stringField(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
