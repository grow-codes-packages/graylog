package graylog

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// searchRecorder answers /api/views/search/sync with fixture name and records bodies.
type searchRecorder struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (s *searchRecorder) handler(t *testing.T, name string) func(w http.ResponseWriter, r *http.Request, n int) {
	f := loadFixture(t, name)
	return func(w http.ResponseWriter, r *http.Request, _ int) {
		s.mu.Lock()
		s.bodies = append(s.bodies, decodeBody(t, r))
		s.mu.Unlock()
		f.write(w)
	}
}

func (s *searchRecorder) last() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[len(s.bodies)-1]
}

func query0(body map[string]any) map[string]any {
	return body["queries"].([]any)[0].(map[string]any)
}

func TestSearch(t *testing.T) {
	ctx := t.Context()
	rec := &searchRecorder{}
	ts := newTestServer(t, rec.handler(t, "search.absolute_sorted_fields"))
	c := newTestClient(t, ts.URL, nil)

	from, _ := time.Parse(time.RFC3339, "2026-11-18T20:28:15.935Z")
	to, _ := time.Parse(time.RFC3339, "2026-11-18T20:28:24.794Z")
	res, err := c.Search(ctx, "marker:growsdk179503370112643 AND transport:tcp", MessageSearchOptions{
		Start: from, End: to, Limit: 10, Fields: []string{"message", "marker", "seq", "timestamp"},
		Sort: []SearchSort{{Field: "seq", Order: OrderAsc}}, Streams: []string{"s1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total < 3 || len(res.Messages) < 3 || res.Messages[0].Index != "graylog_0" || res.Messages[0].ID == "" || res.Messages[0].Timestamp.IsZero() {
		t.Fatalf("result: %+v", res)
	}
	if !res.From.Equal(from) || !res.To.Equal(to) {
		t.Fatalf("effective range %s %s", res.From, res.To)
	}
	q := query0(rec.last())
	tr := q["timerange"].(map[string]any)
	st := q["search_types"].([]any)[0].(map[string]any)
	if tr["type"] != "absolute" || tr["from"] != "2026-11-18T20:28:15.935Z" || tr["to"] != "2026-11-18T20:28:24.794Z" {
		t.Fatalf("timerange %v", tr)
	}
	if st["limit"] != 10.0 || fmt.Sprint(st["sort"]) != "[map[field:seq order:ASC]]" || len(st["fields"].([]any)) != 4 {
		t.Fatalf("search type %v", st)
	}
	if fmt.Sprint(q["filter"]) != "map[filters:[map[id:s1 type:stream]] type:or]" {
		t.Fatalf("filter %v", q["filter"])
	}
	recs := res.Records()
	if recs[0].Body != "growsdk179503370112643 tcp #0" || recs[0].Attributes["seq"] != 0.0 {
		t.Fatalf("records %+v", recs[0])
	}

	// Defaults: relative 300 s, timestamp desc, 100, all streams, "*".
	if _, err := c.Search(ctx, " ", MessageSearchOptions{}); err != nil {
		t.Fatal(err)
	}
	q = query0(rec.last())
	st = q["search_types"].([]any)[0].(map[string]any)
	if fmt.Sprint(q["timerange"]) != "map[range:300 type:relative]" || q["query"].(map[string]any)["query_string"] != "*" ||
		st["limit"] != 100.0 || fmt.Sprint(st["sort"]) != "[map[field:timestamp order:DESC]]" || q["filter"] != nil || st["fields"] != nil {
		t.Fatalf("defaults %v", q)
	}
	if _, err := c.SearchRelative(ctx, "x", 1500*time.Millisecond, MessageSearchOptions{Offset: 5}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(query0(rec.last())["timerange"]) != "map[range:2 type:relative]" {
		t.Fatalf("relative %v", query0(rec.last())["timerange"])
	}
	if _, err := c.Search(ctx, "x", MessageSearchOptions{Keyword: "last five minutes"}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(query0(rec.last())["timerange"]) != "map[keyword:last five minutes type:keyword]" {
		t.Fatal("keyword")
	}
	if _, err := c.Search(ctx, "x", MessageSearchOptions{End: to}); err != nil {
		t.Fatal(err)
	}
	if query0(rec.last())["timerange"].(map[string]any)["from"] != "2026-11-18T20:23:24.794Z" {
		t.Fatalf("start default %v", query0(rec.last())["timerange"])
	}
	if _, err := c.Search(ctx, "x", MessageSearchOptions{Start: from}); err != nil {
		t.Fatal(err)
	}

	// Validation.
	bad := []MessageSearchOptions{
		{Limit: -1}, {Limit: 10001}, {Offset: -1},
		{Range: time.Second, Keyword: "k"}, {Start: from, Range: time.Second},
		{Start: to, End: from}, {Keyword: "  "}, {Range: -time.Second},
		{Sort: []SearchSort{{Field: "x", Order: "up"}}}, {Sort: []SearchSort{{Field: " "}}},
	}
	for i, o := range bad {
		if _, err := c.Search(ctx, "x", o); !errors.Is(err, ErrValidation) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	if _, err := c.SearchRelative(ctx, "x", 0, MessageSearchOptions{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}

func TestSearchResponses(t *testing.T) {
	ctx := t.Context()
	cases := map[string]error{
		"search.invalid_query": ErrValidation,
		"search.bad_request":   ErrValidation,
		"search.unauthorized":  ErrAuthentication,
	}
	for name, want := range cases {
		c := newTestClient(t, newTestServer(t, (&searchRecorder{}).handler(t, name)).URL, nil)
		_, err := c.Search(ctx, "marker:((", MessageSearchOptions{})
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "search.invalid_query" && !strings.Contains(err.Error(), "all shards failed") {
			t.Fatalf("message: %v", err)
		}
	}
	c := newTestClient(t, newTestServer(t, (&searchRecorder{}).handler(t, "search.empty")).URL, nil)
	res, err := c.Search(ctx, "nomatch", MessageSearchOptions{})
	if err != nil || res.Total != 0 || len(res.Messages) != 0 || res.NextOffset != 0 {
		t.Fatalf("empty %+v %v", res, err)
	}
	page := newTestServer(t, (&searchRecorder{}).handler(t, "search.desc_limit_offset"))
	res, err = newTestClient(t, page.URL, nil).Search(ctx, "x", MessageSearchOptions{Limit: 1, Offset: 1})
	if err != nil || len(res.Messages) != 1 || res.NextOffset != 2 {
		t.Fatalf("page %+v %v", res, err)
	}
	exc := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		_, _ = w.Write([]byte(`{"execution":{"completed_exceptionally":true},"results":{}}`))
	})
	if _, err := newTestClient(t, exc.URL, nil).Search(ctx, "x", MessageSearchOptions{}); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "query failed") {
		t.Fatal(err)
	}
}

func TestGetMessage(t *testing.T) {
	ctx := t.Context()
	ts := newTestServer(t, fixtureRoutes(t, map[string]string{
		"GET " + pathMessages + "/graylog_0/99c65855-e38e-11f1-8dde-020650dd320d": "getMessage.ok",
		"GET " + pathMessages + "/graylog_0/missing":                              "getMessage.not_found",
	}))
	c := newTestClient(t, ts.URL, nil)
	m, err := c.GetMessage(ctx, "graylog_0", "99c65855-e38e-11f1-8dde-020650dd320d")
	if err != nil || m.ID != "99c65855-e38e-11f1-8dde-020650dd320d" || m.Index != "graylog_0" || m.Fields["marker"] != "growsdk179503370112643" {
		t.Fatalf("%+v %v", m, err)
	}
	r := m.Record()
	if r.Body != "growsdk179503370112643 http #0" || r.Severity != SeverityInfo || r.Resource["host.name"] != "grow-sdk-verify" || r.Attributes["bool_attr"] != "true" {
		t.Fatalf("record %+v", r)
	}
	if _, ok := r.Attributes["gl2_source_input"]; ok {
		t.Fatal("gl2_* must be skipped")
	}
	if _, err := c.GetMessage(ctx, "graylog_0", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := c.GetMessage(ctx, "", "x"); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := c.GetMessage(ctx, "i", ""); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	idOnly := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		_, _ = w.Write([]byte(`{"message":{"id":"m1"},"index":"i"}`))
	})
	if m, err := newTestClient(t, idOnly.URL, nil).GetMessage(ctx, "i", "m1"); err != nil || m.ID != "m1" || m.Fields == nil {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestLogRecordFromMessage(t *testing.T) {
	otlp := loadFixture(t, "otlpLogs.searched")
	var body struct {
		Message struct {
			Message map[string]any `json:"message"`
		} `json:"message"`
	}
	if err := json.Unmarshal(otlp.Response.Body, &body); err != nil {
		t.Fatal(err)
	}
	r := LogRecordFromMessage(body.Message.Message)
	if r.Severity != SeverityWarn || r.SeverityText != "WARN" || r.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || r.SpanID != "00f067aa0ba902b7" {
		t.Fatalf("otlp record %+v", r)
	}
	if r.Resource["service.name"] != "grow-sdk-verify" || r.Resource["marker"] != "growsdkotlp179503370112643" || r.Attributes["attr_k"] != "v" || r.Attributes["app"] != "server" {
		t.Fatalf("otlp attrs %+v", r)
	}
	if _, ok := r.Attributes["otel_resource_schema_url"]; ok {
		t.Fatal("schema url must be skipped")
	}

	typed := loadFixture(t, "gelfTypedFields.stored")
	body.Message.Message = nil
	if err := json.Unmarshal(typed.Response.Body, &body); err != nil {
		t.Fatal(err)
	}
	r = LogRecordFromMessage(body.Message.Message)
	if r.Severity != SeverityError || r.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || r.Attributes["full_message"] != "line1\nline2" || r.Attributes["t_int"] != 42.0 {
		t.Fatalf("gelf record %+v", r)
	}
	if !r.Timestamp.Equal(time.Date(2026, 11, 18, 11, 6, 40, 123e6, time.UTC)) {
		t.Fatalf("timestamp %s", r.Timestamp)
	}

	r = LogRecordFromMessage(map[string]any{
		"message": 12.5, "level": "7", "service_name": "svc", "attr_id": "x", "trace_id": "NOT-HEX", "span_id": "00f067aa0ba902b7",
		"otel_severity_number": 99.0, "deployment_environment": "prod", "nested": map[string]any{"a": nil}, "nil": nil,
		"timestamp": "2026-11-18 20:28:22.974",
	})
	if r.Body != "12.5" || r.Severity != SeverityDebug || r.Resource["service.name"] != "svc" || r.Resource["deployment.environment"] != "prod" || r.Attributes["id"] != "x" || r.TraceID != "" || r.SpanID != "" {
		t.Fatalf("mixed %+v", r)
	}
	if r.Timestamp.IsZero() {
		t.Fatal("graylog time form")
	}
	if _, ok := r.Attributes["nil"]; ok {
		t.Fatal("nil dropped")
	}
	r = LogRecordFromMessage(map[string]any{"message": []any{"a"}, "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "trace_flags": 1.0, "otel_severity_number": "10"})
	if r.Body != `["a"]` || r.TraceFlags == nil || *r.TraceFlags != 1 || r.Severity != SeverityInfo {
		t.Fatalf("flags %+v", r)
	}
	r = LogRecordFromMessage(map[string]any{"message": nil, "otel_resource_attributes_service_name": "a", "service_name": "b"})
	if r.Body != "" || r.Resource["service.name"] != "a" {
		t.Fatalf("resource precedence %+v", r)
	}
	if canonicalSeverity(0) != SeverityInfo || canonicalSeverity(23) != SeverityFatal {
		t.Fatal("canonical")
	}
	if _, err := parseGraylogTime("nope"); err == nil {
		t.Fatal("bad time")
	}
	if stringField(map[string]any{"bad": make(chan int)}) == "" {
		t.Fatal("stringField fallback")
	}
}

func TestLogQuery(t *testing.T) {
	ctx := t.Context()
	rec := &searchRecorder{}
	search := rec.handler(t, "search.desc_limit_offset")
	routes := fixtureRoutes(t, map[string]string{
		"GET " + pathStreamsPage: "listStreams.ok",
		"GET " + pathFields:      "listLabels.ok",
	})
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.URL.Path == pathSearchSync {
			search(w, r, n)
			return
		}
		routes(w, r, n)
	})
	c := newTestClient(t, ts.URL, nil)
	q := c.LogQuery(LogQueryOptions{})

	res, err := q.Search(ctx, "x", SearchOptions{Cursor: "1", Limit: 1})
	if err != nil || len(res.Records) != 1 || res.NextCursor != "2" || res.Total == nil || *res.Total != 3 {
		t.Fatalf("search %+v %v", res, err)
	}
	body := query0(rec.last())
	tr := body["timerange"].(map[string]any)
	st := body["search_types"].([]any)[0].(map[string]any)
	from, _ := time.Parse(time.RFC3339, tr["from"].(string))
	to, _ := time.Parse(time.RFC3339, tr["to"].(string))
	if tr["type"] != "absolute" || to.Sub(from) != time.Hour || st["offset"] != 1.0 || fmt.Sprint(st["sort"]) != "[map[field:timestamp order:DESC] map[field:gl2_message_id order:DESC]]" {
		t.Fatalf("body %v", body)
	}
	if _, err := q.Search(ctx, "x", SearchOptions{Cursor: "-1"}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := q.Search(ctx, "x", SearchOptions{Order: "sideways"}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	streams, err := q.ListStreams(ctx)
	if err != nil || len(streams) != 3 || streams[0] != "All events" {
		t.Fatalf("streams %v %v", streams, err)
	}
	labels, err := q.ListLabels(ctx)
	if err != nil || len(labels) == 0 {
		t.Fatalf("labels %v %v", labels, err)
	}
	r, err := q.WaitForLog(ctx, "x", WaitForLogOptions{Timeout: time.Second, Interval: time.Millisecond})
	if err != nil || r.Body == "" {
		t.Fatalf("waitForLog %+v %v", r, err)
	}

	sq := c.LogQuery(LogQueryOptions{Streams: []string{"s1"}, DefaultWindow: time.Minute})
	if _, err := sq.Search(ctx, "x", SearchOptions{}); err != nil {
		t.Fatal(err)
	}
	if body := query0(rec.last()); body["filter"] == nil {
		t.Fatalf("streams filter %v", body)
	}
	failing := newTestClient(t, newTestServer(t, status(http.StatusUnauthorized)).URL, nil).LogQuery(LogQueryOptions{})
	if _, err := failing.Search(ctx, "x", SearchOptions{}); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if _, err := failing.ListStreams(ctx); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
}

// tailServer returns messages added with add for every search whose range covers them.
type tailServer struct {
	mu   sync.Mutex
	msgs []map[string]any
	fail int
}

func (s *tailServer) add(id string, ts time.Time, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, map[string]any{"_id": id, "message": msg, "timestamp": ts.UTC().Format(graylogTimeLayout)})
}

func (s *tailServer) handler(t *testing.T) func(w http.ResponseWriter, r *http.Request, n int) {
	return func(w http.ResponseWriter, r *http.Request, _ int) {
		body := decodeBody(t, r)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.fail > 0 {
			s.fail--
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		q := query0(body)
		tr := q["timerange"].(map[string]any)
		from, _ := time.Parse(time.RFC3339, tr["from"].(string))
		st := q["search_types"].([]any)[0].(map[string]any)
		offset, limit := int(st["offset"].(float64)), int(st["limit"].(float64))
		var hits []map[string]any
		for _, m := range s.msgs {
			ts, _ := time.Parse(time.RFC3339, m["timestamp"].(string))
			if !ts.Before(from) {
				hits = append(hits, map[string]any{"message": m, "index": "graylog_0"})
			}
		}
		total := len(hits)
		hits = hits[min(offset, total):min(offset+limit, total)]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"execution": map[string]any{"done": true},
			"results":   map[string]any{"q1": map[string]any{"search_types": map[string]any{"st1": map[string]any{"total_results": total, "messages": hits}}}},
		})
	}
}

func TestTail(t *testing.T) {
	ctx := t.Context()
	s := &tailServer{fail: 1}
	start := time.Now().Add(-time.Minute)
	s.add("old", start.Add(-time.Second), "before start")
	s.add("a", start.Add(time.Second), "first")
	c := newTestClient(t, newTestServer(t, s.handler(t)).URL, func(cfg *Config) { cfg.Retry = fastRetry(0) })
	q := c.LogQuery(LogQueryOptions{})

	got := make(chan string, 16)
	h, err := q.Tail(ctx, "x", func(r LogRecord) {
		got <- r.Body
		if r.Body == "first" {
			panic("callbacks may panic")
		}
	}, TailOptions{Start: start, Interval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	expect := func(want string) {
		t.Helper()
		select {
		case b := <-got:
			if b != want {
				t.Fatalf("got %q want %q", b, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for %q", want)
		}
	}
	expect("first")
	s.add("b", start.Add(2*time.Second), "second")
	expect("second")
	// A late record older than the newest one is still delivered once.
	s.add("late", start.Add(1500*time.Millisecond), "late")
	expect("late")
	h.Stop()
	h.Stop()
	select {
	case b := <-got:
		t.Fatalf("duplicate or unexpected %q", b)
	case <-time.After(30 * time.Millisecond):
	}

	if _, err := q.Tail(ctx, "x", nil, TailOptions{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	// Default start/interval, stopped by Client.Close.
	h2, err := q.Tail(ctx, "x", func(LogRecord) {}, TailOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	h2.Stop()
	if _, err := q.Tail(ctx, "x", func(LogRecord) {}, TailOptions{}); !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
}

func TestTailPagesAndPrunes(t *testing.T) {
	s := &tailServer{}
	start := time.Now().Add(-time.Hour)
	for i := 0; i < 1200; i++ {
		s.add(fmt.Sprintf("m%d", i), start.Add(time.Duration(i)*time.Millisecond), "x")
	}
	c := newTestClient(t, newTestServer(t, s.handler(t)).URL, nil)
	n := 0
	tl := &tailer{q: c.LogQuery(LogQueryOptions{}), query: "x", onRecord: func(LogRecord) { n++ }, since: start, seen: map[string]time.Time{}}
	tl.poll(t.Context())
	if n != 1200 {
		t.Fatalf("delivered %d", n)
	}
	s.add("far", start.Add(time.Hour), "x")
	tl.poll(t.Context())
	if n != 1201 || len(tl.seen) != 1 {
		t.Fatalf("delivered %d seen %d", n, len(tl.seen))
	}
}
