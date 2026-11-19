package graylog

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInputs(t *testing.T) {
	ts := newTestServer(t, fixtureRoutes(t, map[string]string{
		"GET " + pathInputs: "listInputs.ok",
		"GET " + pathInputs + "/6afe0a6607ba3acebff1891c":      "getInput.ok",
		"GET " + pathInputs + "/missing":                       "getInput.not_found",
		"GET " + pathInputTypes:                                "listInputTypes.ok",
		"GET " + pathInputStates + "/6afe0a6607ba3acebff1891c": "getInputState.running",
		"DELETE " + pathInputs + "/6afe0a6607ba3acebff1891c":   "deleteInput.deleted",
		"DELETE " + pathInputs + "/missing":                    "deleteInput.not_found",
		"POST " + pathInputs:                                   "createInput.created",
		"GET " + pathInputStates + "/6afe0a6607ba3acebff1892e": "getInputState.port_collision",
	}))
	c := newTestClient(t, ts.URL, nil)
	ctx := t.Context()

	inputs, err := c.ListInputs(ctx)
	if err != nil || len(inputs) < 4 {
		t.Fatalf("listInputs %v %v", inputs, err)
	}
	var tcp Input
	for _, in := range inputs {
		if in.Type == InputTypeGelfTCP {
			tcp = in
		}
	}
	if tcp.Port() != 12201 || tcp.BindAddress() != "0.0.0.0" || !tcp.Global || tcp.CreatedAt.IsZero() {
		t.Fatalf("tcp input: %+v", tcp)
	}
	in, err := c.GetInput(ctx, "6afe0a6607ba3acebff1891c")
	if err != nil || in.Type != InputTypeGelfHTTP || in.Port() != 12299 {
		t.Fatalf("getInput %+v %v", in, err)
	}
	if _, err := c.GetInput(ctx, "missing"); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("getInput missing: %v", err)
	}
	types, err := c.ListInputTypes(ctx)
	if err != nil || types[InputTypeOTelGRPC] != "OpenTelemetry (gRPC)" {
		t.Fatalf("listInputTypes: %v", err)
	}
	st, err := c.GetInputState(ctx, "6afe0a6607ba3acebff1891c")
	if err != nil || st.State != InputStateRunning || st.Input.ID != "6afe0a6607ba3acebff1891c" {
		t.Fatalf("getInputState %+v %v", st, err)
	}
	id, err := c.CreateInput(ctx, InputTypeGelfHTTP, map[string]any{"port": 12299}, CreateInputOptions{})
	if err != nil || id != "6afe0a6607ba3acebff1891c" {
		t.Fatalf("createInput %q %v", id, err)
	}
	if err := c.DeleteInput(ctx, "6afe0a6607ba3acebff1891c"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteInput(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleteInput missing: %v", err)
	}

	// Request shapes.
	var mu sync.Mutex
	var bodies []map[string]any
	var headers []http.Header
	rec := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		mu.Lock()
		headers = append(headers, r.Header.Clone())
		if r.Method == http.MethodPost {
			bodies = append(bodies, decodeBody(t, r))
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{"id":"abc"}`))
	})
	rc := newTestClient(t, rec.URL, nil)
	if _, err := rc.CreateInput(ctx, InputTypeGelfTCP, nil, CreateInputOptions{Node: "node-1"}); err != nil {
		t.Fatal(err)
	}
	if bodies[0]["title"] != "GELFTCPInput (grow-codes)" || bodies[0]["global"] != false || bodies[0]["node"] != "node-1" {
		t.Fatalf("create body: %v", bodies[0])
	}
	if headers[0].Get(HeaderRequestedBy) != DefaultRequestedBy || headers[0].Get("Authorization") != basicAuth(testToken, "token") {
		t.Fatalf("create headers: %v", headers[0])
	}

	// Validation and odd responses.
	for _, err := range []error{
		func() error { _, err := c.GetInput(ctx, ""); return err }(),
		func() error { _, err := c.GetInputState(ctx, "a/b"); return err }(),
		func() error { _, err := c.CreateInput(ctx, " ", nil, CreateInputOptions{}); return err }(),
		c.DeleteInput(ctx, ""),
	} {
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("validation: %v", err)
		}
	}
	noID := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte(`{}`)) })
	nc := newTestClient(t, noID.URL, nil)
	if _, err := nc.CreateInput(ctx, InputTypeGelfTCP, nil, CreateInputOptions{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no id: %v", err)
	}
	if l, err := nc.ListInputs(ctx); err != nil || l == nil {
		t.Fatalf("empty list: %v", err)
	}
	if m, err := nc.ListInputTypes(ctx); err != nil || m == nil {
		t.Fatalf("empty types: %v", err)
	}
	if (Input{Attributes: map[string]any{"port": "12"}}).Port() != 12 || (Input{Attributes: map[string]any{"port": 3}}).Port() != 3 || (Input{}).Port() != 0 {
		t.Fatal("Port()")
	}
	bad := newTestServer(t, fixtureRoutes(t, map[string]string{"POST " + pathInputs: "createInput.bad_type"}))
	if _, err := newTestClient(t, bad.URL, nil).CreateInput(ctx, "org.example.NoSuchInput", nil, CreateInputOptions{}); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "no such input type") {
		t.Fatalf("bad type: %v", err)
	}
	csrf := newTestServer(t, fixtureRoutes(t, map[string]string{"POST " + pathInputs: "createInput.missing_requested_by"}))
	if _, err := newTestClient(t, csrf.URL, nil).CreateInput(ctx, InputTypeGelfTCP, nil, CreateInputOptions{}); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "CSRF") {
		t.Fatalf("csrf: %v", err)
	}
}

// ensureServer simulates Graylog for EnsureGelfInput.
type ensureServer struct {
	mu       sync.Mutex
	inputs   []map[string]any
	states   []string // states returned in order for the created input
	created  int
	deleted  []string
	failNext bool
}

func (s *ensureServer) handler(t *testing.T) func(w http.ResponseWriter, r *http.Request, n int) {
	return func(w http.ResponseWriter, r *http.Request, _ int) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == pathInputs:
			_ = json.NewEncoder(w).Encode(map[string]any{"inputs": s.inputs})
		case r.Method == http.MethodPost && r.URL.Path == pathInputs:
			body := decodeBody(t, r)
			cfg := body["configuration"].(map[string]any)
			s.created++
			s.inputs = append(s.inputs, map[string]any{"id": "new1", "title": body["title"], "type": body["type"], "attributes": cfg})
			if s.failNext {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"new1"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, pathInputs+"/"):
			for _, in := range s.inputs {
				if in["id"] == strings.TrimPrefix(r.URL.Path, pathInputs+"/") {
					_ = json.NewEncoder(w).Encode(in)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, pathInputStates+"/"):
			if len(s.states) == 0 {
				_, _ = w.Write([]byte(`{"state":"RUNNING"}`))
				return
			}
			st := s.states[0]
			if len(s.states) > 1 {
				s.states = s.states[1:]
			}
			switch st {
			case "404":
				w.WriteHeader(http.StatusNotFound)
			case "401":
				w.WriteHeader(http.StatusUnauthorized)
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"state": st, "detailed_message": "bind failed: Address already in use"})
			}
		case r.Method == http.MethodDelete:
			s.deleted = append(s.deleted, strings.TrimPrefix(r.URL.Path, pathInputs+"/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestEnsureGelfInput(t *testing.T) {
	ctx := t.Context()
	fast := EnsureGelfInputOptions{Interval: time.Millisecond, Timeout: 2 * time.Second}

	t.Run("reuses an existing input", func(t *testing.T) {
		s := &ensureServer{inputs: []map[string]any{{"id": "old", "type": InputTypeGelfUDP, "attributes": map[string]any{"port": 12201, "bind_address": "0.0.0.0"}}}}
		c := newTestClient(t, newTestServer(t, s.handler(t)).URL, nil)
		in, err := c.EnsureGelfInput(ctx, GelfUDP, 12201, fast)
		if err != nil || in.ID != "old" || in.Created || s.created != 0 {
			t.Fatalf("%+v %v", in, err)
		}
	})

	t.Run("creates and waits for RUNNING", func(t *testing.T) {
		for _, p := range []GelfProtocol{GelfTCP, GelfHTTP} {
			s := &ensureServer{states: []string{"404", "STARTING", "RUNNING"}}
			c := newTestClient(t, newTestServer(t, s.handler(t)).URL, nil)
			opts := fast
			opts.Configuration = map[string]any{"tls_enable": true}
			in, err := c.EnsureGelfInput(ctx, p, 12299, opts)
			if err != nil || in.ID != "new1" || !in.Created || in.Port() != 12299 {
				t.Fatalf("%s: %+v %v", p, in, err)
			}
			if in.Attributes["tls_enable"] != true || in.Attributes["bind_address"] != "0.0.0.0" || in.Title != "grow-codes GELF "+strings.ToUpper(string(p))+" 12299" {
				t.Fatalf("%s config: %+v", p, in)
			}
		}
	})

	t.Run("failed input is a conflict and is deleted", func(t *testing.T) {
		s := &ensureServer{states: []string{"FAILED"}}
		c := newTestClient(t, newTestServer(t, s.handler(t)).URL, nil)
		_, err := c.EnsureGelfInput(ctx, GelfTCP, 12201, fast)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "Address already in use") || len(s.deleted) != 1 {
			t.Fatalf("%v deleted=%v", err, s.deleted)
		}
	})

	t.Run("timeout deletes the created input", func(t *testing.T) {
		s := &ensureServer{states: []string{"STARTING"}}
		c := newTestClient(t, newTestServer(t, s.handler(t)).URL, nil)
		opts := fast
		opts.Timeout = 30 * time.Millisecond
		if _, err := c.EnsureGelfInput(ctx, GelfTCP, 12201, opts); !errors.Is(err, ErrTimeout) || len(s.deleted) != 1 {
			t.Fatalf("%v deleted=%v", err, s.deleted)
		}
	})

	t.Run("state error", func(t *testing.T) {
		s := &ensureServer{states: []string{"401"}}
		c := newTestClient(t, newTestServer(t, s.handler(t)).URL, nil)
		if _, err := c.EnsureGelfInput(ctx, GelfTCP, 12201, fast); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	})

	t.Run("ambiguous create re-lists", func(t *testing.T) {
		s := &ensureServer{failNext: true}
		c := newTestClient(t, newTestServer(t, s.handler(t)).URL, func(cfg *Config) { cfg.Retry = fastRetry(0) })
		in, err := c.EnsureGelfInput(ctx, GelfTCP, 12201, fast)
		if err != nil || in.ID != "new1" || in.Created {
			t.Fatalf("%+v %v", in, err)
		}
	})

	t.Run("create failure", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"inputs":[]}`))
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})
		c := newTestClient(t, ts.URL, nil)
		if _, err := c.EnsureGelfInput(ctx, GelfTCP, 12201, fast); !errors.Is(err, ErrPermissionDenied) {
			t.Fatal(err)
		}
	})

	t.Run("validation and list errors", func(t *testing.T) {
		c := newTestClient(t, newTestServer(t, statusHandler(http.StatusUnauthorized)).URL, nil)
		if _, err := c.EnsureGelfInput(ctx, "smtp", 1, fast); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
		if _, err := c.EnsureGelfInput(ctx, GelfTCP, 0, fast); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
		if _, err := c.EnsureGelfInput(ctx, GelfTCP, 1, EnsureGelfInputOptions{}); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	})
}

func TestStreamsAndIndexSets(t *testing.T) {
	ctx := t.Context()
	ts := newTestServer(t, fixtureRoutes(t, map[string]string{
		"GET " + pathStreamsPage:                                   "listStreams.ok",
		"GET " + pathStreams + "/6afe0a6607ba3acebff1894e":         "getStream.ok",
		"GET " + pathStreams + "/missing":                          "getStream.not_found",
		"POST " + pathStreams:                                      "createStream.created",
		"POST " + pathStreams + "/6afe0a6607ba3acebff1894e/resume": "resumeStream.ok",
		"DELETE " + pathStreams + "/6afe0a6607ba3acebff1894e":      "deleteStream.deleted",
		"DELETE " + pathStreams + "/missing":                       "deleteStream.not_found",
		"GET " + pathIndexSets:                                     "listIndexSets.ok",
	}))
	c := newTestClient(t, ts.URL, nil)

	page, err := c.ListStreams(ctx, ListStreamsOptions{})
	if err != nil || page.Total != 3 || len(page.Streams) != 3 || page.Page != 1 || page.PerPage != 50 {
		t.Fatalf("listStreams %+v %v", page, err)
	}
	q := ts.request(0).URL.Query()
	if q.Get("page") != "1" || q.Get("per_page") != "50" || q.Get("sort") != "title" || q.Get("order") != "asc" || q.Has("query") {
		t.Fatalf("listStreams query: %v", q)
	}
	all, err := c.listAllStreams(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("listAllStreams %v %v", all, err)
	}
	s, err := c.GetStream(ctx, "6afe0a6607ba3acebff1894e")
	if err != nil || s.Disabled || len(s.Rules) != 1 || s.Rules[0].Type != StreamRuleExact || s.IndexSetID == "" {
		t.Fatalf("getStream %+v %v", s, err)
	}
	if _, err := c.GetStream(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	sets, err := c.ListIndexSets(ctx)
	if err != nil || len(sets) != 3 || !sets[0].Default || sets[0].Title != "Default index set" {
		t.Fatalf("listIndexSets %+v %v", sets, err)
	}
	id, err := c.CreateStream(ctx, CreateStreamOptions{Title: "t", Rules: []StreamRule{{ID: "x", Field: "marker", Type: StreamRuleExact, Value: "v"}}})
	if err != nil || id != "6afe0a6607ba3acebff1894e" {
		t.Fatalf("createStream %q %v", id, err)
	}
	if err := c.DeleteStream(ctx, "6afe0a6607ba3acebff1894e"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteStream(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	// Request body of CreateStream and options of ListStreams.
	var mu sync.Mutex
	var created map[string]any
	var resumed int
	rec := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == pathIndexSets:
			_, _ = w.Write([]byte(`{"index_sets":[{"id":"first","default":false},{"id":"second","default":false}]}`))
		case r.Method == http.MethodPost && r.URL.Path == pathStreams:
			created = decodeBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"stream_id":"s1"}`))
		case strings.HasSuffix(r.URL.Path, "/resume"):
			resumed++
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte(`{"pagination":{"total":0,"page":2,"per_page":5},"elements":null}`))
		}
	})
	rc := newTestClient(t, rec.URL, nil)
	if _, err := rc.CreateStream(ctx, CreateStreamOptions{Title: "t", MatchingType: "or", Disabled: true}); err != nil {
		t.Fatal(err)
	}
	entity := created["entity"].(map[string]any)
	if entity["index_set_id"] != "first" || entity["matching_type"] != "OR" || resumed != 0 {
		t.Fatalf("entity %v resumed %d", entity, resumed)
	}
	p, err := rc.ListStreams(ctx, ListStreamsOptions{Page: 2, PerPage: 5, Query: "grow", Sort: "created_at", Order: OrderDesc})
	if err != nil || p.Streams == nil || p.Page != 2 {
		t.Fatalf("page %+v %v", p, err)
	}
	if q := rec.request(int(rec.calls.Load()) - 1).URL.Query(); q.Get("query") != "grow" || q.Get("order") != "desc" || q.Get("per_page") != "5" {
		t.Fatalf("list query: %v", q)
	}

	// Validation.
	for _, err := range []error{
		func() error { _, err := c.CreateStream(ctx, CreateStreamOptions{Title: " "}); return err }(),
		func() error {
			_, err := c.CreateStream(ctx, CreateStreamOptions{Title: "t", MatchingType: "XOR"})
			return err
		}(),
		func() error { _, err := c.ListStreams(ctx, ListStreamsOptions{Order: "up"}); return err }(),
		func() error { _, err := c.GetStream(ctx, ""); return err }(),
		c.ResumeStream(ctx, ""),
		c.DeleteStream(ctx, ""),
	} {
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("validation: %v", err)
		}
	}
	noSets := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		switch r.URL.Path {
		case pathIndexSets:
			_, _ = w.Write([]byte(`{}`))
		case pathStreams:
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	nc := newTestClient(t, noSets.URL, func(cfg *Config) { cfg.Retry = fastRetry(0) })
	if _, err := nc.CreateStream(ctx, CreateStreamOptions{Title: "t"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("no index sets: %v", err)
	}
	if _, err := nc.CreateStream(ctx, CreateStreamOptions{Title: "t", IndexSetID: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no stream id: %v", err)
	}
	if _, err := nc.listAllStreams(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("list error: %v", err)
	}
	failing := newTestServer(t, statusHandler(http.StatusUnauthorized))
	fc := newTestClient(t, failing.URL, nil)
	if _, err := fc.CreateStream(ctx, CreateStreamOptions{Title: "t"}); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if _, err := fc.CreateStream(ctx, CreateStreamOptions{Title: "t", IndexSetID: "x"}); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if _, err := fc.ListIndexSets(ctx); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if _, err := fc.ListStreams(ctx, ListStreamsOptions{}); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	resumeFail := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		if strings.HasSuffix(r.URL.Path, "/resume") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"stream_id":"s9"}`))
	})
	if id, err := newTestClient(t, resumeFail.URL, nil).CreateStream(ctx, CreateStreamOptions{Title: "t", IndexSetID: "x"}); id != "s9" || !errors.Is(err, ErrNotFound) {
		t.Fatalf("resume failure: %q %v", id, err)
	}
	missing := newTestServer(t, fixtureRoutes(t, map[string]string{"POST " + pathStreams: "createStream.missing_index_set"}))
	if _, err := newTestClient(t, missing.URL, nil).CreateStream(ctx, CreateStreamOptions{Title: "bad", IndexSetID: "x"}); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "indexSetId") {
		t.Fatalf("missing index set: %v", err)
	}
}
