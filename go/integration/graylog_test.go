package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	graylog "github.com/grow-codes-packages/graylog/go"
)

// setup loads /bootstrap/env and returns a client from the environment.
func setup(t *testing.T) *graylog.Client {
	t.Helper()
	bootstrap := os.Getenv("GROW_BOOTSTRAP_ENV")
	if bootstrap == "" {
		bootstrap = "/bootstrap/env"
	}
	loadBootstrapEnv(t, bootstrap)
	if os.Getenv("GROW_GRAYLOG_URL") == "" {
		t.Skip("GROW_GRAYLOG_URL is not set; run through docker/compose.yml")
	}
	c, err := graylog.NewClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func runID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "gr" + hex.EncodeToString(b)
}

// waitMessages polls Search until at least n messages match query.
func waitMessages(t *testing.T, c *graylog.Client, query string, n int, opts graylog.MessageSearchOptions) graylog.MessageSearchResult {
	t.Helper()
	if opts.Range == 0 && opts.Start.IsZero() && opts.Keyword == "" {
		opts.Range = 15 * time.Minute
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := c.Search(t.Context(), query, opts)
		if err == nil && len(res.Messages) >= n {
			return res
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("search %q: %v", query, err)
			}
			t.Fatalf("search %q: %d messages, want %d", query, len(res.Messages), n)
		}
		// A sort on a field that is not mapped yet (the first message is
		// still being indexed) fails with "all shards failed": retry.
		time.Sleep(500 * time.Millisecond)
	}
}

func TestCoreAndSystem(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	hs, err := c.Health(ctx)
	if err != nil || !hs.Healthy || hs.Status != "ok" || hs.Details["lb_status"] != "ALIVE" {
		t.Fatalf("health %+v %v", hs, err)
	}
	if d, err := c.Ping(ctx); err != nil || d <= 0 {
		t.Fatalf("ping %s %v", d, err)
	}
	version, err := c.ServerVersion(ctx)
	if err != nil || !strings.HasPrefix(version, "7.") {
		t.Fatalf("serverVersion %q %v", version, err)
	}
	t.Logf("Graylog server version %s", version)
	info, err := c.SystemInfo(ctx)
	if err != nil || info.Version != version || info.NodeID == "" || !info.IsProcessing {
		t.Fatalf("systemInfo %+v %v", info, err)
	}
	fields, err := c.ListFields(ctx)
	if err != nil || !slices.Contains(fields, "message") {
		t.Fatalf("listFields %v %v", fields, err)
	}

	cfg := c.Config()
	cfg.APIToken = graylog.NewSecret("not-a-valid-token")
	cfg.Username, cfg.Password = "", graylog.Secret{}
	bad, err := graylog.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	if _, err := bad.Ping(ctx); !errors.Is(err, graylog.ErrAuthentication) || strings.Contains(err.Error(), "not-a-valid-token") {
		t.Fatalf("bad token: %v", err)
	}
	pw := c.Config()
	pw.APIToken = graylog.Secret{}
	pwc, err := graylog.NewClient(pw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pwc.Close() }()
	if _, err := pwc.Ping(ctx); err != nil {
		t.Fatalf("password auth: %v", err)
	}
}

func TestInputs(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	inputs, err := c.ListInputs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tcpID := os.Getenv("GRAYLOG_INPUT_ID_GELF_TCP")
	if !slices.ContainsFunc(inputs, func(in graylog.Input) bool { return in.ID == tcpID }) {
		t.Fatalf("bootstrap TCP input %s not listed", tcpID)
	}
	types, err := c.ListInputTypes(ctx)
	if err != nil || types[graylog.InputTypeGelfHTTP] == "" {
		t.Fatalf("listInputTypes: %v", err)
	}
	in, err := c.GetInput(ctx, tcpID)
	if err != nil || in.Type != graylog.InputTypeGelfTCP || in.Port() != 12201 {
		t.Fatalf("getInput %+v %v", in, err)
	}
	st, err := c.GetInputState(ctx, tcpID)
	if err != nil || st.State != graylog.InputStateRunning {
		t.Fatalf("getInputState %+v %v", st, err)
	}

	// Existing input is reused.
	ensured, err := c.EnsureGelfInput(ctx, graylog.GelfTCP, 12201, graylog.EnsureGelfInputOptions{})
	if err != nil || ensured.Created || ensured.ID != tcpID {
		t.Fatalf("ensure existing %+v %v", ensured, err)
	}
	// New input is created, RUNNING, then deleted.
	ensured, err = c.EnsureGelfInput(ctx, graylog.GelfUDP, 12291, graylog.EnsureGelfInputOptions{})
	if err != nil || !ensured.Created || ensured.Port() != 12291 {
		t.Fatalf("ensure new %+v %v", ensured, err)
	}
	if err := c.DeleteInput(ctx, ensured.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetInput(ctx, ensured.ID); !errors.Is(err, graylog.ErrNotFound) {
		t.Fatalf("deleted input: %v", err)
	}

	id, err := c.CreateInput(ctx, graylog.InputTypeGelfHTTP, map[string]any{
		"bind_address": "0.0.0.0", "port": 12292, "enable_bulk_receiving": true, "max_chunk_size": 1048576,
		"recv_buffer_size": 1048576, "number_worker_threads": 1,
	}, graylog.CreateInputOptions{Title: "grow-sdk go " + runID(t)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.GetInput(ctx, id)
	if err != nil || got.Port() != 12292 || !strings.HasPrefix(got.Title, "grow-sdk go ") {
		t.Fatalf("created input %+v %v", got, err)
	}
	if err := c.DeleteInput(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteInput(ctx, id); !errors.Is(err, graylog.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := c.CreateInput(ctx, "org.example.NoSuchInput", map[string]any{}, graylog.CreateInputOptions{}); !errors.Is(err, graylog.ErrNotFound) {
		t.Fatalf("unknown type: %v", err)
	}
	// A busy port fails to start → CONFLICT, and the created input is removed.
	before, _ := c.ListInputs(ctx)
	if _, err := c.EnsureGelfInput(ctx, graylog.GelfHTTP, 12201, graylog.EnsureGelfInputOptions{Timeout: 20 * time.Second}); !errors.Is(err, graylog.ErrConflict) {
		t.Fatalf("busy port: %v", err)
	}
	after, _ := c.ListInputs(ctx)
	if len(after) != len(before) {
		t.Fatalf("failed input not removed: %d → %d", len(before), len(after))
	}
}

func TestStreamsAndSearch(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	run := runID(t)

	sets, err := c.ListIndexSets(ctx)
	if err != nil || !slices.ContainsFunc(sets, func(s graylog.IndexSet) bool { return s.Default && s.ID == os.Getenv("GRAYLOG_DEFAULT_INDEX_SET_ID") }) {
		t.Fatalf("listIndexSets %+v %v", sets, err)
	}
	page, err := c.ListStreams(ctx, graylog.ListStreamsOptions{})
	if err != nil || !slices.ContainsFunc(page.Streams, func(s graylog.Stream) bool { return s.IsDefault }) {
		t.Fatalf("listStreams %+v %v", page, err)
	}
	streamID, err := c.CreateStream(ctx, graylog.CreateStreamOptions{
		Title: "grow-sdk go " + run, Description: "go integration",
		Rules: []graylog.StreamRule{{Field: "marker", Type: graylog.StreamRuleExact, Value: run, Description: "marker"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.DeleteStream(context.WithoutCancel(ctx), streamID) }()
	s, err := c.GetStream(ctx, streamID)
	if err != nil || s.Disabled || s.Title != "grow-sdk go "+run || len(s.Rules) != 1 {
		t.Fatalf("getStream %+v %v", s, err)
	}
	if err := c.ResumeStream(ctx, streamID); err != nil {
		t.Fatal(err)
	}

	// Write three messages through GELF TCP.
	tr, err := c.GelfTransport(graylog.GelfTCP, graylog.GelfTransportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Close() }()
	var msgs []*graylog.GelfMessage
	base := time.Now().Add(-2 * time.Second)
	for i := 0; i < 3; i++ {
		lvl := graylog.GelfLevelWarning
		m, err := graylog.NewGelfMessage(graylog.GelfMessageOptions{
			Host: "go-it", ShortMessage: run + " search #" + string(rune('0'+i)), Timestamp: base.Add(time.Duration(i) * time.Millisecond * 10),
			Level: &lvl, Fields: map[string]any{"marker": run, "seq": i},
		})
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
	}
	if res, err := tr.Send(ctx, msgs, graylog.GelfSendOptions{}); err != nil || res.Sent != 3 {
		t.Fatalf("send %+v %v", res, err)
	}

	res := waitMessages(t, c, "marker:"+run, 3, graylog.MessageSearchOptions{
		Streams: []string{streamID}, Sort: []graylog.SearchSort{{Field: "seq", Order: graylog.OrderAsc}},
		Fields: []string{"message", "seq", "marker", "timestamp"},
	})
	if res.Total != 3 || res.Messages[0].Fields["seq"] != 0.0 || res.Messages[2].Fields["seq"] != 2.0 || res.Messages[0].Fields["level"] != nil {
		t.Fatalf("stream search %+v", res)
	}
	paged, err := c.Search(ctx, "marker:"+run, graylog.MessageSearchOptions{
		Start: time.Now().Add(-10 * time.Minute), End: time.Now().Add(time.Minute), Limit: 1, Offset: 1,
		Sort: []graylog.SearchSort{{Field: "seq", Order: graylog.OrderDesc}},
	})
	if err != nil || len(paged.Messages) != 1 || paged.Messages[0].Fields["seq"] != 1.0 || paged.NextOffset != 2 {
		t.Fatalf("paged %+v %v", paged, err)
	}
	rel, err := c.SearchRelative(ctx, "marker:"+run, 10*time.Minute, graylog.MessageSearchOptions{})
	if err != nil || rel.Total != 3 {
		t.Fatalf("searchRelative %+v %v", rel, err)
	}
	kw, err := c.Search(ctx, "marker:"+run, graylog.MessageSearchOptions{Keyword: "last 1 hour"})
	if err != nil || kw.Total != 3 {
		t.Fatalf("keyword %+v %v", kw, err)
	}
	hit := rel.Messages[0]
	m, err := c.GetMessage(ctx, hit.Index, hit.ID)
	if err != nil || m.ID != hit.ID || m.Fields["marker"] != run {
		t.Fatalf("getMessage %+v %v", m, err)
	}
	rec := m.Record()
	if rec.Severity != graylog.SeverityWarn || rec.Resource["host.name"] != "go-it" || !strings.HasPrefix(rec.Body, run) {
		t.Fatalf("record %+v", rec)
	}
	if _, err := c.GetMessage(ctx, hit.Index, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, graylog.ErrNotFound) {
		t.Fatalf("missing message: %v", err)
	}
	if _, err := c.Search(ctx, "marker:((", graylog.MessageSearchOptions{}); !errors.Is(err, graylog.ErrValidation) {
		t.Fatalf("invalid query: %v", err)
	}

	if err := c.DeleteStream(ctx, streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetStream(ctx, streamID); !errors.Is(err, graylog.ErrNotFound) {
		t.Fatalf("deleted stream: %v", err)
	}
}

// TestGelfLogClients sends records through every GELF transport with the
// shared attribute mapping and reads them back as LogRecords.
func TestGelfLogClients(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	for _, p := range []graylog.GelfProtocol{graylog.GelfTCP, graylog.GelfHTTP, graylog.GelfUDP} {
		t.Run(string(p), func(t *testing.T) {
			run := runID(t)
			lc, err := c.NewLogClient(graylog.LogOptions{
				Protocol: p,
				LogClientOptions: graylog.LogClientOptions{
					Resource: map[string]graylog.AttrValue{"service.name": "go-it", "deployment.environment": "test", "host.name": "go-host"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lc.Close(context.WithoutCancel(ctx)) }()
			send := func() {
				lc.Send(ctx, graylog.LogRecord{
					Severity: graylog.SeverityError, Body: run + " via " + string(p),
					Attributes: map[string]graylog.AttrValue{
						"marker": run, "flag": true, "count": 42, "ratio": 1.5, "id": "attr-id",
						"nested": map[string]graylog.AttrValue{"a": 1}, "list": []graylog.AttrValue{1, "two"}, "password": "hunter2",
					},
					TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7",
				})
				if err := lc.Flush(ctx); err != nil {
					t.Fatal(err)
				}
			}
			send()
			var recs []graylog.LogRecord
			deadline := time.Now().Add(60 * time.Second)
			for len(recs) == 0 {
				res, err := c.LogQuery(graylog.LogQueryOptions{}).Search(ctx, "marker:"+run, graylog.SearchOptions{Start: time.Now().Add(-15 * time.Minute)})
				if err != nil {
					t.Fatal(err)
				}
				recs = res.Records
				if len(recs) > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s: record not found", p)
				}
				time.Sleep(time.Second)
				if p == graylog.GelfUDP {
					send() // UDP is best-effort: retry the send
				}
			}
			r := recs[0]
			if r.Severity != graylog.SeverityError || r.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || r.SpanID != "00f067aa0ba902b7" {
				t.Fatalf("%s record %+v", p, r)
			}
			if r.Attributes["flag"] != "true" || r.Attributes["count"] != 42.0 || r.Attributes["ratio"] != 1.5 || r.Attributes["id"] != "attr-id" ||
				r.Attributes["nested"] != `{"a":1}` || r.Attributes["list"] != `[1,"two"]` || r.Attributes["password"] != "[REDACTED]" {
				t.Fatalf("%s attributes %+v", p, r.Attributes)
			}
			if r.Resource["host.name"] != "go-host" {
				t.Fatalf("%s resource %+v", p, r.Resource)
			}
			svc := r.Resource["service.name"]
			if svc == nil {
				svc = r.Attributes["service.name"]
			}
			if svc != "go-it" {
				t.Fatalf("%s service.name round trip: resource %+v attributes %+v", p, r.Resource, r.Attributes)
			}
			if s := lc.Stats(); s.Dropped != 0 || s.Failed != 0 {
				t.Fatalf("%s stats %+v", p, s)
			}
		})
	}
}

func TestLogQueryAndTail(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	q := c.LogQuery(graylog.LogQueryOptions{})
	streams, err := q.ListStreams(ctx)
	if err != nil || !slices.Contains(streams, "Default Stream") {
		t.Fatalf("listStreams %v %v", streams, err)
	}
	labels, err := q.ListLabels(ctx)
	if err != nil || !slices.Contains(labels, "source") {
		t.Fatalf("listLabels %v %v", labels, err)
	}

	run := runID(t)
	got := make(chan graylog.LogRecord, 10)
	h, err := q.Tail(ctx, "marker:"+run, func(r graylog.LogRecord) { got <- r }, graylog.TailOptions{Start: time.Now().Add(-time.Minute), Interval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	lc, err := c.NewLogClient(graylog.LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lc.Logger("tail", map[string]graylog.AttrValue{"marker": run}).Warn(ctx, run+" tail one")
	if err := lc.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		// Graylog stores field names with "." replaced by "_": logger.name
		// reads back as logger_name.
		if r.Body != run+" tail one" || r.Attributes["logger_name"] != "tail" {
			t.Fatalf("tail record %+v", r)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("tail: no record")
	}
	found, err := q.WaitForLog(ctx, "marker:"+run, graylog.WaitForLogOptions{Timeout: 30 * time.Second, Search: graylog.SearchOptions{Start: time.Now().Add(-time.Hour)}})
	if err != nil || found.Severity != graylog.SeverityWarn {
		t.Fatalf("waitForLog %+v %v", found, err)
	}
	h.Stop()
}

func TestOTLPLogClient(t *testing.T) {
	c := setup(t)
	if os.Getenv("GRAYLOG_OTLP_GRPC_ENDPOINT") == "" {
		t.Skip("the OpenTelemetry (gRPC) input is not installed")
	}
	ctx := t.Context()
	run := runID(t)
	lc, err := c.NewLogClient(graylog.LogOptions{
		Protocol:         graylog.ProtocolOTLP,
		LogClientOptions: graylog.LogClientOptions{Resource: map[string]graylog.AttrValue{"service.name": "go-otlp"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	lc.Send(ctx, graylog.LogRecord{
		Severity: graylog.SeverityWarn, Body: run + " via otlp", Attributes: map[string]graylog.AttrValue{"marker": run},
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7",
	})
	if err := lc.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if s := lc.Stats(); s.Sent != 1 || s.Failed != 0 {
		t.Fatalf("otlp stats %+v", s)
	}
	r, err := c.LogQuery(graylog.LogQueryOptions{}).WaitForLog(ctx, "otel_attributes_marker:"+run, graylog.WaitForLogOptions{Timeout: 60 * time.Second, Search: graylog.SearchOptions{Start: time.Now().Add(-time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Severity != graylog.SeverityWarn || r.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || r.Resource["service.name"] != "go-otlp" || r.Attributes["marker"] != run {
		t.Fatalf("otlp record %+v", r)
	}
}

// TestDirectTransports uses the transport constructors and the message
// builder directly.
func TestDirectTransports(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	cfg := c.Config()
	run := runID(t)
	udp, err := graylog.NewGelfUDPTransport(graylog.GelfUDPOptions{Host: cfg.GelfHost, Port: 12201, Compression: graylog.GelfCompressionZlib})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	tcp, err := graylog.NewGelfTCPTransport(graylog.GelfTCPOptions{Host: cfg.GelfHost, Port: 12201})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	httpT, err := graylog.NewGelfHTTPTransport(graylog.GelfHTTPOptions{URL: cfg.GelfHTTPEndpoint(), DisableBulk: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = httpT.Close() }()
	for _, tr := range []graylog.GelfTransport{tcp, httpT, udp} {
		m, err := graylog.NewGelfMessage(graylog.GelfMessageOptions{Host: "direct", ShortMessage: run + " direct " + string(tr.Protocol()), FullMessage: "line1\nline2"})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.SetField("marker", run); err != nil {
			t.Fatal(err)
		}
		if err := m.SetField("transport", string(tr.Protocol())); err != nil {
			t.Fatal(err)
		}
		query := "marker:" + run + " AND transport:" + string(tr.Protocol())
		deadline := time.Now().Add(60 * time.Second)
		for {
			if res, err := tr.Send(ctx, []*graylog.GelfMessage{m}, graylog.GelfSendOptions{}); err != nil || res.Sent != 1 {
				t.Fatalf("%s send %+v %v", tr.Protocol(), res, err)
			}
			res, err := c.SearchRelative(ctx, query, 15*time.Minute, graylog.MessageSearchOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Messages) > 0 {
				if res.Messages[0].Fields["full_message"] != "line1\nline2" {
					t.Fatalf("%s full_message %+v", tr.Protocol(), res.Messages[0].Fields)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: message not found", tr.Protocol())
			}
			time.Sleep(2 * time.Second) // TCP/HTTP resend only after a 2 s grace; duplicates are fine
		}
	}
}
