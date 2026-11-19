package graylog

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestGelfLevels(t *testing.T) {
	cases := map[Severity]GelfLevel{
		SeverityTrace: 7, SeverityDebug: 7, SeverityDebug + 2: 7, SeverityInfo: 6, SeverityInfo + 3: 6,
		SeverityWarn: 4, SeverityError: 3, SeverityFatal: 2, 24: 2, SeverityUnspecified: 6, 30: 6,
	}
	for s, want := range cases {
		if got := SeverityToGelfLevel(s); got != want {
			t.Fatalf("%d → %d, want %d", s, got, want)
		}
	}
	back := map[int]Severity{-1: SeverityFatal, 0: SeverityFatal, 2: SeverityFatal, 3: SeverityError, 4: SeverityWarn, 5: SeverityInfo, 6: SeverityInfo, 7: SeverityDebug, 9: SeverityDebug}
	for l, want := range back {
		if got := GelfLevelToSeverity(l); got != want {
			t.Fatalf("%d → %s, want %s", l, got, want)
		}
	}
}

func TestGelfFieldMapping(t *testing.T) {
	keys := map[string]string{"id": "_attr_id", "user id": "_user_id", "a.b-c_d": "_a.b-c_d", "_x": "__x", "ü": "__"}
	for in, want := range keys {
		if got := GelfFieldKey(in); got != want {
			t.Fatalf("key %q → %q, want %q", in, got, want)
		}
	}
	values := []struct {
		in   any
		want any
		ok   bool
	}{
		{"s", "s", true}, {42, int64(42), true}, {1.5, 1.5, true}, {true, "true", true}, {false, "false", true},
		{nil, nil, false}, {[]any{1, "two"}, `[1,"two"]`, true}, {map[string]any{"a": 1, "b": "x"}, `{"a":1,"b":"x"}`, true},
		{math.NaN(), "NaN", true}, {time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "2026-01-02T03:04:05Z", true},
	}
	for _, v := range values {
		got, ok := GelfFieldValue(v.in)
		if ok != v.ok || got != v.want {
			t.Fatalf("value %v → %v %v", v.in, got, ok)
		}
	}
	for _, k := range []string{"", "_", "a b", "id", "_id", "ü"} {
		if _, err := ValidateGelfFieldKey(k); !errors.Is(err, ErrValidation) {
			t.Fatalf("key %q: %v", k, err)
		}
	}
	if k, err := ValidateGelfFieldKey("_ok.key-1"); err != nil || k != "_ok.key-1" {
		t.Fatal(k, err)
	}
}

func TestGelfMessage(t *testing.T) {
	lvl := GelfLevelError
	ts := time.Date(2026, 11, 18, 11, 6, 40, 123456789, time.UTC)
	m, err := NewGelfMessage(GelfMessageOptions{
		Host: "h", ShortMessage: "short", FullMessage: "line1\nline2", Timestamp: ts, Level: &lvl,
		Fields: map[string]any{"user_id": 7, "_flag": true, "gone": nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetField("extra", map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetField("extra", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.SetField("bad key", 1); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	got := map[string]any{}
	if err := json.Unmarshal(m.Encode(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"version": "1.1", "host": "h", "short_message": "short", "full_message": "line1\nline2",
		"timestamp": 1795000000.123, "level": 3.0, "_user_id": 7.0, "_flag": "true",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %v, want %v (%s)", k, got[k], v, m.String())
		}
	}
	if !strings.Contains(m.String(), `"timestamp":1795000000.123`) {
		t.Fatal(m.String())
	}
	if m.Host() != "h" || m.ShortMessage() != "short" || m.FullMessage() != "line1\nline2" || !m.Timestamp().Equal(ts) || len(m.Fields()) != 2 {
		t.Fatal("getters")
	}
	if l, ok := m.Level(); !ok || l != GelfLevelError {
		t.Fatal("level")
	}
	plain, _ := NewGelfMessage(GelfMessageOptions{Host: "h", ShortMessage: "s"})
	if doc := plain.Map(); len(doc) != 3 {
		t.Fatalf("minimal %v", doc)
	}
	bad := 8
	badLevel := GelfLevel(bad)
	for i, o := range []GelfMessageOptions{
		{ShortMessage: "s"}, {Host: "h", ShortMessage: " "}, {Host: "h", ShortMessage: "s", Level: &badLevel},
		{Host: "h", ShortMessage: "s", Fields: map[string]any{"id": 1}},
	} {
		if _, err := NewGelfMessage(o); !errors.Is(err, ErrValidation) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	stamps := map[time.Time]string{
		time.Unix(1795000000, 0):           "1795000000",
		time.Unix(1795000000, 120e6):       "1795000000.12",
		time.UnixMilli(-1500):              "-1.5",
		time.Unix(1795000000, 999_999_999): "1795000000.999",
	}
	for in, want := range stamps {
		if got := GelfTimestamp(in).String(); got != want {
			t.Fatalf("%s → %s, want %s", in, got, want)
		}
	}
}

func TestGelfMessageFromLogRecord(t *testing.T) {
	flags := uint8(1)
	rec := LogRecord{
		Timestamp: time.UnixMilli(1795000000123), Severity: SeverityWarn, Body: "hello",
		Attributes: map[string]AttrValue{"id": "a1", "user name": "bob", "ok": true, "nested": map[string]AttrValue{"x": 1}, "nothing": nil, "": "skip", "service.name": "attr-wins"},
		Resource:   map[string]AttrValue{"service.name": "svc", "host.name": "web-1", "k8s": map[string]AttrValue{"pod": map[string]AttrValue{"name": "p"}}},
		TraceID:    "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7", TraceFlags: &flags,
	}
	m := GelfMessageFromLogRecord(rec, FromLogRecordOptions{Host: "fallback"})
	doc := m.Map()
	want := map[string]any{
		"host": "web-1", "short_message": "hello", "level": 4, "_attr_id": "a1", "_user_name": "bob", "_ok": "true",
		"_nested": `{"x":1}`, "_service.name": "attr-wins", "_k8s.pod.name": "p", "_trace_id": rec.TraceID, "_span_id": rec.SpanID, "_trace_flags": int64(1),
	}
	for k, v := range want {
		if doc[k] != v {
			t.Fatalf("%s = %#v, want %#v (%v)", k, doc[k], v, doc)
		}
	}
	for _, k := range []string{"_host.name", "_nothing", "_"} {
		if _, ok := doc[k]; ok {
			t.Fatalf("%s must be omitted", k)
		}
	}
	if doc["timestamp"].(json.Number).String() != "1795000000.123" {
		t.Fatal(doc["timestamp"])
	}
	m = GelfMessageFromLogRecord(LogRecord{Body: "  "}, FromLogRecordOptions{Host: "fallback"})
	if m.Host() != "fallback" || m.ShortMessage() != "-" {
		t.Fatalf("defaults %s", m)
	}
	saved := hostnameFn
	t.Cleanup(func() { hostnameFn = saved })
	hostnameFn = func() (string, error) { return "", errors.New("no host") }
	if m := GelfMessageFromLogRecord(LogRecord{Body: "x"}, FromLogRecordOptions{}); m.Host() != "unknown" {
		t.Fatal(m.Host())
	}
	hostnameFn = func() (string, error) { return " ", nil }
	if m := GelfMessageFromLogRecord(LogRecord{Body: "x"}, FromLogRecordOptions{}); m.Host() != "unknown" {
		t.Fatal(m.Host())
	}
	hostnameFn = func() (string, error) { return "box", nil }
	if m := GelfMessageFromLogRecord(LogRecord{Body: "x"}, FromLogRecordOptions{}); m.Host() != "box" {
		t.Fatal(m.Host())
	}
}
