package graylog

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GelfVersion is the GELF specification version written into every message.
const GelfVersion = "1.1"

// GelfLevel is the GELF "level" field: a syslog severity 0–7.
type GelfLevel int

// Syslog levels used by the GELF level field.
const (
	GelfLevelEmergency     GelfLevel = 0
	GelfLevelAlert         GelfLevel = 1
	GelfLevelCritical      GelfLevel = 2
	GelfLevelError         GelfLevel = 3
	GelfLevelWarning       GelfLevel = 4
	GelfLevelNotice        GelfLevel = 5
	GelfLevelInformational GelfLevel = 6
	GelfLevelDebug         GelfLevel = 7
)

// SeverityToGelfLevel maps an OpenTelemetry severity to a syslog level:
// TRACE/DEBUG → 7, INFO → 6, WARN → 4, ERROR → 3, FATAL → 2. Numbers between
// the named values use the range they fall into; unspecified → 6.
func SeverityToGelfLevel(s Severity) GelfLevel {
	switch canonicalSeverity(s) {
	case SeverityTrace, SeverityDebug:
		return GelfLevelDebug
	case SeverityWarn:
		return GelfLevelWarning
	case SeverityError:
		return GelfLevelError
	case SeverityFatal:
		return GelfLevelCritical
	}
	return GelfLevelInformational
}

// GelfLevelToSeverity maps a syslog level to a severity: 0–2 → FATAL,
// 3 → ERROR, 4 → WARN, 5–6 → INFO, 7 → DEBUG (below 0 → FATAL, above 7 → DEBUG).
func GelfLevelToSeverity(level int) Severity {
	switch {
	case level <= 2:
		return SeverityFatal
	case level == 3:
		return SeverityError
	case level == 4:
		return SeverityWarn
	case level >= 7:
		return SeverityDebug
	}
	return SeverityInfo
}

var (
	gelfKeyChars    = regexp.MustCompile(`^[\w.\-]+$`)
	gelfKeySanitize = regexp.MustCompile(`[^\w.\-]`)
)

// GelfFieldKey maps an attribute name to its GELF additional field key (the
// rule shared by all five languages): a "_" prefix, every character outside
// [A-Za-z0-9_.-] replaced by "_", and "id" (reserved by GELF) → "_attr_id".
func GelfFieldKey(name string) string {
	if name == "id" {
		return "_attr_id"
	}
	return "_" + gelfKeySanitize.ReplaceAllString(name, "_")
}

// GelfFieldValue maps an attribute value to its GELF form: strings and finite
// numbers unchanged, booleans → "true"/"false" (Graylog drops JSON booleans),
// NaN/±Inf → their text, time.Time → RFC 3339 UTC text, arrays and maps →
// compact JSON strings. nil reports false (the field is omitted).
func GelfFieldValue(v any) (any, bool) {
	switch x := NormalizeAttrValue(v).(type) {
	case nil:
		return nil, false
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case string, int64, float64:
		return x, true
	default:
		b, _ := json.Marshal(x) // normalized arrays and maps always encode
		return string(b), true
	}
}

// ValidateGelfFieldKey validates an explicit additional field key ("name" or
// "_name") and returns the "_name" wire key. Keys outside [A-Za-z0-9_.-],
// empty keys and the reserved "id" are VALIDATION errors.
func ValidateGelfFieldKey(key string) (string, error) {
	name := strings.TrimPrefix(key, "_")
	if name == "" || !gelfKeyChars.MatchString(name) {
		return "", ValidationError("gelf", fmt.Sprintf("invalid additional field key %q (allowed: letters, digits, _ . -)", key))
	}
	if name == "id" {
		return "", ValidationError("gelf", `additional field "_id" is reserved`)
	}
	return "_" + name, nil
}

// GelfMessageOptions describe a GelfMessage. Host and ShortMessage are
// required.
type GelfMessageOptions struct {
	// Host is the source host (stored by Graylog as "source").
	Host string
	// ShortMessage is stored as "message".
	ShortMessage string
	// FullMessage is a long message (for example a stack trace).
	FullMessage string
	// Timestamp is the event time (zero = the server's receive time). It is
	// sent as Unix seconds with millisecond precision.
	Timestamp time.Time
	// Level is the syslog level 0–7 (nil = not sent).
	Level *GelfLevel
	// Fields are additional fields; keys are validated like SetField.
	Fields map[string]any
}

// GelfMessage is one GELF 1.1 message. Build it with NewGelfMessage and
// SetField, or from a LogRecord with GelfMessageFromLogRecord. It is not safe
// for concurrent modification.
type GelfMessage struct {
	host         string
	shortMessage string
	fullMessage  string
	timestamp    time.Time
	level        GelfLevel
	hasLevel     bool
	fields       map[string]any
}

// NewGelfMessage validates opts and returns a message (VALIDATION error for a
// blank host or short message, a level outside 0–7 or a bad field key).
func NewGelfMessage(opts GelfMessageOptions) (*GelfMessage, error) {
	if strings.TrimSpace(opts.Host) == "" {
		return nil, ValidationError("gelf", "host must not be blank")
	}
	if strings.TrimSpace(opts.ShortMessage) == "" {
		return nil, ValidationError("gelf", "shortMessage must not be blank")
	}
	m := &GelfMessage{host: opts.Host, shortMessage: opts.ShortMessage, fullMessage: opts.FullMessage, timestamp: opts.Timestamp, fields: map[string]any{}}
	if opts.Level != nil {
		if *opts.Level < GelfLevelEmergency || *opts.Level > GelfLevelDebug {
			return nil, ValidationError("gelf", "level must be an integer 0..7")
		}
		m.level, m.hasLevel = *opts.Level, true
	}
	keys := make([]string, 0, len(opts.Fields))
	for k := range opts.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := m.SetField(k, opts.Fields[k]); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// SetField sets an additional field ("name" or "_name"). The key is validated
// with ValidateGelfFieldKey, the value mapped with GelfFieldValue; a nil
// value removes the field.
func (m *GelfMessage) SetField(key string, value any) error {
	wireKey, err := ValidateGelfFieldKey(key)
	if err != nil {
		return err
	}
	if v, ok := GelfFieldValue(value); ok {
		m.fields[wireKey] = v
	} else {
		delete(m.fields, wireKey)
	}
	return nil
}

// Host returns "host".
func (m *GelfMessage) Host() string { return m.host }

// ShortMessage returns "short_message".
func (m *GelfMessage) ShortMessage() string { return m.shortMessage }

// FullMessage returns "full_message" ("" when not set).
func (m *GelfMessage) FullMessage() string { return m.fullMessage }

// Timestamp returns the event time (zero when not set).
func (m *GelfMessage) Timestamp() time.Time { return m.timestamp }

// Level returns "level" and whether it is set.
func (m *GelfMessage) Level() (GelfLevel, bool) { return m.level, m.hasLevel }

// Fields returns a copy of the additional fields (keys with the "_" prefix).
func (m *GelfMessage) Fields() map[string]any {
	out := make(map[string]any, len(m.fields))
	for k, v := range m.fields {
		out[k] = v
	}
	return out
}

// Map returns the GELF wire object: version, host, short_message and, when
// set, full_message, timestamp, level and the additional fields.
func (m *GelfMessage) Map() map[string]any {
	doc := make(map[string]any, len(m.fields)+6)
	for k, v := range m.fields {
		doc[k] = v
	}
	doc["version"] = GelfVersion
	doc["host"] = m.host
	doc["short_message"] = m.shortMessage
	if m.fullMessage != "" {
		doc["full_message"] = m.fullMessage
	}
	if !m.timestamp.IsZero() {
		doc["timestamp"] = GelfTimestamp(m.timestamp)
	}
	if m.hasLevel {
		doc["level"] = int(m.level)
	}
	return doc
}

// MarshalJSON encodes the wire object (keys sorted).
func (m *GelfMessage) MarshalJSON() ([]byte, error) { return json.Marshal(m.Map()) }

// String returns the compact JSON text.
func (m *GelfMessage) String() string {
	b, _ := m.MarshalJSON() // the wire object holds only JSON-safe values
	return string(b)
}

// Encode returns the UTF-8 JSON bytes.
func (m *GelfMessage) Encode() []byte {
	b, _ := m.MarshalJSON() // the wire object holds only JSON-safe values
	return b
}

// GelfTimestamp renders t as Unix seconds with millisecond precision (a JSON
// number such as 1795000000.123).
func GelfTimestamp(t time.Time) json.Number {
	return json.Number(strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', -1, 64))
}

// FromLogRecordOptions configure GelfMessageFromLogRecord.
type FromLogRecordOptions struct {
	// Host is used when the record has no Resource["host.name"] (default: the
	// local host name).
	Host string
}

var hostnameFn = os.Hostname

func localHostname() string {
	if h, err := hostnameFn(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// GelfMessageFromLogRecord converts a LogRecord with the mapping shared by
// all five languages: host = Resource["host.name"] (else opts.Host, else the
// local host name); short_message = Body ("-" when blank); timestamp; level =
// SeverityToGelfLevel(Severity); resource attributes flattened with dotted
// keys (except host.name), then the record attributes (they win), then
// "_trace_id", "_span_id" and "_trace_flags". Keys go through GelfFieldKey,
// values through GelfFieldValue.
func GelfMessageFromLogRecord(rec LogRecord, opts FromLogRecordOptions) *GelfMessage {
	host, _ := rec.Resource["host.name"].(string)
	if strings.TrimSpace(host) == "" {
		host = opts.Host
		if host == "" {
			host = localHostname()
		}
	}
	if strings.TrimSpace(host) == "" {
		host = "unknown"
	}
	body := rec.Body
	if strings.TrimSpace(body) == "" {
		body = "-"
	}
	m := &GelfMessage{
		host: host, shortMessage: body, timestamp: rec.Timestamp,
		level: SeverityToGelfLevel(rec.Severity), hasLevel: true, fields: map[string]any{},
	}
	put := func(name string, value any) {
		if name == "" {
			return
		}
		if v, ok := GelfFieldValue(value); ok {
			m.fields[GelfFieldKey(name)] = v
		}
	}
	res := FlattenAttributes(rec.Resource)
	for _, k := range sortedKeys(res) {
		if k != "host.name" {
			put(k, res[k])
		}
	}
	for _, k := range sortedKeys(rec.Attributes) {
		put(k, rec.Attributes[k])
	}
	if rec.TraceID != "" {
		put("trace_id", rec.TraceID)
	}
	if rec.SpanID != "" {
		put("span_id", rec.SpanID)
	}
	if rec.TraceFlags != nil {
		put("trace_flags", int64(*rec.TraceFlags))
	}
	return m
}

// FlattenAttributes flattens nested maps into dotted keys; arrays and scalars
// are leaves.
func FlattenAttributes(attrs map[string]AttrValue) map[string]AttrValue {
	out := map[string]AttrValue{}
	flattenInto(out, "", attrs)
	return out
}

func flattenInto(out map[string]AttrValue, prefix string, attrs map[string]AttrValue) {
	for k, v := range attrs {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch x := NormalizeAttrValue(v).(type) {
		case map[string]AttrValue:
			flattenInto(out, key, x)
		default:
			out[key] = x
		}
	}
}

func sortedKeys(m map[string]AttrValue) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
