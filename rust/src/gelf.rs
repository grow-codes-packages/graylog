//! GELF 1.1 messages: the [`GelfMessage`] builder, level mapping and the attribute mapping
//! shared by all five languages.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Number, Value};

use crate::core::{Error, Result};
use crate::logging::{AttrValue, Attributes, LogRecord, Severity};

/// GELF specification version written into every message.
pub const GELF_VERSION: &str = "1.1";

/// The GELF `level` field: a syslog severity 0–7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum GelfLevel {
    /// 0.
    Emergency = 0,
    /// 1.
    Alert = 1,
    /// 2.
    Critical = 2,
    /// 3.
    Error = 3,
    /// 4.
    Warning = 4,
    /// 5.
    Notice = 5,
    /// 6.
    Informational = 6,
    /// 7.
    Debug = 7,
}

impl GelfLevel {
    /// The syslog number.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// The level for a syslog number 0–7 (`VALIDATION` otherwise).
    pub fn from_number(n: i64) -> Result<GelfLevel> {
        Ok(match n {
            0 => GelfLevel::Emergency,
            1 => GelfLevel::Alert,
            2 => GelfLevel::Critical,
            3 => GelfLevel::Error,
            4 => GelfLevel::Warning,
            5 => GelfLevel::Notice,
            6 => GelfLevel::Informational,
            7 => GelfLevel::Debug,
            _ => return Err(Error::validation("gelf: level must be an integer 0..7")),
        })
    }
}

/// Maps a severity to a syslog level: TRACE/DEBUG → 7, INFO → 6, WARN → 4, ERROR → 3,
/// FATAL → 2.
pub fn severity_to_gelf_level(severity: Severity) -> GelfLevel {
    match severity {
        Severity::Trace | Severity::Debug => GelfLevel::Debug,
        Severity::Info => GelfLevel::Informational,
        Severity::Warn => GelfLevel::Warning,
        Severity::Error => GelfLevel::Error,
        Severity::Fatal => GelfLevel::Critical,
    }
}

/// Maps a syslog level to a severity: 0–2 → FATAL, 3 → ERROR, 4 → WARN, 5–6 → INFO, 7 → DEBUG
/// (below 0 → FATAL, above 7 → DEBUG).
pub fn gelf_level_to_severity(level: i64) -> Severity {
    match level {
        i64::MIN..=2 => Severity::Fatal,
        3 => Severity::Error,
        4 => Severity::Warn,
        5 | 6 => Severity::Info,
        _ => Severity::Debug,
    }
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// Maps an attribute name to its GELF additional field key (the rule shared by all five
/// languages): a `_` prefix, every character outside `[A-Za-z0-9_.-]` replaced by `_`, and `id`
/// (reserved by GELF) → `_attr_id`.
pub fn gelf_field_key(name: &str) -> String {
    if name == "id" {
        return "_attr_id".to_owned();
    }
    let mut out = String::with_capacity(name.len() + 1);
    out.push('_');
    out.extend(name.chars().map(|c| if is_key_char(c) { c } else { '_' }));
    out
}

/// Maps an attribute value to its GELF form: strings and numbers unchanged, booleans →
/// `"true"`/`"false"` (Graylog drops JSON booleans), arrays and maps → compact JSON strings.
/// `null` returns `None` (the field is omitted).
pub fn gelf_field_value(value: &AttrValue) -> Option<Value> {
    match value {
        Value::Null => None,
        Value::Bool(b) => Some(Value::String(b.to_string())),
        Value::String(_) | Value::Number(_) => Some(value.clone()),
        Value::Array(_) | Value::Object(_) => Some(Value::String(value.to_string())),
    }
}

/// Validates an explicit additional field key (`name` or `_name`) and returns the `_name` wire
/// key. Keys outside `[A-Za-z0-9_.-]`, empty keys and the reserved `id` are `VALIDATION` errors.
pub fn validate_gelf_field_key(key: &str) -> Result<String> {
    let name = key.strip_prefix('_').unwrap_or(key);
    if name.is_empty() || !name.chars().all(is_key_char) {
        return Err(Error::validation(format!(
            "gelf: invalid additional field key {key:?} (allowed: letters, digits, _ . -)"
        )));
    }
    if name == "id" {
        return Err(Error::validation(
            "gelf: additional field \"_id\" is reserved",
        ));
    }
    Ok(format!("_{name}"))
}

/// Renders a time as Unix seconds with millisecond precision (a JSON number such as
/// `1795000000.123`).
pub fn gelf_timestamp(t: SystemTime) -> Number {
    let ms = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as f64,
        Err(e) => -(e.duration().as_millis() as f64),
    };
    Number::from_f64(ms / 1000.0).unwrap_or_else(|| Number::from(0))
}

/// Description of a [`GelfMessage`]; `host` and `short_message` are required.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GelfMessageOptions {
    /// Source host (stored by Graylog as `source`).
    pub host: String,
    /// Stored as `message`.
    pub short_message: String,
    /// Long message (for example a stack trace).
    pub full_message: Option<String>,
    /// Event time (`None` = the server's receive time); sent as Unix seconds with ms precision.
    pub timestamp: Option<SystemTime>,
    /// Syslog level (`None` = not sent).
    pub level: Option<GelfLevel>,
    /// Additional fields; keys are validated like [`GelfMessage::set_field`].
    pub fields: Attributes,
}

/// Options of [`GelfMessage::from_log_record`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FromLogRecordOptions {
    /// Host used when the record has no `resource["host.name"]` (default: the local host name).
    pub host: Option<String>,
}

/// One GELF 1.1 message. Build it with [`GelfMessage::new`] and
/// [`set_field`](GelfMessage::set_field), or from a [`LogRecord`] with
/// [`GelfMessage::from_log_record`]. `Display` renders the compact JSON text.
#[derive(Debug, Clone, PartialEq)]
pub struct GelfMessage {
    host: String,
    short_message: String,
    full_message: Option<String>,
    timestamp: Option<SystemTime>,
    level: Option<GelfLevel>,
    fields: BTreeMap<String, Value>,
}

/// The local host name (`unknown` when it cannot be determined).
pub(crate) fn local_hostname() -> String {
    let from_file = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    from_file("/proc/sys/kernel/hostname")
        .or_else(|| from_file("/etc/hostname"))
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned())
}

impl GelfMessage {
    /// Validates `opts` and returns a message (`VALIDATION` for a blank host or short message or
    /// a bad field key).
    pub fn new(opts: GelfMessageOptions) -> Result<GelfMessage> {
        if opts.host.trim().is_empty() {
            return Err(Error::validation("gelf: host must not be blank"));
        }
        if opts.short_message.trim().is_empty() {
            return Err(Error::validation("gelf: shortMessage must not be blank"));
        }
        let mut m = GelfMessage {
            host: opts.host,
            short_message: opts.short_message,
            full_message: opts.full_message.filter(|s| !s.is_empty()),
            timestamp: opts.timestamp,
            level: opts.level,
            fields: BTreeMap::new(),
        };
        for (k, v) in &opts.fields {
            m.set_field(k, v.clone())?;
        }
        Ok(m)
    }

    /// Shorthand for a message with only `host` and `short_message`.
    pub fn simple(host: impl Into<String>, short_message: impl Into<String>) -> Result<Self> {
        Self::new(GelfMessageOptions {
            host: host.into(),
            short_message: short_message.into(),
            ..GelfMessageOptions::default()
        })
    }

    /// Sets an additional field (`name` or `_name`). The key is validated with
    /// [`validate_gelf_field_key`], the value mapped with [`gelf_field_value`]; `null` removes
    /// the field.
    pub fn set_field(&mut self, key: &str, value: impl Into<AttrValue>) -> Result<()> {
        let wire = validate_gelf_field_key(key)?;
        match gelf_field_value(&value.into()) {
            Some(v) => {
                self.fields.insert(wire, v);
            }
            None => {
                self.fields.remove(&wire);
            }
        }
        Ok(())
    }

    /// Builder form of [`set_field`](Self::set_field).
    pub fn with_field(mut self, key: &str, value: impl Into<AttrValue>) -> Result<Self> {
        self.set_field(key, value)?;
        Ok(self)
    }

    /// `host`.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// `short_message`.
    pub fn short_message(&self) -> &str {
        &self.short_message
    }
    /// `full_message`, when set.
    pub fn full_message(&self) -> Option<&str> {
        self.full_message.as_deref()
    }
    /// Event time, when set.
    pub fn timestamp(&self) -> Option<SystemTime> {
        self.timestamp
    }
    /// `level`, when set.
    pub fn level(&self) -> Option<GelfLevel> {
        self.level
    }
    /// Additional fields (keys with the `_` prefix).
    pub fn fields(&self) -> &BTreeMap<String, Value> {
        &self.fields
    }

    /// The GELF wire object: `version`, `host`, `short_message` and, when set,
    /// `full_message`, `timestamp`, `level` and the additional fields (keys sorted).
    pub fn to_value(&self) -> Value {
        let mut doc: Map<String, Value> = self
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        doc.insert("version".into(), Value::String(GELF_VERSION.into()));
        doc.insert("host".into(), Value::String(self.host.clone()));
        doc.insert(
            "short_message".into(),
            Value::String(self.short_message.clone()),
        );
        if let Some(f) = &self.full_message {
            doc.insert("full_message".into(), Value::String(f.clone()));
        }
        if let Some(t) = self.timestamp {
            doc.insert("timestamp".into(), Value::Number(gelf_timestamp(t)));
        }
        if let Some(l) = self.level {
            doc.insert("level".into(), Value::from(l.number()));
        }
        Value::Object(doc)
    }

    /// UTF-8 JSON bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().to_string().into_bytes()
    }

    /// Converts a record with the mapping shared by all five languages: `host` =
    /// `resource["host.name"]` (else `opts.host`, else the local host name); `short_message` =
    /// body (`-` when blank); `timestamp`; `level` from the severity; resource attributes
    /// flattened with dotted keys (except `host.name`), then the record attributes (they win),
    /// then `_trace_id`, `_span_id` and `_trace_flags` (numeric). Keys go through
    /// [`gelf_field_key`], values through [`gelf_field_value`].
    pub fn from_log_record(record: &LogRecord, opts: &FromLogRecordOptions) -> GelfMessage {
        let host = record
            .resource
            .get("host.name")
            .and_then(Value::as_str)
            .filter(|h| !h.trim().is_empty())
            .map(str::to_owned)
            .or_else(|| opts.host.clone().filter(|h| !h.trim().is_empty()))
            .unwrap_or_else(local_hostname);
        let body = if record.body.trim().is_empty() {
            "-".to_owned()
        } else {
            record.body.clone()
        };
        let mut m = GelfMessage {
            host,
            short_message: body,
            full_message: None,
            timestamp: Some(record.timestamp),
            level: Some(severity_to_gelf_level(record.severity)),
            fields: BTreeMap::new(),
        };
        let mut put = |name: &str, value: &AttrValue| {
            if name.is_empty() {
                return;
            }
            if let Some(v) = gelf_field_value(value) {
                m.fields.insert(gelf_field_key(name), v);
            }
        };
        for (k, v) in flatten_attributes(&record.resource) {
            if k != "host.name" {
                put(&k, &v);
            }
        }
        for (k, v) in &record.attributes {
            put(k, v);
        }
        if let Some(t) = record.trace_id.as_deref().filter(|t| !t.is_empty()) {
            put("trace_id", &Value::String(t.to_owned()));
        }
        if let Some(s) = record.span_id.as_deref().filter(|s| !s.is_empty()) {
            put("span_id", &Value::String(s.to_owned()));
        }
        if let Some(f) = record.trace_flags {
            put("trace_flags", &Value::from(f));
        }
        m
    }
}

impl fmt::Display for GelfMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_value())
    }
}

/// Flattens nested maps into dotted keys; arrays and scalars are leaves.
pub fn flatten_attributes(attributes: &Attributes) -> Attributes {
    fn walk(out: &mut Attributes, prefix: &str, map: &mut dyn Iterator<Item = (&String, &Value)>) {
        for (k, v) in map {
            let key = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            match v {
                Value::Object(inner) => walk(out, &key, &mut inner.iter()),
                other => {
                    out.insert(key, other.clone());
                }
            }
        }
    }
    let mut out = Attributes::new();
    walk(&mut out, "", &mut attributes.iter());
    out
}
