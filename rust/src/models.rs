//! REST models of Graylog Open (system, inputs, streams, index sets) and time helpers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// GELF UDP input class.
pub const INPUT_TYPE_GELF_UDP: &str = "org.graylog2.inputs.gelf.udp.GELFUDPInput";
/// GELF TCP input class.
pub const INPUT_TYPE_GELF_TCP: &str = "org.graylog2.inputs.gelf.tcp.GELFTCPInput";
/// GELF HTTP input class.
pub const INPUT_TYPE_GELF_HTTP: &str = "org.graylog2.inputs.gelf.http.GELFHttpInput";
/// OpenTelemetry (gRPC) input class.
pub const INPUT_TYPE_OTEL_GRPC: &str = "org.graylog.inputs.otel.OTelGrpcInput";
/// Input state of a started input.
pub const INPUT_STATE_RUNNING: &str = "RUNNING";
/// Input state of an input that could not start (for example a busy port).
pub const INPUT_STATE_FAILED: &str = "FAILED";

/// Stream rule type: exact match.
pub const STREAM_RULE_EXACT: i64 = 1;
/// Stream rule type: regular expression.
pub const STREAM_RULE_REGEX: i64 = 2;
/// Stream rule type: greater than.
pub const STREAM_RULE_GREATER: i64 = 3;
/// Stream rule type: smaller than.
pub const STREAM_RULE_SMALLER: i64 = 4;
/// Stream rule type: field presence.
pub const STREAM_RULE_PRESENCE: i64 = 5;
/// Stream rule type: contains.
pub const STREAM_RULE_CONTAINS: i64 = 6;
/// Stream rule type: always match.
pub const STREAM_RULE_ALWAYS_MATCH: i64 = 7;
/// Stream rule type: match input.
pub const STREAM_RULE_MATCH_INPUT: i64 = 8;

/// Parses ISO-8601 timestamps (`Z` or offset) and Graylog's `yyyy-MM-dd HH:mm:ss.SSS` (UTC).
pub(crate) fn parse_graylog_time(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Numeric offset (+hh:mm / -hh:mm) after the time part.
    if s.len() > 16 {
        let (base, tail) = s.split_at(s.len() - 6);
        let b = tail.as_bytes();
        if (b[0] == b'+' || b[0] == b'-') && b[3] == b':' {
            let h: u64 = tail[1..3].parse().ok()?;
            let m: u64 = tail[4..].parse().ok()?;
            let t = humantime::parse_rfc3339_weak(base).ok()?;
            let off = Duration::from_secs(h * 3600 + m * 60);
            return if b[0] == b'+' {
                t.checked_sub(off)
            } else {
                t.checked_add(off)
            };
        }
    }
    humantime::parse_rfc3339_weak(s.trim_end_matches('Z')).ok()
}

/// Formats a time as Graylog's ISO-8601 UTC form with milliseconds (`2026-11-18T20:23:12.920Z`).
pub(crate) fn format_graylog_time(t: SystemTime) -> String {
    let t = if t < UNIX_EPOCH { UNIX_EPOCH } else { t };
    let ms = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let rounded = UNIX_EPOCH + Duration::from_millis(ms);
    humantime::format_rfc3339_millis(rounded).to_string()
}

fn de_time<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
    let v = Option::<Value>::deserialize(d)?;
    Ok(v.as_ref()
        .and_then(Value::as_str)
        .and_then(parse_graylog_time))
}

fn de_string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::String(s)) => s,
        _ => String::new(),
    })
}

fn de_bool<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(matches!(
        Option::<Value>::deserialize(d)?,
        Some(Value::Bool(true))
    ))
}

fn de_i64<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Ok(Option::<Value>::deserialize(d)?
        .as_ref()
        .and_then(Value::as_i64)
        .unwrap_or(0))
}

fn de_map<'de, D: Deserializer<'de>>(d: D) -> Result<Map<String, Value>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    })
}

fn de_rules<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<StreamRule>, D::Error> {
    Ok(Option::<Vec<StreamRule>>::deserialize(d)?.unwrap_or_default())
}

/// Node information (`GET /api/system`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct SystemInfo {
    /// `graylog-server`.
    #[serde(default, deserialize_with = "de_string")]
    pub facility: String,
    /// Release code name.
    #[serde(default, deserialize_with = "de_string")]
    pub codename: String,
    /// Node id.
    #[serde(default, deserialize_with = "de_string")]
    pub node_id: String,
    /// Cluster id.
    #[serde(default, deserialize_with = "de_string")]
    pub cluster_id: String,
    /// Full version, for example `7.0.16+58e0f6e`.
    #[serde(default, deserialize_with = "de_string")]
    pub version: String,
    /// Node start time.
    #[serde(default, deserialize_with = "de_time")]
    pub started_at: Option<SystemTime>,
    /// Host name of the node.
    #[serde(default, deserialize_with = "de_string")]
    pub hostname: String,
    /// Lifecycle (`running`, …).
    #[serde(default, deserialize_with = "de_string")]
    pub lifecycle: String,
    /// Load-balancer status (`alive`, …).
    #[serde(default, deserialize_with = "de_string")]
    pub lb_status: String,
    /// Server time zone.
    #[serde(default, deserialize_with = "de_string")]
    pub timezone: String,
    /// Operating system description.
    #[serde(default, deserialize_with = "de_string")]
    pub operating_system: String,
    /// Whether the node is the cluster leader.
    #[serde(default, deserialize_with = "de_bool")]
    pub is_leader: bool,
    /// Whether the node processes messages.
    #[serde(default, deserialize_with = "de_bool")]
    pub is_processing: bool,
}

/// A message input (`GET /api/system/inputs`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Input {
    /// Input id.
    #[serde(default, deserialize_with = "de_string")]
    pub id: String,
    /// Title.
    #[serde(default, deserialize_with = "de_string")]
    pub title: String,
    /// Input class, for example [`INPUT_TYPE_GELF_TCP`].
    #[serde(default, rename = "type", deserialize_with = "de_string")]
    pub input_type: String,
    /// Display name of the type.
    #[serde(default, deserialize_with = "de_string")]
    pub name: String,
    /// Whether the input runs on every node.
    #[serde(default, deserialize_with = "de_bool")]
    pub global: bool,
    /// Node of a local input.
    #[serde(default, deserialize_with = "de_string")]
    pub node: String,
    /// Creation time.
    #[serde(default, deserialize_with = "de_time")]
    pub created_at: Option<SystemTime>,
    /// Creator.
    #[serde(default, deserialize_with = "de_string")]
    pub creator_user_id: String,
    /// Configuration. Secret attributes come back as `{"is_set": bool}` objects.
    #[serde(default, deserialize_with = "de_map")]
    pub attributes: Map<String, Value>,
    /// Static fields added to every message.
    #[serde(default, deserialize_with = "de_map")]
    pub static_fields: Map<String, Value>,
}

impl Input {
    /// The `port` attribute (0 when absent).
    pub fn port(&self) -> u16 {
        match self.attributes.get("port") {
            Some(Value::Number(n)) => n
                .as_u64()
                .or_else(|| n.as_f64().map(|f| f as u64))
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(0),
            Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
            _ => 0,
        }
    }

    /// The `bind_address` attribute (empty when absent).
    pub fn bind_address(&self) -> &str {
        self.attributes
            .get("bind_address")
            .and_then(Value::as_str)
            .unwrap_or("")
    }
}

/// Runtime state of an input (`GET /api/system/inputstates/{id}`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct InputState {
    /// Input id.
    #[serde(default, deserialize_with = "de_string")]
    pub id: String,
    /// `RUNNING`, `STARTING`, `FAILED`, `STOPPED`, …
    #[serde(default, deserialize_with = "de_string")]
    pub state: String,
    /// Start time.
    #[serde(default, deserialize_with = "de_time")]
    pub started_at: Option<SystemTime>,
    /// Failure details.
    #[serde(default, deserialize_with = "de_string")]
    pub detailed_message: String,
    /// The input.
    #[serde(default, rename = "message_input")]
    pub input: Input,
}

/// One rule of a stream.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StreamRule {
    /// Rule id (ignored when creating).
    #[serde(default, deserialize_with = "de_string", skip_serializing)]
    pub id: String,
    /// Message field.
    #[serde(default, deserialize_with = "de_string")]
    pub field: String,
    /// Rule type ([`STREAM_RULE_EXACT`], …).
    #[serde(default, rename = "type", deserialize_with = "de_i64")]
    pub rule_type: i64,
    /// Value to compare.
    #[serde(default, deserialize_with = "de_string")]
    pub value: String,
    /// Negates the rule.
    #[serde(default, deserialize_with = "de_bool")]
    pub inverted: bool,
    /// Description.
    #[serde(default, deserialize_with = "de_string")]
    pub description: String,
}

impl StreamRule {
    /// An exact-match rule `field == value`.
    pub fn exact(field: impl Into<String>, value: impl Into<String>) -> Self {
        StreamRule {
            field: field.into(),
            rule_type: STREAM_RULE_EXACT,
            value: value.into(),
            ..StreamRule::default()
        }
    }
}

/// A stream.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Stream {
    /// Stream id.
    #[serde(default, deserialize_with = "de_string")]
    pub id: String,
    /// Title.
    #[serde(default, deserialize_with = "de_string")]
    pub title: String,
    /// Description.
    #[serde(default, deserialize_with = "de_string")]
    pub description: String,
    /// Routing rules.
    #[serde(default, deserialize_with = "de_rules")]
    pub rules: Vec<StreamRule>,
    /// Whether the stream is paused.
    #[serde(default, deserialize_with = "de_bool")]
    pub disabled: bool,
    /// Target index set.
    #[serde(default, deserialize_with = "de_string")]
    pub index_set_id: String,
    /// Whether this is the default stream.
    #[serde(default, deserialize_with = "de_bool")]
    pub is_default: bool,
    /// `AND` or `OR`.
    #[serde(default, deserialize_with = "de_string")]
    pub matching_type: String,
    /// Whether matches leave the default stream.
    #[serde(default, deserialize_with = "de_bool")]
    pub remove_matches_from_default_stream: bool,
    /// Creation time.
    #[serde(default, deserialize_with = "de_time")]
    pub created_at: Option<SystemTime>,
    /// Creator.
    #[serde(default, deserialize_with = "de_string")]
    pub creator_user_id: String,
}

/// One page of streams.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StreamPage {
    /// Streams of this page.
    pub streams: Vec<Stream>,
    /// Streams matching the query.
    pub total: u64,
    /// Page number (1-based).
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

/// An index set.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct IndexSet {
    /// Index set id.
    #[serde(default, deserialize_with = "de_string")]
    pub id: String,
    /// Title.
    #[serde(default, deserialize_with = "de_string")]
    pub title: String,
    /// Description.
    #[serde(default, deserialize_with = "de_string")]
    pub description: String,
    /// Index prefix.
    #[serde(default, deserialize_with = "de_string")]
    pub index_prefix: String,
    /// Whether this is the default index set.
    #[serde(default, deserialize_with = "de_bool")]
    pub default: bool,
    /// Whether it is writable.
    #[serde(default, deserialize_with = "de_bool")]
    pub writable: bool,
    /// Shards per index.
    #[serde(default, deserialize_with = "de_i64")]
    pub shards: i64,
    /// Replicas per index.
    #[serde(default, deserialize_with = "de_i64")]
    pub replicas: i64,
}
