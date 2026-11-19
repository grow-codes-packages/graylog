//! Search (Views API), stored messages and their normalization into [`LogRecord`]s.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::client::{decode_json, require_id, seg, GraylogClient};
use crate::core::redact::truncate;
use crate::core::transport::MAX_VENDOR_MESSAGE;
use crate::core::{Error, Method, Result};
use crate::gelf::gelf_level_to_severity;
use crate::logging::{Attributes, LogRecord, Severity, SortOrder};
use crate::models::{format_graylog_time, parse_graylog_time};

const PATH_SEARCH_SYNC: &str = "/api/views/search/sync";
const PATH_MESSAGES: &str = "/api/messages";

/// Sort field of [`GraylogClient::search`] when none is given.
pub const DEFAULT_MESSAGE_SORT_FIELD: &str = "timestamp";
/// Page size of [`GraylogClient::search`] when none is given.
pub const DEFAULT_SEARCH_LIMIT: usize = 100;
/// Largest page `search` requests (OpenSearch's default `max_result_window` for offset + limit).
pub const MAX_SEARCH_LIMIT: usize = 10_000;
/// Relative range of [`GraylogClient::search`] when no range is given (300 s).
pub const DEFAULT_SEARCH_RANGE: Duration = Duration::from_secs(300);

/// One sort key of [`GraylogClient::search`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchSort {
    /// Field name.
    pub field: String,
    /// Order (default descending).
    pub order: SortOrder,
}

impl SearchSort {
    /// Ascending on `field`.
    pub fn asc(field: impl Into<String>) -> Self {
        SearchSort {
            field: field.into(),
            order: SortOrder::Asc,
        }
    }
    /// Descending on `field`.
    pub fn desc(field: impl Into<String>) -> Self {
        SearchSort {
            field: field.into(),
            order: SortOrder::Desc,
        }
    }
}

/// Options of [`GraylogClient::search`]. Give at most one of `range`, `start`/`end` and
/// `keyword`; the default searches the last 5 minutes of every readable stream, newest first,
/// 100 per page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageSearchOptions {
    /// Relative range ending now (whole seconds, rounded up; default 300 s).
    pub range: Option<Duration>,
    /// Start of an absolute range (default `end` − 300 s).
    pub start: Option<SystemTime>,
    /// End of an absolute range (default now).
    pub end: Option<SystemTime>,
    /// Graylog keyword range such as `last five minutes`.
    pub keyword: Option<String>,
    /// Page size (default 100, at most 10 000).
    pub limit: Option<usize>,
    /// Matches to skip (pagination).
    pub offset: usize,
    /// Returned fields (Graylog always adds `_id`); empty = all.
    pub fields: Vec<String>,
    /// Sort keys (default `timestamp` descending); later keys break ties.
    pub sort: Vec<SearchSort>,
    /// Stream ids to search (default: every stream the caller may read).
    pub streams: Vec<String>,
}

/// One search hit or stored message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Message {
    /// Message id (`_id`); with `index` it identifies the message for
    /// [`GraylogClient::get_message`].
    pub id: String,
    /// Index that stores the message.
    pub index: String,
    /// Message timestamp.
    pub timestamp: Option<SystemTime>,
    /// Every returned field as JSON.
    pub fields: Map<String, Value>,
}

impl Message {
    fn new(fields: Map<String, Value>, index: String) -> Message {
        let id = fields
            .get("_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let timestamp = fields
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_graylog_time);
        Message {
            id,
            index,
            timestamp,
            fields,
        }
    }

    /// The message normalized into a [`LogRecord`] (see [`log_record_from_message`]).
    pub fn record(&self) -> LogRecord {
        log_record_from_message(&self.fields)
    }
}

/// One page of [`GraylogClient::search`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MessageSearchResult {
    /// Hits of this page.
    pub messages: Vec<Message>,
    /// Matches of the whole query.
    pub total: u64,
    /// Effective start of the searched range.
    pub from: Option<SystemTime>,
    /// Effective end of the searched range.
    pub to: Option<SystemTime>,
    /// Offset of the next page (`None` when there is none).
    pub next_offset: Option<usize>,
}

impl MessageSearchResult {
    /// Every hit normalized into a [`LogRecord`].
    pub fn records(&self) -> Vec<LogRecord> {
        self.messages.iter().map(Message::record).collect()
    }
}

fn order_str(o: SortOrder) -> &'static str {
    match o {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    }
}

fn timerange(op: &str, opts: &MessageSearchOptions) -> Result<Value> {
    let kinds = [
        opts.range.is_some(),
        opts.start.is_some() || opts.end.is_some(),
        opts.keyword.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if kinds > 1 {
        return Err(Error::validation(format!(
            "{op}: give only one of range, start/end and keyword"
        )));
    }
    if opts.start.is_some() || opts.end.is_some() {
        let end = opts.end.unwrap_or_else(SystemTime::now);
        let start = opts
            .start
            .unwrap_or_else(|| end.checked_sub(DEFAULT_SEARCH_RANGE).unwrap_or(UNIX_EPOCH));
        if start > end {
            return Err(Error::validation(format!("{op}: start is after end")));
        }
        return Ok(
            json!({"type": "absolute", "from": format_graylog_time(start), "to": format_graylog_time(end)}),
        );
    }
    if let Some(k) = &opts.keyword {
        if k.trim().is_empty() {
            return Err(Error::validation(format!(
                "{op}: keyword must not be empty"
            )));
        }
        return Ok(json!({"type": "keyword", "keyword": k}));
    }
    let range = opts.range.unwrap_or(DEFAULT_SEARCH_RANGE);
    if range.is_zero() {
        return Err(Error::validation(format!("{op}: range must be positive")));
    }
    Ok(json!({"type": "relative", "range": range.as_secs_f64().ceil() as u64}))
}

fn first_error(body: &Value) -> Option<String> {
    let errs = body
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            body.pointer("/results/q1/errors")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    let mut any = false;
    for e in errs {
        any = true;
        if let Some(d) = e.get("description").and_then(Value::as_str) {
            if !d.is_empty() {
                return Some(d.to_owned());
            }
        }
    }
    let exceptional = body
        .pointer("/execution/completed_exceptionally")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    (any || exceptional).then(|| "query failed".to_owned())
}

impl GraylogClient {
    /// Runs a Lucene query through the Views search API (`POST /api/views/search/sync`) and
    /// returns one page of messages. An empty query matches everything. Query errors (Graylog
    /// answers HTTP 200 with `errors[]`) are `VALIDATION` errors.
    pub async fn search(
        &self,
        query: &str,
        opts: MessageSearchOptions,
    ) -> Result<MessageSearchResult> {
        const OP: &str = "search";
        let limit = opts.limit.unwrap_or(DEFAULT_SEARCH_LIMIT);
        if !(1..=MAX_SEARCH_LIMIT).contains(&limit) {
            return Err(Error::validation(format!(
                "{OP}: limit must be an integer 1..10000"
            )));
        }
        let sorts = if opts.sort.is_empty() {
            vec![SearchSort::desc(DEFAULT_MESSAGE_SORT_FIELD)]
        } else {
            opts.sort.clone()
        };
        let mut sort_body = Vec::with_capacity(sorts.len());
        for s in &sorts {
            if s.field.trim().is_empty() {
                return Err(Error::validation(format!(
                    "{OP}: sort field must not be empty"
                )));
            }
            sort_body.push(json!({"field": s.field, "order": order_str(s.order)}));
        }
        let query = if query.trim().is_empty() { "*" } else { query };
        let tr = timerange(OP, &opts)?;
        let mut st = json!({"id": "st1", "type": "messages", "limit": limit, "offset": opts.offset, "sort": sort_body});
        if !opts.fields.is_empty() {
            st["fields"] = json!(opts.fields);
        }
        let mut q = json!({
            "id": "q1",
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": tr,
            "search_types": [st],
        });
        if !opts.streams.is_empty() {
            let filters: Vec<Value> = opts
                .streams
                .iter()
                .map(|s| json!({"type": "stream", "id": s}))
                .collect();
            q["filter"] = json!({"type": "or", "filters": filters});
        }
        let resp = self
            .send(
                self.request(Method::POST, PATH_SEARCH_SYNC, OP)
                    .json(&json!({ "queries": [q] }))
                    .idempotent(true),
            )
            .await?;
        let body: Value = decode_json(&resp, OP)?;
        if let Some(text) = first_error(&body) {
            return Err(Error::validation(format!(
                "{OP}: {}",
                truncate(&self.transport().redact(&text), MAX_VENDOR_MESSAGE)
            )));
        }
        let st = body
            .pointer("/results/q1/search_types/st1")
            .cloned()
            .unwrap_or(Value::Null);
        let total = st.get("total_results").and_then(Value::as_u64).unwrap_or(0);
        let time = |k: &str| {
            st.pointer(&format!("/effective_timerange/{k}"))
                .and_then(Value::as_str)
                .and_then(parse_graylog_time)
        };
        let messages: Vec<Message> = st
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|h| {
                let fields = h
                    .get("message")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                let index = h
                    .get("index")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                Message::new(fields, index)
            })
            .collect();
        let next = opts.offset + messages.len();
        Ok(MessageSearchResult {
            next_offset: (!messages.is_empty() && (next as u64) < total).then_some(next),
            from: time("from"),
            to: time("to"),
            total,
            messages,
        })
    }

    /// [`search`](Self::search) over the last `range` (relative, whole seconds rounded up).
    /// `start`, `end` and `keyword` of `opts` must be unset.
    pub async fn search_relative(
        &self,
        query: &str,
        range: Duration,
        mut opts: MessageSearchOptions,
    ) -> Result<MessageSearchResult> {
        if range.is_zero() {
            return Err(Error::validation("searchRelative: range must be positive"));
        }
        opts.range = Some(range);
        self.search(query, opts).await
    }

    /// One stored message by index and id (`GET /api/messages/{index}/{id}`); `NOT_FOUND` when
    /// it does not exist or the caller may not read it. Search hits carry both values.
    pub async fn get_message(&self, index: &str, id: &str) -> Result<Message> {
        const OP: &str = "getMessage";
        require_id(OP, "index", index)?;
        require_id(OP, "id", id)?;
        let body: Value = self
            .get_json(
                &format!("{PATH_MESSAGES}/{}/{}", seg(index), seg(id)),
                &format!("{OP} {index}/{id}"),
            )
            .await?;
        let fields = body
            .pointer("/message/fields")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let idx = body
            .get("index")
            .and_then(Value::as_str)
            .unwrap_or(index)
            .to_owned();
        let mut m = Message::new(fields, idx);
        if m.id.is_empty() {
            m.id = body
                .pointer("/message/id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
        }
        Ok(m)
    }
}

/// Stored field names mapped back to OpenTelemetry resource keys (Graylog replaces `.` with
/// `_`; OTLP resource attributes arrive as `otel_resource_attributes_<name>`).
pub const RESOURCE_FIELDS: &[(&str, &str)] = &[
    ("service_name", "service.name"),
    ("service_version", "service.version"),
    ("service_namespace", "service.namespace"),
    ("service_instance_id", "service.instance.id"),
    ("deployment_environment", "deployment.environment"),
    ("deployment_environment_name", "deployment.environment.name"),
];

fn resource_key(field: &str) -> Option<&'static str> {
    RESOURCE_FIELDS
        .iter()
        .find(|(k, _)| *k == field)
        .map(|(_, v)| *v)
}

const SKIPPED_FIELDS: &[&str] = &[
    "_id",
    "message",
    "timestamp",
    "level",
    "source",
    "streams",
    "trace_id",
    "span_id",
    "trace_flags",
    "otel_trace_id",
    "otel_span_id",
    "otel_trace_flags",
    "otel_severity_number",
    "otel_severity_text",
    "otel_time_unix_nano",
    "otel_observed_time_unix_nano",
    "otel_resource_schema_url",
    "otel_scope_schema_url",
];

fn number_field(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn hex_id(len: usize, values: &[Option<&Value>]) -> Option<String> {
    values.iter().flatten().find_map(|v| {
        let s = v.as_str()?.trim().to_ascii_lowercase();
        (s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
    })
}

fn string_field(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Normalizes stored Graylog message fields (a search hit or [`GraylogClient::get_message`])
/// into a [`LogRecord`]. OTLP fields (`otel_*`) win over GELF fields:
/// - body = `message`, timestamp = `timestamp`, `resource["host.name"]` = `source`;
/// - severity from `otel_severity_number` (named level of its range), else from the syslog
///   `level` (0–2 FATAL, 3 ERROR, 4 WARN, 5–6 INFO, 7 DEBUG), else INFO;
/// - `otel_resource_attributes_<k>` → `resource[RESOURCE_FIELDS[k] or k]`, stored fields named in
///   [`RESOURCE_FIELDS`] → resource (unless already set), `otel_attributes_<k>` →
///   `attributes[k]`, `attr_id` → `attributes["id"]`, every other field except `gl2_*` and the
///   reserved ones → attributes;
/// - trace id from `otel_trace_id` or `trace_id` (32 lower-hex), and only then span id (16
///   lower-hex) and trace flags.
pub fn log_record_from_message(fields: &Map<String, Value>) -> LogRecord {
    let severity = match number_field(fields.get("otel_severity_number")) {
        Some(n) if (1.0..=24.0).contains(&n) => Severity::from_number(n as u8),
        _ => number_field(fields.get("level"))
            .map(|l| gelf_level_to_severity(l as i64))
            .unwrap_or(Severity::Info),
    };
    let mut resource = Attributes::new();
    let mut attributes = Attributes::new();
    if let Some(src) = fields
        .get("source")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        resource.insert("host.name".into(), Value::String(src.to_owned()));
    }
    let mut late_resource: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in fields {
        if v.is_null() || SKIPPED_FIELDS.contains(&k.as_str()) || k.starts_with("gl2_") {
            continue;
        }
        if let Some(name) = k.strip_prefix("otel_resource_attributes_") {
            let key = resource_key(name).unwrap_or(name);
            resource.insert(key.to_owned(), v.clone());
        } else if let Some(name) = k.strip_prefix("otel_attributes_") {
            attributes.insert(name.to_owned(), v.clone());
        } else if let Some(rk) = resource_key(k) {
            late_resource.insert(rk.to_owned(), v.clone());
        } else if k == "attr_id" {
            attributes.insert("id".into(), v.clone());
        } else {
            attributes.insert(k.clone(), v.clone());
        }
    }
    for (k, v) in late_resource {
        resource.entry(k).or_insert(v);
    }
    let trace_id = hex_id(32, &[fields.get("otel_trace_id"), fields.get("trace_id")]);
    let (span_id, trace_flags) = if trace_id.is_some() {
        let span = hex_id(16, &[fields.get("otel_span_id"), fields.get("span_id")]);
        let flags = [fields.get("otel_trace_flags"), fields.get("trace_flags")]
            .into_iter()
            .find_map(|f| number_field(f).filter(|n| (0.0..=255.0).contains(n)))
            .map(|n| n as u8);
        (span, flags)
    } else {
        (None, None)
    };
    LogRecord {
        timestamp: fields
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_graylog_time)
            .unwrap_or(UNIX_EPOCH),
        observed_timestamp: None,
        severity,
        severity_text: severity.text().to_owned(),
        body: string_field(fields.get("message")),
        attributes,
        resource,
        trace_id,
        span_id,
        trace_flags,
    }
}
