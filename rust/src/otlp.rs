//! Optional OTLP/gRPC logs exporter for the Graylog OpenTelemetry (gRPC) input.
//!
//! Graylog Open 7.0 has no OTLP/HTTP input, so this speaks gRPC over HTTP/2 with a small
//! hand-written protobuf encoder (no code generation, no extra runtime dependency).

use std::fmt;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use http_body_util::BodyExt as _;
use serde_json::Value;

use crate::core::config::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT};
use crate::core::redact::{redact_text, truncate};
use crate::core::transport::{default_user_agent, MAX_VENDOR_MESSAGE, SDK_VERSION};
use crate::core::{Error, ErrorCode, Result, Secret, TlsConfig};
use crate::gelf_transport::{compress, GelfCompression};
use crate::logging::{AttrValue, Attributes, ExportOptions, ExportResult, LogExporter, LogRecord};

/// Instrumentation scope written into every OTLP export.
pub const OTLP_SCOPE_NAME: &str = "grow-codes-graylog";
/// gRPC method path of the OTLP logs service.
pub const OTLP_LOGS_EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

// ---- protobuf writer ------------------------------------------------------------------------

fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

fn put_tag(buf: &mut Vec<u8>, field: u32, wire: u8) {
    put_varint(buf, (u64::from(field) << 3) | u64::from(wire));
}

fn put_len(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    put_tag(buf, field, 2);
    put_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn put_uvarint(buf: &mut Vec<u8>, field: u32, v: u64) {
    put_tag(buf, field, 0);
    put_varint(buf, v);
}

fn put_fixed64(buf: &mut Vec<u8>, field: u32, v: u64) {
    put_tag(buf, field, 1);
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_fixed32(buf: &mut Vec<u8>, field: u32, v: u32) {
    put_tag(buf, field, 5);
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encodes an `AnyValue` (`None` for null).
fn any_value(v: &AttrValue) -> Option<Vec<u8>> {
    let mut b = Vec::new();
    match v {
        Value::Null => return None,
        Value::String(s) => put_len(&mut b, 1, s.as_bytes()),
        Value::Bool(x) => put_uvarint(&mut b, 2, u64::from(*x)),
        Value::Number(n) => match n.as_i64() {
            Some(i) => put_uvarint(&mut b, 3, i as u64),
            None => put_fixed64(&mut b, 4, n.as_f64().unwrap_or(0.0).to_bits()),
        },
        Value::Array(items) => {
            let mut arr = Vec::new();
            for item in items {
                if let Some(av) = any_value(item) {
                    put_len(&mut arr, 1, &av);
                }
            }
            put_len(&mut b, 5, &arr);
        }
        Value::Object(map) => {
            let mut kvl = Vec::new();
            for (k, item) in map {
                if let Some(kv) = key_value(k, item) {
                    put_len(&mut kvl, 1, &kv);
                }
            }
            put_len(&mut b, 6, &kvl);
        }
    }
    Some(b)
}

fn key_value(key: &str, v: &AttrValue) -> Option<Vec<u8>> {
    let av = any_value(v)?;
    let mut b = Vec::new();
    put_len(&mut b, 1, key.as_bytes());
    put_len(&mut b, 2, &av);
    Some(b)
}

fn put_attributes(buf: &mut Vec<u8>, field: u32, attrs: &Attributes) {
    for (k, v) in attrs {
        if let Some(kv) = key_value(k, v) {
            put_len(buf, field, &kv);
        }
    }
}

fn unix_nanos(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn decode_hex(s: &str, len: usize) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() != len * 2 || !s.is_ascii() {
        return None;
    }
    (0..len)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn log_record(r: &LogRecord) -> Vec<u8> {
    let mut b = Vec::new();
    put_fixed64(&mut b, 1, unix_nanos(r.timestamp));
    put_uvarint(&mut b, 2, u64::from(r.severity.number()));
    let text = if r.severity_text.is_empty() {
        r.severity.text()
    } else {
        &r.severity_text
    };
    put_len(&mut b, 3, text.as_bytes());
    let body = any_value(&Value::String(r.body.clone())).unwrap_or_default();
    put_len(&mut b, 5, &body);
    put_attributes(&mut b, 6, &r.attributes);
    if let Some(f) = r.trace_flags {
        put_fixed32(&mut b, 8, u32::from(f));
    }
    if let Some(t) = r.trace_id.as_deref().and_then(|t| decode_hex(t, 16)) {
        put_len(&mut b, 9, &t);
    }
    if let Some(s) = r.span_id.as_deref().and_then(|s| decode_hex(s, 8)) {
        put_len(&mut b, 10, &s);
    }
    if let Some(o) = r.observed_timestamp {
        put_fixed64(&mut b, 11, unix_nanos(o));
    }
    b
}

/// Encodes records as one protobuf `ExportLogsServiceRequest`: one `ResourceLogs` per distinct
/// resource (first-seen order) with one `ScopeLogs` each (scope [`OTLP_SCOPE_NAME`]).
pub fn encode_export_logs_request(records: &[LogRecord]) -> Vec<u8> {
    let mut groups: Vec<(&Attributes, Vec<u8>)> = Vec::new();
    for r in records {
        let idx = match groups.iter().position(|(res, _)| **res == r.resource) {
            Some(i) => i,
            None => {
                groups.push((&r.resource, Vec::new()));
                groups.len() - 1
            }
        };
        let lr = log_record(r);
        put_len(&mut groups[idx].1, 2, &lr);
    }
    let mut scope = Vec::new();
    put_len(&mut scope, 1, OTLP_SCOPE_NAME.as_bytes());
    put_len(&mut scope, 2, SDK_VERSION.as_bytes());
    let mut req = Vec::new();
    for (resource, logs) in groups {
        let mut res = Vec::new();
        put_attributes(&mut res, 1, resource);
        let mut scope_logs = Vec::new();
        put_len(&mut scope_logs, 1, &scope);
        scope_logs.extend_from_slice(&logs);
        let mut rl = Vec::new();
        put_len(&mut rl, 1, &res);
        put_len(&mut rl, 2, &scope_logs);
        put_len(&mut req, 1, &rl);
    }
    req
}

// ---- protobuf reader ------------------------------------------------------------------------

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*pos)?;
        *pos += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b < 0x80 {
            return Some(v);
        }
    }
    None
}

/// One decoded field: `(field, wire type, varint value, length-delimited bytes)`.
type Field<'a> = (u64, u64, u64, &'a [u8]);

/// Walks the fields of a message.
fn fields(buf: &[u8]) -> Option<Vec<Field<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos)?;
        let (field, wire) = (tag >> 3, tag & 7);
        match wire {
            0 => out.push((field, wire, read_varint(buf, &mut pos)?, &buf[0..0])),
            1 | 5 => {
                let n = if wire == 1 { 8 } else { 4 };
                pos = pos.checked_add(n).filter(|p| *p <= buf.len())?;
            }
            2 => {
                let n = read_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(n).filter(|e| *e <= buf.len())?;
                out.push((field, wire, 0, &buf[pos..end]));
                pos = end;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// `partial_success` of an `ExportLogsServiceResponse`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtlpPartialSuccess {
    /// Records the server rejected.
    pub rejected_log_records: i64,
    /// Server explanation.
    pub error_message: String,
}

/// Decodes an `ExportLogsServiceResponse` (`VALIDATION` for malformed bytes).
pub fn decode_export_logs_response(buf: &[u8]) -> Result<OtlpPartialSuccess> {
    let bad = || Error::unavailable("otlp.export: malformed response").with_retryable(false);
    let mut out = OtlpPartialSuccess::default();
    for (f, w, _, data) in fields(buf).ok_or_else(bad)? {
        if f == 1 && w == 2 {
            for (pf, pw, v, pdata) in fields(data).ok_or_else(bad)? {
                match (pf, pw) {
                    (1, 0) => out.rejected_log_records = v as i64,
                    (2, 2) => out.error_message = String::from_utf8_lossy(pdata).into_owned(),
                    _ => {}
                }
            }
        }
    }
    Ok(out)
}

// ---- gRPC status mapping --------------------------------------------------------------------

/// Maps a gRPC status code to the SDK error: CANCELLED, INVALID_ARGUMENT/FAILED_PRECONDITION →
/// VALIDATION, DEADLINE_EXCEEDED → TIMEOUT, NOT_FOUND, ALREADY_EXISTS → CONFLICT,
/// PERMISSION_DENIED, RESOURCE_EXHAUSTED → RATE_LIMITED, UNIMPLEMENTED → UNSUPPORTED,
/// UNAUTHENTICATED → AUTHENTICATION; ABORTED, OUT_OF_RANGE, UNAVAILABLE and DATA_LOSS →
/// retryable UNAVAILABLE; anything else → non-retryable UNAVAILABLE.
pub fn error_for_grpc_status(code: u32, message: &str) -> Error {
    let message = if message.is_empty() {
        format!("gRPC status {code}")
    } else {
        message.to_owned()
    };
    let text = format!(
        "otlp.export: {} (gRPC {code})",
        truncate(&message, MAX_VENDOR_MESSAGE)
    );
    let (c, retryable) = match code {
        1 => (ErrorCode::Cancelled, false),
        3 | 9 => (ErrorCode::Validation, false),
        4 => (ErrorCode::Timeout, true),
        5 => (ErrorCode::NotFound, false),
        6 => (ErrorCode::Conflict, false),
        7 => (ErrorCode::PermissionDenied, false),
        8 => (ErrorCode::RateLimited, true),
        12 => (ErrorCode::Unsupported, false),
        16 => (ErrorCode::Authentication, false),
        10 | 11 | 14 | 15 => (ErrorCode::Unavailable, true),
        _ => (ErrorCode::Unavailable, false),
    };
    Error::new(c, text).with_retryable(retryable)
}

/// gRPC status for an HTTP status of a non-gRPC answer (gRPC HTTP/2 spec).
fn grpc_code_for_http(status: u16) -> u32 {
    match status {
        400 => 13,
        401 => 16,
        403 => 7,
        404 => 12,
        429 | 502 | 503 | 504 => 14,
        _ => 2,
    }
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("m={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

// ---- exporter -------------------------------------------------------------------------------

/// Options of [`OtlpGrpcLogExporter::new`].
#[derive(Debug, Clone)]
pub struct OtlpGrpcLogExporterOptions {
    /// `http://host:4317` (plaintext h2c) or `https://host:4317` (TLS).
    pub endpoint: String,
    /// Sent as `authorization: Bearer <token>` (the input's optional `bearer_token`).
    pub bearer_token: Option<Secret>,
    /// Extra gRPC metadata entries.
    pub headers: Vec<(String, String)>,
    /// TLS settings for https endpoints.
    pub tls: TlsConfig,
    /// Deadline of one export call (default 30 s).
    pub timeout: Duration,
    /// Connection setup timeout (default 10 s).
    pub connect_timeout: Duration,
}

impl OtlpGrpcLogExporterOptions {
    /// Options for `endpoint` with the defaults.
    pub fn new(endpoint: impl Into<String>) -> Self {
        OtlpGrpcLogExporterOptions {
            endpoint: endpoint.into(),
            bearer_token: None,
            headers: Vec::new(),
            tls: TlsConfig::default(),
            timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

/// The `LogExporter` for the Graylog OpenTelemetry (gRPC) input
/// (`org.graylog.inputs.otel.OTelGrpcInput`): OTLP `LogsService/Export` over gRPC, gzip when the
/// batch asks for it. Graylog stores `otel_*` fields;
/// [`log_record_from_message`](crate::log_record_from_message) reads them back.
pub struct OtlpGrpcLogExporter {
    client: reqwest::Client,
    url: String,
    timeout: Duration,
    headers: Vec<(String, Secret)>,
    secrets: Vec<String>,
    closed: AtomicBool,
}

impl fmt::Debug for OtlpGrpcLogExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpGrpcLogExporter")
            .field("url", &self.url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn read_file(path: &std::path::Path, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        Error::config(format!("{what} file {} cannot be read", path.display())).with_source(e)
    })
}

impl OtlpGrpcLogExporter {
    /// Validates `opts` (`CONFIG`) and returns an exporter; it connects lazily.
    pub fn new(opts: OtlpGrpcLogExporterOptions) -> Result<Self> {
        let u = url::Url::parse(&opts.endpoint)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| Error::config("otlp: endpoint must be an http(s) URL"))?;
        if opts.timeout.is_zero() || opts.connect_timeout.is_zero() {
            return Err(Error::config("otlp: timeouts must be positive"));
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .use_rustls_tls()
            .http2_prior_knowledge()
            .connect_timeout(opts.connect_timeout)
            .user_agent(default_user_agent());
        if u.scheme() == "https" {
            let tls = &opts.tls;
            if tls.insecure_skip_verify {
                builder = builder.danger_accept_invalid_certs(true);
            }
            let mut pem = Vec::new();
            if let Some(p) = &tls.ca_cert_path {
                pem.extend(read_file(p, "CA certificate")?);
                pem.push(b'\n');
            }
            if let Some(p) = &tls.ca_cert_pem {
                pem.extend_from_slice(p.as_bytes());
            }
            if !pem.is_empty() {
                let certs = reqwest::Certificate::from_pem_bundle(&pem)
                    .map_err(|e| Error::config("CA certificate is not valid PEM").with_source(e))?;
                for c in certs {
                    builder = builder.add_root_certificate(c);
                }
            }
            if let (Some(c), Some(k)) = (&tls.client_cert_path, &tls.client_key_path) {
                let mut pem = read_file(c, "client certificate")?;
                pem.push(b'\n');
                pem.extend(read_file(k, "client key")?);
                let id = reqwest::Identity::from_pem(&pem).map_err(|e| {
                    Error::config("client certificate or key is not valid PEM").with_source(e)
                })?;
                builder = builder.identity(id);
            }
        }
        let client = builder
            .build()
            .map_err(|e| Error::config("otlp: cannot build the HTTP/2 client").with_source(e))?;
        let mut headers = Vec::new();
        let mut secrets = Vec::new();
        for (k, v) in opts.headers {
            if v.len() >= 4 {
                secrets.push(v.clone());
            }
            headers.push((k.to_ascii_lowercase(), Secret::new(v)));
        }
        if let Some(t) = opts.bearer_token {
            secrets.push(t.expose_secret().to_owned());
            headers.push((
                "authorization".into(),
                Secret::new(format!("Bearer {}", t.expose_secret())),
            ));
        }
        let base = opts.endpoint.trim_end_matches('/');
        Ok(OtlpGrpcLogExporter {
            client,
            url: format!("{base}{OTLP_LOGS_EXPORT_PATH}"),
            timeout: opts.timeout,
            headers,
            secrets,
            closed: AtomicBool::new(false),
        })
    }

    fn redact(&self, s: &str) -> String {
        redact_text(s, &self.secrets)
    }

    async fn call(&self, frame: Vec<u8>, gzip: bool) -> Result<OtlpPartialSuccess> {
        let mut req = self
            .client
            .post(&self.url)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("grpc-accept-encoding", "identity")
            .header("grpc-timeout", format!("{}m", self.timeout.as_millis()));
        if gzip {
            req = req.header("grpc-encoding", "gzip");
        }
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.expose_secret());
        }
        let resp = req.body(frame).send().await.map_err(|e| {
            if e.is_timeout() {
                Error::timeout("otlp.export: connection timed out")
            } else {
                Error::unavailable("otlp.export: network error").with_source(e.without_url())
            }
        })?;
        let status = resp.status().as_u16();
        let resp: http::Response<reqwest::Body> = resp.into();
        let (parts, body) = resp.into_parts();
        let header = |map: &http::HeaderMap, name: &str| {
            map.get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        if status != 200 {
            return Err(error_for_grpc_status(
                grpc_code_for_http(status),
                &format!("HTTP {status}"),
            ));
        }
        // Trailers-only answer (errors before any message).
        if let Some(code) = header(&parts.headers, "grpc-status") {
            let code: u32 = code.trim().parse().unwrap_or(2);
            if code != 0 {
                let msg = header(&parts.headers, "grpc-message").unwrap_or_default();
                return Err(error_for_grpc_status(
                    code,
                    &self.redact(&percent_decode(&msg)),
                ));
            }
        }
        let collected = body.collect().await.map_err(|e| {
            Error::unavailable("otlp.export: response could not be read").with_source(e)
        })?;
        if let Some(trailers) = collected.trailers() {
            if let Some(code) = header(trailers, "grpc-status") {
                let code: u32 = code.trim().parse().unwrap_or(2);
                if code != 0 {
                    let msg = header(trailers, "grpc-message").unwrap_or_default();
                    return Err(error_for_grpc_status(
                        code,
                        &self.redact(&percent_decode(&msg)),
                    ));
                }
            }
        }
        let bytes = collected.to_bytes();
        if bytes.len() < 5 {
            return Ok(OtlpPartialSuccess::default());
        }
        let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        let data = bytes.get(5..5 + len).ok_or_else(|| {
            Error::unavailable("otlp.export: malformed response").with_retryable(false)
        })?;
        if bytes[0] == 1 {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(data)
                .read_to_end(&mut out)
                .map_err(|_| {
                    Error::unavailable("otlp.export: malformed response").with_retryable(false)
                })?;
            return decode_export_logs_response(&out);
        }
        decode_export_logs_response(data)
    }
}

#[async_trait]
impl LogExporter for OtlpGrpcLogExporter {
    /// Sends records as one `ExportLogsServiceRequest`. A partial success counts the rejected
    /// records (`VALIDATION` error in the result).
    async fn export(&self, records: &[LogRecord], opts: ExportOptions) -> Result<ExportResult> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::config("otlp.export: exporter is closed"));
        }
        if records.is_empty() {
            return Ok(ExportResult::default());
        }
        let msg = encode_export_logs_request(records);
        let (flag, payload) = if opts.gzip {
            (1u8, compress(GelfCompression::Gzip, &msg))
        } else {
            (0u8, msg)
        };
        let mut frame = Vec::with_capacity(payload.len() + 5);
        frame.push(flag);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let ps = match tokio::time::timeout(self.timeout, self.call(frame, opts.gzip)).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(Error::timeout(format!(
                    "otlp.export: deadline of {} ms exceeded",
                    self.timeout.as_millis()
                )))
            }
        };
        let n = records.len();
        let rejected = usize::try_from(ps.rejected_log_records.max(0))
            .unwrap_or(n)
            .min(n);
        if rejected == 0 {
            return Ok(ExportResult::accepted(n));
        }
        let mut msg = format!("otlp.export: {rejected} records rejected");
        if !ps.error_message.is_empty() {
            msg.push_str(": ");
            msg.push_str(&truncate(
                &self.redact(&ps.error_message),
                MAX_VENDOR_MESSAGE,
            ));
        }
        Ok(ExportResult::partial(
            n - rejected,
            rejected,
            Some(Error::validation(msg)),
        ))
    }

    /// Later exports fail with `CONFIG`. Idempotent.
    async fn shutdown(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
