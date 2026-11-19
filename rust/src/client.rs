// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! `GraylogClient`: entry point of the SDK (SPEC §2.4).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures::future::BoxFuture;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::config::GraylogConfig;
use crate::core::lifecycle::CloseGroup;
use crate::core::redact::truncate;
use crate::core::transport::{RequestBuilder, MAX_VENDOR_MESSAGE};
use crate::core::{
    Error, ErrorCode, HealthStatus, HttpTransport, Method, Response, Result, Secret,
};
use crate::models::SystemInfo;

pub(crate) const PATH_LB_STATUS: &str = "/api/system/lbstatus";
pub(crate) const PATH_SYSTEM: &str = "/api/system";
pub(crate) const PATH_FIELDS: &str = "/api/system/fields";

/// Graylog's CSRF guard header; required on every non-GET request (HTTP 400 without it). The
/// client always sends it.
pub const HEADER_REQUESTED_BY: &str = "X-Requested-By";
/// Response header that names the Graylog node.
pub const HEADER_NODE_ID: &str = "X-Graylog-Node-Id";

/// Async client for Graylog Open. Cheap to clone (clones share one connection pool).
///
/// REST functions hang off the client directly: [`system_info`](Self::system_info),
/// [`list_inputs`](Self::list_inputs), [`get_input`](Self::get_input),
/// [`list_input_types`](Self::list_input_types), [`get_input_state`](Self::get_input_state),
/// [`create_input`](Self::create_input), [`ensure_gelf_input`](Self::ensure_gelf_input),
/// [`delete_input`](Self::delete_input), [`list_streams`](Self::list_streams),
/// [`get_stream`](Self::get_stream), [`create_stream`](Self::create_stream),
/// [`resume_stream`](Self::resume_stream), [`delete_stream`](Self::delete_stream),
/// [`list_index_sets`](Self::list_index_sets), [`search`](Self::search),
/// [`search_relative`](Self::search_relative), [`get_message`](Self::get_message) and
/// [`list_fields`](Self::list_fields). GELF ingest goes through
/// [`new_log_client`](Self::new_log_client) (the logging category `LogClient`) or the
/// transports ([`GelfUdpTransport`](crate::GelfUdpTransport),
/// [`GelfTcpTransport`](crate::GelfTcpTransport), [`GelfHttpTransport`](crate::GelfHttpTransport));
/// stored logs are read through [`log_query`](Self::log_query) (`LogQueryClient`).
#[derive(Debug, Clone)]
pub struct GraylogClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: GraylogConfig,
    transport: HttpTransport,
    on_close: CloseGroup,
    closed: AtomicBool,
    authorization: Option<Secret>,
}

/// Decodes a JSON body; a malformed body is a non-retryable `UNAVAILABLE`.
pub(crate) fn decode_json<T: DeserializeOwned>(resp: &Response, op: &str) -> Result<T> {
    serde_json::from_slice(resp.bytes()).map_err(|_| {
        Error::unavailable(format!("{op}: invalid JSON response"))
            .with_status(resp.status())
            .with_retryable(false)
    })
}

/// HTTP Basic credentials: `<token>:token` for an API token (it wins), `<user>:<password>`
/// otherwise.
pub(crate) fn basic_credentials(config: &GraylogConfig) -> Option<Secret> {
    let raw = match (config.api_token(), config.username(), config.password()) {
        (Some(token), _, _) => format!("{}:token", token.expose_secret()),
        (None, Some(user), Some(pass)) => format!("{user}:{}", pass.expose_secret()),
        _ => return None,
    };
    Some(Secret::new(
        base64::engine::general_purpose::STANDARD.encode(raw),
    ))
}

impl GraylogClient {
    /// Creates a client from a configuration.
    pub fn new(config: GraylogConfig) -> Result<Self> {
        config.validate()?;
        let transport = HttpTransport::new(config.common())?;
        if let Some(t) = config.api_token() {
            transport.add_known_secret(t);
        }
        if let Some(p) = config.password() {
            transport.add_known_secret(p);
        }
        let authorization = basic_credentials(&config).map(|b64| {
            transport.add_known_secret(&b64);
            Secret::new(format!("Basic {}", b64.expose_secret()))
        });
        Ok(GraylogClient {
            inner: Arc::new(Inner {
                config,
                transport,
                on_close: CloseGroup::new(),
                closed: AtomicBool::new(false),
                authorization,
            }),
        })
    }

    /// Creates a client from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::new(GraylogConfig::from_env()?)
    }

    /// The configuration in use.
    pub fn config(&self) -> &GraylogConfig {
        &self.inner.config
    }

    /// The HTTP transport (for service modules).
    pub fn transport(&self) -> &HttpTransport {
        &self.inner.transport
    }

    /// Registers work that [`GraylogClient::close`] runs (flush, stop tails, …).
    pub fn on_close<F>(&self, f: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static,
    {
        self.inner.on_close.register(f);
    }

    /// A request with the auth header and, for non-GET methods, `X-Requested-By`.
    pub(crate) fn request(&self, method: Method, path: &str, op: &str) -> RequestBuilder<'_> {
        let non_get = method != Method::GET && method != Method::HEAD;
        let mut req = self.inner.transport.request(method, path).operation(op);
        if let Some(auth) = &self.inner.authorization {
            req = req.secret_header("authorization", auth);
        }
        if non_get {
            req = req.header(HEADER_REQUESTED_BY, self.config().requested_by());
        }
        req
    }

    /// Sends a request built by [`request`](Self::request).
    pub(crate) async fn send(&self, req: RequestBuilder<'_>) -> Result<Response> {
        if self.is_closed() {
            return Err(Error::cancelled("client is closed"));
        }
        req.send().await
    }

    /// Sends a GET and decodes the JSON response.
    pub(crate) async fn get_json<T: DeserializeOwned>(&self, path: &str, op: &str) -> Result<T> {
        let resp = self.send(self.request(Method::GET, path, op)).await?;
        decode_json(&resp, op)
    }

    /// Unauthenticated liveness check (`GET /api/system/lbstatus`, `text/plain`). `ALIVE` (200)
    /// → healthy, status `ok`; `THROTTLED` (429) → `degraded`; `DEAD` (503) or any other answer
    /// → `unhealthy`; network errors → `unreachable`. `details["lb_status"]` holds Graylog's
    /// word. Only `CANCELLED` and `CONFIG` are returned as errors.
    pub async fn health(&self) -> Result<HealthStatus> {
        if self.is_closed() {
            return Err(Error::cancelled("health: client is closed"));
        }
        let mut req = self
            .inner
            .transport
            .get(PATH_LB_STATUS)
            .operation("health")
            .header("accept", "text/plain");
        for status in 400..600 {
            req = req.ok_status(status);
        }
        let resp =
            match req.send().await {
                Ok(r) => r,
                Err(err) => {
                    return match err.code() {
                        ErrorCode::Cancelled | ErrorCode::Config => Err(err),
                        _ => Ok(HealthStatus::unhealthy("unreachable")
                            .with_detail("error", err.message())),
                    }
                }
            };
        let text = String::from_utf8_lossy(resp.bytes());
        let first = text.trim().lines().next().unwrap_or("").trim();
        let word = truncate(
            &self.transport().redact(&first.to_ascii_uppercase()),
            MAX_VENDOR_MESSAGE,
        );
        Ok(match resp.status() {
            429 => HealthStatus::unhealthy("degraded").with_detail("lb_status", "THROTTLED"),
            503 => HealthStatus::unhealthy("unhealthy").with_detail("lb_status", "DEAD"),
            200 if word == "ALIVE" => HealthStatus::healthy("ok").with_detail("lb_status", word),
            s => {
                let word = if word.is_empty() {
                    format!("HTTP {s}")
                } else {
                    word
                };
                HealthStatus::unhealthy("unhealthy").with_detail("lb_status", word)
            }
        })
    }

    /// Authenticated round trip (`GET /api/system`); returns the latency. `AUTHENTICATION` on
    /// bad or missing credentials.
    pub async fn ping(&self) -> Result<Duration> {
        let started = Instant::now();
        self.send(self.request(Method::GET, PATH_SYSTEM, "ping"))
            .await?;
        Ok(started.elapsed())
    }

    /// Node information (`GET /api/system`). `version` is Graylog's full string, for example
    /// `7.0.16+58e0f6e`.
    pub async fn system_info(&self) -> Result<SystemInfo> {
        self.get_json(PATH_SYSTEM, "systemInfo").await
    }

    /// Server version as reported by `GET /api/system`, for example `7.0.16+58e0f6e`.
    /// `UNSUPPORTED` when the server reports none.
    pub async fn server_version(&self) -> Result<String> {
        let info = self.system_info().await?;
        if info.version.is_empty() {
            return Err(Error::unsupported(
                "serverVersion: the service does not report a version",
            ));
        }
        Ok(info.version)
    }

    /// Every indexed field name (`GET /api/system/fields`), sorted.
    pub async fn list_fields(&self) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            fields: Option<Vec<serde_json::Value>>,
        }
        let body: Body = self.get_json(PATH_FIELDS, "listFields").await?;
        let mut out: Vec<String> = body
            .fields
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        out.sort();
        Ok(out)
    }

    /// Flushes and closes the log clients created by this client, stops its tails and releases
    /// the connections. Later calls fail with `CANCELLED`. Idempotent.
    pub async fn close(&self) {
        self.inner.on_close.close().await;
        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.transport.close();
    }

    /// Whether [`GraylogClient::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst) || self.inner.transport.is_closed()
    }
}

/// Rejects blank ids and ids with `/` (`VALIDATION`).
pub(crate) fn require_id(op: &str, name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::validation(format!("{op}: {name} is required")));
    }
    if value.contains('/') {
        return Err(Error::validation(format!(
            "{op}: {name} must not contain '/'"
        )));
    }
    Ok(())
}

/// Percent-encodes one path segment.
pub(crate) fn seg(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}
