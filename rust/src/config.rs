// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! `GraylogConfig`: common settings (SPEC §2.2) plus the Graylog Open credentials and the GELF /
//! OTLP ingest endpoints.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::core::{
    CommonConfig, CommonConfigBuilder, EnvReader, Error, Hooks, Result, RetryPolicy, Secret,
    TlsConfig,
};

/// Endpoint used when neither the builder nor the environment sets one.
pub const DEFAULT_URL: &str = "http://127.0.0.1:9000";
/// Default GELF UDP and TCP port.
pub const DEFAULT_GELF_PORT: u16 = 12201;
/// Default GELF HTTP port (Graylog has no fixed one; 12202 is the common choice).
pub const DEFAULT_GELF_HTTP_PORT: u16 = 12202;
/// Default port of the OpenTelemetry (gRPC) input.
pub const DEFAULT_OTLP_GRPC_PORT: u16 = 4317;
/// Default `X-Requested-By` value (Graylog requires the header on every non-GET request).
pub const DEFAULT_REQUESTED_BY: &str = "grow-codes-graylog";

/// Vendor variables checked (in order) after `GROW_GRAYLOG_URL`.
const VENDOR_URL_VARS: &[&str] = &["GRAYLOG_URL"];
const VENDOR_API_TOKEN_VARS: &[&str] = &["GRAYLOG_API_TOKEN"];
const VENDOR_USER_VARS: &[&str] = &["GRAYLOG_USER"];
const VENDOR_PASSWORD_VARS: &[&str] = &["GRAYLOG_PASSWORD"];
/// Vendor variable, then the platform stack alias.
const VENDOR_GELF_HOST_VARS: &[&str] = &["GRAYLOG_GELF_HOST", "GRAYLOG_HOST"];
const VENDOR_GELF_PORT_VARS: &[&str] = &["GRAYLOG_GELF_PORT", "GRAYLOG_PORT"];
const VENDOR_GELF_PROTOCOL_VARS: &[&str] = &["GRAYLOG_GELF_PROTOCOL", "GRAYLOG_TRANSPORT"];
const VENDOR_GELF_HTTP_URL_VARS: &[&str] = &["GRAYLOG_GELF_HTTP_URL"];
const VENDOR_OTLP_ENDPOINT_VARS: &[&str] = &["GRAYLOG_OTLP_GRPC_ENDPOINT"];

/// Log transport: the three GELF transports plus OTLP/gRPC.
///
/// [`GelfProtocol::Otlp`] is only valid in [`LogOptions::protocol`](crate::LogOptions); the
/// configuration's `gelf_protocol` must be `udp`, `tcp` or `http`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GelfProtocol {
    /// One (possibly chunked and compressed) datagram per message; best-effort delivery.
    Udp,
    /// NUL-terminated JSON frames over one connection (default).
    #[default]
    Tcp,
    /// Messages posted to the GELF HTTP input (newline-terminated bulk bodies, gzip).
    Http,
    /// OTLP/gRPC to the OpenTelemetry (gRPC) input (log clients only).
    Otlp,
}

impl GelfProtocol {
    /// `udp`, `tcp`, `http` or `otlp`.
    pub fn as_str(self) -> &'static str {
        match self {
            GelfProtocol::Udp => "udp",
            GelfProtocol::Tcp => "tcp",
            GelfProtocol::Http => "http",
            GelfProtocol::Otlp => "otlp",
        }
    }

    /// Whether this is one of the GELF transports (`udp`, `tcp`, `http`).
    pub fn is_gelf(self) -> bool {
        self != GelfProtocol::Otlp
    }
}

impl fmt::Display for GelfProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for GelfProtocol {
    type Err = Error;

    /// Parses `udp`, `tcp`, `http` or `otlp` (case-insensitive, surrounding spaces ignored).
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(GelfProtocol::Udp),
            "tcp" => Ok(GelfProtocol::Tcp),
            "http" => Ok(GelfProtocol::Http),
            "otlp" => Ok(GelfProtocol::Otlp),
            _ => Err(Error::validation("protocol must be udp, tcp, http or otlp")),
        }
    }
}

/// Immutable client configuration; build it with [`GraylogConfig::builder`] or
/// [`GraylogConfig::from_env`]. `Debug` output redacts every credential.
///
/// REST credentials: `api_token` (sent as HTTP Basic `<token>:token`) wins over
/// `username`/`password`. The GELF fields configure the ingest transports of
/// [`GraylogClient::new_log_client`](crate::GraylogClient::new_log_client).
#[derive(Clone)]
pub struct GraylogConfig {
    common: CommonConfig,
    api_token: Option<Secret>,
    username: Option<String>,
    password: Option<Secret>,
    gelf_host: String,
    gelf_port: Option<u16>,
    gelf_protocol: GelfProtocol,
    gelf_http_url: Option<String>,
    gelf_tls: bool,
    otlp_endpoint: Option<String>,
    requested_by: String,
}

impl fmt::Debug for GraylogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraylogConfig")
            .field("common", &self.common)
            .field("api_token", &self.api_token)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("gelf_host", &self.gelf_host)
            .field("gelf_port", &self.gelf_port)
            .field("gelf_protocol", &self.gelf_protocol)
            .field(
                "gelf_http_url",
                &self
                    .gelf_http_url
                    .as_deref()
                    .map(crate::core::redact::redact_url),
            )
            .field("gelf_tls", &self.gelf_tls)
            .field(
                "otlp_endpoint",
                &self
                    .otlp_endpoint
                    .as_deref()
                    .map(crate::core::redact::redact_url),
            )
            .field("requested_by", &self.requested_by)
            .finish()
    }
}

impl GraylogConfig {
    /// A builder with nothing set.
    pub fn builder() -> GraylogConfigBuilder {
        GraylogConfigBuilder::default()
    }

    /// Configuration from the process environment
    /// (explicit > `GROW_GRAYLOG_*` > vendor variables > platform aliases > defaults).
    pub fn from_env() -> Result<Self> {
        Self::builder().build_from_env()
    }

    /// Settings shared by every Grow Codes SDK.
    pub fn common(&self) -> &CommonConfig {
        &self.common
    }

    /// REST base URL.
    pub fn url(&self) -> &url::Url {
        self.common.url()
    }

    /// Graylog access token (`GROW_GRAYLOG_API_TOKEN`, `GRAYLOG_API_TOKEN`).
    pub fn api_token(&self) -> Option<&Secret> {
        self.api_token.as_ref()
    }

    /// User name for HTTP Basic auth (`GROW_GRAYLOG_USER`, `GRAYLOG_USER`).
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Password for HTTP Basic auth (`GROW_GRAYLOG_PASSWORD`, `GRAYLOG_PASSWORD`).
    pub fn password(&self) -> Option<&Secret> {
        self.password.as_ref()
    }

    /// Host of the GELF inputs (`GROW_GRAYLOG_GELF_HOST`, `GRAYLOG_GELF_HOST`, `GRAYLOG_HOST`;
    /// default the host of [`url`](Self::url)).
    pub fn gelf_host(&self) -> &str {
        &self.gelf_host
    }

    /// Explicit GELF port (`GROW_GRAYLOG_GELF_PORT`, `GRAYLOG_GELF_PORT`, `GRAYLOG_PORT`); see
    /// [`gelf_port_for`](Self::gelf_port_for) for the effective port.
    pub fn gelf_port(&self) -> Option<u16> {
        self.gelf_port
    }

    /// Default GELF transport (`GROW_GRAYLOG_GELF_PROTOCOL`, `GRAYLOG_GELF_PROTOCOL`,
    /// `GRAYLOG_TRANSPORT`; default `tcp`).
    pub fn gelf_protocol(&self) -> GelfProtocol {
        self.gelf_protocol
    }

    /// Explicit GELF HTTP URL (`GROW_GRAYLOG_GELF_HTTP_URL`, `GRAYLOG_GELF_HTTP_URL`); see
    /// [`gelf_http_endpoint`](Self::gelf_http_endpoint).
    pub fn gelf_http_url(&self) -> Option<&str> {
        self.gelf_http_url.as_deref()
    }

    /// Whether GELF TCP uses TLS and the default GELF HTTP URL is `https`
    /// (`GROW_GRAYLOG_GELF_TLS`). TLS settings come from the common configuration.
    pub fn gelf_tls(&self) -> bool {
        self.gelf_tls
    }

    /// Explicit OTLP/gRPC endpoint (`GROW_GRAYLOG_OTLP_ENDPOINT`, `GRAYLOG_OTLP_GRPC_ENDPOINT`);
    /// see [`otlp_grpc_endpoint`](Self::otlp_grpc_endpoint).
    pub fn otlp_endpoint(&self) -> Option<&str> {
        self.otlp_endpoint.as_deref()
    }

    /// `X-Requested-By` value of non-GET requests (default [`DEFAULT_REQUESTED_BY`]).
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// The GELF port used for `protocol`: the explicit port when set, else 12202 for HTTP and
    /// 12201 otherwise.
    pub fn gelf_port_for(&self, protocol: GelfProtocol) -> u16 {
        match (self.gelf_port, protocol) {
            (Some(p), _) => p,
            (None, GelfProtocol::Http) => DEFAULT_GELF_HTTP_PORT,
            (None, _) => DEFAULT_GELF_PORT,
        }
    }

    /// Effective GELF HTTP URL: the explicit URL, else
    /// `http(s)://<gelf_host>:<gelf_port_for(http)>/gelf` (`https` with `gelf_tls`).
    pub fn gelf_http_endpoint(&self) -> String {
        if let Some(u) = &self.gelf_http_url {
            return u.clone();
        }
        let scheme = if self.gelf_tls { "https" } else { "http" };
        format!(
            "{scheme}://{}:{}/gelf",
            url_host(&self.gelf_host),
            self.gelf_port_for(GelfProtocol::Http)
        )
    }

    /// Effective OTLP/gRPC endpoint: the explicit endpoint, else `http://<gelf_host>:4317`.
    pub fn otlp_grpc_endpoint(&self) -> String {
        match &self.otlp_endpoint {
            Some(e) => e.clone(),
            None => format!(
                "http://{}:{DEFAULT_OTLP_GRPC_PORT}",
                url_host(&self.gelf_host)
            ),
        }
    }

    /// Checks the service rules (they are also checked when building).
    pub fn validate(&self) -> Result<()> {
        if !self.gelf_protocol.is_gelf() {
            return Err(Error::config("gelfProtocol must be udp, tcp or http"));
        }
        if self.gelf_port == Some(0) {
            return Err(Error::config("gelfPort must be an integer 1..65535"));
        }
        if self.gelf_host.trim().is_empty() {
            return Err(Error::config("gelfHost must not be blank"));
        }
        if let Some(u) = &self.gelf_http_url {
            if !is_http_url(u) {
                return Err(Error::config("gelfHttpUrl must be an http(s) URL"));
            }
        }
        if let Some(u) = &self.otlp_endpoint {
            if !is_http_url(u) {
                return Err(Error::config("otlpEndpoint must be an http(s) URL"));
            }
        }
        if let Some(t) = &self.api_token {
            if t.expose_secret().trim().is_empty() {
                return Err(Error::config("apiToken must not be blank"));
            }
        }
        if self.username.is_some() != self.password.is_some() {
            return Err(Error::config(
                "username and password must be given together",
            ));
        }
        if self.requested_by.trim().is_empty() {
            return Err(Error::config("requestedBy must not be blank"));
        }
        Ok(())
    }
}

/// Wraps an IPv6 literal in brackets for use in a URL authority.
pub(crate) fn url_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

pub(crate) fn is_http_url(s: &str) -> bool {
    url::Url::parse(s)
        .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .unwrap_or(false)
}

/// Builder for [`GraylogConfig`]. Values set here win over the environment.
#[derive(Clone, Default)]
pub struct GraylogConfigBuilder {
    common: CommonConfigBuilder,
    api_token: Option<Secret>,
    username: Option<String>,
    password: Option<Secret>,
    gelf_host: Option<String>,
    gelf_port: Option<u16>,
    gelf_protocol: Option<GelfProtocol>,
    gelf_http_url: Option<String>,
    gelf_tls: Option<bool>,
    otlp_endpoint: Option<String>,
    requested_by: Option<String>,
}

impl fmt::Debug for GraylogConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraylogConfigBuilder")
            .field("common", &self.common)
            .field("api_token", &self.api_token)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("gelf_host", &self.gelf_host)
            .field("gelf_port", &self.gelf_port)
            .field("gelf_protocol", &self.gelf_protocol)
            .finish_non_exhaustive()
    }
}

impl GraylogConfigBuilder {
    /// REST base URL (default [`DEFAULT_URL`]).
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.common = self.common.url(url);
        self
    }
    /// Graylog access token (sent as HTTP Basic `<token>:token`; wins over user/password).
    pub fn api_token(mut self, token: impl Into<Secret>) -> Self {
        self.api_token = Some(token.into());
        self
    }
    /// User name and password for HTTP Basic auth.
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<Secret>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }
    /// User name for HTTP Basic auth (requires a password).
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
    /// Password for HTTP Basic auth (requires a user name).
    pub fn password(mut self, password: impl Into<Secret>) -> Self {
        self.password = Some(password.into());
        self
    }
    /// Host of the GELF inputs (default the host of the URL).
    pub fn gelf_host(mut self, host: impl Into<String>) -> Self {
        self.gelf_host = Some(host.into());
        self
    }
    /// GELF port (default 12201 for UDP/TCP, 12202 for HTTP).
    pub fn gelf_port(mut self, port: u16) -> Self {
        self.gelf_port = Some(port);
        self
    }
    /// Default GELF transport (default `tcp`).
    pub fn gelf_protocol(mut self, protocol: GelfProtocol) -> Self {
        self.gelf_protocol = Some(protocol);
        self
    }
    /// Full URL of the GELF HTTP input.
    pub fn gelf_http_url(mut self, url: impl Into<String>) -> Self {
        self.gelf_http_url = Some(url.into());
        self
    }
    /// TLS for GELF TCP and `https` for the default GELF HTTP URL.
    pub fn gelf_tls(mut self, tls: bool) -> Self {
        self.gelf_tls = Some(tls);
        self
    }
    /// `http(s)://host:port` of an OpenTelemetry (gRPC) input.
    pub fn otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_endpoint = Some(endpoint.into());
        self
    }
    /// `X-Requested-By` value (default [`DEFAULT_REQUESTED_BY`]).
    pub fn requested_by(mut self, value: impl Into<String>) -> Self {
        self.requested_by = Some(value.into());
        self
    }
    /// Connect timeout (default 10 s).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.connect_timeout(timeout);
        self
    }
    /// Per-attempt timeout (default 30 s).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.request_timeout(timeout);
        self
    }
    /// Whole-call timeout including retries (default 120 s).
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.total_timeout(timeout);
        self
    }
    /// Retry policy.
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.common = self.common.retry(retry);
        self
    }
    /// Maximum retries (default 3).
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.common = self.common.max_retries(max_retries);
        self
    }
    /// TLS settings (REST, GELF HTTP/TCP and OTLP).
    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.common = self.common.tls(tls);
        self
    }
    /// Extra trusted CA certificates (PEM file).
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.common = self.common.ca_cert_path(path);
        self
    }
    /// Disables TLS verification (tests only).
    pub fn insecure_skip_verify(mut self, skip: bool) -> Self {
        self.common = self.common.insecure_skip_verify(skip);
        self
    }
    /// Proxy URL (environment proxies are ignored).
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.common = self.common.proxy(proxy);
        self
    }
    /// Extra request header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.common = self.common.header(name, value);
        self
    }
    /// Text appended to the User-Agent.
    pub fn user_agent_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.common = self.common.user_agent_suffix(suffix);
        self
    }
    /// Request hooks.
    pub fn hooks(mut self, hooks: Arc<dyn Hooks>) -> Self {
        self.common = self.common.hooks(hooks);
        self
    }
    /// Edits any other common setting.
    pub fn common(mut self, f: impl FnOnce(CommonConfigBuilder) -> CommonConfigBuilder) -> Self {
        self.common = f(self.common);
        self
    }

    /// Builds without reading the environment.
    pub fn build(self) -> Result<GraylogConfig> {
        let common = self.common.build(DEFAULT_URL)?;
        let gelf_host = match self.gelf_host {
            Some(h) => h
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            None => common
                .url()
                .host_str()
                .unwrap_or("127.0.0.1")
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
        };
        let config = GraylogConfig {
            common,
            api_token: self.api_token,
            username: self.username,
            password: self.password,
            gelf_host,
            gelf_port: self.gelf_port,
            gelf_protocol: self.gelf_protocol.unwrap_or_default(),
            gelf_http_url: self.gelf_http_url,
            gelf_tls: self.gelf_tls.unwrap_or(false),
            otlp_endpoint: self.otlp_endpoint,
            requested_by: self
                .requested_by
                .unwrap_or_else(|| DEFAULT_REQUESTED_BY.to_owned()),
        };
        config.validate()?;
        Ok(config)
    }

    /// Fills unset values from the process environment, then builds.
    pub fn build_from_env(self) -> Result<GraylogConfig> {
        self.build_with_env(&EnvReader::new())
    }

    /// Fills unset values from `env`, then builds.
    pub fn build_with_env(mut self, env: &EnvReader) -> Result<GraylogConfig> {
        self.common = self.common.apply_env(env, VENDOR_URL_VARS)?;
        if self.api_token.is_none() {
            self.api_token = env.secret("API_TOKEN", VENDOR_API_TOKEN_VARS);
        }
        if self.username.is_none() {
            self.username = env.string("USER", VENDOR_USER_VARS);
        }
        if self.password.is_none() {
            self.password = env.secret("PASSWORD", VENDOR_PASSWORD_VARS);
        }
        if self.gelf_host.is_none() {
            self.gelf_host = env.string("GELF_HOST", VENDOR_GELF_HOST_VARS);
        }
        if self.gelf_http_url.is_none() {
            self.gelf_http_url = env.string("GELF_HTTP_URL", VENDOR_GELF_HTTP_URL_VARS);
        }
        if self.otlp_endpoint.is_none() {
            self.otlp_endpoint = env.string("OTLP_ENDPOINT", VENDOR_OTLP_ENDPOINT_VARS);
        }
        if self.gelf_protocol.is_none() {
            if let Some((var, value)) = env.lookup("GELF_PROTOCOL", VENDOR_GELF_PROTOCOL_VARS) {
                match value.parse::<GelfProtocol>() {
                    Ok(p) if p.is_gelf() => self.gelf_protocol = Some(p),
                    _ => {
                        return Err(Error::config(format!(
                            "invalid value in environment variable {var}: expected udp, tcp or http"
                        )))
                    }
                }
            }
        }
        if self.gelf_tls.is_none() {
            self.gelf_tls = env.bool("GELF_TLS", &[])?;
        }
        if self.gelf_port.is_none() {
            if let Some(n) = env.int("GELF_PORT", VENDOR_GELF_PORT_VARS)? {
                let port = u16::try_from(n).ok().filter(|p| *p > 0).ok_or_else(|| {
                    let var = env
                        .lookup("GELF_PORT", VENDOR_GELF_PORT_VARS)
                        .map(|(v, _)| v)
                        .unwrap_or_default();
                    Error::config(format!(
                        "environment variable {var} must be an integer 1..65535"
                    ))
                })?;
                self.gelf_port = Some(port);
            }
        }
        self.build()
    }
}
