//! GELF transports: [`GelfUdpTransport`] (chunked, compressed datagrams),
//! [`GelfTcpTransport`] (NUL-framed, TLS, reconnect) and [`GelfHttpTransport`] (bulk, gzip).

use std::fmt;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use crate::client::HEADER_REQUESTED_BY;
use crate::config::{url_host, GelfProtocol, DEFAULT_GELF_PORT, DEFAULT_REQUESTED_BY};
use crate::core::config::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT};
use crate::core::redact::is_sensitive_header;
use crate::core::{CommonConfig, Error, HttpTransport, Result, RetryPolicy, Secret, TlsConfig};
use crate::gelf::GelfMessage;

/// Per-call options of [`GelfTransport::send`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GelfSendOptions {
    /// Overrides the HTTP transport's compression for this call (`None` = transport default).
    /// UDP and TCP ignore it.
    pub gzip: Option<bool>,
}

/// Outcome of [`GelfTransport::send`].
#[derive(Debug, Default)]
pub struct GelfSendResult {
    /// Messages handed to the network.
    pub sent: usize,
    /// Messages rejected client-side (for example too large for UDP).
    pub rejected: usize,
    /// Why messages were rejected.
    pub error: Option<Error>,
}

/// Sends GELF messages to a Graylog input. Implementations are safe for concurrent use.
#[async_trait]
pub trait GelfTransport: Send + Sync + fmt::Debug {
    /// `udp`, `tcp` or `http`.
    fn protocol(&self) -> GelfProtocol;

    /// Delivers messages in order. Network failures are errors (`UNAVAILABLE`, `TIMEOUT`);
    /// client-side rejections are counted in the result. A closed transport returns `CONFIG`.
    async fn send(&self, messages: &[GelfMessage], opts: GelfSendOptions)
        -> Result<GelfSendResult>;

    /// Releases sockets. Idempotent.
    async fn close(&self) -> Result<()>;
}

/// Payload compression of the UDP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GelfCompression {
    /// gzip (default).
    #[default]
    Gzip,
    /// zlib.
    Zlib,
    /// No compression.
    None,
}

/// Chunk magic bytes `0x1e 0x0f`.
pub const GELF_CHUNK_MAGIC: [u8; 2] = [0x1e, 0x0f];
/// Chunk header: magic (2), message id (8), sequence number (1), sequence count (1).
pub const GELF_CHUNK_HEADER_SIZE: usize = 12;
/// GELF limit of chunks per message.
pub const GELF_MAX_CHUNKS: usize = 128;
/// Default datagram size including the chunk header (fits a 1500-byte Ethernet MTU).
pub const DEFAULT_UDP_CHUNK_SIZE: usize = 1420;

fn check_host_port(op: &str, host: &str, port: u16) -> Result<String> {
    if host.trim().is_empty() {
        return Err(Error::config(format!("{op}: host must not be blank")));
    }
    if port == 0 {
        return Err(Error::config(format!(
            "{op}: port must be an integer 1..65535"
        )));
    }
    Ok(format!("{}:{port}", url_host(host)))
}

fn network_error(op: &str, err: &std::io::Error) -> Error {
    if err.kind() == std::io::ErrorKind::TimedOut {
        return Error::timeout(format!("{op}: timeout"));
    }
    Error::unavailable(format!("{op}: network error: {}", err.kind()))
}

fn closed_error(op: &str) -> Error {
    Error::config(format!("{op}: transport is closed"))
}

/// Compresses `payload` (gzip, zlib or not at all).
pub(crate) fn compress(compression: GelfCompression, payload: &[u8]) -> Vec<u8> {
    match compression {
        GelfCompression::Gzip => {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            let _ = e.write_all(payload);
            e.finish().unwrap_or_default()
        }
        GelfCompression::Zlib => {
            let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
            let _ = e.write_all(payload);
            e.finish().unwrap_or_default()
        }
        GelfCompression::None => payload.to_vec(),
    }
}

/// Compresses `payload` and splits it into datagrams: one datagram when it fits `chunk_size`,
/// else chunks `0x1e 0x0f | id(8) | seq | count | data`. More than 128 chunks is a
/// `VALIDATION` error. `message_id = None` uses a random id.
pub fn encode_gelf_udp(
    payload: &[u8],
    compression: GelfCompression,
    chunk_size: usize,
    message_id: Option<[u8; 8]>,
) -> Result<Vec<Vec<u8>>> {
    if chunk_size <= GELF_CHUNK_HEADER_SIZE {
        return Err(Error::validation(
            "gelf.udp: chunk size must exceed the 12-byte header",
        ));
    }
    let data = compress(compression, payload);
    if data.len() <= chunk_size {
        return Ok(vec![data]);
    }
    let per = chunk_size - GELF_CHUNK_HEADER_SIZE;
    let count = data.len().div_ceil(per);
    if count > GELF_MAX_CHUNKS {
        return Err(Error::validation(format!(
            "gelf.udp: message needs {count} chunks (max 128); use TCP or HTTP for large messages"
        )));
    }
    let id = message_id.unwrap_or_else(rand::random);
    Ok(data
        .chunks(per)
        .enumerate()
        .map(|(seq, part)| {
            let mut chunk = Vec::with_capacity(GELF_CHUNK_HEADER_SIZE + part.len());
            chunk.extend_from_slice(&GELF_CHUNK_MAGIC);
            chunk.extend_from_slice(&id);
            chunk.push(seq as u8);
            chunk.push(count as u8);
            chunk.extend_from_slice(part);
            chunk
        })
        .collect())
}

// ---------------------------------------------------------------------------------------------
// UDP

/// Options of [`GelfUdpTransport::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GelfUdpOptions {
    /// Host of the GELF UDP input (required).
    pub host: String,
    /// Port (default 12201).
    pub port: u16,
    /// Compression applied before chunking (default gzip).
    pub compression: GelfCompression,
    /// Datagram size including the 12-byte chunk header (64..=65507, default 1420).
    pub chunk_size: usize,
}

impl GelfUdpOptions {
    /// Options for `host` with the defaults.
    pub fn new(host: impl Into<String>) -> Self {
        GelfUdpOptions {
            host: host.into(),
            port: DEFAULT_GELF_PORT,
            compression: GelfCompression::Gzip,
            chunk_size: DEFAULT_UDP_CHUNK_SIZE,
        }
    }
}

/// Fire-and-forget datagrams: compressed, chunked up to 128 chunks. Delivery is best-effort
/// (UDP has no acknowledgement).
#[derive(Debug)]
pub struct GelfUdpTransport {
    addr: String,
    compression: GelfCompression,
    chunk_size: usize,
    socket: Mutex<Option<UdpSocket>>,
    closed: AtomicBool,
}

impl GelfUdpTransport {
    /// Validates `opts` (`CONFIG`); the socket is opened on first use.
    pub fn new(opts: GelfUdpOptions) -> Result<Self> {
        let addr = check_host_port("gelf.udp", &opts.host, opts.port)?;
        if !(64..=65507).contains(&opts.chunk_size) {
            return Err(Error::config(
                "gelf.udp: chunkSize must be an integer 64..65507",
            ));
        }
        Ok(GelfUdpTransport {
            addr,
            compression: opts.compression,
            chunk_size: opts.chunk_size,
            socket: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl GelfTransport for GelfUdpTransport {
    fn protocol(&self) -> GelfProtocol {
        GelfProtocol::Udp
    }

    /// Writes every message as one or more datagrams. Messages that need more than 128 chunks
    /// are rejected (counted, not sent).
    async fn send(&self, messages: &[GelfMessage], _: GelfSendOptions) -> Result<GelfSendResult> {
        let mut guard = self.socket.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err(closed_error("gelf.udp"));
        }
        let mut res = GelfSendResult::default();
        for m in messages {
            let datagrams =
                match encode_gelf_udp(&m.encode(), self.compression, self.chunk_size, None) {
                    Ok(d) => d,
                    Err(e) => {
                        res.rejected += 1;
                        res.error = Some(e);
                        continue;
                    }
                };
            if guard.is_none() {
                let bind = if self.addr.starts_with('[') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let sock = UdpSocket::bind(bind)
                    .await
                    .map_err(|e| network_error("gelf.udp", &e))?;
                sock.connect(&self.addr)
                    .await
                    .map_err(|e| network_error("gelf.udp", &e))?;
                *guard = Some(sock);
            }
            let sock = guard.as_ref().expect("socket opened above");
            for d in &datagrams {
                if let Err(e) = sock.send(d).await {
                    *guard = None;
                    return Err(network_error("gelf.udp", &e));
                }
            }
            res.sent += 1;
        }
        Ok(res)
    }

    async fn close(&self) -> Result<()> {
        let mut guard = self.socket.lock().await;
        self.closed.store(true, Ordering::SeqCst);
        *guard = None;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// TCP

/// Options of [`GelfTcpTransport::new`].
#[derive(Debug, Clone)]
pub struct GelfTcpOptions {
    /// Host of the GELF TCP input (required).
    pub host: String,
    /// Port (default 12201).
    pub port: u16,
    /// Enables TLS with `tls_config` (the input needs `tls_enable`).
    pub tls: bool,
    /// TLS settings (CA, client certificate, `insecure_skip_verify`).
    pub tls_config: TlsConfig,
    /// SNI / verification name (default `host`).
    pub server_name: Option<String>,
    /// Connection setup timeout (default 10 s).
    pub connect_timeout: Duration,
    /// Write timeout per batch (default 30 s).
    pub write_timeout: Duration,
    /// Reconnects: a batch whose connect or write fails is re-sent on a new connection up to
    /// `retry.max_retries` times with full-jitter backoff.
    pub retry: RetryPolicy,
}

impl GelfTcpOptions {
    /// Options for `host` with the defaults.
    pub fn new(host: impl Into<String>) -> Self {
        GelfTcpOptions {
            host: host.into(),
            port: DEFAULT_GELF_PORT,
            tls: false,
            tls_config: TlsConfig::default(),
            server_name: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            write_timeout: DEFAULT_REQUEST_TIMEOUT,
            retry: RetryPolicy::default(),
        }
    }
}

trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Conn for T {}

/// NUL-terminated JSON frames over one long-lived connection (input option
/// `use_null_delimiter`). Batches never interleave. A connection closed by the server is
/// detected before each batch and re-opened; a failed batch is re-sent on a new connection
/// (at-least-once).
pub struct GelfTcpTransport {
    addr: String,
    opts: GelfTcpOptions,
    tls: Option<(
        Arc<rustls::ClientConfig>,
        rustls::pki_types::ServerName<'static>,
    )>,
    conn: Mutex<Option<Box<dyn Conn>>>,
    closed: AtomicBool,
    connections: AtomicUsize,
}

impl fmt::Debug for GelfTcpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GelfTcpTransport")
            .field("addr", &self.addr)
            .field("secure", &self.secure())
            .field("connections", &self.connections())
            .finish_non_exhaustive()
    }
}

/// Encodes messages as NUL-terminated JSON frames.
pub fn frame_gelf_tcp(messages: &[GelfMessage]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in messages {
        out.extend(m.encode());
        out.push(0);
    }
    out
}

impl GelfTcpTransport {
    /// Validates `opts` (`CONFIG`); the connection is opened on first use.
    pub fn new(opts: GelfTcpOptions) -> Result<Self> {
        let addr = check_host_port("gelf.tcp", &opts.host, opts.port)?;
        if opts.connect_timeout.is_zero() || opts.write_timeout.is_zero() {
            return Err(Error::config("gelf.tcp: timeouts must be positive"));
        }
        opts.retry.validate()?;
        let tls = if opts.tls {
            let name = opts
                .server_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| opts.host.trim_matches(['[', ']']).to_owned());
            Some((
                crate::tls::client_config(&opts.tls_config)?,
                crate::tls::server_name(&name)?,
            ))
        } else {
            None
        };
        Ok(GelfTcpTransport {
            addr,
            opts,
            tls,
            conn: Mutex::new(None),
            closed: AtomicBool::new(false),
            connections: AtomicUsize::new(0),
        })
    }

    /// Whether the transport uses TLS.
    pub fn secure(&self) -> bool {
        self.tls.is_some()
    }

    /// Connections opened so far (diagnostics).
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    async fn dial(&self) -> std::io::Result<Box<dyn Conn>> {
        let connect = async {
            let tcp = TcpStream::connect(&self.addr).await?;
            let _ = tcp.set_nodelay(true);
            match &self.tls {
                None => Ok(Box::new(tcp) as Box<dyn Conn>),
                Some((cfg, name)) => {
                    let tls = tokio_rustls::TlsConnector::from(cfg.clone())
                        .connect(name.clone(), tcp)
                        .await?;
                    Ok(Box::new(tls) as Box<dyn Conn>)
                }
            }
        };
        match tokio::time::timeout(self.opts.connect_timeout, connect).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            )),
        }
    }

    /// Graylog never writes on a GELF TCP connection, so a read that completes means EOF or a
    /// reset (or unexpected data, which is ignored).
    async fn alive(conn: &mut Box<dyn Conn>) -> bool {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(1), conn.read(&mut buf)).await {
            Err(_) => true,
            Ok(Ok(n)) => n > 0,
            Ok(Err(_)) => false,
        }
    }

    async fn write(&self, slot: &mut Option<Box<dyn Conn>>, data: &[u8]) -> std::io::Result<()> {
        if let Some(c) = slot.as_mut() {
            if !Self::alive(c).await {
                *slot = None;
            }
        }
        if slot.is_none() {
            *slot = Some(self.dial().await?);
            self.connections.fetch_add(1, Ordering::SeqCst);
        }
        let conn = slot.as_mut().expect("connection opened above");
        let io = async {
            conn.write_all(data).await?;
            conn.flush().await
        };
        let res = match tokio::time::timeout(self.opts.write_timeout, io).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write timeout",
            )),
        };
        if res.is_err() {
            *slot = None;
        }
        res
    }
}

#[async_trait]
impl GelfTransport for GelfTcpTransport {
    fn protocol(&self) -> GelfProtocol {
        GelfProtocol::Tcp
    }

    /// Writes all messages as NUL-terminated frames in one write; failed batches are re-sent on
    /// a new connection (see [`GelfTcpOptions::retry`]).
    async fn send(&self, messages: &[GelfMessage], _: GelfSendOptions) -> Result<GelfSendResult> {
        let mut slot = self.conn.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err(closed_error("gelf.tcp"));
        }
        if messages.is_empty() {
            return Ok(GelfSendResult::default());
        }
        let data = frame_gelf_tcp(messages);
        let mut attempt = 0;
        loop {
            match self.write(&mut slot, &data).await {
                Ok(()) => {
                    return Ok(GelfSendResult {
                        sent: messages.len(),
                        ..GelfSendResult::default()
                    })
                }
                Err(e) if attempt >= self.opts.retry.max_retries => {
                    return Err(network_error("gelf.tcp", &e))
                }
                Err(_) => {
                    tokio::time::sleep(self.opts.retry.backoff(attempt)).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn close(&self) -> Result<()> {
        let mut slot = self.conn.lock().await;
        self.closed.store(true, Ordering::SeqCst);
        if let Some(mut c) = slot.take() {
            let _ = c.shutdown().await;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// HTTP

/// Options of [`GelfHttpTransport::new`].
#[derive(Debug, Clone)]
pub struct GelfHttpOptions {
    /// URL of the GELF HTTP input, for example `http://graylog:12202/gelf`.
    pub url: String,
    /// gzip-compressed bodies (default true).
    pub gzip: bool,
    /// One body of newline-terminated messages per batch (default true); `false` posts one
    /// request per message (inputs without `enable_bulk_receiving`).
    pub bulk: bool,
    /// Extra request headers (for example the input's optional authorization header);
    /// sensitive values are redacted.
    pub headers: Vec<(String, String)>,
    /// Timeouts, retries, TLS, proxy and hooks (its URL and headers are ignored; `None` = the
    /// defaults).
    pub config: Option<CommonConfig>,
}

impl GelfHttpOptions {
    /// Options for `url` with the defaults.
    pub fn new(url: impl Into<String>) -> Self {
        GelfHttpOptions {
            url: url.into(),
            gzip: true,
            bulk: true,
            headers: Vec::new(),
            config: None,
        }
    }
}

/// Posts GELF messages to a GELF HTTP input (202 Accepted). Graylog answers 202 even for
/// invalid JSON or a missing `short_message` and drops the message, so messages are validated
/// when they are built.
#[derive(Debug)]
pub struct GelfHttpTransport {
    path: String,
    transport: HttpTransport,
    gzip: bool,
    bulk: bool,
    headers: Vec<(String, Secret)>,
}

/// A copy of `base` with another URL (and no extra headers).
pub(crate) fn rebase_config(base: Option<&CommonConfig>, url: &str) -> Result<CommonConfig> {
    let mut b = CommonConfig::builder().url(url);
    if let Some(c) = base {
        b = b
            .connect_timeout(c.connect_timeout())
            .request_timeout(c.request_timeout())
            .total_timeout(c.total_timeout())
            .retry(c.retry().clone())
            .tls(c.tls().clone());
        if let Some(p) = c.proxy() {
            b = b.proxy(p);
        }
        if let Some(s) = c.user_agent_suffix() {
            b = b.user_agent_suffix(s);
        }
        if let Some(h) = c.hooks() {
            b = b.hooks(h.clone());
        }
    }
    b.build(url)
}

impl GelfHttpTransport {
    /// Validates `opts` (`CONFIG`).
    pub fn new(opts: GelfHttpOptions) -> Result<Self> {
        let u = url::Url::parse(&opts.url)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| Error::config("gelf.http: url must be an http(s) URL"))?;
        let base = format!(
            "{}://{}",
            u.scheme(),
            &u[url::Position::BeforeHost..url::Position::AfterPort]
        );
        let cfg = rebase_config(opts.config.as_ref(), &base)?;
        let transport = HttpTransport::new(&cfg)?;
        let mut headers = Vec::new();
        for (k, v) in opts.headers {
            let s = Secret::new(v);
            if is_sensitive_header(&k) {
                transport.add_known_secret(&s);
            }
            headers.push((k, s));
        }
        let path = match u.path() {
            "" | "/" => "/gelf".to_owned(),
            p => p.to_owned(),
        };
        let path = match u.query() {
            Some(q) => format!("{path}?{q}"),
            None => path,
        };
        Ok(GelfHttpTransport {
            path,
            transport,
            gzip: opts.gzip,
            bulk: opts.bulk,
            headers,
        })
    }
}

#[async_trait]
impl GelfTransport for GelfHttpTransport {
    fn protocol(&self) -> GelfProtocol {
        GelfProtocol::Http
    }

    /// Posts messages: one body of newline-terminated messages per call (bulk), or one request
    /// per message without bulk. Every message ends with `\n`, also single ones (Graylog 7.0
    /// drops the first message of the third and later request on a reused connection
    /// otherwise). Bodies are gzip-compressed unless disabled.
    async fn send(
        &self,
        messages: &[GelfMessage],
        opts: GelfSendOptions,
    ) -> Result<GelfSendResult> {
        if self.transport.is_closed() {
            return Err(closed_error("gelf.http"));
        }
        let gzip = opts.gzip.unwrap_or(self.gzip);
        let groups: Vec<&[GelfMessage]> = if self.bulk {
            if messages.is_empty() {
                Vec::new()
            } else {
                vec![messages]
            }
        } else {
            messages.chunks(1).collect()
        };
        let mut res = GelfSendResult::default();
        for g in groups {
            let mut body = Vec::new();
            for m in g {
                body.extend(m.encode());
                body.push(b'\n');
            }
            let mut req = self
                .transport
                .post(&self.path)
                .operation("gelf.http")
                .header(HEADER_REQUESTED_BY, DEFAULT_REQUESTED_BY);
            for (k, v) in &self.headers {
                req = if is_sensitive_header(k) {
                    req.secret_header(k.clone(), v)
                } else {
                    req.header(k.clone(), v.expose_secret())
                };
            }
            req = if gzip {
                req.header("content-encoding", "gzip")
                    .body(compress(GelfCompression::Gzip, &body), "application/json")
            } else {
                req.body(body, "application/json")
            };
            req.send().await?;
            res.sent += g.len();
        }
        Ok(res)
    }

    async fn close(&self) -> Result<()> {
        self.transport.close();
        Ok(())
    }
}
