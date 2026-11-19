//! Logging category: the [`GelfLogExporter`] and the log clients the [`GraylogClient`] creates.

use std::sync::Arc;

use async_trait::async_trait;

use crate::client::GraylogClient;
use crate::config::GelfProtocol;
use crate::core::{Error, Result, Secret};
use crate::gelf::{FromLogRecordOptions, GelfMessage};
use crate::gelf_transport::{
    GelfCompression, GelfHttpOptions, GelfHttpTransport, GelfSendOptions, GelfTcpOptions,
    GelfTcpTransport, GelfTransport, GelfUdpOptions, GelfUdpTransport, DEFAULT_UDP_CHUNK_SIZE,
};
use crate::logging::{
    AttrValue, Attributes, BatchOptions, BatchingLogClient, ExportOptions, ExportResult,
    LogExporter, LogRecord, RedactionProcessor, Severity,
};
use crate::otlp::{OtlpGrpcLogExporter, OtlpGrpcLogExporterOptions};

/// The `LogExporter` of the logging category: converts records with
/// [`GelfMessage::from_log_record`] and sends them through a [`GelfTransport`].
#[derive(Debug, Clone)]
pub struct GelfLogExporter {
    transport: Arc<dyn GelfTransport>,
    opts: FromLogRecordOptions,
}

impl GelfLogExporter {
    /// An exporter over `transport`; `opts.host` is the GELF host of records without
    /// `resource["host.name"]`.
    pub fn new(transport: Arc<dyn GelfTransport>, opts: FromLogRecordOptions) -> Self {
        GelfLogExporter { transport, opts }
    }

    /// The underlying transport.
    pub fn transport(&self) -> &Arc<dyn GelfTransport> {
        &self.transport
    }
}

#[async_trait]
impl LogExporter for GelfLogExporter {
    /// Converts and sends records; `ExportOptions::gzip` is passed to the transport (only HTTP
    /// uses it). Client-side rejections are counted.
    async fn export(&self, records: &[LogRecord], opts: ExportOptions) -> Result<ExportResult> {
        let msgs: Vec<GelfMessage> = records
            .iter()
            .map(|r| GelfMessage::from_log_record(r, &self.opts))
            .collect();
        let res = self
            .transport
            .send(
                &msgs,
                GelfSendOptions {
                    gzip: Some(opts.gzip),
                },
            )
            .await?;
        Ok(ExportResult::partial(res.sent, res.rejected, res.error))
    }

    /// Closes the transport.
    async fn shutdown(&self) -> Result<()> {
        self.transport.close().await
    }
}

/// Options of [`GraylogClient::gelf_transport`].
#[derive(Debug, Clone)]
pub struct GelfTransportOptions {
    /// UDP payload compression (default gzip).
    pub compression: GelfCompression,
    /// UDP datagram size (default 1420).
    pub chunk_size: usize,
    /// HTTP: newline-delimited bulk bodies (default true).
    pub bulk: bool,
    /// HTTP: extra headers (for example the input's authorization header).
    pub headers: Vec<(String, String)>,
}

impl Default for GelfTransportOptions {
    fn default() -> Self {
        GelfTransportOptions {
            compression: GelfCompression::Gzip,
            chunk_size: DEFAULT_UDP_CHUNK_SIZE,
            bulk: true,
            headers: Vec::new(),
        }
    }
}

/// Options of [`GraylogClient::new_log_client`]: the batching options plus the transport choice.
#[derive(Debug, Clone)]
pub struct LogOptions {
    /// Batch settings.
    pub batch: BatchOptions,
    /// Resource attributes merged into every record (record keys win): `service.name`,
    /// `service.version`, `deployment.environment`, `host.name`.
    pub resource: Attributes,
    /// Redaction applied before records leave the process (default
    /// [`RedactionProcessor::default`]); `None` disables it.
    pub redaction: Option<RedactionProcessor>,
    /// Minimum severity of loggers made by `LogClient::logger` (default `Info`).
    pub min_severity: Severity,
    /// `udp`, `tcp`, `http` or `otlp` (`None` = the configured GELF protocol).
    pub protocol: Option<GelfProtocol>,
    /// GELF host of records without `resource["host.name"]` (default: the local host name).
    pub host: Option<String>,
    /// Used instead of building a transport (closed with the log client).
    pub transport: Option<Arc<dyn GelfTransport>>,
    /// UDP, HTTP and header settings of the built transport.
    pub transport_options: GelfTransportOptions,
    /// OTLP: the input's bearer token.
    pub bearer_token: Option<Secret>,
}

impl Default for LogOptions {
    fn default() -> Self {
        LogOptions {
            batch: BatchOptions::default(),
            resource: Attributes::new(),
            redaction: Some(RedactionProcessor::default()),
            min_severity: Severity::Info,
            protocol: None,
            host: None,
            transport: None,
            transport_options: GelfTransportOptions::default(),
            bearer_token: None,
        }
    }
}

impl LogOptions {
    /// Adds one resource attribute.
    pub fn resource_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<AttrValue>,
    ) -> Self {
        self.resource.insert(key.into(), value.into());
        self
    }
    /// Sets the batch options.
    pub fn batch(mut self, batch: BatchOptions) -> Self {
        self.batch = batch;
        self
    }
    /// Sets the protocol.
    pub fn protocol(mut self, protocol: GelfProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }
}

impl GraylogClient {
    /// A GELF transport from the configuration for `protocol` (`None` = the configured
    /// protocol): host `gelf_host`, port `gelf_port_for(protocol)`, HTTP URL
    /// `gelf_http_endpoint`, TLS for TCP with `gelf_tls`. TCP and HTTP share the client's
    /// timeouts and retry policy; HTTP also its TLS, proxy and hooks. The caller owns the
    /// transport (close it when done).
    pub fn gelf_transport(
        &self,
        protocol: Option<GelfProtocol>,
        opts: GelfTransportOptions,
    ) -> Result<Arc<dyn GelfTransport>> {
        let cfg = self.config();
        let protocol = protocol.unwrap_or(cfg.gelf_protocol());
        Ok(match protocol {
            GelfProtocol::Udp => Arc::new(GelfUdpTransport::new(GelfUdpOptions {
                host: cfg.gelf_host().to_owned(),
                port: cfg.gelf_port_for(GelfProtocol::Udp),
                compression: opts.compression,
                chunk_size: opts.chunk_size,
            })?),
            GelfProtocol::Tcp => Arc::new(GelfTcpTransport::new(GelfTcpOptions {
                host: cfg.gelf_host().to_owned(),
                port: cfg.gelf_port_for(GelfProtocol::Tcp),
                tls: cfg.gelf_tls(),
                tls_config: cfg.common().tls().clone(),
                server_name: None,
                connect_timeout: cfg.common().connect_timeout(),
                write_timeout: cfg.common().request_timeout(),
                retry: cfg.common().retry().clone(),
            })?),
            GelfProtocol::Http => Arc::new(GelfHttpTransport::new(GelfHttpOptions {
                url: cfg.gelf_http_endpoint(),
                gzip: true,
                bulk: opts.bulk,
                headers: opts.headers,
                config: Some(cfg.common().clone()),
            })?),
            GelfProtocol::Otlp => {
                return Err(Error::validation(
                    "gelfTransport: protocol must be udp, tcp or http",
                ))
            }
        })
    }

    /// A batching `LogClient` that sends through GELF (`udp`, `tcp`, `http`) or OTLP/gRPC
    /// (`otlp`, endpoint `otlp_grpc_endpoint`). Closing the `GraylogClient` flushes and closes
    /// it. Must be called inside a tokio runtime. A closed client returns `CANCELLED`.
    pub fn new_log_client(&self, opts: LogOptions) -> Result<BatchingLogClient> {
        if self.is_closed() {
            return Err(Error::cancelled("logClient: client is closed"));
        }
        let cfg = self.config();
        let protocol = opts.protocol.unwrap_or(cfg.gelf_protocol());
        let exporter: Arc<dyn LogExporter> = if protocol == GelfProtocol::Otlp {
            Arc::new(OtlpGrpcLogExporter::new(OtlpGrpcLogExporterOptions {
                endpoint: cfg.otlp_grpc_endpoint(),
                bearer_token: opts.bearer_token.clone(),
                headers: opts.transport_options.headers.clone(),
                tls: cfg.common().tls().clone(),
                timeout: cfg.common().request_timeout(),
                connect_timeout: cfg.common().connect_timeout(),
            })?)
        } else {
            let transport = match &opts.transport {
                Some(t) => t.clone(),
                None => self.gelf_transport(Some(protocol), opts.transport_options.clone())?,
            };
            Arc::new(GelfLogExporter::new(
                transport,
                FromLogRecordOptions {
                    host: opts.host.clone(),
                },
            ))
        };
        self.new_log_client_with_exporter(exporter, opts)
    }

    /// A batching `LogClient` for any exporter (the transport fields of `opts` are ignored).
    /// Closing the `GraylogClient` flushes and closes it. A closed client returns `CANCELLED`.
    pub fn new_log_client_with_exporter(
        &self,
        exporter: Arc<dyn LogExporter>,
        opts: LogOptions,
    ) -> Result<BatchingLogClient> {
        if self.is_closed() {
            return Err(Error::cancelled("logClient: client is closed"));
        }
        let client = BatchingLogClient::builder(exporter)
            .batch_options(opts.batch)
            .resource(opts.resource)
            .redaction(opts.redaction)
            .min_severity(opts.min_severity)
            .build()?;
        let closing = client.clone();
        self.on_close(move || {
            Box::pin(async move {
                let _ = crate::logging::LogClient::close(&closing).await;
            })
        });
        Ok(client)
    }
}
