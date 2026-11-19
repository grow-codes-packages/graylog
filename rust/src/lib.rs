// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! # grow-graylog
//!
//! Rust SDK for [Graylog Open](https://grow-codes-packages.github.io/graylog/) by Grow Codes.
//!
//! ```no_run
//! # async fn demo() -> grow_graylog::Result<()> {
//! use grow_graylog::logging::{attrs, LogClient, LogQueryClient, WaitOptions};
//! use grow_graylog::{GraylogClient, GraylogConfig, LogOptions, LogQueryOptions};
//!
//! let client = GraylogClient::new(GraylogConfig::from_env()?)?;
//! let health = client.health().await?;
//! println!("healthy: {}", health.healthy);
//!
//! // GELF over the configured protocol (TCP by default), batched.
//! let logs = client.new_log_client(LogOptions::default().resource_attribute("service.name", "checkout"))?;
//! logs.logger(Some("http"), attrs! {}).info("order placed", attrs! { "order_id" => "o-1" });
//! logs.flush(None).await?;
//!
//! // Read it back through the Views search API.
//! let record = client
//!     .log_query(LogQueryOptions::default())
//!     .wait_for_log("order_id:o-1", WaitOptions::default())
//!     .await?;
//! println!("{}", record.body);
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Modules: GELF messages and transports ([`GelfMessage`], [`GelfUdpTransport`],
//! [`GelfTcpTransport`], [`GelfHttpTransport`]), the optional OTLP/gRPC exporter
//! ([`OtlpGrpcLogExporter`]), search ([`GraylogClient::search`],
//! [`GraylogClient::search_relative`], [`GraylogClient::get_message`]), admin (inputs, streams,
//! index sets, [`GraylogClient::system_info`]) and the logging category
//! ([`GraylogClient::new_log_client`], [`GraylogClient::log_query`]).
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes and the conformance
//! runner), `tracing-layer` and `log-bridge` (logging adapters, on by default).
//!
//! Graylog is a trademark of Graylog, Inc. This project is not affiliated with or endorsed by
//! Graylog, Inc.
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod admin;
mod client;
mod config;
mod exporter;
mod gelf;
mod gelf_transport;
mod logquery;
mod models;
mod otlp;
mod search;
mod tls;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub mod logging;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::{
    GelfProtocol, DEFAULT_GELF_HTTP_PORT, DEFAULT_GELF_PORT, DEFAULT_OTLP_GRPC_PORT,
    DEFAULT_REQUESTED_BY, DEFAULT_URL,
};

pub use crate::client::{GraylogClient, HEADER_NODE_ID, HEADER_REQUESTED_BY};

pub use crate::admin::{
    CreateInputOptions, CreateStreamOptions, EnsureGelfInputOptions, EnsuredInput,
    ListStreamsOptions,
};
pub use crate::exporter::{GelfLogExporter, GelfTransportOptions, LogOptions};
pub use crate::gelf::{
    flatten_attributes, gelf_field_key, gelf_field_value, gelf_level_to_severity, gelf_timestamp,
    severity_to_gelf_level, validate_gelf_field_key, FromLogRecordOptions, GelfLevel, GelfMessage,
    GelfMessageOptions, GELF_VERSION,
};
pub use crate::gelf_transport::{
    encode_gelf_udp, frame_gelf_tcp, GelfCompression, GelfHttpOptions, GelfHttpTransport,
    GelfSendOptions, GelfSendResult, GelfTcpOptions, GelfTcpTransport, GelfTransport,
    GelfUdpOptions, GelfUdpTransport, DEFAULT_UDP_CHUNK_SIZE, GELF_CHUNK_HEADER_SIZE,
    GELF_CHUNK_MAGIC, GELF_MAX_CHUNKS,
};
pub use crate::logquery::{
    LogQuery, LogQueryOptions, DEFAULT_LOG_QUERY_WINDOW, DEFAULT_TAIL_INTERVAL,
};
pub use crate::models::{
    IndexSet, Input, InputState, Stream, StreamPage, StreamRule, SystemInfo, INPUT_STATE_FAILED,
    INPUT_STATE_RUNNING, INPUT_TYPE_GELF_HTTP, INPUT_TYPE_GELF_TCP, INPUT_TYPE_GELF_UDP,
    INPUT_TYPE_OTEL_GRPC, STREAM_RULE_ALWAYS_MATCH, STREAM_RULE_CONTAINS, STREAM_RULE_EXACT,
    STREAM_RULE_GREATER, STREAM_RULE_MATCH_INPUT, STREAM_RULE_PRESENCE, STREAM_RULE_REGEX,
    STREAM_RULE_SMALLER,
};
pub use crate::otlp::{
    decode_export_logs_response, encode_export_logs_request, error_for_grpc_status,
    OtlpGrpcLogExporter, OtlpGrpcLogExporterOptions, OtlpPartialSuccess, OTLP_LOGS_EXPORT_PATH,
    OTLP_SCOPE_NAME,
};
pub use crate::search::{
    log_record_from_message, Message, MessageSearchOptions, MessageSearchResult, SearchSort,
    DEFAULT_MESSAGE_SORT_FIELD, DEFAULT_SEARCH_LIMIT, DEFAULT_SEARCH_RANGE, MAX_SEARCH_LIMIT,
    RESOURCE_FIELDS,
};

pub use crate::config::GraylogConfig;

pub use crate::config::GraylogConfigBuilder;

/// Service-prefixed alias of [`Error`].
pub type GraylogError = Error;
