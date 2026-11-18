// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! # grow-graylog
//!
//! Rust SDK for [Graylog Open](https://grow-codes-packages.github.io/graylog/) by Grow Codes.
//!
//! ```no_run
//! # async fn demo() -> grow_graylog::Result<()> {
//! use grow_graylog::{GraylogClient, GraylogConfig};
//!
//! let client = GraylogClient::new(GraylogConfig::from_env()?)?;
//! let health = client.health().await?;
//! println!("healthy: {}", health.healthy);
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes and the conformance
//! runner)
//! , `tracing-layer` and `log-bridge` (logging adapters, on by default)
//! .
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod client;
mod config;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub mod logging;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::DEFAULT_URL;

pub use crate::client::GraylogClient;

pub use crate::config::GraylogConfig;

pub use crate::config::GraylogConfigBuilder;

/// Service-prefixed alias of [`Error`].
pub type GraylogError = Error;
