// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! Blocking wrapper (feature `blocking`). Each client owns a small tokio runtime with one
//! worker thread, so background work (tails, batching log clients) keeps running between calls.
//!
//! Do not use it from inside an async runtime (calls would panic); use the async client there.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::core::{Error, HealthStatus, Result};
use crate::logging::{
    BatchingLogClient, LogExporter, LogQueryClient, LogRecord, LogSearchResult, RecordCallback,
    SearchOptions, TailHandle, TailOptions, WaitOptions,
};
use crate::{
    CreateInputOptions, CreateStreamOptions, EnsureGelfInputOptions, EnsuredInput, GelfMessage,
    GelfProtocol, GelfSendOptions, GelfSendResult, GelfTransport, GelfTransportOptions,
    GraylogClient as AsyncClient, GraylogConfig, IndexSet, Input, InputState, ListStreamsOptions,
    LogOptions, LogQueryOptions, Message, MessageSearchOptions, MessageSearchResult, Stream,
    StreamPage, SystemInfo,
};

/// Blocking client for Graylog Open with the same methods as the async client.
#[derive(Debug)]
pub struct GraylogClient {
    inner: AsyncClient,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl GraylogClient {
    /// Creates a client from a configuration.
    pub fn new(config: GraylogConfig) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("grow-graylog")
            .enable_all()
            .build()
            .map_err(|e| Error::config("cannot start the tokio runtime").with_source(e))?;
        let inner = {
            let _guard = runtime.enter();
            AsyncClient::new(config)?
        };
        Ok(GraylogClient {
            inner,
            runtime: Arc::new(runtime),
        })
    }

    /// Creates a client from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::new(GraylogConfig::from_env()?)
    }

    /// The wrapped async client.
    pub fn async_client(&self) -> &AsyncClient {
        &self.inner
    }

    /// Runs a future of the async API to completion on this client's runtime.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// See [`AsyncClient::config`].
    pub fn config(&self) -> &GraylogConfig {
        self.inner.config()
    }

    /// See [`AsyncClient::health`].
    pub fn health(&self) -> Result<HealthStatus> {
        self.block_on(self.inner.health())
    }

    /// See [`AsyncClient::ping`].
    pub fn ping(&self) -> Result<Duration> {
        self.block_on(self.inner.ping())
    }

    /// See [`AsyncClient::server_version`].
    pub fn server_version(&self) -> Result<String> {
        self.block_on(self.inner.server_version())
    }

    /// See [`AsyncClient::system_info`].
    pub fn system_info(&self) -> Result<SystemInfo> {
        self.block_on(self.inner.system_info())
    }

    /// See [`AsyncClient::list_fields`].
    pub fn list_fields(&self) -> Result<Vec<String>> {
        self.block_on(self.inner.list_fields())
    }

    /// See [`AsyncClient::list_inputs`].
    pub fn list_inputs(&self) -> Result<Vec<Input>> {
        self.block_on(self.inner.list_inputs())
    }

    /// See [`AsyncClient::get_input`].
    pub fn get_input(&self, id: &str) -> Result<Input> {
        self.block_on(self.inner.get_input(id))
    }

    /// See [`AsyncClient::list_input_types`].
    pub fn list_input_types(&self) -> Result<BTreeMap<String, String>> {
        self.block_on(self.inner.list_input_types())
    }

    /// See [`AsyncClient::get_input_state`].
    pub fn get_input_state(&self, id: &str) -> Result<InputState> {
        self.block_on(self.inner.get_input_state(id))
    }

    /// See [`AsyncClient::create_input`].
    pub fn create_input(
        &self,
        input_type: &str,
        configuration: Map<String, Value>,
        opts: CreateInputOptions,
    ) -> Result<String> {
        self.block_on(self.inner.create_input(input_type, configuration, opts))
    }

    /// See [`AsyncClient::ensure_gelf_input`].
    pub fn ensure_gelf_input(
        &self,
        protocol: GelfProtocol,
        port: u16,
        opts: EnsureGelfInputOptions,
    ) -> Result<EnsuredInput> {
        self.block_on(self.inner.ensure_gelf_input(protocol, port, opts))
    }

    /// See [`AsyncClient::delete_input`].
    pub fn delete_input(&self, id: &str) -> Result<()> {
        self.block_on(self.inner.delete_input(id))
    }

    /// See [`AsyncClient::list_streams`].
    pub fn list_streams(&self, opts: ListStreamsOptions) -> Result<StreamPage> {
        self.block_on(self.inner.list_streams(opts))
    }

    /// See [`AsyncClient::get_stream`].
    pub fn get_stream(&self, id: &str) -> Result<Stream> {
        self.block_on(self.inner.get_stream(id))
    }

    /// See [`AsyncClient::create_stream`].
    pub fn create_stream(&self, opts: CreateStreamOptions) -> Result<String> {
        self.block_on(self.inner.create_stream(opts))
    }

    /// See [`AsyncClient::resume_stream`].
    pub fn resume_stream(&self, id: &str) -> Result<()> {
        self.block_on(self.inner.resume_stream(id))
    }

    /// See [`AsyncClient::delete_stream`].
    pub fn delete_stream(&self, id: &str) -> Result<()> {
        self.block_on(self.inner.delete_stream(id))
    }

    /// See [`AsyncClient::list_index_sets`].
    pub fn list_index_sets(&self) -> Result<Vec<IndexSet>> {
        self.block_on(self.inner.list_index_sets())
    }

    /// See [`AsyncClient::search`].
    pub fn search(&self, query: &str, opts: MessageSearchOptions) -> Result<MessageSearchResult> {
        self.block_on(self.inner.search(query, opts))
    }

    /// See [`AsyncClient::search_relative`].
    pub fn search_relative(
        &self,
        query: &str,
        range: Duration,
        opts: MessageSearchOptions,
    ) -> Result<MessageSearchResult> {
        self.block_on(self.inner.search_relative(query, range, opts))
    }

    /// See [`AsyncClient::get_message`].
    pub fn get_message(&self, index: &str, id: &str) -> Result<Message> {
        self.block_on(self.inner.get_message(index, id))
    }

    /// See [`AsyncClient::gelf_transport`]; send with [`GraylogClient::send_gelf`].
    pub fn gelf_transport(
        &self,
        protocol: Option<GelfProtocol>,
        opts: GelfTransportOptions,
    ) -> Result<Arc<dyn GelfTransport>> {
        let _guard = self.runtime.enter();
        self.inner.gelf_transport(protocol, opts)
    }

    /// Sends messages through `transport` on this client's runtime.
    pub fn send_gelf(
        &self,
        transport: &dyn GelfTransport,
        messages: &[GelfMessage],
        opts: GelfSendOptions,
    ) -> Result<GelfSendResult> {
        self.block_on(transport.send(messages, opts))
    }

    /// See [`AsyncClient::log_query`].
    pub fn log_query(&self, opts: LogQueryOptions) -> LogQuery {
        LogQuery {
            inner: self.inner.log_query(opts),
            runtime: Arc::clone(&self.runtime),
        }
    }

    /// See [`AsyncClient::new_log_client`]. Flush with `client.block_on(lc.flush(None))`.
    pub fn new_log_client(&self, opts: LogOptions) -> Result<BatchingLogClient> {
        let _guard = self.runtime.enter();
        self.inner.new_log_client(opts)
    }

    /// See [`AsyncClient::new_log_client_with_exporter`].
    pub fn new_log_client_with_exporter(
        &self,
        exporter: Arc<dyn LogExporter>,
        opts: LogOptions,
    ) -> Result<BatchingLogClient> {
        let _guard = self.runtime.enter();
        self.inner.new_log_client_with_exporter(exporter, opts)
    }

    /// See [`AsyncClient::close`]. Idempotent.
    pub fn close(&self) {
        self.block_on(self.inner.close());
    }
}

impl Drop for GraylogClient {
    fn drop(&mut self) {
        self.inner.transport().close();
    }
}

/// Blocking [`LogQueryClient`] (see [`crate::LogQuery`]).
#[derive(Debug, Clone)]
pub struct LogQuery {
    inner: crate::LogQuery,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl LogQuery {
    /// See [`LogQueryClient::search`].
    pub fn search(&self, query: &str, opts: SearchOptions) -> Result<LogSearchResult> {
        self.runtime.block_on(self.inner.search(query, opts))
    }

    /// See [`LogQueryClient::tail`]; stop it with [`TailHandle::stop`].
    pub fn tail(
        &self,
        query: &str,
        on_record: RecordCallback,
        opts: TailOptions,
    ) -> Result<TailHandle> {
        self.runtime
            .block_on(self.inner.tail(query, on_record, opts))
    }

    /// See [`LogQueryClient::list_streams`].
    pub fn list_streams(&self) -> Result<Vec<String>> {
        self.runtime.block_on(self.inner.list_streams())
    }

    /// See [`LogQueryClient::list_labels`].
    pub fn list_labels(&self) -> Result<Vec<String>> {
        self.runtime.block_on(self.inner.list_labels())
    }

    /// See [`LogQueryClient::wait_for_log`].
    pub fn wait_for_log(&self, query: &str, opts: WaitOptions) -> Result<LogRecord> {
        self.runtime.block_on(self.inner.wait_for_log(query, opts))
    }
}
