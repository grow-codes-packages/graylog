# grow-graylog (Rust)

Rust SDK for Graylog Open by [Grow Codes](https://grow.codes). Async on tokio, with an optional
blocking client.

```toml
[dependencies]
grow-graylog = "0.1.0"
# blocking client:   features = ["blocking"]
# test fakes/runner: features = ["testing"] (dev-dependency)
```

```rust,no_run
use grow_graylog::{GraylogClient, GraylogConfig};

#[tokio::main]
async fn main() -> grow_graylog::Result<()> {
    // explicit > GROW_GRAYLOG_* > GRAYLOG_* > platform aliases > defaults
    let client = GraylogClient::new(GraylogConfig::from_env()?)?;
    println!("{:?}", client.health().await?);
    client.close().await;
    Ok(())
}
```

Graylog functions:

- GELF: `GelfMessage` (builder, shared attribute mapping), `GelfUdpTransport` (gzip/zlib,
  chunking up to 128 chunks), `GelfTcpTransport` (NUL framing, TLS, reconnect),
  `GelfHttpTransport` (newline-terminated bulk bodies, gzip); `client.new_log_client(...)` for a
  batching `LogClient` over GELF or OTLP/gRPC (`OtlpGrpcLogExporter`).
- Search: `search`, `search_relative`, `get_message`, `log_record_from_message`;
  `client.log_query(...)` is the `LogQueryClient` (search, polling tail, streams, fields,
  `wait_for_log`).
- Admin: `system_info`, `list_inputs`, `get_input`, `list_input_types`, `get_input_state`,
  `create_input`, `ensure_gelf_input`, `delete_input`, `list_streams`, `get_stream`,
  `create_stream`, `resume_stream`, `delete_stream`, `list_index_sets`, `list_fields`.

- Errors: one `Error` enum with `code()`, `http_status()`, `request_id()`, `is_retryable()`,
  `retry_after()`; messages never contain credentials.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation (drop the future or pass a `CancellationToken`), request hooks, `tracing` debug
  events.
- MSRV 1.88. Licence Apache-2.0. Documentation: https://grow-codes-packages.github.io/graylog/

Development: `make deps build lint test coverage license pack docs` (see `Makefile`).
