// Created by sdk-kit 0.1.0; owned by this repository.
//! The Graylog Open Rust SDK against a real server: health and version, a GELF input, a stream,
//! structured logging through GELF, and reading the records back with the search API.
//!
//! ```sh
//! GROW_GRAYLOG_URL=http://127.0.0.1:9000 GROW_GRAYLOG_API_TOKEN=... \
//! GROW_GRAYLOG_GELF_HOST=127.0.0.1 cargo run
//! ```

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use grow_graylog as sdk;
use sdk::core::{ErrorInfo, Hooks};
use sdk::logging::{attrs, LogClient, LogQueryClient, WaitOptions};
use sdk::{
    CreateStreamOptions, EnsureGelfInputOptions, ErrorCode, GelfProtocol, GraylogClient,
    GraylogConfig, LogOptions, LogQueryOptions, MessageSearchOptions, StreamRule,
};

/// Prints every retry.
struct RetryLogger;

impl Hooks for RetryLogger {
    fn on_error(&self, info: &ErrorInfo) {
        if info.will_retry {
            eprintln!(
                "retrying {} {} (attempt {})",
                info.method, info.url, info.attempt
            );
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error [{}]: {err}", err.code());
        std::process::exit(1);
    }
}

async fn run() -> sdk::Result<()> {
    // explicit > GROW_GRAYLOG_* > GRAYLOG_* > platform aliases > defaults; invalid values name
    // the variable, never its value.
    let config = GraylogConfig::builder()
        .hooks(Arc::new(RetryLogger))
        .build_from_env()?;
    println!("config: {config:?}"); // credentials print as [REDACTED]
    let client = GraylogClient::new(config)?;

    let health = client.health().await?; // never fails for an unreachable server
    println!("health: {} ({})", health.healthy, health.status);
    match client.server_version().await {
        Ok(v) => println!("server version: {v}"),
        Err(e) if e.code() == ErrorCode::Authentication => {
            println!("check GROW_GRAYLOG_API_TOKEN ({e})");
            return Ok(());
        }
        Err(e) => return Err(e),
    }

    // A running GELF TCP input (reused when it exists).
    let input = client
        .ensure_gelf_input(GelfProtocol::Tcp, 12201, EnsureGelfInputOptions::default())
        .await?;
    println!(
        "GELF TCP input {} (created: {})",
        input.input.id, input.created
    );

    // A stream that routes our messages.
    let marker = format!(
        "example{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let stream_id = client
        .create_stream(
            CreateStreamOptions::new(format!("example {marker}"))
                .rule(StreamRule::exact("marker", &marker)),
        )
        .await?;

    // Structured logging through GELF (batched; trace ids come from the active OTel span).
    let logs = client.new_log_client(
        LogOptions::default()
            .resource_attribute("service.name", "checkout")
            .resource_attribute("deployment.environment", "dev"),
    )?;
    let log = logs.logger(Some("example"), attrs! { "marker" => marker.clone() });
    log.info(
        "order placed",
        attrs! { "order_id" => "o-1", "amount" => 42.5 },
    );
    log.warn(
        "payment slow",
        attrs! { "latency_ms" => 1800, "password" => "redacted-before-send" },
    );
    logs.flush(None).await?;

    // Read them back.
    let query = format!("marker:{marker}");
    let record = client
        .log_query(LogQueryOptions::default())
        .wait_for_log(
            &query,
            WaitOptions::default().timeout(Duration::from_secs(30)),
        )
        .await?;
    println!("first record: [{}] {}", record.severity, record.body);
    let page = client
        .search_relative(
            &query,
            Duration::from_secs(300),
            MessageSearchOptions::default(),
        )
        .await?;
    for m in &page.messages {
        let full = client.get_message(&m.index, &m.id).await?;
        println!("  {} {}", full.id, full.fields["message"]);
    }

    client.delete_stream(&stream_id).await?;
    client.close().await; // flushes the log client too
    Ok(())
}
