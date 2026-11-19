// Created by sdk-kit 0.1.0; owned by this repository.
//! Conformance scenarios for `core` and `logging` against the real Graylog (Docker).

use std::sync::Arc;

use grow_graylog as sdk;
use grow_graylog_integration as support;
use sdk::logging::{LogClient, LogQueryClient};
use sdk::testing::logging::{LoggingHandler, LoggingTarget};
use sdk::testing::{ConformanceRunner, CoreHandler};
use sdk::{GraylogClient as Client, LogOptions, LogQueryOptions};
use support::{conformance_dir, load_bootstrap_env};

#[tokio::test]
async fn conformance() {
    load_bootstrap_env();
    if std::env::var_os("GROW_GRAYLOG_URL").is_none() {
        eprintln!("GROW_GRAYLOG_URL is not set; run through docker/compose.yml");
        return;
    }
    let logging = LoggingHandler::new(|batch| async move {
        let client = Client::from_env()?;
        let lc = client.new_log_client(LogOptions {
            batch,
            ..LogOptions::default()
                .resource_attribute("service.name", "grow-conformance-rust")
                .resource_attribute("deployment.environment", "conformance")
        })?;
        let client: Arc<dyn LogClient> = Arc::new(lc);
        let query: Arc<dyn LogQueryClient> =
            Arc::new(Client::from_env()?.log_query(LogQueryOptions::default()));
        Ok(LoggingTarget {
            client,
            query: Some(query),
        })
    });
    // Graylog serves search (Views API), a polling tail, streams, field names (labels) and the
    // server version.
    let runner = ConformanceRunner::new(conformance_dir())
        .capabilities(["version", "query", "tail", "labels", "streams"])
        .handler(CoreHandler::new(Client::from_env))
        .handler(logging);
    let report = runner.run().await.expect("scenarios load");
    println!("{report}");
    report.assert_success();
}
