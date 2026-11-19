//! Shared helpers for the Graylog service tests: recorded fixtures and mock clients.
#![allow(dead_code)]

use std::time::Duration;

use grow_graylog as sdk;
use sdk::core::{RandomSource, RetryPolicy};
use sdk::{GraylogClient, GraylogConfig, GraylogConfigBuilder};
use serde_json::Value;
use wiremock::{MockServer, ResponseTemplate};

/// A request/response pair recorded from the real Graylog 7.0.16 container.
pub struct Fixture {
    pub status: u16,
    pub body: Option<Value>,
    pub request_body: Option<Value>,
}

impl Fixture {
    /// The recorded response as a wiremock template.
    pub fn response(&self) -> ResponseTemplate {
        let t = ResponseTemplate::new(self.status).insert_header("x-graylog-node-id", "node-1");
        match &self.body {
            None | Some(Value::Null) => t,
            Some(Value::String(s)) => t.set_body_raw(s.clone().into_bytes(), "text/plain"),
            Some(v) => t.set_body_json(v.clone()),
        }
    }

    /// The response body (panics when absent).
    pub fn body(&self) -> Value {
        self.body.clone().expect("fixture body")
    }
}

/// Loads `tests/fixtures/graylog/<name>.json`.
pub fn fixture(name: &str) -> Fixture {
    let path = format!(
        "{}/tests/fixtures/graylog/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let v: Value = serde_json::from_str(&text).expect("fixture json");
    Fixture {
        status: v["response"]["status"].as_u64().unwrap() as u16,
        body: v["response"].get("body").cloned(),
        request_body: v["request"].get("body").cloned(),
    }
}

/// Retry policy with deterministic jitter and short backoffs.
pub fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(20),
        ..RetryPolicy::default()
    }
    .with_random(RandomSource::fixed(0.0))
}

/// Builder pointing at the mock server with a token and fast retries.
pub fn builder(server: &MockServer) -> GraylogConfigBuilder {
    GraylogConfig::builder()
        .url(server.uri())
        .api_token("tok-secret-1")
        .retry(fast_retry())
}

/// Client pointing at the mock server.
pub fn client(server: &MockServer) -> GraylogClient {
    GraylogClient::new(builder(server).build().unwrap()).unwrap()
}

/// `Authorization` header value for the test token.
pub const TOKEN_AUTH: &str = "Basic dG9rLXNlY3JldC0xOnRva2Vu";

/// A local port with nothing listening.
pub fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}
