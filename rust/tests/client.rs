// Taken over from sdk-kit 0.1.0 (header removed): the template tested the demo skeleton client;
// these tests cover the Graylog client surface (lbstatus health, /api/system ping/version, auth
// headers, close) with the recorded fixtures.
//! Graylog client surface: health, ping, version, system info, auth and close.

mod graylog_support;

use std::time::Duration;

use graylog_support::{builder, client, closed_port, fixture, TOKEN_AUTH};
use grow_graylog as sdk;
use sdk::core::ErrorCode;
use sdk::{GraylogClient as Client, GraylogConfig as Config};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn client_surface_with_fixtures() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/system/lbstatus"))
        .and(header("accept", "text/plain"))
        .respond_with(fixture("health.ok").response())
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system"))
        .and(header("authorization", TOKEN_AUTH))
        .respond_with(fixture("ping.ok_token").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/system/fields"))
        .respond_with(fixture("listLabels.ok").response())
        .mount(&server)
        .await;
    let c = client(&server);
    let h = c.health().await.unwrap();
    assert!(h.healthy);
    assert_eq!(h.status, "ok");
    assert_eq!(h.details["lb_status"], "ALIVE");
    assert!(c.ping().await.unwrap() > Duration::ZERO);
    assert_eq!(c.server_version().await.unwrap(), "7.0.16+58e0f6e");
    let info = c.system_info().await.unwrap();
    assert_eq!(info.facility, "graylog-server");
    assert!(info.started_at.is_some());
    assert!(info.is_processing);
    assert!(!info.node_id.is_empty());
    let fields = c.list_fields().await.unwrap();
    assert!(fields.contains(&"source".to_owned()));
    assert!(fields.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(c.config().gelf_host(), "127.0.0.1");
    assert!(format!("{c:?}").contains("GraylogClient"));
}

#[tokio::test]
async fn client_health_variants() {
    for (status, body, healthy, word, lb) in [
        (429, "THROTTLED", false, "degraded", "THROTTLED"),
        (503, "DEAD", false, "unhealthy", "DEAD"),
        (200, "starting", false, "unhealthy", "STARTING"),
        (500, "", false, "unhealthy", "HTTP 500"),
    ] {
        let server = MockServer::start().await;
        Mock::given(path("/api/system/lbstatus"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        let h = client(&server).health().await.unwrap();
        assert_eq!(h.healthy, healthy, "{status}");
        assert_eq!(h.status, word, "{status}");
        assert_eq!(h.details["lb_status"], lb, "{status}");
    }
    // 406 when a JSON accept header is sent: the client never sends one (recorded fixture).
    let server = MockServer::start().await;
    Mock::given(path("/api/system/lbstatus"))
        .respond_with(fixture("health.json_accept_406").response())
        .mount(&server)
        .await;
    let h = client(&server).health().await.unwrap();
    assert!(!h.healthy);
}

#[tokio::test]
async fn core_health_unreachable_and_closed() {
    let cfg = Config::builder()
        .url(format!("http://127.0.0.1:{}", closed_port()))
        .max_retries(0)
        .build()
        .unwrap();
    let c = Client::new(cfg).unwrap();
    let h = c.health().await.unwrap();
    assert!(!h.healthy);
    assert_eq!(h.status, "unreachable");
    assert!(h.details.contains_key("error"));
    c.close().await;
    assert_eq!(c.health().await.unwrap_err().code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn client_auth_errors_and_password() {
    let server = MockServer::start().await;
    Mock::given(path("/api/system"))
        .and(header("authorization", "Basic YWRtaW46cHctc2VjcmV0LTE="))
        .respond_with(fixture("ping.ok_password").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/system"))
        .respond_with(fixture("ping.unauthorized").response())
        .mount(&server)
        .await;
    let pw = Client::new(
        Config::builder()
            .url(server.uri())
            .credentials("admin", "pw-secret-1")
            .build()
            .unwrap(),
    )
    .unwrap();
    pw.ping().await.unwrap();
    let bad = client(&server);
    let err = bad.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    assert_eq!(err.http_status(), Some(401));
    assert!(!err.to_string().contains("tok-secret-1"));
    let none = Client::new(Config::builder().url(server.uri()).build().unwrap()).unwrap();
    assert_eq!(
        none.server_version().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
}

#[tokio::test]
async fn client_server_version_unsupported_and_bad_json() {
    let server = MockServer::start().await;
    Mock::given(path("/api/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"facility": "x"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/system/fields"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
        .mount(&server)
        .await;
    let c = client(&server);
    assert_eq!(
        c.server_version().await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    let err = c.list_fields().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn core_close_idempotent() {
    let server = MockServer::start().await;
    let c = client(&server);
    assert!(!c.is_closed());
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let r = ran.clone();
    c.on_close(move || {
        Box::pin(async move {
            r.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
    });
    c.close().await;
    c.close().await;
    assert!(c.is_closed());
    assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
    assert_eq!(
        c.list_inputs().await.unwrap_err().code(),
        ErrorCode::Cancelled
    );
}

#[tokio::test]
async fn client_config_errors_and_secrets() {
    let bad = Config::builder()
        .ca_cert_path("/nonexistent/ca.pem")
        .build()
        .unwrap();
    assert_eq!(Client::new(bad).unwrap_err().code(), ErrorCode::Config);
    let server = MockServer::start().await;
    let c = Client::new(
        builder(&server)
            .credentials("u", "pass-secret-9")
            .build()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        c.transport().redact("x tok-secret-1 pass-secret-9"),
        "x [REDACTED] [REDACTED]"
    );
    assert!(!format!("{:?}", c.config()).contains("tok-secret-1"));
    let _ = Client::from_env();
}
