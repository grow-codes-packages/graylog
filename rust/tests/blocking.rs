// Taken over from sdk-kit 0.1.0 (header removed): the template exercised the demo endpoints;
// this covers every method of the Graylog blocking client against a mock server.
//! Blocking client (feature `blocking`).
#![cfg(feature = "blocking")]

mod graylog_support;

use std::sync::Arc;
use std::time::Duration;

use graylog_support::fixture;
use grow_graylog as sdk;
use sdk::blocking::GraylogClient as Client;
use sdk::core::ErrorCode;
use sdk::logging::{LogClient, SearchOptions, TailOptions, WaitOptions};
use sdk::{
    CreateInputOptions, CreateStreamOptions, EnsureGelfInputOptions, GelfMessage, GelfProtocol,
    GelfSendOptions, GelfTransportOptions, GraylogConfig as Config, ListStreamsOptions, LogOptions,
    LogQueryOptions, MessageSearchOptions,
};
use serde_json::{json, Map};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn server_with_mocks() -> (tokio::runtime::Runtime, MockServer) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        let mounts: Vec<(&str, &str, ResponseTemplate)> = vec![
            (
                "GET",
                "/api/system/lbstatus",
                fixture("health.ok").response(),
            ),
            ("GET", "/api/system", fixture("ping.ok_token").response()),
            (
                "GET",
                "/api/system/fields",
                fixture("listLabels.ok").response(),
            ),
            (
                "GET",
                "/api/system/inputs",
                ResponseTemplate::new(200).set_body_json(json!({"inputs": [
                {"id": "in1", "type": sdk::INPUT_TYPE_GELF_TCP, "attributes": {"port": 12201}}]})),
            ),
            (
                "GET",
                "/api/system/inputs/in1",
                fixture("getInput.ok").response(),
            ),
            (
                "GET",
                "/api/system/inputs/types",
                fixture("listInputTypes.ok").response(),
            ),
            (
                "GET",
                "/api/system/inputstates/in1",
                fixture("getInputState.running").response(),
            ),
            (
                "POST",
                "/api/system/inputs",
                fixture("createInput.created").response(),
            ),
            (
                "DELETE",
                "/api/system/inputs/in1",
                ResponseTemplate::new(204),
            ),
            (
                "GET",
                "/api/streams/paginated",
                fixture("listStreams.ok").response(),
            ),
            ("GET", "/api/streams/s1", fixture("getStream.ok").response()),
            (
                "POST",
                "/api/streams",
                ResponseTemplate::new(201).set_body_json(json!({"stream_id": "s1"})),
            ),
            ("POST", "/api/streams/s1/resume", ResponseTemplate::new(204)),
            ("DELETE", "/api/streams/s1", ResponseTemplate::new(204)),
            (
                "GET",
                "/api/system/indices/index_sets",
                fixture("listIndexSets.ok").response(),
            ),
            (
                "POST",
                "/api/views/search/sync",
                fixture("searchRelative.ok").response(),
            ),
            (
                "GET",
                "/api/messages/graylog_0/m1",
                fixture("getMessage.ok").response(),
            ),
            ("POST", "/gelf", ResponseTemplate::new(202)),
        ];
        for (m, p, r) in mounts {
            Mock::given(method(m))
                .and(path(p))
                .respond_with(r)
                .mount(&server)
                .await;
        }
        Mock::given(path_regex("^/nothing$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        server
    });
    (rt, server)
}

#[test]
fn blocking_client_every_method() {
    let (_rt, server) = server_with_mocks();
    let cfg = Config::builder()
        .url(server.uri())
        .api_token("t-1234")
        .gelf_http_url(format!("{}/gelf", server.uri()))
        .build()
        .unwrap();
    let c = Client::new(cfg).unwrap();
    assert!(c.health().unwrap().healthy);
    c.ping().unwrap();
    assert_eq!(c.server_version().unwrap(), "7.0.16+58e0f6e");
    assert_eq!(c.system_info().unwrap().codename, "Noir");
    assert!(!c.list_fields().unwrap().is_empty());
    assert_eq!(c.list_inputs().unwrap().len(), 1);
    assert!(!c.get_input("in1").unwrap().id.is_empty());
    assert!(!c.list_input_types().unwrap().is_empty());
    assert_eq!(c.get_input_state("in1").unwrap().state, "RUNNING");
    assert!(!c
        .create_input("a.B", Map::new(), CreateInputOptions::default())
        .unwrap()
        .is_empty());
    let ensured = c
        .ensure_gelf_input(GelfProtocol::Tcp, 12201, EnsureGelfInputOptions::default())
        .unwrap();
    assert!(!ensured.created);
    c.delete_input("in1").unwrap();
    assert_eq!(
        c.list_streams(ListStreamsOptions::default()).unwrap().total,
        3
    );
    assert!(!c.get_stream("s1").unwrap().id.is_empty());
    assert_eq!(
        c.create_stream(CreateStreamOptions::new("t")).unwrap(),
        "s1"
    );
    c.resume_stream("s1").unwrap();
    c.delete_stream("s1").unwrap();
    assert!(!c.list_index_sets().unwrap().is_empty());
    assert_eq!(
        c.search("x", MessageSearchOptions::default())
            .unwrap()
            .total,
        13
    );
    assert_eq!(
        c.search_relative(
            "x",
            Duration::from_secs(60),
            MessageSearchOptions::default()
        )
        .unwrap()
        .total,
        13
    );
    assert!(!c.get_message("graylog_0", "m1").unwrap().id.is_empty());
    let t = c
        .gelf_transport(Some(GelfProtocol::Http), GelfTransportOptions::default())
        .unwrap();
    let r = c
        .send_gelf(
            t.as_ref(),
            &[GelfMessage::simple("h", "m").unwrap()],
            GelfSendOptions::default(),
        )
        .unwrap();
    assert_eq!(r.sent, 1);

    let q = c.log_query(LogQueryOptions::default());
    assert_eq!(
        q.search("x", SearchOptions::default()).unwrap().total,
        Some(13)
    );
    assert!(!q.list_streams().unwrap().is_empty());
    assert!(!q.list_labels().unwrap().is_empty());
    q.wait_for_log("x", WaitOptions::default()).unwrap();
    let h = q
        .tail("x", Arc::new(|_| {}), TailOptions::default())
        .unwrap();
    h.stop();

    let lc = c
        .new_log_client(LogOptions::default().protocol(GelfProtocol::Http))
        .unwrap();
    lc.send("blocking".into());
    c.block_on(lc.flush(None)).unwrap();
    assert_eq!(lc.stats().sent, 1);
    let exp = Arc::new(sdk::GelfLogExporter::new(
        t,
        sdk::FromLogRecordOptions::default(),
    ));
    let lc2 = c
        .new_log_client_with_exporter(exp, LogOptions::default())
        .unwrap();
    lc2.send("again".into());
    assert!(!c.async_client().is_closed());
    assert_eq!(c.config().requested_by(), "grow-codes-graylog");
    assert_eq!(c.block_on(async { 7 }), 7);
    c.close();
    c.close();
    assert_eq!(c.ping().unwrap_err().code(), ErrorCode::Cancelled);
    let _ = Client::from_env();
    let bad = Config::builder()
        .ca_cert_path("/nonexistent")
        .build()
        .unwrap();
    assert_eq!(Client::new(bad).unwrap_err().code(), ErrorCode::Config);
}
