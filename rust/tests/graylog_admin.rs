//! Admin REST functions (inputs, streams, index sets) against recorded fixtures.

mod graylog_support;

use std::time::Duration;

use graylog_support::{client, fixture, TOKEN_AUTH};
use grow_graylog as sdk;
use sdk::core::ErrorCode;
use sdk::logging::SortOrder;
use sdk::{
    CreateInputOptions, CreateStreamOptions, EnsureGelfInputOptions, GelfProtocol,
    ListStreamsOptions, StreamRule,
};
use serde_json::{json, Map, Value};
use wiremock::matchers::{body_partial_json, header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[tokio::test]
async fn inputs_with_fixtures() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .and(header("authorization", TOKEN_AUTH))
        .respond_with(fixture("listInputs.ok").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputs/6afe0a6607ba3acebff1891c"))
        .and(method("GET"))
        .respond_with(fixture("getInput.ok").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputs/types"))
        .respond_with(fixture("listInputTypes.ok").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputstates/6afe0a6607ba3acebff1891c"))
        .respond_with(fixture("getInputState.running").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputs/missing"))
        .respond_with(fixture("getInput.not_found").response())
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/system/inputs/6afe0a6607ba3acebff1891c"))
        .and(header_exists("x-requested-by"))
        .respond_with(fixture("deleteInput.deleted").response())
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/system/inputs/gone"))
        .respond_with(fixture("deleteInput.not_found").response())
        .mount(&server)
        .await;
    let c = client(&server);
    let inputs = c.list_inputs().await.unwrap();
    assert!(!inputs.is_empty());
    let tcp = inputs
        .iter()
        .find(|i| i.input_type == sdk::INPUT_TYPE_GELF_TCP)
        .expect("tcp input");
    assert_eq!(tcp.port(), 12201);
    assert!(!tcp.bind_address().is_empty());
    assert!(tcp.created_at.is_some());
    let input = c.get_input("6afe0a6607ba3acebff1891c").await.unwrap();
    assert_eq!(input.input_type, sdk::INPUT_TYPE_GELF_HTTP);
    let types = c.list_input_types().await.unwrap();
    assert_eq!(types[sdk::INPUT_TYPE_GELF_HTTP], "GELF HTTP");
    let st = c.get_input_state("6afe0a6607ba3acebff1891c").await.unwrap();
    assert_eq!(st.state, sdk::INPUT_STATE_RUNNING);
    assert_eq!(st.input.id, "6afe0a6607ba3acebff1891c");
    let err = c.get_input("missing").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert!(err.message().contains("not found"));
    c.delete_input("6afe0a6607ba3acebff1891c").await.unwrap();
    assert_eq!(
        c.delete_input("gone").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    for bad in ["", " ", "a/b"] {
        assert_eq!(
            c.get_input(bad).await.unwrap_err().code(),
            ErrorCode::Validation
        );
        assert_eq!(
            c.get_input_state(bad).await.unwrap_err().code(),
            ErrorCode::Validation
        );
        assert_eq!(
            c.delete_input(bad).await.unwrap_err().code(),
            ErrorCode::Validation
        );
    }
}

#[tokio::test]
async fn input_port_attribute_forms() {
    let server = MockServer::start().await;
    Mock::given(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": [
            {"id": "a", "attributes": {"port": "12201"}},
            {"id": "b", "attributes": {"port": 1.0e3}},
            {"id": "c", "attributes": {"port": true}},
            {"id": "d", "type": null, "global": "yes", "attributes": null},
        ]})))
        .mount(&server)
        .await;
    let inputs = client(&server).list_inputs().await.unwrap();
    let ports: Vec<u16> = inputs.iter().map(|i| i.port()).collect();
    assert_eq!(ports, vec![12201, 1000, 0, 0]);
    assert_eq!(inputs[3].bind_address(), "");
    assert!(!inputs[3].global);
}

#[tokio::test]
async fn create_input_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .and(header("x-requested-by", "grow-codes-graylog"))
        .and(body_partial_json(json!({"type": sdk::INPUT_TYPE_GELF_UDP, "global": true, "title": "GELFUDPInput (grow-codes)"})))
        .respond_with(fixture("createInput.created").response())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .and(body_partial_json(
            json!({"global": false, "node": "n1", "title": "local"}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .and(body_partial_json(json!({"type": "org.example.Nope"})))
        .respond_with(fixture("createInput.bad_type").response())
        .mount(&server)
        .await;
    let c = client(&server);
    let id = c
        .create_input(
            sdk::INPUT_TYPE_GELF_UDP,
            Map::new(),
            CreateInputOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(id, "6afe0a6607ba3acebff1891c");
    let err = c
        .create_input(
            sdk::INPUT_TYPE_GELF_UDP,
            Map::new(),
            CreateInputOptions {
                title: Some("local".into()),
                node: Some("n1".into()),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    let err = c
        .create_input(
            "org.example.Nope",
            Map::new(),
            CreateInputOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(
        c.create_input("", Map::new(), CreateInputOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    // The CSRF error shape maps to VALIDATION.
    let server = MockServer::start().await;
    Mock::given(path("/api/system/inputs"))
        .respond_with(fixture("createInput.missing_requested_by").response())
        .mount(&server)
        .await;
    let err = client(&server)
        .create_input("x.Y", Map::new(), CreateInputOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("CSRF"));
}

fn ensure_opts() -> EnsureGelfInputOptions {
    EnsureGelfInputOptions {
        timeout: Some(Duration::from_millis(300)),
        interval: Some(Duration::from_millis(10)),
        ..EnsureGelfInputOptions::default()
    }
}

#[tokio::test]
async fn ensure_gelf_input_reuses_existing() {
    let server = MockServer::start().await;
    Mock::given(path("/api/system/inputs"))
        .respond_with(fixture("listInputs.ok").response())
        .mount(&server)
        .await;
    let list = fixture("listInputs.ok").body();
    let tcp_id = list["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["type"] == sdk::INPUT_TYPE_GELF_TCP)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Mock::given(path(format!("/api/system/inputstates/{tcp_id}")))
        .respond_with(fixture("getInputState.running").response())
        .mount(&server)
        .await;
    let got = client(&server)
        .ensure_gelf_input(GelfProtocol::Tcp, 12201, ensure_opts())
        .await
        .unwrap();
    assert!(!got.created);
    assert_eq!(got.input.id, tcp_id);
}

#[tokio::test]
async fn ensure_gelf_input_creates_and_waits() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .and(body_partial_json(
            json!({"title": "grow-codes GELF UDP 12291",
            "configuration": {"port": 12291, "bind_address": "0.0.0.0", "recv_buffer_size": 1}}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "new1"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputs/new1"))
        .and(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"id": "new1", "type": sdk::INPUT_TYPE_GELF_UDP, "attributes": {"port": 12291}}),
        ))
        .mount(&server)
        .await;
    // Not running yet (404), then starting, then running.
    Mock::given(path("/api/system/inputstates/new1"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "x"})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputstates/new1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "new1", "state": "STARTING"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputstates/new1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "new1", "state": "RUNNING"})),
        )
        .mount(&server)
        .await;
    let mut opts = ensure_opts();
    opts.configuration
        .insert("recv_buffer_size".into(), json!(1));
    let got = client(&server)
        .ensure_gelf_input(GelfProtocol::Udp, 12291, opts)
        .await
        .unwrap();
    assert!(got.created);
    assert_eq!(got.input.port(), 12291);
}

#[tokio::test]
async fn ensure_gelf_input_failed_state_is_conflict_and_deletes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .respond_with(fixture("createInput.port_collision").response())
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs/6afe0a6607ba3acebff1892e"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "6afe0a6607ba3acebff1892e"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputstates/6afe0a6607ba3acebff1892e"))
        .respond_with(fixture("getInputState.port_collision").response())
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/system/inputs/6afe0a6607ba3acebff1892e"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let err = client(&server)
        .ensure_gelf_input(GelfProtocol::Http, 12201, ensure_opts())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    assert!(err.message().contains("bind"), "{err}");
}

#[tokio::test]
async fn ensure_gelf_input_timeout_relist_and_validation() {
    let server = MockServer::start().await;
    // First list empty, create fails, re-list finds the input (ambiguous create).
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": []})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": [
            {"id": "x1", "type": sdk::INPUT_TYPE_GELF_TCP, "attributes": {"port": 12299, "bind_address": "0.0.0.0"}}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "boom"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputstates/x1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"state": "STARTING"})))
        .mount(&server)
        .await;
    let c = client(&server);
    let err = c
        .ensure_gelf_input(GelfProtocol::Tcp, 12299, ensure_opts())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Timeout);
    assert_eq!(
        c.ensure_gelf_input(GelfProtocol::Otlp, 1, ensure_opts())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    assert_eq!(
        c.ensure_gelf_input(GelfProtocol::Udp, 0, ensure_opts())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );

    // Create fails and the re-list does not find it: the create error is returned.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "no"})))
        .mount(&server)
        .await;
    let err = client(&server)
        .ensure_gelf_input(GelfProtocol::Udp, 12201, EnsureGelfInputOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);

    // A state error other than 404 is returned at once.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": [
            {"id": "y1", "type": sdk::INPUT_TYPE_GELF_UDP, "attributes": {"port": 12201}}
        ]})))
        .mount(&server)
        .await;
    Mock::given(path("/api/system/inputstates/y1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let err = client(&server)
        .ensure_gelf_input(GelfProtocol::Udp, 12201, ensure_opts())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    // list error
    let server = MockServer::start().await;
    let err = client(&server)
        .ensure_gelf_input(GelfProtocol::Udp, 12201, ensure_opts())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn streams_with_fixtures() {
    let server = MockServer::start().await;
    Mock::given(path("/api/streams/paginated"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "50"))
        .and(query_param("sort", "title"))
        .and(query_param("order", "asc"))
        .respond_with(fixture("listStreams.ok").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/streams/paginated"))
        .and(query_param("order", "desc"))
        .and(query_param("query", "Default"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"elements": null})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/streams/6afe0a6607ba3acebff1894e"))
        .respond_with(fixture("getStream.ok").response())
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/streams/000000000000000000000fff"))
        .respond_with(fixture("getStream.not_found").response())
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/streams/6afe0a6607ba3acebff1894e"))
        .respond_with(fixture("deleteStream.deleted").response())
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/streams/gone"))
        .respond_with(fixture("deleteStream.not_found").response())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams/6afe0a6607ba3acebff1894e/resume"))
        .and(header("x-requested-by", "grow-codes-graylog"))
        .respond_with(fixture("resumeStream.ok").response())
        .mount(&server)
        .await;
    let c = client(&server);
    let page = c.list_streams(ListStreamsOptions::default()).await.unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.page, 1);
    assert_eq!(page.per_page, 50);
    assert!(page.streams.iter().any(|s| s.is_default));
    let other = c
        .list_streams(ListStreamsOptions {
            page: Some(2),
            per_page: Some(10),
            query: Some("Default".into()),
            sort: Some("title".into()),
            order: Some(SortOrder::Desc),
        })
        .await
        .unwrap();
    assert!(other.streams.is_empty());
    let s = c.get_stream("6afe0a6607ba3acebff1894e").await.unwrap();
    assert_eq!(s.rules.len(), 1);
    assert_eq!(s.rules[0].rule_type, sdk::STREAM_RULE_EXACT);
    assert!(!s.disabled);
    assert_eq!(
        c.get_stream("000000000000000000000fff")
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    c.resume_stream("6afe0a6607ba3acebff1894e").await.unwrap();
    c.delete_stream("6afe0a6607ba3acebff1894e").await.unwrap();
    assert_eq!(
        c.delete_stream("gone").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    for bad in ["", "a/b"] {
        assert_eq!(
            c.get_stream(bad).await.unwrap_err().code(),
            ErrorCode::Validation
        );
        assert_eq!(
            c.resume_stream(bad).await.unwrap_err().code(),
            ErrorCode::Validation
        );
        assert_eq!(
            c.delete_stream(bad).await.unwrap_err().code(),
            ErrorCode::Validation
        );
    }
}

#[tokio::test]
async fn create_stream_flow() {
    let server = MockServer::start().await;
    Mock::given(path("/api/system/indices/index_sets"))
        .and(query_param("skip_stats", "true"))
        .respond_with(fixture("listIndexSets.ok").response())
        .mount(&server)
        .await;
    let sets = fixture("listIndexSets.ok").body();
    let default_id = sets["index_sets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["default"] == true)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Mock::given(method("POST"))
        .and(path("/api/streams"))
        .and(body_partial_json(json!({"entity": {"title": "t", "index_set_id": default_id, "matching_type": "OR",
            "rules": [{"field": "marker", "type": 1, "value": "abc", "inverted": false, "description": ""}]}})))
        .respond_with(fixture("createStream.created").response())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams/6afe0a6607ba3acebff1894e/resume"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    let index_sets = c.list_index_sets().await.unwrap();
    assert!(index_sets.iter().any(|s| s.default && s.writable));
    let mut opts = CreateStreamOptions::new("t")
        .description("d")
        .rule(StreamRule::exact("marker", "abc"));
    opts.matching_type = Some("or".into());
    let id = c.create_stream(opts).await.unwrap();
    assert_eq!(id, "6afe0a6607ba3acebff1894e");
    // disabled: no resume (the expect(1) above would fail on a second call)
    let mut opts = CreateStreamOptions::new("t").rule(StreamRule::exact("marker", "abc"));
    opts.matching_type = Some("OR".into());
    opts.disabled = true;
    opts.index_set_id = Some(default_id.clone());
    assert_eq!(
        c.create_stream(opts).await.unwrap(),
        "6afe0a6607ba3acebff1894e"
    );

    assert_eq!(
        c.create_stream(CreateStreamOptions::new(" "))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    let mut bad = CreateStreamOptions::new("t");
    bad.matching_type = Some("XOR".into());
    assert_eq!(
        c.create_stream(bad).await.unwrap_err().code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn create_stream_edge_cases() {
    // No index set at all.
    let server = MockServer::start().await;
    Mock::given(path("/api/system/indices/index_sets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"index_sets": []})))
        .mount(&server)
        .await;
    let err = client(&server)
        .create_stream(CreateStreamOptions::new("t"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    // No default: the first set is used; missing stream id in the answer.
    let server = MockServer::start().await;
    Mock::given(path("/api/system/indices/index_sets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"index_sets": [{"id": "first"}, {"id": "second"}]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams"))
        .and(body_partial_json(
            json!({"entity": {"index_set_id": "first"}}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;
    let err = client(&server)
        .create_stream(CreateStreamOptions::new("t"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    // Recorded 400 for a missing index set.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/streams"))
        .respond_with(fixture("createStream.missing_index_set").response())
        .mount(&server)
        .await;
    let mut opts = CreateStreamOptions::new("t");
    opts.index_set_id = Some("x".into());
    let err = client(&server).create_stream(opts).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("indexSetId"));
    // Resume fails.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/streams"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"stream_id": "s1"})))
        .mount(&server)
        .await;
    let mut opts = CreateStreamOptions::new("t");
    opts.index_set_id = Some("x".into());
    let err = client(&server).create_stream(opts).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn list_all_streams_pages() {
    let server = MockServer::start().await;
    let page = |ids: &[&str], total: u64| {
        let elements: Vec<Value> = ids
            .iter()
            .map(|i| json!({"id": i, "title": format!("T{i}")}))
            .collect();
        json!({"pagination": {"total": total, "page": 1, "per_page": 100}, "elements": elements})
    };
    Mock::given(path("/api/streams/paginated"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&["b", "a"], 3)))
        .mount(&server)
        .await;
    Mock::given(path("/api/streams/paginated"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&["c"], 3)))
        .mount(&server)
        .await;
    let q = client(&server).log_query(sdk::LogQueryOptions::default());
    use sdk::logging::LogQueryClient;
    assert_eq!(q.list_streams().await.unwrap(), vec!["Ta", "Tb", "Tc"]);
    let _ = |r: &Request| r.url.clone();
}
