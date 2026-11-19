//! Search, stored messages, record normalization and the LogQuery client.

mod graylog_support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use graylog_support::{client, fixture};
use grow_graylog as sdk;
use sdk::core::ErrorCode;
use sdk::logging::{LogQueryClient, SearchOptions, Severity, SortOrder, TailOptions, WaitOptions};
use sdk::{log_record_from_message, LogQueryOptions, MessageSearchOptions, SearchSort};
use serde_json::{json, Map, Value};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn ts(s: &str) -> SystemTime {
    humantime::parse_rfc3339(s).unwrap()
}

#[tokio::test]
async fn search_absolute_sorted_fields() {
    let f = fixture("search.absolute_sorted_fields");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/views/search/sync"))
        .and(body_partial_json(f.request_body.clone().unwrap()))
        .respond_with(f.response())
        .mount(&server)
        .await;
    let c = client(&server);
    let res = c
        .search(
            "marker:growsdk179503370112643 AND transport:tcp",
            MessageSearchOptions {
                start: Some(ts("2026-11-18T20:28:15.935Z")),
                end: Some(ts("2026-11-18T20:28:24.794Z")),
                limit: Some(10),
                fields: vec![
                    "message".into(),
                    "marker".into(),
                    "seq".into(),
                    "timestamp".into(),
                ],
                sort: vec![SearchSort::asc("seq")],
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(res.total, 3);
    assert_eq!(res.messages.len(), 3);
    assert_eq!(res.next_offset, None);
    assert!(res.from.is_some() && res.to.is_some());
    let m = &res.messages[0];
    assert_eq!(m.index, "graylog_0");
    assert_eq!(m.id, "99c65856-e38e-11f1-8dde-020650dd320d");
    assert_eq!(m.fields["seq"], json!(0));
    assert!(m.timestamp.is_some());
    let records = res.records();
    assert_eq!(records[0].body, "growsdk179503370112643 tcp #0");
}

#[tokio::test]
async fn search_paging_relative_keyword_streams() {
    let server = MockServer::start().await;
    for name in [
        "search.desc_limit_offset",
        "searchRelative.ok",
        "search.keyword_range",
        "search.stream_filter",
    ] {
        let f = fixture(name);
        Mock::given(path("/api/views/search/sync"))
            .and(body_partial_json(f.request_body.clone().unwrap()))
            .respond_with(f.response())
            .mount(&server)
            .await;
    }
    let c = client(&server);
    let window = (
        Some(ts("2026-11-18T20:28:15.935Z")),
        Some(ts("2026-11-18T20:28:24.794Z")),
    );
    let paged = c
        .search(
            "marker:growsdk179503370112643 AND transport:tcp",
            MessageSearchOptions {
                start: window.0,
                end: window.1,
                limit: Some(1),
                offset: 1,
                sort: vec![SearchSort::desc("seq")],
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(paged.messages.len(), 1);
    assert_eq!(paged.next_offset, Some(2));
    let rel = c
        .search_relative(
            "marker:growsdk179503370112643",
            Duration::from_millis(299_100),
            MessageSearchOptions {
                limit: Some(50),
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(rel.total, 13);
    let kw = c
        .search(
            "marker:growsdk179503370112643",
            MessageSearchOptions {
                keyword: Some("last five minutes".into()),
                limit: Some(1),
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(kw.next_offset, Some(1));
    let streams = c
        .search(
            "",
            MessageSearchOptions {
                start: window.0,
                end: window.1,
                limit: Some(50),
                streams: vec!["6afe0a6607ba3acebff1894e".into()],
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(streams.total, 13);
}

#[tokio::test]
async fn search_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(
            json!({"queries": [{"query": {"query_string": "marker:(("}}]}),
        ))
        .respond_with(fixture("search.invalid_query").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(
            json!({"queries": [{"query": {"query_string": "bad"}}]}),
        ))
        .respond_with(fixture("search.bad_request").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(
            json!({"queries": [{"query": {"query_string": "unauth"}}]}),
        ))
        .respond_with(fixture("search.unauthorized").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(json!({"queries": [{"query": {"query_string": "exc"}}]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"execution": {"completed_exceptionally": true}, "errors": [{"description": ""}]})))
        .mount(&server)
        .await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(
            json!({"queries": [{"query": {"query_string": "empty"}}]}),
        ))
        .respond_with(fixture("search.empty").response())
        .mount(&server)
        .await;
    let c = client(&server);
    let d = MessageSearchOptions::default;
    let err = c.search("marker:((", d()).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("all shards failed"), "{err}");
    assert_eq!(
        c.search("bad", d()).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        c.search("unauth", d()).await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    let err = c.search("exc", d()).await.unwrap_err();
    assert!(err.message().contains("query failed"));
    let empty = c.search("empty", d()).await.unwrap();
    assert!(empty.messages.is_empty() && empty.next_offset.is_none());

    // client-side validation
    let cases = vec![
        MessageSearchOptions {
            limit: Some(0),
            ..d()
        },
        MessageSearchOptions {
            limit: Some(10_001),
            ..d()
        },
        MessageSearchOptions {
            sort: vec![SearchSort::asc(" ")],
            ..d()
        },
        MessageSearchOptions {
            range: Some(Duration::from_secs(1)),
            keyword: Some("x".into()),
            ..d()
        },
        MessageSearchOptions {
            start: Some(SystemTime::now()),
            end: Some(UNIX_EPOCH),
            ..d()
        },
        MessageSearchOptions {
            keyword: Some(" ".into()),
            ..d()
        },
        MessageSearchOptions {
            range: Some(Duration::ZERO),
            ..d()
        },
    ];
    for o in cases {
        assert_eq!(
            c.search("x", o.clone()).await.unwrap_err().code(),
            ErrorCode::Validation,
            "{o:?}"
        );
    }
    assert_eq!(
        c.search_relative("x", Duration::ZERO, d())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn search_default_and_open_ranges() {
    let server = MockServer::start().await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(json!({"queries": [{"query": {"query_string": "*"},
            "timerange": {"type": "relative", "range": 300},
            "search_types": [{"limit": 100, "offset": 0, "sort": [{"field": "timestamp", "order": "DESC"}]}]}]})))
        .respond_with(fixture("search.empty").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(json!({"queries": [{"query": {"query_string": "open"}, "timerange": {"type": "absolute"}}]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let c = client(&server);
    c.search("  ", MessageSearchOptions::default())
        .await
        .unwrap();
    let r = c
        .search(
            "open",
            MessageSearchOptions {
                end: Some(SystemTime::now()),
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(r.total, 0);
    c.search(
        "open",
        MessageSearchOptions {
            start: Some(UNIX_EPOCH + Duration::from_secs(10)),
            ..MessageSearchOptions::default()
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn get_message_with_fixtures() {
    let server = MockServer::start().await;
    Mock::given(path(
        "/api/messages/graylog_0/99c65855-e38e-11f1-8dde-020650dd320d",
    ))
    .respond_with(fixture("getMessage.ok").response())
    .mount(&server)
    .await;
    Mock::given(path("/api/messages/graylog_0/missing"))
        .respond_with(fixture("getMessage.not_found").response())
        .mount(&server)
        .await;
    Mock::given(path("/api/messages/graylog_0/noid"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"message": {"id": "from-envelope", "fields": {"message": "m"}}}),
            ),
        )
        .mount(&server)
        .await;
    let c = client(&server);
    let m = c
        .get_message("graylog_0", "99c65855-e38e-11f1-8dde-020650dd320d")
        .await
        .unwrap();
    assert_eq!(m.id, "99c65855-e38e-11f1-8dde-020650dd320d");
    assert_eq!(m.index, "graylog_0");
    assert_eq!(m.fields["marker"], "growsdk179503370112643");
    let r = m.record();
    assert_eq!(r.severity, Severity::Info);
    assert_eq!(r.resource["host.name"], "grow-sdk-verify");
    assert_eq!(r.attributes["bool_attr"], "true");
    assert!(!r.attributes.contains_key("gl2_message_id"));
    assert!(!r.attributes.contains_key("streams"));
    let err = c.get_message("graylog_0", "missing").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(
        c.get_message("graylog_0", "noid").await.unwrap().id,
        "from-envelope"
    );
    for (i, id) in [("", "x"), ("x", ""), ("a/b", "x")] {
        assert_eq!(
            c.get_message(i, id).await.unwrap_err().code(),
            ErrorCode::Validation
        );
    }
}

#[test]
fn record_normalization_otlp_and_gelf() {
    let hit = fixture("otlpLogs.searched").body();
    let fields = hit["message"]["message"].as_object().unwrap().clone();
    let r = log_record_from_message(&fields);
    assert_eq!(r.severity, Severity::Warn);
    assert_eq!(r.severity_text, "WARN");
    assert_eq!(
        r.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(r.span_id.as_deref(), Some("00f067aa0ba902b7"));
    assert_eq!(r.resource["service.name"], "grow-sdk-verify");
    assert_eq!(r.resource["marker"], "growsdkotlp179503370112643");
    assert_eq!(r.attributes["attr_k"], "v");
    assert_eq!(r.attributes["app"], "server");
    assert!(r.timestamp > UNIX_EPOCH);

    let typed = fixture("gelfTypedFields.stored").body();
    let fields = typed["message"]["message"].as_object().unwrap().clone();
    let r = log_record_from_message(&fields);
    assert!(!r.body.is_empty());

    let mut f: Map<String, Value> = serde_json::from_value(json!({
        "message": 42, "level": "3", "trace_id": "4BF92F3577B34DA6A3CE929D0E0E4736", "span_id": "zz",
        "trace_flags": 1, "service_name": "svc", "deployment_environment": "prod", "attr_id": "aid",
        "otel_resource_attributes_service_version": "2", "service_version": "ignored", "nil": null,
        "gl2_x": 1, "timestamp": "2026-11-18 20:28:22.973", "other": [1, "two"],
    }))
    .unwrap();
    let r = log_record_from_message(&f);
    assert_eq!(r.body, "42");
    assert_eq!(r.severity, Severity::Error);
    assert_eq!(
        r.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(r.span_id, None);
    assert_eq!(r.trace_flags, Some(1));
    assert_eq!(r.resource["service.name"], "svc");
    assert_eq!(r.resource["deployment.environment"], "prod");
    assert_eq!(r.resource["service.version"], "2");
    assert_eq!(r.attributes["id"], "aid");
    assert_eq!(r.attributes["other"], json!([1, "two"]));
    assert!(!r.attributes.contains_key("nil") && !r.attributes.contains_key("gl2_x"));
    assert_eq!(r.timestamp, ts("2026-11-18T20:28:22.973Z"));

    f.clear();
    f.insert("otel_severity_number".into(), json!(99));
    f.insert("level".into(), json!(0));
    f.insert("trace_id".into(), json!("short"));
    f.insert("trace_flags".into(), json!(1));
    f.insert("timestamp".into(), json!("2026-11-18T21:28:22.973+01:00"));
    let r = log_record_from_message(&f);
    assert_eq!(r.severity, Severity::Fatal);
    assert_eq!(r.trace_id, None);
    assert_eq!(r.trace_flags, None);
    assert_eq!(r.body, "");
    assert_eq!(r.timestamp, ts("2026-11-18T20:28:22.973Z"));
    f.insert("timestamp".into(), json!("2026-11-18T19:28:22.973-01:00"));
    assert_eq!(
        log_record_from_message(&f).timestamp,
        ts("2026-11-18T20:28:22.973Z")
    );
    f.insert("timestamp".into(), json!("garbage-garbage-garbage"));
    assert_eq!(log_record_from_message(&f).timestamp, UNIX_EPOCH);
    let empty = log_record_from_message(&Map::new());
    assert_eq!(empty.severity, Severity::Info);
    assert_eq!(empty.timestamp, UNIX_EPOCH);
}

/// Answers searches with a fixed list of hits (one page).
struct Hits(Arc<Mutex<Vec<Value>>>);

impl Respond for Hits {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        let hits = self.0.lock().unwrap().clone();
        let n = hits.len();
        ResponseTemplate::new(200).set_body_json(
            json!({"execution": {"done": true}, "results": {"q1": {"errors": [],
            "search_types": {"st1": {"total_results": n, "messages": hits}}}}}),
        )
    }
}

fn hit(id: &str, msg: &str, t: &str) -> Value {
    json!({"index": "graylog_0", "message": {"_id": id, "message": msg, "timestamp": t, "level": 4}})
}

#[tokio::test]
async fn log_query_search_cursor_and_labels() {
    let server = MockServer::start().await;
    let hits = Arc::new(Mutex::new(vec![hit(
        "a",
        "one",
        "2026-11-18T20:28:22.938Z",
    )]));
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(json!({"queries": [{"search_types": [{"offset": 5, "limit": 2,
            "sort": [{"field": "timestamp", "order": "ASC"}, {"field": "gl2_message_id", "order": "ASC"}]}],
            "filter": {"filters": [{"id": "s1"}]}}]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": {"q1": {"search_types": {"st1": {
            "total_results": 10, "messages": [hit("x", "m", "2026-11-18T20:28:22.938Z"), hit("y", "n", "2026-11-18T20:28:22.939Z")]}}}}})))
        .mount(&server)
        .await;
    Mock::given(path("/api/views/search/sync"))
        .respond_with(Hits(hits.clone()))
        .mount(&server)
        .await;
    Mock::given(path("/api/system/fields"))
        .respond_with(fixture("listLabels.ok").response())
        .mount(&server)
        .await;
    let c = client(&server);
    let q = c.log_query(LogQueryOptions {
        streams: vec!["s1".into()],
        default_window: Some(Duration::from_secs(60)),
    });
    let page = q
        .search(
            "x",
            SearchOptions::default()
                .limit(2)
                .order(SortOrder::Asc)
                .cursor("5"),
        )
        .await
        .unwrap();
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.next_cursor.as_deref(), Some("7"));
    assert_eq!(page.total, Some(10));
    assert_eq!(
        q.search("x", SearchOptions::default().cursor("nope"))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    let plain = c.log_query(LogQueryOptions::default());
    let r = plain.search("one", SearchOptions::default()).await.unwrap();
    assert_eq!(r.records[0].severity, Severity::Warn);
    assert_eq!(r.next_cursor, None);
    let found = plain
        .wait_for_log(
            "one",
            WaitOptions::default().timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    assert_eq!(found.body, "one");
    assert!(plain
        .list_labels()
        .await
        .unwrap()
        .contains(&"source".to_owned()));
    assert!(format!("{plain:?}").contains("LogQuery"));
}

#[tokio::test]
async fn log_query_tail_polls_and_dedupes() {
    let server = MockServer::start().await;
    let hits = Arc::new(Mutex::new(Vec::new()));
    Mock::given(path("/api/views/search/sync"))
        .respond_with(Hits(hits.clone()))
        .mount(&server)
        .await;
    let c = client(&server);
    let q = c.log_query(LogQueryOptions::default());
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    let handle = q
        .tail(
            "marker:x",
            Arc::new(move |r| {
                if r.body == "boom" {
                    panic!("callback panics are contained");
                }
                g.lock().unwrap().push(r.body)
            }),
            TailOptions {
                interval: Duration::from_millis(20),
                start: Some(UNIX_EPOCH),
            },
        )
        .await
        .unwrap();
    let now = humantime::format_rfc3339_millis(SystemTime::now()).to_string();
    hits.lock().unwrap().push(hit("1", "first", &now));
    hits.lock().unwrap().push(hit("b", "boom", &now));
    tokio::time::sleep(Duration::from_millis(150)).await;
    hits.lock().unwrap().push(hit("2", "second", &now));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let bodies = got.lock().unwrap().clone();
    assert_eq!(bodies, vec!["first", "second"], "{bodies:?}");
    handle.stop();
    assert!(handle.is_stopped());

    // A failing search keeps polling; closing the client stops the tail.
    let server = MockServer::start().await;
    Mock::given(path("/api/views/search/sync"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "x"})))
        .mount(&server)
        .await;
    let c = client(&server);
    let h = c
        .log_query(LogQueryOptions::default())
        .tail("q", Arc::new(|_| {}), TailOptions::default())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    c.close().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(h.is_stopped());
    let err = c
        .log_query(LogQueryOptions::default())
        .tail("q", Arc::new(|_| {}), TailOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn log_query_tail_paginates() {
    let server = MockServer::start().await;
    let now = humantime::format_rfc3339_millis(SystemTime::now()).to_string();
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(
            json!({"queries": [{"search_types": [{"offset": 0}]}]}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"results": {"q1": {"search_types": {"st1": {
            "total_results": 2, "messages": [hit("p1", "page one", &now)]}}}}})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/views/search/sync"))
        .and(body_partial_json(
            json!({"queries": [{"search_types": [{"offset": 1}]}]}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"results": {"q1": {"search_types": {"st1": {
            "total_results": 2, "messages": [hit("p2", "page two", &now)]}}}}})),
        )
        .mount(&server)
        .await;
    let c = client(&server);
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    let h = c
        .log_query(LogQueryOptions::default())
        .tail(
            "q",
            Arc::new(move |r| g.lock().unwrap().push(r.body)),
            TailOptions {
                interval: Duration::from_millis(500),
                start: None,
            },
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.stop();
    assert_eq!(*got.lock().unwrap(), vec!["page one", "page two"]);
}
