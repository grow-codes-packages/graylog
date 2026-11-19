//! Integration suite against the real Graylog (Docker): every public function is called at
//! least once with a round-trip assertion (write → read back).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use grow_graylog as sdk;
use grow_graylog_integration::load_bootstrap_env;
use sdk::blocking::GraylogClient as BlockingClient;
use sdk::logging::{
    attrs, AttrValue, LogClient, LogQueryClient, LogRecord, SearchOptions, Severity, TailOptions,
    WaitOptions,
};
use sdk::{
    CreateInputOptions, CreateStreamOptions, EnsureGelfInputOptions, ErrorCode, GelfHttpOptions,
    GelfHttpTransport, GelfLevel, GelfMessage, GelfMessageOptions, GelfProtocol, GelfSendOptions,
    GelfTcpOptions, GelfTcpTransport, GelfTransport, GelfTransportOptions, GelfUdpOptions,
    GelfUdpTransport, GraylogClient as Client, GraylogConfig as Config, ListStreamsOptions,
    LogOptions, LogQueryOptions, MessageSearchOptions, MessageSearchResult, SearchSort, StreamRule,
};
use serde_json::{json, Map};

fn client() -> Option<Client> {
    load_bootstrap_env();
    if std::env::var_os("GROW_GRAYLOG_URL").is_none() {
        eprintln!("GROW_GRAYLOG_URL is not set; run through docker/compose.yml");
        return None;
    }
    Some(Client::from_env().expect("client from env"))
}

fn run_id() -> String {
    format!("rs{}", sdk::testing::run_id())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// Polls `search` until at least `n` messages match.
async fn wait_messages(
    c: &Client,
    query: &str,
    n: usize,
    mut opts: MessageSearchOptions,
) -> MessageSearchResult {
    if opts.range.is_none() && opts.start.is_none() && opts.keyword.is_none() {
        opts.range = Some(Duration::from_secs(900));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let res = c.search(query, opts.clone()).await;
        if let Ok(r) = &res {
            if r.messages.len() >= n {
                return r.clone();
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("search {query:?}: {res:?}, want {n} messages");
        }
        // A sort on a field that is not mapped yet fails with "all shards failed": retry.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn core_and_system() {
    let Some(c) = client() else { return };
    let h = c.health().await.unwrap();
    assert!(h.healthy, "{h:?}");
    assert_eq!(h.status, "ok");
    assert_eq!(h.details["lb_status"], "ALIVE");
    assert!(c.ping().await.unwrap() > Duration::ZERO);
    let version = c.server_version().await.unwrap();
    assert!(version.starts_with("7."), "{version}");
    println!("Graylog server version {version}");
    let info = c.system_info().await.unwrap();
    assert_eq!(info.version, version);
    assert!(!info.node_id.is_empty() && info.is_processing);
    let fields = c.list_fields().await.unwrap();
    assert!(fields.contains(&"message".to_owned()));

    let bad = Client::new(
        Config::builder()
            .url(c.config().url().as_str())
            .api_token("not-a-valid-token")
            .build()
            .unwrap(),
    )
    .unwrap();
    let err = bad.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    assert!(!err.to_string().contains("not-a-valid-token"));
    let pw = Client::new(
        Config::builder()
            .url(c.config().url().as_str())
            .credentials(env("GRAYLOG_USER"), env("GRAYLOG_PASSWORD"))
            .build()
            .unwrap(),
    )
    .unwrap();
    pw.ping().await.expect("password auth");
    c.close().await;
    c.close().await;
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn inputs() {
    let Some(c) = client() else { return };
    let tcp_id = env("GRAYLOG_INPUT_ID_GELF_TCP");
    let inputs = c.list_inputs().await.unwrap();
    assert!(
        inputs.iter().any(|i| i.id == tcp_id),
        "bootstrap TCP input not listed"
    );
    let types = c.list_input_types().await.unwrap();
    assert!(!types[sdk::INPUT_TYPE_GELF_HTTP].is_empty());
    let input = c.get_input(&tcp_id).await.unwrap();
    assert_eq!(input.input_type, sdk::INPUT_TYPE_GELF_TCP);
    assert_eq!(input.port(), 12201);
    let st = c.get_input_state(&tcp_id).await.unwrap();
    assert_eq!(st.state, sdk::INPUT_STATE_RUNNING);

    // Existing input is reused.
    let ensured = c
        .ensure_gelf_input(GelfProtocol::Tcp, 12201, EnsureGelfInputOptions::default())
        .await
        .unwrap();
    assert!(!ensured.created);
    assert_eq!(ensured.input.id, tcp_id);
    // A new input is created, RUNNING, then deleted.
    let ensured = c
        .ensure_gelf_input(GelfProtocol::Udp, 12281, EnsureGelfInputOptions::default())
        .await
        .unwrap();
    assert!(ensured.created);
    assert_eq!(ensured.input.port(), 12281);
    c.delete_input(&ensured.input.id).await.unwrap();
    assert_eq!(
        c.get_input(&ensured.input.id).await.unwrap_err().code(),
        ErrorCode::NotFound
    );

    let mut cfg = Map::new();
    for (k, v) in [
        ("bind_address", json!("0.0.0.0")),
        ("port", json!(12282)),
        ("enable_bulk_receiving", json!(true)),
        ("max_chunk_size", json!(1048576)),
        ("recv_buffer_size", json!(1048576)),
        ("number_worker_threads", json!(1)),
    ] {
        cfg.insert(k.into(), v);
    }
    let title = format!("grow-sdk rust {}", run_id());
    let id = c
        .create_input(
            sdk::INPUT_TYPE_GELF_HTTP,
            cfg,
            CreateInputOptions {
                title: Some(title.clone()),
                node: None,
            },
        )
        .await
        .unwrap();
    let got = c.get_input(&id).await.unwrap();
    assert_eq!(got.port(), 12282);
    assert_eq!(got.title, title);
    c.delete_input(&id).await.unwrap();
    assert_eq!(
        c.delete_input(&id).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let err = c
        .create_input(
            "org.example.NoSuchInput",
            Map::new(),
            CreateInputOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    // A busy port fails to start → CONFLICT, and the created input is removed.
    let before = c.list_inputs().await.unwrap().len();
    let err = c
        .ensure_gelf_input(
            GelfProtocol::Http,
            12201,
            EnsureGelfInputOptions {
                timeout: Some(Duration::from_secs(20)),
                ..EnsureGelfInputOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict, "{err}");
    assert_eq!(c.list_inputs().await.unwrap().len(), before);
    c.close().await;
}

#[tokio::test]
async fn streams_and_search() {
    let Some(c) = client() else { return };
    let run = run_id();
    let sets = c.list_index_sets().await.unwrap();
    let default_set = env("GRAYLOG_DEFAULT_INDEX_SET_ID");
    assert!(sets.iter().any(|s| s.default && s.id == default_set));
    let page = c.list_streams(ListStreamsOptions::default()).await.unwrap();
    assert!(page.streams.iter().any(|s| s.is_default));
    let stream_id = c
        .create_stream(
            CreateStreamOptions::new(format!("grow-sdk rust {run}"))
                .description("rust integration")
                .rule(StreamRule::exact("marker", &run)),
        )
        .await
        .unwrap();
    let s = c.get_stream(&stream_id).await.unwrap();
    assert!(!s.disabled);
    assert_eq!(s.title, format!("grow-sdk rust {run}"));
    assert_eq!(s.rules.len(), 1);
    c.resume_stream(&stream_id).await.unwrap();

    // Three messages through GELF TCP.
    let t = c
        .gelf_transport(Some(GelfProtocol::Tcp), GelfTransportOptions::default())
        .unwrap();
    let base = SystemTime::now() - Duration::from_secs(2);
    let msgs: Vec<GelfMessage> = (0..3)
        .map(|i| {
            GelfMessage::new(GelfMessageOptions {
                host: "rust-it".into(),
                short_message: format!("{run} search #{i}"),
                timestamp: Some(base + Duration::from_millis(10 * i)),
                level: Some(GelfLevel::Warning),
                fields: attrs! {"marker" => run.clone(), "seq" => i},
                ..GelfMessageOptions::default()
            })
            .unwrap()
        })
        .collect();
    let res = t.send(&msgs, GelfSendOptions::default()).await.unwrap();
    assert_eq!(res.sent, 3);
    t.close().await.unwrap();

    let query = format!("marker:{run}");
    let found = wait_messages(
        &c,
        &query,
        3,
        MessageSearchOptions {
            streams: vec![stream_id.clone()],
            sort: vec![SearchSort::asc("seq")],
            fields: vec![
                "message".into(),
                "seq".into(),
                "marker".into(),
                "timestamp".into(),
            ],
            ..MessageSearchOptions::default()
        },
    )
    .await;
    assert_eq!(found.total, 3);
    assert_eq!(found.messages[0].fields["seq"], json!(0));
    assert_eq!(found.messages[2].fields["seq"], json!(2));
    assert!(!found.messages[0].fields.contains_key("level"));
    let paged = c
        .search(
            &query,
            MessageSearchOptions {
                start: Some(SystemTime::now() - Duration::from_secs(600)),
                end: Some(SystemTime::now() + Duration::from_secs(60)),
                limit: Some(1),
                offset: 1,
                sort: vec![SearchSort::desc("seq")],
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(paged.messages.len(), 1);
    assert_eq!(paged.messages[0].fields["seq"], json!(1));
    assert_eq!(paged.next_offset, Some(2));
    let rel = c
        .search_relative(
            &query,
            Duration::from_secs(600),
            MessageSearchOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(rel.total, 3);
    let kw = c
        .search(
            &query,
            MessageSearchOptions {
                keyword: Some("last 1 hour".into()),
                ..MessageSearchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(kw.total, 3);
    let hit = &rel.messages[0];
    let m = c.get_message(&hit.index, &hit.id).await.unwrap();
    assert_eq!(m.id, hit.id);
    assert_eq!(m.fields["marker"], json!(run));
    let rec = m.record();
    assert_eq!(rec.severity, Severity::Warn);
    assert_eq!(rec.resource["host.name"], json!("rust-it"));
    assert!(rec.body.starts_with(&run));
    assert_eq!(
        c.get_message(&hit.index, "00000000-0000-0000-0000-000000000000")
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        c.search("marker:((", MessageSearchOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    c.delete_stream(&stream_id).await.unwrap();
    assert_eq!(
        c.get_stream(&stream_id).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    c.close().await;
}

/// Records through every GELF transport with the shared attribute mapping, read back as
/// LogRecords.
#[tokio::test]
async fn gelf_log_clients() {
    let Some(c) = client() else { return };
    for p in [GelfProtocol::Tcp, GelfProtocol::Http, GelfProtocol::Udp] {
        let run = run_id();
        let lc = c
            .new_log_client(LogOptions {
                protocol: Some(p),
                ..LogOptions::default()
                    .resource_attribute("service.name", "rust-it")
                    .resource_attribute("deployment.environment", "test")
                    .resource_attribute("host.name", "rust-host")
            })
            .unwrap();
        let send = || {
            let mut r = LogRecord::new(Severity::Error, format!("{run} via {p}"));
            r.attributes = attrs! {
                "marker" => run.clone(), "flag" => true, "count" => 42, "ratio" => 1.5, "id" => "attr-id",
                "nested" => json!({"a": 1}), "list" => json!([1, "two"]), "password" => "hunter2",
            };
            r.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".into());
            r.span_id = Some("00f067aa0ba902b7".into());
            lc.send(r.into());
        };
        send();
        lc.flush(None).await.unwrap();
        let q = c.log_query(LogQueryOptions::default());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let rec = loop {
            let page = q
                .search(&format!("marker:{run}"), SearchOptions::default())
                .await
                .unwrap();
            if let Some(r) = page.records.into_iter().next() {
                break r;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{p}: record not found"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
            if p == GelfProtocol::Udp {
                send(); // UDP is best-effort: retry the send
                lc.flush(None).await.unwrap();
            }
        };
        assert_eq!(rec.severity, Severity::Error, "{p}");
        assert_eq!(
            rec.trace_id.as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(rec.span_id.as_deref(), Some("00f067aa0ba902b7"));
        let a = &rec.attributes;
        assert_eq!(a["flag"], json!("true"), "{p} {a:?}");
        assert_eq!(a["count"], json!(42));
        assert_eq!(a["ratio"], json!(1.5));
        assert_eq!(a["id"], json!("attr-id"));
        assert_eq!(a["nested"], json!(r#"{"a":1}"#));
        assert_eq!(a["list"], json!(r#"[1,"two"]"#));
        assert_eq!(a["password"], json!("[REDACTED]"));
        assert_eq!(rec.resource["host.name"], json!("rust-host"));
        assert_eq!(
            rec.resource["service.name"],
            json!("rust-it"),
            "{p} {:?}",
            rec.resource
        );
        assert_eq!(rec.resource["deployment.environment"], json!("test"));
        let s = lc.stats();
        assert_eq!((s.dropped, s.failed), (0, 0), "{p}");
        lc.close().await.unwrap();
    }
    c.close().await;
}

#[tokio::test]
async fn log_query_and_tail() {
    let Some(c) = client() else { return };
    let q = c.log_query(LogQueryOptions::default());
    assert!(q
        .list_streams()
        .await
        .unwrap()
        .contains(&"Default Stream".to_owned()));
    assert!(q
        .list_labels()
        .await
        .unwrap()
        .contains(&"source".to_owned()));
    let run = run_id();
    let got = Arc::new(Mutex::new(Vec::<LogRecord>::new()));
    let g = got.clone();
    let handle = q
        .tail(
            &format!("marker:{run}"),
            Arc::new(move |r| g.lock().unwrap().push(r)),
            TailOptions {
                interval: Duration::from_millis(500),
                start: Some(SystemTime::now() - Duration::from_secs(60)),
            },
        )
        .await
        .unwrap();
    let lc = c.new_log_client(LogOptions::default()).unwrap();
    lc.logger(Some("tail"), attrs! {"marker" => run.clone()})
        .warn(format!("{run} tail one"), attrs! {});
    lc.flush(None).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while got.lock().unwrap().is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "tail: no record");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let r = got.lock().unwrap()[0].clone();
    assert_eq!(r.body, format!("{run} tail one"));
    // Graylog stores field names with "." replaced by "_": logger.name reads back as logger_name.
    assert_eq!(r.attributes["logger_name"], AttrValue::from("tail"));
    let found = q
        .wait_for_log(
            &format!("marker:{run}"),
            WaitOptions::default().timeout(Duration::from_secs(30)),
        )
        .await
        .unwrap();
    assert_eq!(found.severity, Severity::Warn);
    handle.stop();
    c.close().await;
}

#[tokio::test]
async fn otlp_log_client() {
    let Some(c) = client() else { return };
    if std::env::var_os("GRAYLOG_OTLP_GRPC_ENDPOINT").is_none() {
        eprintln!("the OpenTelemetry (gRPC) input is not installed");
        return;
    }
    let run = run_id();
    let lc = c
        .new_log_client(LogOptions {
            protocol: Some(GelfProtocol::Otlp),
            ..LogOptions::default().resource_attribute("service.name", "rust-otlp")
        })
        .unwrap();
    let mut r = LogRecord::new(Severity::Warn, format!("{run} via otlp"));
    r.attributes = attrs! {"marker" => run.clone()};
    r.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".into());
    r.span_id = Some("00f067aa0ba902b7".into());
    lc.send(r.into());
    lc.flush(None).await.unwrap();
    let s = lc.stats();
    assert_eq!((s.sent, s.failed), (1, 0), "{s:?}");
    let rec = c
        .log_query(LogQueryOptions::default())
        .wait_for_log(
            &format!("otel_attributes_marker:{run}"),
            WaitOptions::default().timeout(Duration::from_secs(60)),
        )
        .await
        .unwrap();
    assert_eq!(rec.severity, Severity::Warn);
    assert_eq!(
        rec.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(rec.resource["service.name"], json!("rust-otlp"));
    assert_eq!(rec.attributes["marker"], json!(run));
    c.close().await;
}

/// The transport constructors and the message builder, used directly.
#[tokio::test]
async fn direct_transports() {
    let Some(c) = client() else { return };
    let host = c.config().gelf_host().to_owned();
    let run = run_id();
    let udp = GelfUdpTransport::new(GelfUdpOptions {
        compression: sdk::GelfCompression::Zlib,
        ..GelfUdpOptions::new(&host)
    })
    .unwrap();
    let tcp = GelfTcpTransport::new(GelfTcpOptions::new(&host)).unwrap();
    let http = GelfHttpTransport::new(GelfHttpOptions {
        bulk: false,
        ..GelfHttpOptions::new(c.config().gelf_http_endpoint())
    })
    .unwrap();
    let transports: Vec<Box<dyn GelfTransport>> =
        vec![Box::new(tcp), Box::new(http), Box::new(udp)];
    for t in &transports {
        let p = t.protocol();
        let m = GelfMessage::new(GelfMessageOptions {
            host: "direct".into(),
            short_message: format!("{run} direct {p}"),
            full_message: Some("line1\nline2".into()),
            ..GelfMessageOptions::default()
        })
        .unwrap()
        .with_field("marker", run.clone())
        .unwrap()
        .with_field("transport", p.as_str())
        .unwrap();
        let query = format!("marker:{run} AND transport:{p}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let res = t
                .send(std::slice::from_ref(&m), GelfSendOptions::default())
                .await
                .unwrap();
            assert_eq!(res.sent, 1, "{p}");
            let found = c
                .search_relative(
                    &query,
                    Duration::from_secs(900),
                    MessageSearchOptions::default(),
                )
                .await
                .unwrap();
            if let Some(hit) = found.messages.first() {
                assert_eq!(hit.fields["full_message"], json!("line1\nline2"), "{p}");
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{p}: message not found"
            );
            // TCP/HTTP resend only after a 2 s grace; duplicates are fine.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        t.close().await.unwrap();
    }
    c.close().await;
}

#[test]
fn blocking_round_trip() {
    load_bootstrap_env();
    if std::env::var_os("GROW_GRAYLOG_URL").is_none() {
        return;
    }
    let c = BlockingClient::from_env().expect("client");
    assert!(c.health().expect("health").healthy);
    c.ping().expect("ping");
    assert!(c.server_version().unwrap().starts_with("7."));
    let run = run_id();
    let lc = c.new_log_client(LogOptions::default()).unwrap();
    lc.send(
        LogRecord::new(Severity::Info, format!("{run} blocking"))
            .with_attribute("marker", run.clone())
            .into(),
    );
    c.block_on(lc.flush(None)).unwrap();
    let rec = c
        .log_query(LogQueryOptions::default())
        .wait_for_log(
            &format!("marker:{run}"),
            WaitOptions::default().timeout(Duration::from_secs(60)),
        )
        .unwrap();
    assert_eq!(rec.body, format!("{run} blocking"));
    c.close();
}
