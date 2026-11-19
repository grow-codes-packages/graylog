//! Log clients built by the GraylogClient: GELF over TCP, HTTP and UDP, custom transports and
//! exporters.

mod graylog_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use grow_graylog as sdk;
use sdk::core::{Error, ErrorCode};
use sdk::logging::{attrs, ExportOptions, LogClient, LogExporter, LogRecord, Severity};
use sdk::{
    FromLogRecordOptions, GelfLogExporter, GelfMessage, GelfProtocol, GelfSendOptions,
    GelfSendResult, GelfTransport, GelfTransportOptions, GraylogClient, GraylogConfig, LogOptions,
};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(gelf_port: u16, protocol: GelfProtocol) -> GraylogClient {
    GraylogClient::new(
        GraylogConfig::builder()
            .gelf_host("127.0.0.1")
            .gelf_port(gelf_port)
            .gelf_protocol(protocol)
            .build()
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn tcp_log_client_maps_records() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let c = client_for(port, GelfProtocol::Tcp);
    let lc = c
        .new_log_client(
            LogOptions::default()
                .resource_attribute("service.name", "svc")
                .resource_attribute("host.name", "web-1"),
        )
        .unwrap();
    lc.logger(Some("http"), attrs! {"marker" => "m1"})
        .warn("hello", attrs! {"password" => "hunter2", "flag" => true});
    lc.flush(None).await.unwrap();
    let (mut conn, _) = listener.accept().await.unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while !data.contains(&0) {
        let n = conn.read(&mut buf).await.unwrap();
        data.extend_from_slice(&buf[..n]);
    }
    let v: Value = serde_json::from_slice(&data[..data.len() - 1]).unwrap();
    assert_eq!(v["short_message"], "hello");
    assert_eq!(v["host"], "web-1");
    assert_eq!(v["level"], 4);
    assert_eq!(v["_service.name"], "svc");
    assert_eq!(v["_logger.name"], "http");
    assert_eq!(v["_marker"], "m1");
    assert_eq!(v["_flag"], "true");
    assert_eq!(v["_password"], "[REDACTED]");
    assert_eq!(lc.stats().sent, 1);
    c.close().await;
    c.close().await;
}

#[tokio::test]
async fn http_and_udp_log_clients() {
    let server = MockServer::start().await;
    Mock::given(path("/gelf"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    let c = GraylogClient::new(
        GraylogConfig::builder()
            .gelf_http_url(format!("{}/gelf", server.uri()))
            .build()
            .unwrap(),
    )
    .unwrap();
    let lc = c
        .new_log_client(LogOptions {
            protocol: Some(GelfProtocol::Http),
            host: Some("explicit-host".into()),
            transport_options: GelfTransportOptions {
                headers: vec![("x-input-auth".into(), "v".into())],
                ..GelfTransportOptions::default()
            },
            ..LogOptions::default()
        })
        .unwrap();
    lc.send(LogRecord::new(Severity::Info, "via http").into());
    lc.send("second".into());
    lc.flush(None).await.unwrap();
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "one bulk request");
    assert_eq!(reqs[0].headers["x-input-auth"], "v");
    assert_eq!(lc.stats().sent, 2);

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let c = client_for(port, GelfProtocol::Udp);
    let lc = c.new_log_client(LogOptions::default()).unwrap();
    lc.send("via udp".into());
    lc.flush(None).await.unwrap();
    let mut buf = vec![0u8; 4000];
    let n = sock.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..2], &[0x1f, 0x8b]);
    assert!(n > 10);
    c.close().await;
}

#[tokio::test]
async fn gelf_transport_factory() {
    let c = client_for(12201, GelfProtocol::Tcp);
    assert_eq!(
        c.gelf_transport(None, GelfTransportOptions::default())
            .unwrap()
            .protocol(),
        GelfProtocol::Tcp
    );
    for p in [GelfProtocol::Udp, GelfProtocol::Http] {
        let t = c
            .gelf_transport(Some(p), GelfTransportOptions::default())
            .unwrap();
        assert_eq!(t.protocol(), p);
        t.close().await.unwrap();
    }
    let err = c
        .gelf_transport(Some(GelfProtocol::Otlp), GelfTransportOptions::default())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    let bad_udp = GelfTransportOptions {
        chunk_size: 1,
        ..GelfTransportOptions::default()
    };
    assert_eq!(
        c.new_log_client(LogOptions {
            protocol: Some(GelfProtocol::Udp),
            transport_options: bad_udp,
            ..LogOptions::default()
        })
        .unwrap_err()
        .code(),
        ErrorCode::Config
    );
    let otlp_bad = GraylogClient::new(
        GraylogConfig::builder()
            .otlp_endpoint("http://h:1")
            .build()
            .unwrap(),
    )
    .unwrap();
    let mut o = LogOptions::default().protocol(GelfProtocol::Otlp);
    o.batch.max_batch_size = 0;
    assert!(otlp_bad.new_log_client(o).is_err());
}

/// Records every send and fails on demand.
#[derive(Debug, Default)]
struct FakeTransport {
    sent: Mutex<Vec<GelfMessage>>,
    gzip: Mutex<Vec<Option<bool>>>,
    fail: bool,
    closed: Mutex<bool>,
}

#[async_trait]
impl GelfTransport for FakeTransport {
    fn protocol(&self) -> GelfProtocol {
        GelfProtocol::Tcp
    }
    async fn send(
        &self,
        messages: &[GelfMessage],
        opts: GelfSendOptions,
    ) -> sdk::Result<GelfSendResult> {
        if self.fail {
            return Err(Error::validation("nope"));
        }
        self.gzip.lock().unwrap().push(opts.gzip);
        self.sent.lock().unwrap().extend_from_slice(messages);
        Ok(GelfSendResult {
            sent: messages.len(),
            ..GelfSendResult::default()
        })
    }
    async fn close(&self) -> sdk::Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

#[tokio::test]
async fn custom_transport_and_exporter() {
    let fake = Arc::new(FakeTransport::default());
    let c = client_for(1, GelfProtocol::Tcp);
    let lc = c
        .new_log_client(LogOptions {
            transport: Some(fake.clone()),
            batch: sdk::logging::BatchOptions {
                flush_interval: Duration::from_millis(10),
                ..sdk::logging::BatchOptions::default()
            },
            ..LogOptions::default()
        })
        .unwrap();
    lc.send("custom".into());
    lc.flush(None).await.unwrap();
    assert_eq!(fake.sent.lock().unwrap()[0].short_message(), "custom");
    c.close().await;
    assert!(*fake.closed.lock().unwrap());

    let exp = GelfLogExporter::new(
        fake.clone(),
        FromLogRecordOptions {
            host: Some("h".into()),
        },
    );
    assert_eq!(exp.transport().protocol(), GelfProtocol::Tcp);
    let r = exp
        .export(
            &[LogRecord::new(Severity::Info, "x")],
            ExportOptions::new(false),
        )
        .await
        .unwrap();
    assert_eq!(r.accepted, 1);
    assert_eq!(fake.gzip.lock().unwrap().last(), Some(&Some(false)));
    assert!(format!("{exp:?}").contains("GelfLogExporter"));

    let failing = Arc::new(FakeTransport {
        fail: true,
        ..FakeTransport::default()
    });
    let exp = GelfLogExporter::new(failing, FromLogRecordOptions::default());
    assert_eq!(
        exp.export(
            &[LogRecord::new(Severity::Info, "x")],
            ExportOptions::default()
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Validation
    );

    let c = client_for(1, GelfProtocol::Tcp);
    let lc2 = c
        .new_log_client_with_exporter(
            Arc::new(GelfLogExporter::new(
                fake.clone(),
                FromLogRecordOptions::default(),
            )),
            LogOptions::default(),
        )
        .unwrap();
    lc2.send("again".into());
    c.close().await;
    assert_eq!(
        fake.sent.lock().unwrap().last().unwrap().short_message(),
        "again"
    );
}
