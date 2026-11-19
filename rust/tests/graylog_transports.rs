//! GELF transports against local UDP, TCP (plain and TLS) and HTTP servers.

mod graylog_support;

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use graylog_support::{closed_port, fast_retry};
use grow_graylog as sdk;
use sdk::core::{ErrorCode, RetryPolicy, TlsConfig};
use sdk::{
    GelfCompression, GelfHttpOptions, GelfHttpTransport, GelfMessage, GelfProtocol,
    GelfSendOptions, GelfTcpOptions, GelfTcpTransport, GelfTransport, GelfUdpOptions,
    GelfUdpTransport,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn msg(text: &str) -> GelfMessage {
    GelfMessage::simple("test-host", text).unwrap()
}

fn gunzip(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(b)
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[tokio::test]
async fn udp_sends_datagrams() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let t = GelfUdpTransport::new(GelfUdpOptions {
        port,
        compression: GelfCompression::None,
        chunk_size: 64,
        ..GelfUdpOptions::new("127.0.0.1")
    })
    .unwrap();
    assert_eq!(t.protocol(), GelfProtocol::Udp);
    let big = "z".repeat(200);
    let too_big = "q".repeat(128 * 52 + 10);
    let res = t
        .send(
            &[msg("one"), msg(&big), msg(&too_big)],
            GelfSendOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(res.sent, 2);
    assert_eq!(res.rejected, 1);
    assert_eq!(res.error.unwrap().code(), ErrorCode::Validation);
    let mut buf = vec![0u8; 70000];
    let n = server.recv(&mut buf).await.unwrap();
    let v: Value = serde_json::from_slice(&buf[..n]).unwrap();
    assert_eq!(v["short_message"], "one");
    let n = server.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..2], &[0x1e, 0x0f]);
    assert!(n <= 64);
    t.close().await.unwrap();
    t.close().await.unwrap();
    assert_eq!(
        t.send(&[msg("x")], GelfSendOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    assert!(format!("{t:?}").contains("GelfUdpTransport"));
}

#[tokio::test]
async fn udp_gzip_default_and_config_errors() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let t = GelfUdpTransport::new(GelfUdpOptions {
        port,
        ..GelfUdpOptions::new("127.0.0.1")
    })
    .unwrap();
    t.send(&[msg("gz")], GelfSendOptions::default())
        .await
        .unwrap();
    let mut buf = vec![0u8; 2000];
    let n = server.recv(&mut buf).await.unwrap();
    let v: Value = serde_json::from_slice(&gunzip(&buf[..n])).unwrap();
    assert_eq!(v["short_message"], "gz");
    for o in [
        GelfUdpOptions::new(" "),
        GelfUdpOptions {
            port: 0,
            ..GelfUdpOptions::new("h")
        },
        GelfUdpOptions {
            chunk_size: 63,
            ..GelfUdpOptions::new("h")
        },
        GelfUdpOptions {
            chunk_size: 65508,
            ..GelfUdpOptions::new("h")
        },
    ] {
        assert_eq!(
            GelfUdpTransport::new(o).unwrap_err().code(),
            ErrorCode::Config
        );
    }
    // IPv6 literal host binds an IPv6 socket.
    let t6 = GelfUdpTransport::new(GelfUdpOptions::new("::1")).unwrap();
    let _ = t6.send(&[msg("v6")], GelfSendOptions::default()).await;
    // unresolvable host → UNAVAILABLE
    let bad = GelfUdpTransport::new(GelfUdpOptions::new("no-such-host.invalid")).unwrap();
    assert_eq!(
        bad.send(&[msg("x")], GelfSendOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );
}

/// Reads NUL-framed messages from one accepted connection.
async fn read_frames<S: tokio::io::AsyncRead + Unpin>(s: &mut S, want: usize) -> Vec<Value> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while data.iter().filter(|b| **b == 0).count() < want {
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed early");
        data.extend_from_slice(&buf[..n]);
    }
    data.split(|b| *b == 0)
        .filter(|f| !f.is_empty())
        .map(|f| serde_json::from_slice(f).unwrap())
        .collect()
}

#[tokio::test]
async fn tcp_frames_and_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = GelfTcpTransport::new(GelfTcpOptions {
        port,
        retry: fast_retry(),
        ..GelfTcpOptions::new("127.0.0.1")
    })
    .unwrap();
    assert_eq!(t.protocol(), GelfProtocol::Tcp);
    assert!(!t.secure());
    let empty = t.send(&[], GelfSendOptions::default()).await.unwrap();
    assert_eq!(empty.sent, 0);
    let res = t
        .send(&[msg("a"), msg("b")], GelfSendOptions::default())
        .await
        .unwrap();
    assert_eq!(res.sent, 2);
    let (mut conn, _) = listener.accept().await.unwrap();
    let frames = read_frames(&mut conn, 2).await;
    assert_eq!(frames[0]["short_message"], "a");
    assert_eq!(frames[1]["short_message"], "b");
    // Same connection for the next batch.
    t.send(&[msg("c")], GelfSendOptions::default())
        .await
        .unwrap();
    assert_eq!(read_frames(&mut conn, 1).await[0]["short_message"], "c");
    assert_eq!(t.connections(), 1);
    // Server closes the connection: the transport notices and reconnects.
    drop(conn);
    tokio::time::sleep(Duration::from_millis(50)).await;
    t.send(&[msg("d")], GelfSendOptions::default())
        .await
        .unwrap();
    let (mut conn2, _) = listener.accept().await.unwrap();
    assert_eq!(read_frames(&mut conn2, 1).await[0]["short_message"], "d");
    assert_eq!(t.connections(), 2);
    // Unexpected bytes from the server are ignored.
    conn2.write_all(b"x").await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    t.send(&[msg("e")], GelfSendOptions::default())
        .await
        .unwrap();
    assert_eq!(read_frames(&mut conn2, 1).await[0]["short_message"], "e");
    t.close().await.unwrap();
    t.close().await.unwrap();
    assert_eq!(
        t.send(&[msg("x")], GelfSendOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    assert!(format!("{t:?}").contains("connections"));
}

#[tokio::test]
async fn tcp_connect_failures_and_config() {
    let t = GelfTcpTransport::new(GelfTcpOptions {
        port: closed_port(),
        retry: RetryPolicy::none(),
        ..GelfTcpOptions::new("127.0.0.1")
    })
    .unwrap();
    let err = t
        .send(&[msg("x")], GelfSendOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.is_retryable());
    let t = GelfTcpTransport::new(GelfTcpOptions {
        port: closed_port(),
        retry: fast_retry().with_max_retries(2),
        ..GelfTcpOptions::new("127.0.0.1")
    })
    .unwrap();
    assert!(t
        .send(&[msg("x")], GelfSendOptions::default())
        .await
        .is_err());
    // Connect timeout (non-routable address).
    let t = GelfTcpTransport::new(GelfTcpOptions {
        connect_timeout: Duration::from_millis(50),
        retry: RetryPolicy::none(),
        ..GelfTcpOptions::new("10.255.255.1")
    })
    .unwrap();
    let err = t
        .send(&[msg("x")], GelfSendOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err.code(), ErrorCode::Timeout | ErrorCode::Unavailable),
        "{err}"
    );
    for o in [
        GelfTcpOptions::new(""),
        GelfTcpOptions {
            port: 0,
            ..GelfTcpOptions::new("h")
        },
        GelfTcpOptions {
            connect_timeout: Duration::ZERO,
            ..GelfTcpOptions::new("h")
        },
        GelfTcpOptions {
            write_timeout: Duration::ZERO,
            ..GelfTcpOptions::new("h")
        },
        GelfTcpOptions {
            tls: true,
            server_name: Some("bad name!".into()),
            ..GelfTcpOptions::new("h")
        },
        GelfTcpOptions {
            tls: true,
            tls_config: TlsConfig {
                ca_cert_path: Some("/nonexistent".into()),
                ..TlsConfig::default()
            },
            ..GelfTcpOptions::new("h")
        },
        GelfTcpOptions {
            tls: true,
            tls_config: TlsConfig {
                ca_cert_pem: Some("not pem".into()),
                ..TlsConfig::default()
            },
            ..GelfTcpOptions::new("h")
        },
        GelfTcpOptions {
            tls: true,
            tls_config: TlsConfig {
                client_cert_path: Some(fixture_path("gelf-server.pem").into()),
                client_key_path: Some(fixture_path("gelf-ca.pem").into()),
                ..TlsConfig::default()
            },
            ..GelfTcpOptions::new("h")
        },
        GelfTcpOptions {
            tls: true,
            tls_config: TlsConfig {
                client_cert_path: Some("/nonexistent".into()),
                client_key_path: Some("/nonexistent".into()),
                ..TlsConfig::default()
            },
            ..GelfTcpOptions::new("h")
        },
    ] {
        assert_eq!(
            GelfTcpTransport::new(o).unwrap_err().code(),
            ErrorCode::Config
        );
    }
    let mut bad_retry = GelfTcpOptions::new("h");
    bad_retry.retry.multiplier = 0.1;
    assert!(GelfTcpTransport::new(bad_retry).is_err());
}

fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(fixture_path("gelf-server.pem"))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_file(fixture_path("gelf-server.key")).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

#[tokio::test]
async fn tcp_tls_with_ca_and_insecure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tls_acceptor();
    let server = tokio::spawn(async move {
        let mut out = Vec::new();
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            out.extend(read_frames(&mut tls, 1).await);
        }
        out
    });
    let t = GelfTcpTransport::new(GelfTcpOptions {
        port,
        tls: true,
        tls_config: TlsConfig {
            ca_cert_path: Some(fixture_path("gelf-ca.pem").into()),
            ..TlsConfig::default()
        },
        server_name: Some("localhost".into()),
        ..GelfTcpOptions::new("127.0.0.1")
    })
    .unwrap();
    assert!(t.secure());
    t.send(&[msg("tls-ca")], GelfSendOptions::default())
        .await
        .unwrap();
    let pem = std::fs::read_to_string(fixture_path("gelf-ca.pem")).unwrap();
    let insecure = GelfTcpTransport::new(GelfTcpOptions {
        port,
        tls: true,
        tls_config: TlsConfig {
            insecure_skip_verify: true,
            ca_cert_pem: Some(pem),
            ..TlsConfig::default()
        },
        ..GelfTcpOptions::new("127.0.0.1")
    })
    .unwrap();
    insecure
        .send(&[msg("tls-insecure")], GelfSendOptions::default())
        .await
        .unwrap();
    let frames = server.await.unwrap();
    assert_eq!(frames[0]["short_message"], "tls-ca");
    assert_eq!(frames[1]["short_message"], "tls-insecure");
    t.close().await.unwrap();
    insecure.close().await.unwrap();

    // An untrusted certificate fails the handshake.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tls_acceptor();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });
    let untrusted = GelfTcpTransport::new(GelfTcpOptions {
        port,
        tls: true,
        retry: RetryPolicy::none(),
        ..GelfTcpOptions::new("127.0.0.1")
    })
    .unwrap();
    let err = untrusted
        .send(&[msg("x")], GelfSendOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
}

#[tokio::test]
async fn tcp_tls_client_certificate_loads() {
    // A valid client identity loads (the fixture server cert/key doubles as one).
    let t = GelfTcpTransport::new(GelfTcpOptions {
        tls: true,
        tls_config: TlsConfig {
            client_cert_path: Some(fixture_path("gelf-server.pem").into()),
            client_key_path: Some(fixture_path("gelf-server.key").into()),
            ..TlsConfig::default()
        },
        ..GelfTcpOptions::new("localhost")
    })
    .unwrap();
    assert!(t.secure());
}

#[tokio::test]
async fn http_bulk_single_and_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/gelf"))
        .and(header("content-type", "application/json"))
        .and(header("x-requested-by", "grow-codes-graylog"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/custom"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let t = GelfHttpTransport::new(GelfHttpOptions {
        headers: vec![
            ("authorization".into(), "input-secret-1".into()),
            ("x-extra".into(), "visible".into()),
        ],
        ..GelfHttpOptions::new(format!("{}/gelf", server.uri()))
    })
    .unwrap();
    assert_eq!(t.protocol(), GelfProtocol::Http);
    let res = t
        .send(&[msg("a"), msg("b")], GelfSendOptions::default())
        .await
        .unwrap();
    assert_eq!(res.sent, 2);
    assert_eq!(
        t.send(&[], GelfSendOptions::default()).await.unwrap().sent,
        0
    );
    let res = t
        .send(&[msg("plain")], GelfSendOptions { gzip: Some(false) })
        .await
        .unwrap();
    assert_eq!(res.sent, 1);
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].headers["content-encoding"], "gzip");
    assert_eq!(reqs[0].headers["authorization"], "input-secret-1");
    assert_eq!(reqs[0].headers["x-extra"], "visible");
    let body = String::from_utf8(gunzip(&reqs[0].body)).unwrap();
    let lines: Vec<&str> = body.split_terminator('\n').collect();
    assert_eq!(lines.len(), 2);
    assert!(body.ends_with('\n'));
    let single = String::from_utf8(reqs[1].body.clone()).unwrap();
    assert!(
        single.ends_with("}\n"),
        "every message ends with a newline: {single:?}"
    );
    assert!(reqs[1].headers.get("content-encoding").is_none());

    // One request per message without bulk; root path defaults to /gelf.
    let nb = GelfHttpTransport::new(GelfHttpOptions {
        bulk: false,
        gzip: false,
        ..GelfHttpOptions::new(server.uri())
    })
    .unwrap();
    nb.send(&[msg("x"), msg("y")], GelfSendOptions::default())
        .await
        .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 4);

    let bad = GelfHttpTransport::new(GelfHttpOptions::new(format!("{}/custom?a=1", server.uri())))
        .unwrap();
    let err = bad
        .send(&[msg("x")], GelfSendOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    t.close().await.unwrap();
    assert_eq!(
        t.send(&[msg("x")], GelfSendOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    for u in ["ftp://x/gelf", "not a url", "http://"] {
        assert_eq!(
            GelfHttpTransport::new(GelfHttpOptions::new(u))
                .unwrap_err()
                .code(),
            ErrorCode::Config,
            "{u}"
        );
    }
    assert!(format!("{nb:?}").contains("GelfHttpTransport"));
}
