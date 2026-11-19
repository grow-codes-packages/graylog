//! OTLP/gRPC exporter: protobuf encoding, gRPC status mapping, and exports against a local h2c
//! server.

mod graylog_support;

use std::convert::Infallible;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use grow_graylog as sdk;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::{HeaderMap, Request, Response};
use sdk::core::{ErrorCode, Secret, TlsConfig};
use sdk::logging::{attrs, ExportOptions, LogExporter, LogRecord, Severity};
use sdk::{
    decode_export_logs_response, encode_export_logs_request, error_for_grpc_status,
    OtlpGrpcLogExporter, OtlpGrpcLogExporterOptions, OTLP_LOGS_EXPORT_PATH,
};
use serde_json::json;
use tokio::net::TcpListener;

// ---- tiny protobuf reader for assertions ----------------------------------------------------

fn varint(b: &[u8], p: &mut usize) -> u64 {
    let mut v = 0u64;
    let mut s = 0;
    loop {
        let x = b[*p];
        *p += 1;
        v |= u64::from(x & 0x7f) << s;
        if x < 0x80 {
            return v;
        }
        s += 7;
    }
}

/// (field, wire, value bytes or varint)
fn parse(b: &[u8]) -> Vec<(u64, u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < b.len() {
        let tag = varint(b, &mut p);
        let (f, w) = (tag >> 3, tag & 7);
        let v = match w {
            0 => varint(b, &mut p).to_le_bytes().to_vec(),
            1 => {
                p += 8;
                b[p - 8..p].to_vec()
            }
            5 => {
                p += 4;
                b[p - 4..p].to_vec()
            }
            2 => {
                let n = varint(b, &mut p) as usize;
                p += n;
                b[p - n..p].to_vec()
            }
            _ => panic!("wire {w}"),
        };
        out.push((f, w, v));
    }
    out
}

fn field(b: &[u8], f: u64) -> Vec<Vec<u8>> {
    parse(b)
        .into_iter()
        .filter(|x| x.0 == f)
        .map(|x| x.2)
        .collect()
}

fn record() -> LogRecord {
    let mut r = LogRecord::new(Severity::Warn, "hello otlp");
    r.resource = attrs! {"service.name" => "svc"};
    r.attributes = attrs! {"s" => "x", "b" => true, "i" => -3, "f" => 1.5, "arr" => json!([1, null, "a"]),
    "obj" => json!({"k": "v", "n": null}), "nil" => serde_json::Value::Null, "big" => json!(u64::MAX)};
    r.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".into());
    r.span_id = Some("00f067aa0ba902b7".into());
    r.trace_flags = Some(1);
    r.observed_timestamp = Some(r.timestamp);
    r
}

#[test]
fn encodes_export_request() {
    let mut other = LogRecord::new(Severity::Info, "second");
    other.resource = attrs! {"service.name" => "other"};
    other.severity_text = "notice".into();
    other.trace_id = Some("not-hex".into());
    let req = encode_export_logs_request(&[record(), other, record()]);
    let rls = field(&req, 1);
    assert_eq!(rls.len(), 2, "one ResourceLogs per distinct resource");
    let resource = &field(&rls[0], 1)[0];
    let kv = &field(resource, 1)[0];
    assert_eq!(field(kv, 1)[0], b"service.name");
    let scope_logs = &field(&rls[0], 2)[0];
    let scope = &field(scope_logs, 1)[0];
    assert_eq!(field(scope, 1)[0], sdk::OTLP_SCOPE_NAME.as_bytes());
    let logs = field(scope_logs, 2);
    assert_eq!(logs.len(), 2);
    let lr = &logs[0];
    assert_eq!(
        u64::from_le_bytes(field(lr, 2)[0].clone().try_into().unwrap()),
        13
    );
    assert_eq!(field(lr, 3)[0], b"WARN");
    let body = &field(lr, 5)[0];
    assert_eq!(field(body, 1)[0], b"hello otlp");
    assert_eq!(field(lr, 6).len(), 7, "null attribute skipped");
    assert_eq!(field(lr, 9)[0].len(), 16);
    assert_eq!(field(lr, 10)[0].len(), 8);
    assert_eq!(field(lr, 8)[0], 1u32.to_le_bytes());
    assert_eq!(field(lr, 11).len(), 1);
    let other_lr = &field(&field(&rls[1], 2)[0], 2)[0];
    assert_eq!(field(other_lr, 3)[0], b"notice");
    assert!(field(other_lr, 9).is_empty());
    assert!(encode_export_logs_request(&[]).is_empty());
}

#[test]
fn decodes_response_and_maps_status() {
    assert_eq!(
        decode_export_logs_response(&[])
            .unwrap()
            .rejected_log_records,
        0
    );
    // partial_success { rejected_log_records: 2, error_message: "bad" }, plus an unknown field.
    let inner = [0x08, 0x02, 0x12, 0x03, b'b', b'a', b'd', 0x18, 0x01];
    let mut buf = vec![0x0a, inner.len() as u8];
    buf.extend_from_slice(&inner);
    buf.extend_from_slice(&[0x10, 0x05, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0x25, 0, 0, 0, 0]);
    let ps = decode_export_logs_response(&buf).unwrap();
    assert_eq!(ps.rejected_log_records, 2);
    assert_eq!(ps.error_message, "bad");
    for bad in [
        vec![0x0a, 0x05, 0x01],
        vec![0x0b],
        vec![0x80],
        vec![0x0a, 0x02, 0x08, 0x80],
    ] {
        assert_eq!(
            decode_export_logs_response(&bad).unwrap_err().code(),
            ErrorCode::Unavailable
        );
    }
    let cases = [
        (1, ErrorCode::Cancelled, false),
        (3, ErrorCode::Validation, false),
        (9, ErrorCode::Validation, false),
        (4, ErrorCode::Timeout, true),
        (5, ErrorCode::NotFound, false),
        (6, ErrorCode::Conflict, false),
        (7, ErrorCode::PermissionDenied, false),
        (8, ErrorCode::RateLimited, true),
        (12, ErrorCode::Unsupported, false),
        (16, ErrorCode::Authentication, false),
        (10, ErrorCode::Unavailable, true),
        (11, ErrorCode::Unavailable, true),
        (14, ErrorCode::Unavailable, true),
        (15, ErrorCode::Unavailable, true),
        (2, ErrorCode::Unavailable, false),
        (13, ErrorCode::Unavailable, false),
    ];
    for (code, want, retry) in cases {
        let e = error_for_grpc_status(code, "msg");
        assert_eq!(e.code(), want, "{code}");
        assert_eq!(e.is_retryable(), retry, "{code}");
        assert!(e.message().contains(&format!("(gRPC {code})")));
    }
    assert!(error_for_grpc_status(14, "")
        .message()
        .contains("gRPC status 14"));
}

// ---- h2c gRPC test server -------------------------------------------------------------------

#[derive(Clone, Default)]
struct Reply {
    http_status: u16,
    headers: Vec<(&'static str, String)>,
    data: Option<Vec<u8>>,
    trailers: Vec<(&'static str, String)>,
}

#[derive(Clone, Default)]
struct Seen {
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn grpc_server(reply: Reply, delay: Duration) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let reply = reply.clone();
            let s = s.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let reply = reply.clone();
                    let s = s.clone();
                    async move {
                        let path = req.uri().path().to_owned();
                        let headers = req.headers().clone();
                        let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                        s.lock().unwrap().push(Seen {
                            path,
                            headers,
                            body,
                        });
                        tokio::time::sleep(delay).await;
                        let mut frames: Vec<Result<Frame<Bytes>, Infallible>> = Vec::new();
                        if let Some(d) = reply.data {
                            frames.push(Ok(Frame::data(Bytes::from(d))));
                        }
                        if !reply.trailers.is_empty() {
                            let mut t = HeaderMap::new();
                            for (k, v) in &reply.trailers {
                                t.insert(*k, v.parse().unwrap());
                            }
                            frames.push(Ok(Frame::trailers(t)));
                        }
                        let mut resp = Response::builder()
                            .status(reply.http_status)
                            .header("content-type", "application/grpc");
                        for (k, v) in &reply.headers {
                            resp = resp.header(*k, v);
                        }
                        Ok::<_, Infallible>(
                            resp.body(StreamBody::new(futures::stream::iter(frames)))
                                .unwrap(),
                        )
                    }
                });
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(tcp), svc)
                        .await;
            });
        }
    });
    (format!("http://{addr}"), seen)
}

fn frame(msg: &[u8], compressed: bool) -> Vec<u8> {
    let mut f = vec![u8::from(compressed)];
    f.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    f.extend_from_slice(msg);
    f
}

fn ok_reply(data: Option<Vec<u8>>) -> Reply {
    Reply {
        http_status: 200,
        data,
        trailers: vec![("grpc-status", "0".into())],
        ..Reply::default()
    }
}

fn exporter(endpoint: &str) -> OtlpGrpcLogExporter {
    OtlpGrpcLogExporter::new(OtlpGrpcLogExporterOptions {
        bearer_token: Some(Secret::new("bearer-secret-1")),
        headers: vec![("X-Tenant".into(), "t1".into())],
        timeout: Duration::from_secs(5),
        ..OtlpGrpcLogExporterOptions::new(endpoint)
    })
    .unwrap()
}

#[tokio::test]
async fn export_success_gzip_and_plain() {
    let (url, seen) = grpc_server(ok_reply(Some(frame(&[], false))), Duration::ZERO).await;
    let e = exporter(&url);
    let recs = vec![record(), record()];
    let r = e.export(&recs, ExportOptions::new(true)).await.unwrap();
    assert_eq!(r.accepted, 2);
    assert_eq!(r.rejected, 0);
    let r = e
        .export(&[record()], ExportOptions::new(false))
        .await
        .unwrap();
    assert_eq!(r.accepted, 1);
    let empty = e.export(&[], ExportOptions::default()).await.unwrap();
    assert_eq!(empty.accepted, 0);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].path, OTLP_LOGS_EXPORT_PATH);
    assert_eq!(seen[0].headers["content-type"], "application/grpc");
    assert_eq!(seen[0].headers["te"], "trailers");
    assert_eq!(seen[0].headers["grpc-encoding"], "gzip");
    assert_eq!(seen[0].headers["authorization"], "Bearer bearer-secret-1");
    assert_eq!(seen[0].headers["x-tenant"], "t1");
    assert!(seen[0].headers["user-agent"]
        .to_str()
        .unwrap()
        .starts_with("grow-codes-graylog/"));
    assert_eq!(seen[0].body[0], 1);
    let mut msg = Vec::new();
    flate2::read::GzDecoder::new(&seen[0].body[5..])
        .read_to_end(&mut msg)
        .unwrap();
    assert_eq!(msg, encode_export_logs_request(&recs));
    assert_eq!(seen[1].body[0], 0);
    assert!(seen[1].headers.get("grpc-encoding").is_none());
    e.shutdown().await.unwrap();
    assert_eq!(
        e.export(&[record()], ExportOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    assert!(format!("{e:?}").contains("OtlpGrpcLogExporter"));
}

#[tokio::test]
async fn export_partial_success() {
    let inner = [0x08, 0x01, 0x12, 0x0f];
    let mut ps = inner.to_vec();
    ps.extend_from_slice(b"bearer-secret-1");
    let mut msg = vec![0x0a, ps.len() as u8];
    msg.extend_from_slice(&ps);
    let (url, _) = grpc_server(ok_reply(Some(frame(&msg, false))), Duration::ZERO).await;
    let r = exporter(&url)
        .export(&[record(), record()], ExportOptions::new(false))
        .await
        .unwrap();
    assert_eq!(r.accepted, 1);
    assert_eq!(r.rejected, 1);
    let err = r.error.unwrap();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("1 records rejected"));
    assert!(!err.message().contains("bearer-secret-1"), "{err}");

    // gzip-compressed response message, rejected count above the batch size is capped.
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&[0x0a, 0x02, 0x08, 0x09]).unwrap();
    let body = frame(&gz.finish().unwrap(), true);
    let (url, _) = grpc_server(ok_reply(Some(body)), Duration::ZERO).await;
    let r = exporter(&url)
        .export(&[record()], ExportOptions::new(false))
        .await
        .unwrap();
    assert_eq!(r.rejected, 1);
    assert_eq!(r.accepted, 0);
    assert!(r.error.unwrap().message().ends_with("rejected"));
}

#[tokio::test]
async fn export_errors() {
    // Status in trailers.
    let (url, _) = grpc_server(
        Reply {
            http_status: 200,
            data: Some(frame(&[], false)),
            trailers: vec![
                ("grpc-status", "16".into()),
                ("grpc-message", "bad%20token%20bearer-secret-1".into()),
            ],
            ..Reply::default()
        },
        Duration::ZERO,
    )
    .await;
    let err = exporter(&url)
        .export(&[record()], ExportOptions::new(false))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    assert!(err.message().contains("bad token"), "{err}");
    assert!(!err.message().contains("bearer-secret-1"));
    // Trailers-only (status in headers).
    let (url, _) = grpc_server(
        Reply {
            http_status: 200,
            headers: vec![
                ("grpc-status", "14".into()),
                ("grpc-message", "down".into()),
            ],
            ..Reply::default()
        },
        Duration::ZERO,
    )
    .await;
    let err = exporter(&url)
        .export(&[record()], ExportOptions::new(false))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.is_retryable());
    // Non-200 HTTP status.
    for (status, want) in [
        (404, ErrorCode::Unsupported),
        (503, ErrorCode::Unavailable),
        (401, ErrorCode::Authentication),
        (403, ErrorCode::PermissionDenied),
        (400, ErrorCode::Unavailable),
        (418, ErrorCode::Unavailable),
    ] {
        let (url, _) = grpc_server(
            Reply {
                http_status: status,
                ..Reply::default()
            },
            Duration::ZERO,
        )
        .await;
        let err = exporter(&url)
            .export(&[record()], ExportOptions::new(false))
            .await
            .unwrap_err();
        assert_eq!(err.code(), want, "{status}");
    }
    // Malformed response frame.
    let (url, _) = grpc_server(ok_reply(Some(vec![0, 0, 0, 0, 9, 1])), Duration::ZERO).await;
    let err = exporter(&url)
        .export(&[record()], ExportOptions::new(false))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    let (url, _) = grpc_server(ok_reply(Some(frame(b"not gzip", true))), Duration::ZERO).await;
    assert!(exporter(&url)
        .export(&[record()], ExportOptions::new(false))
        .await
        .is_err());
    // No body, no trailers: treated as success with nothing rejected.
    let (url, _) = grpc_server(
        Reply {
            http_status: 200,
            ..Reply::default()
        },
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        exporter(&url)
            .export(&[record()], ExportOptions::new(false))
            .await
            .unwrap()
            .accepted,
        1
    );
    // Deadline.
    let (url, _) = grpc_server(ok_reply(None), Duration::from_millis(500)).await;
    let slow = OtlpGrpcLogExporter::new(OtlpGrpcLogExporterOptions {
        timeout: Duration::from_millis(100),
        ..OtlpGrpcLogExporterOptions::new(url)
    })
    .unwrap();
    assert_eq!(
        slow.export(&[record()], ExportOptions::new(false))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Timeout
    );
    // Connection refused.
    let refused = exporter(&format!(
        "http://127.0.0.1:{}",
        graylog_support::closed_port()
    ));
    let err = refused
        .export(&[record()], ExportOptions::new(false))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
}

#[test]
fn exporter_config_validation() {
    for e in ["ftp://x:1", "nope", "http://"] {
        assert_eq!(
            OtlpGrpcLogExporter::new(OtlpGrpcLogExporterOptions::new(e))
                .unwrap_err()
                .code(),
            ErrorCode::Config,
            "{e}"
        );
    }
    let zero = OtlpGrpcLogExporterOptions {
        timeout: Duration::ZERO,
        ..OtlpGrpcLogExporterOptions::new("http://h:1")
    };
    assert!(OtlpGrpcLogExporter::new(zero).is_err());
    let fixtures = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let tls = |t: TlsConfig| {
        OtlpGrpcLogExporter::new(OtlpGrpcLogExporterOptions {
            tls: t,
            ..OtlpGrpcLogExporterOptions::new("https://h:4317")
        })
    };
    assert!(tls(TlsConfig {
        ca_cert_path: Some(format!("{fixtures}/gelf-ca.pem").into()),
        ca_cert_pem: Some(std::fs::read_to_string(format!("{fixtures}/gelf-ca.pem")).unwrap()),
        client_cert_path: Some(format!("{fixtures}/gelf-server.pem").into()),
        client_key_path: Some(format!("{fixtures}/gelf-server.key").into()),
        insecure_skip_verify: true,
    })
    .is_ok());
    assert!(tls(TlsConfig {
        ca_cert_path: Some("/nonexistent".into()),
        ..TlsConfig::default()
    })
    .is_err());
    assert!(tls(TlsConfig {
        ca_cert_pem: Some("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n".into()),
        ..TlsConfig::default()
    })
    .is_err());
    assert!(tls(TlsConfig {
        client_cert_path: Some(format!("{fixtures}/gelf-ca.pem").into()),
        client_key_path: Some("/nonexistent".into()),
        ..TlsConfig::default()
    })
    .is_err());
    assert!(tls(TlsConfig {
        client_cert_path: Some("/nonexistent".into()),
        client_key_path: Some("/nonexistent".into()),
        ..TlsConfig::default()
    })
    .is_err());
    assert!(tls(TlsConfig {
        client_cert_path: Some(format!("{fixtures}/gelf-ca.pem").into()),
        client_key_path: Some(format!("{fixtures}/gelf-ca.pem").into()),
        ..TlsConfig::default()
    })
    .is_err());
}

#[tokio::test]
async fn otlp_log_client_from_graylog_client() {
    let (url, seen) = grpc_server(ok_reply(Some(frame(&[], false))), Duration::ZERO).await;
    let c = sdk::GraylogClient::new(
        sdk::GraylogConfig::builder()
            .otlp_endpoint(url)
            .build()
            .unwrap(),
    )
    .unwrap();
    let lc = c
        .new_log_client(sdk::LogOptions {
            protocol: Some(sdk::GelfProtocol::Otlp),
            bearer_token: Some(Secret::new("otlp-token-1")),
            ..sdk::LogOptions::default().resource_attribute("service.name", "svc")
        })
        .unwrap();
    use sdk::logging::LogClient;
    lc.send(record().into());
    lc.flush(None).await.unwrap();
    assert_eq!(lc.stats().sent, 1);
    c.close().await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers["authorization"], "Bearer otlp-token-1");
}
