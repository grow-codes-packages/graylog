//! GELF messages, the shared attribute mapping and UDP chunking.

use std::io::Read;
use std::time::{Duration, UNIX_EPOCH};

use grow_graylog as sdk;
use sdk::core::ErrorCode;
use sdk::logging::{attrs, LogRecord, Severity};
use sdk::{
    encode_gelf_udp, flatten_attributes, frame_gelf_tcp, gelf_field_key, gelf_field_value,
    gelf_level_to_severity, gelf_timestamp, severity_to_gelf_level, validate_gelf_field_key,
    FromLogRecordOptions, GelfCompression, GelfLevel, GelfMessage, GelfMessageOptions,
};
use serde_json::{json, Value};

#[test]
fn level_mapping() {
    assert_eq!(severity_to_gelf_level(Severity::Trace), GelfLevel::Debug);
    assert_eq!(severity_to_gelf_level(Severity::Debug), GelfLevel::Debug);
    assert_eq!(
        severity_to_gelf_level(Severity::Info),
        GelfLevel::Informational
    );
    assert_eq!(severity_to_gelf_level(Severity::Warn), GelfLevel::Warning);
    assert_eq!(severity_to_gelf_level(Severity::Error), GelfLevel::Error);
    assert_eq!(severity_to_gelf_level(Severity::Fatal), GelfLevel::Critical);
    let expect = [
        (-1, Severity::Fatal),
        (0, Severity::Fatal),
        (2, Severity::Fatal),
        (3, Severity::Error),
        (4, Severity::Warn),
        (5, Severity::Info),
        (6, Severity::Info),
        (7, Severity::Debug),
        (9, Severity::Debug),
    ];
    for (l, s) in expect {
        assert_eq!(gelf_level_to_severity(l), s, "{l}");
    }
    for n in 0..=7 {
        assert_eq!(GelfLevel::from_number(n).unwrap().number() as i64, n);
    }
    assert_eq!(
        GelfLevel::from_number(8).unwrap_err().code(),
        ErrorCode::Validation
    );
}

#[test]
fn field_keys_and_values() {
    assert_eq!(gelf_field_key("service.name"), "_service.name");
    assert_eq!(gelf_field_key("id"), "_attr_id");
    assert_eq!(gelf_field_key("a b/c-d_e"), "_a_b_c-d_e");
    assert_eq!(gelf_field_key("ünï"), "__n_");
    assert_eq!(gelf_field_value(&json!(null)), None);
    assert_eq!(gelf_field_value(&json!(true)), Some(json!("true")));
    assert_eq!(gelf_field_value(&json!(false)), Some(json!("false")));
    assert_eq!(gelf_field_value(&json!(42)), Some(json!(42)));
    assert_eq!(gelf_field_value(&json!(1.5)), Some(json!(1.5)));
    assert_eq!(gelf_field_value(&json!("s")), Some(json!("s")));
    assert_eq!(
        gelf_field_value(&json!({"b": "x", "a": 1})),
        Some(json!(r#"{"a":1,"b":"x"}"#))
    );
    assert_eq!(
        gelf_field_value(&json!([1, "two"])),
        Some(json!(r#"[1,"two"]"#))
    );
    assert_eq!(validate_gelf_field_key("marker").unwrap(), "_marker");
    assert_eq!(
        validate_gelf_field_key("_marker.x-y").unwrap(),
        "_marker.x-y"
    );
    for bad in ["", "_", "a b", "_id", "id", "ü"] {
        assert_eq!(
            validate_gelf_field_key(bad).unwrap_err().code(),
            ErrorCode::Validation,
            "{bad}"
        );
    }
    let t = UNIX_EPOCH + Duration::from_millis(1_795_000_000_123);
    assert_eq!(gelf_timestamp(t).to_string(), "1795000000.123");
    assert_eq!(
        gelf_timestamp(UNIX_EPOCH - Duration::from_millis(1500)).to_string(),
        "-1.5"
    );
    let flat = flatten_attributes(&attrs! {"a" => json!({"b": {"c": 1}, "d": [1]}), "e" => "x"});
    assert_eq!(flat["a.b.c"], json!(1));
    assert_eq!(flat["a.d"], json!([1]));
    assert_eq!(flat["e"], json!("x"));
}

#[test]
fn message_builder() {
    let t = UNIX_EPOCH + Duration::from_millis(1_795_000_000_123);
    let mut m = GelfMessage::new(GelfMessageOptions {
        host: "h".into(),
        short_message: "short".into(),
        full_message: Some("line1\nline2".into()),
        timestamp: Some(t),
        level: Some(GelfLevel::Warning),
        fields: attrs! {"marker" => "abc", "_n" => 1, "flag" => true},
    })
    .unwrap();
    m.set_field("gone", "x").unwrap();
    m.set_field("gone", Value::Null).unwrap();
    let v = m.to_value();
    assert_eq!(
        v,
        json!({"version": "1.1", "host": "h", "short_message": "short", "full_message": "line1\nline2",
            "timestamp": 1795000000.123, "level": 4, "_marker": "abc", "_n": 1, "_flag": "true"})
    );
    assert_eq!(m.host(), "h");
    assert_eq!(m.short_message(), "short");
    assert_eq!(m.full_message(), Some("line1\nline2"));
    assert_eq!(m.timestamp(), Some(t));
    assert_eq!(m.level(), Some(GelfLevel::Warning));
    assert_eq!(m.fields().len(), 3);
    assert_eq!(m.to_string(), v.to_string());
    assert_eq!(m.encode(), v.to_string().into_bytes());
    let simple = GelfMessage::simple("h", "s")
        .unwrap()
        .with_field("k", 1)
        .unwrap();
    assert_eq!(
        simple.to_value(),
        json!({"version": "1.1", "host": "h", "short_message": "s", "_k": 1})
    );
    assert!(GelfMessage::simple("h", "s")
        .unwrap()
        .with_field("id", 1)
        .is_err());
    for (host, msg) in [(" ", "m"), ("h", "  ")] {
        assert_eq!(
            GelfMessage::simple(host, msg).unwrap_err().code(),
            ErrorCode::Validation
        );
    }
    let bad = GelfMessage::new(GelfMessageOptions {
        host: "h".into(),
        short_message: "s".into(),
        fields: attrs! {"bad key" => 1},
        ..GelfMessageOptions::default()
    });
    assert!(bad.is_err());
}

#[test]
fn message_from_log_record_shared_mapping() {
    let mut r = LogRecord::new(Severity::Error, "boom");
    r.timestamp = UNIX_EPOCH + Duration::from_millis(1_795_000_000_500);
    r.resource = attrs! {"service.name" => "svc", "host.name" => "web-1", "deployment" => json!({"environment": "prod"})};
    r.attributes = attrs! {"id" => "a1", "flag" => false, "nested" => json!({"a": 1}), "nil" => Value::Null, "" => "x", "service.name" => "override"};
    r.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".into());
    r.span_id = Some("00f067aa0ba902b7".into());
    r.trace_flags = Some(1);
    let m = GelfMessage::from_log_record(&r, &FromLogRecordOptions::default());
    assert_eq!(
        m.to_value(),
        json!({"version": "1.1", "host": "web-1", "short_message": "boom", "timestamp": 1795000000.5, "level": 3,
            "_service.name": "override", "_deployment.environment": "prod", "_attr_id": "a1", "_flag": "false",
            "_nested": "{\"a\":1}", "_trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "_span_id": "00f067aa0ba902b7",
            "_trace_flags": 1})
    );
    let blank = LogRecord::new(Severity::Info, "  ");
    let m = GelfMessage::from_log_record(
        &blank,
        &FromLogRecordOptions {
            host: Some("fallback".into()),
        },
    );
    assert_eq!(m.short_message(), "-");
    assert_eq!(m.host(), "fallback");
    let m = GelfMessage::from_log_record(&blank, &FromLogRecordOptions::default());
    assert!(!m.host().is_empty());
}

fn gunzip(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(b)
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[test]
fn udp_encoding_and_chunking() {
    let small = encode_gelf_udp(b"{\"a\":1}", GelfCompression::None, 1420, None).unwrap();
    assert_eq!(small, vec![b"{\"a\":1}".to_vec()]);
    let gz = encode_gelf_udp(b"hello", GelfCompression::Gzip, 1420, None).unwrap();
    assert_eq!(&gz[0][..2], &[0x1f, 0x8b]);
    assert_eq!(gunzip(&gz[0]), b"hello");
    let z = encode_gelf_udp(b"hello", GelfCompression::Zlib, 1420, None).unwrap();
    assert_eq!(z[0][0], 0x78);
    // 1000 bytes uncompressed in 100-byte datagrams: 88 data bytes per chunk → 12 chunks.
    let payload = vec![b'x'; 1000];
    let chunks = encode_gelf_udp(
        &payload,
        GelfCompression::None,
        100,
        Some([1, 2, 3, 4, 5, 6, 7, 8]),
    )
    .unwrap();
    assert_eq!(chunks.len(), 12);
    for (i, c) in chunks.iter().enumerate() {
        assert_eq!(&c[..2], &sdk::GELF_CHUNK_MAGIC);
        assert_eq!(&c[2..10], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(c[10] as usize, i);
        assert_eq!(c[11], 12);
        assert!(c.len() <= 100);
    }
    let joined: Vec<u8> = chunks.iter().flat_map(|c| c[12..].to_vec()).collect();
    assert_eq!(joined, payload);
    // 128 chunks is the ceiling.
    let max = vec![b'y'; 128 * 52];
    assert_eq!(
        encode_gelf_udp(&max, GelfCompression::None, 64, None)
            .unwrap()
            .len(),
        128
    );
    let over = vec![b'y'; 128 * 52 + 1];
    let err = encode_gelf_udp(&over, GelfCompression::None, 64, None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("129 chunks"));
    assert_eq!(
        encode_gelf_udp(b"x", GelfCompression::None, 12, None)
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    let m = GelfMessage::simple("h", "a").unwrap();
    let framed = frame_gelf_tcp(&[m.clone(), m.clone()]);
    let enc = m.encode();
    assert_eq!(framed.len(), 2 * (enc.len() + 1));
    assert_eq!(framed[enc.len()], 0);
    assert_eq!(*framed.last().unwrap(), 0);
}
