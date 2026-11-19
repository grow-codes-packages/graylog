//! GraylogConfig: environment precedence, platform aliases, GELF/OTLP endpoints, validation.

use grow_graylog as sdk;
use sdk::core::{EnvReader, ErrorCode};
use sdk::{GelfProtocol, GraylogConfig as Config};

fn env(pairs: &[(&str, &str)]) -> EnvReader {
    EnvReader::from_map(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
}

#[test]
fn defaults_and_endpoints() {
    let c = Config::builder().build().unwrap();
    assert_eq!(c.url().as_str(), "http://127.0.0.1:9000/");
    assert_eq!(c.gelf_host(), "127.0.0.1");
    assert_eq!(c.gelf_protocol(), GelfProtocol::Tcp);
    assert_eq!(c.gelf_port(), None);
    assert_eq!(c.gelf_port_for(GelfProtocol::Udp), 12201);
    assert_eq!(c.gelf_port_for(GelfProtocol::Tcp), 12201);
    assert_eq!(c.gelf_port_for(GelfProtocol::Http), 12202);
    assert_eq!(c.gelf_http_endpoint(), "http://127.0.0.1:12202/gelf");
    assert_eq!(c.otlp_grpc_endpoint(), "http://127.0.0.1:4317");
    assert_eq!(c.requested_by(), sdk::DEFAULT_REQUESTED_BY);
    assert!(!c.gelf_tls());
    assert!(c.api_token().is_none() && c.username().is_none() && c.password().is_none());
    assert!(c.gelf_http_url().is_none() && c.otlp_endpoint().is_none());

    let c = Config::builder()
        .url("https://graylog.example:9443")
        .gelf_port(5555)
        .gelf_tls(true)
        .build()
        .unwrap();
    assert_eq!(c.gelf_host(), "graylog.example");
    assert_eq!(c.gelf_port_for(GelfProtocol::Http), 5555);
    assert_eq!(c.gelf_http_endpoint(), "https://graylog.example:5555/gelf");

    let c = Config::builder().url("http://[::1]:9000").build().unwrap();
    assert_eq!(c.gelf_host(), "::1");
    assert_eq!(c.gelf_http_endpoint(), "http://[::1]:12202/gelf");
    assert_eq!(c.otlp_grpc_endpoint(), "http://[::1]:4317");

    let c = Config::builder()
        .gelf_host("logs")
        .gelf_http_url("http://h:1/x")
        .otlp_endpoint("https://o:4317")
        .requested_by("me")
        .gelf_protocol(GelfProtocol::Udp)
        .username("u")
        .password("p")
        .build()
        .unwrap();
    assert_eq!(c.gelf_http_endpoint(), "http://h:1/x");
    assert_eq!(c.otlp_grpc_endpoint(), "https://o:4317");
    assert_eq!(c.requested_by(), "me");
    assert_eq!(c.gelf_protocol(), GelfProtocol::Udp);
    assert_eq!(c.username(), Some("u"));
}

#[test]
fn env_precedence_and_aliases() {
    let e = env(&[
        ("GRAYLOG_URL", "http://vendor:9000"),
        ("GRAYLOG_API_TOKEN", "vendor-token"),
        ("GRAYLOG_USER", "admin"),
        ("GRAYLOG_PASSWORD", "pw"),
        ("GRAYLOG_HOST", "alias-host"),
        ("GRAYLOG_PORT", "1234"),
        ("GRAYLOG_TRANSPORT", "UDP"),
        ("GRAYLOG_GELF_HTTP_URL", "http://g:12202/gelf"),
        ("GRAYLOG_OTLP_GRPC_ENDPOINT", "http://o:4317"),
        ("GROW_GRAYLOG_GELF_TLS", "true"),
    ]);
    let c = Config::builder().build_with_env(&e).unwrap();
    assert_eq!(c.url().as_str(), "http://vendor:9000/");
    assert_eq!(c.api_token().unwrap().expose_secret(), "vendor-token");
    assert_eq!(c.username(), Some("admin"));
    assert_eq!(c.password().unwrap().expose_secret(), "pw");
    assert_eq!(c.gelf_host(), "alias-host");
    assert_eq!(c.gelf_port(), Some(1234));
    assert_eq!(c.gelf_protocol(), GelfProtocol::Udp);
    assert_eq!(c.gelf_http_url(), Some("http://g:12202/gelf"));
    assert_eq!(c.otlp_endpoint(), Some("http://o:4317"));
    assert!(c.gelf_tls());

    let e = env(&[
        ("GROW_GRAYLOG_GELF_HOST", "grow"),
        ("GRAYLOG_GELF_HOST", "vendor"),
        ("GRAYLOG_HOST", "alias"),
        ("GROW_GRAYLOG_GELF_PROTOCOL", "http"),
        ("GRAYLOG_GELF_PROTOCOL", "udp"),
        ("GRAYLOG_GELF_PORT", "12210"),
        ("GRAYLOG_PORT", "1"),
        ("GROW_GRAYLOG_OTLP_ENDPOINT", "http://grow-otlp:4317"),
    ]);
    let c = Config::builder().build_with_env(&e).unwrap();
    assert_eq!(c.gelf_host(), "grow");
    assert_eq!(c.gelf_protocol(), GelfProtocol::Http);
    assert_eq!(c.gelf_port(), Some(12210));
    assert_eq!(c.otlp_endpoint(), Some("http://grow-otlp:4317"));
    // explicit wins
    let c = Config::builder()
        .gelf_host("explicit")
        .gelf_protocol(GelfProtocol::Tcp)
        .gelf_port(7)
        .gelf_tls(false)
        .build_with_env(&e)
        .unwrap();
    assert_eq!(c.gelf_host(), "explicit");
    assert_eq!(c.gelf_protocol(), GelfProtocol::Tcp);
    assert_eq!(c.gelf_port(), Some(7));
}

#[test]
fn env_errors_name_the_variable() {
    for (k, v) in [
        ("GRAYLOG_TRANSPORT", "carrier-pigeon"),
        ("GRAYLOG_GELF_PROTOCOL", "otlp"),
        ("GROW_GRAYLOG_GELF_PORT", "70000"),
        ("GRAYLOG_PORT", "0"),
        ("GRAYLOG_GELF_PORT", "abc"),
        ("GROW_GRAYLOG_GELF_TLS", "maybe"),
    ] {
        let err = Config::builder()
            .build_with_env(&env(&[(k, v)]))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Config, "{k}");
        assert!(err.message().contains(k), "{k}: {err}");
        assert!(!err.message().contains(v) || v == "otlp", "{k}: {err}");
    }
}

#[test]
fn validation() {
    let cases: Vec<(&str, sdk::Result<Config>)> = vec![
        (
            "otlp",
            Config::builder().gelf_protocol(GelfProtocol::Otlp).build(),
        ),
        ("port", Config::builder().gelf_port(0).build()),
        ("host", Config::builder().gelf_host("  ").build()),
        (
            "http url",
            Config::builder().gelf_http_url("ftp://x").build(),
        ),
        (
            "otlp url",
            Config::builder().otlp_endpoint("not a url").build(),
        ),
        ("token", Config::builder().api_token("  ").build()),
        ("user only", Config::builder().username("u").build()),
        ("password only", Config::builder().password("p").build()),
        ("requested by", Config::builder().requested_by(" ").build()),
    ];
    for (name, r) in cases {
        assert_eq!(r.unwrap_err().code(), ErrorCode::Config, "{name}");
    }
}

#[test]
fn protocol_parsing_and_debug() {
    for (s, p) in [
        ("udp", GelfProtocol::Udp),
        (" TCP ", GelfProtocol::Tcp),
        ("Http", GelfProtocol::Http),
        ("otlp", GelfProtocol::Otlp),
    ] {
        let parsed: GelfProtocol = s.parse().unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.to_string(), p.as_str());
    }
    assert!(!GelfProtocol::Otlp.is_gelf());
    assert!(GelfProtocol::Udp.is_gelf());
    assert_eq!(
        "x".parse::<GelfProtocol>().unwrap_err().code(),
        ErrorCode::Validation
    );
    let c = Config::builder()
        .api_token("debug-token-1")
        .credentials("user", "debug-pass-1")
        .gelf_http_url("http://u:url-pass-1@h/gelf")
        .otlp_endpoint("http://u:otlp-pass-1@h:4317")
        .build()
        .unwrap();
    let b = Config::builder()
        .api_token("debug-token-2")
        .password("debug-pass-2");
    let text = format!("{c:?} {b:?}");
    for s in [
        "debug-token-1",
        "debug-pass-1",
        "url-pass-1",
        "otlp-pass-1",
        "debug-token-2",
        "debug-pass-2",
    ] {
        assert!(!text.contains(s), "{s} leaked: {text}");
    }
    assert!(text.contains("user"));
}
