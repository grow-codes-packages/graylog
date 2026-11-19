package codes.grow.packages.graylog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.graylog.core.AuthenticationException;
import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.CertsBridge;
import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.ConflictException;
import codes.grow.packages.graylog.core.ErrorCode;
import codes.grow.packages.graylog.core.GraylogException;
import codes.grow.packages.graylog.core.NotFoundException;
import codes.grow.packages.graylog.core.PermissionDeniedException;
import codes.grow.packages.graylog.core.RateLimitException;
import codes.grow.packages.graylog.core.Secret;
import codes.grow.packages.graylog.core.TimeoutException;
import codes.grow.packages.graylog.core.TlsOptions;
import codes.grow.packages.graylog.core.UnavailableException;
import codes.grow.packages.graylog.core.UnsupportedException;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.ExportOptions;
import codes.grow.packages.graylog.logging.ExportResult;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.Severity;
import java.io.ByteArrayInputStream;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;
import okhttp3.Protocol;
import okio.Buffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OtlpTest {
  private static final ExportOptions PLAIN = new ExportOptions(false, Duration.ofSeconds(5));

  private MockWebServer server;

  @BeforeEach
  void start() throws Exception {
    server = new MockWebServer();
    server.setProtocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE));
    server.start();
  }

  @AfterEach
  void stop() {
    server.close();
  }

  private String endpoint() {
    return "http://127.0.0.1:" + server.getPort();
  }

  private static LogRecord record(String body) {
    Map<String, Object> attrs = new LinkedHashMap<>();
    attrs.put("s", "v");
    attrs.put("b", true);
    attrs.put("n", 42);
    attrs.put("d", 1.5);
    attrs.put("l", List.of("x", 1));
    attrs.put("m", Map.of("k", "v"));
    return LogRecord.builder()
        .timestamp(Instant.ofEpochSecond(1795000000L, 123))
        .observedTimestamp(Instant.ofEpochSecond(1795000001L))
        .severity(Severity.WARN)
        .body(body)
        .attributes(attrs)
        .resource(Map.of("service.name", "svc"))
        .traceId("4bf92f3577b34da6a3ce929d0e0e4736")
        .spanId("00f067aa0ba902b7")
        .traceFlags(1)
        .build();
  }

  private static byte[] grpcFrame(byte[] message) {
    return ByteBuffer.allocate(5 + message.length)
        .put((byte) 0)
        .putInt(message.length)
        .put(message)
        .array();
  }

  private static byte[] partialSuccess(long rejected, String message) {
    Otlp.ProtoWriter inner = new Otlp.ProtoWriter().varint(1, rejected);
    if (message != null) {
      inner.string(2, message);
    }
    return new Otlp.ProtoWriter().bytes(1, inner.finish()).finish();
  }

  private static MockResponse ok(byte[] message) {
    return new MockResponse.Builder()
        .code(200)
        .addHeader("content-type", "application/grpc")
        .body(new Buffer().write(grpcFrame(message)))
        .trailers(Headers.of("grpc-status", "0"))
        .build();
  }

  /** Collects the fields of a message as (field, wire) to value. */
  private static List<Object[]> fields(byte[] buf) {
    List<Object[]> out = new ArrayList<>();
    Otlp.ProtoReader r = new Otlp.ProtoReader(buf);
    while (r.next()) {
      out.add(new Object[] {r.field, r.wire, r.wire == 2 ? r.bytes : (Object) r.varint});
    }
    return out;
  }

  private static byte[] field(byte[] buf, int field) {
    for (Object[] f : fields(buf)) {
      if ((int) f[0] == field) {
        return (byte[]) f[2];
      }
    }
    throw new AssertionError("no field " + field);
  }

  @Test
  void encodesRequest() {
    LogRecord other =
        LogRecord.builder().body("epoch").resource(Map.of("service.name", "other")).build();
    byte[] req = Otlp.encodeExportLogsRequest(List.of(record("a"), record("b"), other));
    List<Object[]> top = fields(req);
    assertThat(top).hasSize(2); // two distinct resources
    byte[] rl = (byte[]) top.get(0)[2];
    byte[] resource = field(rl, 1);
    byte[] kv = field(resource, 1);
    assertThat(new String(field(kv, 1), StandardCharsets.UTF_8)).isEqualTo("service.name");
    byte[] scopeLogs = field(rl, 2);
    List<Object[]> sl = fields(scopeLogs);
    assertThat(sl).hasSize(3); // scope + 2 records
    byte[] scope = (byte[]) sl.get(0)[2];
    assertThat(new String(field(scope, 1), StandardCharsets.UTF_8)).isEqualTo(Otlp.SCOPE_NAME);
    byte[] lr = (byte[]) sl.get(1)[2];
    List<Object[]> lf = fields(lr);
    assertThat(lf.stream().map(f -> (int) f[0]).toList())
        .containsExactly(1, 2, 3, 5, 6, 6, 6, 6, 6, 6, 8, 9, 10, 11);
    assertThat((long) lf.get(1)[2]).isEqualTo(13L);
    assertThat(new String(field(lr, 3), StandardCharsets.UTF_8)).isEqualTo("WARN");
    assertThat(field(lr, 9)).hasSize(16);
    assertThat(field(lr, 10)).hasSize(8);

    // the record with an EPOCH timestamp omits time_unix_nano and observed_time_unix_nano
    byte[] rl2 = (byte[]) top.get(1)[2];
    byte[] lr2 = (byte[]) fields(field(rl2, 2)).get(1)[2];
    assertThat(fields(lr2).stream().map(f -> (int) f[0]).toList()).containsExactly(2, 3, 5);
    assertThat(Otlp.encodeExportLogsRequest(List.of())).isEmpty();
  }

  @Test
  void decodesPartialSuccess() {
    assertThat(Otlp.decodePartialSuccess(partialSuccess(3, "bad")))
        .isEqualTo(new Otlp.PartialSuccess(3, "bad"));
    assertThat(Otlp.decodePartialSuccess(new byte[0])).isEqualTo(new Otlp.PartialSuccess(0, ""));
    byte[] skipped =
        new Otlp.ProtoWriter()
            .fixed32(2, 7)
            .fixed64(3, 9)
            .varint(4, 1)
            .bytes(1, new Otlp.ProtoWriter().varint(1, 1).fixed32(3, 1).finish())
            .finish();
    assertThat(Otlp.decodePartialSuccess(skipped).rejectedLogRecords()).isEqualTo(1);
    assertThat(Otlp.decodePartialSuccess(new byte[] {0x0a, 0x05, 0x01}))
        .isEqualTo(new Otlp.PartialSuccess(0, ""));
    assertThat(Otlp.decodePartialSuccess(new byte[] {(byte) 0x80}))
        .isEqualTo(new Otlp.PartialSuccess(0, ""));
    assertThat(Otlp.decodePartialSuccess(new byte[] {0x0b}))
        .isEqualTo(new Otlp.PartialSuccess(0, ""));
    assertThat(Otlp.decodePartialSuccess(new byte[] {0x15, 0x01}))
        .isEqualTo(new Otlp.PartialSuccess(0, ""));
    byte[] longVarint = new byte[12];
    longVarint[0] = 0x08;
    for (int i = 1; i < 12; i++) {
      longVarint[i] = (byte) 0xFF;
    }
    assertThat(Otlp.decodePartialSuccess(longVarint)).isEqualTo(new Otlp.PartialSuccess(0, ""));
  }

  @Test
  void mapsGrpcStatus() {
    Map<Integer, Class<? extends GraylogException>> want = new LinkedHashMap<>();
    want.put(1, CancelledException.class);
    want.put(3, ValidationException.class);
    want.put(9, ValidationException.class);
    want.put(4, TimeoutException.class);
    want.put(5, NotFoundException.class);
    want.put(6, ConflictException.class);
    want.put(7, PermissionDeniedException.class);
    want.put(8, RateLimitException.class);
    want.put(12, UnsupportedException.class);
    want.put(16, AuthenticationException.class);
    want.put(10, UnavailableException.class);
    want.put(11, UnavailableException.class);
    want.put(14, UnavailableException.class);
    want.put(15, UnavailableException.class);
    want.forEach((code, type) -> assertThat(Otlp.errorForGrpcStatus(code, "m")).isInstanceOf(type));
    assertThat(Otlp.errorForGrpcStatus(14, "m").retryable()).isTrue();
    GraylogException unknown = Otlp.errorForGrpcStatus(2, "");
    assertThat(unknown.code()).isEqualTo(ErrorCode.UNAVAILABLE);
    assertThat(unknown.retryable()).isFalse();
    assertThat(unknown.getMessage()).isEqualTo("otlp.export: gRPC status 2 (gRPC 2)");
    assertThat(Otlp.errorForGrpcStatus(13, null).getMessage()).contains("gRPC status 13");
  }

  @Test
  void framing() throws Exception {
    byte[] msg = "hello".getBytes(StandardCharsets.UTF_8);
    byte[] plain = OtlpGrpcLogExporter.frame(msg, false);
    assertThat(plain[0]).isZero();
    assertThat(ByteBuffer.wrap(plain, 1, 4).order(ByteOrder.BIG_ENDIAN).getInt()).isEqualTo(5);
    assertThat(OtlpGrpcLogExporter.unframe(plain)).isEqualTo(msg);
    byte[] gz = OtlpGrpcLogExporter.frame(msg, true);
    assertThat(gz[0]).isEqualTo((byte) 1);
    try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz, 5, gz.length - 5))) {
      assertThat(in.readAllBytes()).isEqualTo(msg);
    }
    assertThat(OtlpGrpcLogExporter.unframe(gz)).isEqualTo(msg);
    assertThat(OtlpGrpcLogExporter.unframe(new byte[3])).isEmpty();
    assertThat(OtlpGrpcLogExporter.unframe(new byte[] {0, 0, 0, 0, 9, 1})).isEmpty();
    assertThat(OtlpGrpcLogExporter.unframe(new byte[] {0, (byte) 0xFF, 0, 0, 0})).isEmpty();
    assertThat(OtlpGrpcLogExporter.decodeMessage(null)).isEmpty();
    assertThat(OtlpGrpcLogExporter.decodeMessage("a%20b+c")).isEqualTo("a b+c");
    assertThat(OtlpGrpcLogExporter.decodeMessage("bad%zz")).isEqualTo("bad%zz");
  }

  @Test
  void exportsOverH2c() throws Exception {
    server.enqueue(ok(new byte[0]));
    OtlpGrpcLogExporter e =
        OtlpGrpcLogExporter.builder(endpoint() + "/ignored")
            .bearerToken(Secret.of("bearer-secret"))
            .header("X-Tenant", "tenant-1")
            .headers(null)
            .headers(Map.of("x-short", "a"))
            .tls(null)
            .timeout(null)
            .connectTimeout(null)
            .build();
    assertThat(e.endpoint()).isEqualTo(endpoint());
    assertThat(e.toString()).contains("127.0.0.1");
    ExportResult res = e.export(List.of(record("a"), record("b")), PLAIN).get(10, TimeUnit.SECONDS);
    assertThat(res).isEqualTo(ExportResult.success(2));
    RecordedRequest req = server.takeRequest(5, TimeUnit.SECONDS);
    assertThat(req.getUrl().encodedPath()).isEqualTo(Otlp.LOGS_EXPORT_PATH);
    assertThat(req.getHeaders().get("content-type")).isEqualTo("application/grpc");
    assertThat(req.getHeaders().get("te")).isEqualTo("trailers");
    assertThat(req.getHeaders().get("authorization")).isEqualTo("Bearer bearer-secret");
    assertThat(req.getHeaders().get("x-tenant")).isEqualTo("tenant-1");
    assertThat(req.getHeaders().get("grpc-encoding")).isNull();
    byte[] body = req.getBody().toByteArray();
    assertThat(body[0]).isZero();
    assertThat(fields(OtlpGrpcLogExporter.unframe(body))).hasSize(1);

    server.enqueue(ok(partialSuccess(1, "record rejected for bearer-secret")));
    ExportResult partial =
        e.export(List.of(record("a"), record("b")), new ExportOptions(true, Duration.ofSeconds(5)))
            .get();
    assertThat(partial.accepted()).isEqualTo(1);
    assertThat(partial.rejected()).isEqualTo(1);
    assertThat(partial.error().get())
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("1 records rejected")
        .hasMessageNotContaining("bearer-secret");
    RecordedRequest gz = server.takeRequest(5, TimeUnit.SECONDS);
    assertThat(gz.getHeaders().get("grpc-encoding")).isEqualTo("gzip");

    server.enqueue(ok(partialSuccess(99, null)));
    ExportResult all = e.export(List.of(record("a")), null).get();
    assertThat(all.rejected()).isEqualTo(1);
    assertThat(all.error().get().getMessage()).isEqualTo("otlp.export: 1 records rejected");

    assertThat(e.export(List.of(), PLAIN).get()).isEqualTo(ExportResult.success(0));
    e.shutdown().get();
    e.shutdown();
    assertThatThrownBy(() -> e.export(List.of(record("a")), PLAIN).join())
        .hasCauseInstanceOf(ConfigException.class);
  }

  private void expectFailure(MockResponse response, Class<? extends Throwable> type, String text)
      throws Exception {
    server.enqueue(response);
    OtlpGrpcLogExporter e = OtlpGrpcLogExporter.builder(endpoint()).build();
    try {
      assertThatThrownBy(() -> e.export(List.of(record("a")), PLAIN).get(10, TimeUnit.SECONDS))
          .isInstanceOf(ExecutionException.class)
          .cause()
          .isInstanceOf(type)
          .hasMessageContaining(text);
    } finally {
      e.shutdown();
    }
  }

  @Test
  void grpcAndHttpErrors() throws Exception {
    expectFailure(
        new MockResponse.Builder()
            .code(200)
            .addHeader("grpc-status", "16")
            .addHeader("grpc-message", "invalid%20token")
            .build(),
        AuthenticationException.class,
        "invalid token (gRPC 16)");
    expectFailure(
        new MockResponse.Builder()
            .code(200)
            .body(new Buffer())
            .trailers(Headers.of("grpc-status", "14", "grpc-message", "down"))
            .build(),
        UnavailableException.class,
        "down");
    expectFailure(
        new MockResponse.Builder().code(404).build(), UnavailableException.class, "HTTP 404");
    expectFailure(
        new MockResponse.Builder().code(200).build(),
        UnavailableException.class,
        "without grpc-status");
    expectFailure(
        new MockResponse.Builder().code(200).addHeader("grpc-status", "x").build(),
        UnavailableException.class,
        "invalid grpc-status");
  }

  @Test
  void timeoutCancelAndConnectionErrors() throws Exception {
    server.enqueue(ok(new byte[0]).newBuilder().headersDelay(2, TimeUnit.SECONDS).build());
    OtlpGrpcLogExporter slow =
        OtlpGrpcLogExporter.builder(endpoint()).timeout(Duration.ofMillis(200)).build();
    assertThatThrownBy(() -> slow.export(List.of(record("a")), PLAIN).get(10, TimeUnit.SECONDS))
        .cause()
        .isInstanceOf(TimeoutException.class);
    slow.shutdown();

    // A fresh server: the delayed stream above can make MockWebServer drop its connections.
    try (MockWebServer slowServer = new MockWebServer()) {
      slowServer.setProtocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE));
      slowServer.enqueue(ok(new byte[0]).newBuilder().headersDelay(5, TimeUnit.SECONDS).build());
      slowServer.start();
      OtlpGrpcLogExporter c =
          OtlpGrpcLogExporter.builder("http://127.0.0.1:" + slowServer.getPort()).build();
      CompletableFuture<ExportResult> f = c.export(List.of(record("a")), PLAIN);
      assertThat(slowServer.takeRequest(5, TimeUnit.SECONDS)).isNotNull();
      assertThat(f.isDone()).as("done before cancel: %s", f).isFalse();
      assertThat(f.cancel(true)).isTrue();
      assertThat(f.isCancelled()).isTrue();
      c.shutdown();
    }

    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    OtlpGrpcLogExporter refused = OtlpGrpcLogExporter.builder("http://127.0.0.1:" + port).build();
    assertThatThrownBy(() -> refused.export(List.of(record("a")), PLAIN).get(10, TimeUnit.SECONDS))
        .cause()
        .isInstanceOf(UnavailableException.class)
        .hasMessageContaining("otlp.export");
    refused.shutdown();

    assertThatThrownBy(() -> OtlpGrpcLogExporter.builder("grpc://x").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> OtlpGrpcLogExporter.builder(null).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> OtlpGrpcLogExporter.builder("http://a b").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> OtlpGrpcLogExporter.builder("http://h").timeout(Duration.ZERO).build())
        .hasMessageContaining("timeouts");
    assertThatThrownBy(
            () -> OtlpGrpcLogExporter.builder("http://h").timeout(Duration.ofSeconds(-1)).build())
        .hasMessageContaining("timeouts");
    assertThatThrownBy(
            () -> OtlpGrpcLogExporter.builder("http://h").connectTimeout(Duration.ZERO).build())
        .hasMessageContaining("timeouts");
    assertThatThrownBy(
            () ->
                OtlpGrpcLogExporter.builder("http://h")
                    .connectTimeout(Duration.ofSeconds(-1))
                    .build())
        .hasMessageContaining("timeouts");
  }

  @Test
  void exportsOverTls(@TempDir Path dir) throws Exception {
    CertsBridge.Server certs = CertsBridge.server(dir);
    try (MockWebServer tls = new MockWebServer()) {
      tls.useHttps(certs.server().getSocketFactory());
      tls.setProtocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1));
      tls.start();
      tls.enqueue(ok(new byte[0]));
      tls.enqueue(ok(new byte[0]));
      OtlpGrpcLogExporter e =
          OtlpGrpcLogExporter.builder("https://localhost:" + tls.getPort())
              .tls(TlsOptions.builder().caCertPem(certs.certPem()).build())
              .build();
      assertThat(e.export(List.of(record("a")), PLAIN).get(10, TimeUnit.SECONDS).accepted())
          .isEqualTo(1);
      e.shutdown();
      OtlpGrpcLogExporter insecure =
          OtlpGrpcLogExporter.builder("https://127.0.0.1:" + tls.getPort())
              .tls(TlsOptions.builder().insecureSkipVerify(true).build())
              .build();
      assertThat(insecure.export(List.of(record("a")), PLAIN).get(10, TimeUnit.SECONDS).accepted())
          .isEqualTo(1);
      insecure.shutdown();
      OtlpGrpcLogExporter platform =
          OtlpGrpcLogExporter.builder("https://localhost:" + tls.getPort()).build();
      assertThatThrownBy(
              () -> platform.export(List.of(record("a")), PLAIN).get(10, TimeUnit.SECONDS))
          .cause()
          .isInstanceOf(UnavailableException.class);
      platform.shutdown();
    }
    assertThat(OtlpGrpcLogExporter.platformTrustManager()).isNotNull();
  }
}
