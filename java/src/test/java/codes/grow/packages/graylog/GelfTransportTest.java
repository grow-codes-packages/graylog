package codes.grow.packages.graylog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.CertsBridge;
import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.MockServer;
import codes.grow.packages.graylog.core.RetryPolicy;
import codes.grow.packages.graylog.core.TimeoutException;
import codes.grow.packages.graylog.core.TlsOptions;
import codes.grow.packages.graylog.core.UnavailableException;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.ExportOptions;
import codes.grow.packages.graylog.logging.ExportResult;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import javax.net.ssl.SSLServerSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("try") // transports are closed explicitly inside try-with-resources on purpose
class GelfTransportTest {
  private static GelfMessage msg(String text) {
    return GelfMessage.builder("h", text).field("marker", "m").build();
  }

  private static byte[] gunzip(byte[] b) throws Exception {
    try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(b))) {
      return in.readAllBytes();
    }
  }

  private static byte[] inflate(byte[] b) throws Exception {
    try (InputStream in = new InflaterInputStream(new ByteArrayInputStream(b))) {
      return in.readAllBytes();
    }
  }

  private static String randomText(int n) {
    byte[] b = new byte[n / 2];
    new SecureRandom().nextBytes(b);
    return HexFormat.of().formatHex(b);
  }

  // ---- UDP -------------------------------------------------------------------------------

  @Test
  void udpEncoding() throws Exception {
    byte[] payload = "{\"short_message\":\"x\"}".getBytes(StandardCharsets.UTF_8);
    byte[] gz = GelfUdpTransport.encode(payload, null, 0, null).get(0);
    assertThat(gz[0] & 0xFF).isEqualTo(0x1f);
    assertThat(gz[1] & 0xFF).isEqualTo(0x8b);
    assertThat(gunzip(gz)).isEqualTo(payload);
    byte[] z = GelfUdpTransport.encode(payload, GelfCompression.ZLIB, 1420, null).get(0);
    assertThat(z[0] & 0xFF).isEqualTo(0x78);
    assertThat(inflate(z)).isEqualTo(payload);
    assertThat(GelfUdpTransport.encode(payload, GelfCompression.NONE, 1420, null).get(0))
        .isEqualTo(payload);

    byte[] big = randomText(500).getBytes(StandardCharsets.UTF_8);
    byte[] id = {1, 2, 3, 4, 5, 6, 7, 8};
    List<byte[]> chunks = GelfUdpTransport.encode(big, GelfCompression.NONE, 112, id);
    assertThat(chunks).hasSize(5);
    ByteArrayOutputStream joined = new ByteArrayOutputStream();
    for (int i = 0; i < chunks.size(); i++) {
      byte[] c = chunks.get(i);
      assertThat(c.length).isLessThanOrEqualTo(112);
      assertThat(c[0]).isEqualTo((byte) 0x1e);
      assertThat(c[1]).isEqualTo((byte) 0x0f);
      assertThat(Arrays.copyOfRange(c, 2, 10)).isEqualTo(id);
      assertThat(c[10]).isEqualTo((byte) i);
      assertThat(c[11]).isEqualTo((byte) 5);
      joined.write(c, 12, c.length - 12);
    }
    assertThat(joined.toByteArray()).isEqualTo(big);
    List<byte[]> randomId = GelfUdpTransport.encode(big, GelfCompression.NONE, 112, null);
    assertThat(randomId).hasSize(5);

    byte[] tooBig = randomText(129 * 52 + 10).getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(() -> GelfUdpTransport.encode(tooBig, GelfCompression.NONE, 64, null))
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("max 128");
    assertThat(
            GelfUdpTransport.encode(
                randomText(128 * 52).getBytes(StandardCharsets.UTF_8),
                GelfCompression.NONE,
                64,
                null))
        .hasSize(128);
    assertThatThrownBy(() -> GelfUdpTransport.encode(payload, GelfCompression.NONE, 12, null))
        .hasMessageContaining("header");
  }

  @Test
  void udpSend() throws Exception {
    try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        GelfUdpTransport t =
            GelfUdpTransport.builder("127.0.0.1")
                .port(server.getLocalPort())
                .compression(null)
                .chunkSize(64)
                .build()) {
      server.setSoTimeout(5000);
      assertThat(t.protocol()).isEqualTo(GelfProtocol.UDP);
      assertThat(t.compression()).isEqualTo(GelfCompression.GZIP);
      assertThat(t.chunkSize()).isEqualTo(64);
      GelfMessage huge = GelfMessage.builder("h", "big").field("blob", randomText(20000)).build();
      GelfSendResult res = t.send(List.of(msg("one"), huge));
      assertThat(res.sent()).isEqualTo(1);
      assertThat(res.rejected()).isEqualTo(1);
      assertThat(res.error()).get().isInstanceOf(ValidationException.class);
      byte[] buf = new byte[70000];
      DatagramPacket p = new DatagramPacket(buf, buf.length);
      ByteArrayOutputStream joined = new ByteArrayOutputStream();
      server.receive(p);
      byte[] first = Arrays.copyOf(p.getData(), p.getLength());
      if (first[0] == 0x1e) {
        int count = first[11];
        joined.write(first, 12, first.length - 12);
        for (int i = 1; i < count; i++) {
          server.receive(p);
          joined.write(p.getData(), 12, p.getLength() - 12);
        }
      } else {
        joined.write(first);
      }
      JsonNode doc = Json.tree(gunzip(joined.toByteArray()));
      assertThat(doc.path("short_message").asText()).isEqualTo("one");
      assertThat(t.sendAsync(List.of(msg("two")), GelfSendOptions.defaults()).get().sent())
          .isEqualTo(1);
      assertThat(t.toString()).contains("127.0.0.1");
      t.close();
      t.close();
      assertThatThrownBy(() -> t.send(List.of(msg("x")))).isInstanceOf(ConfigException.class);
    }
  }

  @Test
  void udpErrors() {
    assertThatThrownBy(() -> GelfUdpTransport.builder(" ").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GelfUdpTransport.builder("h").port(0).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GelfUdpTransport.builder("h").chunkSize(10).build())
        .hasMessageContaining("chunkSize");
    assertThatThrownBy(() -> GelfUdpTransport.builder("h").chunkSize(70000).build())
        .hasMessageContaining("chunkSize");
    try (GelfUdpTransport t = GelfUdpTransport.builder("no-such-host.invalid").build()) {
      assertThatThrownBy(() -> t.send(List.of(msg("x")))).isInstanceOf(UnavailableException.class);
      assertThatThrownBy(() -> t.send(null)).isInstanceOf(ValidationException.class);
      List<GelfMessage> withNull = new ArrayList<>();
      withNull.add(null);
      assertThatThrownBy(() -> t.send(withNull)).isInstanceOf(ValidationException.class);
    }
  }

  // ---- TCP -------------------------------------------------------------------------------

  /** Accepts connections and collects NUL-terminated frames. */
  private static final class TcpSink implements AutoCloseable {
    final ServerSocket server;
    final List<String> frames = new CopyOnWriteArrayList<>();
    final List<Socket> sockets = new CopyOnWriteArrayList<>();
    final Thread thread;

    TcpSink(ServerSocket server) {
      this.server = server;
      this.thread =
          new Thread(
              () -> {
                while (!server.isClosed()) {
                  try {
                    Socket s = server.accept();
                    sockets.add(s);
                    Thread reader = new Thread(() -> read(s));
                    reader.setDaemon(true);
                    reader.start();
                  } catch (Exception e) {
                    return;
                  }
                }
              });
      thread.setDaemon(true);
      thread.start();
    }

    void read(Socket s) {
      try (InputStream in = s.getInputStream()) {
        ByteArrayOutputStream cur = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) >= 0) {
          if (b == 0) {
            frames.add(cur.toString(StandardCharsets.UTF_8));
            cur.reset();
          } else {
            cur.write(b);
          }
        }
      } catch (Exception ignored) {
        // closed
      }
    }

    void await(int n) throws InterruptedException {
      long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (frames.size() < n && System.nanoTime() < end) {
        Thread.sleep(10);
      }
      assertThat(frames).hasSizeGreaterThanOrEqualTo(n);
    }

    @Override
    public void close() throws java.io.IOException {
      server.close();
      for (Socket s : sockets) {
        s.close();
      }
    }
  }

  @Test
  void tcpSendsFramesAndReconnects() throws Exception {
    try (TcpSink sink = new TcpSink(new ServerSocket(0, 50, InetAddress.getLoopbackAddress()));
        GelfTcpTransport t =
            GelfTcpTransport.builder("127.0.0.1")
                .port(sink.server.getLocalPort())
                .connectTimeout(null)
                .writeTimeout(null)
                .retry(null)
                .tlsOptions(null)
                .build()) {
      assertThat(t.protocol()).isEqualTo(GelfProtocol.TCP);
      assertThat(t.secure()).isFalse();
      assertThat(t.send(List.of()).sent()).isZero();
      assertThat(t.send(List.of(msg("a"), msg("b"))).sent()).isEqualTo(2);
      sink.await(2);
      assertThat(
              Json.tree(sink.frames.get(0).getBytes(StandardCharsets.UTF_8))
                  .path("short_message")
                  .asText())
          .isEqualTo("a");
      t.send(List.of(msg("c")));
      sink.await(3);
      assertThat(t.connections()).isEqualTo(1);
      // the server drops the connection: the next batch reconnects
      for (Socket s : sink.sockets) {
        s.close();
      }
      Thread.sleep(50);
      t.send(List.of(msg("d")));
      sink.await(4);
      assertThat(t.connections()).isEqualTo(2);
      assertThat(t.toString()).contains("127.0.0.1");
      t.close();
      assertThatThrownBy(() -> t.send(List.of(msg("x")))).isInstanceOf(ConfigException.class);
    }
    assertThat(GelfTcpTransport.frame(List.of(msg("x")))).endsWith(0);
  }

  @Test
  void tcpRetriesAndFails() throws Exception {
    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    try (GelfTcpTransport t =
        GelfTcpTransport.builder("127.0.0.1")
            .port(port)
            .retry(RetryPolicy.builder().maxRetries(2).build())
            .build()) {
      List<Duration> sleeps = new ArrayList<>();
      t.sleeper = sleeps::add;
      assertThatThrownBy(() -> t.send(List.of(msg("x"))))
          .isInstanceOf(UnavailableException.class)
          .hasMessageContaining("gelf.tcp");
      assertThat(sleeps).hasSize(2);
      t.sleeper =
          d -> {
            throw new InterruptedException();
          };
      assertThatThrownBy(() -> t.send(List.of(msg("x")))).isInstanceOf(CancelledException.class);
      assertThat(Thread.interrupted()).isTrue();
      Thread.currentThread().interrupt();
      try {
        assertThatThrownBy(() -> t.send(List.of(msg("x")))).isInstanceOf(CancelledException.class);
      } finally {
        Thread.interrupted();
      }
    }
    assertThatThrownBy(() -> GelfTcpTransport.builder("").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GelfTcpTransport.builder("h").port(65536).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GelfTcpTransport.builder("h").connectTimeout(Duration.ZERO).build())
        .hasMessageContaining("timeouts");
    assertThatThrownBy(
            () -> GelfTcpTransport.builder("h").writeTimeout(Duration.ofSeconds(-1)).build())
        .hasMessageContaining("timeouts");
    assertThatThrownBy(
            () -> GelfTcpTransport.builder("h").connectTimeout(Duration.ofSeconds(-1)).build())
        .hasMessageContaining("timeouts");
    assertThatThrownBy(() -> GelfTcpTransport.builder("h").writeTimeout(Duration.ZERO).build())
        .hasMessageContaining("timeouts");
  }

  @Test
  void tcpWriteTimeout() throws Exception {
    try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        GelfTcpTransport t =
            GelfTcpTransport.builder("127.0.0.1")
                .port(server.getLocalPort())
                .writeTimeout(Duration.ofMillis(200))
                .retry(RetryPolicy.none())
                .build()) {
      // the server accepts but never reads: the socket buffers fill and the watchdog fires
      CompletableFuture.runAsync(
          () -> {
            try {
              server.accept();
            } catch (Exception ignored) {
              // closed
            }
          });
      List<GelfMessage> many = new ArrayList<>();
      String blob = randomText(1_000_000);
      for (int i = 0; i < 64; i++) {
        many.add(GelfMessage.builder("h", "m").field("blob", blob).build());
      }
      assertThatThrownBy(() -> t.send(many)).isInstanceOf(TimeoutException.class);
    }
  }

  @Test
  void tcpAliveCheck() throws Exception {
    try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Socket client = new Socket("127.0.0.1", server.getLocalPort());
        Socket peer = server.accept()) {
      assertThat(GelfTcpTransport.alive(client)).isTrue();
      peer.getOutputStream().write(1);
      peer.getOutputStream().flush();
      Thread.sleep(50);
      assertThat(GelfTcpTransport.alive(client)).isTrue();
      peer.close();
      Thread.sleep(50);
      assertThat(GelfTcpTransport.alive(client)).isFalse();
      client.close();
      assertThat(GelfTcpTransport.alive(client)).isFalse();
    }
  }

  @Test
  void tcpTls(@TempDir Path dir) throws Exception {
    CertsBridge.Server certs = CertsBridge.server(dir);
    SSLServerSocket server =
        (SSLServerSocket)
            certs
                .server()
                .getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
    try (TcpSink sink = new TcpSink(server)) {
      try (GelfTcpTransport t =
          GelfTcpTransport.builder("localhost")
              .port(server.getLocalPort())
              .tls(true)
              .tlsOptions(TlsOptions.builder().caCertPem(certs.certPem()).build())
              .build()) {
        assertThat(t.secure()).isTrue();
        assertThat(t.toString()).contains("tls");
        t.send(List.of(msg("secure")));
        sink.await(1);
      }
      try (GelfTcpTransport t =
          GelfTcpTransport.builder("127.0.0.1")
              .port(server.getLocalPort())
              .serverName("not-the-cert-name")
              .tls(true)
              .tlsOptions(TlsOptions.builder().insecureSkipVerify(true).build())
              .build()) {
        t.send(List.of(msg("insecure")));
        sink.await(2);
      }
      try (GelfTcpTransport t =
          GelfTcpTransport.builder("localhost")
              .port(server.getLocalPort())
              .tls(true)
              .retry(RetryPolicy.none())
              .build()) {
        // default trust store does not know the self-signed certificate
        assertThatThrownBy(() -> t.send(List.of(msg("untrusted"))))
            .isInstanceOf(UnavailableException.class);
      }
    }
  }

  // ---- HTTP ------------------------------------------------------------------------------

  @Test
  void httpBulkGzip() throws Exception {
    try (MockServer server = MockServer.start();
        GelfHttpTransport t =
            GelfHttpTransport.builder(server.url() + "/gelf")
                .header("X-Input-Auth", "secret-value")
                .headers(null)
                .build()) {
      server.enqueue(202, "");
      assertThat(t.protocol()).isEqualTo(GelfProtocol.HTTP);
      assertThat(t.send(List.of(msg("a"), msg("b"))).sent()).isEqualTo(2);
      MockServer.Recorded r = server.requests().get(0);
      assertThat(r.method()).isEqualTo("POST");
      assertThat(r.uri()).isEqualTo("/gelf");
      assertThat(r.header("Content-Encoding")).isEqualTo("gzip");
      assertThat(r.header("Content-Type")).isEqualTo("application/json");
      assertThat(r.header("X-Requested-By")).isEqualTo("grow-codes-graylog");
      assertThat(r.header("X-Input-Auth")).isEqualTo("secret-value");
      assertThat(t.toString()).contains("gzip=true", "bulk=true");
    }
    assertThat(
            new String(
                GelfHttpTransport.bodies(List.of(msg("a"), msg("b")), true).get(0),
                StandardCharsets.UTF_8))
        .matches("(?s)\\{.*\\}\\n\\{.*\\}\\n");
    assertThat(GelfHttpTransport.bodies(List.of(msg("a")), true).get(0)).endsWith('\n');
    assertThat(GelfHttpTransport.bodies(List.of(msg("a"), msg("b")), false)).hasSize(2);
    assertThat(GelfHttpTransport.bodies(List.of(), true)).isEmpty();
  }

  @Test
  void httpPlainPerMessage() throws Exception {
    try (MockServer server = MockServer.start();
        GelfHttpTransport t =
            GelfHttpTransport.builder(server.url())
                .bulk(false)
                .gzip(false)
                .header("Authorization", "Token abc")
                .config(GraylogConfig.builder().requestTimeout(Duration.ofSeconds(5)).build())
                .build()) {
      server.fallback(ex -> MockServer.send(ex, 202, ""));
      assertThat(t.send(List.of(msg("a"), msg("b")), null).sent()).isEqualTo(2);
      List<MockServer.Recorded> reqs = server.requests();
      assertThat(reqs).hasSize(2);
      assertThat(reqs.get(0).uri()).isEqualTo("/gelf");
      assertThat(reqs.get(0).header("Content-Encoding")).isNull();
      assertThat(reqs.get(0).body()).endsWith("\n");
      assertThat(
              Json.tree(reqs.get(1).body().getBytes(StandardCharsets.UTF_8))
                  .path("short_message")
                  .asText())
          .isEqualTo("b");
      // per-call gzip override
      t.send(List.of(msg("c")), GelfSendOptions.gzip(true));
      assertThat(server.requests().get(2).header("Content-Encoding")).isEqualTo("gzip");

      server.fallback(ex -> MockServer.send(ex, 400, "{\"message\":\"bad\"}"));
      assertThatThrownBy(() -> t.send(List.of(msg("d")))).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> t.send(null)).isInstanceOf(ValidationException.class);
      t.close();
      assertThatThrownBy(() -> t.send(List.of(msg("e")))).isInstanceOf(ConfigException.class);
    }
    assertThatThrownBy(() -> GelfHttpTransport.builder("udp://x").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GelfHttpTransport.builder(null).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GelfHttpTransport.builder("http://a b/").build())
        .isInstanceOf(ConfigException.class);
  }

  // ---- exporter --------------------------------------------------------------------------

  @Test
  void exporterConvertsAndCounts() throws Exception {
    try (MockServer server = MockServer.start()) {
      server.fallback(ex -> MockServer.send(ex, 202, ""));
      GelfLogExporter e =
          new GelfLogExporter(
              GelfHttpTransport.builder(server.url() + "/gelf").build(), "fallback-host");
      assertThat(e.transport()).isInstanceOf(GelfHttpTransport.class);
      LogRecord r =
          LogRecord.builder()
              .body("hello")
              .severity(Severity.WARN)
              .attributes(Map.of("k", "v"))
              .build();
      ExportResult res =
          e.export(List.of(r), new ExportOptions(false, Duration.ofSeconds(5))).get();
      assertThat(res.accepted()).isEqualTo(1);
      assertThat(res.rejected()).isZero();
      JsonNode doc =
          Json.tree(server.requests().get(0).body().trim().getBytes(StandardCharsets.UTF_8));
      assertThat(doc.path("host").asText()).isEqualTo("fallback-host");
      assertThat(doc.path("level").asInt()).isEqualTo(4);
      assertThat(doc.path("_k").asText()).isEqualTo("v");
      e.shutdown().get();
      assertThatThrownBy(
              () -> e.export(List.of(r), new ExportOptions(true, Duration.ofSeconds(1))).join())
          .hasCauseInstanceOf(ConfigException.class);
    }
    try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
      GelfLogExporter e =
          new GelfLogExporter(
              GelfUdpTransport.builder("127.0.0.1")
                  .port(server.getLocalPort())
                  .chunkSize(64)
                  .build(),
              null);
      LogRecord huge = LogRecord.builder().body("x").attribute("blob", randomText(20000)).build();
      ExportResult res =
          e.export(
                  List.of(huge, LogRecord.builder().body("ok").build()),
                  new ExportOptions(true, Duration.ofSeconds(1)))
              .get();
      assertThat(res.accepted()).isEqualTo(1);
      assertThat(res.rejected()).isEqualTo(1);
      assertThat(res.error()).isPresent();
      e.shutdown();
    }
  }
}
