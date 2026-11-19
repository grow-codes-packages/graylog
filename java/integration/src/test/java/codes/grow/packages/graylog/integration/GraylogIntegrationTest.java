package codes.grow.packages.graylog.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.graylog.CreateInputOptions;
import codes.grow.packages.graylog.CreateStreamOptions;
import codes.grow.packages.graylog.EnsureGelfInputOptions;
import codes.grow.packages.graylog.EnsuredInput;
import codes.grow.packages.graylog.GelfCompression;
import codes.grow.packages.graylog.GelfHttpTransport;
import codes.grow.packages.graylog.GelfLogExporter;
import codes.grow.packages.graylog.GelfMessage;
import codes.grow.packages.graylog.GelfProtocol;
import codes.grow.packages.graylog.GelfSendResult;
import codes.grow.packages.graylog.GelfTcpTransport;
import codes.grow.packages.graylog.GelfTransport;
import codes.grow.packages.graylog.GelfUdpTransport;
import codes.grow.packages.graylog.Gelf;
import codes.grow.packages.graylog.GraylogClient;
import codes.grow.packages.graylog.GraylogConfig;
import codes.grow.packages.graylog.GraylogInput;
import codes.grow.packages.graylog.GraylogLogClientOptions;
import codes.grow.packages.graylog.GraylogLogQueryClient;
import codes.grow.packages.graylog.GraylogMessage;
import codes.grow.packages.graylog.GraylogStream;
import codes.grow.packages.graylog.IndexSet;
import codes.grow.packages.graylog.InputState;
import codes.grow.packages.graylog.InputTypes;
import codes.grow.packages.graylog.ListStreamsOptions;
import codes.grow.packages.graylog.MessageSearchOptions;
import codes.grow.packages.graylog.MessageSearchResult;
import codes.grow.packages.graylog.OtlpGrpcLogExporter;
import codes.grow.packages.graylog.SearchSort;
import codes.grow.packages.graylog.StreamPage;
import codes.grow.packages.graylog.StreamRule;
import codes.grow.packages.graylog.SystemInfo;
import codes.grow.packages.graylog.core.AuthenticationException;
import codes.grow.packages.graylog.core.ConflictException;
import codes.grow.packages.graylog.core.EnvReader;
import codes.grow.packages.graylog.core.HealthStatus;
import codes.grow.packages.graylog.core.NotFoundException;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.BatchStats;
import codes.grow.packages.graylog.logging.BatchingLogClient;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.LogSearchResult;
import codes.grow.packages.graylog.logging.SearchOptions;
import codes.grow.packages.graylog.logging.Severity;
import codes.grow.packages.graylog.logging.TailHandle;
import codes.grow.packages.graylog.logging.TailOptions;
import codes.grow.packages.graylog.logging.WaitForLogOptions;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Calls every public function of the Java package against the real Graylog from {@code
 * docker/compose.yml} with a round-trip assertion (write, then read back).
 */
@SuppressWarnings("try")
class GraylogIntegrationTest {
  private static Map<String, String> env;

  @BeforeAll
  static void load() throws IOException {
    env = ConformanceTest.environment();
  }

  private static GraylogClient client() {
    String var = EnvReader.DEFAULT_PREFIX + "URL";
    assumeTrue(env.containsKey(var), var + " is not set; use docker/compose.yml");
    return GraylogClient.builder().fromEnv(EnvReader.of(env)).build();
  }

  private static String runId() {
    byte[] b = new byte[5];
    new SecureRandom().nextBytes(b);
    return "grj" + HexFormat.of().formatHex(b);
  }

  /** Polls search until at least {@code n} messages match (ingest takes 1–2 s). */
  private static MessageSearchResult waitMessages(
      GraylogClient c, String query, int n, MessageSearchOptions options) throws Exception {
    MessageSearchOptions o =
        options.range().isEmpty() && options.start().isEmpty() && options.keyword().isEmpty()
            ? options.toBuilder().range(Duration.ofMinutes(15)).build()
            : options;
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
    while (true) {
      try {
        MessageSearchResult r = c.search(query, o);
        if (r.messages().size() >= n) {
          return r;
        }
      } catch (ValidationException e) {
        // a sort on a field that is not mapped yet fails with "all shards failed": retry
      }
      if (System.nanoTime() > deadline) {
        throw new AssertionError("search " + query + ": fewer than " + n + " messages");
      }
      Thread.sleep(500);
    }
  }

  @Test
  void coreAndSystem() throws Exception {
    try (GraylogClient c = client()) {
      HealthStatus h = c.health();
      assertTrue(h.healthy());
      assertEquals("ok", h.status());
      assertEquals("ALIVE", h.details().get("lb_status"));
      assertTrue(c.healthAsync().get().healthy());
      assertTrue(c.ping().toNanos() > 0);
      assertTrue(c.pingAsync().get().toNanos() > 0);
      String version = c.serverVersion();
      assertTrue(version.startsWith("7."), version);
      assertEquals(version, c.serverVersionAsync().get());
      System.out.println("Graylog server version " + version);
      SystemInfo info = c.systemInfo();
      assertEquals(version, info.version());
      assertFalse(info.nodeId().isEmpty());
      assertTrue(info.isProcessing());
      assertEquals(version, c.systemInfoAsync().get().version());
      List<String> fields = c.listFields();
      assertTrue(fields.contains("message"));
      assertTrue(c.listFieldsAsync().get().contains("source"));

      GraylogConfig bad =
          c.config().toBuilder().apiToken("not-a-valid-token").basicAuth(null, (String) null).build();
      try (GraylogClient badClient = GraylogClient.create(bad)) {
        AuthenticationException e = assertThrows(AuthenticationException.class, badClient::ping);
        assertFalse(e.getMessage().contains("not-a-valid-token"));
      }
      GraylogConfig pw = c.config().toBuilder().apiToken((String) null).build();
      assumeTrue(pw.username().isPresent(), "bootstrap provides GRAYLOG_USER/PASSWORD");
      try (GraylogClient pwClient = GraylogClient.create(pw)) {
        assertTrue(pwClient.ping().toNanos() > 0);
      }
    }
  }

  @Test
  void inputs() throws Exception {
    try (GraylogClient c = client()) {
      List<GraylogInput> inputs = c.listInputs();
      String tcpId = env.get("GRAYLOG_INPUT_ID_GELF_TCP");
      assertTrue(inputs.stream().anyMatch(i -> i.id().equals(tcpId)), "bootstrap TCP input listed");
      assertFalse(c.listInputsAsync().get().isEmpty());
      Map<String, String> types = c.listInputTypes();
      assertNotNull(types.get(InputTypes.GELF_HTTP));
      assertFalse(c.listInputTypesAsync().get().isEmpty());
      GraylogInput tcp = c.getInput(tcpId);
      assertEquals(InputTypes.GELF_TCP, tcp.type());
      assertEquals(12201, tcp.port());
      assertEquals(tcpId, c.getInputAsync(tcpId).get().id());
      InputState st = c.getInputState(tcpId);
      assertEquals(InputTypes.STATE_RUNNING, st.state());
      assertEquals(tcpId, c.getInputStateAsync(tcpId).get().id());

      // an existing input is reused
      EnsuredInput existing = c.ensureGelfInput(GelfProtocol.TCP, 12201, null);
      assertFalse(existing.created());
      assertEquals(tcpId, existing.id());
      // a new input is created, RUNNING, then deleted
      EnsuredInput created =
          c.ensureGelfInputAsync(GelfProtocol.UDP, 12391, EnsureGelfInputOptions.defaults()).get();
      assertTrue(created.created());
      assertEquals(12391, created.input().port());
      c.deleteInput(created.id());
      assertThrows(NotFoundException.class, () -> c.getInput(created.id()));

      Map<String, Object> cfg = new LinkedHashMap<>();
      cfg.put("bind_address", "0.0.0.0");
      cfg.put("port", 12392);
      cfg.put("enable_bulk_receiving", true);
      cfg.put("max_chunk_size", 1048576);
      cfg.put("recv_buffer_size", 1048576);
      cfg.put("number_worker_threads", 1);
      String title = "grow-sdk java " + runId();
      String id = c.createInput(InputTypes.GELF_HTTP, cfg, CreateInputOptions.titled(title));
      GraylogInput got = c.getInput(id);
      assertEquals(12392, got.port());
      assertEquals(title, got.title());
      c.deleteInputAsync(id).get();
      assertThrows(NotFoundException.class, () -> c.deleteInput(id));
      String id2 =
          c.createInputAsync(InputTypes.GELF_UDP, Map.of("bind_address", "0.0.0.0", "port", 12393), null)
              .get();
      c.deleteInput(id2);
      assertThrows(
          NotFoundException.class,
          () -> c.createInput("org.example.NoSuchInput", Map.of(), CreateInputOptions.defaults()));

      // a busy port fails to start: CONFLICT, and the created input is removed again
      int before = c.listInputs().size();
      assertThrows(
          ConflictException.class,
          () ->
              c.ensureGelfInput(
                  GelfProtocol.HTTP,
                  12201,
                  EnsureGelfInputOptions.builder().timeout(Duration.ofSeconds(20)).build()));
      assertEquals(before, c.listInputs().size());
    }
  }

  @Test
  void streamsAndSearch() throws Exception {
    try (GraylogClient c = client()) {
      String run = runId();
      List<IndexSet> sets = c.listIndexSets();
      String defaultSet = env.get("GRAYLOG_DEFAULT_INDEX_SET_ID");
      assertTrue(sets.stream().anyMatch(s -> s.isDefault() && s.id().equals(defaultSet)));
      assertFalse(c.listIndexSetsAsync().get().isEmpty());
      StreamPage page = c.listStreams();
      assertTrue(page.streams().stream().anyMatch(GraylogStream::isDefault));
      assertTrue(c.listStreamsAsync(ListStreamsOptions.page(1, 10)).get().total() >= 3);

      String streamId =
          c.createStream(
              CreateStreamOptions.builder("grow-sdk java " + run)
                  .description("java integration")
                  .rules(new StreamRule("", "marker", StreamRule.TYPE_EXACT, run, false, "marker"))
                  .build());
      try {
        GraylogStream s = c.getStream(streamId);
        assertFalse(s.disabled());
        assertEquals("grow-sdk java " + run, s.title());
        assertEquals(1, s.rules().size());
        assertEquals(streamId, c.getStreamAsync(streamId).get().id());
        c.resumeStream(streamId);
        c.resumeStreamAsync(streamId).get();

        try (GelfTransport tcp = c.gelfTransport(GelfProtocol.TCP)) {
          List<GelfMessage> msgs = new ArrayList<>();
          Instant base = Instant.now().minusSeconds(2);
          for (int i = 0; i < 3; i++) {
            msgs.add(
                GelfMessage.builder("java-it", run + " search #" + i)
                    .timestamp(base.plusMillis(10L * i))
                    .level(Gelf.LEVEL_WARNING)
                    .fields(Map.of("marker", run, "seq", i))
                    .build());
          }
          GelfSendResult res = tcp.send(msgs);
          assertEquals(3, res.sent());
        }

        MessageSearchResult res =
            waitMessages(
                c,
                "marker:" + run,
                3,
                MessageSearchOptions.builder()
                    .streams(streamId)
                    .sort(SearchSort.asc("seq"))
                    .fields("message", "seq", "marker", "timestamp")
                    .build());
        assertEquals(3, res.total());
        assertEquals(0L, res.messages().get(0).fields().get("seq"));
        assertEquals(2L, res.messages().get(2).fields().get("seq"));
        assertFalse(res.messages().get(0).fields().containsKey("level"));

        MessageSearchResult paged =
            c.search(
                "marker:" + run,
                MessageSearchOptions.builder()
                    .start(Instant.now().minus(Duration.ofMinutes(10)))
                    .end(Instant.now().plus(Duration.ofMinutes(1)))
                    .limit(1)
                    .offset(1)
                    .sort(SearchSort.desc("seq"))
                    .build());
        assertEquals(1, paged.messages().size());
        assertEquals(1L, paged.messages().get(0).fields().get("seq"));
        assertEquals(2, paged.nextOffset().getAsInt());
        MessageSearchResult rel = c.searchRelative("marker:" + run, Duration.ofMinutes(10));
        assertEquals(3, rel.total());
        assertEquals(
            3, c.searchRelativeAsync("marker:" + run, Duration.ofMinutes(10), null).get().total());
        MessageSearchResult kw =
            c.searchAsync("marker:" + run, MessageSearchOptions.builder().keyword("last 1 hour").build())
                .get();
        assertEquals(3, kw.total());
        assertEquals(3, c.search("marker:" + run, MessageSearchOptions.builder().range(Duration.ofHours(1)).build()).total());

        GraylogMessage hit = rel.messages().get(0);
        GraylogMessage m = c.getMessage(hit.index(), hit.id());
        assertEquals(hit.id(), m.id());
        assertEquals(run, m.fields().get("marker"));
        assertEquals(hit.id(), c.getMessageAsync(hit.index(), hit.id()).get().id());
        LogRecord rec = m.toLogRecord();
        assertEquals(Severity.WARN, rec.severity());
        assertEquals("java-it", rec.resource().get("host.name"));
        assertTrue(rec.body().startsWith(run));
        assertEquals(3, rel.records().size());
        assertThrows(
            NotFoundException.class,
            () -> c.getMessage(hit.index(), "00000000-0000-0000-0000-000000000000"));
        assertThrows(ValidationException.class, () -> c.search("marker:(("));
      } finally {
        c.deleteStream(streamId);
      }
      assertThrows(NotFoundException.class, () -> c.getStream(streamId));
      String paused =
          c.createStreamAsync(CreateStreamOptions.builder("grow-sdk java paused " + run).start(false).build())
              .get();
      assertTrue(c.getStream(paused).disabled());
      c.deleteStreamAsync(paused).get();
    }
  }

  @Test
  void gelfLogClients() throws Exception {
    try (GraylogClient c = client()) {
      for (GelfProtocol p : List.of(GelfProtocol.TCP, GelfProtocol.HTTP, GelfProtocol.UDP)) {
        String run = runId();
        BatchingLogClient lc =
            c.logClient(
                GraylogLogClientOptions.builder()
                    .protocol(p)
                    .resource(
                        Map.of(
                            "service.name", "java-it",
                            "deployment.environment", "test",
                            "host.name", "java-host"))
                    .build());
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("marker", run);
        attrs.put("flag", true);
        attrs.put("count", 42);
        attrs.put("ratio", 1.5);
        attrs.put("id", "attr-id");
        attrs.put("nested", Map.of("a", 1));
        attrs.put("list", List.of(1, "two"));
        attrs.put("password", "hunter2");
        LogRecord record =
            LogRecord.builder()
                .timestamp(Instant.now())
                .severity(Severity.ERROR)
                .body(run + " via " + p)
                .attributes(attrs)
                .traceId("4bf92f3577b34da6a3ce929d0e0e4736")
                .spanId("00f067aa0ba902b7")
                .build();
        lc.send(record);
        lc.flush(Duration.ofSeconds(30));
        GraylogLogQueryClient q = c.logQueryClient();
        List<LogRecord> recs = List.of();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (recs.isEmpty()) {
          recs =
              q.search(
                      "marker:" + run,
                      SearchOptions.builder().start(Instant.now().minus(Duration.ofMinutes(15))).build())
                  .records();
          if (!recs.isEmpty()) {
            break;
          }
          if (System.nanoTime() > deadline) {
            throw new AssertionError(p + ": record not found");
          }
          Thread.sleep(1000);
          if (p == GelfProtocol.UDP) {
            lc.send(record); // UDP is best-effort: retry the send
            lc.flush(Duration.ofSeconds(30));
          }
        }
        LogRecord r = recs.get(0);
        assertEquals(Severity.ERROR, r.severity(), p + " severity");
        assertEquals(Optional.of("4bf92f3577b34da6a3ce929d0e0e4736"), r.traceId());
        assertEquals(Optional.of("00f067aa0ba902b7"), r.spanId());
        Map<String, Object> a = r.attributes();
        assertEquals("true", a.get("flag"), p + " flag");
        assertEquals(42L, a.get("count"));
        assertEquals(1.5, a.get("ratio"));
        assertEquals("attr-id", a.get("id"));
        assertEquals("{\"a\":1}", a.get("nested"));
        assertEquals("[1,\"two\"]", a.get("list"));
        assertEquals("[REDACTED]", a.get("password"));
        assertEquals("java-host", r.resource().get("host.name"));
        Object svc = r.resource().getOrDefault("service.name", a.get("service.name"));
        assertEquals("java-it", svc, p + " service.name round trip");
        BatchStats s = lc.stats();
        assertEquals(0, s.dropped());
        assertEquals(0, s.failed());
        lc.close();
      }
    }
  }

  @Test
  void logQueryAndTail() throws Exception {
    try (GraylogClient c = client()) {
      GraylogLogQueryClient q = c.logQueryClient();
      assertTrue(q.listStreams().contains("Default Stream"));
      assertTrue(q.listStreamsAsync().get().contains("Default Stream"));
      assertTrue(q.listLabels().contains("source"));
      assertTrue(q.listLabelsAsync().get().contains("message"));

      String run = runId();
      LinkedBlockingQueue<LogRecord> got = new LinkedBlockingQueue<>();
      TailHandle h =
          q.tail(
              "marker:" + run,
              got::add,
              new TailOptions(Optional.of(Instant.now().minusSeconds(60)), Duration.ofMillis(500), null));
      try {
        BatchingLogClient lc = c.logClient();
        lc.logger("tail", Map.of("marker", run)).warn(run + " tail one");
        lc.flush(Duration.ofSeconds(30));
        LogRecord r = got.poll(60, TimeUnit.SECONDS);
        assertNotNull(r, "tail: no record");
        assertEquals(run + " tail one", r.body());
        // Graylog stores field names with "." replaced by "_": logger.name reads back as logger_name
        assertEquals("tail", r.attributes().get("logger_name"));
        LogRecord found =
            q.waitForLog(
                "marker:" + run,
                new WaitForLogOptions(
                    Duration.ofSeconds(30),
                    Duration.ofSeconds(1),
                    null,
                    SearchOptions.builder().start(Instant.now().minus(Duration.ofHours(1))).build()));
        assertEquals(Severity.WARN, found.severity());
        LogSearchResult page = q.searchAsync("marker:" + run, SearchOptions.defaults()).get();
        assertEquals(1, page.total().getAsLong());
      } finally {
        h.stop();
      }
      TailHandle defaults = q.tail("marker:" + run, r -> {});
      defaults.close();
    }
  }

  @Test
  void otlpLogClient() throws Exception {
    assumeTrue(env.containsKey("GRAYLOG_OTLP_GRPC_ENDPOINT"), "the OpenTelemetry (gRPC) input is not installed");
    try (GraylogClient c = client()) {
      String run = runId();
      BatchingLogClient lc =
          c.logClient(
              GraylogLogClientOptions.builder()
                  .protocol(GelfProtocol.OTLP)
                  .resource(Map.of("service.name", "java-otlp"))
                  .build());
      lc.send(
          LogRecord.builder()
              .timestamp(Instant.now())
              .severity(Severity.WARN)
              .body(run + " via otlp")
              .attribute("marker", run)
              .traceId("4bf92f3577b34da6a3ce929d0e0e4736")
              .spanId("00f067aa0ba902b7")
              .build());
      lc.flush(Duration.ofSeconds(30));
      assertEquals(1, lc.stats().sent());
      assertEquals(0, lc.stats().failed());
      LogRecord r =
          c.logQueryClient()
              .waitForLog(
                  "otel_attributes_marker:" + run,
                  new WaitForLogOptions(
                      Duration.ofSeconds(60),
                      Duration.ofSeconds(1),
                      null,
                      SearchOptions.builder().start(Instant.now().minus(Duration.ofHours(1))).build()));
      assertEquals(Severity.WARN, r.severity());
      assertEquals(Optional.of("4bf92f3577b34da6a3ce929d0e0e4736"), r.traceId());
      assertEquals("java-otlp", r.resource().get("service.name"));
      assertEquals(run, r.attributes().get("marker"));

      // the exporter used directly, through logClientWithExporter
      String run2 = runId();
      OtlpGrpcLogExporter exporter =
          OtlpGrpcLogExporter.builder(c.config().otlpGrpcEndpoint()).timeout(Duration.ofSeconds(10)).build();
      BatchingLogClient direct =
          c.logClientWithExporter(exporter, GraylogLogClientOptions.builder().resource(Map.of("service.name", "java-otlp-direct")).build());
      direct.logger().info(run2 + " direct otlp", Map.of("marker", run2));
      direct.flush(Duration.ofSeconds(30));
      LogRecord r2 =
          c.logQueryClient()
              .waitForLog(
                  "otel_attributes_marker:" + run2,
                  new WaitForLogOptions(
                      Duration.ofSeconds(60),
                      Duration.ofSeconds(1),
                      null,
                      SearchOptions.builder().start(Instant.now().minus(Duration.ofHours(1))).build()));
      assertEquals("java-otlp-direct", r2.resource().get("service.name"));
    }
  }

  @Test
  void directTransports() throws Exception {
    try (GraylogClient c = client()) {
      GraylogConfig cfg = c.config();
      String run = runId();
      try (GelfUdpTransport udp =
              GelfUdpTransport.builder(cfg.gelfHost()).port(12201).compression(GelfCompression.ZLIB).build();
          GelfTcpTransport tcp = GelfTcpTransport.builder(cfg.gelfHost()).port(12201).build();
          GelfHttpTransport http = GelfHttpTransport.builder(cfg.gelfHttpEndpoint()).bulk(false).config(cfg).build()) {
        for (GelfTransport t : List.<GelfTransport>of(tcp, http, udp)) {
          GelfMessage m =
              GelfMessage.builder("direct", run + " direct " + t.protocol())
                  .fullMessage("line1\nline2")
                  .field("marker", run)
                  .field("transport", t.protocol().wireValue())
                  .build();
          String query = "marker:" + run + " AND transport:" + t.protocol().wireValue();
          long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
          while (true) {
            GelfSendResult sent = t.sendAsync(List.of(m), null).get();
            assertEquals(1, sent.sent(), t.protocol() + " send");
            MessageSearchResult res = c.searchRelative(query, Duration.ofMinutes(15));
            if (!res.messages().isEmpty()) {
              assertEquals("line1\nline2", res.messages().get(0).fields().get("full_message"));
              break;
            }
            if (System.nanoTime() > deadline) {
              throw new AssertionError(t.protocol() + ": message not found");
            }
            Thread.sleep(2000); // TCP/HTTP resend only after a grace period; duplicates are fine
          }
        }
      }

      // GelfLogExporter over an explicit HTTP transport
      String run2 = runId();
      BatchingLogClient lc =
          c.logClientWithExporter(
              new GelfLogExporter(GelfHttpTransport.builder(cfg.gelfHttpEndpoint()).build(), "exporter-host"),
              GraylogLogClientOptions.defaults());
      lc.logger().info(run2 + " exporter", Map.of("marker", run2));
      lc.flush(Duration.ofSeconds(30));
      MessageSearchResult res = waitMessages(c, "marker:" + run2, 1, MessageSearchOptions.defaults());
      assertEquals("exporter-host", res.messages().get(0).fields().get("source"));
    }
  }
}
