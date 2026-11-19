package codes.grow.packages.graylog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GelfTest {
  @Test
  void levels() {
    assertThat(Gelf.severityToLevel(Severity.TRACE)).isEqualTo(7);
    assertThat(Gelf.severityToLevel(Severity.DEBUG)).isEqualTo(7);
    assertThat(Gelf.severityToLevel(Severity.INFO)).isEqualTo(6);
    assertThat(Gelf.severityToLevel(Severity.WARN)).isEqualTo(4);
    assertThat(Gelf.severityToLevel(Severity.ERROR)).isEqualTo(3);
    assertThat(Gelf.severityToLevel(Severity.FATAL)).isEqualTo(2);
    assertThat(Gelf.severityToLevel(null)).isEqualTo(6);
    assertThat(Gelf.levelToSeverity(-1)).isEqualTo(Severity.FATAL);
    assertThat(Gelf.levelToSeverity(0)).isEqualTo(Severity.FATAL);
    assertThat(Gelf.levelToSeverity(2)).isEqualTo(Severity.FATAL);
    assertThat(Gelf.levelToSeverity(3)).isEqualTo(Severity.ERROR);
    assertThat(Gelf.levelToSeverity(4)).isEqualTo(Severity.WARN);
    assertThat(Gelf.levelToSeverity(5)).isEqualTo(Severity.INFO);
    assertThat(Gelf.levelToSeverity(6)).isEqualTo(Severity.INFO);
    assertThat(Gelf.levelToSeverity(7)).isEqualTo(Severity.DEBUG);
    assertThat(Gelf.levelToSeverity(9)).isEqualTo(Severity.DEBUG);
  }

  @Test
  void fieldKeysAndValues() {
    assertThat(Gelf.fieldKey("id")).isEqualTo("_attr_id");
    assertThat(Gelf.fieldKey("service.name")).isEqualTo("_service.name");
    assertThat(Gelf.fieldKey("a b/c-d_e")).isEqualTo("_a_b_c-d_e");
    // ASCII only: non-ASCII letters are replaced too
    assertThat(Gelf.fieldKey("größe")).isEqualTo("_gr__e");

    assertThat(Gelf.fieldValue(null)).isEmpty();
    assertThat(Gelf.fieldValue(true)).contains("true");
    assertThat(Gelf.fieldValue(false)).contains("false");
    assertThat(Gelf.fieldValue(42)).contains(42L);
    assertThat(Gelf.fieldValue(1.5)).contains(1.5);
    assertThat(Gelf.fieldValue(Double.NaN)).contains("NaN");
    assertThat(Gelf.fieldValue(Double.POSITIVE_INFINITY)).contains("Infinity");
    assertThat(Gelf.fieldValue("s")).contains("s");
    assertThat(Gelf.fieldValue(Instant.parse("2026-01-02T03:04:05Z")))
        .contains("2026-01-02T03:04:05Z");
    Map<String, Object> obj = new LinkedHashMap<>();
    obj.put("a", 1);
    obj.put("b", "x");
    assertThat(Gelf.fieldValue(obj)).contains("{\"a\":1,\"b\":\"x\"}");
    assertThat(Gelf.fieldValue(List.of(1, "two"))).contains("[1,\"two\"]");

    assertThat(Gelf.validateFieldKey("marker")).isEqualTo("_marker");
    assertThat(Gelf.validateFieldKey("_marker")).isEqualTo("_marker");
    assertThatThrownBy(() -> Gelf.validateFieldKey("_id")).hasMessageContaining("reserved");
    assertThatThrownBy(() -> Gelf.validateFieldKey("id")).hasMessageContaining("reserved");
    assertThatThrownBy(() -> Gelf.validateFieldKey("")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> Gelf.validateFieldKey("_")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> Gelf.validateFieldKey(null)).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> Gelf.validateFieldKey("a b")).isInstanceOf(ValidationException.class);

    assertThat(Gelf.timestamp(Instant.ofEpochMilli(1795000000123L)))
        .isEqualTo(new BigDecimal("1795000000.123"));
    assertThat(Gelf.timestamp(Instant.ofEpochSecond(1795000000L)).toString())
        .isEqualTo("1795000000");
    assertThat(Gelf.timestamp(Instant.ofEpochMilli(1500)).toString()).isEqualTo("1.5");

    Map<String, Object> nested = new HashMap<>();
    nested.put("service", Map.of("name", "svc", "version", "1"));
    nested.put("list", List.of(1));
    nested.put("plain", "v");
    assertThat(Gelf.flattenAttributes(nested))
        .containsExactly(
            Map.entry("list", List.of(1)),
            Map.entry("plain", "v"),
            Map.entry("service.name", "svc"),
            Map.entry("service.version", "1"));
    assertThat(Gelf.flattenAttributes(null)).isEmpty();
  }

  @Test
  void messageBuilder() {
    Instant ts = Instant.ofEpochMilli(1795000000123L);
    GelfMessage m =
        GelfMessage.builder("host-1", "hello")
            .fullMessage("line1\nline2")
            .timestamp(ts)
            .level(Gelf.LEVEL_WARNING)
            .field("marker", "abc")
            .field("_count", 3)
            .field("flag", true)
            .field("gone", "x")
            .field("gone", null)
            .fields(Map.of("z", "last"))
            .build();
    assertThat(m.host()).isEqualTo("host-1");
    assertThat(m.shortMessage()).isEqualTo("hello");
    assertThat(m.fullMessage()).contains("line1\nline2");
    assertThat(m.timestamp()).contains(ts);
    assertThat(m.level()).hasValue(4);
    assertThat(m.fields()).containsOnlyKeys("_count", "_flag", "_marker", "_z");
    JsonNode doc = Json.tree(m.encode());
    assertThat(doc.path("version").asText()).isEqualTo("1.1");
    assertThat(doc.path("timestamp").decimalValue()).isEqualTo(new BigDecimal("1795000000.123"));
    assertThat(doc.path("_flag").asText()).isEqualTo("true");
    assertThat(doc.path("_count").asLong()).isEqualTo(3);
    assertThat(m.toString()).contains("\"short_message\":\"hello\"");
    assertThat(new String(m.encode(), StandardCharsets.UTF_8)).isEqualTo(m.toString());
    assertThat(m.toBuilder().build()).isEqualTo(m);
    assertThat(m.hashCode()).isEqualTo(m.toBuilder().build().hashCode());
    assertThat(m).isNotEqualTo("x");

    GelfMessage minimal = GelfMessage.builder("h", "s").fullMessage("").build();
    assertThat(minimal.fullMessage()).isEmpty();
    assertThat(minimal.timestamp()).isEmpty();
    assertThat(minimal.level()).isEmpty();
    assertThat(minimal.toMap()).containsOnlyKeys("version", "host", "short_message");

    assertThatThrownBy(() -> GelfMessage.builder(" ", "s").build()).hasMessageContaining("host");
    assertThatThrownBy(() -> GelfMessage.builder(null, "s").build()).hasMessageContaining("host");
    assertThatThrownBy(() -> GelfMessage.builder("h", "").build())
        .hasMessageContaining("shortMessage");
    assertThatThrownBy(() -> GelfMessage.builder("h", null).build())
        .hasMessageContaining("shortMessage");
    assertThatThrownBy(() -> GelfMessage.builder("h", "s").level(8).build())
        .hasMessageContaining("level");
    assertThatThrownBy(() -> GelfMessage.builder("h", "s").level(-1).build())
        .hasMessageContaining("level");
    assertThatThrownBy(() -> GelfMessage.builder("h", "s").field("_id", 1))
        .hasMessageContaining("reserved");
  }

  @Test
  void fromLogRecordSharedMapping() {
    Map<String, Object> resource = new LinkedHashMap<>();
    resource.put("service.name", "svc");
    resource.put("host.name", "res-host");
    resource.put("deployment", Map.of("environment", "test"));
    Map<String, Object> attrs = new LinkedHashMap<>();
    attrs.put("id", "attr-id");
    attrs.put("flag", true);
    attrs.put("count", 42);
    attrs.put("service.name", "attr-wins");
    attrs.put("bad key", "v");
    attrs.put("", "dropped");
    LogRecord r =
        LogRecord.builder()
            .timestamp(Instant.ofEpochMilli(1795000000123L))
            .severity(Severity.ERROR)
            .body("boom")
            .resource(resource)
            .attributes(attrs)
            .traceId("4BF92F3577B34DA6A3CE929D0E0E4736")
            .spanId("00f067aa0ba902b7")
            .traceFlags(1)
            .build();
    GelfMessage m = GelfMessage.fromLogRecord(r, "fallback");
    assertThat(m.host()).isEqualTo("res-host");
    assertThat(m.shortMessage()).isEqualTo("boom");
    assertThat(m.level()).hasValue(3);
    assertThat(m.timestamp()).contains(Instant.ofEpochMilli(1795000000123L));
    assertThat(m.fields())
        .containsEntry("_attr_id", "attr-id")
        .containsEntry("_flag", "true")
        .containsEntry("_count", 42L)
        .containsEntry("_service.name", "attr-wins")
        .containsEntry("_deployment.environment", "test")
        .containsEntry("_bad_key", "v")
        .containsEntry("_trace_id", "4bf92f3577b34da6a3ce929d0e0e4736")
        .containsEntry("_span_id", "00f067aa0ba902b7")
        .containsEntry("_trace_flags", 1L)
        .doesNotContainKey("_host.name")
        .doesNotContainKey("_");

    LogRecord blank = LogRecord.builder().body("  ").build();
    GelfMessage b = GelfMessage.fromLogRecord(blank, "fallback");
    assertThat(b.shortMessage()).isEqualTo("-");
    assertThat(b.host()).isEqualTo("fallback");
    assertThat(b.timestamp()).isEmpty();
    assertThat(b.level()).hasValue(6);

    var saved = GelfMessage.hostnameSupplier;
    try {
      GelfMessage.hostnameSupplier = () -> "local-box";
      assertThat(GelfMessage.fromLogRecord(blank, null).host()).isEqualTo("local-box");
      assertThat(GelfMessage.fromLogRecord(blank, " ").host()).isEqualTo("local-box");
      GelfMessage.hostnameSupplier = () -> "";
      assertThat(GelfMessage.fromLogRecord(blank, null).host()).isEqualTo("unknown");
      GelfMessage.hostnameSupplier = () -> null;
      assertThat(GelfMessage.localHostname()).isEqualTo("unknown");
    } finally {
      GelfMessage.hostnameSupplier = saved;
    }
    assertThat(GelfMessage.localHostname()).isNotBlank();
  }

  private static Map<String, Object> storedFields(String fixture) {
    return Nodes.map(Fixtures.body(fixture).path("message").path("message"));
  }

  @Test
  void readBackGelfFields() {
    LogRecord r = GraylogRecords.fromMessage(storedFields("gelfTypedFields.stored"));
    assertThat(r.body()).isEqualTo("growsdk179503370112643 typed");
    assertThat(r.severity()).isEqualTo(Severity.ERROR);
    assertThat(r.severityText()).isEqualTo("ERROR");
    assertThat(r.timestamp()).isEqualTo(Instant.parse("2026-11-18T11:06:40.123Z"));
    assertThat(r.resource()).containsEntry("host.name", "grow-sdk-verify");
    assertThat(r.traceId()).contains("4bf92f3577b34da6a3ce929d0e0e4736");
    assertThat(r.spanId()).contains("00f067aa0ba902b7");
    assertThat(r.attributes())
        .containsEntry("t_int", 42L)
        .containsEntry("t_float", 1.5)
        .containsEntry("t_arr", "[1,\"two\"]")
        .containsEntry("full_message", "line1\nline2")
        .doesNotContainKeys("gl2_remote_ip", "streams", "_id", "trace_id", "level", "source");

    Map<String, Object> f = new HashMap<>();
    f.put("message", 12);
    f.put("level", "4");
    f.put("service_name", "svc");
    f.put("service_version", "1.2");
    f.put("deployment_environment", "prod");
    f.put("attr_id", "a-1");
    f.put("trace_id", "nothex");
    f.put("span_id", "00f067aa0ba902b7");
    f.put("nullish", null);
    f.put("timestamp", "2026-11-18 20:28:22.974");
    LogRecord r2 = GraylogRecords.fromMessage(f);
    assertThat(r2.body()).isEqualTo("12");
    assertThat(r2.severity()).isEqualTo(Severity.WARN);
    assertThat(r2.timestamp()).isEqualTo(Instant.parse("2026-11-18T20:28:22.974Z"));
    assertThat(r2.resource())
        .containsEntry("service.name", "svc")
        .containsEntry("service.version", "1.2")
        .containsEntry("deployment.environment", "prod");
    assertThat(r2.attributes()).containsEntry("id", "a-1").doesNotContainKey("nullish");
    assertThat(r2.traceId()).isEmpty();
    assertThat(r2.spanId()).isEmpty();

    Map<String, Object> f3 = new HashMap<>();
    f3.put("message", Map.of("k", "v"));
    f3.put("level", "x");
    f3.put("trace_id", "4BF92F3577B34DA6A3CE929D0E0E4736");
    f3.put("trace_flags", "300");
    f3.put("otel_trace_flags", 1);
    f3.put("timestamp", "garbage");
    LogRecord r3 = GraylogRecords.fromMessage(f3);
    assertThat(r3.body()).isEqualTo("{\"k\":\"v\"}");
    assertThat(r3.severity()).isEqualTo(Severity.INFO);
    assertThat(r3.traceFlags()).hasValue(1);
    assertThat(r3.spanId()).isEmpty();
    assertThat(GraylogRecords.fromMessage(Map.of("message", true)).body()).isEqualTo("true");
    assertThat(GraylogRecords.fromMessage(Map.of()).body()).isEmpty();
  }

  @Test
  void readBackOtlpFields() {
    LogRecord r = GraylogRecords.fromMessage(storedFields("otlpLogs.searched"));
    assertThat(r.severity()).isEqualTo(Severity.WARN);
    assertThat(r.traceId()).contains("4bf92f3577b34da6a3ce929d0e0e4736");
    assertThat(r.spanId()).contains("00f067aa0ba902b7");
    assertThat(r.resource())
        .containsEntry("service.name", "grow-sdk-verify")
        .containsEntry("marker", "growsdkotlp179503370112643")
        .containsEntry("host.name", "172.30.0.5");
    assertThat(r.attributes())
        .containsEntry("attr_k", "v")
        .containsEntry("app", "server")
        .doesNotContainKey("otel_severity_text");

    Map<String, Object> f = new HashMap<>();
    f.put("otel_severity_number", 30);
    f.put("level", 7);
    f.put("otel_resource_attributes_service_name", "otel");
    f.put("service_name", "gelf");
    assertThat(GraylogRecords.fromMessage(f).severity()).isEqualTo(Severity.DEBUG);
    assertThat(GraylogRecords.fromMessage(f).resource()).containsEntry("service.name", "otel");
  }

  @Test
  void protocolEnum() {
    assertThat(GelfProtocol.parseGelf(" UDP ")).contains(GelfProtocol.UDP);
    assertThat(GelfProtocol.parseGelf("tcp")).contains(GelfProtocol.TCP);
    assertThat(GelfProtocol.parseGelf("http")).contains(GelfProtocol.HTTP);
    assertThat(GelfProtocol.parseGelf("otlp")).isEmpty();
    assertThat(GelfProtocol.parseGelf(null)).isEmpty();
    assertThat(GelfProtocol.OTLP.isGelf()).isFalse();
    assertThat(GelfProtocol.HTTP.wireValue()).isEqualTo("http");
    assertThat(GelfProtocol.TCP.toString()).isEqualTo("tcp");
    assertThat(InputTypes.gelf(GelfProtocol.UDP)).isEqualTo(InputTypes.GELF_UDP);
    assertThat(InputTypes.gelf(GelfProtocol.TCP)).isEqualTo(InputTypes.GELF_TCP);
    assertThat(InputTypes.gelf(GelfProtocol.HTTP)).isEqualTo(InputTypes.GELF_HTTP);
  }

  @Test
  void valueTypes() {
    assertThat(new GelfSendOptions(null).gzip()).isEmpty();
    assertThat(GelfSendOptions.gzip(true).gzip()).contains(true);
    assertThat(new GelfSendResult(1, 0, null).error()).isEmpty();
    assertThat(new SearchSort("f", null).order())
        .isEqualTo(codes.grow.packages.graylog.logging.SortOrder.DESC);
    assertThat(SearchSort.desc("f").field()).isEqualTo("f");
    assertThat(new StreamRule(null, null, 1, null, false, null).field()).isEmpty();
    assertThat(new CreateInputOptions(null, null).title()).isEmpty();
    assertThat(new GraylogMessage(null, null, null, null).fields()).isEmpty();
    assertThat(new MessageSearchResult(null, 0, null, null, null).messages()).isEmpty();
    assertThat(new StreamPage(null, 0, 1, 1).streams()).isEmpty();
    assertThat(
            new GraylogLogQueryClientOptions(List.of("s"), Duration.ofSeconds(-1)).defaultWindow())
        .isEqualTo(GraylogLogQueryClientOptions.DEFAULT_WINDOW);
    assertThat(GraylogLogQueryClientOptions.streams("a").streams()).containsExactly("a");
    MessageSearchOptions o =
        MessageSearchOptions.builder().streams(List.of("x")).range(Duration.ofSeconds(1)).build();
    assertThat(o.toBuilder().build().streams()).containsExactly("x");
    assertThat(o.range()).isPresent();
    assertThat(o.keyword()).isEmpty();
    EnsureGelfInputOptions e = EnsureGelfInputOptions.defaults();
    assertThat(e.title()).isEmpty();
    assertThat(e.bindAddress()).isEqualTo("0.0.0.0");
    assertThat(e.configuration()).isEmpty();
    CreateStreamOptions cs = CreateStreamOptions.builder("t").build();
    assertThat(cs.indexSetId()).isEmpty();
    assertThat(cs.start()).isTrue();
    GraylogInput in =
        new GraylogInput(
            "i",
            "t",
            "x",
            "n",
            true,
            "",
            java.util.Optional.empty(),
            "",
            Map.of("port", "12x"),
            Map.of());
    assertThat(in.port()).isZero();
    assertThat(in.bindAddress()).isEmpty();
    assertThat(
            new GraylogInput(
                    "i",
                    "t",
                    "x",
                    "n",
                    true,
                    "",
                    java.util.Optional.empty(),
                    "",
                    Map.of("port", " 5 ", "bind_address", ""),
                    Map.of())
                .port())
        .isEqualTo(5);
    assertThat(
            new GraylogInput(
                    "i",
                    "t",
                    "x",
                    "n",
                    true,
                    "",
                    java.util.Optional.empty(),
                    "",
                    Map.of(),
                    Map.of())
                .port())
        .isZero();
  }

  @Test
  void nodesHelpers() {
    JsonNode n =
        Json.tree(
            "{\"n\":\"12\",\"bad\":\"x\",\"big\":123456789012345678901234567890,\"b\":\"TRUE\",\"o\":{\"k\":[1,2.5,null]},\"s\":{\"a\":1,\"b\":{\"c\":true}}}"
                .getBytes(StandardCharsets.UTF_8));
    assertThat(Nodes.number(n, "n", 0)).isEqualTo(12);
    assertThat(Nodes.number(n, "bad", 7)).isEqualTo(7);
    assertThat(Nodes.number(n, "missing", 3)).isEqualTo(3);
    assertThat(Nodes.bool(n, "b")).isTrue();
    assertThat(Nodes.text(n, "o")).isEmpty();
    assertThat(Nodes.map(n).get("big")).isEqualTo("123456789012345678901234567890");
    assertThat(Nodes.stringMap(n.get("s")))
        .containsEntry("a", "1")
        .containsEntry("b", "{\"c\":true}");
    assertThat(Nodes.parseTime(null)).isEmpty();
    assertThat(Nodes.array(null, "x")).isEmpty();
  }
}
