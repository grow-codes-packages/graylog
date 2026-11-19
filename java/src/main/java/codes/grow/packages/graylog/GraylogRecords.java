package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.Severity;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/** Normalises stored Graylog messages into {@link LogRecord}s (the read-back mapping). */
public final class GraylogRecords {
  /**
   * Stored field names (dots become underscores in Graylog) mapped back to OpenTelemetry resource
   * keys; {@code otel_resource_attributes_<k>} uses the same table.
   */
  public static final Map<String, String> RESOURCE_FIELDS =
      Map.of(
          "service_name", "service.name",
          "service_version", "service.version",
          "service_namespace", "service.namespace",
          "service_instance_id", "service.instance.id",
          "deployment_environment", "deployment.environment",
          "deployment_environment_name", "deployment.environment.name");

  private static final Set<String> SKIPPED =
      Set.of(
          "_id",
          "message",
          "timestamp",
          "level",
          "source",
          "streams",
          "trace_id",
          "span_id",
          "trace_flags",
          "otel_trace_id",
          "otel_span_id",
          "otel_trace_flags",
          "otel_severity_number",
          "otel_severity_text",
          "otel_time_unix_nano",
          "otel_observed_time_unix_nano",
          "otel_resource_schema_url",
          "otel_scope_schema_url");

  private static final Pattern HEX32 = Pattern.compile("^[0-9a-f]{32}$");
  private static final Pattern HEX16 = Pattern.compile("^[0-9a-f]{16}$");

  private GraylogRecords() {}

  /**
   * Normalises stored message fields (a search hit or {@code getMessage}) into a log record. OTLP
   * fields ({@code otel_*}) win over GELF fields:
   *
   * <ul>
   *   <li>body = {@code message}, timestamp = {@code timestamp}, {@code resource["host.name"]} =
   *       {@code source};
   *   <li>severity from {@code otel_severity_number}, else from the syslog {@code level} (see
   *       {@link Gelf#levelToSeverity}), else INFO;
   *   <li>{@code otel_resource_attributes_<k>} to {@code resource[RESOURCE_FIELDS[k] or k]}, stored
   *       fields named in {@link #RESOURCE_FIELDS} to the resource (unless already set), {@code
   *       otel_attributes_<k>} to {@code attributes[k]}, {@code attr_id} to {@code
   *       attributes["id"]} and every other field except {@code gl2_*} and the reserved ones to the
   *       attributes;
   *   <li>trace id from {@code otel_trace_id} or {@code trace_id} (32 lower-hex), and only then the
   *       span id (16 lower-hex) and trace flags.
   * </ul>
   *
   * @param fields stored fields
   * @return the record
   */
  public static LogRecord fromMessage(Map<String, ?> fields) {
    LogRecord.Builder b = LogRecord.builder();
    b.body(stringField(fields.get("message")));
    Object ts = fields.get("timestamp");
    if (ts instanceof String) {
      Nodes.parseTime((String) ts).ifPresent(b::timestamp);
    }
    Severity severity = Severity.INFO;
    OptionalDouble otelSev = number(fields.get("otel_severity_number"));
    OptionalDouble level = number(fields.get("level"));
    if (otelSev.isPresent() && otelSev.getAsDouble() >= 1 && otelSev.getAsDouble() <= 24) {
      severity = Severity.fromNumber((int) otelSev.getAsDouble());
    } else if (level.isPresent()) {
      severity = Gelf.levelToSeverity((int) level.getAsDouble());
    }
    b.severity(severity).severityText(severity.text());
    Map<String, Object> resource = new LinkedHashMap<>();
    Map<String, Object> attributes = new LinkedHashMap<>();
    Object src = fields.get("source");
    if (src instanceof String && !((String) src).isEmpty()) {
      resource.put("host.name", src);
    }
    for (Map.Entry<String, ?> e : new TreeMap<String, Object>(fields).entrySet()) {
      String k = e.getKey();
      Object v = e.getValue();
      if (v == null || SKIPPED.contains(k) || k.startsWith("gl2_")) {
        continue;
      }
      if (k.startsWith("otel_resource_attributes_")) {
        String name = k.substring("otel_resource_attributes_".length());
        resource.put(RESOURCE_FIELDS.getOrDefault(name, name), v);
      } else if (k.startsWith("otel_attributes_")) {
        attributes.put(k.substring("otel_attributes_".length()), v);
      } else if (RESOURCE_FIELDS.containsKey(k)) {
        resource.putIfAbsent(RESOURCE_FIELDS.get(k), v);
      } else if (k.equals("attr_id")) {
        attributes.put("id", v);
      } else {
        attributes.put(k, v);
      }
    }
    b.resource(resource).attributes(attributes);
    Optional<String> traceId = hexId(HEX32, fields.get("otel_trace_id"), fields.get("trace_id"));
    if (traceId.isPresent()) {
      b.traceId(traceId.get());
      hexId(HEX16, fields.get("otel_span_id"), fields.get("span_id")).ifPresent(b::spanId);
      for (Object f : new Object[] {fields.get("otel_trace_flags"), fields.get("trace_flags")}) {
        OptionalDouble n = number(f);
        if (n.isPresent() && n.getAsDouble() >= 0 && n.getAsDouble() <= 255) {
          b.traceFlags((int) n.getAsDouble());
          break;
        }
      }
    }
    return b.build();
  }

  private static Optional<String> hexId(Pattern re, Object... values) {
    for (Object v : values) {
      if (v instanceof String) {
        String s = ((String) v).trim().toLowerCase(Locale.ROOT);
        if (re.matcher(s).matches()) {
          return Optional.of(s);
        }
      }
    }
    return Optional.empty();
  }

  private static OptionalDouble number(Object v) {
    if (v instanceof Number) {
      return OptionalDouble.of(((Number) v).doubleValue());
    }
    if (v instanceof String) {
      try {
        return OptionalDouble.of(Double.parseDouble(((String) v).trim()));
      } catch (NumberFormatException e) {
        return OptionalDouble.empty();
      }
    }
    return OptionalDouble.empty();
  }

  private static String stringField(Object v) {
    if (v == null) {
      return "";
    }
    if (v instanceof String) {
      return (String) v;
    }
    if (v instanceof Number || v instanceof Boolean) {
      return String.valueOf(v);
    }
    return Json.stringify(v);
  }
}
