package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.UnavailableException;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Defensive JSON decoding helpers for Graylog responses. */
final class Nodes {
  private static final DateTimeFormatter GL2 =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

  private Nodes() {}

  static JsonNode object(JsonNode n, String op) {
    if (n == null || !n.isObject()) {
      throw new UnavailableException(op + ": unexpected response (not a JSON object)");
    }
    return n;
  }

  static String text(JsonNode n, String field) {
    JsonNode v = n.get(field);
    return v == null || v.isNull() || v.isContainerNode() ? "" : v.asText();
  }

  static Optional<String> optText(JsonNode n, String field) {
    String s = text(n, field);
    return s.isEmpty() ? Optional.empty() : Optional.of(s);
  }

  static boolean bool(JsonNode n, String field) {
    JsonNode v = n.get(field);
    return v != null && (v.isBoolean() ? v.asBoolean() : "true".equalsIgnoreCase(v.asText()));
  }

  static long number(JsonNode n, String field, long dflt) {
    JsonNode v = n.get(field);
    if (v == null || v.isNull()) {
      return dflt;
    }
    if (v.isNumber()) {
      return v.asLong();
    }
    try {
      return Long.parseLong(v.asText().trim());
    } catch (NumberFormatException e) {
      return dflt;
    }
  }

  static Optional<Instant> instant(JsonNode n, String field) {
    return parseTime(text(n, field));
  }

  /** Parses ISO-8601 timestamps and Graylog's {@code yyyy-MM-dd HH:mm:ss.SSS} (UTC) form. */
  static Optional<Instant> parseTime(String s) {
    if (s == null || s.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional.of(java.time.OffsetDateTime.parse(s).toInstant());
    } catch (DateTimeParseException e) {
      try {
        return Optional.of(LocalDateTime.parse(s, GL2).toInstant(ZoneOffset.UTC));
      } catch (DateTimeParseException e2) {
        return Optional.empty();
      }
    }
  }

  static List<JsonNode> array(JsonNode n, String field) {
    JsonNode v = n == null ? null : n.get(field);
    List<JsonNode> out = new ArrayList<>();
    if (v != null && v.isArray()) {
      v.forEach(out::add);
    }
    return out;
  }

  /**
   * Converts a JSON object into a map of plain values (Long, Double, String, Boolean, List, Map).
   */
  static Map<String, Object> map(JsonNode n) {
    Map<String, Object> out = new LinkedHashMap<>();
    if (n != null && n.isObject()) {
      for (Map.Entry<String, JsonNode> e : n.properties()) {
        out.put(e.getKey(), value(e.getValue()));
      }
    }
    return Collections.unmodifiableMap(out);
  }

  static Object value(JsonNode v) {
    if (v == null || v.isNull()) {
      return null;
    }
    if (v.isObject()) {
      return map(v);
    }
    if (v.isArray()) {
      List<Object> list = new ArrayList<>();
      v.forEach(x -> list.add(value(x)));
      return Collections.unmodifiableList(list);
    }
    if (v.isIntegralNumber()) {
      return v.canConvertToLong() ? (Object) v.asLong() : v.asText();
    }
    if (v.isNumber()) {
      return v.asDouble();
    }
    if (v.isBoolean()) {
      return v.asBoolean();
    }
    return v.asText();
  }

  static Map<String, String> stringMap(JsonNode n) {
    Map<String, String> out = new LinkedHashMap<>();
    if (n != null && n.isObject()) {
      for (Map.Entry<String, JsonNode> e : n.properties()) {
        out.put(
            e.getKey(),
            e.getValue().isValueNode()
                ? e.getValue().asText()
                : Json.stringify(value(e.getValue())));
      }
    }
    return Collections.unmodifiableMap(out);
  }
}
