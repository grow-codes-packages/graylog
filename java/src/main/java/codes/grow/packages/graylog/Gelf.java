package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.AttrValues;
import codes.grow.packages.graylog.logging.Severity;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * GELF 1.1 helpers shared by every transport: syslog level mapping, additional field key and value
 * rules (identical in all five languages) and the timestamp format.
 */
public final class Gelf {
  /** GELF specification version written into every message. */
  public static final String VERSION = "1.1";

  /** Syslog level 0 (emergency). */
  public static final int LEVEL_EMERGENCY = 0;

  /** Syslog level 1 (alert). */
  public static final int LEVEL_ALERT = 1;

  /** Syslog level 2 (critical). */
  public static final int LEVEL_CRITICAL = 2;

  /** Syslog level 3 (error). */
  public static final int LEVEL_ERROR = 3;

  /** Syslog level 4 (warning). */
  public static final int LEVEL_WARNING = 4;

  /** Syslog level 5 (notice). */
  public static final int LEVEL_NOTICE = 5;

  /** Syslog level 6 (informational). */
  public static final int LEVEL_INFORMATIONAL = 6;

  /** Syslog level 7 (debug). */
  public static final int LEVEL_DEBUG = 7;

  private static final Pattern KEY_CHARS = Pattern.compile("^[A-Za-z0-9_.\\-]+$");
  private static final Pattern KEY_SANITIZE = Pattern.compile("[^A-Za-z0-9_.\\-]");

  private Gelf() {}

  /**
   * Maps a severity to a syslog level: TRACE/DEBUG 7, INFO 6, WARN 4, ERROR 3, FATAL 2.
   *
   * @param severity the severity ({@code null} means INFO)
   * @return the level 0..7
   */
  public static int severityToLevel(Severity severity) {
    if (severity == null) {
      return LEVEL_INFORMATIONAL;
    }
    switch (severity) {
      case TRACE:
      case DEBUG:
        return LEVEL_DEBUG;
      case WARN:
        return LEVEL_WARNING;
      case ERROR:
        return LEVEL_ERROR;
      case FATAL:
        return LEVEL_CRITICAL;
      default:
        return LEVEL_INFORMATIONAL;
    }
  }

  /**
   * Maps a syslog level to a severity: 0–2 FATAL, 3 ERROR, 4 WARN, 5–6 INFO, 7 DEBUG (below 0
   * FATAL, above 7 DEBUG).
   *
   * @param level syslog level
   * @return the severity
   */
  public static Severity levelToSeverity(int level) {
    if (level <= 2) {
      return Severity.FATAL;
    }
    if (level == 3) {
      return Severity.ERROR;
    }
    if (level == 4) {
      return Severity.WARN;
    }
    if (level >= 7) {
      return Severity.DEBUG;
    }
    return Severity.INFO;
  }

  /**
   * Maps an attribute name to its GELF additional field key: a {@code _} prefix, every character
   * outside {@code [A-Za-z0-9_.-]} replaced by {@code _}, and {@code id} (reserved by GELF) mapped
   * to {@code _attr_id}.
   *
   * @param name attribute name
   * @return the wire key
   */
  public static String fieldKey(String name) {
    if ("id".equals(name)) {
      return "_attr_id";
    }
    return "_" + KEY_SANITIZE.matcher(name).replaceAll("_");
  }

  /**
   * Maps an attribute value to its GELF form: strings and finite numbers unchanged, booleans to
   * {@code "true"}/{@code "false"} (Graylog drops JSON booleans), NaN/infinity to their text,
   * {@link Instant} to ISO-8601 text, lists and maps to compact JSON strings. {@code null} is
   * omitted.
   *
   * @param value any value
   * @return the wire value, or empty when the field must be omitted
   */
  public static Optional<Object> fieldValue(Object value) {
    if (value == null) {
      return Optional.empty();
    }
    if (value instanceof Instant) {
      return Optional.of(value.toString());
    }
    Object v = AttrValues.normalize(value);
    if (v instanceof Boolean) {
      return Optional.of(((Boolean) v) ? "true" : "false");
    }
    if (v instanceof Double) {
      double d = (Double) v;
      return Optional.of(Double.isFinite(d) ? (Object) d : Double.toString(d));
    }
    if (v instanceof String || v instanceof Long) {
      return Optional.of(v);
    }
    return Optional.of(Json.stringify(v));
  }

  /**
   * Validates an explicit additional field key ({@code name} or {@code _name}).
   *
   * @param key the key
   * @return the {@code _name} wire key
   * @throws ValidationException for an empty key, characters outside {@code [A-Za-z0-9_.-]} or the
   *     reserved {@code _id}
   */
  public static String validateFieldKey(String key) {
    String name = key == null ? "" : key.startsWith("_") ? key.substring(1) : key;
    if (name.isEmpty() || !KEY_CHARS.matcher(name).matches()) {
      throw new ValidationException(
          "gelf: invalid additional field key \"" + key + "\" (allowed: letters, digits, _ . -)");
    }
    if (name.equals("id")) {
      throw new ValidationException("gelf: additional field \"_id\" is reserved");
    }
    return "_" + name;
  }

  /**
   * Renders an instant as Unix seconds with millisecond precision (e.g. {@code 1795000000.123}).
   *
   * @param t the instant
   * @return the GELF timestamp
   */
  public static BigDecimal timestamp(Instant t) {
    BigDecimal d = BigDecimal.valueOf(t.toEpochMilli(), 3).stripTrailingZeros();
    return d.scale() < 0 ? d.setScale(0) : d;
  }

  /**
   * Flattens nested maps into dotted keys; lists and scalars are leaves.
   *
   * @param attributes attributes (may be {@code null})
   * @return a sorted flat map
   */
  public static Map<String, Object> flattenAttributes(Map<String, ?> attributes) {
    Map<String, Object> out = new TreeMap<>();
    flatten(out, "", attributes);
    return out;
  }

  private static void flatten(Map<String, Object> out, String prefix, Map<?, ?> attrs) {
    if (attrs == null) {
      return;
    }
    for (Map.Entry<?, ?> e : attrs.entrySet()) {
      String key = prefix.isEmpty() ? String.valueOf(e.getKey()) : prefix + "." + e.getKey();
      Object v = e.getValue();
      if (v instanceof Map) {
        flatten(out, key, (Map<?, ?>) v);
      } else {
        out.put(key, v);
      }
    }
  }
}
