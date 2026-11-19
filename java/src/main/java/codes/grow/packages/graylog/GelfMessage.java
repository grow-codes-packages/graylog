package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.LogRecord;
import java.net.InetAddress;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * One immutable GELF 1.1 message. Build it with {@link #builder(String, String)} or from a {@link
 * LogRecord} with {@link #fromLogRecord(LogRecord, String)}.
 */
public final class GelfMessage {
  static Supplier<String> hostnameSupplier = GelfMessage::lookupHostname;

  private final String host;
  private final String shortMessage;
  private final String fullMessage;
  private final Instant timestamp;
  private final Integer level;
  private final Map<String, Object> fields;

  private GelfMessage(
      String host,
      String shortMessage,
      String fullMessage,
      Instant timestamp,
      Integer level,
      Map<String, Object> fields) {
    this.host = host;
    this.shortMessage = shortMessage;
    this.fullMessage = fullMessage;
    this.timestamp = timestamp;
    this.level = level;
    this.fields = Collections.unmodifiableMap(new TreeMap<>(fields));
  }

  /**
   * Starts a builder; {@code host} and {@code shortMessage} are required (non-blank).
   *
   * @param host source host (stored by Graylog as {@code source})
   * @param shortMessage short message (stored as {@code message})
   * @return a new builder
   */
  public static Builder builder(String host, String shortMessage) {
    return new Builder(host, shortMessage);
  }

  /**
   * Returns a builder pre-filled with this message.
   *
   * @return a new builder
   */
  public Builder toBuilder() {
    Builder b = new Builder(host, shortMessage);
    b.fullMessage = fullMessage;
    b.timestamp = timestamp;
    b.level = level;
    b.fields.putAll(fields);
    return b;
  }

  /**
   * Converts a log record with the mapping shared by all five languages: host = {@code
   * resource["host.name"]} (else {@code defaultHost}, else the local host name); short_message =
   * body ({@code "-"} when blank); timestamp (omitted for {@link Instant#EPOCH}); level = {@link
   * Gelf#severityToLevel}; resource attributes flattened with dotted keys (except {@code
   * host.name}), then the record attributes (they win), then {@code _trace_id}, {@code _span_id}
   * and {@code _trace_flags}. Keys go through {@link Gelf#fieldKey}, values through {@link
   * Gelf#fieldValue}.
   *
   * @param record the record
   * @param defaultHost host for records without {@code host.name} ({@code null} = local host name)
   * @return the message
   */
  public static GelfMessage fromLogRecord(LogRecord record, String defaultHost) {
    Object h = record.resource().get("host.name");
    String host = h instanceof String ? (String) h : "";
    if (host.isBlank()) {
      host = defaultHost != null && !defaultHost.isBlank() ? defaultHost : localHostname();
    }
    String body = record.body().isBlank() ? "-" : record.body();
    Map<String, Object> fields = new TreeMap<>();
    Gelf.flattenAttributes(record.resource())
        .forEach(
            (k, v) -> {
              if (!k.equals("host.name")) {
                put(fields, k, v);
              }
            });
    for (Map.Entry<String, Object> e : new TreeMap<>(record.attributes()).entrySet()) {
      put(fields, e.getKey(), e.getValue());
    }
    record.traceId().ifPresent(v -> put(fields, "trace_id", v));
    record.spanId().ifPresent(v -> put(fields, "span_id", v));
    OptionalInt flags = record.traceFlags();
    if (flags.isPresent()) {
      put(fields, "trace_flags", (long) flags.getAsInt());
    }
    Instant ts = Instant.EPOCH.equals(record.timestamp()) ? null : record.timestamp();
    return new GelfMessage(host, body, null, ts, Gelf.severityToLevel(record.severity()), fields);
  }

  private static void put(Map<String, Object> fields, String name, Object value) {
    if (name.isEmpty()) {
      return;
    }
    Gelf.fieldValue(value).ifPresent(v -> fields.put(Gelf.fieldKey(name), v));
  }

  static String localHostname() {
    String h = hostnameSupplier.get();
    return h == null || h.isBlank() ? "unknown" : h;
  }

  private static String lookupHostname() {
    try {
      return InetAddress.getLocalHost().getHostName();
    } catch (Exception e) {
      return System.getenv().getOrDefault("HOSTNAME", "unknown");
    }
  }

  /**
   * Returns {@code host}.
   *
   * @return the host
   */
  public String host() {
    return host;
  }

  /**
   * Returns {@code short_message}.
   *
   * @return the short message
   */
  public String shortMessage() {
    return shortMessage;
  }

  /**
   * Returns {@code full_message}.
   *
   * @return the full message, or empty
   */
  public Optional<String> fullMessage() {
    return Optional.ofNullable(fullMessage);
  }

  /**
   * Returns the event time.
   *
   * @return the timestamp, or empty (the server's receive time is used)
   */
  public Optional<Instant> timestamp() {
    return Optional.ofNullable(timestamp);
  }

  /**
   * Returns the syslog level.
   *
   * @return the level 0..7, or empty when not sent
   */
  public OptionalInt level() {
    return level == null ? OptionalInt.empty() : OptionalInt.of(level);
  }

  /**
   * Returns the additional fields (keys with the {@code _} prefix), sorted.
   *
   * @return immutable map
   */
  public Map<String, Object> fields() {
    return fields;
  }

  /**
   * Returns the GELF wire object: version, host, short_message and, when set, full_message,
   * timestamp, level and the additional fields (sorted keys).
   *
   * @return a new sorted map
   */
  public Map<String, Object> toMap() {
    Map<String, Object> doc = new TreeMap<>(fields);
    doc.put("version", Gelf.VERSION);
    doc.put("host", host);
    doc.put("short_message", shortMessage);
    if (fullMessage != null) {
      doc.put("full_message", fullMessage);
    }
    if (timestamp != null) {
      doc.put("timestamp", Gelf.timestamp(timestamp));
    }
    if (level != null) {
      doc.put("level", level);
    }
    return new LinkedHashMap<>(doc);
  }

  /**
   * Returns the UTF-8 JSON bytes.
   *
   * @return the encoded message
   */
  public byte[] encode() {
    return Json.encode(toMap());
  }

  /**
   * Returns the compact JSON text.
   *
   * @return the JSON
   */
  @Override
  public String toString() {
    return Json.stringify(toMap());
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof GelfMessage && toMap().equals(((GelfMessage) o).toMap());
  }

  @Override
  public int hashCode() {
    return toMap().hashCode();
  }

  /** Builder of a {@link GelfMessage}. */
  public static final class Builder {
    private final String host;
    private final String shortMessage;
    private String fullMessage;
    private Instant timestamp;
    private Integer level;
    private final Map<String, Object> fields = new TreeMap<>();

    private Builder(String host, String shortMessage) {
      this.host = host;
      this.shortMessage = shortMessage;
    }

    /**
     * Sets a long message (for example a stack trace).
     *
     * @param fullMessage text, {@code null} to unset
     * @return this builder
     */
    public Builder fullMessage(String fullMessage) {
      this.fullMessage = fullMessage == null || fullMessage.isEmpty() ? null : fullMessage;
      return this;
    }

    /**
     * Sets the event time (sent as Unix seconds with millisecond precision).
     *
     * @param timestamp instant, {@code null} for the server's receive time
     * @return this builder
     */
    public Builder timestamp(Instant timestamp) {
      this.timestamp = timestamp;
      return this;
    }

    /**
     * Sets the syslog level.
     *
     * @param level 0..7
     * @return this builder
     */
    public Builder level(int level) {
      this.level = level;
      return this;
    }

    /**
     * Sets an additional field ({@code name} or {@code _name}); the key is validated with {@link
     * Gelf#validateFieldKey}, the value mapped with {@link Gelf#fieldValue}. A {@code null} value
     * removes the field.
     *
     * @param key field key
     * @param value field value
     * @return this builder
     * @throws ValidationException for an invalid key
     */
    public Builder field(String key, Object value) {
      String wireKey = Gelf.validateFieldKey(key);
      Optional<Object> v = Gelf.fieldValue(value);
      if (v.isPresent()) {
        fields.put(wireKey, v.get());
      } else {
        fields.remove(wireKey);
      }
      return this;
    }

    /**
     * Sets several additional fields (see {@link #field(String, Object)}), in key order.
     *
     * @param fields fields
     * @return this builder
     */
    public Builder fields(Map<String, ?> fields) {
      new TreeMap<>(Objects.requireNonNull(fields, "fields")).forEach(this::field);
      return this;
    }

    /**
     * Validates and builds the message.
     *
     * @return the message
     * @throws ValidationException for a blank host or short message or a level outside 0..7
     */
    public GelfMessage build() {
      if (host == null || host.isBlank()) {
        throw new ValidationException("gelf: host must not be blank");
      }
      if (shortMessage == null || shortMessage.isBlank()) {
        throw new ValidationException("gelf: shortMessage must not be blank");
      }
      if (level != null && (level < 0 || level > 7)) {
        throw new ValidationException("gelf: level must be an integer 0..7");
      }
      return new GelfMessage(host, shortMessage, fullMessage, timestamp, level, fields);
    }
  }
}
