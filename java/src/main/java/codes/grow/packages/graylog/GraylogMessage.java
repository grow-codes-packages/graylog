package codes.grow.packages.graylog;

import codes.grow.packages.graylog.logging.LogRecord;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * One search hit or stored message.
 *
 * @param id message id ({@code _id}); with {@code index} it identifies the message for {@link
 *     GraylogClient#getMessage(String, String)}
 * @param index index that stores the message
 * @param timestamp message timestamp
 * @param fields every returned field (numbers are {@code Long} or {@code Double})
 */
public record GraylogMessage(
    String id, String index, Optional<Instant> timestamp, Map<String, Object> fields) {
  /** Normalises {@code null} values. */
  public GraylogMessage {
    id = id == null ? "" : id;
    index = index == null ? "" : index;
    timestamp = timestamp == null ? Optional.empty() : timestamp;
    fields = fields == null ? Map.of() : fields;
  }

  /**
   * Normalises the message into a log record (see {@link GraylogRecords#fromMessage(Map)}).
   *
   * @return the record
   */
  public LogRecord toLogRecord() {
    return GraylogRecords.fromMessage(fields);
  }

  static GraylogMessage of(Map<String, Object> fields, String index) {
    Object id = fields.get("_id");
    Object ts = fields.get("timestamp");
    return new GraylogMessage(
        id instanceof String ? (String) id : "",
        index,
        ts instanceof String ? Nodes.parseTime((String) ts) : Optional.empty(),
        fields);
  }
}
