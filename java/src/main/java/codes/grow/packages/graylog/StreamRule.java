package codes.grow.packages.graylog;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One rule of a stream.
 *
 * @param id rule id (empty for new rules)
 * @param field message field
 * @param type rule type (see the {@code TYPE_*} constants)
 * @param value value to compare
 * @param inverted negate the rule
 * @param description description
 */
public record StreamRule(
    String id, String field, int type, String value, boolean inverted, String description) {
  /** Exact match. */
  public static final int TYPE_EXACT = 1;

  /** Regular expression. */
  public static final int TYPE_REGEX = 2;

  /** Greater than. */
  public static final int TYPE_GREATER = 3;

  /** Smaller than. */
  public static final int TYPE_SMALLER = 4;

  /** Field presence. */
  public static final int TYPE_PRESENCE = 5;

  /** Contains. */
  public static final int TYPE_CONTAINS = 6;

  /** Always match. */
  public static final int TYPE_ALWAYS_MATCH = 7;

  /** Match input. */
  public static final int TYPE_MATCH_INPUT = 8;

  /** Normalises {@code null} strings to empty. */
  public StreamRule {
    id = id == null ? "" : id;
    field = field == null ? "" : field;
    value = value == null ? "" : value;
    description = description == null ? "" : description;
  }

  /**
   * Creates a new rule.
   *
   * @param field message field
   * @param type rule type
   * @param value value
   * @return the rule
   */
  public static StreamRule of(String field, int type, String value) {
    return new StreamRule("", field, type, value, false, "");
  }

  Map<String, Object> toWire() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("field", field);
    m.put("type", type);
    m.put("value", value);
    m.put("inverted", inverted);
    m.put("description", description);
    return m;
  }

  static StreamRule from(JsonNode n) {
    return new StreamRule(
        Nodes.text(n, "id"),
        Nodes.text(n, "field"),
        (int) Nodes.number(n, "type", 0),
        Nodes.text(n, "value"),
        Nodes.bool(n, "inverted"),
        Nodes.text(n, "description"));
  }
}
