package codes.grow.packages.graylog;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * A Graylog message input.
 *
 * @param id input id
 * @param title title
 * @param type input class, e.g. {@link InputTypes#GELF_TCP}
 * @param name type display name
 * @param global whether it runs on every node
 * @param node node id of a node-local input (empty for global inputs)
 * @param createdAt creation time
 * @param creatorUserId creator
 * @param attributes input configuration; secret attributes come back as {@code {"is_set": bool}}
 *     maps, never as values
 * @param staticFields static fields added to every message
 */
public record GraylogInput(
    String id,
    String title,
    String type,
    String name,
    boolean global,
    String node,
    Optional<Instant> createdAt,
    String creatorUserId,
    Map<String, Object> attributes,
    Map<String, String> staticFields) {
  /**
   * Returns the {@code port} attribute.
   *
   * @return the port, or 0 when absent
   */
  public int port() {
    Object v = attributes.get("port");
    if (v instanceof Number) {
      return ((Number) v).intValue();
    }
    try {
      return v == null ? 0 : Integer.parseInt(v.toString().trim());
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  /**
   * Returns the {@code bind_address} attribute.
   *
   * @return the bind address, or empty
   */
  public Optional<String> bindAddress() {
    Object v = attributes.get("bind_address");
    return v instanceof String && !((String) v).isEmpty()
        ? Optional.of((String) v)
        : Optional.empty();
  }

  static GraylogInput from(JsonNode n) {
    return new GraylogInput(
        Nodes.text(n, "id"),
        Nodes.text(n, "title"),
        Nodes.text(n, "type"),
        Nodes.text(n, "name"),
        Nodes.bool(n, "global"),
        Nodes.text(n, "node"),
        Nodes.instant(n, "created_at"),
        Nodes.text(n, "creator_user_id"),
        Nodes.map(n.get("attributes")),
        Nodes.stringMap(n.get("static_fields")));
  }
}
