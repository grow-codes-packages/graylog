package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.Json;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.Optional;

/**
 * Runtime state of an input ({@code GET /api/system/inputstates/{id}}).
 *
 * @param id input id
 * @param state {@code RUNNING}, {@code STARTING}, {@code FAILED}, {@code STOPPED}, ...
 * @param startedAt start time
 * @param detailedMessage failure details
 * @param input the input
 */
public record InputState(
    String id,
    String state,
    Optional<Instant> startedAt,
    Optional<String> detailedMessage,
    GraylogInput input) {
  static InputState from(JsonNode n) {
    JsonNode in = n.get("message_input");
    return new InputState(
        Nodes.text(n, "id"),
        Nodes.text(n, "state"),
        Nodes.instant(n, "started_at"),
        Nodes.optText(n, "detailed_message"),
        GraylogInput.from(in != null && in.isObject() ? in : Json.mapper().createObjectNode()));
  }
}
