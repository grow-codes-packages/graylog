package codes.grow.packages.graylog;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * A Graylog stream.
 *
 * @param id stream id
 * @param title title
 * @param description description
 * @param rules rules
 * @param disabled whether the stream is paused
 * @param indexSetId target index set
 * @param isDefault whether this is the default stream
 * @param matchingType {@code AND} or {@code OR}
 * @param removeMatchesFromDefaultStream whether matches leave the default stream
 * @param createdAt creation time
 * @param creatorUserId creator
 */
public record GraylogStream(
    String id,
    String title,
    String description,
    List<StreamRule> rules,
    boolean disabled,
    String indexSetId,
    boolean isDefault,
    String matchingType,
    boolean removeMatchesFromDefaultStream,
    Optional<Instant> createdAt,
    String creatorUserId) {
  static GraylogStream from(JsonNode n) {
    return new GraylogStream(
        Nodes.text(n, "id"),
        Nodes.text(n, "title"),
        Nodes.text(n, "description"),
        Nodes.array(n, "rules").stream().map(StreamRule::from).toList(),
        Nodes.bool(n, "disabled"),
        Nodes.text(n, "index_set_id"),
        Nodes.bool(n, "is_default"),
        Nodes.text(n, "matching_type"),
        Nodes.bool(n, "remove_matches_from_default_stream"),
        Nodes.instant(n, "created_at"),
        Nodes.text(n, "creator_user_id"));
  }
}
