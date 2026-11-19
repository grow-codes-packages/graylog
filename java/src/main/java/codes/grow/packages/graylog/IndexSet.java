package codes.grow.packages.graylog;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A Graylog index set.
 *
 * @param id index set id
 * @param title title
 * @param description description
 * @param indexPrefix index prefix
 * @param isDefault whether this is the default index set
 * @param writable whether it accepts writes
 * @param shards shards per index
 * @param replicas replicas per index
 */
public record IndexSet(
    String id,
    String title,
    String description,
    String indexPrefix,
    boolean isDefault,
    boolean writable,
    int shards,
    int replicas) {
  static IndexSet from(JsonNode n) {
    return new IndexSet(
        Nodes.text(n, "id"),
        Nodes.text(n, "title"),
        Nodes.text(n, "description"),
        Nodes.text(n, "index_prefix"),
        Nodes.bool(n, "default"),
        Nodes.bool(n, "writable"),
        (int) Nodes.number(n, "shards", 0),
        (int) Nodes.number(n, "replicas", 0));
  }
}
