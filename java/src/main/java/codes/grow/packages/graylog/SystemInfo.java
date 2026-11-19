package codes.grow.packages.graylog;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.Optional;

/**
 * Node information from {@code GET /api/system}.
 *
 * @param facility facility name
 * @param codename release code name
 * @param nodeId node id
 * @param clusterId cluster id
 * @param version full version, e.g. {@code 7.0.16+58e0f6e}
 * @param startedAt node start time
 * @param hostname node host name
 * @param lifecycle lifecycle state
 * @param lbStatus load-balancer status
 * @param timezone server time zone
 * @param operatingSystem operating system
 * @param isLeader whether the node is the leader
 * @param isProcessing whether the node processes messages
 */
public record SystemInfo(
    String facility,
    String codename,
    String nodeId,
    String clusterId,
    String version,
    Optional<Instant> startedAt,
    String hostname,
    String lifecycle,
    String lbStatus,
    String timezone,
    String operatingSystem,
    boolean isLeader,
    boolean isProcessing) {
  static SystemInfo from(JsonNode n) {
    return new SystemInfo(
        Nodes.text(n, "facility"),
        Nodes.text(n, "codename"),
        Nodes.text(n, "node_id"),
        Nodes.text(n, "cluster_id"),
        Nodes.text(n, "version"),
        Nodes.instant(n, "started_at"),
        Nodes.text(n, "hostname"),
        Nodes.text(n, "lifecycle"),
        Nodes.text(n, "lb_status"),
        Nodes.text(n, "timezone"),
        Nodes.text(n, "operating_system"),
        Nodes.bool(n, "is_leader"),
        Nodes.bool(n, "is_processing"));
  }
}
