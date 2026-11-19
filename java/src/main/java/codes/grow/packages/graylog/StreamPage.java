package codes.grow.packages.graylog;

import java.util.List;

/**
 * One page of streams.
 *
 * @param streams the streams
 * @param total number of streams matching the query
 * @param page 1-based page
 * @param perPage page size
 */
public record StreamPage(List<GraylogStream> streams, int total, int page, int perPage) {
  /** Copies the list. */
  public StreamPage {
    streams = streams == null ? List.of() : List.copyOf(streams);
  }
}
