package codes.grow.packages.graylog;

import codes.grow.packages.graylog.logging.SortOrder;
import java.util.Optional;

/**
 * Options of {@link GraylogClient#listStreams(ListStreamsOptions)}.
 *
 * @param page 1-based page (default 1)
 * @param perPage page size (default 50)
 * @param query Graylog stream search text (title/description)
 * @param sort sort field (default {@code title})
 * @param order order (default ascending)
 */
public record ListStreamsOptions(
    int page, int perPage, Optional<String> query, String sort, SortOrder order) {
  /** Applies the defaults to zero and {@code null} values. */
  public ListStreamsOptions {
    page = page == 0 ? 1 : page;
    perPage = perPage == 0 ? 50 : perPage;
    query = query == null ? Optional.empty() : query.filter(q -> !q.isEmpty());
    sort = sort == null || sort.isEmpty() ? "title" : sort;
    order = order == null ? SortOrder.ASC : order;
  }

  /**
   * Returns the defaults (page 1, 50 per page, title ascending).
   *
   * @return default options
   */
  public static ListStreamsOptions defaults() {
    return new ListStreamsOptions(0, 0, null, null, null);
  }

  /**
   * Returns options for one page.
   *
   * @param page 1-based page
   * @param perPage page size
   * @return the options
   */
  public static ListStreamsOptions page(int page, int perPage) {
    return new ListStreamsOptions(page, perPage, null, null, null);
  }

  /**
   * Returns a copy with a search query.
   *
   * @param query query text
   * @return the options
   */
  public ListStreamsOptions withQuery(String query) {
    return new ListStreamsOptions(page, perPage, Optional.ofNullable(query), sort, order);
  }

  /**
   * Returns a copy with a sort field and order.
   *
   * @param sort sort field
   * @param order order
   * @return the options
   */
  public ListStreamsOptions withSort(String sort, SortOrder order) {
    return new ListStreamsOptions(page, perPage, query, sort, order);
  }
}
