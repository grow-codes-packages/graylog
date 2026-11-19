package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.AuthenticationException;
import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.ConflictException;
import codes.grow.packages.graylog.core.GraylogException;
import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.NotFoundException;
import codes.grow.packages.graylog.core.PermissionDeniedException;
import codes.grow.packages.graylog.core.RateLimitException;
import codes.grow.packages.graylog.core.Redaction;
import codes.grow.packages.graylog.core.SdkInfo;
import codes.grow.packages.graylog.core.TimeoutException;
import codes.grow.packages.graylog.core.UnavailableException;
import codes.grow.packages.graylog.core.UnsupportedException;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.LogRecord;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * OTLP logs wire helpers for the Graylog OpenTelemetry (gRPC) input: a small hand-written protobuf
 * encoder for {@code ExportLogsServiceRequest}, the partial-success decoder and the gRPC status
 * mapping.
 */
public final class Otlp {
  /** gRPC method path of the OTLP logs service. */
  public static final String LOGS_EXPORT_PATH =
      "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

  /** Instrumentation scope name written into every export. */
  public static final String SCOPE_NAME = "grow-codes-graylog";

  private Otlp() {}

  /**
   * Partial success of an {@code ExportLogsServiceResponse}.
   *
   * @param rejectedLogRecords number of rejected records
   * @param errorMessage server message (may be empty)
   */
  public record PartialSuccess(long rejectedLogRecords, String errorMessage) {}

  /**
   * Encodes records as one {@code ExportLogsServiceRequest}: one {@code ResourceLogs} per distinct
   * resource (first-seen order) with one {@code ScopeLogs} each.
   *
   * @param records records
   * @return the protobuf bytes
   */
  public static byte[] encodeExportLogsRequest(List<LogRecord> records) {
    Map<String, List<LogRecord>> groups = new LinkedHashMap<>();
    for (LogRecord r : records) {
      groups.computeIfAbsent(Json.stringify(r.resource()), k -> new ArrayList<>()).add(r);
    }
    ProtoWriter w = new ProtoWriter();
    for (List<LogRecord> group : groups.values()) {
      Map<String, Object> resource = group.get(0).resource();
      w.message(
          1,
          rl -> {
            rl.message(
                1, res -> resource.forEach((k, v) -> res.message(1, kv -> keyValue(kv, k, v))));
            rl.message(
                2,
                sl -> {
                  sl.message(1, sc -> sc.string(1, SCOPE_NAME).string(2, SdkInfo.VERSION));
                  for (LogRecord r : group) {
                    sl.message(2, lr -> logRecord(lr, r));
                  }
                });
          });
    }
    return w.finish();
  }

  private static void logRecord(ProtoWriter lr, LogRecord r) {
    long ts = nanos(r.timestamp());
    if (ts != 0) {
      lr.fixed64(1, ts);
    }
    lr.varint(2, r.severity().number());
    lr.string(3, r.severityText());
    lr.message(5, av -> av.string(1, r.body()));
    r.attributes().forEach((k, v) -> lr.message(6, kv -> keyValue(kv, k, v)));
    if (r.traceFlags().isPresent()) {
      lr.fixed32(8, r.traceFlags().getAsInt());
    }
    r.traceId().ifPresent(id -> lr.bytes(9, HexFormat.of().parseHex(id)));
    r.spanId().ifPresent(id -> lr.bytes(10, HexFormat.of().parseHex(id)));
    long observed = r.observedTimestamp().map(Otlp::nanos).orElse(ts);
    if (observed != 0) {
      lr.fixed64(11, observed);
    }
  }

  private static long nanos(Instant t) {
    return t.getEpochSecond() * 1_000_000_000L + t.getNano();
  }

  private static void keyValue(ProtoWriter kv, String key, Object value) {
    kv.string(1, key);
    kv.message(2, av -> anyValue(av, value));
  }

  private static void anyValue(ProtoWriter w, Object value) {
    if (value instanceof Boolean) {
      w.varint(2, ((Boolean) value) ? 1 : 0);
    } else if (value instanceof Long || value instanceof Integer) {
      w.varint(3, ((Number) value).longValue());
    } else if (value instanceof Double || value instanceof Float) {
      w.double64(4, ((Number) value).doubleValue());
    } else if (value instanceof List) {
      w.message(
          5,
          arr -> {
            for (Object item : (List<?>) value) {
              arr.message(1, iv -> anyValue(iv, item));
            }
          });
    } else if (value instanceof Map) {
      w.message(
          6,
          kvl -> {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
              kvl.message(1, kv -> keyValue(kv, String.valueOf(e.getKey()), e.getValue()));
            }
          });
    } else {
      w.string(1, String.valueOf(value));
    }
  }

  /**
   * Decodes {@code ExportLogsServiceResponse.partial_success}; zero values when absent or
   * malformed.
   *
   * @param buf response message bytes
   * @return the partial success
   */
  public static PartialSuccess decodePartialSuccess(byte[] buf) {
    long rejected = 0;
    String message = "";
    try {
      ProtoReader outer = new ProtoReader(buf);
      while (outer.next()) {
        if (outer.field == 1 && outer.wire == 2) {
          ProtoReader inner = new ProtoReader(outer.bytes);
          while (inner.next()) {
            if (inner.field == 1 && inner.wire == 0) {
              rejected = inner.varint;
            } else if (inner.field == 2 && inner.wire == 2) {
              message = new String(inner.bytes, StandardCharsets.UTF_8);
            }
          }
        }
      }
    } catch (IllegalArgumentException e) {
      return new PartialSuccess(0, "");
    }
    return new PartialSuccess(rejected, message);
  }

  /**
   * Maps a gRPC status to the SDK error: CANCELLED (1), INVALID_ARGUMENT/FAILED_PRECONDITION (3, 9)
   * VALIDATION, DEADLINE_EXCEEDED (4) TIMEOUT, NOT_FOUND (5), ALREADY_EXISTS (6) CONFLICT,
   * PERMISSION_DENIED (7), RESOURCE_EXHAUSTED (8) RATE_LIMITED, UNIMPLEMENTED (12) UNSUPPORTED,
   * UNAUTHENTICATED (16) AUTHENTICATION; ABORTED, OUT_OF_RANGE, UNAVAILABLE and DATA_LOSS (10, 11,
   * 14, 15) retryable UNAVAILABLE; anything else non-retryable UNAVAILABLE.
   *
   * @param status gRPC status code
   * @param message status message (already redacted)
   * @return the exception
   */
  public static GraylogException errorForGrpcStatus(int status, String message) {
    String text =
        "otlp.export: "
            + Redaction.truncate(
                message == null || message.isEmpty() ? "gRPC status " + status : message,
                Redaction.MAX_VENDOR_TEXT)
            + " (gRPC "
            + status
            + ")";
    switch (status) {
      case 1:
        return new CancelledException(text);
      case 3:
      case 9:
        return new ValidationException(text);
      case 4:
        return new TimeoutException(text);
      case 5:
        return new NotFoundException(text);
      case 6:
        return new ConflictException(text);
      case 7:
        return new PermissionDeniedException(text);
      case 8:
        return new RateLimitException(text);
      case 12:
        return new UnsupportedException(text);
      case 16:
        return new AuthenticationException(text);
      case 10:
      case 11:
      case 14:
      case 15:
        return new UnavailableException(text);
      default:
        return new PermanentUnavailableException(text);
    }
  }

  /** An UNAVAILABLE error that must not be retried (unknown gRPC status). */
  static final class PermanentUnavailableException extends UnavailableException {
    private static final long serialVersionUID = 1L;

    PermanentUnavailableException(String message) {
      super(message, null, null, false, null, null);
    }
  }

  /** Minimal protobuf writer (varint, fixed32/64, double, length-delimited). */
  static final class ProtoWriter {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    private void rawVarint(long value) {
      long v = value;
      while ((v & ~0x7FL) != 0) {
        out.write((int) ((v & 0x7F) | 0x80));
        v >>>= 7;
      }
      out.write((int) v);
    }

    private void tag(int field, int wire) {
      rawVarint(((long) field << 3) | wire);
    }

    ProtoWriter varint(int field, long value) {
      tag(field, 0);
      rawVarint(value);
      return this;
    }

    ProtoWriter fixed64(int field, long value) {
      tag(field, 1);
      out.writeBytes(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array());
      return this;
    }

    ProtoWriter fixed32(int field, int value) {
      tag(field, 5);
      out.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
      return this;
    }

    ProtoWriter double64(int field, double value) {
      return fixed64(field, Double.doubleToLongBits(value));
    }

    ProtoWriter bytes(int field, byte[] value) {
      tag(field, 2);
      rawVarint(value.length);
      out.writeBytes(value);
      return this;
    }

    ProtoWriter string(int field, String value) {
      return bytes(field, value.getBytes(StandardCharsets.UTF_8));
    }

    ProtoWriter message(int field, Consumer<ProtoWriter> build) {
      ProtoWriter inner = new ProtoWriter();
      build.accept(inner);
      return bytes(field, inner.finish());
    }

    byte[] finish() {
      return out.toByteArray();
    }
  }

  /** Minimal protobuf reader: iterates fields (varint and length-delimited values kept). */
  static final class ProtoReader {
    private final byte[] buf;
    private int pos;
    int field;
    int wire;
    long varint;
    byte[] bytes;

    ProtoReader(byte[] buf) {
      this.buf = buf;
    }

    private long readVarint() {
      long result = 0;
      for (int shift = 0; shift < 64; shift += 7) {
        if (pos >= buf.length) {
          throw new IllegalArgumentException("truncated varint");
        }
        int b = buf[pos++] & 0xFF;
        result |= (long) (b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
          return result;
        }
      }
      throw new IllegalArgumentException("varint too long");
    }

    boolean next() {
      if (pos >= buf.length) {
        return false;
      }
      long tag = readVarint();
      field = (int) (tag >>> 3);
      wire = (int) (tag & 7);
      switch (wire) {
        case 0:
          varint = readVarint();
          break;
        case 1:
          skip(8);
          break;
        case 2:
          long len = readVarint();
          if (len < 0 || len > buf.length - pos) {
            throw new IllegalArgumentException("truncated field");
          }
          bytes = new byte[(int) len];
          System.arraycopy(buf, pos, bytes, 0, (int) len);
          pos += (int) len;
          break;
        case 5:
          skip(4);
          break;
        default:
          throw new IllegalArgumentException("unsupported wire type " + wire);
      }
      return true;
    }

    private void skip(int n) {
      if (n > buf.length - pos) {
        throw new IllegalArgumentException("truncated field");
      }
      pos += n;
    }
  }
}
