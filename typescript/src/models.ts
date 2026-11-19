// Service-owned: typed models of the Graylog REST API (camelCase) and their decoders.

import { UnavailableError } from "./core/index.js";

/** Input class names of the GELF inputs. */
export const GELF_INPUT_TYPES = Object.freeze({
  udp: "org.graylog2.inputs.gelf.udp.GELFUDPInput",
  tcp: "org.graylog2.inputs.gelf.tcp.GELFTCPInput",
  http: "org.graylog2.inputs.gelf.http.GELFHttpInput",
} as const);

/** Input class name of the OpenTelemetry (gRPC) input. */
export const OTLP_GRPC_INPUT_TYPE = "org.graylog.inputs.otel.OTelGrpcInput";

/** `GET /api/system` (`systemInfo()`). */
export interface SystemInfo {
  facility: string;
  codename: string;
  nodeId: string;
  clusterId: string;
  /** As reported, e.g. `7.0.16+58e0f6e`. */
  version: string;
  startedAt: Date | null;
  hostname: string;
  lifecycle: string;
  lbStatus: string;
  timezone: string;
  operatingSystem: string;
  isLeader: boolean;
  isProcessing: boolean;
}

/** A configured input (`GET /api/system/inputs`). */
export interface GraylogInput {
  id: string;
  title: string;
  /** Input class, e.g. {@link GELF_INPUT_TYPES}.tcp. */
  type: string;
  /** Human name of the type, e.g. `GELF TCP`. */
  name: string;
  global: boolean;
  /** Node id for node-local inputs, `null` for global ones. */
  node: string | null;
  createdAt: Date | null;
  creatorUserId: string | null;
  /** Configuration as returned (secret values come back as `{ is_set }` objects). */
  attributes: Record<string, unknown>;
  staticFields: Record<string, string>;
  /** `attributes.port` when numeric. */
  port: number | null;
  /** `attributes.bind_address` when present. */
  bindAddress: string | null;
}

/** Runtime state of an input (`GET /api/system/inputstates/{id}`). */
export interface InputState {
  id: string;
  /** `RUNNING`, `STARTING`, `FAILED`, `STOPPED`, … */
  state: string;
  startedAt: Date | null;
  detailedMessage: string | null;
  input: GraylogInput | null;
}

/** A stream rule. `type`: 1 exact, 2 regex, 3 greater, 4 smaller, 5 presence, 6 contain, 7 always, 8 input. */
export interface StreamRule {
  id?: string;
  field: string;
  type: number;
  value: string;
  inverted: boolean;
  description: string;
}

/** A stream. */
export interface GraylogStream {
  id: string;
  title: string;
  description: string;
  disabled: boolean;
  indexSetId: string;
  isDefault: boolean;
  /** `AND` or `OR`. */
  matchingType: string;
  removeMatchesFromDefaultStream: boolean;
  rules: StreamRule[];
  createdAt: Date | null;
  creatorUserId: string | null;
}

/** One page of `GET /api/streams/paginated`. */
export interface StreamPage {
  streams: GraylogStream[];
  /** Streams matching the query. */
  total: number;
  /** 1-based page number. */
  page: number;
  perPage: number;
}

/** An index set (`GET /api/system/indices/index_sets`). */
export interface IndexSet {
  id: string;
  title: string;
  description: string;
  indexPrefix: string;
  /** Whether this is the default index set. */
  isDefault: boolean;
  writable: boolean;
  shards: number;
  replicas: number;
  createdAt: Date | null;
}

/** A stored message (search hit or `getMessage`). */
export interface GraylogMessage {
  /** Message id (`_id`). */
  id: string;
  /** OpenSearch index holding it (pass to `getMessage`). */
  index: string;
  timestamp: Date | null;
  /** Every stored field (including `message`, `source`, `timestamp`, `gl2_*`). */
  fields: Record<string, unknown>;
}

/** Result of `search()` / `searchRelative()`. */
export interface SearchResult {
  messages: GraylogMessage[];
  /** Total matches in the time range (may exceed `messages.length`). */
  total: number;
  /** Resolved time range. */
  from: Date | null;
  to: Date | null;
  /** Offset of the next page, when more results exist. */
  nextOffset?: number;
}

type Json = Record<string, unknown>;

function obj(v: unknown): Json {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {};
}
function str(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}
function strOrNull(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}
function num(v: unknown, fallback = 0): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}
function bool(v: unknown): boolean {
  return v === true;
}
/** Parses an ISO date; `null` when absent or invalid. */
export function dateOrNull(v: unknown): Date | null {
  if (typeof v !== "string") return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : new Date(t);
}

/** Throws when a JSON body is not an object (unexpected response). */
export function expectObject(data: unknown, operation: string): Json {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new UnavailableError(`${operation}: unexpected response`, { retryable: false });
  }
  return data as Json;
}

/** @internal */
export function decodeSystemInfo(v: unknown): SystemInfo {
  const o = obj(v);
  return {
    facility: str(o.facility),
    codename: str(o.codename),
    nodeId: str(o.node_id),
    clusterId: str(o.cluster_id),
    version: str(o.version),
    startedAt: dateOrNull(o.started_at),
    hostname: str(o.hostname),
    lifecycle: str(o.lifecycle),
    lbStatus: str(o.lb_status),
    timezone: str(o.timezone),
    operatingSystem: str(o.operating_system),
    isLeader: bool(o.is_leader),
    isProcessing: bool(o.is_processing),
  };
}

/** @internal */
export function decodeInput(v: unknown): GraylogInput {
  const o = obj(v);
  const attributes = obj(o.attributes);
  const staticFields: Record<string, string> = {};
  for (const [k, val] of Object.entries(obj(o.static_fields))) staticFields[k] = String(val);
  return {
    id: str(o.id),
    title: str(o.title),
    type: str(o.type),
    name: str(o.name),
    global: bool(o.global),
    node: strOrNull(o.node),
    createdAt: dateOrNull(o.created_at),
    creatorUserId: strOrNull(o.creator_user_id),
    attributes,
    staticFields,
    port: typeof attributes.port === "number" ? attributes.port : null,
    bindAddress: strOrNull(attributes.bind_address),
  };
}

/** @internal */
export function decodeInputState(v: unknown): InputState {
  const o = obj(v);
  return {
    id: str(o.id),
    state: str(o.state, "UNKNOWN"),
    startedAt: dateOrNull(o.started_at),
    detailedMessage: strOrNull(o.detailed_message),
    input:
      o.message_input === undefined || o.message_input === null
        ? null
        : decodeInput(o.message_input),
  };
}

/** @internal */
export function decodeStreamRule(v: unknown): StreamRule {
  const o = obj(v);
  const rule: StreamRule = {
    field: str(o.field),
    type: num(o.type),
    value:
      typeof o.value === "string"
        ? o.value
        : typeof o.value === "number" || typeof o.value === "boolean"
          ? String(o.value)
          : "",
    inverted: bool(o.inverted),
    description: str(o.description),
  };
  if (typeof o.id === "string") rule.id = o.id;
  return rule;
}

/** @internal */
export function decodeStream(v: unknown): GraylogStream {
  const o = obj(v);
  return {
    id: str(o.id),
    title: str(o.title),
    description: str(o.description),
    disabled: bool(o.disabled),
    indexSetId: str(o.index_set_id),
    isDefault: bool(o.is_default),
    matchingType: str(o.matching_type, "AND"),
    removeMatchesFromDefaultStream: bool(o.remove_matches_from_default_stream),
    rules: Array.isArray(o.rules) ? o.rules.map(decodeStreamRule) : [],
    createdAt: dateOrNull(o.created_at),
    creatorUserId: strOrNull(o.creator_user_id),
  };
}

/** @internal */
export function decodeIndexSet(v: unknown): IndexSet {
  const o = obj(v);
  return {
    id: str(o.id),
    title: str(o.title),
    description: str(o.description),
    indexPrefix: str(o.index_prefix),
    isDefault: bool(o.default),
    writable: bool(o.writable),
    shards: num(o.shards),
    replicas: num(o.replicas),
    createdAt: dateOrNull(o.creation_date),
  };
}

/** Decodes a stored message from its field map plus index. @internal */
export function decodeMessage(fields: unknown, index: unknown): GraylogMessage {
  const f = obj(fields);
  return {
    id: str(f._id, str(f.id)),
    index: str(index),
    timestamp: dateOrNull(f.timestamp),
    fields: f,
  };
}
