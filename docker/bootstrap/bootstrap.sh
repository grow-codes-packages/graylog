#!/bin/sh
# Graylog 7.0 bootstrap for the grow-graylog SDK integration suite (GRO-1373).
#
# Runs once in the `bootstrap` service (curlimages/curl, busybox sh) after graylog is healthy:
#   1. waits for /api/system/lbstatus = ALIVE and an authenticated /api/system,
#   2. ensures global inputs (matched by title, so re-runs reuse them):
#        GELF UDP 12201/udp, GELF TCP 12201/tcp (NUL framing), GELF HTTP 12202/tcp (bulk on),
#        OpenTelemetry gRPC 4317/tcp (only when the input type is installed),
#      and waits until each one is RUNNING,
#   3. reuses the API token from an earlier run when it still authenticates, else creates one,
#   4. writes KEY=value lines to /bootstrap/env (atomic replace, mode 0644).
#
# Never prints the password or the token.
set -eu

URL="${GRAYLOG_INIT_URL:-http://graylog:9000}"
USER_NAME="${GRAYLOG_INIT_USER:-admin}"
PASSWORD="${GRAYLOG_INIT_PASSWORD:?GRAYLOG_INIT_PASSWORD is required}"
OUT_DIR="${BOOTSTRAP_DIR:-/bootstrap}"
OUT="$OUT_DIR/env"
GELF_HOST="${GRAYLOG_GELF_HOST_NAME:-graylog}"
WAIT_SECONDS="${BOOTSTRAP_WAIT_SECONDS:-300}"

log() { printf 'bootstrap: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# api METHOD PATH [JSON]  -> body on stdout, HTTP status in $API_STATUS (file), never fails the shell.
STATUS_FILE="$(mktemp)"
BODY_FILE="$(mktemp)"
trap 'rm -f "$STATUS_FILE" "$BODY_FILE"' EXIT
api() {
  _m="$1"; _p="$2"; _d="${3:-}"
  if [ -n "$_d" ]; then
    curl -sS -o "$BODY_FILE" -w '%{http_code}' -u "$USER_NAME:$PASSWORD" -X "$_m" \
      -H 'Accept: application/json' -H 'Content-Type: application/json' \
      -H 'X-Requested-By: grow-sdk-bootstrap' --data "$_d" "$URL$_p" >"$STATUS_FILE" 2>/dev/null || echo 000 >"$STATUS_FILE"
  else
    curl -sS -o "$BODY_FILE" -w '%{http_code}' -u "$USER_NAME:$PASSWORD" -X "$_m" \
      -H 'Accept: application/json' -H 'X-Requested-By: grow-sdk-bootstrap' \
      "$URL$_p" >"$STATUS_FILE" 2>/dev/null || echo 000 >"$STATUS_FILE"
  fi
  cat "$BODY_FILE" 2>/dev/null || true
}
status() { cat "$STATUS_FILE"; }

# --- 1. readiness ------------------------------------------------------------------------------
deadline=$(( $(date +%s) + WAIT_SECONDS ))
until [ "$(curl -s -H 'Accept: text/plain' "$URL/api/system/lbstatus" 2>/dev/null || true)" = "ALIVE" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || die "Graylog lbstatus did not become ALIVE within ${WAIT_SECONDS}s"
  sleep 2
done
until api GET /api/system >/dev/null && [ "$(status)" = "200" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || die "authenticated GET /api/system failed (HTTP $(status))"
  sleep 2
done
SYSTEM_JSON="$(api GET /api/system)"
VERSION="$(printf '%s' "$SYSTEM_JSON" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
log "Graylog $VERSION is ready"

# --- 2. inputs ---------------------------------------------------------------------------------
# input_id_by_title TITLE -> id or empty
input_id_by_title() {
  api GET /api/system/inputs | sed 's/{"title":/\n{"title":/g' | grep -F "{\"title\":\"$1\"" \
    | grep -o '"id":"[0-9a-f]\{24\}"' | head -n 1 | sed 's/"id":"\(.*\)"/\1/' || true
}

# ensure_input TITLE TYPE CONFIG_JSON -> prints id
ensure_input() {
  _title="$1"; _type="$2"; _conf="$3"
  _id="$(input_id_by_title "$_title")"
  if [ -z "$_id" ]; then
    _body="$(api POST /api/system/inputs "{\"title\":\"$_title\",\"type\":\"$_type\",\"global\":true,\"configuration\":$_conf}")"
    [ "$(status)" = "201" ] || die "create input '$_title' failed: HTTP $(status) $_body"
    _id="$(printf '%s' "$_body" | sed -n 's/.*"id":"\([0-9a-f]\{24\}\)".*/\1/p')"
    log "created input '$_title' ($_id)"
  else
    log "input '$_title' exists ($_id)"
  fi
  [ -n "$_id" ] || die "no id for input '$_title'"
  _dl=$(( $(date +%s) + 90 ))
  while :; do
    _st="$(api GET "/api/system/inputstates/$_id" | sed -n 's/^{"id":"[0-9a-f]*","state":"\([A-Z_]*\)".*/\1/p')"
    [ "$_st" = "RUNNING" ] && break
    [ "$(date +%s)" -lt "$_dl" ] || die "input '$_title' not RUNNING (state '${_st:-unknown}', HTTP $(status))"
    sleep 1
  done
  printf '%s' "$_id"
}

ID_GELF_UDP="$(ensure_input 'grow-sdk GELF UDP' org.graylog2.inputs.gelf.udp.GELFUDPInput \
  '{"bind_address":"0.0.0.0","port":12201,"recv_buffer_size":262144,"number_worker_threads":2,"decompress_size_limit":8388608}')"
ID_GELF_TCP="$(ensure_input 'grow-sdk GELF TCP' org.graylog2.inputs.gelf.tcp.GELFTCPInput \
  '{"bind_address":"0.0.0.0","port":12201,"recv_buffer_size":1048576,"number_worker_threads":2,"tls_enable":false,"tcp_keepalive":false,"use_null_delimiter":true,"max_message_size":2097152,"decompress_size_limit":8388608}')"
ID_GELF_HTTP="$(ensure_input 'grow-sdk GELF HTTP' org.graylog2.inputs.gelf.http.GELFHttpInput \
  '{"bind_address":"0.0.0.0","port":12202,"recv_buffer_size":1048576,"number_worker_threads":2,"tls_enable":false,"tcp_keepalive":false,"enable_bulk_receiving":true,"enable_cors":true,"max_chunk_size":8388608,"idle_writer_timeout":60,"decompress_size_limit":8388608}')"

ID_OTLP=""
if api GET /api/system/inputs/types | grep -q 'org.graylog.inputs.otel.OTelGrpcInput'; then
  ID_OTLP="$(ensure_input 'grow-sdk OTLP gRPC' org.graylog.inputs.otel.OTelGrpcInput \
    '{"bind_address":"0.0.0.0","port":4317,"insecure":true,"throttling_allowed":false,"max_inbound_msg_size":4194304}')"
else
  log "OpenTelemetry gRPC input type not installed; skipping OTLP input"
fi

# --- 3. API token ------------------------------------------------------------------------------
TOKEN=""
if [ -f "$OUT" ]; then
  TOKEN="$(sed -n 's/^GRAYLOG_API_TOKEN=//p' "$OUT" | head -n 1)"
  if [ -n "$TOKEN" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' -u "$TOKEN:token" -H 'Accept: application/json' "$URL/api/system" || true)"
    if [ "$code" = "200" ]; then log "reusing existing API token"; else TOKEN=""; fi
  fi
fi
if [ -z "$TOKEN" ]; then
  USER_ID="$(api GET "/api/users/$USER_NAME" | sed -n 's/^{"id":"\([^"]*\)".*/\1/p')"
  [ -n "$USER_ID" ] || die "cannot resolve user id of '$USER_NAME' (HTTP $(status))"
  TOKEN_NAME="grow-sdk-$(date +%s)"
  body="$(api POST "/api/users/$USER_ID/tokens/$TOKEN_NAME" '{"token_ttl":"P30D"}')"
  [ "$(status)" = "200" ] || die "token creation failed: HTTP $(status)"
  TOKEN="$(printf '%s' "$body" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "$TOKEN" ] || die "token missing in response"
  log "created API token '$TOKEN_NAME' for $USER_ID"
fi

# --- 4. ids + env file -------------------------------------------------------------------------
INDEX_SET_ID="$(api GET '/api/system/indices/index_sets?skip_stats=true' | sed 's/{"id":/\n{"id":/g' \
  | grep '"default":true' | head -n 1 | sed -n 's/^{"id":"\([0-9a-f]\{24\}\)".*/\1/p' || true)"
[ -n "$INDEX_SET_ID" ] || die "default index set not found"

mkdir -p "$OUT_DIR"
TMP="$OUT.tmp.$$"
umask 022
{
  echo "GRAYLOG_URL=$URL"
  echo "GRAYLOG_USER=$USER_NAME"
  echo "GRAYLOG_PASSWORD=$PASSWORD"
  echo "GRAYLOG_API_TOKEN=$TOKEN"
  echo "GRAYLOG_VERSION=$VERSION"
  echo "GRAYLOG_GELF_HOST=$GELF_HOST"
  echo "GRAYLOG_GELF_PORT=12201"
  echo "GRAYLOG_GELF_PROTOCOL=tcp"
  echo "GRAYLOG_GELF_UDP_PORT=12201"
  echo "GRAYLOG_GELF_TCP_PORT=12201"
  echo "GRAYLOG_GELF_HTTP_PORT=12202"
  echo "GRAYLOG_GELF_HTTP_URL=http://$GELF_HOST:12202/gelf"
  echo "GRAYLOG_INPUT_ID_GELF_UDP=$ID_GELF_UDP"
  echo "GRAYLOG_INPUT_ID_GELF_TCP=$ID_GELF_TCP"
  echo "GRAYLOG_INPUT_ID_GELF_HTTP=$ID_GELF_HTTP"
  if [ -n "$ID_OTLP" ]; then
    echo "GRAYLOG_OTLP_GRPC_ENDPOINT=http://$GELF_HOST:4317"
    echo "GRAYLOG_INPUT_ID_OTLP_GRPC=$ID_OTLP"
  fi
  echo "GRAYLOG_DEFAULT_INDEX_SET_ID=$INDEX_SET_ID"
  echo "GRAYLOG_DEFAULT_STREAM_ID=000000000000000000000001"
} >"$TMP"
chmod 0644 "$TMP"
mv -f "$TMP" "$OUT"
log "wrote $OUT ($(wc -l <"$OUT") keys)"
