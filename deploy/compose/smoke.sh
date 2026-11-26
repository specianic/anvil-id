#!/usr/bin/env bash
# deploy/compose/smoke.sh: smoke test of the Compose examples (OPS-08 from the shipped artefact).
#
#   scripts/docker-image.sh            # builds anvilid:ci
#   deploy/compose/smoke.sh
#
# Brings up deploy/compose/postgres/compose.yml with the observability overlay and asserts:
#   1. the anvilid container becomes healthy (`anvilid healthcheck`) and /health/ready is 200;
#   2. discovery is served;
#   3. the metrics listener (:9464/metrics) exposes anvil_http_requests_total;
#   4. Prometheus scrapes it (up{job="anvilid"} == 1);
#   5. a line on anvilid's stderr parses as JSON (log_format json);
#   6. the OpenTelemetry Collector received a span with service.name=anvilid.
# Then `down -v`. Secrets are random per run and only ever in this process's environment.
#
# Environment: ANVILID_IMAGE (default anvilid:ci), SMOKE_PROJECT (default anvilid-smoke).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export ANVILID_IMAGE=${ANVILID_IMAGE:-anvilid:ci}
ANVILID_KEK=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
export ANVILID_KEK POSTGRES_PASSWORD
export ANVILID_PUBLIC_URL=http://localhost:8080
PROJECT=${SMOKE_PROJECT:-anvilid-smoke}
BASE=http://127.0.0.1:8080
# Requests carry the public host, as a browser would.
HOST_HEADER="Host: localhost:8080"

dc() {
    docker compose -p "$PROJECT" \
        -f deploy/compose/postgres/compose.yml \
        -f deploy/compose/observability/compose.yml "$@"
}

ok=0
cleanup() {
    if ((ok == 0)); then
        echo "--- smoke test failed; service logs:" >&2
        dc ps -a >&2 || true
        dc logs --no-color >&2 || true
    fi
    dc down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "error: $*" >&2
    exit 1
}

# poll SECONDS COMMAND...: retries COMMAND once a second until it succeeds or time runs out.
poll() {
    local secs=$1
    shift
    for _ in $(seq 1 "$secs"); do
        if "$@"; then return 0; fi
        sleep 1
    done
    return 1
}

dc config -q
# --wait: every service running, and healthy where it has a health check (postgres, anvilid).
dc up -d --wait --wait-timeout 180

cid=$(dc ps -q anvilid)
[[ -n "$cid" ]] || fail "no anvilid container"
health=$(docker inspect -f '{{.State.Health.Status}}' "$cid")
[[ "$health" == "healthy" ]] || fail "anvilid container health is '$health', expected healthy"
echo "ok: container healthy (anvilid healthcheck)"

curl -fsS "$BASE/health/ready" >/dev/null || fail "/health/ready is not 200"
echo "ok: /health/ready"

discovery=$(curl -fsS -H "$HOST_HEADER" "$BASE/.well-known/openid-configuration") ||
    fail "discovery request failed"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["issuer"].startswith("http://localhost:8080"), d["issuer"]' \
    "$discovery" || fail "unexpected discovery document"
echo "ok: discovery"

metrics_ok() {
    local body
    body=$(curl -fsS http://127.0.0.1:9464/metrics 2>/dev/null) || return 1
    grep -q '^anvil_http_requests_total' <<<"$body"
}
poll 30 metrics_ok || fail ":9464/metrics has no anvil_http_requests_total"
echo "ok: /metrics has anvil_http_requests_total"

prometheus_ok() {
    local body
    body=$(curl -fsS --get --data-urlencode 'query=up{job="anvilid"}' \
        http://127.0.0.1:9090/api/v1/query 2>/dev/null) || return 1
    python3 -c 'import json,sys; r=json.loads(sys.argv[1])["data"]["result"]; sys.exit(0 if r and r[0]["value"][1] == "1" else 1)' \
        "$body"
}
poll 60 prometheus_ok || fail "Prometheus does not report up{job=\"anvilid\"} == 1"
echo "ok: Prometheus scrapes anvilid"

# stderr only (stdout carries the audit JSON lines, which must not satisfy this check).
stderr_log=$(docker logs "$cid" 2>&1 >/dev/null)
python3 -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        if isinstance(json.loads(line), dict):
            sys.exit(0)
    except ValueError:
        pass
sys.exit(1)
' <<<"$stderr_log" || fail "no stderr line of anvilid parses as a JSON object"
echo "ok: stderr log line parses as JSON"

span_ok() {
    local logs
    logs=$(dc logs --no-color --no-log-prefix otel-collector 2>/dev/null) || return 1
    grep -qE 'service\.name: Str\(anvilid\)' <<<"$logs"
}
# Spans leave in batches; anvilid also flushes at shutdown, so stop it if the batch has not come.
if ! poll 30 span_ok; then
    dc stop anvilid >/dev/null
    poll 15 span_ok || fail "the collector received no span with service.name=anvilid"
fi
echo "ok: collector received a span with service.name=anvilid"

ok=1
echo "compose smoke test passed"
