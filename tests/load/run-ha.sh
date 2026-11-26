#!/usr/bin/env bash
# tests/load/run-ha.sh: the OPS-03 HA test.
#
# 1. Starts deploy/compose/ha (Postgres, Valkey, HAProxy and three anvilid:ci nodes started at the
#    same time on an empty database: concurrent first start).
# 2. Completes setup through HAProxy and creates the admin and benchmark clients
#    (tests/load/lib.sh); checks that all three nodes are still running.
# 3. Runs tests/load/ha.js (300 req/s for 120 s through HAProxy) while restarting node1, node2
#    and node3 with `docker compose restart` (SIGTERM, drain, start), 20 s apart. k6 fails the run
#    on any failed request, failed check or dropped iteration.
# 4. Checks all three nodes are running and the stack is ready afterwards.
#
# Plan 05-26 adds the shared-limit check (small quotas, requests to the nodes directly) and the
# webhook delivery check, and makes this gating in CI.
#
# Output: $LOAD_OUT (default target/load): summary-ha.json, ha.md, and the logs of every service
# (setup token and credentials redacted); ha.md is appended to $GITHUB_STEP_SUMMARY when set.
#
# Needs: Docker with compose, the anvilid:ci image (`just docker-image`), curl, python3, and k6
# (on PATH, or the pinned grafana/k6 image). Uses host port 8080.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tests/load/lib.sh
source "$ROOT/tests/load/lib.sh"

IMAGE=${ANVILID_IMAGE:-anvilid:ci}
RATE=${RATE:-300}
SPACING=${RESTART_SPACING:-20}
BASE=http://localhost:8080
OUT=${LOAD_OUT:-target/load}
[[ "$OUT" = /* ]] || OUT="$ROOT/$OUT"
COMPOSE_FILE="$ROOT/deploy/compose/ha/compose.yml"
NODES=(node1 node2 node3)
export BASE RATE ANVILID_IMAGE="$IMAGE"

require_tools docker curl python3
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found; run 'just docker-image' first"

mkdir -p "$OUT"
make_tmp
compose() { docker compose -f "$COMPOSE_FILE" "$@"; }
K6_PID=""

cleanup() {
    local status=$?
    if [[ -n "$K6_PID" ]]; then
        kill "$K6_PID" 2>/dev/null || true
        wait "$K6_PID" 2>/dev/null || true
    fi
    local svc
    for svc in "${NODES[@]}" haproxy postgres valkey; do
        compose logs --no-color "$svc" 2>&1 | redact >"$OUT/ha-$svc.log" || true
    done
    if ((status != 0)); then
        echo "--- node logs (redacted, last 30 lines each) ---" >&2
        for svc in "${NODES[@]}"; do tail -30 "$OUT/ha-$svc.log" >&2 || true; done
    fi
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$LOAD_TMP"
    exit "$status"
}
trap cleanup EXIT

# running_nodes: how many of the three nodes are running.
running_nodes() {
    compose ps --status running --services 2>/dev/null | grep -cE '^node[123]$' || true
}

# Leftovers from an interrupted run would reuse an installed database (no setup URL).
compose down -v --remove-orphans >/dev/null 2>&1 || true

log "starting the HA stack ($IMAGE x3, Postgres, Valkey, HAProxy)"
ANVILID_KEK=$(random_kek)
export ANVILID_KEK
compose up -d --quiet-pull >/dev/null 2>&1 || {
    compose up -d
    die "docker compose up failed"
}
unset ANVILID_KEK

SETUP_URL=$(setup_url_from_logs compose logs --no-color "${NODES[@]}")
wait_ready "$BASE"
provision "$SETUP_URL" "$BASE"
unset SETUP_URL
sleep 3
started=$(running_nodes)
[[ "$started" == 3 ]] || die "only $started of 3 nodes survived the concurrent first start"

log "k6 ha.js at $RATE req/s through HAProxy; restarting nodes ${SPACING}s apart"
run_k6 tests/load/ha.js "$OUT/summary-ha.json" &
K6_PID=$!
for node in "${NODES[@]}"; do
    sleep "$SPACING"
    log "restarting $node"
    compose restart "$node" >/dev/null
done
k6_status=0
wait "$K6_PID" || k6_status=$?
K6_PID=""

after=$(running_nodes)
wait_ready "$BASE" 30

python3 -I - "$OUT/summary-ha.json" "$RATE" "$after" "$k6_status" >"$OUT/ha.md" <<'PY' || true
import json, sys
path, rate, after, status = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
print(f"### HA test ({rate} req/s through HAProxy, 3 node restarts)")
print()
try:
    m = json.load(open(path))["metrics"]
    val = lambda name, stat, d=None: m.get(name, {}).get("values", {}).get(stat, d)
    print("| requests | failed rate | dropped | p99 (ms) | nodes running after | k6 exit |")
    print("|---|---|---|---|---|---|")
    print(f"| {val('http_reqs', 'count')} | {val('http_req_failed', 'rate')} | "
          f"{val('dropped_iterations', 'count', 0)} | {val('http_req_duration', 'p(99)', 0):.2f} | "
          f"{after}/3 | {status} |")
except (OSError, ValueError, KeyError):
    print(f"No k6 summary (k6 exit {status}); nodes running after: {after}/3")
PY
while IFS= read -r line; do summary_line "$line"; done <"$OUT/ha.md"

[[ "$after" == 3 ]] || die "only $after of 3 nodes are running after the restarts"
((k6_status == 0)) || die "k6 thresholds failed during the restarts (exit $k6_status)"
log "HA test passed"
