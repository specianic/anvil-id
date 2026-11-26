#!/usr/bin/env bash
# tests/load/run-perf.sh: the QUAL-05 token-endpoint benchmark (PRD §6.3).
#
#   tests/load/run-perf.sh            # 3 trials at 1000 req/s
#   RATE=1500 TRIALS=5 tests/load/run-perf.sh
#
# 1. Starts Postgres 18 and one anvilid:ci node with docker compose (a compose file generated in a
#    private temp dir; the Postgres image is the digest pinned in deploy/compose/ha/compose.yml).
#    Token quotas are raised above the test rate (research Pitfall 1: otherwise the run measures
#    the rate limiter), JSON logs at info.
# 2. Gates the node's idle memory (QUAL-05: < 100 MB): 30 s after the node is ready, before setup
#    or any load, VmRSS of the anvilid process is read from the host's /proc/<pid>/status, where
#    <pid> is `docker inspect -f '{{.State.Pid}}'` of the node container (the distroless image has
#    no shell; the Linux runner's procfs shows the containerised process). >= 102400 kB fails.
# 3. Completes setup from the logged setup URL, creates a system-tenant admin client and a
#    client_credentials benchmark client in the default tenant (tests/load/lib.sh).
# 4. Runs tests/load/token.js TRIALS times (default 3) and takes the median trial by p99. The run
#    fails when any threshold of the median trial fails (p99 < 50 ms in the measured minute, no
#    failed requests, all checks passed, no dropped iterations, no HTTP 429) or when the median
#    trial's measured throughput is below the target rate. Each trial's numbers are recorded
#    either way.
#
# The targets (RATE 1000, p99 50 ms, 0 failures, 0 dropped, 0 x 429, idle < 100 MB) are the PRD
# §6.3 figures on the public 4-vCPU runner shared by k6, Postgres and AnvilID (05-CONTEXT Q2).
# They change only by an owner decision, never to make a run pass.
#
# Output: $LOAD_OUT (default target/load): summary-token-<n>.json per trial, perf.md, and the node
# logs (setup token redacted); the table is appended to $GITHUB_STEP_SUMMARY when set.
#
# Needs: Docker with compose on Linux (host procfs for the idle gate), the anvilid:ci image
# (`just docker-image`), curl, python3, and k6 (on PATH, or the pinned grafana/k6 image). Uses
# host port 8080.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tests/load/lib.sh
source "$ROOT/tests/load/lib.sh"

IMAGE=${ANVILID_IMAGE:-anvilid:ci}
RATE=${RATE:-1000}
TRIALS=${TRIALS:-3}
# QUAL-05: idle VmRSS below 100 MiB, sampled after IDLE_WAIT seconds of idle.
IDLE_RSS_LIMIT_KB=102400
IDLE_WAIT=${IDLE_WAIT:-30}
# Quotas well above the test rate (per IP and per client: k6 is one IP and one client).
QUOTA=$((RATE * 5))
BASE=http://localhost:8080
OUT=${LOAD_OUT:-target/load}
[[ "$OUT" = /* ]] || OUT="$ROOT/$OUT"
export BASE RATE

require_tools docker curl python3
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found; run 'just docker-image' first"
POSTGRES_IMAGE=$(sed -nE 's/^ *image: (postgres:[^ ]+@sha256:[0-9a-f]{64}) *$/\1/p' deploy/compose/ha/compose.yml)
[[ -n "$POSTGRES_IMAGE" ]] || die "no digest-pinned postgres image in deploy/compose/ha/compose.yml"

mkdir -p "$OUT"
make_tmp
COMPOSE_FILE="$LOAD_TMP/perf-compose.yml"
compose() { docker compose -p anvilid-perf -f "$COMPOSE_FILE" "$@"; }

cleanup() {
    local status=$?
    if [[ -f "$COMPOSE_FILE" ]]; then
        compose logs --no-color anvilid 2>&1 | redact >"$OUT/perf-anvilid.log" || true
        if ((status != 0)); then
            echo "--- anvilid logs (redacted, last 50 lines) ---" >&2
            tail -50 "$OUT/perf-anvilid.log" >&2 || true
        fi
        compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    rm -rf "$LOAD_TMP"
    exit "$status"
}
trap cleanup EXIT

cat >"$COMPOSE_FILE" <<EOF
name: anvilid-perf
services:
  postgres:
    image: $POSTGRES_IMAGE
    environment:
      POSTGRES_USER: anvilid
      POSTGRES_PASSWORD: anvilid-local-only
      POSTGRES_DB: anvilid
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U anvilid -d anvilid"]
      interval: 1s
      timeout: 3s
      retries: 60
    tmpfs:
      - /var/lib/postgresql
  anvilid:
    image: $IMAGE
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      ANVILID_DATABASE_URL: postgres://anvilid:anvilid-local-only@postgres:5432/anvilid
      ANVILID_KEK: \${ANVILID_KEK:-}
      ANVILID_PUBLIC_URL: $BASE
      ANVILID_LISTEN: 0.0.0.0:8080
      ANVILID_LOG_FORMAT: json
      RUST_LOG: info
      ANVILID_RATE_LIMIT_TOKEN_PER_SECOND: "$QUOTA"
      ANVILID_RATE_LIMIT_TOKEN_CLIENT_PER_SECOND: "$QUOTA"
      ANVILID_DATABASE_MAX_CONNECTIONS: "20"
    ports:
      - "127.0.0.1:8080:8080"
EOF

# Leftovers from an interrupted run would reuse an installed database (no setup URL).
compose down -v --remove-orphans >/dev/null 2>&1 || true

log "starting Postgres and one anvilid node ($IMAGE)"
ANVILID_KEK=$(random_kek)
export ANVILID_KEK
compose up -d --quiet-pull >/dev/null 2>&1 || {
    compose up -d
    die "docker compose up failed"
}
unset ANVILID_KEK

SETUP_URL=$(setup_url_from_logs compose logs --no-color anvilid)
wait_ready "$BASE"

# Idle memory: host VmRSS of the node's anvilid process, after IDLE_WAIT s idle, before setup.
log "sampling idle VmRSS after ${IDLE_WAIT}s idle"
sleep "$IDLE_WAIT"
NODE_PID=$(docker inspect -f '{{.State.Pid}}' "$(compose ps -q anvilid)")
[[ "$NODE_PID" =~ ^[0-9]+$ && "$NODE_PID" != 0 ]] || die "no host pid for the anvilid container"
IDLE_RSS_KB=$(awk '/^VmRSS:/{print $2}' "/proc/$NODE_PID/status" 2>/dev/null || true)
[[ "$IDLE_RSS_KB" =~ ^[0-9]+$ ]] || die "cannot read VmRSS from /proc/$NODE_PID/status on this host"
IDLE_HWM_KB=$(awk '/^VmHWM:/{print $2}' "/proc/$NODE_PID/status" 2>/dev/null || echo "?")
log "idle VmRSS ${IDLE_RSS_KB} kB (VmHWM ${IDLE_HWM_KB} kB)"

provision "$SETUP_URL" "$BASE"
unset SETUP_URL

log "running $TRIALS trials of tests/load/token.js at $RATE req/s"
for ((i = 1; i <= TRIALS; i++)); do
    status=0
    run_k6 tests/load/token.js "$OUT/summary-token-$i.json" || status=$?
    log "trial $i: k6 exit $status"
done

# Median trial by measured p99; its thresholds, its throughput and the idle gate decide.
set +e
python3 -I - "$OUT" "$TRIALS" "$RATE" "$IDLE_RSS_KB" "$IDLE_HWM_KB" "$IDLE_RSS_LIMIT_KB" \
    >"$OUT/perf.md" <<'PY'
import json, os, sys
out, trials, rate = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
idle_kb, hwm_kb, limit_kb = int(sys.argv[4]), sys.argv[5], int(sys.argv[6])
P99 = "http_req_duration{phase:measure}"
REQS = "http_reqs{phase:measure}"
MEASURE_SECONDS = 60
rows = []
for i in range(1, trials + 1):
    path = os.path.join(out, f"summary-token-{i}.json")
    try:
        m = json.load(open(path))["metrics"]
    except (OSError, ValueError, KeyError):
        rows.append({"trial": i, "p99": float("inf"), "rps": 0.0, "failed": None,
                     "dropped": None, "r429": None, "ok": False, "missing": True})
        continue
    val = lambda name, stat, d=None: m.get(name, {}).get("values", {}).get(stat, d)
    thresholds = all(t.get("ok", False)
                     for metric in m.values()
                     for t in metric.get("thresholds", {}).values())
    count = val(REQS, "count", 0)
    rows.append({
        "trial": i,
        "p99": val(P99, "p(99)", float("inf")),
        "rps": count / MEASURE_SECONDS,
        "failed": val("http_req_failed", "rate"),
        "dropped": val("dropped_iterations", "count", 0),
        "r429": val("http_429", "count", 0),
        # constant-arrival-rate starts RATE iterations per second; a scheduler boundary may cost
        # one iteration over the minute, nothing more (dropped iterations already fail above).
        "ok": thresholds and count >= rate * MEASURE_SECONDS - 1,
        "missing": False,
    })
ranked = sorted(rows, key=lambda r: r["p99"])
median = ranked[len(ranked) // 2]
idle_ok = idle_kb < limit_kb
print(f"### Token endpoint benchmark ({rate} req/s target, p99 < 50 ms, median of {trials})")
print()
print("| trial | p99 (ms) | throughput (req/s) | failed rate | dropped | HTTP 429 | verdict |")
print("|---|---|---|---|---|---|---|")
for r in rows:
    mark = " (median)" if r is median else ""
    if r["missing"]:
        print(f"| {r['trial']}{mark} | no summary | | | | | fail |")
    else:
        print(f"| {r['trial']}{mark} | {r['p99']:.2f} | {r['rps']:.1f} | {r['failed']} | "
              f"{r['dropped']} | {r['r429']} | {'pass' if r['ok'] else 'fail'} |")
print()
print(f"Idle VmRSS of the node (host /proc, Postgres backend, before setup): {idle_kb} kB "
      f"(VmHWM {hwm_kb} kB; limit {limit_kb} kB): {'pass' if idle_ok else 'fail'}")
print()
print("Runner: public GitHub-hosted 4 vCPU, shared by k6, Postgres and AnvilID (05-CONTEXT Q2).")
sys.exit(0 if median["ok"] and idle_ok else 1)
PY
verdict=$?
set -e
while IFS= read -r line; do summary_line "$line"; done <"$OUT/perf.md"
printf '{"idle_vmrss_kb":%s,"idle_vmhwm_kb":"%s","limit_kb":%s}\n' \
    "$IDLE_RSS_KB" "$IDLE_HWM_KB" "$IDLE_RSS_LIMIT_KB" >"$OUT/idle.json"
if ((verdict != 0)); then
    die "the median trial or the idle gate missed a target (see $OUT/perf.md)"
fi
log "benchmark passed"
