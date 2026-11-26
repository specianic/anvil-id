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
# 2. Completes setup from the logged setup URL, creates a system-tenant admin client and a
#    client_credentials benchmark client in the default tenant (tests/load/lib.sh).
# 3. Records the node's idle memory (docker stats) and, when the musl binary from
#    scripts/docker-image.sh exists, scripts/measure-idle.sh for it.
# 4. Runs tests/load/token.js TRIALS times (default 3) and takes the median trial by p99. The run
#    fails when any threshold of the median trial fails (p99 < 50 ms in the measured minute, no
#    failed requests, all checks passed, no dropped iterations). Each trial's numbers are
#    recorded either way.
#
# Output: $LOAD_OUT (default target/load): summary-token-<n>.json per trial, perf.md, and the node
# logs (setup token redacted); the table is appended to $GITHUB_STEP_SUMMARY when set.
#
# Needs: Docker with compose, the anvilid:ci image (`just docker-image`), curl, python3, and k6
# (on PATH, or the pinned grafana/k6 image). Uses host port 8080.
#
# ANVILID_DATABASE_MAX_CONNECTIONS takes effect once plan 05-05 adds the key (ignored before).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tests/load/lib.sh
source "$ROOT/tests/load/lib.sh"

IMAGE=${ANVILID_IMAGE:-anvilid:ci}
RATE=${RATE:-1000}
TRIALS=${TRIALS:-3}
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
      - "8080:8080"
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
provision "$SETUP_URL" "$BASE"
unset SETUP_URL

# Idle memory of the containerised node (Postgres backend), before any load.
sleep 5
IDLE_MEM=$(docker stats --no-stream --format '{{.MemUsage}}' "$(compose ps -q anvilid)" | cut -d/ -f1 | tr -d ' ')
MUSL_BIN="$ROOT/target/x86_64-unknown-linux-musl/release/anvilid"
if [[ -x "$MUSL_BIN" ]]; then
    MEASURE_OUT="$OUT" scripts/measure-idle.sh "$MUSL_BIN" x86_64-unknown-linux-musl || true
fi

log "running $TRIALS trials of tests/load/token.js at $RATE req/s"
for ((i = 1; i <= TRIALS; i++)); do
    status=0
    run_k6 tests/load/token.js "$OUT/summary-token-$i.json" || status=$?
    log "trial $i: k6 exit $status"
done

# Median trial by measured p99; its thresholds decide.
set +e
python3 -I - "$OUT" "$TRIALS" "$RATE" "$IDLE_MEM" >"$OUT/perf.md" <<'PY'
import json, os, sys
out, trials, rate, idle = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
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
                     "dropped": None, "ok": False, "missing": True})
        continue
    val = lambda name, stat, d=None: m.get(name, {}).get("values", {}).get(stat, d)
    ok = all(t.get("ok", False)
             for metric in m.values()
             for t in metric.get("thresholds", {}).values())
    rows.append({
        "trial": i,
        "p99": val(P99, "p(99)", float("inf")),
        "rps": val(REQS, "count", 0) / MEASURE_SECONDS,
        "failed": val("http_req_failed", "rate"),
        "dropped": val("dropped_iterations", "count", 0),
        "ok": ok,
        "missing": False,
    })
ranked = sorted(rows, key=lambda r: r["p99"])
median = ranked[len(ranked) // 2]
print(f"### Token endpoint benchmark ({rate} req/s target, median of {trials})")
print()
print("| trial | p99 (ms) | throughput (req/s) | failed rate | dropped | thresholds |")
print("|---|---|---|---|---|---|")
for r in rows:
    mark = " (median)" if r is median else ""
    if r["missing"]:
        print(f"| {r['trial']}{mark} | no summary | | | | fail |")
    else:
        print(f"| {r['trial']}{mark} | {r['p99']:.2f} | {r['rps']:.0f} | {r['failed']} | "
              f"{r['dropped']} | {'pass' if r['ok'] else 'fail'} |")
print()
print(f"Idle memory of the node (docker stats, Postgres backend): {idle}")
sys.exit(0 if median["ok"] else 1)
PY
verdict=$?
set -e
while IFS= read -r line; do summary_line "$line"; done <"$OUT/perf.md"
if [[ -f "$OUT/measure-x86_64-unknown-linux-musl.json" ]]; then
    summary_line "measure-idle (SQLite, musl binary): $(cat "$OUT/measure-x86_64-unknown-linux-musl.json")"
fi
if ((verdict != 0)); then
    die "the median trial missed a threshold (see $OUT/perf.md)"
fi
log "benchmark passed"
