#!/usr/bin/env bash
# tests/load/run-ha.sh: the OPS-03 HA test (gating in .github/workflows/load.yml).
#
# 1. Concurrent first start: deploy/compose/ha (Postgres, Valkey, HAProxy, the counting webhook
#    sink and three anvilid:ci nodes started at the same time on an empty database). All three
#    nodes must be running and ready on their own ports after setup.
# 2. Completes setup through HAProxy, creates the admin and benchmark clients (tests/load/lib.sh)
#    and a webhook endpoint (user.created) pointing at the sink.
# 3. Restarts under load: tests/load/ha.js runs 300 req/s for 120 s through HAProxy while node1,
#    node2 and node3 are restarted one by one with `docker compose restart` (SIGTERM, drain,
#    start), RESTART_SPACING s apart. At the same time USERS users are created through HAProxy,
#    one per USER_INTERVAL s. k6 fails on any failed request, failed check, dropped iteration or
#    HTTP 429; every user creation must answer 201.
# 4. Exactly-once jobs: every created user's user.created event reaches the sink exactly once
#    (by webhook-id): deliveries == unique ids == distinct user ids == users created.
# 5. Shared limit: the nodes are recreated with token quotas of SHARED_QUOTA/s (burst = rate)
#    and SHARED_PER_NODE requests per node for the benchmark client are fired at the three nodes
#    directly, all at once. Every TCP connection is opened before the start barrier, so the burst
#    window W covers only the requests themselves: connection setup through Docker's published
#    ports can take a SYN retransmission (about 1 s) for part of a 90-connection burst on a CI
#    runner, which would stretch W past 1 s without the server seeing the requests any earlier.
#    Allowed must stay within one shared GCRA budget (bound below), well under the three budgets a
#    per-node limiter would grant.
#
# Shared-limit bound (05-08 limiter contract, governor GCRA): a quota of `b` burst refilled every
# T = 1 s / rate allows at most b + floor(W / T) requests in any window of W seconds, starting from
# an unused key. With rate = burst = Q and the burst fired in W <= 1 s:
#     allowed <= Q + ceil(Q * W) + 1
# (the +1 absorbs the client-side measurement of W against server arrival times). A per-node
# limiter would allow at least 3 * min(Q, SHARED_PER_NODE): with Q = 10 and 30 per node, 30
# versus a shared bound of at most 21. The run fails if the burst takes longer than 1 s (the
# result would be inconclusive), if no request is limited, or on any status other than 200/429.
#
# Output: $LOAD_OUT (default target/load): summary-ha.json, ha.md, users.txt, sink-stats.json,
# shared-limit.json and the logs of every service (setup token and credentials redacted); ha.md
# is appended to $GITHUB_STEP_SUMMARY when set.
#
# Needs: Docker with compose, the anvilid:ci image (`just docker-image`), curl, python3, and k6
# (on PATH, or the pinned grafana/k6 image). Uses host ports 8080-8083 and 9000 (loopback).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tests/load/lib.sh
source "$ROOT/tests/load/lib.sh"

IMAGE=${ANVILID_IMAGE:-anvilid:ci}
RATE=${RATE:-300}
SPACING=${RESTART_SPACING:-20}
USERS=${USERS:-80}
USER_INTERVAL=${USER_INTERVAL:-1}
SHARED_QUOTA=${SHARED_QUOTA:-10}
SHARED_PER_NODE=${SHARED_PER_NODE:-30}
DELIVERY_TIMEOUT=${DELIVERY_TIMEOUT:-120}
BASE=http://localhost:8080
SINK=http://127.0.0.1:9000
# The sink as the nodes reach it (fixed address in the compose subnet, outbound allow-list).
SINK_HOOK=http://172.30.75.200:9000/hook
OUT=${LOAD_OUT:-target/load}
[[ "$OUT" = /* ]] || OUT="$ROOT/$OUT"
COMPOSE_FILE="$ROOT/deploy/compose/ha/compose.yml"
NODES=(node1 node2 node3)
NODE_PORTS=(8081 8082 8083)
export BASE RATE ANVILID_IMAGE="$IMAGE"

require_tools docker curl python3
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found; run 'just docker-image' first"

mkdir -p "$OUT"
make_tmp
compose() { docker compose -f "$COMPOSE_FILE" "$@"; }
K6_PID=""
USERS_PID=""

cleanup() {
    local status=$?
    local pid
    for pid in "$K6_PID" "$USERS_PID"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    local svc
    for svc in "${NODES[@]}" haproxy postgres valkey sink; do
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

# nodes_ready [seconds]: every node answers /health/ready on its own port.
nodes_ready() {
    local port
    for port in "${NODE_PORTS[@]}"; do
        wait_ready "http://127.0.0.1:$port" "${1:-60}"
    done
}

# Leftovers from an interrupted run would reuse an installed database (no setup URL).
compose down -v --remove-orphans >/dev/null 2>&1 || true

# The KEK lives in this shell only (passed to compose per command, never written to disk).
KEK=$(random_kek)

# --- 1. Concurrent first start.
log "starting the HA stack ($IMAGE x3, Postgres, Valkey, HAProxy, sink)"
ANVILID_KEK="$KEK" compose up -d --quiet-pull >/dev/null 2>&1 || {
    ANVILID_KEK="$KEK" compose up -d
    die "docker compose up failed"
}

SETUP_URL=$(setup_url_from_logs compose logs --no-color "${NODES[@]}")
wait_ready "$BASE"

# --- 2. Setup, clients, webhook endpoint.
provision "$SETUP_URL" "$BASE"
unset SETUP_URL
sleep 3
started=$(running_nodes)
[[ "$started" == 3 ]] || die "only $started of 3 nodes survived the concurrent first start"
nodes_ready 30
# Exactly one node installs: one distinct setup token across all node logs (with JSON logs the
# installer prints it on stderr and stdout).
setup_lines=$(compose logs --no-color "${NODES[@]}" 2>&1 |
    sed -nE 's#.*Setup URL: http[^ "]+/setup\?token=([A-Za-z0-9_-]+).*#\1#p' | sort -u | wc -l | tr -d ' ')
log "concurrent first start: 3/3 nodes ready (distinct setup tokens: $setup_lines)"

ADMIN=$(admin_token "$BASE")
status=$(api_call POST "$BASE/api/admin/v1/tenants/default/webhooks" "$ADMIN" \
    "{\"name\": \"ha-sink\", \"url\": \"$SINK_HOOK\", \"events\": [\"user.created\"]}" \
    "$LOAD_TMP/webhook.json")
[[ "$status" == 201 ]] || die "creating the webhook endpoint answered $status: $(cat "$LOAD_TMP/webhook.json")"
rm -f "$LOAD_TMP/webhook.json"

# --- 3. Restarts under load, user creations alongside.
create_users() {
    local run i code
    run=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
    for ((i = 1; i <= USERS; i++)); do
        code=$(api_call POST "$BASE/api/admin/v1/tenants/default/users" "$ADMIN" \
            "{\"email\": \"ha-$run-$i@example.com\", \"email_verified\": true,
              \"password\": \"Ha-$run-$i-$(head -c 9 /dev/urandom | base64 | tr -d '/+=')\"}" \
            "$LOAD_TMP/user-$i.json")
        echo "$i $code" >>"$OUT/users.txt"
        rm -f "$LOAD_TMP/user-$i.json"
        sleep "$USER_INTERVAL"
    done
}
: >"$OUT/users.txt"

log "k6 ha.js at $RATE req/s through HAProxy; restarting nodes ${SPACING}s apart; $USERS user creations"
run_k6 tests/load/ha.js "$OUT/summary-ha.json" &
K6_PID=$!
create_users &
USERS_PID=$!
for node in "${NODES[@]}"; do
    sleep "$SPACING"
    log "restarting $node"
    compose restart "$node" >/dev/null
done
k6_status=0
wait "$K6_PID" || k6_status=$?
K6_PID=""
wait "$USERS_PID" || true
USERS_PID=""

after=$(running_nodes)
wait_ready "$BASE" 30
created=$(awk '$2 == 201' "$OUT/users.txt" | wc -l | tr -d ' ')
failed_users=$(awk '$2 != 201' "$OUT/users.txt" | wc -l | tr -d ' ')

# --- 4. Exactly-once webhook deliveries.
log "waiting up to ${DELIVERY_TIMEOUT}s for $created user.created deliveries"
for ((i = 0; i < DELIVERY_TIMEOUT; i++)); do
    curl -fsS -o "$OUT/sink-stats.json" "$SINK/stats" 2>/dev/null || true
    if [[ -s "$OUT/sink-stats.json" ]] &&
        python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s["unique"] >= int(sys.argv[2]) else 1)' \
            "$OUT/sink-stats.json" "$created"; then
        break
    fi
    sleep 1
done
# Late duplicates (a lease expiring on a delivery that was in fact sent) would arrive after the
# 45 s lease; give them a chance to show up before judging.
sleep "${DUPLICATE_GRACE:-50}"
curl -fsS -o "$OUT/sink-stats.json" "$SINK/stats" || die "the sink did not answer /stats"

# --- 5. Shared limit across the nodes.
for node in "${NODES[@]}"; do
    compose logs --no-color "$node" 2>&1 | redact >"$OUT/ha-$node-restarts.log" || true
done
log "recreating the nodes with token quotas of ${SHARED_QUOTA}/s for the shared-limit check"
RATE_LIMIT_TOKEN="$SHARED_QUOTA" ANVILID_KEK="$KEK" compose up -d --no-deps "${NODES[@]}" >/dev/null 2>&1 || {
    RATE_LIMIT_TOKEN="$SHARED_QUOTA" ANVILID_KEK="$KEK" compose up -d --no-deps "${NODES[@]}"
    die "recreating the nodes failed"
}
nodes_ready 60
# Let any budget used during startup refill completely.
sleep 3
shared_status=0
python3 -I - "$LOAD_TMP/bench.json" "$SHARED_QUOTA" "$SHARED_PER_NODE" "$(
    IFS=,
    echo "${NODE_PORTS[*]}"
)" >"$OUT/shared-limit.json" <<'PY' || shared_status=$?
import base64, http.client, json, math, sys, threading, time, urllib.parse
cred = json.load(open(sys.argv[1]))
quota, per_node, ports = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4].split(",")
basic = "%s:%s" % (urllib.parse.quote(cred["client_id"], safe=""),
                   urllib.parse.quote(cred["client_secret"], safe=""))
headers = {
    "Authorization": "Basic " + base64.b64encode(basic.encode()).decode(),
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
    # Same host as through HAProxy (the default tenant at the public host).
    "Host": "localhost:8080",
}
total = per_node * len(ports)
barrier = threading.Barrier(total)
lock = threading.Lock()
results = []

def fire(port):
    # Connect first (outside the measured window), then wait for every thread, then send.
    conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=10)
    connect_error = None
    try:
        conn.connect()
    except Exception as e:  # a connection that cannot be opened counts as a failure
        connect_error = "connect-error:" + e.__class__.__name__
    barrier.wait()
    t0 = time.monotonic()
    if connect_error is not None:
        status = connect_error
    else:
        try:
            conn.request("POST", "/token", body=b"grant_type=client_credentials",
                         headers=headers)
            response = conn.getresponse()
            response.read()
            status = response.status
        except Exception as e:  # request errors count as failures
            status = "error:" + e.__class__.__name__
        finally:
            conn.close()
    t1 = time.monotonic()
    with lock:
        results.append((port, status, t0, t1))

threads = [threading.Thread(target=fire, args=(p,)) for p in ports for _ in range(per_node)]
for t in threads:
    t.start()
for t in threads:
    t.join()
window = max(r[3] for r in results) - min(r[2] for r in results)
allowed = sum(1 for r in results if r[1] == 200)
limited = sum(1 for r in results if r[1] == 429)
other = [r[1] for r in results if r[1] not in (200, 429)]
bound = quota + math.ceil(quota * window) + 1
per_node_floor = len(ports) * min(quota, per_node)
by_node = {p: sum(1 for r in results if r[0] == p and r[1] == 200) for p in ports}
problems = []
if other:
    problems.append(f"unexpected statuses: {sorted(set(map(str, other)))}")
if window > 1.0:
    problems.append(f"the burst took {window:.3f} s (> 1 s): inconclusive")
if limited == 0:
    problems.append("no request was limited")
if allowed > bound:
    problems.append(f"allowed {allowed} > shared bound {bound}")
print(json.dumps({
    "quota_per_second": quota, "burst": quota, "requests": total, "window_s": round(window, 3),
    "allowed": allowed, "limited": limited, "other": len(other), "allowed_by_node_port": by_node,
    "shared_bound": bound, "per_node_limiter_would_allow_at_least": per_node_floor,
    "problems": problems,
}, indent=2))
sys.exit(1 if problems else 0)
PY

# --- Report.
python3 -I - "$OUT/summary-ha.json" "$RATE" "$after" "$k6_status" "$created" "$failed_users" \
    "$OUT/sink-stats.json" "$OUT/shared-limit.json" "$setup_lines" >"$OUT/ha.md" <<'PY' || true
import json, sys
path, rate, after, status, created, failed_users, sink, shared, setup_lines = sys.argv[1:10]
print(f"### HA test ({rate} req/s through HAProxy, 3 node restarts)")
print()
print(f"Concurrent first start: 3 nodes on an empty Postgres, distinct setup tokens logged: {setup_lines}")
print()
try:
    m = json.load(open(path))["metrics"]
    val = lambda name, stat, d=None: m.get(name, {}).get("values", {}).get(stat, d)
    print("| requests | failed rate | dropped | HTTP 429 | p99 (ms) | nodes running after | k6 exit |")
    print("|---|---|---|---|---|---|---|")
    print(f"| {val('http_reqs', 'count')} | {val('http_req_failed', 'rate')} | "
          f"{val('dropped_iterations', 'count', 0)} | {val('http_429', 'count', 0)} | "
          f"{val('http_req_duration', 'p(99)', 0):.2f} | {after}/3 | {status} |")
except (OSError, ValueError, KeyError):
    print(f"No k6 summary (k6 exit {status}); nodes running after: {after}/3")
print()
try:
    s = json.load(open(sink))
    print("Webhooks (user.created during restarts): "
          f"users created {created} (failed creations {failed_users}), deliveries {s['total']}, "
          f"unique webhook-ids {s['unique']}, distinct user ids {s['user_ids']}, "
          f"duplicates {len(s['duplicates'])}, malformed {s['malformed']}")
except (OSError, ValueError, KeyError):
    print(f"Webhooks: no sink statistics (users created {created})")
print()
try:
    r = json.load(open(shared))
    print(f"Shared limit: {r['requests']} requests in {r['window_s']} s across 3 nodes at "
          f"{r['quota_per_second']}/s (burst {r['burst']}): allowed {r['allowed']} "
          f"(bound {r['shared_bound']}; a per-node limiter would allow at least "
          f"{r['per_node_limiter_would_allow_at_least']}), limited {r['limited']}, "
          f"other {r['other']}, per node {r['allowed_by_node_port']}"
          + (f"; problems: {r['problems']}" if r["problems"] else ""))
except (OSError, ValueError, KeyError):
    print("Shared limit: no result")
PY
while IFS= read -r line; do summary_line "$line"; done <"$OUT/ha.md"

# --- Verdict (every check, then fail on the first problem).
problems=()
[[ "$setup_lines" == 1 ]] || problems+=("expected exactly one installer (setup token), got $setup_lines")
[[ "$after" == 3 ]] || problems+=("only $after of 3 nodes are running after the restarts")
((k6_status == 0)) || problems+=("k6 thresholds failed during the restarts (exit $k6_status)")
((failed_users == 0)) || problems+=("$failed_users user creations did not answer 201 (see users.txt)")
((created == USERS)) || problems+=("created $created of $USERS users")
python3 -I -c '
import json, sys
s, n = json.load(open(sys.argv[1])), int(sys.argv[2])
ok = (s["total"] == n and s["unique"] == n and s["user_ids"] == n and not s["duplicates"]
      and s["malformed"] == 0 and s["types"].get("user.created", 0) == n)
sys.exit(0 if ok else 1)
' "$OUT/sink-stats.json" "$created" ||
    problems+=("webhook deliveries are not exactly once per created user (see sink-stats.json)")
((shared_status == 0)) || problems+=("shared limit check failed (see shared-limit.json)")
if ((${#problems[@]} > 0)); then
    printf 'HA problem: %s\n' "${problems[@]}" >&2
    die "HA test failed (${#problems[@]} problems)"
fi
log "HA test passed"
