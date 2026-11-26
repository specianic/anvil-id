# Load and HA tests

Two gating harnesses, both driven by [k6](https://grafana.com/docs/k6/) and Docker Compose:

| Script | Requirement | What it does |
|---|---|---|
| `run-perf.sh` | QUAL-05 (PRD §6.3) | Postgres 18 and one `anvilid:ci` node. Idle memory is gated first. Then `token.js` runs `client_credentials` with `client_secret_basic` at a constant arrival rate of 1,000 req/s: a 15 s warm-up, then a 60 s measured run, three trials. |
| `run-ha.sh` | OPS-03 | `deploy/compose/ha`: Postgres, Valkey, HAProxy, a counting webhook sink and three nodes started together on an empty database. `ha.js` sends 300 req/s through HAProxy for 120 s while node1, node2 and node3 are restarted 20 s apart and users are created alongside. Then come the exactly-once webhook check and the shared-limit check. |

`lib.sh` holds the shared steps. It waits for readiness, reads the one-time setup URL from the
logs, completes setup, creates a system-tenant admin client and a `client_credentials` benchmark
client in the `default` tenant, calls the admin API, runs k6 and writes the job summary.
`webhook-sink.mjs` is the sink: it counts deliveries by `webhook-id` and serves `/stats`.

## Running

```sh
just docker-image          # builds anvilid:ci
tests/load/run-perf.sh     # RATE=1000 TRIALS=3 IDLE_WAIT=30 by default
tests/load/run-ha.sh       # RATE=300 RESTART_SPACING=20 USERS=80 SHARED_QUOTA=10 SHARED_PER_NODE=30
```

Both need Docker with Compose on Linux (the idle gate reads the host's procfs), plus `curl` and
`python3`. They use the `k6` binary when it is on `PATH`. Otherwise they use the `grafana/k6`
image pinned in `lib.sh`. The following loopback ports must be free:

- 8080: HAProxy, or the perf node;
- 8081-8083: the HA nodes directly;
- 9000: the sink.

Results go to `target/load/` (`LOAD_OUT` overrides this): the k6 JSON summaries, `perf.md` /
`ha.md`, `idle.json`, `users.txt`, `sink-stats.json`, `shared-limit.json`, and the service logs
with secrets redacted. On GitHub Actions the tables are also appended to the job summary.

The KEK is generated for each run and kept only in the shell environment. The client credentials
stay in a private temp directory that is removed on exit, and the logs are written with setup
tokens and credentials redacted.

## Targets (owner decision only)

These numbers are the PRD §6.3 / QUAL-05 / OPS-03 targets:

- 1,000 req/s;
- p99 < 50 ms;
- 0 failed requests, 0 dropped iterations and 0 HTTP 429;
- idle memory < 100 MB;
- 0 failed requests during the restarts.

They live in `token.js`, `ha.js`, `run-perf.sh` and `run-ha.sh`, and change only by an owner
decision. If a run misses a target, record the numbers and fix the server. After three failed
median runs, the gate (05-28) takes the question to the owner. Never relax a threshold to make a
run pass.

## Pass/fail rules

### Performance (`run-perf.sh`)

`token.js` thresholds (k6 exits non-zero when one fails):

- `http_req_duration{phase:measure}`: `p(99) < 50` ms (the warm-up is excluded);
- `http_req_failed`: `rate == 0`;
- `checks`: `rate == 1` (every response is 200);
- `dropped_iterations`: `count == 0`. If k6 could not start an iteration at the target rate, the
  server did not keep up;
- `http_429`: `count == 0`. The token quotas are raised above the rate, so any 429 means the run
  measured the limiter.

**Median of 3.** `run-perf.sh` runs three trials and ranks them by measured p99. The run fails
when any threshold of the median trial fails, or when that trial measured fewer than `RATE × 60`
requests (minus 1 for a scheduler boundary). The numbers of every trial are recorded either way.

**Idle memory.** The node starts and becomes ready, then stays idle for `IDLE_WAIT` seconds
(default 30) before setup or any load. `run-perf.sh` then reads `VmRSS` from the host's
`/proc/<pid>/status`, where `<pid>` is `docker inspect -f '{{.State.Pid}}'` of the node
container. The distroless image has no shell, and the runner's procfs shows the containerised
process. A value of 102,400 kB or more fails. If the value cannot be read, the run fails too: it
never skips.

### HA (`run-ha.sh`)

1. **Concurrent first start.** All three nodes are running and ready on their own ports after
   setup, and exactly one node installed (one distinct setup token in the logs).
2. **Restarts under load.** `ha.js` has the same failure, check, dropped-iteration and 429
   thresholds as `token.js`, and no latency threshold. All three nodes must be running
   afterwards. Each of the `USERS` admin API user creations sent through HAProxy during the
   restarts must answer 201.
3. **Exactly-once jobs.** The default tenant has a webhook endpoint for `user.created` pointing
   at the sink (`172.30.75.200`, inside `ANVILID_OUTBOUND_ALLOW_CIDRS`). After the deliveries
   arrive, plus a 50 s grace period that covers the 45 s delivery lease, the sink must report
   deliveries = unique `webhook-id`s = distinct `data.user_id`s = users created, with no
   duplicates and no malformed deliveries.
4. **Shared limit.** The nodes are recreated with token quotas of `SHARED_QUOTA` per second
   (burst = rate). `SHARED_PER_NODE` requests for the benchmark client are then fired at each of
   the three node ports at once (`Host: localhost:8080`, as through HAProxy). The bound is
   derived below.

#### Shared-limit bound

The bound comes from the 05-08 limiter contract (governor GCRA, pinned in
`crates/anvil-cache/src/limiter/contract.rs`). Take a quota of burst `b`, refilled every
`T = 1 s / rate`, with tolerance `tau = T × (b − 1)`. Starting from an unused key, it allows
exactly `b` requests at once and then one more per `T`. In a window of `W` seconds it therefore
allows at most `b + floor(W / T)` requests.

The HA stack sets `rate = burst = Q`, and the burst is fired within `W ≤ 1 s`, so:

```
allowed ≤ Q + ceil(Q × W) + 1
```

The `+ 1` absorbs the client-side measurement of `W` against server arrival times.

A per-node limiter would allow at least `3 × min(Q, SHARED_PER_NODE)`. With the defaults
(`Q = 10`, 30 per node, 90 requests in total), that is 30 per-node versus a shared bound of at
most 21.

The check also fails in these cases:

- the burst takes longer than 1 s (the result would be inconclusive);
- no request is limited;
- any status other than 200 or 429 comes back.

Both token buckets, per client and per IP, live in Valkey. The direct requests all come from the
compose gateway address, so they share one IP bucket as well.

## Runner size

The PRD figure (≥ 1,000 req/s at p99 < 50 ms on 4 vCPU) is measured on the public GitHub-hosted
`ubuntu-24.04` runner (4 vCPU, 16 GB). Those 4 vCPU are shared by k6, Postgres and AnvilID
(owner decision Q2: no paid runners). This is why the result is the median of three trials, and why
every image (Postgres, Valkey, HAProxy, Node, k6) is pinned by digest. The perf job writes the
runner's vCPU count and memory to the job summary.

## Configuration notes

- The default token quotas (50 req/s per IP, 100 req/s per client) would turn the benchmark into a
  rate-limiter test. Both scripts raise `ANVILID_RATE_LIMIT_TOKEN_PER_SECOND` and
  `ANVILID_RATE_LIMIT_TOKEN_CLIENT_PER_SECOND` above the test rate. The HA shared-limit phase
  lowers them through `RATE_LIMIT_TOKEN`.
- The HA nodes share Valkey (`ANVILID_REDIS_URL`), drain for 10 s on SIGTERM
  (`ANVILID_SHUTDOWN_DRAIN`) and use a pool of 20 connections. Breached-password lookups are off
  so the stack stays hermetic.
- HAProxy (`deploy/compose/ha/haproxy.cfg`) checks `/health/ready` every second (`fall 2 rise 2`)
  and retries only connection failures. Retrying a `POST /token` after an empty response or a
  timeout could replay a refresh token and revoke its family.

## CI

`.github/workflows/load.yml` has two jobs, `perf` and `ha`, each on its own runner. They run on
push to `main` (server, load and HA files), nightly at 03:17 UTC, and on demand
(`workflow_dispatch`, input `which` = `both` | `perf` | `ha`). They do not run on pull requests.
A missed target fails the job. Each job uploads `target/load/` (`load-perf`, `load-ha`).
