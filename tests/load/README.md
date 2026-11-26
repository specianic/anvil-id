# Load and HA tests

Two harnesses, both driven by [k6](https://grafana.com/docs/k6/) and Docker Compose:

| Script | Requirement | What it does |
|---|---|---|
| `run-perf.sh` | QUAL-05 (PRD §6.3) | Postgres 18 and one `anvilid:ci` node. `token.js` runs `client_credentials` with `client_secret_basic` at a constant arrival rate of 1,000 req/s: a 15 s warm-up, then a 60 s measured run. |
| `run-ha.sh` | OPS-03 | `deploy/compose/ha`: Postgres, Valkey, HAProxy and three nodes started together on an empty database. `ha.js` sends 300 req/s through HAProxy for 120 s while node1, node2 and node3 are restarted 20 s apart. |

`lib.sh` holds the shared steps. It waits for readiness, reads the one-time setup URL from the
logs, completes setup, creates a system-tenant admin client and a `client_credentials` benchmark
client in the `default` tenant, runs k6 and writes the job summary.

## Running

```sh
just docker-image          # builds anvilid:ci
tests/load/run-perf.sh     # RATE=1000 TRIALS=3 by default
tests/load/run-ha.sh       # RATE=300 RESTART_SPACING=20 by default
```

Both need Docker with Compose, `curl` and `python3`. They use the `k6` binary when it is on
`PATH`. Otherwise they use the `grafana/k6` image pinned in `lib.sh`. Host port 8080 must be free.
Results (k6 JSON summaries, a markdown table, redacted service logs) go to `target/load/`
(`LOAD_OUT` overrides this). On GitHub Actions the table is also appended to the job summary.

The KEK is generated for each run and kept only in the environment. The client credentials stay
in a private temp directory that is removed on exit, and the logs are written with setup tokens
and credentials redacted.

## Pass/fail rules

`token.js` thresholds (k6 exits non-zero when one fails):

- `http_req_duration{phase:measure}`: `p(99) < 50` ms (the warm-up is excluded);
- `http_req_failed`: `rate == 0`;
- `checks`: `rate == 1` (every response is 200);
- `dropped_iterations`: `count == 0`. If k6 could not start an iteration at the target rate, the
  server did not keep up.

**Median of 3.** `run-perf.sh` runs three trials and ranks them by measured p99. The run fails
when any threshold of the median trial fails. The numbers of every trial are recorded either way.

`ha.js` has the same failure, check and dropped-iteration thresholds and no latency threshold.
`run-ha.sh` also fails when a node does not survive the concurrent first start, or when fewer than
three nodes are running after the restarts.

## Runner size

The PRD figure (≥ 1,000 req/s at p99 < 50 ms on 4 vCPU) is measured on the public GitHub-hosted
`ubuntu-24.04` runner (4 vCPU, 16 GB). Those 4 vCPU are shared by k6, Postgres and AnvilID
(owner decision Q2: no paid runners). This is why the result is the median of three trials, and why
every image (Postgres, Valkey, HAProxy, k6) is pinned by digest.

## Configuration notes

- The default token quotas (50 req/s per IP, 100 req/s per client) would turn the benchmark into a
  rate-limiter test. Both scripts raise `ANVILID_RATE_LIMIT_TOKEN_PER_SECOND` and
  `ANVILID_RATE_LIMIT_TOKEN_CLIENT_PER_SECOND` above the test rate.
- `ANVILID_DATABASE_MAX_CONNECTIONS`, `ANVILID_SHUTDOWN_DRAIN` and `ANVILID_REDIS_URL` are set
  already. They take effect once plans 05-05 and 05-16 add these keys. Until then anvilid ignores
  them, because it reads only the `ANVILID_*` keys it knows.
- HAProxy (`deploy/compose/ha/haproxy.cfg`) checks `/health/ready` every second (`fall 2 rise 2`)
  and retries only connection failures. Retrying a `POST /token` after an empty response or a
  timeout could replay a refresh token and revoke its family.

## Status

Nothing here is a required check yet. `.github/workflows/load.yml` runs only on demand
(`workflow_dispatch`, input `which` = `both` | `perf` | `ha`). Plan 05-18 does the performance work.
Plan 05-26 adds the shared-limit and webhook checks to the HA test, adds the push-to-main and
nightly triggers, and makes the workflow gating.
