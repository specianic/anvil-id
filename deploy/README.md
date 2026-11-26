# Deploying AnvilID

| Path | What it is |
| --- | --- |
| `helm/anvilid/` | Helm chart (SQLite single node or Postgres with several replicas); see its README |
| `compose/postgres/` | Docker Compose: AnvilID + Postgres |
| `compose/observability/` | Compose overlay: OpenTelemetry Collector + Prometheus |
| `compose/smoke.sh` | CI smoke test of the two Compose files |
| `compose/ha/` | HA test stack (3 nodes, Valkey, HAProxy) used by the load tests |
| `compose/qual04-postgres.yml` | Test-only stack for `scripts/qual04.sh` |

The container image is `ghcr.io/specianic/anvil-id:<version>` (distroless, non-root uid 65532, no
shell). The binary is `/usr/local/bin/anvilid`; `anvilid healthcheck` is the image's Docker
`HEALTHCHECK` (it GETs `/health/ready` on the loopback port of `ANVILID_LISTEN`).

## Zero config

```sh
docker run -p 8080:8080 -v anvilid-data:/data ghcr.io/specianic/anvil-id:0.4.0
```

The setup URL for the first administrator is printed in the logs.

## Docker Compose with Postgres

```sh
cp deploy/compose/postgres/.env.example deploy/compose/postgres/.env
# fill in ANVILID_KEK (openssl rand -base64 32) and POSTGRES_PASSWORD (openssl rand -hex 24)
docker compose -f deploy/compose/postgres/compose.yml up -d
docker compose -f deploy/compose/postgres/compose.yml logs anvilid | grep "Setup URL"
```

`.env` is gitignored; keep a copy of the KEK outside the host. AnvilID listens on port 8080; put a
TLS-terminating reverse proxy in front, set `ANVILID_PUBLIC_URL` to the https URL and
`ANVILID_TRUSTED_PROXIES` to the proxy's address.

With traces and Prometheus:

```sh
docker compose -f deploy/compose/postgres/compose.yml \
               -f deploy/compose/observability/compose.yml up -d
```

- Health: `/health/live` (`/healthz`) and `/health/ready` (`/readyz`; 503 while draining or when the
  database is unreachable).
- Metrics: `http://127.0.0.1:9464/metrics` (`ANVILID_METRICS_LISTEN`), scraped by Prometheus at
  `http://127.0.0.1:9090`.
- Traces: OTLP/HTTP to the collector (`ANVILID_OTEL_ENDPOINT`); the example collector prints them
  (`docker compose ... logs otel-collector`). Point its exporter at your tracing backend.
- Logs: JSON on stderr (`ANVILID_LOG_FORMAT=json`); audit events as JSON lines on stdout.
- Shutdown: on SIGTERM readiness turns 503 for `ANVILID_SHUTDOWN_DRAIN` (10 s) before the graceful
  shutdown; `stop_grace_period` is 30 s.

## Kubernetes (Helm)

```sh
helm install anvilid deploy/helm/anvilid                       # SQLite, one pod
```

For Postgres, several replicas and the shared rate limiter see
[`helm/anvilid/README.md`](helm/anvilid/README.md).

## CI

`.github/workflows/deploy.yml`: on pull requests `helm lint`, unsafe-values checks, kubeconform and
`ct lint`; on pushes to main `ct install` on kind (SQLite and Postgres values, `helm test`) and
`compose/smoke.sh` (ready, `anvil_http_requests_total` on `/metrics`, Prometheus scrape, a JSON
stderr line, a span with `service.name=anvilid` in the collector).
