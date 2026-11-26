---
phase: 05-release-0-4-operate-it
plan: 22
subsystem: deployment, ci, observability
tags: [helm, kind, chart-testing, kubeconform, docker-compose, otel-collector, prometheus, healthcheck, ops-08, ops-09]

requires:
  - phase: 05-05
    provides: health/readyz, drain (ANVILID_SHUTDOWN_DRAIN), metrics listener, OTLP config keys, JSON logs
  - phase: 05-16
    provides: redis_url selects the shared limiter
  - phase: 05-17
    provides: anvilid healthcheck (loopback readiness probe for distroless)
provides:
  - "deploy/helm/anvilid chart (database.type sqlite|postgres, template-time safety checks, values.schema.json, helm test)"
  - "deploy/compose/postgres + deploy/compose/observability examples and deploy/compose/smoke.sh"
  - "Dockerfile exec-form HEALTHCHECK (anvilid healthcheck)"
  - ".github/workflows/deploy.yml (lint on PRs; kind ct install + compose smoke on main)"
affects: [05-27, 05-28]

tech-stack:
  added: [helm chart, chart-testing 3.15 (action v2.9.0), kind-action v1.15.2, setup-helm v5.1.0 with Helm v3.22.1, kubeconform v0.8.0, otel/opentelemetry-collector 0.166.0, prom/prometheus v3.13.0, curlimages/curl 8.23.0]
  patterns:
    - "Unsafe Helm values fail in a single anvilid.validate helper included from deployment.yaml"
    - "Secrets only via an operator-created existingSecret (chart) or env/.env (compose); CI generates random KEKs per run"
    - "Images pinned by digest, third-party actions pinned by SHA"

key-files:
  created:
    - deploy/helm/anvilid/Chart.yaml
    - deploy/helm/anvilid/values.yaml
    - deploy/helm/anvilid/values.schema.json
    - deploy/helm/anvilid/README.md
    - deploy/helm/anvilid/templates/_helpers.tpl
    - deploy/helm/anvilid/templates/deployment.yaml
    - deploy/helm/anvilid/templates/service.yaml
    - deploy/helm/anvilid/templates/ingress.yaml
    - deploy/helm/anvilid/templates/servicemonitor.yaml
    - deploy/helm/anvilid/templates/pdb.yaml
    - deploy/helm/anvilid/templates/hpa.yaml
    - deploy/helm/anvilid/templates/pvc.yaml
    - deploy/helm/anvilid/templates/NOTES.txt
    - deploy/helm/anvilid/templates/tests/test-ready.yaml
    - deploy/helm/anvilid/ci/sqlite-values.yaml
    - deploy/helm/anvilid/ci/postgres-values.yaml
    - deploy/helm/ci/postgres.yaml
    - ct.yaml
    - deploy/compose/postgres/compose.yml
    - deploy/compose/postgres/.env.example
    - deploy/compose/observability/compose.yml
    - deploy/compose/observability/otel-collector.yaml
    - deploy/compose/observability/prometheus.yml
    - deploy/compose/smoke.sh
    - deploy/README.md
    - .github/workflows/deploy.yml
  modified:
    - Dockerfile

key-decisions:
  - "Chart drain is shutdownDrainSeconds (integer) so the template can enforce terminationGracePeriodSeconds > drain"
  - "Collector uses the core image with the debug exporter (spans in the collector log) instead of a file exporter: no contrib image, no volume permission issues; smoke.sh greps service.name: Str(anvilid)"
  - "Pod sets enableServiceLinks: false so a Service named *anvilid* cannot inject ANVILID_* variables"
  - "Postgres CI values run 2 replicas with redis.acknowledgePerNodeLimits=true (PDB + concurrent first start on kind)"
  - "SQLite without existingSecret is allowed (KEK generated in /data/kek, NOTES warns); Postgres requires existingSecret"

requirements-completed: [OPS-08, OPS-09]

duration: 25min
completed: 2026-11-26
---

# Phase 5 Plan 22: Helm chart, Compose examples and deploy workflow Summary

**An in-repo Helm chart (SQLite single node or Postgres with several replicas, with template-time refusals for unsafe replica, secret and drain settings), Compose examples for Postgres plus an OpenTelemetry Collector/Prometheus overlay, a distroless exec-form Docker HEALTHCHECK, and a deploy workflow that lints on PRs and installs on kind and smoke-tests Compose on main.**

## Performance

- Duration: about 25 min
- Tasks: 2/2
- Files: 26 created, 1 modified

## Chart values (deploy/helm/anvilid)

| Value | Default | Effect |
| --- | --- | --- |
| `database.type` | `sqlite` | sqlite: `/data` volume (PVC, or emptyDir with `persistence.enabled=false`), `ANVILID_DATA_DIR=/data`, `Recreate` strategy. postgres: `ANVILID_DATABASE_URL` from `existingSecret.databaseUrlKey`, pool size `database.maxConnections` |
| `existingSecret.{name,kekKey,databaseUrlKey}` | `""`, `kek`, `databaseUrl` | `ANVILID_KEK` (and the DB URL) via secretKeyRef; the chart never creates secrets |
| `redis.{url,existingSecretKey,failureMode,acknowledgePerNodeLimits}` | `""`, `""`, `closed`, `false` | `ANVILID_REDIS_URL`, `ANVILID_RATE_LIMIT_REDIS_FAILURE` |
| `metrics.{enabled,port,serviceMonitor.*}` | `true`, `9464`, off | `ANVILID_METRICS_LISTEN=0.0.0.0:9464`, Service port `metrics`, optional ServiceMonitor |
| `otel.{endpoint,serviceName}` | `""`, `anvilid` | `ANVILID_OTEL_ENDPOINT`, `ANVILID_OTEL_SERVICE_NAME` |
| `shutdownDrainSeconds` / `terminationGracePeriodSeconds` | `10` / `40` | `ANVILID_SHUTDOWN_DRAIN=10s`; grace must exceed the drain |
| `publicUrl`, `insecureHttp`, `trustedProxies`, `log.{format,level}` | localhost dev URL, false, `""`, json/info | the matching ANVILID_* / RUST_LOG |
| `ingress`, `hpa`, `pdb.minAvailable`, `persistence`, `resources`, security contexts, `extraEnv`, scheduling, `test.image` | see README | |

Template-time failures (`anvilid.validate`): sqlite with `replicaCount > 1` or HPA; postgres without `existingSecret.name`/keys; `replicaCount > 1` or HPA without `redis.url`/`redis.existingSecretKey` unless `redis.acknowledgePerNodeLimits=true` (message explains the multiplied budget; NOTES.txt warns when acknowledged); `terminationGracePeriodSeconds <= shutdownDrainSeconds`. `values.schema.json` declares every value with `additionalProperties: false`.

Deployment: startup/liveness on `/health/live`, readiness on `/health/ready`; uid/gid 65532, runAsNonRoot, readOnlyRootFilesystem, drop ALL, seccomp RuntimeDefault, no SA token, no service links; emptyDir `/tmp`. PDB when more than one pod can run. `helm test` pod: curl (pinned digest, non-root, read-only) GETs `/health/ready` through the Service.

## Task Commits

1. **Task 1: Helm chart** - `565c127` (feat)
2. **Task 2: Compose examples, Docker HEALTHCHECK, smoke test, deploy workflow** - `62c41ef` (feat)

## Verified locally

- Helm v3.17.0 is installed: `helm lint --strict` on the defaults and both CI values files passes (only INFO "icon is recommended"). `helm template` renders the defaults, both CI values and an everything-on variant (Ingress with TLS, ServiceMonitor, HPA, Redis from the secret, OTel, trusted proxies, digest image), and `persistence.enabled=false` (emptyDir).
- The plan's verify command passes: `--set replicaCount=2` fails; postgres values with 2 replicas and no Redis fail; with `redis.url` they render. The workflow's `must_fail` block was run locally as written: all eight unsafe cases (sqlite x2, postgres without secret, no Redis x2, short grace, bad `database.type`, unknown key) are refused, and the positive case renders.
- `values.yaml` validates against `values.schema.json` (python jsonschema), and every key in values.yaml is declared in the schema.
- yamllint with chart-testing's lint rules on Chart.yaml, values.yaml, the CI values, the kind Postgres manifest and ct.yaml: clean. yamllint (relaxed) on the compose files and deploy.yml: clean apart from line length.
- `bash -n deploy/compose/smoke.sh`; all compose/collector/Prometheus/workflow YAML parses; `HEALTHCHECK` in the Dockerfile.
- Image digests were resolved from the registry (Docker Hub manifest HEAD), and action SHAs from `git ls-remote` of the tags. The kubeconform tarball checksum comes from its v0.8.0 CHECKSUMS file.
- `git grep -nE "BEGIN|password=|kek=" deploy/` finds only the `openssl rand` placeholder in the chart README.

## Not run locally (CI only, verify at the 05-28 gate)

- **kubeconform**: not installed. I tried downloading it into the scratchpad, but the sandbox denied that, so the deploy.yml lint job is the first kubeconform run.
- **ct lint** (yamale/Chart schema, maintainers) and **ct install on kind**: neither ct nor kind is installed. That includes both installs (SQLite with PVC and KEK secret, Postgres with 2 replicas), `helm test`, and the image pull policy `Never` after `kind load`.
- **Docker / Compose**: the Docker CLI is not usable here (exit 126), so `docker compose config`, `smoke.sh`, the image HEALTHCHECK and `scripts/docker-image.sh` with the new HEALTHCHECK did not run.
- Things that only a real run can prove: the collector debug output format (`service.name: Str(anvilid)`); that both Compose path resolutions of `../observability/...` work; that Prometheus reports `up{job="anvilid"} == 1` within 60 s; that discovery before setup answers with Host `localhost:8080`; that two Postgres replicas come up concurrently on kind.

## Deviations from Plan

### Auto-fixed / adjusted

**1. [Rule 2 - Missing critical] `enableServiceLinks: false` on the pod**
- Kubernetes service links inject `<SERVICE>_PORT`-style variables. A release whose Service name starts with `anvilid` (ct uses random `anvilid-xxxx` names) would put `ANVILID_*` variables into anvilid's configuration namespace.

**2. [Rule 2] emptyDir at `/tmp`**
- The root filesystem is read-only, so SQLite temp files and the runtime get a writable scratch directory.

**3. Drain value as integer seconds (`shutdownDrainSeconds`)** instead of a duration string, so that the template can enforce grace > drain.

**4. Collector debug exporter instead of a file exporter** (plan: "file exporter to a volume"; research: "file/debug"). This avoids the larger contrib image and volume ownership problems. smoke.sh reads the span from the collector log.

**5. Extra checks in smoke.sh**: the container health status from `anvilid healthcheck`, discovery, and the Prometheus scrape (`up == 1`). The JSON check reads stderr only (`docker logs 2>&1 >/dev/null`), so the audit JSON on stdout cannot satisfy it.

**6. Extra lint steps in deploy.yml**: the unsafe-values `must_fail` checks, and kubeconform over every values variant, including everything on.

### Extra file (outside files_modified)
- `deploy/compose/postgres/.env.example`: the plan asks for ".env.example documented". It holds empty placeholders, and `.env` stays gitignored.

## Issues Encountered
- Docker Hub's tag API rate-limited some lookups, so digests were resolved through the registry manifest endpoint instead.

## Next Phase Readiness
- 05-28 should push and confirm that deploy.yml's lint, kind and compose jobs pass. 05-27 docs can link deploy/README.md and the chart README.

---
*Phase: 05-release-0-4-operate-it*
*Completed: 2026-11-26*

## Self-Check: PASSED
