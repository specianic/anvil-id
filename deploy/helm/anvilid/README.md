# AnvilID Helm chart

Deploys [AnvilID](https://github.com/specianic/anvil-id), a self-hostable OpenID Connect provider,
from the distroless container image (`ghcr.io/specianic/anvil-id`).

```sh
helm install anvilid deploy/helm/anvilid
kubectl logs deployment/anvilid | grep "Setup URL"
```

The default is a single SQLite node with its data on a PersistentVolumeClaim. AnvilID generates a
key-encryption key (KEK) in `/data/kek` on first start; back it up with the database.

## Production: Postgres, several replicas

Create the Secret yourself (the chart never creates or stores secrets):

```sh
kubectl create secret generic anvilid \
  --from-literal=kek="$(openssl rand -base64 32)" \
  --from-literal=databaseUrl='postgres://USER:PASSWORD@DB_HOST:5432/anvilid' \
  --from-literal=redisUrl='redis://:PASSWORD@REDIS_HOST:6379'

helm install anvilid deploy/helm/anvilid \
  --set publicUrl=https://id.example.com \
  --set database.type=postgres \
  --set existingSecret.name=anvilid \
  --set redis.existingSecretKey=redisUrl \
  --set replicaCount=3 \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=id.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix \
  --set trustedProxies=10.0.0.0/8
```

Keep the KEK somewhere safe outside the cluster: without it the signing keys and secrets stored in
the database cannot be decrypted.

## Safety checks

`helm template` / `helm install` fail, with an explanation, when:

- `database.type=sqlite` and `replicaCount > 1` or `hpa.enabled` (one SQLite file, one writer);
- `database.type=postgres` without `existingSecret.name` (KEK and database URL);
- `replicaCount > 1` or `hpa.enabled` without `redis.url` / `redis.existingSecretKey`: each pod
  would enforce the rate limits alone, multiplying the budget by the number of pods. Set
  `redis.acknowledgePerNodeLimits=true` to accept that; NOTES.txt then prints a warning;
- `terminationGracePeriodSeconds <= shutdownDrainSeconds`.

`values.schema.json` rejects unknown keys and wrong types.

## What the chart deploys

- Deployment: probes on `/health/live` (startup, liveness) and `/health/ready` (readiness, 503 while
  draining or when the database is down); non-root uid 65532, read-only root filesystem, all
  capabilities dropped, seccomp `RuntimeDefault`, no service-account token, no service-link
  environment variables. On SIGTERM readiness turns 503 for `shutdownDrainSeconds` before the
  graceful shutdown (`terminationGracePeriodSeconds` must cover it). An emptyDir is mounted at
  `/tmp`. SQLite mode uses the `Recreate` strategy and mounts the data volume at `/data`.
- Service (`http`, and `metrics` when enabled), optional Ingress, optional ServiceMonitor, optional
  HorizontalPodAutoscaler, a PodDisruptionBudget when more than one pod can run, a PVC for SQLite.
- `helm test`: a curl pod (pinned by digest) that GETs `/health/ready` through the Service.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/specianic/anvil-id` | Image repository |
| `image.tag` | `""` (appVersion) | Image tag |
| `image.digest` | `""` | `sha256:...`; takes precedence over the tag |
| `image.pullPolicy` | `IfNotPresent` | Pull policy |
| `imagePullSecrets` | `[]` | Pull secrets |
| `nameOverride`, `fullnameOverride` | `""` | Resource name overrides |
| `replicaCount` | `1` | Pods (more than 1 needs Postgres and Redis or the acknowledgement) |
| `publicUrl` | `http://localhost:8080` | `ANVILID_PUBLIC_URL` |
| `insecureHttp` | `false` | Allow plain http on a non-loopback host (development only) |
| `database.type` | `sqlite` | `sqlite` or `postgres` |
| `database.maxConnections` | `10` | Postgres pool size per pod |
| `existingSecret.name` | `""` | Secret with the KEK and the database URL |
| `existingSecret.kekKey` | `kek` | Key of the base64 KEK (`ANVILID_KEK`) |
| `existingSecret.databaseUrlKey` | `databaseUrl` | Key of the Postgres URL (`ANVILID_DATABASE_URL`) |
| `redis.url` | `""` | Shared rate limiter URL without credentials (`ANVILID_REDIS_URL`) |
| `redis.existingSecretKey` | `""` | Key in `existingSecret` holding the Redis URL |
| `redis.failureMode` | `closed` | `closed` or `local` when Redis is unreachable |
| `redis.acknowledgePerNodeLimits` | `false` | Allow several pods without Redis |
| `metrics.enabled` | `true` | `/metrics` on a separate port (`ANVILID_METRICS_LISTEN`) |
| `metrics.port` | `9464` | Metrics port |
| `metrics.serviceMonitor.*` | disabled, `30s`, `10s`, `{}` | Prometheus Operator ServiceMonitor |
| `otel.endpoint` | `""` | OTLP/HTTP collector base URL (`ANVILID_OTEL_ENDPOINT`) |
| `otel.serviceName` | `anvilid` | `service.name` of exported traces |
| `shutdownDrainSeconds` | `10` | `ANVILID_SHUTDOWN_DRAIN` |
| `terminationGracePeriodSeconds` | `40` | Must exceed the drain |
| `trustedProxies` | `""` | Comma-separated CIDRs (`ANVILID_TRUSTED_PROXIES`) |
| `log.format` | `json` | `json` or `pretty` |
| `log.level` | `info` | `RUST_LOG` |
| `service.type`, `service.port`, `service.annotations` | `ClusterIP`, `8080`, `{}` | Service |
| `ingress.*` | disabled | Ingress (`className`, `annotations`, `hosts`, `tls`) |
| `persistence.enabled` | `true` | PVC for `/data` (SQLite); `false` uses an emptyDir |
| `persistence.existingClaim`, `storageClass`, `accessModes`, `size` | `""`, `""`, `[ReadWriteOnce]`, `1Gi` | Claim settings |
| `hpa.*` | disabled, 2, 5, 70 | HorizontalPodAutoscaler (Postgres only) |
| `pdb.minAvailable` | `1` | PodDisruptionBudget |
| `resources` | `{}` | Container resources |
| `podSecurityContext`, `securityContext` | non-root 65532, read-only, drop ALL | Security contexts |
| `extraEnv` | `[]` | Extra environment variables (EnvVar objects) |
| `podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity` | empty | Scheduling and metadata |
| `test.image` | `curlimages/curl:8.23.0@sha256:...` | `helm test` image |

## CI

`.github/workflows/deploy.yml` runs `helm lint`, kubeconform and `ct lint` on pull requests, and
`ct install` on kind with `ci/sqlite-values.yaml` and `ci/postgres-values.yaml` on pushes to main.
