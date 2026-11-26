# Installing AnvilID

AnvilID is one binary. It starts with no configuration: on first start it creates its database and
key-encryption key, and prints a one-time URL for creating the first administrator. There are no
default credentials.

This page covers the zero-config start, the release archives, the container image, Docker Compose
with Postgres and the Helm chart. Running it in production (backups, key rotation, several nodes,
metrics) is described in [Operating AnvilID](OPERATIONS.md).

## Zero-config start

Download a release (see [Binary archive](#binary-archive)) and run:

```sh
anvilid serve
```

- It listens on `127.0.0.1:8080`, with the public URL `http://localhost:8080`.
- It keeps the SQLite database, the key-encryption key (KEK) and a lock file in `./anvilid-data/`.
- The log prints `Setup URL: http://localhost:8080/setup?token=…`. Open it within one hour and
  create the first administrator. If the hour has passed, `anvilid admin setup-url` prints a new
  one-time URL.
- The setup result page shows a management client id and secret for the
  [management API](#next-steps). They are shown once.
- The admin console is at `http://localhost:8080/console/`.

On a plain-http localhost URL AnvilID runs in **development mode**: the pages show a banner, and
a few development conveniences are enabled (for example `http://localhost` origins and outbound
requests to loopback). Never expose development mode on a network.

## Binary archive

Every release publishes static Linux binaries (`x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`), macOS binaries (`aarch64-apple-darwin`, `x86_64-apple-darwin`), a
SHA-256 checksum file per archive and build provenance attestations. Set `V` to the release you
install (see the [Releases](https://github.com/specianic/anvil-id/releases) page) and `T` to your
platform:

```sh
V=1.0.0
T=x86_64-unknown-linux-musl
curl -fLO "https://github.com/specianic/anvil-id/releases/download/v$V/anvilid-$V-$T.tar.gz"
curl -fLO "https://github.com/specianic/anvil-id/releases/download/v$V/anvilid-$V-$T.tar.gz.sha256"
sha256sum -c "anvilid-$V-$T.tar.gz.sha256"        # macOS: shasum -a 256 -c ...
tar -xzf "anvilid-$V-$T.tar.gz"
./anvilid-$V-$T/anvilid --version
```

Optionally prove that the archive was built by this repository's release workflow (needs the
GitHub CLI):

```sh
gh attestation verify "anvilid-$V-$T.tar.gz" --repo specianic/anvil-id
```

The archive holds the `anvilid` binary, `LICENSE` and `README.md`. The admin console is embedded
in the binary. [Releasing](RELEASING.md) lists everything a release publishes.

## Container image

The image `ghcr.io/specianic/anvil-id:<version>` is multi-arch (linux/amd64, linux/arm64),
distroless and runs as a non-root user (uid 65532) without a shell. Its health check is
`anvilid healthcheck`.

```sh
docker run -p 8080:8080 -v anvilid-data:/data ghcr.io/specianic/anvil-id:$V
docker logs <container> 2>&1 | grep "Setup URL"
```

In the container AnvilID listens on `0.0.0.0:8080` and keeps its data in `/data`: mount a volume
there, or the database and the KEK are lost with the container.

Optionally verify the image provenance:

```sh
gh attestation verify "oci://ghcr.io/specianic/anvil-id:$V" --repo specianic/anvil-id
```

## Docker Compose with Postgres

The repository has a Compose file for AnvilID with Postgres in `deploy/compose/postgres/`:

```sh
cp deploy/compose/postgres/.env.example deploy/compose/postgres/.env
# fill in ANVILID_KEK (openssl rand -base64 32) and POSTGRES_PASSWORD (openssl rand -hex 24)
docker compose -f deploy/compose/postgres/compose.yml up -d
docker compose -f deploy/compose/postgres/compose.yml logs anvilid | grep "Setup URL"
```

`.env` is gitignored. Keep a copy of the KEK outside the host: without it the signing keys and the
secrets stored in the database cannot be decrypted. An overlay with an OpenTelemetry Collector and
Prometheus is in `deploy/compose/observability/`. See
[`deploy/README.md`](https://github.com/specianic/anvil-id/blob/main/deploy/README.md).

## Kubernetes (Helm)

The Helm chart is in `deploy/helm/anvilid/` in the repository. The default is one SQLite pod with
its data on a PersistentVolumeClaim:

```sh
helm install anvilid deploy/helm/anvilid
kubectl logs deployment/anvilid | grep "Setup URL"
```

For Postgres with several replicas, create a Secret with the KEK, the database URL and (for
shared rate limits) the Redis URL yourself; the chart never creates secrets. The chart refuses
unsafe combinations, such as SQLite with more than one replica. The values and examples are in
[`deploy/helm/anvilid/README.md`](https://github.com/specianic/anvil-id/blob/main/deploy/helm/anvilid/README.md).

## Going beyond localhost

For anything other than a local trial:

- Set the public URL: `--public-url https://id.example.com` (or `ANVILID_PUBLIC_URL`). Every
  issuer and endpoint URL derives from it.
- Terminate TLS with the built-in listener (`--tls-cert`, `--tls-key`) or a reverse proxy. Behind
  a proxy, set `--trusted-proxies` to its addresses, so rate limits see the real client IP.
- Passkeys need the public URL to be a host name, not an IP address.
- Configure SMTP (console or management API) so email verification and recovery work.

Every setting can come from a TOML file (`--config`, default `./anvilid.toml`), an `ANVILID_*`
environment variable or a flag. `anvilid serve --help` lists the flags, and
`anvilid config show` prints the effective value and source of every key.

## Where data lives

| Item | Binary | Container / Helm (SQLite) |
| --- | --- | --- |
| SQLite database | `./anvilid-data/anvilid.db` (`--data-dir`, `--database-url`) | `/data/anvilid.db` |
| Key-encryption key | `./anvilid-data/kek` (`--kek-file`, or `ANVILID_KEK`) | `/data/kek` |
| Postgres | `--database-url postgres://…` | from the Secret (Helm) or `.env` (Compose) |

Back up the database **and** the KEK. [What to back up](OPERATIONS.md#what-to-back-up) and
[Backup and restore](OPERATIONS.md#backup-and-restore-sqlite) explain how.

## Next steps

- Connect an application: [web application (OIDC)](guides/oidc-app.md),
  [single-page app](guides/spa.md), [native app](guides/native-app.md) or an
  [MCP server and AI agents](MCP.md).
- Move users in: [Migrating users](migration/).
- Automate: the management API is at `/api/admin/v1` (OpenAPI document at
  `/api/admin/v1/openapi.json`; the committed copy is
  [`docs/openapi/admin-v1.json`](openapi/admin-v1.json)). Tenant configuration can be kept in
  YAML ([Declarative tenant configuration](CONFIG-YAML.md)).
- Upgrading an existing installation: [Upgrading](UPGRADING.md).
