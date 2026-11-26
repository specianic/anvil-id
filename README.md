# AnvilID

The easiest open-source identity and access platform to self-host.

> **Status: early release (0.2 "Secure by default").** Not ready for production use.

What works today: an OpenID Connect provider (authorization code with PKCE, refresh-token rotation,
client credentials, `query` and `form_post` response modes, introspection and revocation, RS256 /
ES256 / Ed25519 signing with automatic key rotation), sign-in with password, passkeys and TOTP with
recovery codes, a consent screen, self-service account pages (passkeys, TOTP, sessions, connected
apps), registration, email verification and recovery, rate limiting and brute-force protection with
optional CAPTCHA, an audit log, and an admin console at `/console/` on top of the management API.
Upgrading from 0.1: see [docs/UPGRADING.md](docs/UPGRADING.md).

Coming in 0.4 "Operate it" (on `main`, not released yet):

- A multi-tenant admin console: create tenants and switch between them.
- Roles and permissions, mapped into tokens, and role-based console access
  ([docs/UPGRADING.md](docs/UPGRADING.md#03-to-04)).
- Custom user attributes validated with JSON Schema, editable by users on their account page.
- Signed webhooks for user and session events ([docs/WEBHOOKS.md](docs/WEBHOOKS.md)).
- Dynamic client registration (RFC 7591/7592) and Client ID Metadata Documents, both off by
  default, with resource-aware consent for MCP clients ([docs/MCP.md](docs/MCP.md),
  [docs/OPERATIONS.md](docs/OPERATIONS.md#client-registration-policies)).
- Declarative tenant configuration in YAML: export, plan, apply ([docs/CONFIG-YAML.md](docs/CONFIG-YAML.md)).
- Several nodes on Postgres with shared rate limits in Redis, health and readiness probes with
  drain, Prometheus metrics, OpenTelemetry traces, online SQLite backups and shell-only admin
  recovery ([docs/OPERATIONS.md](docs/OPERATIONS.md)).
- A Helm chart and Docker Compose examples ([deploy/README.md](deploy/README.md)).

## Install

Every release publishes static Linux binaries (x86_64, arm64), macOS binaries (Apple silicon,
Intel) and a multi-arch container image. See [Releases](https://github.com/specianic/anvil-id/releases)
and [docs/RELEASING.md](docs/RELEASING.md) for what is published and how to verify it.

**Container image** (linux/amd64, linux/arm64, under 50 MB, runs as nonroot):

```bash
docker run -p 8080:8080 ghcr.io/specianic/anvil-id:0.2.0
```

Data (SQLite database and key-encryption key) lives in `/data` in the container; mount a volume
there to keep it (`-v anvilid-data:/data`).

**Binary** (replace the target with `aarch64-unknown-linux-musl`, `aarch64-apple-darwin` or
`x86_64-apple-darwin` as needed):

```bash
V=0.2.0
T=x86_64-unknown-linux-musl
curl -fLO "https://github.com/specianic/anvil-id/releases/download/v$V/anvilid-$V-$T.tar.gz"
curl -fLO "https://github.com/specianic/anvil-id/releases/download/v$V/anvilid-$V-$T.tar.gz.sha256"
sha256sum -c "anvilid-$V-$T.tar.gz.sha256"     # macOS: shasum -a 256 -c ...
tar -xzf "anvilid-$V-$T.tar.gz"
./anvilid-$V-$T/anvilid serve
```

Optionally check build provenance with the GitHub CLI:
`gh attestation verify "anvilid-$V-$T.tar.gz" --repo specianic/anvil-id`.

## Quickstart

AnvilID starts with no configuration. Start the container (above) or the binary; to build the image
from source instead, run `just docker-image` (needs Docker) and `docker run -p 8080:8080 anvilid:ci`.

On first start the log prints a one-time setup URL:

```
Setup URL: http://localhost:8080/setup?token=…
```

Open it within one hour to create the first administrator. There are no default credentials. The
setup page then shows a management client id and secret for the admin API
(`http://localhost:8080/api/admin/v1`, OpenAPI document at `/api/admin/v1/openapi.json`), which
are shown only once.

The admin console is at `http://localhost:8080/console/`: sign in with the administrator you just
created to manage clients, users, sessions, email templates and SMTP, and to search the audit log. Users manage
their own passkeys, TOTP, sessions and connected apps at `/ui/account/security`.

The binary (`anvilid serve`, or `cargo run -p anvilid -- serve` from source) listens on
`127.0.0.1:8080` and keeps its SQLite database and key-encryption key in `./anvilid-data/`. In the
container the data lives in `/data`; mount a volume there to keep it.

This runs in development mode (plain http on localhost; pages show a banner). For anything else set
`--public-url https://…` and use the built-in TLS listener (`--tls-cert`, `--tls-key`) or a TLS
proxy. Behind a proxy, set `--trusted-proxies` to its addresses so rate limits see the real client
IP. Passkeys need the public URL to be a host name (not an IP address). `anvilid config show` lists
every setting and where its value comes from.

### Sample application

[`examples/node-rp`](examples/node-rp) is a small OpenID Connect relying party (authorization code
with PKCE, UserInfo, refresh-token rotation). Its README shows how to register it as a client and
run it against a local AnvilID. `just qual04 sqlite` (or `postgres`) runs the whole path from
`docker run` to a signed-in user in the sample app and fails if it takes longer than two minutes.

### Standards conformance

[`tests/conformance`](tests/conformance) runs the OpenID Foundation conformance suite against a
local build (`just conformance`).

Planning documents:

- [docs/PRD.md](docs/PRD.md) — product requirements
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — architecture & implementation specification
- [docs/UPGRADING.md](docs/UPGRADING.md) — upgrade notes
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — operating AnvilID (backups, HA, metrics, traces)
- [docs/WEBHOOKS.md](docs/WEBHOOKS.md) — webhook events and signature verification
- [docs/CONFIG-YAML.md](docs/CONFIG-YAML.md) — declarative tenant configuration

## Development

### Prerequisites

- [rustup](https://rustup.rs). The toolchain is selected automatically from `rust-toolchain.toml`.
- `just`: `cargo install just --locked`
- `cargo-deny`: `cargo install cargo-deny --locked`. Run this inside the repository so the pinned
  toolchain is used (recent cargo-deny releases need a newer rustc than some distro defaults).
- `sqlx-cli` 0.9.1 (0.8.x does not understand the per-crate `sqlx.toml` files):

  ```bash
  cargo install sqlx-cli --version 0.9.1 --no-default-features --features rustls,sqlite,postgres,sqlx-toml
  ```

  Do not pass `--locked` here.
- Docker, for the Postgres tests and the OpenID conformance suite.
- Node.js 22.12 or newer, for the admin console (`just console-build` builds it into
  `admin-ui/dist`, which release builds embed).

### The one command

```bash
just ci
```

This runs formatting, clippy, cargo-deny, the crate dependency-rule check, the migration lint, the
full test suite on both storage backends, the security-test map and the admin console type check
(needs Node.js 22.12 or newer). CI runs the same recipes.

Other recipes (`just --list` shows all of them):

- `just fmt` — format the code
- `just test` — run the test suite only
- `just sqlx-prepare` / `just sqlx-check` — regenerate / verify the offline sqlx query metadata
  (uses the local development Postgres started by `just db-up`)
- `just musl [target]` — static musl release build
- `just measure <bin> <target>` — binary size and idle memory report
- `just conformance` — run the OpenID conformance suite locally
- `just clean-test-containers` — remove leftover test containers
- `just docker-image` — build the container image and check it is under 50 MB
- `just qual04 sqlite|postgres` — zero-config start to sample-app login, timed (two-minute limit)
- `just e2e [sqlite|postgres]` — Playwright browser tests against a local build, with Mailpit as
  the SMTP sink (first run `npm ci --prefix tests/e2e`, `npm ci --prefix examples/node-rp` and
  `npx --prefix tests/e2e playwright install chromium`)

## License

MIT — see [LICENSE](LICENSE).
