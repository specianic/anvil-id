# AnvilID

The easiest open-source identity and access platform to self-host.

> **Status: pre-release.** Release 0.1 is in development. Not ready for production use.

## Quickstart

AnvilID starts with no configuration. No container images are published yet, so build the image
locally (needs Docker; the build compiles a static binary inside the official Rust image):

```bash
just docker-image          # builds anvilid:ci
docker run -p 8080:8080 anvilid:ci
```

On first start the log prints a one-time setup URL:

```
Setup URL: http://localhost:8080/setup?token=…
```

Open it within one hour to create the first administrator. There are no default credentials. The
setup page then shows a management client id and secret for the admin API
(`http://localhost:8080/api/admin/v1`, OpenAPI document at `/api/admin/v1/openapi.json`), which
are shown only once.

Without a container, run the binary directly: `cargo run -p anvilid -- serve`. It listens on
`127.0.0.1:8080` and keeps its SQLite database and key-encryption key in `./anvilid-data/`. In the
container the data lives in `/data`; mount a volume there to keep it.

This runs in development mode (plain http on localhost; pages show a banner). For anything else set
`--public-url https://…` and use the built-in TLS listener (`--tls-cert`, `--tls-key`) or a TLS
proxy. `anvilid config show` lists every setting and where its value comes from.

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

### The one command

```bash
just ci
```

This runs formatting, clippy, cargo-deny, the crate dependency-rule check and the full test suite on
both storage backends. CI runs the same recipes.

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
