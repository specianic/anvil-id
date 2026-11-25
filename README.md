# AnvilID

The easiest open-source identity and access platform to self-host.

> **Status: M0 (foundations and spikes).** Not ready for use yet.

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

## License

MIT — see [LICENSE](LICENSE).
