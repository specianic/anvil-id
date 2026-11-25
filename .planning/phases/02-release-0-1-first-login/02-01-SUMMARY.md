---
phase: 02-release-0-1-first-login
plan: 01
subsystem: crypto-jose / build
tags: [jose, jwt, jwks, kek, pkce, client-assertion, cargo-deny, ci, workflows]
requires: []
provides:
  - "Every Phase 2 third-party dependency in [workspace.dependencies], all crate manifests and Cargo.lock"
  - "anvil-jose: generate_rs256, SigningKey, Kek, Jwk/Jwks/thumbprint, verify_jwt, verify_client_assertion, verify_op_token, PKCE and encoding helpers"
  - "just recipes: test-pg, e2e, qual04, docker-image, fuzz-smoke, fuzz, release-graph, security-tests, openapi-update; sqlx-prepare/sqlx-check crate filter"
  - "Workflows: ci (sqlite/postgres matrix + release-graph), conformance (Basic + Config OP, 60 min), e2e, fuzz"
affects: [02-02, 02-03, 02-04, 02-05, 02-06, 02-07, 02-16, 02-17, 02-20, 02-21]
tech-stack:
  added:
    - jsonwebtoken 12.0.0 (aws_lc_rs, use_pem)
    - base64 0.23.1
    - subtle 2.6.1
    - secrecy 0.10.3
    - zeroize 1.9.2 (derive)
    - argon2 0.6.0 (alloc, password-hash)
    - minijinja 3.1.0 (serde)
    - lettre 0.11.24 (tokio1-rustls, aws-lc-rs, webpki-roots, smtp-transport, builder, hostname, pool)
    - utoipa 6.0.0 (axum_extras, uuid, time)
    - utoipa-axum 0.3.0
    - axum-extra 0.12.6 (cookie, typed-header)
    - tower-http 0.6.11 (cors, set-header, limit, trace, request-id, util)
    - figment 0.10.19 (toml, env)
    - reqwest 0.13.5 (rustls = aws-lc-rs provider, json)
    - rustls 0.23.46 / tokio-rustls 0.26.6 (aws_lc_rs, no ring)
    - hyper 1.13 / hyper-util 0.1.21 (server-auto, tokio, service)
    - dev: proptest 1.12.0, insta 1.49.0 (json), wiremock 0.6.5
  patterns:
    - "Own JOSE headers/JWKs/thumbprints; jsonwebtoken only for crypto::sign / crypto::verify"
    - "RSA PKCS#8 wrapped as PRIVATE KEY PEM -> EncodingKey::from_rsa_pem, validated with aws-lc-rs first"
    - "Explicit claim validation (no jsonwebtoken Validation)"
key-files:
  created:
    - crates/anvil-jose/src/error.rs
    - crates/anvil-jose/src/encoding.rs
    - crates/anvil-jose/src/pkce.rs
    - crates/anvil-jose/src/kek.rs
    - crates/anvil-jose/src/jwk.rs
    - crates/anvil-jose/src/keys.rs
    - crates/anvil-jose/src/jws.rs
    - crates/anvil-jose/src/client_assertion.rs
    - crates/anvil-jose/src/op_token.rs
    - .github/workflows/e2e.yml
    - .github/workflows/fuzz.yml
  modified:
    - Cargo.toml
    - Cargo.lock
    - crates/*/Cargo.toml (all except anvil-cache)
    - deny.toml
    - scripts/check-deps.sh
    - scripts/sqlx.sh
    - justfile
    - .github/workflows/ci.yml
    - .github/workflows/conformance.yml
    - crates/anvil-jose/src/lib.rs
decisions:
  - "jsonwebtoken::crypto::{sign, verify} are public in 12.0.0 and used; no direct aws-lc-rs signing fallback needed"
  - "tower-http pinned to 0.6.x (the line reqwest 0.13 already resolves) to avoid a duplicate"
  - "deny.toml: added 0BSD (quoted_printable via lettre); no bans loosened, ring still denied and absent"
  - "Client assertions also reject future nbf/iat (beyond leeway) and jti longer than 256 chars"
  - "verify_jwt rejects any crit header, keys whose use != sig or whose alg differs, and ambiguous key selection (UnknownKey)"
metrics:
  duration: 16min
  completed: 2026-11-25
---

# Phase 2 Plan 01: Dependency foundation and anvil-jose Summary

This plan does two things. It declares every dependency Phase 2 needs in the workspace and the crate manifests, together with the just recipes and the four workflow files, so no later plan has to touch them. It also delivers a complete `anvil-jose` crate: RS256 keys from aws-lc-rs with RFC 7638 kids, an HKDF-derived AES-256-GCM key-encryption envelope, strict JWS verification, `private_key_jwt` assertion rules, checks for tokens this server issued, and PKCE and hash helpers. 57 unit tests cover it, including the RFC test vectors and the negative cases.

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | Phase 2 dependency foundation, recipes and workflows | 74d186c |
| 2 | anvil-jose keys, KEK envelope, JWK/JWKS, signing, encoding, PKCE | 3f4fce2 |
| 3 | JWS verification, client assertions, OP-token checks; anvil-core -> anvil-jose | 14ccd38 |

## What was built

- **Workspace deps**: all versions are listed in the frontmatter. The workspace `tokio` gained the `fs`, `process` and `io-util` features. Cargo.lock only gained entries; Phase 1 pins (sqlx, axum, tokio) are unchanged. `ring` is absent from normal deps on every target.
- **check-deps.sh**: `secrecy` was added to the anvil-core allowlist. The self-test passes.
- **sqlx.sh**: now takes `prepare|check [crates/<storage-crate>]`. Each crate gets its own SQLite dev DB at `target/sqlx/<crate>-dev.db`. An unknown crate exits with status 2. justfile: `sqlx-prepare crate=""` and `sqlx-check crate=""`.
- **anvil-jose API**: matches the plan's `<interfaces>` block, with these small additions:
  - `Alg::is_rsa()` and `Display` for `Alg`.
  - `SigningKey::alg()`.
  - `SigningKey::from_pkcs8` also accepts `Alg::ES256` (P-256 PKCS#8).
  - `jws::MAX_JWS_LEN`.
  - `client_assertion::CLIENT_ASSERTION_TYP`.
  - Crate-root re-exports of the main types.
  - `JoseError` also derives `Clone`, `PartialEq` and `Eq`.
- **Kek::from_base64**: accepts standard base64 with padding or base64url without padding, and trims surrounding whitespace. `to_base64` emits standard base64 with padding.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] License 0BSD added to deny.toml**
- **Found during:** Task 1
- **Issue:** `quoted_printable` (via lettre) is 0BSD, and the license check failed on it.
- **Fix:** Added `"0BSD"` with a comment saying why. Bans are unchanged.
- **Commit:** 74d186c

No other deviations. The TDD tasks were committed as one commit per task, with the tests inside each module. There were no separate RED commits.

## Verification

- `cargo test -p anvil-jose`: 57 passed. `cargo clippy -p anvil-jose --all-targets -- -D warnings`: clean.
- `cargo deny --locked check`: advisories, bans, licenses and sources all ok.
- `scripts/check-deps.sh` and `--self-test`: OK.
- `just --summary` lists all 9 new recipes. All four workflow files parse as YAML.
- `cargo tree -p anvil-core -e normal --depth 1` includes anvil-jose.

## Self-Check: PASSED
