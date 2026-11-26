---
phase: 05-release-0-4-operate-it
plan: 18
subsystem: token-endpoint performance
tags: [performance, signing, cache, tenant-resolution, QUAL-05]
requires:
  - phase: 05-03
    provides: KeyRepo active-key read path used per request
  - phase: 05-05
    provides: AppState::unknown_hosts() moka cache and AppConfig.unknown_host_ttl
provides:
  - content-addressed signer cache private to anvil-core service/key.rs
  - anvil-jose SigningKey holding a parsed aws-lc key pair (cheap Clone, direct signing)
  - unknown-host negative cache in anvil-web tenant.rs
affects: [05-26 (CI perf gate), 05-27 (OPERATIONS notes: host TTL)]
tech-stack:
  added: []
  patterns:
    - "Process-wide std-only cache (static OnceLock<RwLock<HashMap>>) keyed by content hashes, never by mutable identity alone"
    - "Negative-only caching for lookups whose miss is harmless; positive rows always re-read"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/service/key.rs
    - crates/anvil-jose/src/keys.rs
    - crates/anvil-jose/src/jws.rs
    - crates/anvil-jose/src/pem.rs
    - crates/anvil-web/src/tenant.rs
    - crates/anvil-web/tests/jwks_rotation.rs
    - crates/anvil-web/tests/security_tenant.rs
decisions:
  - "Signer cache key = (tenant, alg, kid, row id, sha256(sealed bytes), KEK fingerprint); the KEK fingerprint is sha256 of a domain-separated HKDF output, so an entry opened with one KEK never serves another"
  - "Inserting a signer drops older entries of the same tenant+alg (retired key material leaves memory); map bounded to 1024 entries, cleared on overflow"
  - "Direct aws-lc signing adopted after profiling: jsonwebtoken re-parsed the RSA DER per signature (RS256 504us -> 180us per signature)"
  - "Unknown-host negative cache has no invalidation hook: a newly configured tenant host resolves on each node within unknown_host_ttl (default 5 s); positive results and errors are never cached"
metrics:
  duration: 36min
  completed: 2026-11-26
  tasks: 2
  files: 7
---

# Phase 5 Plan 18: Token Endpoint Performance Summary

A content-addressed signer cache in `service/key.rs` and direct aws-lc signing in anvil-jose
together cut the signing CPU per RS256 token from about 610 µs to about 180 µs. Unknown `Host`
values are now cached as misses for 5 s. Rotation, key deletion, client deletion and tenant
deletion still take effect on the next request, and tests prove it. Locally the server's peak
token throughput went from about 5,100 to about 8,550 req/s on SQLite.

## What was built

### Task 1: signer cache and direct signing (`5b1cb7a`, `ebcd3c9`)

- `service/key.rs`: `signer_for` still reads the active key row on every call. It then goes
  through `open_key_cached`, a private `static SIGNERS: OnceLock<RwLock<HashMap<..>>>`. The
  cache key covers everything the opened key depends on: tenant, alg, kid, row id (the AAD),
  `sha256(sealed bytes)`, and a one-way KEK fingerprint. A new active row always misses. A swapped
  blob, a moved row id or another KEK also miss and then fail closed in the AEAD, exactly as
  before. When a signer is inserted, older entries for the same tenant and alg are dropped. The
  map holds at most `SIGNER_CACHE_CAPACITY = 1024` entries and is cleared on overflow. The
  `KeyService` struct, its constructor and every construction site are unchanged. The only
  dependency is std plus `anvil_jose::encoding::sha256`, which core already uses.
- `anvil-jose/keys.rs`: `SigningKey` now holds `Arc<KeyPair>` (aws-lc `RsaKeyPair`,
  `EcdsaKeyPair` or `Ed25519KeyPair`). It derives `Clone`, which is cheap, and signs directly:
  RS256 with `RSA_PKCS1_SHA256`, PS256 with `RSA_PSS_SHA256`, ES256 with the fixed P-256 encoding,
  and Ed25519. It no longer calls `jsonwebtoken::crypto::sign`. Verification still uses
  jsonwebtoken.
- Tests:
  - `key.rs` (6 new): a hit on the second open; separate entries per tenant; a rotated key misses
    and evicts the old entry; a swapped blob or row id is rejected; another KEK never hits; the
    map stays bounded.
  - `keys.rs`: the direct RS256 signature is byte-identical to jsonwebtoken's.
  - `jws.rs`: RS256, PS256, ES256 and Ed25519 tokens from the original key and from a clone verify
    with `verify_jwt` and fail against another key.
  - `jwks_rotation.rs`: `POST /token` signs with the new kid on the very first request after
    `rotate_now(immediate)`, still works after the retired row is deleted, and follows a second
    rotation.

### Task 2: host negative cache (`efc5c4d`)

- `tenant.rs`: when the host lookup finds no tenant, it inserts into `state.unknown_hosts()`,
  which uses `AppConfig.unknown_host_ttl` (default 5 s) and holds at most 10,000 entries. Later
  requests skip the lookup until the entry expires. Found tenants and lookup errors are never
  cached. The module docs record the contract: a newly configured tenant host resolves on each
  node within the TTL. 05-27 should copy this into the OPERATIONS notes.
- `security_tenant.rs` (4 new):
  - With `unknown_host_ttl = 200 ms`, an unknown host still serves the default tenant after a
    tenant with that host is created. It resolves to the host tenant after sleeping 350 ms of real
    time.
  - With the default 5 s TTL, a found host tenant is not cached, and deleting it takes effect on
    the next request.
  - A deleted path tenant returns 404 at once.
  - A deleted client gets `invalid_client` (401) on the next token request.

## Measurements

The profile was taken before deciding on direct signing. Release build, in-process, 2,000
iterations, on an AMD Ryzen 9 7950X3D (12 vCPU under WSL2):

| step | before | after |
|---|---|---|
| `open_key` (HKDF + AES-GCM + PKCS#8 parse) per request | ~107 µs | 1.1 µs (cache hit) |
| RS256 signature | 504 µs (`jsonwebtoken::crypto::sign`, re-parses DER) | 180 µs (direct aws-lc) |
| ES256 signature | 19.7 µs | 11.7 µs |
| Ed25519 signature | 11.9 µs | 6.3 µs |

End to end, with SQLite, release `anvilid serve`, token quotas raised to 100,000/s, and a
`client_credentials` client using `client_secret_basic` at the public host. Neither k6 nor oha is
installed here, so the load came from a scratch Python asyncio closed-loop generator (several
processes, keep-alive connections, 5 s warm-up) running on the same host. "Before" is the release
build of the same tree with this plan's four source files reverted to `712bbe3`. "After" is HEAD.

| run | before | after |
|---|---|---|
| 1 connection: req/s, p50 / p99 | 788, 1.25 / 1.58 ms | 1,321, 0.74 / 1.00 ms |
| 32 connections (4×8): total req/s, p99 | ~5,127, 7.37 ms | ~8,558, 4.82 ms |
| 64 connections (8×8): total req/s, p99 | ~5,050, 14.5 ms | ~8,540, 8.9 ms |
| RSS after load | 80 MB | 81 MB |

The server is saturated in the multi-connection runs, so these numbers show peak throughput, not
the 1,000 req/s open-model target. Postgres was not measured because Docker is not used here. The
authoritative gate is CI (05-26: k6 open model on 4 vCPU with Postgres).

## Verification

- `cargo test -p anvil-core --lib service::key`: 22 passed.
- `cargo test -p anvil-jose --lib`: 101 passed.
- `cargo test -p anvil-web --test jwks_rotation --test id_token_alg --test token_client_credentials --test security_tenant --test discovery`:
  all passed (SQLite backend).
- Mutation check: a cache looked up by tenant only makes the new `jwks_rotation` test fail
  (`UnknownKey`). The test therefore catches a stale signer.
- `grep -rn "Cache<.*Client\|Cache<.*Tenant" crates --include='*.rs'`: empty.
- Clippy is clean for anvil-jose and anvil-core (all targets) and shows no warnings in anvil-web
  files touched by this plan.
- Not run: the Postgres backend of the web tests (`ANVILID_TEST_DB=postgres`) and k6. Both are
  left for CI.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `pem.rs::pkcs8_pem` became dead code**
- **Found during:** Task 1
- **Issue:** `keys.rs` no longer wraps PKCS#8 as PEM for jsonwebtoken, so `pkcs8_pem` was unused
  outside tests and the build warned about dead code.
- **Fix:** marked it `#[cfg(test)]` and fully qualified its `b64std` call. This is a minimal
  forced edit to a file outside `files_modified`; no other wave-3 plan owns it.
- **Files modified:** `crates/anvil-jose/src/pem.rs`
- **Commit:** 5b1cb7a

**2. Counting storage double replaced with observable proofs**
- The harness has no injectable storage wrapper, and anvil-core has no in-memory `Storage`.
  Instead:
  - The "KEK opened once" check uses `open_key_cached`'s hit flag directly.
  - The "one host lookup within the TTL" check is shown by behaviour: a host tenant created after
    the cached miss stays invisible until the TTL expires, which is only possible if no second
    lookup ran.
  - Rotation through `signer_for` is proven end to end in `jwks_rotation.rs` against the real
    SQLite storage.

**3. Load tool:** neither k6 nor oha is installed, so a scratch Python generator was used. It was
deleted afterwards and is not committed.

## Self-Check: PASSED

- FOUND: crates/anvil-core/src/service/key.rs (contains `SIGNER_CACHE_CAPACITY`, `sha256`)
- FOUND: commits 5b1cb7a, ebcd3c9, efc5c4d
