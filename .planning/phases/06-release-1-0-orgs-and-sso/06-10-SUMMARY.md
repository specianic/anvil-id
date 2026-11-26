---
phase: 06-release-1-0-orgs-and-sso
plan: 10
subsystem: domain-verification
tags: [organizations, dns, hickory, domain-verification, org-04]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: 06-04 DomainTxtLookup port, HickoryTxtLookup skeleton, domain_verification_resolvers; 06-05 policy::domain_verification
provides:
  - service::domain_check::check_domain(lookup, domain, token) -> DomainCheck { Verified, NotVerified }
  - HickoryTxtLookup on hickory-resolver 0.26 (TRANSITIONAL(06-10) removed)
  - tests/dns_support: local UDP DNS stub (hickory-proto), test code only
affects: [06-17, 06-20]

tech-stack:
  added: []
  patterns:
    - "Dedicated resolver per purpose: absolute names, ndots 0, no hosts file, cache 0, per-attempt and overall timeouts"
    - "Uniform outcome: lookup errors and non-matches fold into one NotVerified"

key-files:
  created:
    - crates/anvil-web/tests/dns_support/mod.rs
    - crates/anvil-web/tests/dns_txt_adapter.rs
  modified:
    - crates/anvil-core/src/service/domain_check.rs
    - crates/anvil-web/src/adapters/dns_txt.rs

key-decisions:
  - "An unreadable system resolver configuration (no explicit resolvers) does not stop startup: it logs a warning and every lookup fails with TxtLookupError::Failed; explicit resolvers that can't build a resolver still fail startup with DnsTxtSetupError"
  - "Besides cache_size 0, positive/negative max TTL are 0 so nothing is ever served from cache"
  - "A successful answer with no TXT RR (e.g. only a CNAME) maps to NotFound"
  - "check_domain passes each joined RR to policy::domain_verification::matches as a single string, so a value split across RRs never matches"

requirements-completed: []

duration: ~35min
completed: 2026-11-26
---

# Phase 6 Plan 10: DNS TXT lookup adapter and domain check Summary

**Domain verification now has one bounded, FQDN-only, uncached TXT check. `HickoryTxtLookup` queries the operator's resolvers or the system configuration, and `service::domain_check::check_domain` folds every error and every non-match into one `NotVerified`. Both are tested against a real UDP DNS stub on 127.0.0.1.**

ORG-04 is prepared, not ticked. Only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 35 min
- **Tasks:** 1/1
- **Files:** 2 created, 2 modified

## Task Commits

1. **Task 1, core domain check, hickory adapter, UDP stub and tests:** `03d6e04` (feat)

## Adapter options (crates/anvil-web/src/adapters/dns_txt.rs)

| Option | Value |
|---|---|
| Name servers | `domain_verification_resolvers` (each `NameServerConfig` gets UDP and TCP on the configured port, `ResolverConfig::from_parts(None, vec![], ..)`), else `TokioResolver::builder(TokioRuntimeProvider)` (system config) |
| Query name | `Name::from_ascii(fqdn)` then `set_fqdn(true)`: absolute with or without the trailing dot |
| `ndots` | 0 |
| `use_hosts_file` | `Never` |
| `cache_size` | 0, plus `positive_max_ttl` / `negative_max_ttl` = 0 |
| `timeout` / `attempts` | 2 s / 2 |
| Overall | `tokio::time::timeout(5 s, txt_lookup)` |
| Errors | `is_no_records_found()` (NXDOMAIN, NODATA) and an answer with no TXT RR give `NotFound`. Everything else (SERVFAIL, refused, timeout, unparsable name, unavailable system config) gives `Failed` |
| Result | one `Vec<u8>` per TXT RR, its character-strings joined in order; non-TXT answers are skipped |
| Logging | queried names at debug level only |

The `HickoryTxtLookup::new(&[SocketAddr]) -> Result<Self, DnsTxtSetupError>` signature is unchanged. `startup.rs` already calls it. `Debug` is implemented by hand and shows the resolvers and whether a resolver exists.

## Core check (crates/anvil-core/src/service/domain_check.rs)

```rust
pub enum DomainCheck { Verified, NotVerified }
pub async fn check_domain(lookup: &dyn DomainTxtLookup, domain: &str, token: &str) -> DomainCheck;
```

This queries `record_name(domain)` and compares the result with `matches(.., &record_value(token))`. It is the only domain check. 06-17 (verify) and 06-20 (re-check) call it.

## Stub API (crates/anvil-web/tests/dns_support/mod.rs)

- `DnsStub::start().await` binds `127.0.0.1:0`. `addr()` returns the address to pass to `HickoryTxtLookup::new(&[addr])`.
- `set_txt(name, &[&[&[u8]]])` sets the TXT RRset of a name. Each RR is a list of character-strings. An empty RRset gives NODATA.
- Unknown names get NXDOMAIN. `servfail()` makes every later reply SERVFAIL. `silent()` stops all replies.
- `queries()` returns every query name exactly as received.
- The stub has no TCP listener. The task is aborted on drop.

## Tests

- core `service::domain_check::tests` (7): `one_matching_record_verifies`, `queries_the_record_name`, `not_found_is_not_verified`, `failure_is_not_verified`, `no_match_is_not_verified`, `a_value_split_across_two_records_is_not_verified`, `errors_and_non_matches_are_one_outcome`.
- web lib `adapters::dns_txt::tests` (3): `options_are_bounded_uncached_and_fqdn_only`, `explicit_resolvers_use_udp_and_tcp_on_the_configured_port`, `unparsable_names_fail`.
- `tests/dns_txt_adapter.rs` (8): `dns_txt_adapter_reads_matching_record` (includes a 300-byte value split into two strings and returned joined), `dns_txt_adapter_verifies_a_record_split_into_strings_but_not_across_records`, `dns_txt_adapter_queries_fqdn_without_search_suffix` (with and without the trailing dot), `dns_txt_adapter_nxdomain_is_not_found`, `dns_txt_adapter_nodata_is_not_found`, `dns_txt_adapter_servfail_is_failed`, `dns_txt_adapter_timeout_is_bounded` (Failed in about 5 s, well under 6 s), `dns_txt_adapter_has_no_cache`.

## Verification

- `cargo test -p anvil-core --lib service::domain_check`: 7 passed
- `cargo test -p anvil-web --test dns_txt_adapter`: 8 passed (5.0 s, loopback only)
- `cargo test -p anvil-web --lib adapters::dns_txt`: 3 passed
- `cargo test -p anvilid --test config_phase6`: 7 passed
- `grep -rn "TRANSITIONAL(06-10)" crates/`: no match
- `cargo clippy -p anvil-web --lib --test dns_txt_adapter -- -D warnings` and `cargo clippy -p anvil-core --lib --tests -- -D warnings`: clean
- `cargo build -p anvilid`: OK. `scripts/check-release-graph.sh`: OK

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] Unreadable system resolver configuration**
- **Found during:** Task 1
- **Issue:** `TokioResolver::builder` reads resolv.conf, so it can fail on a host that has none. Turning that into a startup failure would take down the whole server because of an optional feature.
- **Fix:** When no explicit resolvers are configured and the system config can't be read, a warning is logged and every lookup returns `TxtLookupError::Failed` (an explicit failure, never success). Explicit resolvers still fail startup on a setup error.
- **Files modified:** crates/anvil-web/src/adapters/dns_txt.rs
- **Commit:** 03d6e04

### Process notes

- TDD RED and GREEN went into one commit. The old shim made every lookup fail, so the adapter tests could not have passed against it. They were written together with the adapter.
- `cargo clippy -p anvil-web --all-targets` currently fails in `tests/admin_keys.rs` (06-11, in progress in the same tree: `time::Duration` passed to `advance`). That is outside this plan's scope, so clippy was run on this plan's targets only.

## Not run

- Lookups against real public DNS (the tests use only the loopback stub, by design).
- TCP fallback against a TCP DNS server (the stub serves only UDP).

## Self-Check: PASSED
