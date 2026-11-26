---
phase: 06-release-1-0-orgs-and-sso
plan: 01
subsystem: infra
tags: [dependencies, cargo-deny, saml, xml-dsig, bergshamra, uppsala, aws-lc, hickory, psl, flate2]

requires:
  - phase: 05-release-0-4
    provides: deny.toml policy, scripts/check-deps.sh, aws-lc-rs single crypto backend
provides:
  - Every Phase 6 runtime and dev dependency declared once (workspace + anvil-core + anvil-web)
  - deny.toml chrono exception scoped to the wrapper tsp-ltv (decision Q2, option A)
  - check-deps.sh allows psl and idna in anvil-core
  - D4 spike proving bergshamra-dsig sign/verify on aws-lc with trusted keys only
  - ARCHITECTURE §2 chrono exception and §20 D4 spike verdict
affects: [06-05 home_realm, 06-09 saml adapter, 06-10 dns adapter, 06-26 gate]

tech-stack:
  added: [bergshamra-dsig 0.12.0, bergshamra-keys 0.12.0, bergshamra-xml 0.12.0, uppsala 0.12.1, hickory-resolver 0.26.4, hickory-proto 0.26.4 (dev), psl 2.1.264, idna 1.1.0 (direct), flate2 1.1.11 rust_backend]
  patterns:
    - "Test-time X.509: aws-lc-rs keygen + minimal hand-built DER certificate (test code only)"
    - "SAML verify: one uppsala document (forbid_dtd) -> DsigContext::new(trusted keys) -> verify_all_document_with_source -> check resolved_node"

key-files:
  created:
    - crates/anvil-web/tests/saml_dsig_spike.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - deny.toml
    - scripts/check-deps.sh
    - crates/anvil-core/Cargo.toml
    - crates/anvil-web/Cargo.toml
    - docs/ARCHITECTURE.md

key-decisions:
  - "D4 spike passed: bergshamra-dsig 0.12.0 on aws-lc only + uppsala single parser; no checkpoint needed"
  - "chrono allowed only via wrappers = [\"tsp-ltv\"] in deny.toml (owner review pending)"
  - "anvilid manifest unchanged: it needs none of the new crates directly"

requirements-completed: []

duration: ~75min (including ~25 min waiting for 06-02's in-progress core changes to build)
completed: 2026-11-26
---

# Phase 6 Plan 01: Dependencies and D4 spike Summary

**bergshamra-dsig 0.12.0 signs and verifies a SAML assertion (RSA-SHA256 and ECDSA-P256) on aws-lc only, with uppsala as the single parser and trusted keys only. All Phase 6 crates are declared, and chrono gets one deny exception, scoped to tsp-ltv.**

Requirements: ORG-03 is prepared, not ticked. Only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Tasks:** 2/2
- **Files modified:** 8 (1 created)
- **Completed:** 2026-11-26

## Task Commits

1. **Task 1: Workspace dependencies, deny exception, check-deps allowlist**: `8413552` (chore)
2. **Task 2: D4 spike test and ARCHITECTURE verdict**: `a1b03c9` (test)

## Dependency delta

Workspace `[workspace.dependencies]` (new "Phase 6" block):

- `bergshamra-dsig` / `bergshamra-keys` 0.12.0: `default-features = false, features = ["aws-lc"]`
- `bergshamra-xml` 0.12.0: `default-features = false`
- `uppsala = "0.12.1"`, `hickory-resolver = "0.26.4"` (default features), `hickory-proto = "0.26.4"`
- `psl = "2.1"` (2.1.264), `idna = "1.1.0"` (the version already in the lock)
- `flate2 = { version = "1", default-features = false, features = ["rust_backend"] }` (1.1.11, miniz_oxide)

Edges:

- anvil-core (normal): psl, idna
- anvil-web (normal): bergshamra-dsig, bergshamra-keys, bergshamra-xml, uppsala, hickory-resolver, flate2
- anvil-web (dev): hickory-proto
- anvilid: none
- Signing needed no extra feature. `bergshamra_dsig::sign` is in the same crate, and aws-lc-rs is already a normal dependency of anvil-web.
- proptest was already a dev-dependency of anvil-core.

Lockfile: only new packages were added. No existing package was upgraded (checked in the diff: the only removed lines are dependency names that became version-qualified). New transitive packages: bergshamra-{c14n,core,crypto,pkcs12,transforms}, kryptering 0.7.1 (its only crypto dependency is aws-lc-rs), tsp-ltv 0.6.1, cms, hickory-net, resolv-conf, prefix-trie, psl-types, miniz_oxide, crc32fast, plus the RustCrypto *encoding* crates der/spki/pkcs8/x509-cert/const-oid/pem-rfc7468 in their 0.7/0.2 lines. These are second versions next to the webauthn-rs 0.8/0.3-rc lines. They parse certificates only and `multiple-versions = "warn"` accepts them.

## deny.toml exception (FLAGGED FOR OWNER REVIEW)

```toml
  # The ONLY chrono exception (decision Q2, option A; owner review pending). bergshamra-keys hard-depends on
  # tsp-ltv, which hard-depends on chrono; nothing else may pull chrono and our code uses `time`.
  { crate = "chrono", wrappers = ["tsp-ltv"], reason = "bergshamra-keys -> tsp-ltv (X.509 trust facade) needs chrono; our code stays on `time` (ARCHITECTURE §2, decision Q2)" },
```

This was the only deny.toml change. No license exception was needed: bergshamra and uppsala are BSD-2-Clause, which was already allowed. No ban was loosened.

## Graph evidence

`cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`. The only warnings are pre-existing-style `duplicate` warnings.

`cargo tree -i ring --target all`: `warning: nothing to print.` (ring is absent)

`cargo tree -i openssl-sys --target all`: `error: package ID specification 'openssl-sys' did not match any packages` (absent)

`cargo tree -i rsa --target all` (unchanged, crypto-glue only):
```
rsa v0.10.0-rc.19
└── crypto-glue v0.2.2
    ├── webauthn-attestation-ca v0.6.2
    │   └── webauthn-rs-core v0.6.2
    │       └── webauthn-rs v0.6.2
    │           └── anvil-web v0.0.0
    │               └── anvilid v0.4.0
    └── webauthn-rs-core v0.6.2 (*)
```

`cargo tree -i chrono --target all` (tsp-ltv only):
```
chrono v0.4.45
└── tsp-ltv v0.6.1
    └── bergshamra-keys v0.12.0
        ├── anvil-web v0.0.0
        │   └── anvilid v0.4.0
        ├── bergshamra-dsig v0.12.0
        │   └── anvil-web v0.0.0 (*)
        └── bergshamra-transforms v0.12.0
            └── bergshamra-dsig v0.12.0 (*)
```
Before this plan, `cargo tree -i chrono -e all` printed nothing (chrono was in the lockfile but unused).

aws-lc: Cargo.lock has exactly one `aws-lc-rs` (1.19.0) and one `aws-lc-sys` (0.47.0). `cargo tree -d --target all | grep -E "^aws-lc-(rs|sys) "` prints `aws-lc-rs v1.19.0` twice. That is the same version listed twice because of a host/target feature split (rustls as a build dependency through sqlx-macros). It is **pre-existing**: a scratch copy of the pre-plan manifests and lockfile produces the same two lines. It is not a second version, so the stop condition did not apply. The plan's literal `test -z "$(... grep -E '^aws-lc-(rs|sys) ')"` check therefore fails, and it failed before this plan too.

No RustCrypto signature primitive comes in through the new crates. `cargo tree -i {p256,p384,ecdsa,ed25519-dalek,rsa,sha2,hmac,aes}` shows no bergshamra, tsp-ltv, kryptering, hickory, psl, uppsala or flate2 parent. hickory-resolver pulls no ring, rustls, openssl or native-tls.

`cargo tree -e normal -p anvilid | wc -l`: 1474 before, 1617 after.

`scripts/check-deps.sh`: `dependency rules OK`. `--self-test`: `dependency checker self-test OK`. `scripts/check-release-graph.sh`: `release graph OK`.

## Spike verdict (D4): PASS on aws-lc alone

`cargo test -p anvil-web --test saml_dsig_spike`: 4 passed.

- `spike_rsa_sha256_assertion_signs_and_verifies`: valid, 1 reference `#_a1`, `digest_verified`, and `resolved_node == Assertion node`.
- `spike_ecdsa_p256_assertion_signs_and_verifies`: same, with ECDSA-SHA256.
- `spike_tampered_value_fails`: changing one character in the NameID makes it Invalid.
- `spike_untrusted_key_in_keyinfo_fails`: the attacker's cert embedded in X509Data, with only the configured cert trusted, is Invalid. Control: the same document is valid when the attacker's cert is the configured one.

Keys are generated at test time with aws-lc-rs (RSA-2048, P-256). Self-signed v3 certificates come from a small DER builder in the test. No key or cert is committed, and the PKCS#8 PEM label is assembled at runtime.

### Exact API names for 06-09 (all compiled and exercised)

- Parser: `uppsala::Parser::new().with_forbid_dtd(true).with_max_depth(64).parse(&str) -> XmlResult<uppsala::Document<'_>>`. Also available: `with_forbid_entities(bool)` and `with_max_entity_expansion(usize)`. The DOM API is `doc.document_element()`, `doc.children(NodeId) -> Vec<NodeId>`, `doc.element(NodeId) -> Option<&Element>` with `e.name.local_name.as_ref()`, `e.name.namespace_uri`, `doc.get_attribute(NodeId, "ID")` and `doc.parent(NodeId)`.
- Keys: `bergshamra_keys::KeysManager::new()`, `.add_key(Key)`, `bergshamra_keys::loader::load_x509_cert_pem(&[u8]) -> Result<Key, _>` (also `load_x509_cert_der`). Under aws-lc the `loader` module is `src/alternate/loader.rs`: `load_rsa_private_pem` / `load_ec_p256_private_pem` take PKCS#8 `PRIVATE KEY` PEM only. `Key { name, data, usage, x509_chain: Vec<Vec<u8>> }` has public fields.
- Context: `bergshamra_dsig::DsigContext::new(keys)`. `new` already defaults to trusted_keys_only=true, strict_verification=true and require_reference_digests=true. The spike still sets them explicitly with `.with_trusted_keys_only(true)`, `.with_strict_verification(true)`, `.with_require_reference_digests(true)` and `.with_skip_time_checks(true)`. Never use `DsigContext::new_permissive`.
- Verify: `bergshamra_dsig::verify::verify_all_document_with_source(&ctx, &doc, Some(xml)) -> Result<Vec<VerifyResult>, bergshamra_core::Error>`. It returns one result per `<ds:Signature>` in document order. Per-signature failures come back as `Invalid`, and `Err` only for document-level problems (parse, duplicate IDs, no Signature).
- Result: `bergshamra_dsig::VerifyResult::{Valid { signature_node, references: Vec<VerifiedReference>, key_info: VerifiedKeyInfo }, Invalid { reason: String }}`, plus `.is_valid()` and `.all_reference_digests_verified()`.
- Reference: `bergshamra_dsig::VerifiedReference { uri: String, resolved_node: Option<NodeId>, digest_verified: bool }`. It is `#[non_exhaustive]`, so match with `..`.
- Signer (test IdP): `bergshamra_dsig::sign::sign(&ctx, template_xml: &str) -> Result<String, _>`. The template has empty `DigestValue`/`SignatureValue`, and `<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>` is filled from the signing `Key.x509_chain`. Also available: `sign_enveloped_document(&ctx, &mut doc, EnvelopedSignatureOptions)`, but it inserts the signature as the document element's first child, so it does not fit an Assertion inside a Response.
- ID attributes the verifier registers by default: `Id`, `ID`, `id`, `AssertionID`. Extra ones go through `ctx.add_id_attr`.
- bergshamra-core is not a direct dependency, so the test hardcodes the algorithm URIs. 06-09 may do the same, or name the error type through `bergshamra_dsig` re-exports if needed.

## Decisions Made

- D4 option A is confirmed technically. No checkpoint was needed: it builds and verifies on aws-lc alone, chrono comes only through tsp-ltv, and there is no second crypto backend or second aws-lc version.
- The ARCHITECTURE §2 banned list now says "`chrono` (except through `tsp-ltv`, below)". There is a new third-exception paragraph, and §20 D4 holds the spike verdict, SAML experimental through 1.0 (Q3), and the corpus gate 06-09. The macOS targets get verified by the release workflow at 06-26.

## Deviations from Plan

1. **Graph-check interpretation (no code change).** The plan's automated aws-lc duplicate grep matches the pre-existing same-version host/target split (`aws-lc-rs v1.19.0` listed twice). I showed that this predates the plan and that only one version is locked. Recorded above, with no deviation in the graph itself.
2. **`cargo update -p` cannot add new crates.** The new crates were resolved with `cargo metadata`, which adds missing packages without upgrading existing ones. I verified this in the diff.

## Issues / Not run

- `cargo build --workspace --all-targets --locked` fails in existing anvil-web integration tests (authorize_prompt, authorize_step_up, health_metrics, security_admin_v03/v04, security_private_key_jwt, upstream_apple, upstream_buttons). They lack the new `organization` / `org_id` fields from 06-02's in-progress anvil-core model changes. This is not caused by this plan. The spike test and every library crate build.
- Cargo's `unused_dependencies` manifest lint warns about psl, idna, bergshamra-*, flate2 and hickory-resolver until 06-05, 06-09 and 06-10 use them. This is expected because the dependencies are declared up front. It is a manifest warning, not a rustc/clippy `-D warnings` error.
- macOS targets were not built locally. The release workflow covers them at the 06-26 gate.

## Self-Check: PASSED

- FOUND: crates/anvil-web/tests/saml_dsig_spike.rs
- FOUND: commit 8413552
- FOUND: commit a1b03c9
