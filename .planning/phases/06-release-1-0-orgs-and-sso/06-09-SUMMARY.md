---
phase: 06-release-1-0-orgs-and-sso
plan: 09
subsystem: saml
tags: [saml, xml-dsig, bergshamra, uppsala, xsw, attack-corpus, fuzzing, security]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-01 bergshamra/uppsala/flate2 on aws-lc and the D4 spike; 06-04 SamlXml port and adapter skeleton; 06-05 saml::validate and SamlAssertionData.has_conditions"
provides:
  - SamlXmlAdapter (verify_response, parse_metadata, encode_redirect) with no TRANSITIONAL marker
  - pub precheck(&Document) -> Prechecked and pub extract(&Document, NodeId) in adapters::saml_xml
  - D4 attack corpus crates/anvil-web/tests/security_saml.rs (67 tests)
  - Test IdP crates/anvil-web/tests/saml_support (shared with 06-18)
  - Fuzz targets saml_response_parse, saml_metadata_parse, org_domain_parse (nightly matrix)
affects: [06-18 saml login flow, 06-17 connection admin (metadata import), 06-26 gate D4 report]

tech-stack:
  added: []
  patterns:
    - "Verify-then-read on one uppsala Document: document rules -> precheck -> bergshamra verify_all (by position) -> extract from the verified node"
    - "Corpus tests assert the exact SamlXmlReject and, where useful, a bergshamra-only control proving the library alone would accept"

key-files:
  created:
    - crates/anvil-web/tests/saml_support/mod.rs
    - crates/anvil-web/tests/saml_xml_adapter.rs
    - crates/anvil-web/tests/security_saml.rs
    - fuzz/fuzz_targets/saml_response_parse.rs
    - fuzz/fuzz_targets/saml_metadata_parse.rs
    - fuzz/fuzz_targets/org_domain_parse.rs
  modified:
    - crates/anvil-web/src/adapters/saml_xml.rs
    - fuzz/Cargo.toml
    - fuzz/Cargo.lock
    - fuzz/fuzz_targets/authorize_parse.rs
    - .github/workflows/fuzz.yml
  deleted:
    - crates/anvil-web/tests/saml_dsig_spike.rs

key-decisions:
  - "Document-wide rules run in separate passes in a fixed order (PI/relative namespace -> encrypted -> attribute pollution -> duplicate id), so a reason never depends on element order"
  - "Attribute pollution is refused generally: no attribute local name twice on one element (covers ID + samlp:ID and polluted URI/Algorithm attributes bergshamra reads by local name)"
  - "Duplicate-id check covers every id attribute bergshamra registers (ID, Id, id, AssertionID, xml:id), in any namespace"
  - "Exactly one saml:Assertion in the whole document (not only as Response child); Advice is refused; Response children are a fixed sequence"
  - "UntrustedKey vs Signature is reporting only: a failed signature whose KeyInfo names a certificate that is not configured is UntrustedKey, every other failure Signature"
  - "KeyInfo may carry only X509Data/X509Certificate and KeyName (no RetrievalMethod, KeyInfoReference, EncryptedKey)"
  - "Markup cap (at most 16384 '<' bytes) bounds the node count before parsing; refused as Size"
  - "Issuer, NameID, Audience and attribute values are text/CDATA only and trimmed of XML whitespace; attributes are keyed by Name and also by FriendlyName when different"
  - "Metadata cap 1 MiB / 65536 markup; signatures in metadata are not verified (operator import), as the plan states"

requirements-completed: []

duration: ~55min (including ~15 min waiting for peers' in-flight sqlx caches to build)
completed: 2026-11-26
---

# Phase 6 Plan 09: SAML XML adapter, D4 attack corpus and fuzz targets Summary

**The SAML adapter now does everything on one uppsala Document. It parses with `with_forbid_dtd(true)` (depth 64, 256 KiB cap, node cap), runs document rules and a strict profile pre-check before any bergshamra call, verifies with bergshamra-dsig on aws-lc against the configured certificates only (mapped by position, reference resolved to the pinned node), and reads claims only from the verified Assertion node. A 67-case corpus rejects XSW1-8, exclusion, key injection, comment injection, parser-differential, void-c14n, algorithm-downgrade, file-reference and XML-bomb inputs, each with its exact reason code.**

Requirements ORG-03 and ORG-04 are prepared, not ticked. Only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 55 min, including about 15 min blocked on peers (06-07/06-08 sqlx caches)
- **Tasks:** 3/3
- **Files:** 6 created, 5 modified, 1 deleted

## Task Commits

1. **Task 1, SamlXmlAdapter (parse, pre-check, verify, extract, metadata, redirect):** `0c85d24` (feat)
2. **Task 2, D4 attack corpus, spike folded in and deleted:** `7eb9979` (test)
3. **Task 3, fuzz targets and nightly matrix:** `f480fd4` (feat)

The TDD tests were written with each task and run green before committing. I made one commit per task and no separate RED commit, because peers build the same tree (same practice as 06-05).

## Adapter API (crates/anvil-web/src/adapters/saml_xml.rs)

```rust
pub struct SamlXmlAdapter;                       // impl SamlXml; AppState::saml_xml() unchanged
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_METADATA_BYTES: usize = 1024 * 1024;
pub const MAX_AUTHN_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_DEPTH: u32 = 64;
pub const MAX_MARKUP: usize = 16 * 1024;          // '<' bytes in a response (node cap)
pub const MAX_METADATA_MARKUP: usize = 64 * 1024;
pub const EXC_C14N, ENVELOPED: &str;
pub const SIGNATURE_METHODS: &[&str];            // rsa-sha256/384/512, ecdsa-sha256/384
pub const DIGEST_METHODS: &[&str];               // sha256/384/512
pub struct Prechecked { assertion, assertion_signature, assertion_signature_index,
                        response_signature, response_signature_index, signature_count }
pub fn precheck(doc: &uppsala::Document) -> Result<Prechecked, SamlXmlReject>;
pub fn extract(doc: &uppsala::Document, assertion: NodeId) -> Result<SamlAssertionData, SamlXmlReject>;
```

`verify_response` order: `checked_text` (Size, UTF-8) -> `parse` (Dtd/Parse) -> `document_rules` -> `precheck` -> `verify` -> `extract`. `encode_redirect` applies raw DEFLATE (flate2) and then `anvil_jose::encoding::b64std`. The result is not URL-encoded.

`has_conditions` (06-05 deferred item) is set during extraction. Tests: `has_conditions_is_false_without_conditions` (core then returns `missing_conditions`) and `has_conditions_is_true_for_conditions_without_not_on_or_after` (core then returns `conditions_missing_not_on_or_after`).

## Mitigation -> named negative test

| Mitigation | Test(s) |
|---|---|
| Pre-check before any library call; no file reference resolution | `saml_rejects_reference_uri_relative_file`. A file exists at the relative path in a temp CWD (mutex-guarded, CWD restored). The adapter returns SignatureProfile (a library failure would be Signature). The control: bergshamra alone verifies a signature over that file (it read it), and fails once the file is removed. |
| No external references | `saml_rejects_reference_uri_external_url`, `saml_rejects_reference_uri_empty`, `saml_rejects_keyinfo_retrieval_method`, `saml_rejects_external_entity` |
| Pinned signature location | `saml_rejects_assertion_signature_not_after_issuer` (the library alone says valid), `saml_rejects_response_signature_out_of_place`, `saml_rejects_signature_moved_to_sibling` |
| Stray signatures refused | `saml_rejects_stray_signature_in_extensions`, `saml_rejects_two_response_signatures`, `saml_rejects_foreign_signed_element_in_extensions` (the library alone says valid) |
| forbid_dtd | `saml_rejects_doctype_without_entities`, `saml_rejects_billion_laughs`, `saml_rejects_external_entity`, `doctype_anywhere_is_dtd` |
| Claims only from the verified node | `saml_reads_claims_only_from_the_verified_assertion` (decoy NameID/attributes in Extensions are ignored), `saml_rejects_comment_in_name_id` / `_attribute_value` (the library alone says valid) |
| Trusted keys only | `saml_rejects_keyinfo_key_injection` (control: accepted with the attacker cert configured), `another_certificate_or_none_is_refused` |
| Response signature must verify | `saml_rejects_invalid_response_signature` (library verdicts `[false, true]`) |
| Assertion signature required | `saml_accepts_valid_rsa_and_ecdsa_responses` (Response-only signed: the library says valid, the adapter returns SignatureProfile) |

## D4 corpus: case list with reason codes (`cargo test -p anvil-web --test security_saml`: 67 passed)

Positive controls (accepted):
- `saml_accepts_valid_rsa_and_ecdsa_responses`: RSA and ECDSA, Assertion-only and Assertion+Response. A Response-only signature is rejected with **SignatureProfile**.
- `saml_accepts_assertion_with_other_prefixes`: `a:`/`sig:` prefixes and a default protocol namespace. Matching is by URI.
- `saml_reads_claims_only_from_the_verified_assertion`

XSW and wrapping (sketch: R Response, A Assertion, S Signature, * signed, ! forged):

| Test | Structure | Reason |
|---|---|---|
| xsw1_forged_response_wraps_signed_response_in_signature | R!(S[copy, R*(A)], A!) | Structure |
| xsw2_signed_response_detached_before_signature | R!(R*(A), S, A!) | Structure |
| xsw3_cloned_assertion_before_signed | R(A!, A*(S)) | Structure |
| xsw3_clone_with_the_signed_id | R(A! same ID, A*(S)) | DuplicateId |
| cloned_assertion_after_signed | R(A*(S), A!) | Structure |
| xsw4_signed_assertion_wrapped_in_forged_assertion | R(A!(A*(S))) | Structure |
| xsw5_signature_moved_to_forged_assertion | R(A!(S) same ID, A* unsigned); and with a fresh ID | DuplicateId; Structure |
| xsw6_signed_assertion_inside_signature_of_forged | R(A!(S(A*))) | Structure |
| xsw7_signed_assertion_wrapped_in_extensions | R(Extensions(A*), A!) | Structure |
| xsw8_signed_assertion_in_signature_object | R(A!(S(Object(A*)))) | Structure |
| signed_assertion_in_subject_confirmation_data | A!(…SubjectConfirmationData(A*)) | Structure |
| signed_assertion_in_advice | A!(Advice(A*)) | Structure |
| signature_moved_to_sibling | R(S, A unsigned) | SignatureProfile |
| assertion_signature_not_after_issuer | S at the end of A (library: valid) | SignatureProfile |
| response_signature_out_of_place | Response S after Status | SignatureProfile |
| stray_signature_in_extensions | copy of S in Extensions | SignatureProfile |
| two_response_signatures | R(S, S, …) | SignatureProfile |
| foreign_signed_element_in_extensions | IdP-signed md:EntityDescriptor in Extensions, A! unsigned (library: valid) | SignatureProfile |

Exclusion, keys, integrity:

| Test | Reason |
|---|---|
| unsigned_assertion | SignatureProfile |
| signed_response_with_unsigned_assertion | SignatureProfile |
| empty_signature_value | SignatureProfile |
| empty_digest_value | SignatureProfile |
| keyinfo_key_injection | UntrustedKey |
| keyinfo_retrieval_method | SignatureProfile |
| tampered_assertion | Signature |
| invalid_response_signature | Signature |

Comment and element injection: `comment_in_name_id` **Structure** (library: valid), `comment_in_attribute_value` **Structure** (library: valid), `element_in_name_id` **Structure**.

Parser differentials and DTDs: `doctype_without_entities` **Dtd**, `billion_laughs` **Dtd**, `external_entity` (SYSTEM entity and external parameter-entity DTD) **Dtd**, `redefined_saml_prefix` **Structure**, `redefined_ds_prefix` **Structure** (the rebound "signature" is an unknown Assertion child), `default_namespace_trick` **Structure**, `attribute_pollution_prefixed_id` (on the Assertion and on the Response) **Structure**, `void_canonicalization_relative_namespace` (element and default namespace) **Structure**, `void_canonicalization_in_transform` **Structure**, `processing_instruction` **Structure**.

Algorithm and signature profile: `sha1_signature_method` **Algorithm**, `sha1_digest` **Algorithm**, `hmac_signature_method` **Algorithm**, `c14n_with_comments` **Algorithm**, `inclusive_c14n` **Algorithm**, `xpath_transform` **Algorithm**, `xslt_transform` **Algorithm**, `extra_transform` **SignatureProfile**, `missing_transform` **SignatureProfile**, `reordered_transforms` **SignatureProfile**, `reference_uri_empty` **SignatureProfile**, `reference_to_another_element` **SignatureProfile**, `reference_uri_external_url` **SignatureProfile**, `reference_uri_relative_file` **SignatureProfile**, `two_references` **SignatureProfile**, `signature_object` **SignatureProfile**.

Structure and size: `duplicate_ids` (Response=Assertion ID; an id in Extensions; via `Id`, `AssertionID`, `xml:id`) **DuplicateId**, `second_assertion` (two validly signed; library `[true, true]`) **Structure**, `encrypted_assertion` (alone and next to a signed one) **Encrypted**, `encrypted_id` **Encrypted**, `wrong_root_or_version` **Structure**, `unknown_response_child` **Structure**, `deep_nesting` **Parse**, `oversized_response` **Size**, `markup_flood` (20 000 `<x/>` under 256 KiB) **Size**.

## Adapter tests (`cargo test -p anvil-web --test saml_xml_adapter`: 16 passed)

These cover every extracted field plus an end-to-end core `validate::check`. They also cover ECDSA and dual-signed responses, certificate rollover, other/empty/wrong-type/garbage certs (UntrustedKey), DOCTYPE in three positions (Dtd), the 256 KiB boundary (cap+1 Size, cap accepted), depth 65 Parse / 64 parses, non-UTF-8 / malformed / empty / Latin-1 declaration (Parse), the two `has_conditions` cases, several AudienceRestrictions, a malformed signed instant (Structure), metadata (signing + unspecified use kept, encryption skipped, dedupe, PEM round-trips into the verifier, EntitiesDescriptor with one IdP, refusals: http, not a URL, no signing cert, bad base64, no Redirect binding, blank entityID, not metadata, DTD, size), and `encode_redirect` round-tripping through raw inflate plus the size refusal. Unit tests: `absolute_uri_detection`, `cert_body_strips_armour_and_whitespace`.

## saml_support API for 06-18 (crates/anvil-web/tests/saml_support/mod.rs)

- Constants: `SP_ENTITY_ID`, `ACS_URL`, `IDP_ENTITY_ID`, `REQUEST_ID`, `RESPONSE_ID`, `ASSERTION_ID`, `NAME_ID`, namespace and algorithm URIs (`RSA_SHA256`, `RSA_SHA1`, `HMAC_SHA256`, `DIGEST_SHA1`, `EXC_C14N_COMMENTS`, `C14N_10`, `XPATH`, `XSLT`, …).
- `IdpKey::{rsa(), ecdsa(), generate(Alg, cn)}`, `.cert_pem()`, `.cert_b64()`, `.signing_key()`, `.alg`.
- `ResponseOpts::valid(now)` (core accepts it at `now`; `Default` uses the wall clock). Fields: ids, destination, in_response_to, response_issuer, issuer, status_code, issue_instant, name_id(+format), `confirmation: Option<Confirmation>`, `conditions: Option<Conditions>`, authn_statement, session_index, `attributes: Vec<(Name, Option<FriendlyName>, values)>`, `sign_assertion`, `sign_response`.
- `signed_response(&key, &opts)`, `signed_assertion`, `assertion_xml(opts, Option<Alg>)`, `response_xml(opts, Option<Alg>, assertion)`, `signature_template(alg, id)`, `sign_first(&key, template)`.
- Mutators: `replace_once`, `element(xml, open, close)`, `remove`, `insert_after`, `insert_before`, `assertion_signature`, `esc`, `pem`.

## Fuzz notes

- `fuzz/Cargo.toml` adds the `anvil-web` path dependency and three `[[bin]]` targets. `fuzz/Cargo.lock` was reseeded from the main lock. The fuzz-only packages kept their versions (arbitrary 1.5.0, derive_arbitrary 1.5.0, libfuzzer-sys 0.4.13).
- `saml_response_parse` asserts that `verify_response(data, &[CERT])` is never Ok. CERT is a public-only P-256 certificate, generated with `openssl req -x509 … -keyout /dev/null`, so its private key was never stored.
- `org_domain_parse` checks that `normalize_domain` is idempotent and that an accepted value has lowercase LDH labels of 1..=63 bytes, at least two labels, at most 253 bytes and no trailing dot.
- `.github/workflows/fuzz.yml`: the three targets are in the nightly matrix. Push triggers now include `policy/home_realm.rs` and `adapters/saml_xml.rs`, and the PR trigger includes `adapters/saml_xml.rs`.
- `just fuzz-check` (stable type-check): OK.
- ASan nightly (`scripts/fuzz.sh run`, cargo-fuzz 0.13.2): anvil-web **builds** under cargo-fuzz's ASan nightly. Short local runs had no crash: saml_response_parse 60 s (2 740 217 runs), saml_metadata_parse 30 s (1 679 506 runs), org_domain_parse 30 s (669 965 runs). The local corpora were deleted afterwards.
- Disk: `fuzz/target` grew from 1.5 GB to 4.4 GB (the stable check plus the ASan release build with anvil-web). It is the existing shared fuzz target dir, and I did not clean it.

## Files Created/Modified (beyond files_modified)

- `fuzz/fuzz_targets/authorize_parse.rs`: added `organization: OrgClientPolicy::default()` to its `Client` literal. 06-02 added the field, and the target no longer compiled, so `just fuzz-check` (this plan's verify step) failed before this change. It is a one-line forced fix.
- `.planning/phases/06-release-1-0-orgs-and-sso/deferred-items.md`: one out-of-scope note (below).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] fuzz crate did not type-check (pre-existing)**
- **Found during:** Task 3
- **Issue:** `authorize_parse.rs` lacked the new `Client.organization` field
- **Fix:** one-line default (see above)
- **Commit:** f480fd4

**2. [Rule 2 - Hardening beyond the plan list]**
- Extra refusals: processing instructions anywhere; any attribute local name twice on an element (not only `ID`); duplicate ids across all the id attribute names bergshamra registers; `Advice`; any second Assertion anywhere in the document; `ds:Object` and non-hint `KeyInfo` children; empty `DigestValue`/`SignatureValue`; a non-UTF-8 encoding declaration; a markup cap as the node cap; bearer `SubjectConfirmationData` with child elements; `BaseID` or other Subject children.
- Each has a test in the corpus or adapter tests.

### Interpretation

- **Reason codes.** The plan lists the corpus cases without codes. The codes above come from the fixed check order (see key-decisions). For example, most XSW shapes end in `Structure` (a second Assertion anywhere), and keeping the signed ID gives `DuplicateId`.
- **`saml_rejects_redefined_ds_prefix` is `Structure`**, not SignatureProfile. By namespace URI the rebound element is an unknown Assertion child, and the structure check runs before the signature checks.

## Deferred / out of scope

- `crates/anvil-web/src/admin/tenants.rs` says the org claim mappings are "not on the wire yet (06-09)". That is the wrong plan, because this plan does not own the tenant claim-mapping DTO. Logged in deferred-items.md and not changed.

## Verification

- `cargo test -p anvil-web --test saml_xml_adapter`: 16 passed
- `cargo test -p anvil-web --test security_saml`: 67 passed
- `cargo test -p anvil-web --lib adapters::saml_xml`: 2 passed
- `cargo clippy -p anvil-web --lib --test saml_xml_adapter --test security_saml -- -D warnings`: clean. `--all-targets` failed only in 06-11's in-progress untracked `tests/admin_keys.rs` (a `time::Duration` vs `std::time::Duration` mismatch), which is not this plan's file.
- `test ! -f crates/anvil-web/tests/saml_dsig_spike.rs`: OK
- `grep -rn "TRANSITIONAL(06-09)" crates/`: empty
- `just fuzz-check`: OK. The grep checks on fuzz/Cargo.toml and fuzz.yml: OK
- ASan fuzz smoke of the three new targets (60 s / 30 s / 30 s): no crash
- `scripts/check-deps.sh`: dependency rules OK. `scripts/check-release-graph.sh`: release graph OK
- rustfmt (edition 2024) on the plan's own files only

## Not run here

- Postgres, e2e and conformance: this plan has no storage or UI.
- `scripts/check-security-tests.sh`: the Phase 6 map entries belong to the gate (06-26). The corpus test names above are ready to map.

## Self-Check: PASSED

- FOUND: crates/anvil-web/src/adapters/saml_xml.rs, crates/anvil-web/tests/{saml_support/mod.rs,saml_xml_adapter.rs,security_saml.rs}, fuzz/fuzz_targets/{saml_response_parse,saml_metadata_parse,org_domain_parse}.rs
- DELETED: crates/anvil-web/tests/saml_dsig_spike.rs
- FOUND commits: 0c85d24, 7eb9979, f480fd4
