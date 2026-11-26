# Phase 6 deferred items

## From 06-02

- **Pre-existing flake (out of scope):** `model::credential::tests::totp_debug_redacts_the_sealed_seed`
  and `model::webhook::tests::debug_redacts_sealed_secrets` assert that the Debug output does not
  contain `"171"` (the byte `0xAB`). The output also contains UUIDv7 ids, whose timestamp prefix
  contained `171` (`019a2171-…`) for a few minutes on 2026-11-26, so both tests failed in that window
  and passed afterwards. Fix: assert on `"171, 171"` (the byte sequence) instead, as
  `model::organization` does.
- (from 06-05, for 06-09) `SamlAssertionData.has_conditions` (new bool) MUST be set by the XML extractor: `false` when the Assertion has no `<saml:Conditions>` element. Without it `missing_conditions` vs `conditions_missing_not_on_or_after` cannot be told apart; add an extraction test for both.
