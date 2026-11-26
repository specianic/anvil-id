---
phase: 06-release-1-0-orgs-and-sso
plan: 03
subsystem: e2e-tooling
tags: [e2e, playwright, saml, xml-crypto, dns, mock, test-tooling]
requires: []
provides:
  - "tests/e2e/lib/mock-saml-idp.ts: startMockSamlIdp({ entityId?, ssoPath?, port? }) -> { url, ssoUrl, entityId, certPem, metadataXml, requests, setUser, setVariant, close }"
  - "SAML variants: ok, wrong-audience, wrong-recipient, expired, unsigned"
  - "tests/e2e/lib/mock-dns.ts: startMockDns({ port, controlPort }) -> { address, port, controlUrl, setTxt, clear, close }; spec client publishTxt(name, values) / removeTxt(name) over E2E_DNS_CONTROL_URL"
  - "tests/e2e/lib/mock-dns-cli.ts: --port, --control-port; prints `READY <udp port> <control URL>`; exits 0 on SIGTERM/SIGINT"
  - "xml-crypto 6.4.0 (exact pin) in tests/e2e devDependencies"
affects: [06-23, 06-24]
tech-stack:
  added: ["xml-crypto 6.4.0 (npm, MIT, e2e devDependency only)"]
  patterns:
    - "Suite-wide mock DNS: specs publish TXT records only through publishTxt/removeTxt; only specs/mock-dns.spec.ts starts its own instance"
    - "Test keys and certificates are generated in memory at start-up (minimal DER builder for the self-signed cert); nothing key-like is committed"
key-files:
  created:
    - tests/e2e/lib/mock-saml-idp.ts
    - tests/e2e/lib/mock-dns.ts
    - tests/e2e/lib/mock-dns-cli.ts
    - tests/e2e/specs/mock-saml-idp.spec.ts
    - tests/e2e/specs/mock-dns.spec.ts
  modified:
    - tests/e2e/package.json
    - tests/e2e/package-lock.json
decisions:
  - "Mock DNS answers a non-TXT query for a configured name with NOERROR and no answers (NODATA, node reports ENODATA); unknown names get NXDOMAIN (ENOTFOUND)"
  - "Mock SAML IdP signs only the Assertion (enveloped, exc-c14n, RSA-SHA256, Reference #assertionID, ds:Signature right after saml:Issuer) and leaves the Response unsigned; KeyInfo carries the cert, but verifiers should use the pinned cert"
  - "Each bad SAML variant changes exactly one property (wrong-recipient keeps Destination correct, so it tests the Recipient check alone)"
  - "An AuthnRequest missing ID, AssertionConsumerServiceURL or Issuer gets a 400 from the mock (no fallback ACS)"
metrics:
  duration: "~25 min"
  completed: 2026-11-26
  tasks: 2
  files: 7
---

# Phase 6 Plan 03: e2e mocks (SAML IdP, suite-wide DNS) Summary

This plan adds two local mocks for the Phase 6 browser tests. The first is a SAML IdP that signs with xml-crypto 6.4.0 under an RSA key and self-signed certificate it creates in memory at start-up. The second is a UDP DNS server (node:dgram) that answers TXT queries and that tests drive over an HTTP control channel; a CLI lets run.sh start one instance for the whole suite. Both mocks have self-test specs that pass without anvilid.

## What was built

### Mock SAML IdP (`lib/mock-saml-idp.ts`)
- `GET {ssoUrl}?SAMLRequest=&RelayState=`: the mock inflates the request with `inflateRawSync` and reads `ID`, `AssertionConsumerServiceURL` and `Issuer` by string parsing. If any of them is missing it answers 400. Otherwise it serves an HTML page that submits itself on load and also has a visible button (`#mock-saml-continue`) for no-JS browsers. The form POSTs `SAMLResponse` and `RelayState` to the ACS URL.
- The response follows the profile 06-09 pins. `InResponseTo` is the request ID, `Destination` and `Recipient` are the ACS URL, `Audience` is the request Issuer (the SP entity ID), and `NotBefore`/`NotOnOrAfter` are now -/+ 5 minutes. The NameID is persistent and set to the user's id. Attributes are `email`, `given_name` and `family_name`.
- `GET /metadata` serves the same `metadataXml`, and `GET /cert.pem` serves the certificate. The metadata is an EntityDescriptor containing an IDPSSODescriptor, a `KeyDescriptor use="signing"` and a SingleSignOnService with the HTTP-Redirect binding.
- `requests` logs each AuthnRequest the mock received (id, acsUrl, issuer, relayState, variant).
- Exported helpers: `encodeRedirectSamlRequest`, `decodeRedirectSamlRequest`, `parseAuthnRequest`, `buildSamlResponse`, `selfSignedCertPem`, `pemBody`, `escapeXml`, `SAML_NS`.
- Variants:

| Variant | Effect |
|---|---|
| `ok` | Valid signed response |
| `wrong-audience` | `Audience` = `{SP entity ID}/wrong-audience` |
| `wrong-recipient` | `SubjectConfirmationData/@Recipient` = `{ACS origin}/wrong-acs`; `Destination` stays correct |
| `expired` | Conditions and SubjectConfirmationData `NotOnOrAfter` = now - 5 min |
| `unsigned` | No `ds:Signature` anywhere |

### Mock DNS (`lib/mock-dns.ts`, `lib/mock-dns-cli.ts`)
- UDP and HTTP both bind 127.0.0.1. Name matching ignores case and a trailing dot. A TXT query gets one RR per value, with each value split into 255-byte character-strings and TTL 0. Any other query type for a known name gets NOERROR with no answers. An unknown name gets NXDOMAIN. A non-QUERY opcode gets NOTIMP, and a malformed question gets FORMERR. The TC flag is never set.
- Control API:
  - `PUT /txt/{name}` takes a non-empty JSON array of strings, replaces the values and returns 204.
  - `DELETE /txt/{name}` returns 204 even if the name was absent.
  - `DELETE /txt` clears all records and returns 204.
  - `GET /txt` returns the records as JSON, for debugging.
  - Bad input: 400 for an invalid name or body, 413 for a body over 64 KiB, 404/405 for anything else.
- `publishTxt(name, values, controlUrl?)` and `removeTxt(name, controlUrl?)` read `E2E_DNS_CONTROL_URL` when no URL is passed. If neither is available they throw an explicit error.

## How run.sh will wire them (06-23, not this plan)
`run.sh` should start `node --experimental-strip-types lib/mock-dns-cli.ts --port $E2E_DNS_PORT --control-port $E2E_DNS_CONTROL_PORT` before anvilid, using the same runner as mock-idp-cli.ts. Node 24 also runs it without the flag. It should then:
- wait for the line starting with `READY`;
- export `E2E_DNS_PORT` and `E2E_DNS_CONTROL_URL=http://127.0.0.1:$E2E_DNS_CONTROL_PORT`;
- pass `ANVILID_DOMAIN_VERIFICATION_RESOLVERS=127.0.0.1:$E2E_DNS_PORT` to anvilid;
- kill the mock in the cleanup trap (it exits 0 on SIGTERM).

Each SAML spec starts its own `startMockSamlIdp()` and pastes `metadataXml` into the console. Tests choose the identity with `setUser` and the negative case with `setVariant`.

## Verification
- `cd tests/e2e && npm ci && npx tsc --noEmit -p .`: clean.
- `npx playwright test specs/mock-saml-idp.spec.ts specs/mock-dns.spec.ts --project=chromium`: 14/14 passed. They also passed with `--repeat-each=3` (42/42).
  - SAML: the cert parses and verifies, and the metadata is correct. The assertion signature verifies with xml-crypto `checkSignature` against `certPem`. Its single reference is `#assertionID` and the signature sits right after the Issuer. A tampered NameID fails verification, and a different IdP's cert fails too. Each variant passes its checks. Malformed requests get 400 and POST gets 405. In real Chromium the form submits itself to an echo ACS with SAMLResponse and RelayState.
  - DNS: tested with node's `dns.promises.Resolver`. A configured name returns all its values, including a 615-byte value that arrives as 255/255/105 chunks. An unknown name gives ENOTFOUND, a non-TXT query gives ENODATA, and names match regardless of case or a trailing dot. The control API and the spec client work, bad input is rejected, and the client throws when the env var is missing. The CLI test checks READY, a lookup through it, and exit code 0 on SIGTERM.
- `git grep -n "PRIVATE KEY" tests/e2e`: empty.
- `scripts/check-release-graph.sh`: OK (no Rust changes in this plan).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] 413 path of the DNS control channel reset the connection**
- **Found during:** Task 2
- **Issue:** When a body went over the limit, `req.destroy()` dropped the socket before the 413 was sent, so the client saw "other side closed".
- **Fix:** Once the body passes the limit, the rest is read and thrown away, then the server answers 413.
- **Files modified:** tests/e2e/lib/mock-dns.ts
- **Commit:** a231019

**2. [Rule 3 - Verification] The `git grep "PRIVATE KEY"` check matched a test assertion**
- **Found during:** final verification
- **Fix:** The assertion now uses the regex `/PRIVATE\s+KEY/`, so the plan's grep check really comes back empty.
- **Files modified:** tests/e2e/specs/mock-saml-idp.spec.ts
- **Commit:** a231019

### Scope notes
- run.sh is not changed here. Plan 06-23 owns it (it is not in this plan's files_modified). This plan delivers the CLI and its contract.
- Additions beyond the plan's interface: `requests` (an AuthnRequest log), `GET /cert.pem`, `GET /txt`, and an optional `controlUrl` argument on the spec client so the self-test can target its own instance.

## Not run
- The full e2e suite against anvilid. It needs no Docker for these mocks, but the SAML and DNS product features they exercise come in later waves (06-18, 06-23, 06-24).

## Self-Check: PASSED
- FOUND: tests/e2e/lib/mock-saml-idp.ts, tests/e2e/lib/mock-dns.ts, tests/e2e/lib/mock-dns-cli.ts, tests/e2e/specs/mock-saml-idp.spec.ts, tests/e2e/specs/mock-dns.spec.ts
- FOUND: 2ecb442, a231019
