# OpenID certification runbook

This runbook is for the project owner. It covers submitting AnvilID for OpenID Foundation (OIDF) OpenID
Provider certification of five profiles: Basic OP, Config OP, Form Post OP, RP-Initiated Logout OP and
Back-Channel Logout OP. The submission and everything tied to a legal entity (membership, payment or
waiver, the declaration) are owner actions. This document does not take those decisions. It lists them.

The OIDF pages are authoritative for fees, waiver criteria, forms and process. Read them before you
start, because they change:

- Certification overview: <https://openid.net/certification/>
- Hosted conformance suite: <https://www.certification.openid.net/>
- Submission and fee or waiver details: follow the links from the certification overview (the
  "how to certify", fee and open-source waiver pages).

## Self-hosted CI run vs hosted suite

- **CI (our evidence).** `.github/workflows/conformance.yml` runs `tests/conformance/run.sh all` on every
  push to `main`, on `v*` tags and on protocol pull requests. It uses the OIDF suite, self-hosted and
  pinned (`CONFORMANCE_TAG`), against a fresh local instance. It enforces the committed
  `tests/conformance/expected-skips.json` and `expected-failures.json` exactly. Tag runs keep the
  `conformance-results` artifact for 90 days. See [tests/conformance/README.md](https://github.com/specianic/anvil-id/blob/main/tests/conformance/README.md).
- **Hosted suite (the certification artefact).** The submission's "Conformance Test Suite Software" field
  refers to `www.certification.openid.net`, so the logs you submit must come from the hosted suite. The
  hosted suite has to reach the deployment over the internet, which means a **publicly reachable HTTPS
  deployment** of the release candidate.

Only start this runbook once the release candidate's CI conformance run is green (07-24 checks the gate
run's artifact first).

## The five plans

These are the same plan names and variant strings the CI harness runs (from
[tests/conformance/README.md](https://github.com/specianic/anvil-id/blob/main/tests/conformance/README.md)). On the hosted suite, choose the plan and set
the variants shown in brackets.

| Profile | Plan | Variants |
|---------|------|----------|
| Basic OP | `oidcc-basic-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client` |
| Config OP | `oidcc-config-certification-test-plan` | none |
| Form Post OP | `oidcc-formpost-basic-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client` |
| RP-Initiated Logout OP | `oidcc-rp-initiated-logout-certification-test-plan` | `response_type=code`, `client_registration=static_client` |
| Back-Channel Logout OP | `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | `response_type=code`, `client_registration=static_client` |

As full strings (as accepted by the suite's `scripts/run-test-plan.py`):

```text
oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]
oidcc-config-certification-test-plan
oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]
oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]
oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]
```

Notes:

- AnvilID supports only the `code` response type. Implicit and hybrid flows are not supported on purpose,
  so Form Post runs only for basic (code) and the logout plans only for `response_type=code`.
- The logout plans fix `server_metadata=discovery`, `client_auth_type=client_secret_basic` and
  `response_mode=default` themselves (checked in the suite source at the pinned tag).
- Use the plan config for each profile: every plan uses the rendered `anvilid-oidcc.json` except
  Back-Channel Logout, which uses `anvilid-oidcc-backchannel.json`. In that file `client` is the dedicated
  back-channel client. See "Setup flow" in the conformance README for why it is a separate client.

## 1. Owner decisions before starting

- [ ] **Payment or waiver.** Either a payment code from the OIDF certification payment process, or the
      open-source waiver. The waiver has eligibility conditions (including OIDF membership) that are set
      by the OIDF. Check them on the OIDF pages linked above and request the waiver the way those pages
      describe. This runbook does not restate fees or criteria.
- [ ] **OIDF membership**, if the chosen route needs it.
- [ ] **Public hostname** for a throwaway deployment, with a publicly trusted TLS certificate. The issuer
      is part of the certification record. A different protocol endpoint is a different deployment, so pick
      the hostname you want to certify, or accept that this one is a dedicated certification deployment.
- [ ] **Deployment name and version** as they will appear in the submission, for example
      "AnvilID 1.0.0-rc.4" plus the commit. Record it in [Status](#status) after submission.
- [ ] **Who signs the Declaration of Conformance** and who is the authorized contact. This is personal data
      that goes into the OIDF form only. It is never committed to this repository.

## 2. Deploy the release candidate on a throwaway public host

Use the release candidate (the tag created at the release gate, currently `v1.0.0-rc.4`) from its release
binary or container image. Do not reuse an existing deployment, its keys or its clients. OIDF publishes
the full test logs with the certification, and those logs contain client ids, client secrets, tokens and
the test user's credentials.

- Start with a **new, empty data directory**. A first start generates a new key-encryption key and new
  signing keys and prints a one-time `Setup URL:` line.
- Serve it at `https://<public-host>` with `--public-url https://<public-host>`. Use either the built-in
  TLS listener (`--tls-cert`, `--tls-key`) with a publicly trusted certificate, or a TLS proxy with
  `--trusted-proxies` set to the proxy's addresses. The Config OP plan fails if any advertised endpoint is
  not https.
- Keep the defaults otherwise. The CI harness raises one setting, and you should raise it too: the login
  quota. Every module signs in through the suite's scripted browser from the suite's addresses, so the
  default of 10 logins per minute per IP is too low. Set `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=600` (as
  `run.sh` does).
- Leave the outbound guard at its defaults. The Back-Channel Logout plan makes the deployment POST logout
  tokens to `https://www.certification.openid.net/test/a/<alias>/backchannel_logout`. That is a public
  address with a publicly trusted certificate, so the local harness's `ANVILID_OUTBOUND_CA_FILE` and
  `ANVILID_OUTBOUND_ALLOW_CIDRS` settings are not needed.
- `--breach-check off` is optional. The suite's test user has a random password either way.

Check that `https://<public-host>/.well-known/openid-configuration` is reachable from outside before you
continue.

## 3. Provision it with `setup.sh --public`

From a checkout of the release candidate tag, with Python 3 and curl:

```sh
umask 077
WORK=$(mktemp -d)
SUITE_ALIAS=<unique-alias> tests/conformance/setup.sh --public '<Setup URL from the log>' \
  "$WORK/anvilid-oidcc.json" "$WORK/anvilid-oidcc-backchannel.json"
```

Public mode uses normal DNS resolution and normal TLS verification (no loopback pinning, no `-k`). It
points every client's callback, post-logout redirect and back-channel logout URI at
`https://www.certification.openid.net/test/a/<alias>/…`. It creates the four confidential clients and the
test user exactly as in CI and writes the two plan configs. Pick an alias nobody else on the hosted suite
uses. The alias is written into both configs. No secret is printed: the configs are the only copy. Keep
`$WORK` private and delete it once the submission is done. The admin password is random and not shown
anywhere, which is fine because the deployment is thrown away at the end.

## 4. Run the five plans on the hosted suite

1. Sign in at <https://www.certification.openid.net/>.
2. For each of the five plans in the table: create the plan with the listed variants, paste the matching
   rendered config (JSON), and run every module. Use one plan run per profile.
3. Alternatively, drive the hosted suite with the suite's own `scripts/run-test-plan.py`, as `run.sh` does
   locally. Point `CONFORMANCE_SERVER` at the hosted suite and set `CONFORMANCE_TOKEN` to an API token
   from your hosted-suite account instead of `CONFORMANCE_DEV_MODE`. Pass the committed
   `tests/conformance/expected-skips.json` and `expected-failures.json`.

### Checking the results

- Every module must reach the state **FINISHED**. Warnings are allowed by the OIDF process. Any FAILED
  module is a bug: fix it in the code, ship a new release candidate and start again. Never submit around a
  failure.
- Modules that capture a screenshot with an image placeholder finish with the result **REVIEW**, as in CI.
  Check that each captured page is the expected one (the conformance README's "Browser automation" table
  lists them).
- One module is expected to be **SKIPPED** in the Basic OP and Form Post OP plans:
  `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`. AnvilID does not support
  request objects (`request_parameter_supported: false` in discovery). It answers `request_not_supported`
  (OIDC Core 3.1.2.6), which the suite accepts and reports as a skip for an unsupported optional feature.
  This is the single entry in `tests/conformance/expected-skips.json`. If you are unsure whether the OIDF
  accepts it for your submission, ask them before you submit.
- Config OP, RP-Initiated Logout OP and Back-Channel Logout OP have no expected skips.
- Discovery also advertises `pushed_authorization_request_endpoint` and
  `require_pushed_authorization_requests` (RFC 9126, added in 1.0). Both are registered metadata names.
  The Config OP plan must still finish without warnings or failures on them, as it does in CI.

## 5. Export the evidence

For each plan, use **"Publish for certification"** on the plan page. This produces one ZIP per plan (the
logs and the plan configuration). Download the five ZIPs. Before uploading, check that every ZIP is for the
same deployment and release candidate, and that each plan shows all modules FINISHED.

## 6. Submit

Follow the OIDF submission page linked from the certification overview. Checklist (values are entered in
the OIDF forms, never committed here):

- [ ] Entity name, "Deployment Name & Version" (from step 1) and the profiles: Basic OP, Config OP, Form
      Post OP, RP-Initiated Logout OP, Back-Channel Logout OP.
- [ ] "Conformance Test Suite Software": `www.certification.openid.net` plus the suite version shown on the
      hosted suite.
- [ ] The five ZIPs from step 5.
- [ ] The payment code, or the waiver confirmation from the OIDF.
- [ ] The Declaration of Conformance, signed through the process the OIDF sends.

## 7. After submission: revoke and tear down

The OIDF publishes the submitted logs. Everything in them must stop working:

- [ ] Delete the four conformance clients and the test user, or simply destroy the deployment.
- [ ] Destroy the deployment's data directory (database, key-encryption key, signing keys), so the
      published signing keys and secrets are never used again. Do not reuse that data directory or its
      keys for any other deployment.
- [ ] Delete the local rendered configs (`$WORK`) and any downloaded ZIP copies you do not need to keep.
- [ ] Take down the host. Release the TLS certificate and the DNS name, or point them elsewhere.
- [ ] Record the public-safe facts in [Status](#status) below.

## 8. Relation to the 1.0.0 release

The certification names the deployment and version that ran on the hosted suite (the release candidate).
If protocol code changes between the release candidate and 1.0.0 (`crates/anvil-core/src/oauth/`,
`service/{authorize,token,consent,logout}.rs`, `crates/anvil-web/src/protocol/`), the owner decides
whether to re-run the hosted plans. Record that decision in Status. Do not assume it.

## Status

Filled in by the owner checkpoint (07-24) with public-safe facts only: submission date, the profiles
submitted, the deployment name and version as submitted (with its commit), and the certified-list link
once published. No personal data, contact names, payment details or fees.

- Submission: not yet submitted.
