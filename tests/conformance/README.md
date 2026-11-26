# OpenID conformance harness

This harness runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against a freshly started `anvilid` over TLS. It runs five plans:

- `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` (Basic OP)
- `oidcc-config-certification-test-plan` (Config OP)
- `oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`
  (Form Post OP: the Basic plan's module list, error cases included, with `response_mode=form_post`)
- `oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]`
  (RP-Initiated Logout OP; override with `LOGOUT_PLAN`)
- `oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]`
  (Back-Channel Logout OP; override with `BACKCHANNEL_PLAN`)

The logout plans (suite classes `OIDCCRpInitiatedLogoutTestPlan` and
`OIDCCBackchannelRpInitiatedLogoutTestPlan`) fix `server_metadata=discovery`,
`client_auth_type=client_secret_basic` and `response_mode=default` themselves. The two remaining
variant parameters of their modules are `response_type` and `client_registration`, which is what the
variant strings above select. This was checked in the suite source at `release-v5.3.5`; the overrides
exist for other suite tags.

Local runs and CI use the same script. Run it from the repository root:

```sh
tests/conformance/run.sh all        # all five plans (default; also `just conformance`)
tests/conformance/run.sh basic      # Basic OP only
tests/conformance/run.sh config     # Config OP only
tests/conformance/run.sh formpost   # Form Post OP only
tests/conformance/run.sh logout     # RP-Initiated Logout OP only
tests/conformance/run.sh backchannel  # Back-Channel Logout OP only
```

Every selection starts its own suite and its own fresh `anvilid`; `all` runs the five plans in the
order above against one suite instance and one `anvilid`. CI (`.github/workflows/conformance.yml`) runs `run.sh all` on pushes
to `main`, on `v*` tag pushes, on manual dispatch and on pull requests that touch `crates/**` (this includes
`crates/anvil-core/src/oauth/**`, the authorize/token/consent services and
`crates/anvil-web/src/protocol/**`), `themes/**`, the harness or the workflow. Results and logs are
uploaded as the `conformance-results` artifact on every run, failed or not. Tag runs keep the artifact
for 90 days, so the release candidate's evidence stays retrievable; other runs use the repository's
default retention.

This self-hosted run is our own regression evidence. It is not the certification artefact: an
OpenID certification submission uses logs from the hosted suite at `www.certification.openid.net`
against a publicly reachable deployment. [docs/CERTIFICATION.md](../../docs/CERTIFICATION.md) is the
runbook for that, and it reuses `setup.sh --public` (below) to provision the deployment.

Requirements: Docker with the compose plugin, Python 3, curl, openssl and the Rust toolchain. The first
run downloads about 1 GB of images (MongoDB, the suite server and nginx). After that a run takes a few
minutes (one Basic OP module waits 30 seconds on purpose).

## What it does

1. It fetches `scripts/` and `docker-compose-prebuilt.yml` from the suite repository into `./suite`
   (gitignored), using a blobless clone at `CONFORMANCE_TAG`. The scripts and the prebuilt images
   (`registry.gitlab.com/openid/conformance-suite:<tag>`) always use the same tag.
2. It builds `anvilid` (`cargo build --locked -p anvilid`).
3. It generates a throwaway CA and a leaf certificate for `localhost.emobix.co.uk` (see
   [Back-channel callback certificate](#back-channel-callback-certificate)), then starts the suite with
   `docker compose -p anvil-conformance`. `compose.override.yml` maps `host.docker.internal` to the host
   gateway so the suite server (and its scripted browser) can reach the binary, and mounts the leaf
   certificate into the suite's nginx.
4. It generates a throwaway self-signed P-256 certificate for `host.docker.internal` and `localhost` with
   `openssl req -x509` in `conformance-results/tmp/`, then starts

   ```sh
   anvilid serve --listen 0.0.0.0:9443 --public-url https://host.docker.internal:9443 \
     --tls-cert … --tls-key … --data-dir <new temporary directory> --breach-check off
   ```

   This uses the built-in rustls listener. The data directory comes from `mktemp -d`, so every run is a
   zero-config first start (new SQLite database, KEK, signing keys and setup token). The breach check is
   off so the run does not depend on an external API. Port 9443 is used because the suite's nginx
   publishes 8443 and 8444 on the host. Rate limiting stays on with its defaults except for the login
   quota (see [Rate limits](#rate-limits)). Every selection also sets the two outbound settings
   `ANVILID_OUTBOUND_CA_FILE` and `ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32` (see below). They have no
   effect on plans that never make anvilid call out.
5. It waits for discovery, reads the one-time `Setup URL:` line from the log and runs `setup.sh`.
6. It runs the selected plans with the suite's own driver, `scripts/run-test-plan.py`, in dev mode (no API token) against
   `https://localhost.emobix.co.uk:8443/`. That hostname is the suite's public name for loopback: it
   resolves to 127.0.0.1, so traffic stays on the machine.
7. On exit it stops `anvilid`, deletes the data directory and `conformance-results/tmp/` (certificate,
   key and the rendered suite config with its secrets), saves the suite logs, and runs
   `docker compose down -v`. Results go to `conformance-results/`: the exported plans,
   `run-test-plan.log`, `anvilid.log` and `suite.log`.

### TLS and certificates

The suite trusts any certificate (its HTTP client and scripted browser use a trust-all trust manager),
so a self-signed certificate is enough for anvilid's listener and no CA is installed in the suite.
The only CA in the run is the throwaway callback CA that anvilid trusts for its own outbound requests
(next section). The Config OP plan fails if any
advertised endpoint is not https, which is why the harness uses the TLS listener rather than
`--insecure-http`. The key is generated per run in a gitignored temporary directory and is never
committed.

### Back-channel callback certificate

In the Back-Channel Logout plan anvilid itself makes an HTTPS request: it POSTs the logout token to
`https://localhost.emobix.co.uk:8443/test/a/anvilid/backchannel_logout`. With default settings this
request is refused twice:

- The host name resolves to 127.0.0.1, and anvilid's outbound client (the SSRF guard) blocks loopback
  and private addresses.
- The suite's nginx serves a self-signed `CN=localhost` certificate, which fails anvilid's TLS
  verification (untrusted issuer, wrong name).

The harness does not switch either check off. It uses two operator settings that any deployment can use:

- `ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32` lets the guard reach exactly the loopback address.
  Everything else stays blocked.
- `ANVILID_OUTBOUND_CA_FILE=conformance-results/tmp/callback-ca.pem` adds one trusted CA for outbound
  requests, in addition to the system roots. Hostname and chain verification stay on.

`run.sh` (`gen_callback_cert`) generates, per run, a P-256 CA (one day, `CA:TRUE`) and an RSA-2048 leaf
for `localhost.emobix.co.uk` (SAN DNS name, `serverAuth`, `CA:FALSE`) signed by that CA. It checks the
chain with `openssl verify` before the suite starts. `compose.override.yml` mounts the leaf and its key
read-only over `/etc/ssl/certs/nginx-selfsigned.crt` and `/etc/ssl/private/nginx-selfsigned.key`,
the paths from the suite's `nginx/Dockerfile`. Notes on the choices:

- It is a CA plus a leaf, not one self-signed certificate, because webpki rejects a CA certificate used
  as an end-entity certificate.
- The leaf is RSA because one listener in the suite's `nginx.conf` allows only ECDHE-RSA ciphers.
- The suite's own HTTP client and browser trust every certificate, so the replacement does not affect
  them.
- All four files are mode 600 in `conformance-results/tmp/` and are deleted on exit. With
  `KEEP_SUITE=1` nginx keeps serving the certificate it has already loaded, but restarting the
  container fails because the files are gone.

`setup.sh` registers `backchannel_logout_uri` on a dedicated client that only the Back-Channel plan
uses (see the next section).

### Setup flow (`setup.sh`)

`setup.sh <setup-url> <out-config> <out-backchannel-config>` (local mode, used by `run.sh`) provisions
the instance through public interfaces only:

1. `GET /setup?token=…` with a cookie jar (CSRF token and flow cookie), then `POST` an admin email and a
   random password. The result page exposes the management client credentials in `#mgmt-client-id` and
   `#mgmt-client-secret`. Plain curl passes the CSRF layer because it sends no Fetch-Metadata or Origin
   headers.
2. `POST /t/system/token` (client credentials, HTTP Basic) for an admin access token.
3. Confidential clients in the `default` tenant through the admin API: three matching the suite's
   static client sections `client`, `client2` (both `client_secret_basic`) and `client_secret_post`,
   and a back-channel logout client (below). Each has the exact suite callback `https://localhost.emobix.co.uk:8443/test/a/anvilid/callback`,
   grant types `authorization_code` and `refresh_token`, scopes `openid profile email address phone`,
   and `require_pkce: false`, because the Basic OP plan sends no PKCE in most modules (decision C1:
   only confidential clients may opt out). They are created with `consent_mode: "skip_first_party"`
   because the scripted browser signs in but does not answer a consent screen (clients created
   through the admin API default to `consent_mode: "required"`), and with `token_format: "jwt"`
   (the default, stated explicitly). `client` also has
   `post_logout_redirect_uris: ["https://localhost.emobix.co.uk:8443/test/a/anvilid/post_logout_redirect"]`
   for the RP-Initiated Logout plan.
   A fourth client, "conformance back-channel logout client", has the same settings plus the same
   `post_logout_redirect_uris`,
   `backchannel_logout_uri: "https://localhost.emobix.co.uk:8443/test/a/anvilid/backchannel_logout"` and
   `backchannel_logout_session_required: true`. It is a separate client on purpose: a suite module
   reports any request it does not expect as a FAILURE, so if the RP-Initiated Logout plan's `client`
   had a back-channel URI, every successful sign-out in that plan would POST a logout token into a
   module that does not handle it.
4. A user with `email_verified: true`, a random password and every standard claim (including `address`
   and `phone_number_verified`).
5. It renders `config.template.json` twice: into `conformance-results/tmp/anvilid-oidcc.json` (every
   plan except Back-Channel Logout) and into `conformance-results/tmp/anvilid-oidcc-backchannel.json`
   (Back-Channel Logout plan; `client` is the back-channel client there). The paths are stable because
   the expected-skips and expected-failures files match on `configuration-filename`; the back-channel
   name does not match the reviewed skip's `*anvilid-oidcc.json` pattern.

No secret is printed. The two rendered configs are the only place the secrets are written, and they are
deleted on exit.

#### Public mode (`setup.sh --public`)

`setup.sh --public <setup-url> <out-config> <out-backchannel-config>` runs the same five steps against
a publicly reachable deployment, for the hosted suite (see
[docs/CERTIFICATION.md](../../docs/CERTIFICATION.md)). The differences:

- The setup URL must be `https://`. curl resolves the host through normal DNS and verifies TLS
  normally (no `--resolve` to 127.0.0.1 and no `-k`), so the deployment needs a publicly trusted
  certificate.
- The client callbacks, post-logout redirect and back-channel logout URIs point at `SUITE_URL`,
  which defaults to `https://www.certification.openid.net` in public mode (local mode:
  `https://localhost.emobix.co.uk:8443`).

Both modes accept `SUITE_ALIAS` (default `anvilid`). The URIs are `$SUITE_URL/test/a/$SUITE_ALIAS/…`, and a
non-default alias is also written into the rendered configs' `alias` field. On the hosted suite, choose
an alias nobody else is using. Secrets are still never printed. In public mode the rendered configs
are the operator's to keep safe and delete, and the admin password is not shown anywhere. The
deployment is meant to be thrown away after the run. `run.sh` always uses the default local mode. `anvilid.log` contains the one-time setup URL, which is consumed during the run and belongs to
an instance that no longer exists.

### Browser automation

The suite's scripted browser (HtmlUnit, no JavaScript) follows `config.template.json`: on
`/authorize*` it fills `#identifier` and `#password` on `/ui/login*` and clicks `#login-submit`, then
waits for the suite callback. Overrides:

- `oidcc-prompt-login` and `oidcc-max-age-1` capture the second login page as the screenshot
  placeholder (`update-image-placeholder-optional`).
- `oidcc-ensure-registered-redirect-uri` and `oidcc-ensure-request-object-with-redirect-uri` wait for
  the error page sentence "The redirect URI in this request is not registered for this client" and
  capture it (`update-image-placeholder`).

Logout (RP-Initiated and Back-Channel plans). Each logout module first signs in through the
`/authorize*` block above, then the suite sends the browser to `end_session_endpoint`. A second block
matches `/logout*`:

- "Confirm sign-out" (optional): on a confirmation page under `/ui/logout*`, click
  `#logout-confirm-submit` (button text "Sign out").
- "Verify Complete": check that the browser is on the suite's `*/test/*/post_logout_redirect*` page.
  This task has no commands, as in the suite's own logout configuration: the page the suite serves
  there (`resultCaptured.html`) has no `submission_complete` element to wait for.

Module overrides replace the whole browser list, so each one repeats the `/authorize*` block:

| Modules | Expected page (captured with `update-image-placeholder`) |
|---------|------------------------------------------------------------|
| `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri`, `-query-added-to-post-logout-redirect-uri` | "The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client." |
| `oidcc-rp-initiated-logout-modified-id-token-hint`, `-bad-id-token-hint` | "The sign-out request is invalid: the id_token_hint could not be verified." |
| `oidcc-rp-initiated-logout-no-id-token-hint` | "The sign-out request is invalid: post_logout_redirect_uri requires id_token_hint or client_id." |
| `oidcc-rp-initiated-logout-no-params`, `-no-post-logout-redirect-uri`, `-only-state` | Confirm if asked, then "You have been signed out." |

The browser tells pages apart by URL. That makes three more points part of the contract:

- The confirmation page lives under `/ui/logout*`.
- The signed-out page does not live there, because the optional confirm task would match it and fail
  to find the button.
- The error pages are served under the tenant base URL.

These ids and sentences are a contract documented in `themes/default/README.md` (the logout pages are
added in 04-13). Modules that upload a placeholder finish with result `REVIEW`, which is what the suite
expects for them.

The Form Post plan uses the same automation. With `response_mode=form_post` the OP answers with the
themed `form_post.html` page instead of a redirect; the suite's browser runs JavaScript, so the
self-hosted `form_post.js` submits the form to the suite callback and the `*/test/*/callback*` task
matches as in the Basic plan. No extra browser task for the `<noscript>` `Continue` button is needed.

Note on `form-action`: the form_post page sends a per-response CSP whose `form-action` allows only the
redirect URI's origin. HtmlUnit does not enforce CSP, so the suite cannot detect a problem there.
Chromium also applies `form-action` to redirects that follow the form submission, so a relying party
whose callback answers the POST with a redirect to a different origin would be blocked in Chromium.
The suite's callback does not redirect, so this does not affect the conformance result.

### Environment overrides

| Variable | Default | Meaning |
|----------|---------|---------|
| `CONFORMANCE_TAG` | `release-v5.3.5` | Suite git tag and image tag |
| `ANVILID_BIN` | `target/debug/anvilid` | Binary under test. The default path is always rebuilt. Any other path must already exist |
| `ANVILID_PORT` | `9443` | TLS listen port; the public URL is `https://host.docker.internal:$ANVILID_PORT` |
| `RESULTS_DIR` | `conformance-results` | Output directory |
| `KEEP_SUITE` | `0` | `1` leaves the suite containers running after the run, for debugging |
| `CONFORMANCE_AUTH_PER_MINUTE` | `600` | Login quota of the conformance instance, passed as `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE` |
| `LOGOUT_PLAN` | `oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` | Plan run by `run.sh logout` |
| `BACKCHANNEL_PLAN` | `oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` | Plan run by `run.sh backchannel` |

### Rate limits

Rate limiting is on by default (SEC-05) and stays on for the conformance run. The only change is the
login (Auth class) quota: the default of 10 POSTs per minute and client IP, burst 5, is sized for
people, but every suite module signs in through the scripted browser and every request arrives from
the one Docker gateway address, so a full run makes far more than 10 logins a minute. `run.sh` starts
`anvilid` with `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=600` (burst 300). The token, admin and default
classes and the per-client token limit keep their defaults, and the brute-force lockouts (which count
failed logins only) are unchanged.

## Expected skips and failures

`run-test-plan.py` exits non-zero when a condition fails or warns that is not listed in
`expected-failures.json`, when a module is skipped that is not listed in `expected-skips.json`, and
when a listed entry is not used. Both files must match the current behaviour exactly.

`expected-failures.json` is `[]`. A failure is either fixed in the OP or reported for a product
decision. It is never added silently.

`expected-skips.json` contains one reviewed entry. Its `variant` is `*`, so it covers the module in
both the Basic and the Form Post plan:

| Module | Why it is skipped |
|--------|-------------------|
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | Request objects are not supported in releases 0.1 and 0.2 (`request_parameter_supported: false`). The OP answers `request_not_supported` (OIDC Core 3.1.2.6), which the suite allows and reports as a skip |

Some modules in the Basic plan source do not run at all with `client_registration=static_client`
(`oidcc-idtoken-signature`, `oidcc-idtoken-unsigned`,
`oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported`), so they need no skip
entry. `oidcc-ensure-request-object-with-redirect-uri` is not skipped: the OP shows the invalid
redirect URI error page, which the module accepts.

The Config OP and the two logout plans have no skip. `run-test-plan.py` fails on skip entries no
module used, so `run.sh config`, `run.sh logout` and `run.sh backchannel` check against an empty skip
list generated in `conformance-results/tmp/`. `run.sh all` uses `expected-skips.json`, whose entry is
used by the Basic and Form Post plans.

## Running locally

```sh
just conformance                          # build, run all five plans, tear down
KEEP_SUITE=1 just conformance             # keep the suite UI at https://localhost.emobix.co.uk:8443/
docker compose -p anvil-conformance down -v   # stop a kept suite
```

Failing modules link to `https://localhost.emobix.co.uk:8443/log-detail.html?log=…` while the suite
is running. The exported zip files in `conformance-results/` contain the same logs.
