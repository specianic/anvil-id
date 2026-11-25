# OpenID conformance harness

This harness runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against a freshly started `anvilid` over TLS. It runs three plans:

- `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` (Basic OP)
- `oidcc-config-certification-test-plan` (Config OP)
- `oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`
  (Form Post OP: the Basic plan's module list, error cases included, with `response_mode=form_post`)

Local runs and CI use the same script. Run it from the repository root:

```sh
tests/conformance/run.sh all        # all three plans (default; also `just conformance`)
tests/conformance/run.sh basic      # Basic OP only
tests/conformance/run.sh config     # Config OP only
tests/conformance/run.sh formpost   # Form Post OP only
```

Every selection starts its own suite and its own fresh `anvilid`; `all` runs the three plans against one
suite instance and one `anvilid`. CI (`.github/workflows/conformance.yml`) runs `run.sh all` on pushes
to `main`, on manual dispatch and on pull requests that touch `crates/**` (this includes
`crates/anvil-core/src/oauth/**`, the authorize/token/consent services and
`crates/anvil-web/src/protocol/**`), `themes/**`, the harness or the workflow. Results and logs are
uploaded as the `conformance-results` artifact on every run, failed or not.

Requirements: Docker with the compose plugin, Python 3, curl, openssl and the Rust toolchain. The first
run downloads about 1 GB of images (MongoDB, the suite server and nginx). After that a run takes a few
minutes (one Basic OP module waits 30 seconds on purpose).

## What it does

1. It fetches `scripts/` and `docker-compose-prebuilt.yml` from the suite repository into `./suite`
   (gitignored), using a blobless clone at `CONFORMANCE_TAG`. The scripts and the prebuilt images
   (`registry.gitlab.com/openid/conformance-suite:<tag>`) always use the same tag.
2. It builds `anvilid` (`cargo build --locked -p anvilid`).
3. It starts the suite with `docker compose -p anvil-conformance`. `compose.override.yml` maps
   `host.docker.internal` to the host gateway so the suite server (and its scripted browser) can reach
   the binary.
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
   quota (see [Rate limits](#rate-limits)).
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
so a self-signed certificate is enough and no CA is installed anywhere. The Config OP plan fails if any
advertised endpoint is not https, which is why the harness uses the TLS listener rather than
`--insecure-http`. The key is generated per run in a gitignored temporary directory and is never
committed.

### Setup flow (`setup.sh`)

`setup.sh <setup-url> <out-config>` provisions the instance through public interfaces only:

1. `GET /setup?token=…` with a cookie jar (CSRF token and flow cookie), then `POST` an admin email and a
   random password. The result page exposes the management client credentials in `#mgmt-client-id` and
   `#mgmt-client-secret`. Plain curl passes the CSRF layer because it sends no Fetch-Metadata or Origin
   headers.
2. `POST /t/system/token` (client credentials, HTTP Basic) for an admin access token.
3. Three confidential clients in the `default` tenant through the admin API, matching the suite's
   static client sections `client`, `client2` (both `client_secret_basic`) and `client_secret_post`.
   Each has the exact suite callback `https://localhost.emobix.co.uk:8443/test/a/anvilid/callback`,
   grant types `authorization_code` and `refresh_token`, scopes `openid profile email address phone`,
   and `require_pkce: false`, because the Basic OP plan sends no PKCE in most modules (decision C1:
   only confidential clients may opt out). They are created with `consent_mode: "skip_first_party"`
   because the scripted browser signs in but does not answer a consent screen (clients created
   through the admin API default to `consent_mode: "required"`), and with `token_format: "jwt"`
   (the default, stated explicitly).
4. A user with `email_verified: true`, a random password and every standard claim (including `address`
   and `phone_number_verified`).
5. It renders `config.template.json` into `conformance-results/tmp/anvilid-oidcc.json`. The path is
   stable because the expected-skips and expected-failures files match on `configuration-filename`.

No secret is printed. The rendered config is the only place the secrets are written, and it is deleted
on exit. `anvilid.log` contains the one-time setup URL, which is consumed during the run and belongs to
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

These ids and the sentence are a contract documented in `themes/default/README.md`. Modules that
upload a placeholder finish with result `REVIEW`, which is what the suite expects for them.

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

The Config OP plan has no skip. `run-test-plan.py` fails on skip entries no module used, so
`run.sh config` checks against an empty skip list generated in `conformance-results/tmp/`.

## Running locally

```sh
just conformance                          # build, run all three plans, tear down
KEEP_SUITE=1 just conformance             # keep the suite UI at https://localhost.emobix.co.uk:8443/
docker compose -p anvil-conformance down -v   # stop a kept suite
```

Failing modules link to `https://localhost.emobix.co.uk:8443/log-detail.html?log=…` while the suite
is running. The exported zip files in `conformance-results/` contain the same logs.
