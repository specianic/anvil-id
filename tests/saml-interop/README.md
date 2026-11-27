# SAML interop against real IdP software

AnvilID signs in through three SAML identity providers, each running from a pinned container
image: Keycloak, SimpleSAMLphp and Shibboleth IdP. A real browser (Playwright) uses each IdP's
own login page. The scenarios, and the rows of the manual checklist in
[docs/SAML.md](../../docs/SAML.md#automated-interop-ci) they cover, are listed at the top of
[`tests/e2e/specs/saml-interop.spec.ts`](../e2e/specs/saml-interop.spec.ts).

```sh
just saml-interop                     # all three IdPs, SQLite
just saml-interop sqlite keycloak     # one IdP
just saml-interop-clean images=1      # remove leftovers and the pulled IdP images (~1.2 GB)
```

Needs Docker (compose v2), openssl, Node.js, curl and what `just e2e` needs (`npm ci --prefix
tests/e2e`, Playwright's chromium). CI runs the same recipe in `.github/workflows/saml-interop.yml`.

## What runs

`run.sh [--provision-only] [sqlite|postgres] [keycloak simplesamlphp shibboleth ...]`:

1. creates a mode-700 run directory (`mktemp -d`) and generates everything below into it;
2. renders every `*.tmpl` here (placeholders `@@NAME@@`; the run fails if one is left) and
   copies the other files;
3. starts the selected services of `compose.yml` (project `anvil-saml-interop`) and polls each
   IdP's metadata over https with the run's CA until it parses and offers an https HTTP-Redirect
   sign-in endpoint;
4. `--provision-only` stops here. Otherwise it exports the IdP facts (`SAML_INTEROP_*`), the run
   CA as `ANVILID_OUTBOUND_CA_FILE` (AnvilID fetches the metadata by URL through its guarded
   outbound client) and `NODE_EXTRA_CA_CERTS`, and calls `tests/e2e/run.sh <backend>
   specs/saml-interop.spec.ts` (release build, Mailpit, the suite's mock DNS,
   `ANVILID_SAML_EXPERIMENTAL=true`);
5. on exit, always: after a failure the IdP logs are written to `saml-interop-results/logs/` with
   every per-run password replaced by `<redacted>`; then `docker compose down -v` and the run
   directory is deleted.

The spec writes `saml-interop-results/results.json`: per IdP the image, every scenario with its
checklist rows, pass/fail and the observed signature/digest algorithms and NameID format. It never
contains SAML messages, certificates, passwords or user ids.

The regular e2e run (`tests/e2e/run.sh` without spec arguments) excludes this spec.

## Ports and services

All ports are published on 127.0.0.1 only.

| Service | Image (see `compose.yml`) | Host port | Metadata URL |
|---|---|---|---|
| `keycloak` | `quay.io/keycloak/keycloak:26.8.2` | `SAML_INTEROP_KEYCLOAK_PORT` (18443) | `/realms/interop/protocol/saml/descriptor` |
| `simplesamlphp` | `cirrusid/simplesamlphp:v2.5.3.1.20261023T014150` | `SAML_INTEROP_SSP_PORT` (18444) | `/simplesaml/module.php/saml/idp/metadata` |
| `shibboleth` | `i2incommon/shib-idp:5.2.3_20261117_rocky9_multiarch` | `SAML_INTEROP_SHIB_PORT` (18445) | `/idp/shibboleth` |

AnvilID listens on `E2E_PORT` (18090). The IdP templates register the SP values of tenant
`interop` (`http://localhost:$E2E_PORT/t/interop/saml/{slug}` and
`.../t/interop/ui/login/saml/{slug}/acs`), so the IdPs are provisioned before AnvilID starts, and
the spec checks that AnvilID's SP metadata matches them.

- SimpleSAMLphp: the SimpleSAMLphp project publishes no IdP image; the Cirrus Identity image is a
  maintained one. The dated tag is used because the plain `v2.5.3.1` tag pointed at an arm64-only
  manifest when this was written.
- Shibboleth: the Shibboleth project publishes no public Docker Hub image; the Internet2/InCommon
  Trusted Access Platform image is used.

## Generated per run (nothing of value is committed)

- a TLS CA (EC P-256) and a leaf for `IP:127.0.0.1` and `DNS:localhost`, served by all three IdPs;
- SimpleSAMLphp signing key pair; Shibboleth signing, encryption and back-channel key pairs (they
  replace the ones baked into the image) and its sealer key store (made with the image's own
  `seckeygen.sh`, run as the calling user);
- a throwaway "SP encryption" certificate whose private key is discarded at once: it only makes
  Keycloak (`kc-enc`) and SimpleSAMLphp (`ssp-enc`) encrypt, so the spec can prove that AnvilID
  refuses encrypted assertions;
- passwords: the test users' (one per IdP), the Keycloak bootstrap admin's, the SimpleSAMLphp
  admin's; the SimpleSAMLphp secret salt; the Shibboleth sealer and back-channel passwords and
  persistent-ID salt; the Shibboleth test-account file (`openssl passwd -apr1`).

Files below the run directory are world-readable because the containers run as different users
(Keycloak as uid 1000, Apache as `www-data`, Shibboleth as root); the run directory itself is mode
700. Keycloak generates its realm keys when it imports the realm, so no Keycloak key exists outside
the container.

## IdP setup

**Keycloak** (`keycloak/interop-realm.json.tmpl`, imported with `start-dev --import-realm`):
realm `interop`, users `alice` and `bob` (on `kc-ok.interop.example.com`) and `mallory` (on
`outside.example.test`, not an org domain). One SAML client per AnvilID connection, client
signature required off (AnvilID sends unsigned AuthnRequests), exclusive canonicalisation,
NameID format `persistent` (forced), user-property mappers email/firstName/lastName to
`email`/`given_name`/`family_name`:

| Client | Setup |
|---|---|
| `kc-ok` | assertion signed, RSA-SHA256; IdP-initiated URL name `kc-ok` |
| `kc-both` | Response and assertion signed |
| `kc-resp-only` | Response signed, assertion unsigned (refused) |
| `kc-unsigned` | nothing signed (refused) |
| `kc-sha1` | assertion signed with RSA-SHA1 (refused) |
| `kc-enc` | assertion signed and encrypted (refused) |

**SimpleSAMLphp** (`simplesamlphp/*.tmpl`): `exampleauth:UserPass` users `alice` and `bob`
(`mail` on `ssp-ok.interop.example.com`, `givenName`, `sn`), RSA-SHA256, and the
`saml:PersistentNameID` filter on `uid` (the default NameID is transient, which AnvilID refuses).
SPs: `ssp-ok` (Response and assertion signed, the default), `ssp-assert-only`
(`saml20.sign.response` off), `ssp-resp-only` (`saml20.sign.assertion` off, refused), `ssp-enc`
(`assertion.encryption`, refused).

**Shibboleth IdP** (`shibboleth/`): the image's own default files, changed only where marked (each
file names its source version). How the image is wired, as inspected for 5.2.3_20261117:

- `/usr/bin/startup.sh` rebuilds the war (`bin/build.sh`), rewrites `conf/logback.xml` to log to
  named pipes, then runs supervisord with Tomcat and cron. Only individual files are mounted
  (read-only), so the image can still write the rest of `conf/`.
- TLS: Tomcat's `server.xml` reads PEM files `/opt/certs/idp-default.crt` and `.key`; the run's
  leaf is mounted there (no TLS front needed).
- The image ships its own keys and sealer in `credentials/`. They are all replaced by per-run
  files. Sealer rotation (`ENABLE_SEALER_KEY_ROTATION=False`) and the daily usage beacon
  (`TIER_BEACON_OPT_OUT=True`) are off.
- `idp.properties`: entity ID `https://127.0.0.1:$SHIB_PORT/idp/shibboleth`, scope
  `interop.example.com`, `idp.encryption.optional = true`, persistent-ID source `uid`.
- Test accounts: the HTPasswd password validator on `credentials/interop.htpasswd`.
- Attributes: `mail` (`<uid>@shib-ok.interop.example.com`), `givenName` (`Interop`) and `sn`
  (`<uid>`), released to the two AnvilID SPs with the default registry's names
  (`urn:oid:…` Name, FriendlyName `mail`/`givenName`/`sn`; AnvilID maps them by FriendlyName).
- `relying-party.xml`: `shib-ok` signs the assertion (`signAssertions=true`) with encryption off;
  `shib-default` keeps the default SAML2.SSO signing (Response signed, assertion unsigned), which
  AnvilID refuses.

## Bumping an image

1. Pick the new tag and read its digest from the registry, for example:
   - Keycloak: `curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json' https://quay.io/v2/keycloak/keycloak/manifests/<tag> | grep -i docker-content-digest`
   - Docker Hub: `curl -s https://hub.docker.com/v2/repositories/<namespace>/<name>/tags/<tag>`
     (check that `images` lists `amd64`, as the CI runners are amd64).
2. Replace the `name:tag@sha256:digest` reference in `compose.yml` and the row in
   [docs/SAML.md](../../docs/SAML.md#automated-interop-ci).
3. For Shibboleth, diff the image's default files against the copies here
   (`docker run --rm --entrypoint cat <ref> /opt/shibboleth-idp/conf/<file>`) and re-apply the
   marked changes.
4. Run `just saml-interop`, then `just saml-interop-clean images=1`.
