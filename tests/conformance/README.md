# OpenID conformance harness

This harness runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against a freshly started `anvilid`. Local runs and CI use the same script.

```sh
just conformance          # = tests/conformance/run.sh, run from the repository root
```

Requirements: Docker with the compose plugin, Python 3, curl and the Rust toolchain. The first run
downloads about 1 GB of images (MongoDB, the suite server and nginx). After that a run takes a few minutes.

## What it does

1. It fetches `scripts/` and `docker-compose-prebuilt.yml` from the suite repository into `./suite`
   (gitignored), using a sparse clone at `CONFORMANCE_TAG`. The scripts and the prebuilt images
   (`registry.gitlab.com/openid/conformance-suite:<tag>`) always use the same tag.
2. It builds `anvilid` (`cargo build --locked -p anvilid`).
3. It starts the suite with `docker compose -p anvil-conformance`. `compose.override.yml` maps
   `host.docker.internal` to the host gateway so the suite server can reach the binary.
4. It starts a fresh `anvilid serve --listen 0.0.0.0:9090 --issuer http://host.docker.internal:9090`
   and waits for discovery to answer.
5. It runs the suite's own driver, `scripts/run-test-plan.py`, in dev mode (no API token) against
   `https://localhost.emobix.co.uk:8443/`. That hostname is the suite's public name for loopback: it
   resolves to 127.0.0.1, so traffic stays on the machine. The plan is
   `oidcc-config-certification-test-plan` with `config-m0.json`.
6. On exit it stops `anvilid`, saves the suite logs, and runs `docker compose down -v`. Results go to
   `conformance-results/`: the exported plan, `run-test-plan.log`, `anvilid.log` and `suite.log`.

### Environment overrides

| Variable | Default | Meaning |
|----------|---------|---------|
| `CONFORMANCE_TAG` | `release-v5.3.5` | Suite git tag and image tag |
| `ANVILID_BIN` | `target/debug/anvilid` | Binary under test. The default path is always rebuilt. Any other path must already exist |
| `ANVILID_PORT` | `9090` | Listen port. It must match the `discoveryUrl` in `config-m0.json` |
| `RESULTS_DIR` | `conformance-results` | Output directory |
| `KEEP_SUITE` | `0` | `1` leaves the suite containers running after the run, for debugging |

## The expected-failures ratchet

`expected-failures-m0.json` lists every condition that is currently allowed to fail or warn. Each entry
has a `comment` that says why it fails and which phase removes it. `run-test-plan.py` exits non-zero when:

- a condition fails that is **not** listed, or
- a listed condition **no longer fails**.

The second case is intentional. When an improvement fixes a listed condition, remove its entry in the
same PR. The file must always match the current behaviour exactly.

To bootstrap or refresh it, run the harness and copy the JSON template that `--verbose` prints for
unexpected failures. Add a `comment` to each entry.

## The placeholder client

`config-m0.json` contains `"client_id": "m0-placeholder"` and `"client_secret": "m0-placeholder"`. These
are not credentials. The Config OP plan only checks discovery and never authenticates a client, but the
suite requires a `client` block. JSON has no comments, so this note lives here.

## Known limitation: plain-http issuer

In M0 the issuer is `http://host.docker.internal:9090`, so `CheckDiscEndpointAllEndpointsAreHttps` is
expected to fail. Passing the Basic and Config OP plans (Phase 2) needs an https issuer. The planned
approach is a self-signed rustls listener used only by this job. Its key is generated in a temporary
directory at run time and is never committed.
