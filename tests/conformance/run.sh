#!/usr/bin/env bash
# Runs the OpenID conformance suite (Basic OP + Config OP) against a freshly started anvilid over TLS.
#
# Local runs and CI run this same script (`just conformance`). It:
#   1. fetches the suite's scripts + prebuilt compose file at the pinned tag into ./suite,
#   2. starts the suite (prebuilt images, same tag) with docker compose,
#   3. generates a throwaway self-signed P-256 certificate in $RESULTS_DIR/tmp and starts a fresh
#      anvilid (new temporary data dir) on the built-in TLS listener at 0.0.0.0:$ANVILID_PORT with
#      public URL https://host.docker.internal:$ANVILID_PORT,
#   4. provisions it through /setup and the admin API (setup.sh), which writes the suite config,
#   5. runs both plans through the suite's own run-test-plan.py with the expected-skips and
#      expected-failures files, exporting results to $RESULTS_DIR,
#   6. tears everything down (logs saved to $RESULTS_DIR, generated secrets deleted) and exits with
#      the runner's code.
#
# Run from the repository root. See tests/conformance/README.md.
set -euo pipefail

# The suite git tag and the image tag are the same value on purpose (scripts and server must match).
CONFORMANCE_TAG="${CONFORMANCE_TAG:-release-v5.3.5}"
ANVILID_BIN="${ANVILID_BIN:-target/debug/anvilid}"
# Not 8443: the suite's nginx publishes 8443 and 8444 on the host.
ANVILID_PORT="${ANVILID_PORT:-9443}"
RESULTS_DIR="${RESULTS_DIR:-conformance-results}"
KEEP_SUITE="${KEEP_SUITE:-0}"

SUITE_DIR="suite"
SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"
TAG_MARKER="$SUITE_DIR/.anvil-conformance-tag"
COMPOSE_PROJECT="anvil-conformance"
EXPECTED_FAILURES="tests/conformance/expected-failures.json"
EXPECTED_SKIPS="tests/conformance/expected-skips.json"
BASIC_PLAN="oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
CONFIG_PLAN="oidcc-config-certification-test-plan"
PUBLIC_URL="https://host.docker.internal:${ANVILID_PORT}"

log() { printf '[conformance] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

[[ -f Cargo.toml && -d tests/conformance ]] || die "run from the repository root"
command -v docker >/dev/null || die "docker is required"
command -v python3 >/dev/null || die "python3 is required"
command -v curl >/dev/null || die "curl is required"
command -v openssl >/dev/null || die "openssl is required"

mkdir -p "$RESULTS_DIR"
# Generated secrets (TLS key, suite config with client secrets and the user password) live here only.
# The path is stable on purpose: the expected-failures/skips files key on configuration-filename.
TMP_DIR="$RESULTS_DIR/tmp"
CFG="$TMP_DIR/anvilid-oidcc.json"
rm -rf "$TMP_DIR"
mkdir -m 700 "$TMP_DIR"

compose() {
  IMAGE_TAG="$CONFORMANCE_TAG" docker compose -p "$COMPOSE_PROJECT" \
    -f "$SUITE_DIR/docker-compose-prebuilt.yml" \
    -f tests/conformance/compose.override.yml "$@"
}

# --- 1. Suite scripts + compose file at the pinned tag ------------------------------------------
if [[ ! -f "$TAG_MARKER" || "$(cat "$TAG_MARKER")" != "$CONFORMANCE_TAG" ]]; then
  log "fetching conformance suite $CONFORMANCE_TAG"
  rm -rf "$SUITE_DIR"
  # Blobless clone without checkout, then check out only the paths we need. Avoids sparse-checkout,
  # whose cone/non-cone defaults differ across git versions (newer git rejects file patterns).
  git clone --depth 1 --branch "$CONFORMANCE_TAG" --filter=blob:none --no-checkout "$SUITE_REPO" "$SUITE_DIR"
  git -C "$SUITE_DIR" checkout HEAD -- scripts docker-compose-prebuilt.yml
  printf '%s\n' "$CONFORMANCE_TAG" > "$TAG_MARKER"
fi
[[ -f "$SUITE_DIR/docker-compose-prebuilt.yml" && -f "$SUITE_DIR/scripts/run-test-plan.py" ]] \
  || die "suite checkout incomplete; delete ./$SUITE_DIR and retry"

# --- 2. anvilid binary ----------------------------------------------------------------------------
if [[ "$ANVILID_BIN" == "target/debug/anvilid" ]]; then
  # Default path: always (incrementally) build so a stale binary is never tested.
  log "building anvilid"
  cargo build --locked -p anvilid
elif [[ ! -x "$ANVILID_BIN" ]]; then
  die "ANVILID_BIN=$ANVILID_BIN does not exist or is not executable"
fi

# --- Cleanup (registered before anything is started) ------------------------------------------------
ANVILID_PID=""
ANVILID_DATA=""
cleanup() {
  local rc=$?
  set +e
  if [[ -n "$ANVILID_PID" ]] && kill -0 "$ANVILID_PID" 2>/dev/null; then
    kill -TERM "$ANVILID_PID" 2>/dev/null
    wait "$ANVILID_PID" 2>/dev/null
  fi
  if [[ -n "$ANVILID_DATA" && -d "$ANVILID_DATA" ]]; then
    rm -rf "$ANVILID_DATA"
  fi
  rm -rf "$TMP_DIR"
  compose logs --no-color > "$RESULTS_DIR/suite.log" 2>&1
  if [[ "$KEEP_SUITE" == "1" ]]; then
    log "KEEP_SUITE=1: leaving the suite running (docker compose -p $COMPOSE_PROJECT down -v to stop)"
  else
    compose down -v --remove-orphans >/dev/null 2>&1
  fi
  log "results, anvilid.log, suite.log and run-test-plan.log are in $RESULTS_DIR/"
  exit "$rc"
}
trap cleanup EXIT

# --- 3. Start the suite -----------------------------------------------------------------------------
log "starting conformance suite (images $CONFORMANCE_TAG)"
compose up -d

# --- 4. Start a fresh anvilid over TLS ---------------------------------------------------------------
# Throwaway self-signed certificate, generated per run and deleted on exit (the suite trusts any
# certificate). A fresh data dir per run keeps the run zero-config (new SQLite database, KEK, keys
# and setup token).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=host.docker.internal" -addext "subjectAltName=DNS:host.docker.internal,DNS:localhost" \
  -keyout "$TMP_DIR/tls.key" -out "$TMP_DIR/tls.crt" 2>/dev/null \
  || die "openssl could not generate the TLS certificate"
ANVILID_DATA=$(mktemp -d)
# Binary invocation: keep on ONE line.
ANVILID_ARGS=(serve --listen "0.0.0.0:$ANVILID_PORT" --public-url "$PUBLIC_URL" --tls-cert "$TMP_DIR/tls.crt" --tls-key "$TMP_DIR/tls.key" --data-dir "$ANVILID_DATA" --breach-check off)
log "starting $ANVILID_BIN ${ANVILID_ARGS[*]}"
"$ANVILID_BIN" "${ANVILID_ARGS[@]}" > "$RESULTS_DIR/anvilid.log" 2>&1 &
ANVILID_PID=$!

# The host may not resolve host.docker.internal; pin it to loopback for local checks.
discovery="$PUBLIC_URL/.well-known/openid-configuration"
curl_local() { curl -k --resolve "host.docker.internal:${ANVILID_PORT}:127.0.0.1" "$@"; }
for _ in $(seq 50); do
  if curl_local -fsS -o /dev/null "$discovery" 2>/dev/null; then break; fi
  kill -0 "$ANVILID_PID" 2>/dev/null || { cat "$RESULTS_DIR/anvilid.log" >&2; die "anvilid exited during startup"; }
  sleep 0.2
done
curl_local -fsS -o /dev/null "$discovery" || { cat "$RESULTS_DIR/anvilid.log" >&2; die "anvilid discovery not reachable after 10s"; }
log "anvilid is serving discovery over TLS"

# The one-time setup URL is printed as a plain `Setup URL:` line (stdout with json logs).
setup_url=""
for _ in $(seq 25); do
  setup_url=$(grep -a -o 'Setup URL: https://[^"[:space:]]*' "$RESULTS_DIR/anvilid.log" | head -n1 | sed 's/^Setup URL: //') || true
  [[ -n "$setup_url" ]] && break
  sleep 0.2
done
[[ -n "$setup_url" ]] || die "no 'Setup URL:' line in $RESULTS_DIR/anvilid.log"

# --- 4b. Provision clients and the test user, write the suite config -----------------------------------
tests/conformance/setup.sh "$setup_url" "$CFG"

# --- 5. Runner (suite's own driver, in a venv) ------------------------------------------------------------
if [[ ! -x "$SUITE_DIR/.venv/bin/python3" ]]; then
  python3 -m venv "$SUITE_DIR/.venv"
fi
"$SUITE_DIR/.venv/bin/python3" -m pip install --quiet --disable-pip-version-check \
  -r "$SUITE_DIR/scripts/requirements.txt"

log "running $BASIC_PLAN and $CONFIG_PLAN"
set +e
CONFORMANCE_SERVER="https://localhost.emobix.co.uk:8443/" CONFORMANCE_DEV_MODE=1 \
  "$SUITE_DIR/.venv/bin/python3" "$SUITE_DIR/scripts/run-test-plan.py" --verbose \
    --expected-skips-file "$EXPECTED_SKIPS" \
    --expected-failures-file "$EXPECTED_FAILURES" \
    --export-dir "$RESULTS_DIR" \
    "$BASIC_PLAN" "$CFG" "$CONFIG_PLAN" "$CFG" 2>&1 | tee "$RESULTS_DIR/run-test-plan.log"
runner_rc=${PIPESTATUS[0]}
set -e

log "run-test-plan.py exited with $runner_rc"
exit "$runner_rc"
