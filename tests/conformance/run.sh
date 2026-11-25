#!/usr/bin/env bash
# Spike C (FND-05): run the OpenID conformance suite against a freshly started anvilid.
#
# Local runs and CI run this same script (`just conformance`). It:
#   1. fetches the suite's scripts + prebuilt compose file at the pinned tag into ./suite,
#   2. starts the suite (prebuilt images, same tag) with docker compose,
#   3. starts a fresh anvilid listening on 0.0.0.0:$ANVILID_PORT,
#   4. runs the Config OP plan through the suite's own run-test-plan.py with the
#      expected-failures ratchet, exporting results to $RESULTS_DIR,
#   5. tears everything down (logs saved to $RESULTS_DIR) and exits with the runner's code.
#
# Run from the repository root. See tests/conformance/README.md.
set -euo pipefail

# The suite git tag and the image tag are the same value on purpose (scripts and server must match).
CONFORMANCE_TAG="${CONFORMANCE_TAG:-release-v5.3.5}"
ANVILID_BIN="${ANVILID_BIN:-target/debug/anvilid}"
ANVILID_PORT="${ANVILID_PORT:-9090}"
RESULTS_DIR="${RESULTS_DIR:-conformance-results}"
KEEP_SUITE="${KEEP_SUITE:-0}"

SUITE_DIR="suite"
SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"
TAG_MARKER="$SUITE_DIR/.anvil-conformance-tag"
COMPOSE_PROJECT="anvil-conformance"
CONFIG_FILE="tests/conformance/config-m0.json"
EXPECTED_FAILURES="tests/conformance/expected-failures-m0.json"
TEST_PLAN="oidcc-config-certification-test-plan"

log() { printf '[conformance] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

[[ -f Cargo.toml && -d tests/conformance ]] || die "run from the repository root"
command -v docker >/dev/null || die "docker is required"
command -v python3 >/dev/null || die "python3 is required"
command -v curl >/dev/null || die "curl is required"

# The suite reaches anvilid through the discovery URL in the config file, so it must use the same port.
grep -q "host.docker.internal:${ANVILID_PORT}/" "$CONFIG_FILE" \
  || die "$CONFIG_FILE does not point at port $ANVILID_PORT; edit it or unset ANVILID_PORT"

mkdir -p "$RESULTS_DIR"

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
cleanup() {
  local rc=$?
  set +e
  if [[ -n "$ANVILID_PID" ]] && kill -0 "$ANVILID_PID" 2>/dev/null; then
    kill -TERM "$ANVILID_PID" 2>/dev/null
    wait "$ANVILID_PID" 2>/dev/null
  fi
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

# --- 4. Start a fresh anvilid -------------------------------------------------------------------------
# Binary invocation: keep on ONE line (plan 07 appends --database-url here).
ANVILID_ARGS=(serve --listen "0.0.0.0:$ANVILID_PORT" --issuer "http://host.docker.internal:$ANVILID_PORT" --database-url "sqlite::memory:")
log "starting $ANVILID_BIN ${ANVILID_ARGS[*]}"
"$ANVILID_BIN" "${ANVILID_ARGS[@]}" > "$RESULTS_DIR/anvilid.log" 2>&1 &
ANVILID_PID=$!

discovery="http://127.0.0.1:$ANVILID_PORT/.well-known/openid-configuration"
for _ in $(seq 50); do
  if curl -fsS -o /dev/null "$discovery"; then break; fi
  kill -0 "$ANVILID_PID" 2>/dev/null || { cat "$RESULTS_DIR/anvilid.log" >&2; die "anvilid exited during startup"; }
  sleep 0.2
done
curl -fsS -o /dev/null "$discovery" || { cat "$RESULTS_DIR/anvilid.log" >&2; die "anvilid discovery not reachable after 10s"; }
log "anvilid is serving discovery"

# --- 5. Runner (suite's own driver, in a venv) ------------------------------------------------------------
if [[ ! -x "$SUITE_DIR/.venv/bin/python3" ]]; then
  python3 -m venv "$SUITE_DIR/.venv"
fi
"$SUITE_DIR/.venv/bin/python3" -m pip install --quiet --disable-pip-version-check \
  -r "$SUITE_DIR/scripts/requirements.txt"

log "running $TEST_PLAN"
set +e
CONFORMANCE_SERVER="https://localhost.emobix.co.uk:8443/" CONFORMANCE_DEV_MODE=1 \
  "$SUITE_DIR/.venv/bin/python3" "$SUITE_DIR/scripts/run-test-plan.py" --verbose \
    --expected-failures-file "$EXPECTED_FAILURES" \
    --export-dir "$RESULTS_DIR" \
    "$TEST_PLAN" "$CONFIG_FILE" 2>&1 | tee "$RESULTS_DIR/run-test-plan.log"
runner_rc=${PIPESTATUS[0]}
set -e

log "run-test-plan.py exited with $runner_rc"
exit "$runner_rc"
