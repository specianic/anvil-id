#!/usr/bin/env bash
# Runs the OpenID conformance suite (Basic OP, Config OP, Form Post OP, RP-Initiated Logout OP and
# Back-Channel Logout OP) against a freshly started anvilid over TLS.
#
# Usage: tests/conformance/run.sh [basic|config|formpost|logout|backchannel|all]   (default: all)
#        `all` = basic + config + formpost + logout + backchannel, in that order.
#
# Local runs and CI run this same script (`just conformance`). It:
#   1. fetches the suite's scripts + prebuilt compose file at the pinned tag into ./suite,
#   2. generates a throwaway CA + leaf certificate for the suite's nginx (localhost.emobix.co.uk) and
#      starts the suite (prebuilt images, same tag) with docker compose,
#   3. generates a throwaway self-signed P-256 certificate in $RESULTS_DIR/tmp and starts a fresh
#      anvilid (new temporary data dir) on the built-in TLS listener at 0.0.0.0:$ANVILID_PORT with
#      public URL https://host.docker.internal:$ANVILID_PORT; anvilid trusts the callback CA and may
#      reach 127.0.0.1 through its outbound (SSRF) guard, for back-channel logout delivery,
#   4. provisions it through /setup and the admin API (setup.sh), which writes the suite configs,
#   5. runs the selected plans through the suite's own run-test-plan.py with the expected-skips and
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
# The Basic plan's module list with response_mode=form_post (suite: OIDCCFormPostBasicTestPlan).
FORMPOST_PLAN="oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
# Logout plans (suite: OIDCCRpInitiatedLogoutTestPlan, OIDCCBackchannelRpInitiatedLogoutTestPlan). Both
# plans fix server_metadata=discovery, client_auth_type=client_secret_basic and response_mode=default per
# module; the remaining variant parameters of AbstractOIDCCServerTest are response_type and
# client_registration (checked in the suite source at release-v5.3.5). Overridable for other suite tags.
LOGOUT_PLAN="${LOGOUT_PLAN:-oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]}"
BACKCHANNEL_PLAN="${BACKCHANNEL_PLAN:-oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]}"
# Host name of the suite's nginx as seen from the host. It resolves to 127.0.0.1, which is why anvilid
# gets ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32 below (back-channel logout POSTs to this host).
CALLBACK_HOST="localhost.emobix.co.uk"
# Login quota for the conformance instance. Rate limiting stays on, but the default Auth class
# (10 logins per minute and IP, burst 5) is sized for humans: every suite module signs in through
# the scripted browser, and all of them arrive from the one Docker gateway address.
CONFORMANCE_AUTH_PER_MINUTE="${CONFORMANCE_AUTH_PER_MINUTE:-600}"
PUBLIC_URL="https://host.docker.internal:${ANVILID_PORT}"

log() { printf '[conformance] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

[[ $# -le 1 ]] || die "usage: run.sh [basic|config|formpost|logout|backchannel|all]"
SELECTION="${1:-all}"
PLAN_ARGS=()
case "$SELECTION" in
  basic) PLAN_NAMES=("$BASIC_PLAN") ;;
  config) PLAN_NAMES=("$CONFIG_PLAN") ;;
  formpost) PLAN_NAMES=("$FORMPOST_PLAN") ;;
  logout) PLAN_NAMES=("$LOGOUT_PLAN") ;;
  backchannel) PLAN_NAMES=("$BACKCHANNEL_PLAN") ;;
  all) PLAN_NAMES=("$BASIC_PLAN" "$CONFIG_PLAN" "$FORMPOST_PLAN" "$LOGOUT_PLAN" "$BACKCHANNEL_PLAN") ;;
  *) die "unknown plan selection '$SELECTION' (expected basic, config, formpost, logout, backchannel or all)" ;;
esac

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
# Back-Channel Logout plan only: same template, but `client` is the client with a backchannel_logout_uri
# (setup.sh explains why no other plan may use that client). The name does not match the
# `*anvilid-oidcc.json` pattern of the reviewed skip, which belongs to the Basic/Form Post plans.
CFG_BACKCHANNEL="$TMP_DIR/anvilid-oidcc-backchannel.json"
rm -rf "$TMP_DIR"
mkdir -m 700 "$TMP_DIR"

# Throwaway CA + leaf for the suite's nginx, written to $TMP_DIR (deleted by cleanup):
#   callback-ca.pem / callback-ca.key       P-256 CA, 1 day, basicConstraints CA:TRUE
#   callback-leaf.pem / callback-leaf.key   RSA-2048 leaf for $CALLBACK_HOST (SAN DNS, serverAuth,
#                                           CA:FALSE), signed by the CA
# A CA + leaf rather than one self-signed certificate: webpki rejects a CA certificate used as an
# end-entity certificate. RSA for the leaf because the suite's nginx.conf pins ECDHE-RSA ciphers on one
# of its listeners. Self-contained (no log/die) so it can be tested on its own.
gen_callback_cert() {
  local d="$TMP_DIR" host="${CALLBACK_HOST:-localhost.emobix.co.uk}"
  [[ -n "$d" && -d "$d" ]] || { printf 'gen_callback_cert: TMP_DIR is not a directory\n' >&2; return 1; }
  cat > "$d/callback-cert.cnf" <<EOF || return 1
[req]
distinguished_name = dn
prompt = no
[dn]
CN = anvilid conformance callback CA
[leaf_dn]
CN = $host
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[leaf_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$host
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
  openssl req -x509 -config "$d/callback-cert.cnf" -extensions ca_ext \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -keyout "$d/callback-ca.key" -out "$d/callback-ca.pem" 2>/dev/null || return 1
  openssl req -new -config "$d/callback-cert.cnf" -subj "/CN=$host" -newkey rsa:2048 -nodes \
    -keyout "$d/callback-leaf.key" -out "$d/callback-leaf.csr" 2>/dev/null || return 1
  openssl x509 -req -in "$d/callback-leaf.csr" -CA "$d/callback-ca.pem" -CAkey "$d/callback-ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 1 -sha256 \
    -extfile "$d/callback-cert.cnf" -extensions leaf_ext -out "$d/callback-leaf.pem" 2>/dev/null || return 1
  rm -f "$d/callback-leaf.csr" "$d/callback-cert.cnf"
  chmod 600 "$d/callback-ca.key" "$d/callback-ca.pem" "$d/callback-leaf.key" "$d/callback-leaf.pem" || return 1
  # Fail fast: the chain anvilid will verify (leaf for $host issued by the CA) must verify here.
  openssl verify -CAfile "$d/callback-ca.pem" -purpose sslserver -verify_hostname "$host" \
    "$d/callback-leaf.pem" >/dev/null || { printf 'gen_callback_cert: leaf does not verify\n' >&2; return 1; }
}

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
# shellcheck disable=SC2329 # invoked through `trap cleanup EXIT` (newer shellcheck does not see it)
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
# Callback certificate first: compose mounts the leaf into nginx at container start.
gen_callback_cert || die "could not generate the callback CA and leaf certificate"
TMP_ABS=$(cd "$TMP_DIR" && pwd)
# Read by compose.override.yml (mounted read-only over the nginx certificate paths).
export ANVIL_CALLBACK_CERT="$TMP_ABS/callback-leaf.pem"
export ANVIL_CALLBACK_KEY="$TMP_ABS/callback-leaf.key"
CALLBACK_CA="$TMP_ABS/callback-ca.pem"

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
log "starting $ANVILID_BIN ${ANVILID_ARGS[*]} (ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=$CONFORMANCE_AUTH_PER_MINUTE ANVILID_OUTBOUND_CA_FILE=$CALLBACK_CA ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32)"
# Outbound settings (operator config, same for every selection): trust the callback CA in addition to
# the system roots, and let the SSRF guard reach 127.0.0.1 ($CALLBACK_HOST). TLS verification stays on.
ANVILID_RATE_LIMIT_AUTH_PER_MINUTE="$CONFORMANCE_AUTH_PER_MINUTE" \
ANVILID_OUTBOUND_CA_FILE="$CALLBACK_CA" \
ANVILID_OUTBOUND_ALLOW_CIDRS="127.0.0.1/32" \
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
tests/conformance/setup.sh "$setup_url" "$CFG" "$CFG_BACKCHANNEL"

# --- 5. Runner (suite's own driver, in a venv) ------------------------------------------------------------
if [[ ! -x "$SUITE_DIR/.venv/bin/python3" ]]; then
  python3 -m venv "$SUITE_DIR/.venv"
fi
"$SUITE_DIR/.venv/bin/python3" -m pip install --quiet --disable-pip-version-check \
  -r "$SUITE_DIR/scripts/requirements.txt"

# The reviewed skip is a Basic/Form Post module. The Config and logout plans have none, and
# run-test-plan.py fails on unused skip entries, so those runs check against an empty skip list.
SKIPS_FILE="$EXPECTED_SKIPS"
if [[ "$SELECTION" == "config" || "$SELECTION" == "logout" || "$SELECTION" == "backchannel" ]]; then
  SKIPS_FILE="$TMP_DIR/no-skips.json"
  printf '[]\n' > "$SKIPS_FILE"
fi

# All plans share one config file (same clients, user and browser automation) except the Back-Channel
# Logout plan, whose config points `client` at the back-channel client.
for plan in "${PLAN_NAMES[@]}"; do
  if [[ "$plan" == "$BACKCHANNEL_PLAN" ]]; then
    PLAN_ARGS+=("$plan" "$CFG_BACKCHANNEL")
  else
    PLAN_ARGS+=("$plan" "$CFG")
  fi
done
log "running ${PLAN_NAMES[*]}"
set +e
CONFORMANCE_SERVER="https://localhost.emobix.co.uk:8443/" CONFORMANCE_DEV_MODE=1 \
  "$SUITE_DIR/.venv/bin/python3" "$SUITE_DIR/scripts/run-test-plan.py" --verbose \
    --expected-skips-file "$SKIPS_FILE" \
    --expected-failures-file "$EXPECTED_FAILURES" \
    --export-dir "$RESULTS_DIR" \
    "${PLAN_ARGS[@]}" 2>&1 | tee "$RESULTS_DIR/run-test-plan.log"
runner_rc=${PIPESTATUS[0]}
set -e

log "run-test-plan.py exited with $runner_rc"
exit "$runner_rc"
