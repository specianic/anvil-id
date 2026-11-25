#!/usr/bin/env bash
# tests/e2e/run.sh [sqlite|postgres] [spec ...]: the Playwright e2e suite against a real anvilid binary and a
# real SMTP sink (Mailpit).
#
#   1. Mailpit on 127.0.0.1:1025 (SMTP) and 127.0.0.1:8025 (HTTP API)
#   2. `cargo build -p anvilid`, then `anvilid serve` in a temp data dir with
#      ANVILID_SMTP_URL=smtp://127.0.0.1:1025 and --breach-check off (Postgres variant: a throwaway
#      postgres:18-alpine container and a random KEK passed through the environment)
#   3. the setup URL from the logs; the specs complete /setup once and share the credential
#   4. `playwright test` on the given specs (default: every spec below), in both Playwright projects
#      (chromium, and nojs with JavaScript disabled)
#
# Requires Docker, Node.js, `npm ci` in tests/e2e and examples/node-rp (nojs.spec.ts starts the
# sample RP) and Playwright's chromium.
# Ports: E2E_PORT (default 18090) for AnvilID, 1025/8025 for Mailpit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BACKEND=${1:-sqlite}
case "$BACKEND" in
    sqlite | postgres) ;;
    *)
        echo "usage: $0 [sqlite|postgres] [spec ...]" >&2
        exit 2
        ;;
esac
(($# > 0)) && shift
# a11y first: on a fresh instance it audits the setup pages before the setup token is used.
SPECS=("$@")
((${#SPECS[@]} > 0)) || SPECS=(
    specs/a11y.spec.ts specs/registration.spec.ts specs/recovery.spec.ts specs/login.spec.ts
    specs/keyboard.spec.ts specs/nojs.spec.ts specs/fixtures.spec.ts
)

MAILPIT_IMAGE=axllent/mailpit:v1.29.7
POSTGRES_IMAGE=postgres:18-alpine
PORT=${E2E_PORT:-18090}
ANVIL_URL="http://localhost:$PORT"

[[ -d tests/e2e/node_modules ]] || {
    echo "error: tests/e2e/node_modules missing; run 'npm ci --prefix tests/e2e'" >&2
    exit 1
}

TMP_DIR=$(mktemp -d)
chmod 700 "$TMP_DIR"
LOG="$TMP_DIR/anvilid.log"
MAILPIT_CID=""
PG_CID=""
ANVIL_PID=""

cleanup() {
    local status=$?
    if [[ -n "$ANVIL_PID" ]]; then
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
    if ((status != 0)) && [[ -f "$LOG" ]]; then
        echo "--- anvilid log (setup token redacted) ---" >&2
        sed -E 's/(token=)[A-Za-z0-9_-]+/\1<redacted>/g' "$LOG" | tail -50 >&2
    fi
    [[ -n "$MAILPIT_CID" ]] && docker rm -f "$MAILPIT_CID" >/dev/null 2>&1
    [[ -n "$PG_CID" ]] && docker rm -f "$PG_CID" >/dev/null 2>&1
    rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

wait_for() { # url, tries
    local url=$1 tries=${2:-120}
    for _ in $(seq 1 "$tries"); do
        curl -fsS "$url" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    echo "error: $url did not answer" >&2
    return 1
}

# 1. Mailpit.
MAILPIT_CID=$(docker run -d -p 127.0.0.1:1025:1025 -p 127.0.0.1:8025:8025 "$MAILPIT_IMAGE")
wait_for http://127.0.0.1:8025/api/v1/info

# 2. Build and start anvilid.
cargo build -p anvilid --locked
BIN="$ROOT/target/debug/anvilid"

# Every spec posts from 127.0.0.1, so the default login budget (10/min, burst 5) would throttle the
# suite. Rate limiting stays ON (its behaviour is covered by the Rust security_ratelimit /
# security_bruteforce suites); only the per-IP auth budget is raised for this run.
env_args=(ANVILID_SMTP_URL=smtp://127.0.0.1:1025 ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=1200)
if [[ "$BACKEND" == postgres ]]; then
    # Throwaway local-only credentials; the container is removed on exit.
    PG_CID=$(docker run -d -p 127.0.0.1::5432 \
        -e POSTGRES_USER=anvilid -e POSTGRES_PASSWORD=anvilid-local-only -e POSTGRES_DB=anvilid \
        "$POSTGRES_IMAGE")
    for _ in $(seq 1 120); do
        docker exec "$PG_CID" pg_isready -U anvilid -d anvilid -h 127.0.0.1 >/dev/null 2>&1 && break
        sleep 0.5
    done
    PG_PORT=$(docker port "$PG_CID" 5432/tcp | head -1 | sed -E 's/.*:([0-9]+)$/\1/')
    env_args+=(
        "ANVILID_DATABASE_URL=postgres://anvilid:anvilid-local-only@127.0.0.1:$PG_PORT/anvilid"
        "ANVILID_KEK=$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
    )
fi

(cd "$TMP_DIR" && exec env "${env_args[@]}" "$BIN" serve \
    --data-dir "$TMP_DIR/data" \
    --listen "127.0.0.1:$PORT" \
    --public-url "$ANVIL_URL" \
    --breach-check off \
    --log-format pretty) >"$LOG" 2>&1 &
ANVIL_PID=$!
unset env_args

# 3. Setup URL.
SETUP_URL=""
for _ in $(seq 1 120); do
    SETUP_URL=$(sed -nE 's#.*Setup URL: (http[^ ]+/setup\?token=[A-Za-z0-9_-]+).*#\1#p' "$LOG" | head -1)
    [[ -n "$SETUP_URL" ]] && break
    kill -0 "$ANVIL_PID" 2>/dev/null || {
        echo "error: anvilid exited" >&2
        exit 1
    }
    sleep 0.5
done
[[ -n "$SETUP_URL" ]] || {
    echo "error: no 'Setup URL:' line in the anvilid log" >&2
    exit 1
}
wait_for "$ANVIL_URL/health/ready"

# 4. The suite. One worker: the specs share one installation and one single-use setup token.
ANVIL_URL="$ANVIL_URL" \
    MAILPIT_URL=http://127.0.0.1:8025 \
    SETUP_URL="$SETUP_URL" \
    E2E_STATE_FILE="$TMP_DIR/state.json" \
    npx --prefix tests/e2e playwright test --config tests/e2e/playwright.config.ts --workers=1 \
    "${SPECS[@]}"
echo "e2e ($BACKEND): passed"
