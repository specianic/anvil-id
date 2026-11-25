#!/usr/bin/env bash
# scripts/qual04.sh sqlite|postgres: the QUAL-04 timed check.
#
# From a zero-config start of the anvilid:ci container image to a completed login in the sample
# relying party (examples/node-rp), in at most 120 seconds:
#   1. sqlite:   docker run -p 8080:8080 anvilid:ci (no configuration at all)
#      postgres: docker compose -f deploy/compose/qual04-postgres.yml up (Postgres 18 + anvilid:ci,
#                with a random KEK generated here and passed only through the environment)
#   2. read the one-time `Setup URL:` from the container logs
#   3. Playwright (@qual04-setup): /setup, management credential, client created via the admin API
#   4. start examples/node-rp with that client
#   5. Playwright (@qual04-rp): register through the RP login, UserInfo, refresh with rotation
#   6. fail if the elapsed time exceeds 120 seconds
#
# Requires: the anvilid:ci image (`just docker-image`), Node.js, `npm ci` in tests/e2e and
# examples/node-rp, and Playwright's chromium. Uses host ports 8080 and 3000.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BACKEND=${1:-sqlite}
IMAGE=${ANVILID_IMAGE:-anvilid:ci}
LIMIT=120
COMPOSE_FILE="$ROOT/deploy/compose/qual04-postgres.yml"

case "$BACKEND" in
    sqlite | postgres) ;;
    *)
        echo "usage: $0 sqlite|postgres" >&2
        exit 2
        ;;
esac

docker image inspect "$IMAGE" >/dev/null 2>&1 || {
    echo "error: image $IMAGE not found; run 'just docker-image' first" >&2
    exit 1
}
for dir in tests/e2e examples/node-rp; do
    [[ -d "$dir/node_modules" ]] || {
        echo "error: $dir/node_modules missing; run 'npm ci --prefix $dir'" >&2
        exit 1
    }
done

TMP_DIR=$(mktemp -d)
chmod 700 "$TMP_DIR"
CLIENT_FILE="$TMP_DIR/client.json"
RP_LOG="$TMP_DIR/rp.log"
CID=""
RP_PID=""

logs() {
    if [[ "$BACKEND" == sqlite ]]; then
        docker logs "$CID" 2>&1
    else
        docker compose -f "$COMPOSE_FILE" logs --no-color anvilid 2>&1
    fi
}

cleanup() {
    local status=$?
    if [[ -n "$RP_PID" ]]; then
        kill "$RP_PID" 2>/dev/null || true
        wait "$RP_PID" 2>/dev/null || true
    fi
    if ((status != 0)); then
        echo "--- anvilid logs (setup token redacted) ---" >&2
        logs | sed -E 's/(token=)[A-Za-z0-9_-]+/\1<redacted>/g' | tail -50 >&2 || true
        [[ -f "$RP_LOG" ]] && { echo "--- sample RP log ---" >&2; tail -20 "$RP_LOG" >&2; }
    fi
    if [[ "$BACKEND" == sqlite ]]; then
        [[ -n "$CID" ]] && docker rm -f "$CID" >/dev/null 2>&1
    else
        docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1
    fi
    rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

# Leftovers from an interrupted run would reuse an installed database (no setup URL).
if [[ "$BACKEND" == postgres ]]; then
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
fi

start=$(date +%s)

# 1. Zero-config start.
if [[ "$BACKEND" == sqlite ]]; then
    CID=$(docker run -d -p 8080:8080 "$IMAGE")
else
    ANVILID_KEK=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    export ANVILID_KEK ANVILID_IMAGE="$IMAGE"
    docker compose -f "$COMPOSE_FILE" up -d --quiet-pull >/dev/null 2>&1 || {
        echo "error: docker compose up failed" >&2
        docker compose -f "$COMPOSE_FILE" up -d
        exit 1
    }
    unset ANVILID_KEK
fi

# 2. The setup URL from the logs.
SETUP_URL=""
for _ in $(seq 1 120); do
    SETUP_URL=$(logs | sed -nE 's#.*Setup URL: (http[^ ]+/setup\?token=[A-Za-z0-9_-]+).*#\1#p' | head -1)
    [[ -n "$SETUP_URL" ]] && break
    sleep 0.5
done
if [[ -z "$SETUP_URL" ]]; then
    echo "error: no 'Setup URL:' line in the logs" >&2
    exit 1
fi
for _ in $(seq 1 60); do
    curl -fsS http://localhost:8080/health/live >/dev/null 2>&1 && break
    sleep 0.5
done
echo "anvilid up after $(($(date +%s) - start))s; setup URL found in the logs"

export ANVIL_URL=http://localhost:8080
export RP_URL=http://localhost:3000
export QUAL04_CLIENT_FILE="$CLIENT_FILE"

# 3. Setup, management credential and the RP client.
SETUP_URL="$SETUP_URL" npx --prefix tests/e2e playwright test \
    --config tests/e2e/playwright.config.ts --grep @qual04-setup specs/qual04.spec.ts

# 4. The sample relying party with the created client (credentials stay in the environment).
CLIENT_ID=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).client_id)' "$CLIENT_FILE")
CLIENT_SECRET=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).client_secret)' "$CLIENT_FILE")
ISSUER="$ANVIL_URL" CLIENT_ID="$CLIENT_ID" CLIENT_SECRET="$CLIENT_SECRET" PORT=3000 \
    node examples/node-rp/server.js >"$RP_LOG" 2>&1 &
RP_PID=$!
unset CLIENT_SECRET
for _ in $(seq 1 60); do
    curl -fsS "$RP_URL/healthz" >/dev/null 2>&1 && break
    kill -0 "$RP_PID" 2>/dev/null || {
        echo "error: the sample RP exited" >&2
        exit 1
    }
    sleep 0.25
done

# 5. Login through the RP: registration, UserInfo, refresh with rotation.
npx --prefix tests/e2e playwright test \
    --config tests/e2e/playwright.config.ts --grep @qual04-rp specs/qual04.spec.ts

# 6. Time gate.
elapsed=$(($(date +%s) - start))
echo "QUAL-04 ($BACKEND): zero-config start to sample-app login in ${elapsed}s (limit ${LIMIT}s)"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "QUAL-04 ($BACKEND): zero-config start to sample-app login in ${elapsed}s (limit ${LIMIT}s)" >>"$GITHUB_STEP_SUMMARY"
fi
if ((elapsed > LIMIT)); then
    echo "error: QUAL-04 took ${elapsed}s, more than ${LIMIT}s" >&2
    exit 1
fi
