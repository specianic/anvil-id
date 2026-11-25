#!/usr/bin/env bash
# sqlx tooling for the storage backends.
#
#   scripts/sqlx.sh db-up     start the local throwaway Postgres used for query checking
#   scripts/sqlx.sh prepare [crates/<storage-crate>]   regenerate .sqlx/ offline metadata
#   scripts/sqlx.sh check   [crates/<storage-crate>]   fail if .sqlx/ metadata is stale
#
# Without a crate argument every storage crate is processed. With one, only that crate is, so two
# plans can prepare different backends in parallel without touching each other's .sqlx/.
#
# Metadata is prepared per crate (never `--workspace`): each backend has its own sqlx.toml with
# its own DATABASE_URL variable and its own .sqlx/ directory, so identical SQL in two backends
# cannot collide.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORAGE_CRATES=(crates/anvil-storage-sqlite crates/anvil-storage-postgres)

PG_CONTAINER=anvil-dev-pg
PG_PORT=55432
# Local throwaway development database, bound to localhost only for compile-time query checks.
# This password is a fixed default for a disposable container, not a secret.
PG_PASSWORD=postgres
PG_DB=anvil_dev

usage() {
    echo "usage: $0 db-up | $0 {prepare|check} [crates/<storage-crate>]" >&2
}

require_sqlx_cli() {
    local version
    if ! version="$(sqlx --version 2>/dev/null)"; then
        echo "error: sqlx-cli not found. Install it with:" >&2
        echo "  cargo install sqlx-cli --version 0.9.1 --no-default-features --features rustls,sqlite,postgres,sqlx-toml" >&2
        exit 1
    fi
    if [[ ! "$version" =~ [[:space:]]0\.9\. ]]; then
        echo "error: sqlx-cli 0.9.x required, found: $version" >&2
        echo "  cargo install sqlx-cli --version 0.9.1 --no-default-features --features rustls,sqlite,postgres,sqlx-toml" >&2
        exit 1
    fi
}

db_up() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "error: docker is required to run the development Postgres" >&2
        exit 1
    fi
    local state
    state="$(docker inspect -f '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null || true)"
    case "$state" in
        true) ;;
        false) docker start "$PG_CONTAINER" >/dev/null ;;
        *)
            docker run -d --name "$PG_CONTAINER" \
                -p "127.0.0.1:${PG_PORT}:5432" \
                -e POSTGRES_PASSWORD="$PG_PASSWORD" \
                -e POSTGRES_DB="$PG_DB" \
                postgres:18-alpine >/dev/null
            ;;
    esac
    local i
    for i in $(seq 1 60); do
        if docker exec "$PG_CONTAINER" pg_isready -U postgres -d "$PG_DB" >/dev/null 2>&1; then
            echo "postgres ready on localhost:${PG_PORT} (container ${PG_CONTAINER})"
            return 0
        fi
        sleep 1
    done
    echo "error: postgres in container ${PG_CONTAINER} did not become ready" >&2
    exit 1
}

# select_crates [crate-filter]: print the storage crates to process, one per line.
select_crates() {
    local filter="${1:-}" crate
    if [[ -z "$filter" ]]; then
        printf '%s\n' "${STORAGE_CRATES[@]}"
        return 0
    fi
    filter="${filter%/}"
    for crate in "${STORAGE_CRATES[@]}"; do
        if [[ "$filter" == "$crate" || "$filter" == "${crate#crates/}" ]]; then
            echo "$crate"
            return 0
        fi
    done
    echo "error: unknown storage crate: $filter (expected one of: ${STORAGE_CRATES[*]})" >&2
    exit 2
}

# prepare_crates <crate-filter or ""> <extra cargo sqlx prepare args...>
prepare_crates() {
    local filter="$1"
    shift
    local selected
    selected="$(select_crates "$filter")"
    require_sqlx_cli
    mkdir -p "$ROOT/target/sqlx"
    export ANVIL_PG_DATABASE_URL="postgres://postgres:${PG_PASSWORD}@localhost:${PG_PORT}/${PG_DB}"
    export SQLX_OFFLINE=false
    # A global offline dir would override the per-crate .sqlx/ directories.
    unset SQLX_OFFLINE_DIR

    local processed=() crate
    for crate in $selected; do
        if [[ ! -f "$ROOT/$crate/sqlx.toml" ]]; then
            echo "skip: $crate (no sqlx.toml)"
            continue
        fi
        if [[ "$crate" == *postgres* ]]; then
            db_up
        fi
        echo "==> $crate"
        (
            cd "$ROOT/$crate"
            # One SQLite dev database per crate, so parallel runs never share a file.
            export ANVIL_SQLITE_DATABASE_URL="sqlite://$ROOT/target/sqlx/${crate#crates/}-dev.db?mode=rwc"
            sqlx migrate run
            cargo sqlx prepare "$@"
        )
        processed+=("$crate")
    done
    if [[ ${#processed[@]} -eq 0 ]]; then
        echo "error: no storage crate with a sqlx.toml found" >&2
        exit 1
    fi
    echo "processed: ${processed[*]}"
}

main() {
    if [[ $# -lt 1 || $# -gt 2 ]]; then
        usage
        exit 2
    fi
    case "$1" in
        db-up)
            if [[ $# -ne 1 ]]; then
                usage
                exit 2
            fi
            db_up
            ;;
        prepare) prepare_crates "${2:-}" ;;
        check) prepare_crates "${2:-}" --check ;;
        *)
            usage
            exit 2
            ;;
    esac
}

main "$@"
