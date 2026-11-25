# One-command entry point. CI calls the same recipes so local runs and CI cannot drift.
# Recipes delegate to scripts owned by the plans that implement them; the names and
# arguments below are the contract.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Run the full local CI gate.
default: ci

# The single command contributors run (needs Docker for the Postgres tests).
ci: fmt-check lint deny deps test

# Check formatting.
fmt-check:
    cargo fmt --all --check

# Apply formatting.
fmt:
    cargo fmt --all

# Clippy on every crate and target, warnings are errors.
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Advisories, licenses, bans and sources.
deny:
    cargo deny --locked check

# Crate dependency rules (ARCHITECTURE.md §4).
deps:
    scripts/check-deps.sh

# Prove the dependency-rule checker rejects a violation.
deps-selftest:
    scripts/check-deps.sh --self-test

# All tests on both storage backends.
test:
    cargo test --workspace --locked

# Start the local development Postgres used for sqlx query checking (idempotent).
db-up:
    scripts/sqlx.sh db-up

# Regenerate the per-crate .sqlx/ offline query metadata.
sqlx-prepare:
    scripts/sqlx.sh prepare

# Verify the committed .sqlx/ metadata is up to date.
sqlx-check:
    scripts/sqlx.sh check

# Remove leftover testcontainers containers.
clean-test-containers:
    docker ps -aq --filter label=org.testcontainers=true | xargs -r docker rm -f

# Static musl release build for one target.
musl target="x86_64-unknown-linux-musl":
    scripts/build-musl.sh {{target}}

# Report binary size and idle RSS.
measure bin target:
    scripts/measure-idle.sh {{bin}} {{target}}

# Run the OpenID conformance suite against a local build.
conformance:
    tests/conformance/run.sh
