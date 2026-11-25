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

# Regenerate the per-crate .sqlx/ offline query metadata (optionally one crate: crate=crates/<name>).
sqlx-prepare crate="":
    scripts/sqlx.sh prepare {{crate}}

# Verify the committed .sqlx/ metadata is up to date (optionally one crate: crate=crates/<name>).
sqlx-check crate="":
    scripts/sqlx.sh check {{crate}}

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

# --- Phase 2 gates (release 0.1). Not part of `ci` until plan 02-21 wires them in. ---

# Web and binary tests against Postgres (needs Docker).
test-pg:
    ANVILID_TEST_DB=postgres cargo test -p anvil-web -p anvilid --locked

# Playwright end-to-end suite against a local build (scripts owned by plan 02-20).
e2e backend="sqlite":
    tests/e2e/run.sh {{backend}}

# QUAL-04 zero-config first-login script (plan 02-20).
qual04 backend="sqlite":
    scripts/qual04.sh {{backend}}

# Build the container image and enforce the size gate (plan 02-20).
docker-image:
    scripts/docker-image.sh

# Short run of every fuzz target (plan 02-17).
fuzz-smoke:
    scripts/fuzz.sh smoke

# Run one fuzz target for a number of seconds (plan 02-17).
fuzz target seconds="300":
    scripts/fuzz.sh run {{target}} {{seconds}}

# Release dependency-graph checks (plan 02-17).
release-graph:
    scripts/check-release-graph.sh

# Every security control has a negative test (plan 02-21).
security-tests:
    scripts/check-security-tests.sh

# Regenerate the committed OpenAPI document (plan 02-16).
openapi-update:
    UPDATE_OPENAPI=1 cargo test -p anvil-web --test openapi_drift
