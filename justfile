# One-command entry point. CI calls the same recipes so local runs and CI cannot drift.
# Recipes delegate to scripts owned by the plans that implement them; the names and
# arguments below are the contract.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Run the full local CI gate.
default: ci

# The single command contributors run (needs Docker for the Postgres tests and Node >= 22.12 for
# the console check).
ci: fmt-check lint deny deps migrations-check test test-pg release-graph security-tests console-check

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
    docker ps -aq --filter label=org.testcontainers.managed-by=testcontainers | xargs -r docker rm -f

# Static musl release build for one target.
musl target="x86_64-unknown-linux-musl":
    scripts/build-musl.sh {{target}}

# Report binary size and idle RSS.
measure bin target:
    scripts/measure-idle.sh {{bin}} {{target}}

# Run the OpenID conformance suite against a local build.
conformance:
    tests/conformance/run.sh

# --- Phase 2 gates (release 0.1). test-pg, release-graph and security-tests run in `ci`; the rest
# need Docker images, Node or nightly and run in their own CI workflows. ---

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

# Prove the security-test map detects a missing test.
security-tests-selftest:
    scripts/check-security-tests.sh --self-test

# Released migrations unchanged (sha256 manifest) and no unmarked destructive SQL (plan 03-16),
# then the checker's self-test.
migrations-check:
    scripts/check-migrations.sh
    scripts/check-migrations.sh --self-test

# Regenerate the committed OpenAPI document (plan 02-16).
openapi-update:
    UPDATE_OPENAPI=1 cargo test -p anvil-web --test openapi_drift

# --- Admin console (admin-ui/, Node >= 22.12). console-check runs in `ci`; CI runs the same steps
# plus the build in the `console` job. Release builds embed the console and fail without it
# (scripts/check-console-embedded.sh). ---

# Install locked dependencies and build the console into admin-ui/dist (with .br/.gz sidecars).
console-build:
    cd admin-ui && npm ci && npm run build

# Check the generated API types against docs/openapi/admin-v1.json, then type-check the console.
console-check:
    cd admin-ui && npm ci && npm run check:api && npm run typecheck
