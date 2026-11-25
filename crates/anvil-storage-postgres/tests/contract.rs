//! Runs the shared storage contract suite against Postgres 18 (testcontainers).
//!
//! Run with `cargo test`, not nextest: the container is shared per test binary.

mod support;

anvil_storage::storage_contract_tests!(crate::support::postgres);
