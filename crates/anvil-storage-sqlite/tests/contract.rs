//! Runs the shared storage contract suite against both SQLite variants.

mod support;

mod memory {
    anvil_storage::storage_contract_tests!(crate::support::sqlite_memory);
}

mod file {
    anvil_storage::storage_contract_tests!(crate::support::sqlite_file);
}
