# Deferred items (07.1)

- 07.1-19: `cargo fmt --manifest-path fuzz/Cargo.toml --check` reports a formatting diff in
  `fuzz/fuzz_targets/client_assertion.rs` (lines ~213-227). Pre-existing; the fuzz crate is outside
  the workspace, so `just fmt-check` does not cover it. Not fixed in the gate.
