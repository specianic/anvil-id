//! The limiter contract suite (`src/limiter/contract.rs`) against every backend.
//!
//! - `in_process::*` runs on every `cargo test`.

#[path = "../src/limiter/contract.rs"]
mod contract;

use std::sync::Arc;

use anvil_cache::limiter::{InProcessLimiter, LimiterConfig};

use contract::{FakeClock, TestLimiter, limiter_contract_tests};

async fn in_process_limiter(config: LimiterConfig, clock: Arc<FakeClock>) -> TestLimiter {
    TestLimiter {
        limiter: Arc::new(InProcessLimiter::new(config, clock)),
        _guard: Box::new(()),
    }
}

limiter_contract_tests!(in_process, crate::in_process_limiter);
