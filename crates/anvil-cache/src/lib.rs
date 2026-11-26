//! Cache and coordination layer (ARCHITECTURE.md §4).
//!
//! Provides the single keyed rate limiter ([`limiter`], ARCHITECTURE §11) with two backends behind
//! one trait: in-process (default) and Redis (shared across nodes).

pub mod limiter;
