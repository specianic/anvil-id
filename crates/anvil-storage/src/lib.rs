//! Shared storage contract suite and backend-agnostic helpers.
//!
//! The storage port traits themselves live in `anvil_core::ports`. This crate re-exports nothing
//! from `anvil-core`.
//!
//! The contract suite (module [`contract`], feature `contract`) is the single list of behaviours
//! every storage backend must satisfy. Backends enable the feature only as a dev-dependency, so it
//! is never compiled into normal builds.

#[cfg(feature = "contract")]
pub mod contract;

#[cfg(feature = "postgres-container")]
pub mod postgres_container;
