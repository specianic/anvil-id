//! Upstream identity providers: presets, claim extraction and linking decisions (AUTH-07,
//! AUTH-11). Pure logic; outbound HTTP goes through `ports::UpstreamClient`.
//!
//! Pre-declared by plan 04-01; filled in by plan 04-07.

pub mod claims;
pub mod linking;
pub mod providers;
