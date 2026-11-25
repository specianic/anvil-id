//! Upstream identity providers: presets, ID-token validation, claim normalisation and linking
//! decisions (AUTH-07, AUTH-11).
//!
//! Pure logic only (research Pattern 5): the outbound adapter moves bytes through
//! `ports::UpstreamClient` and the upstream service orchestrates ports; every security property
//! (issuer rules, alg allow-list, audience, nonce, email trust, auto-link) lives here.
//!
//! - [`providers`] holds the presets, [`providers::resolve`], the authorization URL and the Apple
//!   client-secret claims.
//! - [`claims`] holds [`claims::validate_id_token`] and the `normalise_*` functions.
//! - [`linking`] holds [`linking::link_decision`].

pub mod claims;
pub mod linking;
pub mod providers;
