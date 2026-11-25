//! Back-channel logout delivery (OIDC Back-Channel Logout 1.0, OIDC-12): logout tokens POSTed to
//! each RP's `backchannel_logout_uri` by a leased background job with retries, through the single
//! SSRF-guarded [`crate::adapters::outbound::OutboundClient`], woken by
//! [`crate::state::AppState::logout_wake`]. Owner: plan 04-17.
//!
//! Registered ahead of time so the owning plan edits only this file.
