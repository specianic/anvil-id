//! OAuth / OIDC request parsing and decisions (plan 02-07).

pub mod authorize_request;
pub mod claims_request;
pub mod decision;
pub mod redirect;

// Phase 3 (pre-declared by plan 03-02; the owning plan fills it in)
pub mod response_mode;
