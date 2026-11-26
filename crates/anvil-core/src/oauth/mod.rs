//! OAuth / OIDC request parsing and decisions (plan 02-07).

pub mod authorize_request;
pub mod claims_request;
pub mod decision;
pub mod redirect;

// Phase 3 (pre-declared by plan 03-02; the owning plan fills it in)
pub mod response_mode;

// Phase 4 (pre-declared by plan 04-01; the owning plans fill them in)
pub mod logout;
pub mod resource;

// Phase 5 (pre-declared by plan 05-02; the owning plans fill them in)
pub mod cimd;
pub mod registration;
