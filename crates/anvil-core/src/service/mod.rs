//! Application services orchestrating the ports.

// Plan 02-07
pub mod authorize;

// Plan 02-08
pub mod claims;
pub mod client_auth;
pub mod key;
pub mod token;
pub mod userinfo;

// Plan 02-09
pub mod flow;
pub mod session;

// Plan 02-10
pub mod admin_scope;
pub mod bootstrap;
pub mod client;
pub mod tenant;
pub mod user;

// Phase 3 (pre-declared by plan 03-02; the owning plans fill them in)
pub mod account;
pub mod audit;
pub mod consent;
pub mod introspect;
pub mod key_rotation;
pub mod mail_settings;
pub mod revoke;

// Phase 4 (pre-declared by plan 04-01; the owning plans fill them in)
pub mod branding;
pub mod connection;
pub mod logout;
pub mod upstream;

// Phase 5 (pre-declared by plan 05-02; the owning plans fill them in)
pub mod admin_recovery;
pub mod attribute;
pub mod client_resolver;
pub mod config;
pub mod registration;
pub mod role;
pub mod webhook;

// Phase 6 (pre-declared by plan 06-04; the owning plans fill them in)
pub mod domain_check;
pub mod domain_recheck;
pub mod org_domain;
pub mod org_invitation;
pub mod organization;
pub mod saml;
