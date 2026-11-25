//! Self-service flows: the form contract (this module) and the flow engine (plan 02-09).

pub mod form;

pub mod engine;
pub mod login;
pub mod recovery;
pub mod registration;
pub mod setup;
pub mod verification;

// Phase 3 (pre-declared by plan 03-02; the owning plans fill them in)
pub mod consent;
pub mod settings;

// Phase 4 (pre-declared by plan 04-01; the owning plans fill them in)
pub mod email_code;
pub mod logout;
pub mod upstream;
