//! Domain model, ports and protocol logic; no I/O.
//!
//! - [`model`]: identifiers and domain records.
//! - [`ports`]: storage and service traits implemented outside the core.
//! - [`error`]: [`error::CoreError`] and its single OAuth mapping.
//! - [`clock`], [`policy`]: time source and password policy.
//! - [`oauth`], [`service`], [`flow`]: protocol logic, services and self-service flows.
//! - [`upstream`]: upstream identity-provider presets, claims and linking decisions.

pub mod clock;
pub mod error;
pub mod flow;
pub mod model;
pub mod oauth;
pub mod policy;
pub mod ports;
pub mod saml;
pub mod service;
pub mod upstream;
