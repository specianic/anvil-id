//! Contract types of the rate limiter.

use std::net::IpAddr;
use std::time::Duration;

use anvil_core::model::{TenantId, UserId};

/// The route class a request belongs to. Each class has its own GCRA quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteClass {
    /// Interactive authentication endpoints (login, password, second factor).
    Auth,
    /// The token endpoint.
    Token,
    /// The admin API.
    Admin,
    /// Everything else.
    Default,
}

impl RouteClass {
    /// Every route class.
    pub const ALL: [RouteClass; 4] = [
        RouteClass::Auth,
        RouteClass::Token,
        RouteClass::Admin,
        RouteClass::Default,
    ];
}

/// What a limit is keyed on.
///
/// Identifiers are never stored in clear: callers pass the SHA-256 of the normalised
/// identifier, and the limiter never learns whether an account exists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LimitKey {
    /// A client IP address.
    Ip(IpAddr),
    /// An identifier alone (the loose brute-force tier).
    Identifier {
        /// The tenant the identifier belongs to.
        tenant: TenantId,
        /// SHA-256 of the normalised identifier.
        ident: [u8; 32],
    },
    /// An identifier from one IP (the strict brute-force tier).
    IdentIp {
        /// The tenant the identifier belongs to.
        tenant: TenantId,
        /// SHA-256 of the normalised identifier.
        ident: [u8; 32],
        /// The client IP address.
        ip: IpAddr,
    },
    /// An OAuth client (`client_id`).
    Client {
        /// The tenant the client belongs to.
        tenant: TenantId,
        /// The OAuth `client_id`.
        client_id: String,
    },
    /// A known user (second-factor attempts).
    User {
        /// The tenant the user belongs to.
        tenant: TenantId,
        /// The user.
        user: UserId,
    },
}

impl LimitKey {
    /// Whether this key is the loose (identifier-only) brute-force tier, which is counted in an
    /// hourly window but never locked progressively (locking it would let anyone lock an
    /// account out from any IP).
    pub fn is_loose_tier(&self) -> bool {
        matches!(self, LimitKey::Identifier { .. })
    }
}

/// The outcome of a limiter check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Proceed.
    Allow,
    /// Reject; the caller may retry after `retry_after`.
    Deny {
        /// How long until a retry can succeed.
        retry_after: Duration,
    },
    /// Proceed only after a solved CAPTCHA.
    RequireCaptcha,
}

/// The progressive-backoff state of a key after a recorded failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Consecutive failures recorded for the key (reset by success or inactivity).
    pub failures: u32,
    /// How long the key is now locked for, if at all.
    pub locked_for: Option<Duration>,
}
