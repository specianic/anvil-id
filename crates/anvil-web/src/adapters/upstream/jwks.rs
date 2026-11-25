//! Upstream JWK Sets with a per-URI cache and a throttled forced refresh.
//!
//! - An entry lives for the response's `Cache-Control: max-age`, clamped to
//!   [[`MIN_TTL`], [`MAX_TTL`]] ([`DEFAULT_TTL`] when absent; `no-store` / `no-cache` count as
//!   the minimum).
//! - `force_refresh` (an ID token with an unknown `kid`) refetches at most once per
//!   [`REFRESH_THROTTLE`] per URI; a throttled request returns the cached set (or fetches when
//!   nothing is cached), so a flood of tokens with random `kid`s cannot turn into a flood of
//!   upstream requests.
//! - Fail closed: a failed fetch is an error, never a stale or empty set. A document that is not
//!   a JWK Set, or carries private key members (`d`, `p`, `k`, ...), is rejected.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anvil_core::ports::UpstreamError;
use anvil_jose::Jwks;
use moka::Expiry;
use moka::sync::Cache;
use reqwest::header::{ACCEPT, CACHE_CONTROL, HeaderValue};

use crate::adapters::outbound::{LIMIT_DOCUMENT, OutboundClient, read_capped};

/// Lower bound of the cache lifetime.
pub const MIN_TTL: Duration = Duration::from_secs(300);
/// Upper bound of the cache lifetime.
pub const MAX_TTL: Duration = Duration::from_secs(86_400);
/// Lifetime when the response has no usable `max-age`.
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);
/// At most one forced refresh per URI within this window.
pub const REFRESH_THROTTLE: Duration = Duration::from_secs(60);
const MAX_ENTRIES: u64 = 10_000;

/// The cache lifetime for a response with this `Cache-Control` value.
pub fn ttl_from_cache_control(value: Option<&str>) -> Duration {
    let Some(value) = value else {
        return DEFAULT_TTL;
    };
    let mut max_age = None;
    for directive in value.split(',') {
        let directive = directive.trim();
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return MIN_TTL;
        }
        if let Some(v) = lower.strip_prefix("max-age=") {
            match v.trim_matches('"').parse::<u64>() {
                Ok(secs) => max_age = Some(Duration::from_secs(secs)),
                // An unparsable (e.g. overflowing) value: fall back to the default.
                Err(_) => return DEFAULT_TTL,
            }
        }
    }
    max_age.map_or(DEFAULT_TTL, |ttl| ttl.clamp(MIN_TTL, MAX_TTL))
}

#[derive(Clone)]
struct Entry {
    jwks: Arc<Jwks>,
    ttl: Duration,
}

struct PerEntryTtl;

impl Expiry<String, Entry> for PerEntryTtl {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Entry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &Entry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// JWK Sets keyed by URI, plus the forced-refresh throttle.
#[derive(Clone)]
pub struct JwksCache {
    sets: Cache<String, Entry>,
    forced: Cache<String, ()>,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            sets: Cache::builder()
                .max_capacity(MAX_ENTRIES)
                .expire_after(PerEntryTtl)
                .build(),
            forced: Cache::builder()
                .max_capacity(MAX_ENTRIES)
                .time_to_live(REFRESH_THROTTLE)
                .build(),
        }
    }

    /// The JWK Set at `uri`; see the module docs for caching and `force_refresh`.
    pub async fn get(
        &self,
        outbound: &OutboundClient,
        uri: &str,
        force_refresh: bool,
    ) -> Result<Arc<Jwks>, UpstreamError> {
        let cached = self.sets.get(uri);
        let refetch = match (&cached, force_refresh) {
            (None, _) => true,
            (Some(_), false) => false,
            // Atomic: only the first forced request within the window wins.
            (Some(_), true) => self.forced.entry_by_ref(uri).or_insert(()).is_fresh(),
        };
        if !refetch && let Some(entry) = cached {
            return Ok(entry.jwks);
        }
        let entry = fetch(outbound, uri).await?;
        let jwks = Arc::clone(&entry.jwks);
        self.sets.insert(uri.to_owned(), entry);
        Ok(jwks)
    }
}

async fn fetch(outbound: &OutboundClient, uri: &str) -> Result<Entry, UpstreamError> {
    tracing::debug!(host = %super::log_host(uri), "fetching upstream JWKS");
    let resp = outbound
        .get(uri)?
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .send()
        .await?;
    let ttl = ttl_from_cache_control(
        resp.headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
    );
    let body = read_capped(resp, LIMIT_DOCUMENT).await?;
    let text =
        std::str::from_utf8(&body).map_err(|_| UpstreamError::InvalidResponse("malformed JWKS"))?;
    let jwks = Jwks::parse(text).map_err(|_| UpstreamError::InvalidResponse("malformed JWKS"))?;
    Ok(Entry {
        jwks: Arc::new(jwks),
        ttl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_is_clamped_and_defaulted() {
        let s = Duration::from_secs;
        assert_eq!(ttl_from_cache_control(None), DEFAULT_TTL);
        assert_eq!(ttl_from_cache_control(Some("public")), DEFAULT_TTL);
        assert_eq!(ttl_from_cache_control(Some("max-age=1")), MIN_TTL);
        assert_eq!(ttl_from_cache_control(Some("max-age=0")), MIN_TTL);
        assert_eq!(
            ttl_from_cache_control(Some("public, max-age=7200, must-revalidate")),
            s(7200)
        );
        assert_eq!(ttl_from_cache_control(Some("MAX-AGE=999999")), MAX_TTL);
        assert_eq!(ttl_from_cache_control(Some("no-store")), MIN_TTL);
        assert_eq!(ttl_from_cache_control(Some("max-age=abc")), DEFAULT_TTL);
        assert_eq!(
            ttl_from_cache_control(Some("max-age=99999999999999999999999")),
            DEFAULT_TTL
        );
    }
}
