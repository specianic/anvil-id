//! Client ID Metadata Document fetcher on the SSRF-guarded outbound client
//! (`ports::ClientMetadataFetcher`, AGT-02).
//!
//! [`OutboundMetadataFetcher`] GETs a client id URL through the single [`OutboundClient`]: its
//! destination policy (private and loopback addresses blocked unless allow-listed, plain http only
//! in development mode and only to allow-listed destinations), no redirects (a 3xx is a status
//! error), no proxies and the outbound timeouts all apply unchanged. On top of that:
//!
//! - `Accept: application/json`, status **200** required, body capped at
//!   [`MAX_DOCUMENT_BYTES`] (5 KiB) while streaming;
//! - `Cache-Control: max-age` is reported to the resolver, which clamps it to the tenant bounds;
//! - **per-host budget:** one request of the one rate limiter's `auth` class per fetch, keyed
//!   `LimitKey::Identifier` on the SHA-256 of `cimd-host:<host>`. Fetches are triggered by
//!   unauthenticated requests and the port carries no tenant, so the budget is per destination
//!   host across the installation (it protects the third-party host whichever tenant asks); the
//!   key's tenant is the nil id, which no tenant has (tenant ids are UUIDv7). An exhausted budget
//!   is reported as status 429, a transient failure;
//! - **concurrency cap:** at most `CIMD_FETCH_PERMITS` fetches in flight
//!   ([`AppState::cimd_fetch_permits`]); waiting longer than the outbound total timeout for a
//!   permit is a timeout.
//!
//! [`ClientMetadataFetcher::allow_http_loopback`] is the installation's development-mode outbound
//! policy (`AppConfig.outbound.allow_http`, set from `dev_mode()` at startup), so production
//! refuses every http client id before any fetch.

use std::sync::Arc;

use anvil_cache::limiter::{Decision, LimitKey, RouteClass};
use anvil_core::model::{FetchedMetadata, TenantId};
use anvil_core::oauth::cimd::MAX_DOCUMENT_BYTES;
use anvil_core::ports::{ClientMetadataFetcher, MetadataFetchError};
use reqwest::header::{ACCEPT, CACHE_CONTROL, HeaderValue};

use crate::adapters::outbound::{OutboundError, TOTAL_TIMEOUT, read_capped};
use crate::layers::ratelimit::identifier_hash;
use crate::state::AppState;

/// The metadata document fetcher of the application (module docs).
#[derive(Clone)]
pub struct OutboundMetadataFetcher {
    state: AppState,
}

impl std::fmt::Debug for OutboundMetadataFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundMetadataFetcher")
            .finish_non_exhaustive()
    }
}

impl OutboundMetadataFetcher {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

/// The limiter key of fetches to `host` (module docs).
pub fn host_limit_key(host: &str) -> LimitKey {
    LimitKey::Identifier {
        tenant: TenantId(uuid::Uuid::nil()),
        ident: identifier_hash(&format!("cimd-host:{host}")),
    }
}

/// The `max-age` directive of a `Cache-Control` value, if any. `no-store` / `no-cache` count as
/// none (the resolver then applies the tenant's minimum). Values beyond `u32` saturate.
pub fn max_age(cache_control: &str) -> Option<u32> {
    let mut found = None;
    for directive in cache_control.split(',') {
        let directive = directive.trim();
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return None;
        }
        if let Some(value) = lower.strip_prefix("max-age=") {
            let value = value.trim_matches('"');
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            found = Some(value.parse::<u32>().unwrap_or(u32::MAX));
        }
    }
    found
}

fn map_outbound(err: OutboundError) -> MetadataFetchError {
    match err {
        OutboundError::Blocked | OutboundError::InvalidUrl => MetadataFetchError::Blocked,
        OutboundError::Network => MetadataFetchError::Network,
        OutboundError::Timeout => MetadataFetchError::Timeout,
        OutboundError::Status(code) => MetadataFetchError::Status(code),
        OutboundError::TooLarge => MetadataFetchError::TooLarge,
    }
}

#[async_trait::async_trait]
impl ClientMetadataFetcher for OutboundMetadataFetcher {
    async fn fetch(&self, url: &str) -> Result<FetchedMetadata, MetadataFetchError> {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .ok_or(MetadataFetchError::Blocked)?;
        // Build (and so check) the request before spending any budget.
        let request = self
            .state
            .outbound()
            .get(url)
            .map_err(map_outbound)?
            .header(ACCEPT, HeaderValue::from_static("application/json"));

        if let Decision::Deny { .. } = self
            .state
            .limiter()
            .check(RouteClass::Auth, &host_limit_key(&host))
            .await
        {
            return Err(MetadataFetchError::Status(429));
        }
        let permits = self.state.cimd_fetch_permits();
        let _permit = tokio::time::timeout(TOTAL_TIMEOUT, permits.acquire_owned())
            .await
            .map_err(|_| MetadataFetchError::Timeout)?
            .map_err(|_| MetadataFetchError::Network)?;

        let resp = request.send().await.map_err(map_outbound)?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(MetadataFetchError::Status(status));
        }
        let max_age_secs = resp
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .and_then(max_age);
        let body = read_capped(resp, MAX_DOCUMENT_BYTES)
            .await
            .map_err(map_outbound)?;
        Ok(FetchedMetadata { body, max_age_secs })
    }

    fn allow_http_loopback(&self) -> bool {
        self.state.config().outbound.allow_http
    }
}

impl AppState {
    /// The metadata document fetcher handed to the authorize, token and client-authentication
    /// services: [`OutboundMetadataFetcher`] on this state's outbound client, limiter and fetch
    /// permits. Whether a URL client id is fetched at all is the tenant's CIMD policy
    /// (`service::client_resolver`).
    pub(crate) fn cimd_fetcher(&self) -> Option<Arc<dyn ClientMetadataFetcher>> {
        Some(Arc::new(OutboundMetadataFetcher::new(self.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_age_is_parsed_from_cache_control() {
        assert_eq!(max_age("max-age=600"), Some(600));
        assert_eq!(max_age("public, Max-Age=3600"), Some(3600));
        assert_eq!(max_age("max-age=\"120\""), Some(120));
        assert_eq!(max_age("max-age=99999999999"), Some(u32::MAX));
        assert_eq!(max_age("public"), None);
        assert_eq!(max_age(""), None);
        assert_eq!(max_age("max-age="), None);
        assert_eq!(max_age("max-age=-5"), None);
        assert_eq!(max_age("max-age=1e3"), None);
        assert_eq!(max_age("no-store, max-age=600"), None);
        assert_eq!(max_age("max-age=600, no-cache"), None);
    }

    #[test]
    fn host_keys_differ_per_host_and_ignore_case() {
        assert_eq!(host_limit_key("app.example"), host_limit_key("APP.example"));
        assert_ne!(
            host_limit_key("app.example"),
            host_limit_key("other.example")
        );
        assert!(host_limit_key("app.example").is_loose_tier());
    }

    #[test]
    fn outbound_errors_map_to_fetch_errors() {
        assert_eq!(
            map_outbound(OutboundError::InvalidUrl),
            MetadataFetchError::Blocked
        );
        assert_eq!(
            map_outbound(OutboundError::Blocked),
            MetadataFetchError::Blocked
        );
        assert_eq!(
            map_outbound(OutboundError::Status(302)),
            MetadataFetchError::Status(302)
        );
        assert_eq!(
            map_outbound(OutboundError::TooLarge),
            MetadataFetchError::TooLarge
        );
    }
}
