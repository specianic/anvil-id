//! Client lookup that materialises Client ID Metadata Document clients (AGT-02).
//!
//! [`ClientResolver::resolve`] is the only `client_id -> Client` entry point at the
//! authorization endpoint and in client authentication (token, revocation, introspection).
//! Every other call site keeps `ClientRepo::get`: a metadata document client is a normal client
//! row (`registration_source = cimd`) once materialised, so consent, token families, logout and
//! the console work unchanged.
//!
//! # Resolution
//!
//! A `client_id` that does not start with `https://` or `http://` is looked up with
//! `ClientRepo::get`. A URL client id is resolved as a metadata document only when all of these
//! hold, **checked before anything is fetched**:
//!
//! 1. a fetcher is configured (`metadata_fetcher` is `Some`);
//! 2. the tenant's effective CIMD policy is not `disabled` (the default; always disabled for the
//!    system tenant);
//! 3. the URL passes [`crate::oauth::cimd::check_url`] with the fetcher's
//!    [`ClientMetadataFetcher::allow_http_loopback`] flag (the development-mode outbound policy;
//!    never a tenant setting or request input), so production refuses every `http://` id;
//! 4. under `allow_listed`, the URL host is one of `allowed_hosts` (ASCII case-insensitive).
//!
//! Otherwise the URL is an ordinary client id: a static or dynamic client registered under it is
//! returned, a materialised CIMD row is **not** (disabling the policy stops CIMD clients at once).
//!
//! A registered (static or dynamic) client always wins over a document: it is returned as is and
//! nothing is fetched.
//!
//! # Cache
//!
//! A CIMD row is fresh while `metadata_expires_at > now`; a fresh row is returned without a fetch.
//! Otherwise the document is fetched (through the single SSRF-guarded outbound client in the
//! adapter: 5 KiB cap, no redirects, the outbound timeouts), validated by
//! [`crate::oauth::cimd::validate`] and upserted with `metadata_expires_at = now + ttl`, where `ttl` is
//! the response's `Cache-Control: max-age` clamped to `[min_cache_secs, max_cache_secs]` (no
//! header = `min_cache_secs`). Every upsert is audited as `cimd_client_refreshed`.
//!
//! Errors are never cached: nothing is written on failure, so the next request fetches again.
//! A **transient** failure (network, timeout, HTTP 429 or 5xx) keeps serving a row that is still
//! before its hard expiry (`metadata_expires_at + max_cache_secs`); without such a row it is
//! [`CoreError::ClientMetadataUnavailable`] (503 at the token endpoint, an error page at
//! `/authorize`). Every other failure (blocked destination, other status, oversized or invalid
//! document) is [`CoreError::InvalidClient`] with a fixed description.
//!
//! # Resources
//!
//! A materialised client may be granted the tenant's self-service resource list
//! (`dcr.allowed_resources`, shared by dynamic and metadata-document clients).

use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, CimdPolicy, CimdSettings, Client,
    ClientId, ClientSource, RequestContext, Tenant,
};
use crate::oauth::cimd::{self, CimdError, MAX_URL_LEN, ServerCaps};
use crate::ports::{ClientMetadataFetcher, Clock, MetadataFetchError, Storage, StorageError};
use crate::service::audit::AuditService;

/// Fixed description of a refused metadata document client (the document is third-party input
/// and is never echoed beyond the fixed [`CimdError`] text).
const DOCUMENT_REFUSED: &str = "the client metadata document was refused";

/// `true` if `client_id` has the shape of a metadata document URL (`https://` or `http://`
/// prefix, at most [`MAX_URL_LEN`] bytes). Says nothing about whether it will be resolved.
pub fn is_url_client_id(client_id: &str) -> bool {
    client_id.len() <= MAX_URL_LEN
        && (client_id.starts_with("https://") || client_id.starts_with("http://"))
}

/// The cache lifetime of a fetched document: `max_age` clamped to the tenant's bounds; no
/// `max-age` means the lower bound. A misconfigured `min > max` resolves to `max`.
pub fn cache_ttl(max_age: Option<u32>, settings: &CimdSettings) -> Duration {
    let min = settings.min_cache_secs.min(settings.max_cache_secs);
    let max = settings.max_cache_secs;
    let secs = max_age.unwrap_or(min).clamp(min, max);
    Duration::seconds(i64::from(secs))
}

/// Until when a stale row may still be served after a transient fetch failure.
pub fn hard_expiry(metadata_expires_at: OffsetDateTime, settings: &CimdSettings) -> OffsetDateTime {
    metadata_expires_at + Duration::seconds(i64::from(settings.max_cache_secs))
}

/// Whether a fetch failure is transient (worth serving a still-valid row and retrying later).
pub fn is_transient(err: &MetadataFetchError) -> bool {
    match err {
        MetadataFetchError::Network | MetadataFetchError::Timeout => true,
        MetadataFetchError::Status(code) => *code == 429 || *code >= 500,
        MetadataFetchError::Blocked
        | MetadataFetchError::TooLarge
        | MetadataFetchError::InvalidResponse(_) => false,
    }
}

/// The service-boundary mapping of a URL or document refusal: `invalid_client` with the fixed
/// [`CimdError`] text.
pub fn cimd_error(err: &CimdError) -> CoreError {
    CoreError::InvalidClient {
        reason: format!("{DOCUMENT_REFUSED}: {err}"),
        basic_auth_used: false,
    }
}

/// The service-boundary mapping of a fetch failure: transient failures are
/// [`CoreError::ClientMetadataUnavailable`], the others `invalid_client`.
pub fn fetch_error(err: &MetadataFetchError) -> CoreError {
    if is_transient(err) {
        CoreError::ClientMetadataUnavailable(err.to_string())
    } else {
        CoreError::InvalidClient {
            reason: format!("{DOCUMENT_REFUSED}: {err}"),
            basic_auth_used: false,
        }
    }
}

/// `true` if `url`'s host is in `allowed_hosts` (ASCII case-insensitive, port ignored).
pub fn host_allowed(url: &str, allowed_hosts: &[String]) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    allowed_hosts
        .iter()
        .any(|allowed| allowed.trim().eq_ignore_ascii_case(host))
}

/// Resolves `client_id`s to clients, materialising metadata document clients (module docs).
#[derive(Clone)]
pub struct ClientResolver {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// `None`: URL client ids are never fetched and materialised CIMD rows are not served.
    pub fetcher: Option<Arc<dyn ClientMetadataFetcher>>,
}

impl ClientResolver {
    /// The client `client_id` of `tenant` at `now`, or `None` if it is unknown (or a URL that
    /// may not be resolved). Errors only for a refused document (`invalid_client`), a transient
    /// fetch failure without a usable row (`ClientMetadataUnavailable`) or storage failures.
    pub async fn resolve(
        &self,
        tenant: &Tenant,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Client>, CoreError> {
        let row = self.storage.clients().get(tenant.id, client_id).await?;
        if !is_url_client_id(client_id) {
            return Ok(row);
        }
        // A registered client under a URL id wins over any document.
        if let Some(c) = &row
            && c.registration_source != ClientSource::Cimd
        {
            return Ok(row);
        }
        let settings = tenant.effective_cimd();
        let Some(fetcher) = self.fetcher.as_ref() else {
            return Ok(None);
        };
        if settings.policy == CimdPolicy::Disabled {
            return Ok(None);
        }
        let allow_http_loopback = fetcher.allow_http_loopback();
        if cimd::check_url(client_id, allow_http_loopback).is_err() {
            return Ok(None);
        }
        if settings.policy == CimdPolicy::AllowListed
            && !host_allowed(client_id, &settings.allowed_hosts)
        {
            return Ok(None);
        }

        // Fresh row: no fetch.
        if let Some(c) = &row
            && c.metadata_expires_at.is_some_and(|exp| exp > now)
        {
            return Ok(row);
        }

        let fetched = match fetcher.fetch(client_id).await {
            Ok(f) => f,
            Err(err) => {
                if is_transient(&err)
                    && let Some(c) = &row
                    && c.metadata_expires_at
                        .is_some_and(|exp| hard_expiry(exp, &settings) > now)
                {
                    return Ok(row);
                }
                return Err(fetch_error(&err));
            }
        };
        let metadata = cimd::validate(
            client_id,
            &fetched.body,
            &ServerCaps::default(),
            allow_http_loopback,
        )
        .map_err(|e| cimd_error(&e))?;
        let expires_at = now + cache_ttl(fetched.max_age_secs, &settings);
        let new_client = metadata.to_new_client(
            ClientId::new_v7(),
            now,
            expires_at,
            tenant.settings.dcr.allowed_resources.clone(),
        );
        let client = match self
            .storage
            .clients()
            .upsert_cimd(tenant.id, &new_client, expires_at, now)
            .await
        {
            Ok(c) => c,
            // A client was registered under this id meanwhile: it wins.
            Err(StorageError::Conflict(_)) => {
                return Ok(self
                    .storage
                    .clients()
                    .get(tenant.id, client_id)
                    .await?
                    .filter(|c| c.registration_source != ClientSource::Cimd));
            }
            Err(e) => return Err(e.into()),
        };
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            tenant.id,
            AuditActor::client(&client.client_id),
            AuditAction::CimdClientRefreshed,
            Some(client.client_id.clone()),
            AuditOutcome::Success,
            &RequestContext::default(),
            AuditDetails::client_source(ClientSource::Cimd),
        )
        .await?;
        Ok(Some(client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(min: u32, max: u32) -> CimdSettings {
        CimdSettings {
            min_cache_secs: min,
            max_cache_secs: max,
            ..CimdSettings::default()
        }
    }

    #[test]
    fn ttl_clamps_max_age_to_the_tenant_bounds() {
        let s = settings(300, 86_400);
        assert_eq!(cache_ttl(Some(10), &s), Duration::seconds(300));
        assert_eq!(cache_ttl(Some(604_800), &s), Duration::seconds(86_400));
        assert_eq!(cache_ttl(Some(3600), &s), Duration::seconds(3600));
        assert_eq!(cache_ttl(None, &s), Duration::seconds(300));
        assert_eq!(cache_ttl(Some(0), &s), Duration::seconds(300));
        // min > max never yields more than max.
        assert_eq!(cache_ttl(None, &settings(900, 600)), Duration::seconds(600));
    }

    #[test]
    fn hard_expiry_adds_the_upper_bound() {
        let exp = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(
            hard_expiry(exp, &settings(300, 86_400)),
            exp + Duration::days(1)
        );
    }

    #[test]
    fn transient_failures_are_network_timeout_429_and_5xx() {
        for e in [
            MetadataFetchError::Network,
            MetadataFetchError::Timeout,
            MetadataFetchError::Status(429),
            MetadataFetchError::Status(500),
            MetadataFetchError::Status(503),
        ] {
            assert!(is_transient(&e), "{e:?}");
            assert!(matches!(
                fetch_error(&e),
                CoreError::ClientMetadataUnavailable(_)
            ));
        }
        for e in [
            MetadataFetchError::Blocked,
            MetadataFetchError::TooLarge,
            MetadataFetchError::InvalidResponse("not json"),
            MetadataFetchError::Status(301),
            MetadataFetchError::Status(404),
        ] {
            assert!(!is_transient(&e), "{e:?}");
            assert!(matches!(
                fetch_error(&e),
                CoreError::InvalidClient {
                    basic_auth_used: false,
                    ..
                }
            ));
        }
    }

    #[test]
    fn cimd_errors_map_to_invalid_client_with_fixed_text() {
        for e in [
            CimdError::InvalidUrl("must use https"),
            CimdError::InvalidDocument("client_id does not equal the document URL".into()),
            CimdError::TooLarge,
        ] {
            match cimd_error(&e) {
                CoreError::InvalidClient {
                    reason,
                    basic_auth_used,
                } => {
                    assert!(!basic_auth_used);
                    assert!(reason.starts_with(DOCUMENT_REFUSED), "{reason}");
                }
                other => panic!("expected invalid_client, got {other:?}"),
            }
        }
    }

    #[test]
    fn url_client_ids_are_recognised_by_prefix_and_length() {
        assert!(is_url_client_id("https://app.example/client.json"));
        assert!(is_url_client_id("http://127.0.0.1:8080/c"));
        assert!(!is_url_client_id("rp"));
        assert!(!is_url_client_id("HTTPS://app.example/c"));
        assert!(!is_url_client_id("urn:example:client"));
        let long = format!("https://app.example/{}", "a".repeat(MAX_URL_LEN));
        assert!(!is_url_client_id(&long));
    }

    #[test]
    fn allow_list_matches_the_host_only() {
        let hosts = vec!["App.Example".to_owned(), "127.0.0.1".to_owned()];
        assert!(host_allowed("https://app.example/c.json", &hosts));
        assert!(host_allowed("https://APP.example:8443/c.json", &hosts));
        assert!(host_allowed("http://127.0.0.1:9999/c", &hosts));
        assert!(!host_allowed("https://evil.example/c.json", &hosts));
        assert!(!host_allowed("https://app.example.evil/c.json", &hosts));
        assert!(!host_allowed("https://sub.app.example/c.json", &hosts));
        assert!(!host_allowed("not a url", &hosts));
        assert!(!host_allowed("https://app.example/c.json", &[]));
    }
}
