//! Pushed authorization requests (RFC 9126, OIDC-18): `ParService` authenticates the client
//! through the token endpoint's client authentication (`ClientAuthService`, implemented by
//! [`ClientAuthenticator`]: the secret methods, `private_key_jwt` with the shared jti replay
//! store, `none` for public clients), validates the pushed parameters with the same
//! [`crate::oauth::authorize_request::validate`] as `/authorize`, stores them under the SHA-256 of
//! a fresh `request_uri`, and consumes them once.
//!
//! Push rules (RFC 9126 §2):
//! - every error is a JSON error ([`CoreError`], mapped by the web layer), never a redirect and
//!   never an interaction error (`login_required`, `consent_required`, ...: no session is looked
//!   at here);
//! - a `request_uri` inside the pushed body is `invalid_request`; `request` (JAR) is
//!   `request_not_supported`;
//! - `id_token_hint` is `invalid_request`: the stored parameters are the validated
//!   `AuthorizationParams`, which do not carry it, and silently dropping a hint would change
//!   the meaning of `prompt=none`;
//! - the pushed redirect URI must match a registered one exactly (no RFC 9126 §2.4 relaxation).
//!
//! Consumption ([`ParService::consume`]) is one atomic storage operation
//! (`GrantRepo::consume_pushed_request`), so exactly one caller wins; the `client_id` presented at
//! the authorization endpoint must equal the client that pushed. The authorization endpoint goes
//! through [`crate::service::authorize::AuthorizeService::resume_pushed_request`], the single
//! resume path.

use std::sync::Arc;

use anvil_jose::encoding::random_bytes;

use crate::error::CoreError;
use crate::model::{AuthorizationParams, NewPushedRequest, Tenant};
use crate::oauth::authorize_request::{RawParams, validate};
use crate::oauth::par::{LIFETIME, new_request_uri, parse_request_uri, push_error};
use crate::ports::{ClientMetadataFetcher, Clock, Storage};
use crate::service::client_auth::{ClientAuthInput, ClientAuthenticator};

/// The PAR endpoint's success response (RFC 9126 §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedAuthorization {
    /// `urn:ietf:params:oauth:request_uri:<43 base64url chars>`; returned once, never stored.
    pub request_uri: String,
    /// Seconds until the request expires.
    pub expires_in: i64,
}

/// Why a pushed request cannot be used at the authorization endpoint. Every case is an error
/// page: there is no trusted redirect URI yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushedRequestRefused {
    /// Not a well-formed `request_uri`, unknown, expired or already used.
    Unusable,
    /// The `client_id` presented at the authorization endpoint is not the client that pushed.
    ClientMismatch,
}

/// Pushed authorization request service.
pub struct ParService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// Client ID Metadata Document fetcher (`None` = URL client ids are not resolved).
    pub metadata_fetcher: Option<Arc<dyn ClientMetadataFetcher>>,
}

impl ParService {
    fn authenticator(&self) -> ClientAuthenticator {
        ClientAuthenticator {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
            metadata_fetcher: self.metadata_fetcher.clone(),
        }
    }

    /// Handles a push: `auth` are the client credentials (the `Authorization` header and the
    /// credential parameters of the body), `raw` the authorization request parameters of the
    /// body (credential parameters removed by the caller).
    pub async fn push(
        &self,
        tenant: &Tenant,
        issuer: &str,
        auth: &ClientAuthInput,
        mut raw: RawParams,
    ) -> Result<PushedAuthorization, CoreError> {
        // Authenticate first, so an unauthenticated caller learns nothing about the parameters.
        let client = self
            .authenticator()
            .authenticate(tenant, issuer, auth)
            .await?;

        if raw.0.iter().any(|(k, _)| k == "request_uri") {
            return Err(CoreError::InvalidRequest(
                "request_uri must not be pushed".to_owned(),
            ));
        }
        if raw.0.iter().any(|(k, _)| k == "request") {
            return Err(CoreError::RequestNotSupported);
        }
        if raw.get("id_token_hint").is_some() {
            return Err(CoreError::InvalidRequest(
                "id_token_hint is not supported with pushed authorization requests".to_owned(),
            ));
        }
        // The authenticated client is the request's client (RFC 9126 §2.1). With HTTP Basic or
        // a client assertion the body may omit `client_id`; client authentication already
        // refused a body `client_id` that contradicts the credentials.
        match raw.0.iter().filter(|(k, _)| k == "client_id").count() {
            0 => raw
                .0
                .push(("client_id".to_owned(), client.client_id.clone())),
            1 if raw.get("client_id") == Some(client.client_id.as_str()) => {}
            _ => {
                return Err(CoreError::InvalidRequest(
                    "client_id must be sent once and name the authenticated client".to_owned(),
                ));
            }
        }

        let validated =
            validate(&raw, Some(&client), tenant.settings.registration).map_err(push_error)?;
        if !client
            .grant_types
            .contains(&crate::model::GrantType::AuthorizationCode)
        {
            return Err(CoreError::UnauthorizedClient(
                "the client may not use the authorization code grant".to_owned(),
            ));
        }

        let now = self.clock.now();
        let (request_uri, request_uri_hash) = new_request_uri(random_bytes::<32>());
        let params = serde_json::to_value(&validated.params)
            .map_err(|e| CoreError::Internal(format!("serializing pushed parameters: {e}")))?;
        self.storage
            .grants()
            .create_pushed_request(
                tenant.id,
                &NewPushedRequest {
                    request_uri_hash,
                    client_id: client.client_id.clone(),
                    params,
                    created_at: now,
                    expires_at: now + LIFETIME,
                },
            )
            .await?;
        Ok(PushedAuthorization {
            request_uri,
            expires_in: LIFETIME.whole_seconds(),
        })
    }

    /// Consumes the pushed request named by `request_uri` for `client_id` (atomically: exactly
    /// one caller gets it). The request is used up even when the client does not match, so a
    /// leaked `request_uri` cannot be retried.
    pub async fn consume(
        &self,
        tenant: &Tenant,
        client_id: &str,
        request_uri: &str,
    ) -> Result<Result<AuthorizationParams, PushedRequestRefused>, CoreError> {
        let Some(hash) = parse_request_uri(request_uri) else {
            return Ok(Err(PushedRequestRefused::Unusable));
        };
        let now = self.clock.now();
        let Some(pushed) = self
            .storage
            .grants()
            .consume_pushed_request(tenant.id, &hash, now)
            .await?
        else {
            return Ok(Err(PushedRequestRefused::Unusable));
        };
        if pushed.client_id != client_id {
            return Ok(Err(PushedRequestRefused::ClientMismatch));
        }
        let params: AuthorizationParams = serde_json::from_value(pushed.params)
            .map_err(|e| CoreError::Internal(format!("stored pushed parameters: {e}")))?;
        Ok(Ok(params))
    }
}
