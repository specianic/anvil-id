//! The authorization endpoint service: validate, decide on the session, persist requests that
//! need a login, issue codes and resume after login.
//!
//! The protocol decisions live in pure functions ([`crate::oauth::authorize_request::validate`],
//! [`crate::oauth::decision::decide`], [`build_code`], [`AuthorizationResponse`]);
//! this service only orchestrates the ports. It is tested end to end over HTTP on both backends.

use std::sync::Arc;

use anvil_jose::{ExpiryCheck, Jwks, verify_op_token};
use secrecy::{ExposeSecret, SecretString};
use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::{
    AuthRequestId, AuthorizationParams, BrowserSession, Client, GrantType, NewAuthorizationCode,
    NewAuthorizationRequest, NewTokenFamily, SecretHash, Tenant, TokenFamilyId, UserStatus,
};
use crate::oauth::authorize_request::{AuthorizeError, RawParams, validate};
use crate::oauth::decision::{SessionDecision, decide};
use crate::oauth::redirect::redirect_matches;
use crate::oauth::response_mode::AuthorizationResponse;
use crate::ports::{Clock, Storage};

/// Lifetime of an authorization code.
pub const CODE_TTL: Duration = Duration::seconds(60);
/// Lifetime of a stored authorization request (time the user has to sign in).
pub const AUTH_REQUEST_TTL: Duration = Duration::minutes(15);
/// Absolute lifetime of a token family created by a code.
pub const FAMILY_TTL: Duration = Duration::days(30);
/// Longest `client_id` looked up in storage.
const MAX_CLIENT_ID_LEN: usize = 255;

/// What the web layer does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// Deliver an authorization response (success or error) to the trusted redirect URI, in the
    /// response's mode. Always carries `iss`.
    Respond(AuthorizationResponse),
    /// Send the user to the login flow, then call [`AuthorizeService::resume`].
    Login { request_id: AuthRequestId },
    /// Show an error page; never redirect. `error_key` is one of `invalid_request`,
    /// `unknown_client`, `redirect_uri_mismatch`, `flow_expired`.
    ErrorPage {
        error_key: &'static str,
        detail: String,
    },
}

/// The error response for `params` (its redirect URI, state and response mode).
fn error_response(
    params: &AuthorizationParams,
    error: &CoreError,
    issuer: &str,
) -> AuthorizeOutcome {
    AuthorizeOutcome::Respond(AuthorizationResponse::error(
        &params.redirect_uri,
        error,
        params.state.as_deref(),
        issuer,
        params.response_mode,
    ))
}

/// Builds a code and its pre-created token family. Returns the plaintext code (sent to the
/// client only) and the records to store; only the code's hash is stored.
pub fn build_code(
    client: &Client,
    params: &AuthorizationParams,
    session: &BrowserSession,
    now: OffsetDateTime,
) -> (SecretString, NewAuthorizationCode, NewTokenFamily) {
    let plaintext = anvil_jose::encoding::random_token();
    let code_hash = SecretHash(anvil_jose::encoding::secret_hash(&plaintext));
    let family_id = TokenFamilyId::new_v7();
    let family = NewTokenFamily {
        id: family_id,
        client_id: client.client_id.clone(),
        user_id: Some(session.user_id),
        scope: params.scope.clone(),
        auth_time: Some(session.auth_time),
        acr: Some(session.acr.clone()),
        amr: session.amr.clone(),
        session_id: Some(session.id),
        claims: params.claims.clone(),
        created_at: now,
        absolute_expires_at: now + FAMILY_TTL,
    };
    let code = NewAuthorizationCode {
        code_hash,
        client_id: client.client_id.clone(),
        user_id: session.user_id,
        session_id: session.id,
        redirect_uri: params.redirect_uri.clone(),
        scope: params.scope.clone(),
        nonce: params.nonce.clone(),
        code_challenge: params.code_challenge.clone(),
        auth_time: session.auth_time,
        acr: session.acr.clone(),
        amr: session.amr.clone(),
        token_family_id: family_id,
        expires_at: now + CODE_TTL,
        created_at: now,
    };
    (SecretString::from(plaintext), code, family)
}

/// Authorization endpoint service.
pub struct AuthorizeService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl AuthorizeService {
    /// Handles an authorization request.
    pub async fn authorize(
        &self,
        tenant: &Tenant,
        issuer: &str,
        raw: RawParams,
        session: Option<BrowserSession>,
    ) -> Result<AuthorizeOutcome, CoreError> {
        let now = self.clock.now();
        let client = match raw.single("client_id") {
            Some(id) if id.len() <= MAX_CLIENT_ID_LEN => {
                self.storage.clients().get(tenant.id, id).await?
            }
            _ => None,
        };
        let validated = match validate(&raw, client.as_ref()) {
            Ok(v) => v,
            Err(AuthorizeError::ErrorPage { error_key, detail }) => {
                return Ok(AuthorizeOutcome::ErrorPage { error_key, detail });
            }
            Err(AuthorizeError::Redirect {
                redirect_uri,
                state,
                response_mode,
                error,
            }) => {
                return Ok(AuthorizeOutcome::Respond(AuthorizationResponse::error(
                    &redirect_uri,
                    &error,
                    state.as_deref(),
                    issuer,
                    response_mode,
                )));
            }
        };
        let client = validated.client;
        let params = validated.params;
        let fail = |error: CoreError| error_response(&params, &error, issuer);

        if !client.grant_types.contains(&GrantType::AuthorizationCode) {
            return Ok(fail(CoreError::UnauthorizedClient(
                "the client may not use the authorization code grant".to_owned(),
            )));
        }

        let prompt_none = params.prompt.iter().any(|p| p == "none");
        let hint_sub = match validated.id_token_hint.as_deref() {
            None => None,
            Some(hint) => match self.hint_subject(tenant, issuer, hint, now).await? {
                Some(sub) => Some(sub),
                None if prompt_none => {
                    return Ok(fail(CoreError::InvalidRequest(
                        "id_token_hint is invalid".to_owned(),
                    )));
                }
                None => None,
            },
        };

        let session = self.usable_session(tenant, session).await?;
        match decide(
            &params.prompt,
            params.max_age,
            session.as_ref(),
            hint_sub.as_deref(),
            now,
            now,
        ) {
            SessionDecision::UseSession => {
                let session = session.ok_or_else(|| {
                    CoreError::Internal("UseSession decided without a session".to_owned())
                })?;
                self.issue(tenant, issuer, &client, &params, &session, now)
                    .await
            }
            SessionDecision::RequireLogin => {
                let request_id = AuthRequestId::new_v7();
                let request = NewAuthorizationRequest {
                    id: request_id,
                    client_id: client.client_id.clone(),
                    params: params.clone(),
                    created_at: now,
                    expires_at: now + AUTH_REQUEST_TTL,
                };
                self.storage
                    .grants()
                    .create_authorization_request(tenant.id, &request)
                    .await?;
                Ok(AuthorizeOutcome::Login { request_id })
            }
            SessionDecision::Fail(error) => Ok(fail(error)),
        }
    }

    /// Continues a stored authorization request after the login flow.
    pub async fn resume(
        &self,
        tenant: &Tenant,
        issuer: &str,
        request_id: AuthRequestId,
        session: Option<BrowserSession>,
    ) -> Result<AuthorizeOutcome, CoreError> {
        let now = self.clock.now();
        let Some(request) = self
            .storage
            .grants()
            .get_authorization_request(tenant.id, request_id, now)
            .await?
        else {
            return Ok(flow_expired());
        };
        let Some(client) = self
            .storage
            .clients()
            .get(tenant.id, &request.client_id)
            .await?
        else {
            return Ok(AuthorizeOutcome::ErrorPage {
                error_key: "unknown_client",
                detail: "the client is no longer registered".to_owned(),
            });
        };
        let params = request.params;
        // The client may have changed while the user signed in.
        if !redirect_matches(
            &client.redirect_uris,
            &params.redirect_uri,
            client.application_type,
        ) {
            return Ok(AuthorizeOutcome::ErrorPage {
                error_key: "redirect_uri_mismatch",
                detail: "redirect_uri is no longer registered".to_owned(),
            });
        }
        if !client.grant_types.contains(&GrantType::AuthorizationCode) {
            return Ok(error_response(
                &params,
                &CoreError::UnauthorizedClient(
                    "the client may not use the authorization code grant".to_owned(),
                ),
                issuer,
            ));
        }

        let session = self.usable_session(tenant, session).await?;
        match decide(
            &params.prompt,
            params.max_age,
            session.as_ref(),
            None,
            request.created_at,
            now,
        ) {
            SessionDecision::UseSession => {
                let session = session.ok_or_else(|| {
                    CoreError::Internal("UseSession decided without a session".to_owned())
                })?;
                // Deleting first makes the request single-use: a concurrent resume loses.
                if !self
                    .storage
                    .grants()
                    .delete_authorization_request(tenant.id, request_id)
                    .await?
                {
                    return Ok(flow_expired());
                }
                self.issue(tenant, issuer, &client, &params, &session, now)
                    .await
            }
            SessionDecision::RequireLogin => Ok(AuthorizeOutcome::Login { request_id }),
            SessionDecision::Fail(error) => {
                self.storage
                    .grants()
                    .delete_authorization_request(tenant.id, request_id)
                    .await?;
                Ok(error_response(&params, &error, issuer))
            }
        }
    }

    async fn issue(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client: &Client,
        params: &AuthorizationParams,
        session: &BrowserSession,
        now: OffsetDateTime,
    ) -> Result<AuthorizeOutcome, CoreError> {
        let (plaintext, code, family) = build_code(client, params, session, now);
        self.storage
            .grants()
            .create_code(tenant.id, &code, &family)
            .await?;
        Ok(AuthorizeOutcome::Respond(AuthorizationResponse::success(
            &params.redirect_uri,
            plaintext.expose_secret(),
            params.state.as_deref(),
            issuer,
            params.response_mode,
        )))
    }

    /// The session if it belongs to this tenant, is not revoked and its user exists and is not
    /// blocked; otherwise `None` (treated as no session).
    async fn usable_session(
        &self,
        tenant: &Tenant,
        session: Option<BrowserSession>,
    ) -> Result<Option<BrowserSession>, CoreError> {
        let Some(s) = session else {
            return Ok(None);
        };
        if s.tenant_id != tenant.id || s.revoked_at.is_some() {
            return Ok(None);
        }
        let user = self.storage.users().get(tenant.id, s.user_id).await?;
        Ok(match user {
            Some(u) if u.status == UserStatus::Active => Some(s),
            _ => None,
        })
    }

    /// The `sub` of a valid `id_token_hint` (signed by a published key of this tenant, issued by
    /// `issuer`; expiry ignored), or `None` when the hint is invalid. The hint is never logged.
    async fn hint_subject(
        &self,
        tenant: &Tenant,
        issuer: &str,
        hint: &str,
        now: OffsetDateTime,
    ) -> Result<Option<String>, CoreError> {
        let keys = self.storage.keys().published(tenant.id, now).await?;
        let Ok(jwks) = Jwks::from_public_jwks(keys.iter().map(|k| k.public_jwk.as_str())) else {
            return Err(CoreError::Internal(
                "a published signing key has an unreadable public JWK".to_owned(),
            ));
        };
        Ok(
            verify_op_token(hint, &jwks, issuer, None, ExpiryCheck::Ignore, now)
                .ok()
                .and_then(|jwt| {
                    jwt.claims
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                }),
        )
    }
}

fn flow_expired() -> AuthorizeOutcome {
    AuthorizeOutcome::ErrorPage {
        error_key: "flow_expired",
        detail: "the authorization request expired or was already used".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ACR_PWD, AMR_PWD, SessionId, TenantId, UserId};
    use crate::oauth::authorize_request::tests::{CHALLENGE, RP, client};
    use crate::oauth::response_mode::ResponseMode;
    use time::macros::datetime;

    const ISSUER: &str = "https://id.example.test/t/acme";
    const NOW: OffsetDateTime = datetime!(2026-11-25 12:00:00 UTC);

    fn params() -> AuthorizationParams {
        AuthorizationParams {
            redirect_uri: RP.to_owned(),
            scope: "openid profile".to_owned(),
            state: Some("st".to_owned()),
            nonce: Some("n-1".to_owned()),
            code_challenge: Some(CHALLENGE.to_owned()),
            prompt: Vec::new(),
            max_age: None,
            login_hint: None,
            acr_values: Vec::new(),
            ui_locales: None,
            claims: None,
            response_mode: ResponseMode::Query,
        }
    }

    fn session() -> BrowserSession {
        let auth = NOW - Duration::minutes(3);
        BrowserSession {
            id: SessionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            user_id: UserId::new_v7(),
            token_hash: SecretHash([7; 32]),
            auth_time: auth,
            acr: ACR_PWD.to_owned(),
            amr: vec![AMR_PWD.to_owned()],
            created_at: auth,
            last_seen_at: auth,
            expires_at: auth + Duration::days(1),
            idle_expires_at: auth + Duration::hours(1),
            revoked_at: None,
            ip: None,
            user_agent: None,
        }
    }

    #[test]
    fn build_code_binds_everything_and_stores_only_the_hash() {
        let c = client();
        let p = params();
        let s = session();
        let (plain, code, family) = build_code(&c, &p, &s, NOW);
        let plain = plain.expose_secret();
        assert_eq!(plain.len(), 43);
        assert_eq!(
            code.code_hash,
            SecretHash(anvil_jose::encoding::secret_hash(plain))
        );
        assert_ne!(code.code_hash.as_bytes().as_slice(), plain.as_bytes());
        assert_eq!(code.expires_at, NOW + Duration::seconds(60));
        assert_eq!(code.created_at, NOW);
        assert_eq!(family.absolute_expires_at, NOW + Duration::days(30));
        assert_eq!(code.token_family_id, family.id);
        assert_eq!(code.code_challenge.as_deref(), Some(CHALLENGE));
        assert_eq!(code.nonce.as_deref(), Some("n-1"));
        assert_eq!(code.redirect_uri, RP);
        assert_eq!(code.client_id, "rp");
        assert_eq!(code.user_id, s.user_id);
        assert_eq!(code.session_id, s.id);
        assert_eq!(code.auth_time, s.auth_time);
        assert_eq!(code.acr, ACR_PWD);
        assert_eq!(code.amr, vec![AMR_PWD]);
        assert_eq!(family.user_id, Some(s.user_id));
        assert_eq!(family.session_id, Some(s.id));
        assert_eq!(family.auth_time, Some(s.auth_time));
        assert_eq!(family.acr.as_deref(), Some(ACR_PWD));
        assert_eq!(family.scope, "openid profile");
        // Two codes never collide.
        let (other, _, other_family) = build_code(&c, &p, &s, NOW);
        assert_ne!(other.expose_secret(), plain);
        assert_ne!(other_family.id, family.id);
    }

    #[test]
    fn error_response_carries_the_stored_mode_state_and_iss() {
        let mut p = params();
        p.response_mode = ResponseMode::FormPost;
        let AuthorizeOutcome::Respond(r) = error_response(&p, &CoreError::LoginRequired, ISSUER)
        else {
            panic!("expected a response");
        };
        assert_eq!(r.mode, ResponseMode::FormPost);
        assert_eq!(r.redirect_uri, RP);
        let keys: Vec<&str> = r.params.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["error", "error_description", "state", "iss"]);
        assert_eq!(r.params[2].1, "st");
        assert_eq!(r.params[3].1, ISSUER);

        let AuthorizeOutcome::Respond(r) =
            error_response(&params(), &CoreError::LoginRequired, ISSUER)
        else {
            panic!("expected a response");
        };
        assert_eq!(r.mode, ResponseMode::Query);
        assert!(
            r.to_redirect_url()
                .starts_with("https://rp.example.test/cb?error=login_required")
        );
    }
}
