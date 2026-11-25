//! Logout: RP-initiated logout (OIDC-12, OpenID Connect RP-Initiated Logout 1.0).
//!
//! # End session
//!
//! [`LogoutService::end_session`] serves the end-session endpoint (`GET`/`POST {issuer}/logout`):
//!
//! 1. The `id_token_hint`, when sent, is verified like the authorization endpoint's hint: signed
//!    by a published key of this tenant with one of the tenant's enabled algorithms (`alg: none`,
//!    foreign keys and other algorithms fail), `typ: JWT` (an access or logout token is not an ID
//!    token), `iss` exactly this tenant's issuer; expiry is ignored (RP-Initiated Logout 1.0 §2:
//!    an expired ID token is still a valid hint). Any failure is [`HintCheck::Invalid`]. The hint
//!    is never logged or stored.
//! 2. The client named by the hint (`azp`, else the first `aud`) and the client named by
//!    `client_id` are loaded from this tenant.
//! 3. The pure decision [`validate_end_session`] decides: log out now, ask, or refuse.
//! 4. Logging out revokes the browser session and its token families with
//!    `SessionRepo::revoke_with_families`, which in the same transaction enqueues the back-channel
//!    logout deliveries for every RP the session signed in to. Delivery is asynchronous; the
//!    caller wakes the delivery worker and never waits for it. A revocation records the
//!    `logout` audit event (user actor, the session as target, the client id as detail).
//!
//! # Confirmation
//!
//! Without a valid hint for the current session the user confirms first. The confirmation page
//! re-runs the decision without any hint ([`LogoutService::start_confirmation`]); without a hint
//! the decision table can only confirm or refuse, never log out, so opening the page has no
//! effect. It creates a `FlowKind::Logout` flow (flow cookie + CSRF token, 15 minutes) holding the
//! validated redirect ([`LogoutState`]). [`LogoutService::confirm`] checks the binding (a wrong
//! cookie or CSRF token is [`CoreError::Forbidden`]), consumes the flow (deleted, so a second
//! submission finds nothing) and logs the current session out.

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use anvil_jose::{ExpiryCheck, verify_op_token_algs};
use secrecy::SecretString;

use super::audit::AuditService;
use super::flow::{BindingError, FLOW_LIFETIME, check_binding};
use super::key::published_jwks;
use super::key_rotation::enabled_algs;
use super::token::ID_TOKEN_TYP;
use crate::error::CoreError;
use crate::flow::logout::LogoutState;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, BrowserSession, Client, FlowId, FlowKind,
    NewFlow, RequestContext, SecretHash, Tenant,
};
use crate::oauth::logout::{
    CurrentSession, EndSessionDecision, EndSessionRequest, HintCheck, LogoutError,
    PostLogoutRedirect, validate_end_session,
};
use crate::ports::{Clock, Storage};

/// Longest `id_token_hint` that is parsed at all; longer values are invalid without any work.
pub const MAX_HINT_LEN: usize = 16 * 1024;

/// The end-session parameters as received (RP-Initiated Logout 1.0 §2). Empty values count as
/// absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawEndSession {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub ui_locales: Option<String>,
}

/// What the end-session endpoint does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// Logged out (or there was no session): redirect to `redirect` (final URL with `state`) or
    /// show the signed-out page. `revoked` is whether a session was revoked by this call.
    LoggedOut {
        redirect: Option<String>,
        revoked: bool,
    },
    /// Ask the user first ([`LogoutService::start_confirmation`] opens the page).
    Confirm {
        client_id: Option<String>,
        redirect: Option<PostLogoutRedirect>,
    },
    /// Refused: error page, no logout, no redirect.
    Error(LogoutError),
}

/// A newly created logout confirmation flow: the cookie and the CSRF token go to the browser.
#[derive(Debug)]
pub struct StartedLogoutFlow {
    pub flow_id: FlowId,
    pub cookie_token: SecretString,
    pub csrf_token: SecretString,
}

/// Result of opening the confirmation page.
#[derive(Debug)]
pub enum ConfirmationStart {
    Started {
        flow: StartedLogoutFlow,
        /// The name of the client the request named, for the page.
        client_name: Option<String>,
    },
    Error(LogoutError),
}

/// A confirmation's binding to its flow (`?flow=`, flow cookie, `csrf_token` field).
#[derive(Debug, Clone, Copy)]
pub struct LogoutBinding<'a> {
    pub flow_id: FlowId,
    pub cookie_token: Option<&'a str>,
    pub csrf_token: &'a str,
}

/// Result of a confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmResult {
    /// Logged out: redirect (final URL) or show the signed-out page.
    LoggedOut {
        redirect: Option<String>,
        revoked: bool,
    },
    /// The flow expired, does not exist or was already used; nothing changed.
    Expired,
}

/// RP-initiated logout.
pub struct LogoutService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

/// `None` for an absent or empty parameter.
fn non_empty(v: &Option<String>) -> Option<String> {
    v.as_ref().filter(|s| !s.is_empty()).cloned()
}

impl LogoutService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Verifies `hint` (module docs) and returns the check with the client id the hint names.
    async fn check_hint(
        &self,
        tenant: &Tenant,
        issuer: &str,
        hint: &str,
    ) -> Result<(HintCheck, Option<String>), CoreError> {
        if hint.len() > MAX_HINT_LEN {
            return Ok((HintCheck::Invalid, None));
        }
        let jwks = published_jwks(self.storage.as_ref(), self.clock.as_ref(), tenant.id).await?;
        let algs = enabled_algs(tenant)?;
        let Ok(jwt) = verify_op_token_algs(
            hint,
            &jwks,
            &algs,
            issuer,
            Some(ID_TOKEN_TYP),
            ExpiryCheck::Ignore,
            self.clock.now(),
        ) else {
            return Ok((HintCheck::Invalid, None));
        };
        let claims = &jwt.claims;
        let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) else {
            return Ok((HintCheck::Invalid, None));
        };
        let aud: Vec<String> = match claims.get("aud") {
            Some(serde_json::Value::String(a)) => vec![a.clone()],
            Some(serde_json::Value::Array(list)) => list
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        if aud.is_empty() {
            return Ok((HintCheck::Invalid, None));
        }
        let sid = match claims.get("sid") {
            None => None,
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(_) => return Ok((HintCheck::Invalid, None)),
        };
        let client = claims
            .get("azp")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| aud.first().cloned());
        Ok((
            HintCheck::Valid {
                sub: sub.to_owned(),
                sid,
                aud,
            },
            client,
        ))
    }

    async fn client(&self, tenant: &Tenant, client_id: &str) -> Result<Option<Client>, CoreError> {
        Ok(self.storage.clients().get(tenant.id, client_id).await?)
    }

    /// Runs the decision table. `hint` is the raw hint (`None` = absent).
    async fn decide(
        &self,
        tenant: &Tenant,
        issuer: &str,
        raw: &RawEndSession,
        hint: Option<&str>,
        current: Option<&BrowserSession>,
    ) -> Result<(EndSessionDecision, Option<String>), CoreError> {
        let (check, hint_client_id) = match hint {
            None => (HintCheck::Absent, None),
            Some(h) => self.check_hint(tenant, issuer, h).await?,
        };
        let hint_client = match &hint_client_id {
            Some(id) => self.client(tenant, id).await?,
            None => None,
        };
        let client_id = non_empty(&raw.client_id);
        let client_by_id = match &client_id {
            Some(id) => self.client(tenant, id).await?,
            None => None,
        };
        let req = EndSessionRequest {
            id_token_hint: check,
            client_id: client_id.clone(),
            post_logout_redirect_uri: non_empty(&raw.post_logout_redirect_uri),
            state: non_empty(&raw.state),
            ui_locales: non_empty(&raw.ui_locales),
        };
        let current = current
            .filter(|s| s.tenant_id == tenant.id && s.revoked_at.is_none())
            .map(|s| CurrentSession {
                user_id: s.user_id.to_string(),
                session_id: s.id.to_string(),
            });
        let decision = validate_end_session(
            &req,
            hint_client.as_ref(),
            client_by_id.as_ref(),
            current.as_ref(),
        );
        // The client the logout is attributed to (audit).
        let attributed = hint_client.map(|c| c.client_id).or(client_id);
        Ok((decision, attributed))
    }

    /// Revokes `current` (if it is an unrevoked session of this tenant) with its token families
    /// and the back-channel deliveries; audits `logout` when something was revoked.
    async fn log_out(
        &self,
        tenant: &Tenant,
        current: Option<&BrowserSession>,
        client_id: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<bool, CoreError> {
        let Some(session) = current.filter(|s| s.tenant_id == tenant.id && s.revoked_at.is_none())
        else {
            return Ok(false);
        };
        let revoked = self
            .storage
            .sessions()
            .revoke_with_families(tenant.id, session.id, self.clock.now())
            .await?;
        if revoked {
            self.audit()
                .record(
                    tenant.id,
                    AuditActor::user(session.user_id),
                    AuditAction::Logout,
                    Some(session.id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                    AuditDetails::logout(client_id),
                )
                .await?;
        }
        Ok(revoked)
    }

    /// The end-session endpoint (module docs). `current` is the caller's active session of this
    /// tenant, if any.
    pub async fn end_session(
        &self,
        tenant: &Tenant,
        issuer: &str,
        raw: &RawEndSession,
        current: Option<&BrowserSession>,
        ctx: &RequestContext,
    ) -> Result<LogoutOutcome, CoreError> {
        let hint = non_empty(&raw.id_token_hint);
        let (decision, attributed) = self
            .decide(tenant, issuer, raw, hint.as_deref(), current)
            .await?;
        Ok(match decision {
            EndSessionDecision::Error(e) => LogoutOutcome::Error(e),
            EndSessionDecision::Confirm {
                client_id,
                redirect,
            } => LogoutOutcome::Confirm {
                client_id,
                redirect,
            },
            EndSessionDecision::LogoutNow { redirect } => {
                let revoked = self
                    .log_out(tenant, current, attributed.as_deref(), ctx)
                    .await?;
                LogoutOutcome::LoggedOut {
                    redirect: redirect.map(|r| r.to_url()),
                    revoked,
                }
            }
        })
    }

    /// Opens the confirmation page for `client_id`, `post_logout_redirect_uri` and `state` of
    /// `raw` (any `id_token_hint` is ignored: without a hint the decision never logs out). The
    /// redirect is validated again here, so a hand-made page URL cannot add an unregistered one.
    pub async fn start_confirmation(
        &self,
        tenant: &Tenant,
        issuer: &str,
        raw: &RawEndSession,
    ) -> Result<ConfirmationStart, CoreError> {
        let (decision, _) = self.decide(tenant, issuer, raw, None, None).await?;
        let (client_id, redirect) = match decision {
            EndSessionDecision::Confirm {
                client_id,
                redirect,
            } => (client_id, redirect),
            EndSessionDecision::Error(e) => return Ok(ConfirmationStart::Error(e)),
            EndSessionDecision::LogoutNow { .. } => {
                return Err(CoreError::Internal(
                    "the end-session decision logged out without a hint".to_owned(),
                ));
            }
        };
        let client_name = match &client_id {
            Some(id) => self.client(tenant, id).await?.map(|c| c.name),
            None => None,
        };
        let state = LogoutState::new(client_id, redirect);
        let now = self.clock.now();
        let cookie = random_token();
        let csrf = random_token();
        let new = NewFlow {
            id: FlowId::new_v7(),
            kind: FlowKind::Logout,
            state: state.to_json(),
            csrf_hash: SecretHash(secret_hash(&csrf)),
            cookie_hash: SecretHash(secret_hash(&cookie)),
            auth_request_id: None,
            created_at: now,
            expires_at: now + FLOW_LIFETIME,
        };
        self.storage.flows().create(tenant.id, &new).await?;
        Ok(ConfirmationStart::Started {
            flow: StartedLogoutFlow {
                flow_id: new.id,
                cookie_token: SecretString::from(cookie),
                csrf_token: SecretString::from(csrf),
            },
            client_name,
        })
    }

    /// The user confirmed: checks the binding (`Forbidden` on a wrong cookie or CSRF token or a
    /// flow of another kind), consumes the flow and logs `current` out.
    pub async fn confirm(
        &self,
        tenant: &Tenant,
        binding: &LogoutBinding<'_>,
        current: Option<&BrowserSession>,
        ctx: &RequestContext,
    ) -> Result<ConfirmResult, CoreError> {
        let now = self.clock.now();
        let Some(flow) = self
            .storage
            .flows()
            .get(tenant.id, binding.flow_id, now)
            .await?
        else {
            return Ok(ConfirmResult::Expired);
        };
        if flow.kind != FlowKind::Logout {
            return Err(CoreError::Forbidden);
        }
        match check_binding(&flow, binding.cookie_token, binding.csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => return Ok(ConfirmResult::Expired),
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden),
        }
        let state =
            LogoutState::from_json(&flow.state).map_err(|e| CoreError::Internal(e.to_string()))?;
        // Single use: of two submissions exactly one deletes the flow.
        if !self.storage.flows().delete(tenant.id, flow.id).await? {
            return Ok(ConfirmResult::Expired);
        }
        let revoked = self
            .log_out(tenant, current, state.client_id.as_deref(), ctx)
            .await?;
        Ok(ConfirmResult::LoggedOut {
            redirect: state.redirect().map(|r| r.to_url()),
            revoked,
        })
    }
}
