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
//!
//! # Without a session
//!
//! A request that would ask, while the browser has no active session of this tenant, does not
//! ask: there is nothing to sign out. [`LogoutService::end_session`] answers
//! [`LogoutOutcome::LoggedOut`] (`revoked: false`) and [`LogoutService::start_confirmation`]
//! answers [`ConfirmationStart::NotSignedIn`], both with the validated post-logout redirect if the
//! request had one. Refusals stay refusals (the decision runs first), and no flow is created.
//! With a session nothing changes: the confirmation is asked as before. The outcomes carry the
//! client the logout named (`client_id`) so the pages can offer a way back to it.

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use anvil_jose::keys::SigningKey;
use anvil_jose::{ExpiryCheck, verify_op_token_algs};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::audit::AuditService;
use super::flow::{BindingError, FLOW_LIFETIME, check_binding};
use super::key::KeyService;
use super::key::published_jwks;
use super::key_rotation::enabled_algs;
use super::token::{ID_TOKEN_TYP, id_token_alg};
use crate::error::CoreError;
use crate::flow::logout::LogoutState;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, BrowserSession, Client,
    DEFAULT_TENANT_SLUG, FlowId, FlowKind, LogoutDelivery, NewFlow, PublicUrl, RequestContext,
    SecretHash, Tenant, TenantBase, issuer,
};
use crate::oauth::logout::{
    CurrentSession, EndSessionDecision, EndSessionRequest, HintCheck, LogoutError,
    PostLogoutRedirect, logout_token_claims, validate_end_session,
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

/// A parameter of the end-session request was sent more than once (OAuth 2.0 §3.1: request
/// parameters must not be included more than once).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("repeated end-session parameter")]
pub struct RepeatedParameter;

impl RawEndSession {
    /// The parameters from decoded query or form pairs. Unknown parameters are ignored; a known
    /// parameter that appears twice is [`RepeatedParameter`].
    pub fn from_pairs<K, V>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, RepeatedParameter>
    where
        K: AsRef<str>,
        V: Into<String>,
    {
        let mut raw = Self::default();
        for (k, v) in pairs {
            let slot = match k.as_ref() {
                "id_token_hint" => &mut raw.id_token_hint,
                "client_id" => &mut raw.client_id,
                "post_logout_redirect_uri" => &mut raw.post_logout_redirect_uri,
                "state" => &mut raw.state,
                "ui_locales" => &mut raw.ui_locales,
                _ => continue,
            };
            if slot.is_some() {
                return Err(RepeatedParameter);
            }
            *slot = Some(v.into());
        }
        Ok(raw)
    }
}

/// What the end-session endpoint does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// Logged out (or there was no session): redirect to `redirect` (final URL with `state`) or
    /// show the signed-out page. `revoked` is whether a session was revoked by this call.
    LoggedOut {
        redirect: Option<String>,
        revoked: bool,
        /// The client the logout named (hint or `client_id`), for the page's way forward.
        client_id: Option<String>,
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
        /// The validated client the request named, for the page's way back.
        client_id: Option<String>,
    },
    /// No active session of this tenant: nothing to confirm and no flow created. `redirect` is
    /// the validated post-logout redirect (final URL with `state`), if the request had one.
    NotSignedIn {
        redirect: Option<String>,
        client_id: Option<String>,
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
        /// The client the confirmed logout named, for the page's way forward.
        client_id: Option<String>,
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

/// `current` if it is an unrevoked session of `tenant`.
fn active_in<'a>(
    tenant: &Tenant,
    current: Option<&'a BrowserSession>,
) -> Option<&'a BrowserSession> {
    current.filter(|s| s.tenant_id == tenant.id && s.revoked_at.is_none())
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
        let current = active_in(tenant, current).map(|s| CurrentSession {
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
        let Some(session) = active_in(tenant, current) else {
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
            // Nothing to sign out: no question (module docs, "Without a session").
            EndSessionDecision::Confirm {
                client_id,
                redirect,
            } if active_in(tenant, current).is_none() => LogoutOutcome::LoggedOut {
                redirect: redirect.map(|r| r.to_url()),
                revoked: false,
                client_id,
            },
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
                    client_id: attributed,
                }
            }
        })
    }

    /// Opens the confirmation page for `client_id`, `post_logout_redirect_uri` and `state` of
    /// `raw` (any `id_token_hint` is ignored: without a hint the decision never logs out). The
    /// redirect is validated again here, so a hand-made page URL cannot add an unregistered one.
    /// Without an active session of this tenant (`current`) there is nothing to confirm:
    /// [`ConfirmationStart::NotSignedIn`], no flow.
    pub async fn start_confirmation(
        &self,
        tenant: &Tenant,
        issuer: &str,
        raw: &RawEndSession,
        current: Option<&BrowserSession>,
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
        if active_in(tenant, current).is_none() {
            return Ok(ConfirmationStart::NotSignedIn {
                redirect: redirect.map(|r| r.to_url()),
                client_id,
            });
        }
        let client_name = match &client_id {
            Some(id) => self.client(tenant, id).await?.map(|c| c.name),
            None => None,
        };
        let state = LogoutState::new(client_id.clone(), redirect);
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
            client_id,
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
            client_id: state.client_id,
        })
    }
}

/// `typ` header of logout tokens (Back-Channel Logout 1.0 §2.4).
pub const LOGOUT_TOKEN_TYP: &str = "logout+jwt";

/// A back-channel logout delivery ready to send: the destination and the freshly signed logout
/// token. The token is never logged or stored.
#[derive(Debug)]
pub struct PreparedDelivery {
    /// The client's current `backchannel_logout_uri` (query string preserved).
    pub uri: String,
    pub logout_token: SecretString,
}

/// The canonical issuer of `tenant`: its custom host, the public URL for the default tenant,
/// else `/t/{slug}`. Background work (no request, so no request host) uses this issuer.
pub fn canonical_issuer(public_url: &PublicUrl, tenant: &Tenant) -> String {
    let base = match &tenant.host {
        Some(h) => TenantBase::Host(h.clone()),
        None if tenant.slug == DEFAULT_TENANT_SLUG => TenantBase::Root,
        None => TenantBase::Path(tenant.slug.clone()),
    };
    issuer(public_url, &base)
}

/// The `iss` of `delivery`'s logout token: the issuer the RP got its ID tokens from, recorded on
/// the RP session and copied onto the delivery (Back-Channel Logout 1.0 §2.4: it must equal the
/// ID token's `iss`). `None` exists only for rows written before the issuer column (SQLite
/// migration 0006, Postgres 0005); those fall back to the tenant's canonical issuer.
pub fn logout_token_issuer(
    public_url: &PublicUrl,
    tenant: &Tenant,
    delivery: &LogoutDelivery,
) -> String {
    delivery
        .issuer
        .clone()
        .unwrap_or_else(|| canonical_issuer(public_url, tenant))
}

/// Signs the logout token of `delivery` with `signer` (header `typ: logout+jwt`): claims
/// exactly `iss`, `aud` (the client), `iat`, `exp` (2 minutes), `jti`, `sub`, `sid`, `events`;
/// never a `nonce` (Back-Channel Logout 1.0 §2.4).
pub fn sign_logout_token(
    signer: &SigningKey,
    issuer: &str,
    delivery: &LogoutDelivery,
    jti: &str,
    now: OffsetDateTime,
) -> Result<String, CoreError> {
    let claims = logout_token_claims(
        issuer,
        &delivery.client_id,
        &delivery.sub,
        &delivery.sid,
        jti,
        now,
    );
    signer
        .sign_jwt(Some(LOGOUT_TOKEN_TYP), &claims)
        .map_err(|_| CoreError::Internal("logout token signing failed".to_owned()))
}

impl LogoutService {
    /// Prepares one back-channel logout delivery at send time (OIDC Back-Channel Logout 1.0):
    /// loads the tenant and the client, and signs a fresh logout token (new random `jti`) with
    /// the key of the client's ID-token algorithm (no fallback to another algorithm: an alg the
    /// tenant cannot serve is `Internal`). The destination is the client's *current*
    /// `backchannel_logout_uri`.
    ///
    /// A deleted tenant or client, or a client that no longer has a back-channel logout URI, is
    /// [`CoreError::NotFound`]: the delivery can never succeed and is given up.
    pub async fn prepare_delivery(
        &self,
        keys: &KeyService,
        public_url: &PublicUrl,
        delivery: &LogoutDelivery,
        now: OffsetDateTime,
    ) -> Result<PreparedDelivery, CoreError> {
        let tenant = self
            .storage
            .tenants()
            .get(delivery.tenant_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let client = self
            .client(&tenant, &delivery.client_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let uri = client
            .backchannel_logout_uri
            .clone()
            .filter(|u| !u.is_empty())
            .ok_or(CoreError::NotFound)?;
        let alg = id_token_alg(&tenant, &client)?;
        let signer = keys.signer_for(tenant.id, alg).await?;
        let issuer = logout_token_issuer(public_url, &tenant, delivery);
        let token = sign_logout_token(&signer, &issuer, delivery, &random_token(), now)?;
        Ok(PreparedDelivery {
            uri,
            logout_token: SecretString::from(token),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_pairs_reads_known_parameters_and_ignores_others() {
        let raw = RawEndSession::from_pairs([
            ("id_token_hint", "h"),
            ("client_id", "rp"),
            ("post_logout_redirect_uri", "https://rp.example/bye"),
            ("state", "s"),
            ("ui_locales", "de en"),
            ("foo", "bar"),
            ("foo", "baz"),
        ])
        .expect("valid");
        assert_eq!(
            raw,
            RawEndSession {
                id_token_hint: Some("h".into()),
                client_id: Some("rp".into()),
                post_logout_redirect_uri: Some("https://rp.example/bye".into()),
                state: Some("s".into()),
                ui_locales: Some("de en".into()),
            }
        );
        assert_eq!(
            RawEndSession::from_pairs(Vec::<(&str, &str)>::new()),
            Ok(RawEndSession::default())
        );
    }

    #[test]
    fn from_pairs_rejects_every_repeated_known_parameter() {
        for name in [
            "id_token_hint",
            "client_id",
            "post_logout_redirect_uri",
            "state",
            "ui_locales",
        ] {
            assert_eq!(
                RawEndSession::from_pairs([(name, "a"), (name, "b")]),
                Err(RepeatedParameter),
                "{name}"
            );
            // Also when the first value is empty.
            assert_eq!(
                RawEndSession::from_pairs([(name, ""), (name, "b")]),
                Err(RepeatedParameter),
                "{name}"
            );
        }
    }

    fn delivery() -> LogoutDelivery {
        let t = time::macros::datetime!(2026-11-25 12:00 UTC);
        LogoutDelivery {
            id: crate::model::LogoutDeliveryId::new_v7(),
            tenant_id: crate::model::TenantId::new_v7(),
            client_id: "rp".into(),
            uri: "https://rp.example.test/bc?x=1".into(),
            sub: "user-1".into(),
            sid: "session-1".into(),
            issuer: None,
            attempts: 0,
            next_attempt_at: t,
            give_up_at: t + crate::model::LOGOUT_DELIVERY_TTL,
            created_at: t,
            delivered_at: None,
            last_error: None,
        }
    }

    #[test]
    fn logout_token_has_typ_and_exactly_the_spec_claims() {
        use crate::model::KeyState;
        use crate::service::key::{jwks_from_rows, open_key, tests::sealed_row};
        use anvil_jose::jws::{decode_header, verify_jwt};
        use anvil_jose::keys::Alg;

        let kek = anvil_jose::Kek::generate();
        let row = sealed_row(&kek, KeyState::Active);
        let signer = open_key(&kek, &row).unwrap();
        let d = delivery();
        let now = time::macros::datetime!(2026-11-25 12:05 UTC);
        let token = sign_logout_token(&signer, "https://op.example", &d, "jti-1", now).unwrap();

        let header = decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some(LOGOUT_TOKEN_TYP));
        assert_eq!(header.kid.as_deref(), Some(row.kid.as_str()));
        let jwt = verify_jwt(&token, &jwks_from_rows(&[row]).unwrap(), &[Alg::RS256]).unwrap();
        let claims = &jwt.claims;
        let mut names: Vec<&str> = claims.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["aud", "events", "exp", "iat", "iss", "jti", "sid", "sub"]
        );
        assert_eq!(claims["iss"], "https://op.example");
        assert_eq!(claims["aud"], "rp");
        assert_eq!(claims["sub"], "user-1");
        assert_eq!(claims["sid"], "session-1");
        assert_eq!(claims["jti"], "jti-1");
        assert_eq!(claims["iat"], now.unix_timestamp());
        assert_eq!(claims["exp"], now.unix_timestamp() + 120);
        assert_eq!(
            claims["events"],
            serde_json::json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
        );
        assert!(claims.get("nonce").is_none());
    }

    #[test]
    fn canonical_issuer_follows_host_default_and_slug() {
        let url = PublicUrl::parse("https://id.example").unwrap();
        let mut t = Tenant {
            id: crate::model::TenantId::new_v7(),
            slug: DEFAULT_TENANT_SLUG.into(),
            display_name: "d".into(),
            host: None,
            settings: crate::model::TenantSettings::default(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(canonical_issuer(&url, &t), "https://id.example");
        t.slug = "acme".into();
        assert_eq!(canonical_issuer(&url, &t), "https://id.example/t/acme");
        t.host = Some("login.acme.test".into());
        assert_eq!(canonical_issuer(&url, &t), "https://login.acme.test");
    }

    #[test]
    fn logout_token_uses_the_delivery_issuer_before_the_canonical_one() {
        use crate::model::KeyState;
        use crate::service::key::{jwks_from_rows, open_key, tests::sealed_row};
        use anvil_jose::jws::verify_jwt;
        use anvil_jose::keys::Alg;

        let url = PublicUrl::parse("https://id.example").unwrap();
        // A custom-host tenant whose user signed in through /t/{slug}.
        let tenant = Tenant {
            id: crate::model::TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "a".into(),
            host: Some("login.acme.test".into()),
            settings: crate::model::TenantSettings::default(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let mut d = delivery();
        d.issuer = Some("https://id.example/t/acme".into());
        let iss = logout_token_issuer(&url, &tenant, &d);
        assert_eq!(iss, "https://id.example/t/acme");

        let kek = anvil_jose::Kek::generate();
        let row = sealed_row(&kek, KeyState::Active);
        let signer = open_key(&kek, &row).unwrap();
        let now = time::macros::datetime!(2026-11-25 12:05 UTC);
        let token = sign_logout_token(&signer, &iss, &d, "jti-1", now).unwrap();
        let jwt = verify_jwt(&token, &jwks_from_rows(&[row]).unwrap(), &[Alg::RS256]).unwrap();
        assert_eq!(jwt.claims["iss"], "https://id.example/t/acme");

        // Rows from before the issuer column fall back to the canonical (host) issuer.
        d.issuer = None;
        assert_eq!(
            logout_token_issuer(&url, &tenant, &d),
            "https://login.acme.test"
        );
    }

    #[test]
    fn empty_values_count_as_absent() {
        assert_eq!(non_empty(&Some(String::new())), None);
        assert_eq!(non_empty(&None), None);
        assert_eq!(non_empty(&Some("x".into())).as_deref(), Some("x"));
    }
}
