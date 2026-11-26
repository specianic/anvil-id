//! Upstream sign-in orchestration: authorization redirect, callback, token validation and
//! linking (AUTH-07, AUTH-11).
//!
//! # Start
//!
//! [`UpstreamService::start`] is a form POST bound to a flow (flow cookie + CSRF token):
//!
//! - a login flow in its identify step: purpose [`UpstreamPurpose::Login`];
//! - the account page's settings flow (owner, re-authentication within 15 minutes, checked by
//!   `AccountService`): purpose [`UpstreamPurpose::Link`].
//!
//! It resolves the connection (generic OIDC: discovery through the [`UpstreamClient`] port),
//! creates `state` (`{flow_id}.{random}`), a nonce (OIDC) and a PKCE verifier (S256, when the
//! provider uses PKCE; never for Apple) and stores the [`PendingUpstream`] in the flow with a
//! compare-and-swap. The browser gets a binding cookie whose hash is in the pending
//! authorization, and is sent to the provider.
//!
//! # Callback
//!
//! [`UpstreamService::callback`] finds the flow through `state`, checks the `state` hash, the
//! connection and the binding cookie ([`check_callback`]), then takes the pending authorization
//! out of the flow with a compare-and-swap (a replayed callback finds nothing). RFC 9207: when the
//! provider advertises `authorization_response_iss_parameter_supported`, `iss` must equal its
//! issuer. The code is exchanged with the connection secret opened by
//! [`ConnectionService::open_secret`] (Apple: an ES256 client-secret JWT minted per request from
//! the opened `.p8` key). OIDC ID tokens are validated by
//! [`validate_id_token`] (JWKS through the port, refreshed once for an unknown `kid`); GitHub and
//! generic OAuth2 identities come from their profile APIs. The identity then goes through
//! [`link_decision`]:
//!
//! - existing link: sign in; verified + trusted email of a verified local account with tenant
//!   `auto_link`: link (`identity_linked`, mode `auto`) and sign in;
//! - other email match: continue in a fresh login flow holding a [`PendingLink`]; signing in to
//!   an existing account there links it ([`confirm_link`], mode `confirmed`);
//! - no match: just-in-time registration when `upstream_registration` allows it (email verified
//!   only for a verified and trusted upstream email; Apple names from the first-login user JSON).
//!   An account created with an unverified email gets a verification email in the same storage
//!   transaction, like local registration.
//!
//! Under the tenant's `require_verified_email`, a `Login` that resolved to an account whose email
//! is not verified (existing link, or an account just created from an untrusted or unverified
//! upstream email) creates no session: it is audited `upstream_login_failed` with reason
//! `email_not_verified` and restarts the sign-in with `registration.check_email` (just created)
//! or `login.email_not_verified`. The `Link` purpose (account page) is not affected.
//!
//! Generic OIDC: when the ID token carries no `email`, or the connection has `fetch_userinfo`
//! on, the UserInfo endpoint is called through the [`UpstreamClient`] port (the guarded outbound
//! client) with the access token (OIDC Core §5.4 lets a provider return `email` only there). Its
//! `sub` must equal the ID token's (§5.3.2), otherwise the sign-in fails with
//! `userinfo_subject`. Without `fetch_userinfo` only `email` and `email_verified` are taken from
//! it, and a failed call leaves the identity without an email (an existing link still signs in).
//!
//! [`UpstreamService::callback`] reports `binding_proved` once the `state` and the binding
//! cookie matched the pending sign-in: only then may the caller clear the binding cookie, so a
//! forged callback cannot cancel a pending sign-in.
//!
//! An upstream sign-in is single factor (`amr` `[fed]`, pwd `acr`); the flow's effective MFA
//! policy then applies (`FlowService::upstream_primary`). The `Link` purpose links the identity to
//! the settings flow's owner instead (mode `account`); an identity linked to another user is
//! refused.
//!
//! Every failure is audited `upstream_login_failed` with a reason code only (never a token,
//! code, email or provider message) and shown as one generic error.

use std::sync::Arc;

use anvil_jose::encoding::{b64url, b64url_decode, random_token, sha256};
use anvil_jose::{Alg, Kek, SigningKey};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use time::OffsetDateTime;

use super::account::{AccountError, AccountService, SettingsBinding};
use super::audit::AuditService;
use super::connection::ConnectionService;
use super::flow::{
    BindingError, FlowContext, FlowService, StartedFlow, UpstreamPrimary, check_binding,
    self_service_email,
};
use super::session::NewSessionCookie;
use crate::error::CoreError;
use crate::flow::engine::{FlowState, LoginState, LoginStep};
use crate::flow::form::{FormMessage, MessageLevel};
use crate::flow::login::link_confirmation;
use crate::flow::settings::{SettingsState, is_recent_auth};
use crate::flow::upstream::{
    PendingLink, PendingUpstream, PostedResponse, SealedIdentity, UPSTREAM_IDENTITY_PURPOSE,
    UPSTREAM_PKCE_PURPOSE, UPSTREAM_RESPONSE_PURPOSE, UpstreamPurpose, check_callback, is_fresh,
    split_state, upstream_aad, value_hash,
};
use crate::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditOutcome, AuthRequestId, BrowserSession,
    Connection, ConnectionConfig, ConnectionKind, Flow, FlowId, FlowKind, IdentityLinkId,
    NewIdentityLink, NewUser, RegistrationMode, SelfServiceKind, StandardClaims, TenantId, User,
    UserId, UserStatus, normalize_email,
};
use crate::ports::{
    ApiProfile, Clock, CodeExchange, ProviderMetadata, Storage, StorageError, UpstreamClient,
};
use crate::upstream::claims::{
    UpstreamIdentity, UpstreamTokenError, normalise_apple, normalise_github, normalise_oauth2,
    normalise_oidc, validate_id_token,
};
use crate::upstream::linking::{EmailMatch, LinkDecision, LinkInputs, RefuseReason, link_decision};
use crate::upstream::providers::{
    Protocol, ResolvedProvider, apple_client_secret_claims, authorization_url, resolve,
};

/// Message key of every failed upstream sign-in (one generic error).
pub const FAILED_KEY: &str = "upstream.failed";
/// Message key of a failed link from the account page.
pub const LINK_FAILED_KEY: &str = "upstream.link_failed";
/// Message key: the provider identity is already linked to another account.
pub const ALREADY_LINKED_KEY: &str = "upstream.already_linked";

/// Where the browser goes next after a successful start.
#[derive(Debug)]
pub struct UpstreamRedirect {
    /// The provider's authorization URL.
    pub url: String,
    /// Value of the browser-binding cookie (its hash is in the flow).
    pub binding_cookie: SecretString,
}

/// Result of [`UpstreamService::start`].
#[derive(Debug)]
pub enum StartResult {
    Redirect(UpstreamRedirect),
    /// The sign-in could not start (expired flow, provider unreachable, ...): show this.
    Done(Box<UpstreamOutcome>),
}

/// Result of an upstream callback.
#[derive(Debug)]
pub enum UpstreamOutcome {
    /// Signed in: set the session cookie and continue the authorization request (or show the
    /// signed-in page).
    SignedIn {
        cookie: NewSessionCookie,
        continue_to: Option<AuthRequestId>,
    },
    /// Continue in a fresh login flow (set its cookie, render its form): the second-factor
    /// step (`factor_user` set), the enrolment step (`totp` set), the link confirmation
    /// (form id `upstream-link`) or the sign-in form with the generic error. `request` is the
    /// authorization request the new flow continues.
    Continue {
        started: StartedFlow,
        request: Option<AuthRequestId>,
    },
    /// The provider identity is now linked to the signed-in user (account page).
    Linked,
    /// Linking from the account page failed: show the message `key`.
    LinkFailed { key: &'static str },
}

/// Result of [`UpstreamService::callback`].
#[derive(Debug)]
pub struct CallbackResult {
    pub outcome: UpstreamOutcome,
    /// The callback's `state` and the browser's binding cookie matched the pending sign-in
    /// ([`check_callback`] passed). Only then is the binding cookie cleared: a forged or
    /// mismatched callback must not cancel the pending sign-in of the browser it lands in.
    pub binding_proved: bool,
}

/// Query parameters of the callback (`GET`).
#[derive(Debug, Default)]
pub struct CallbackParams {
    pub state: Option<String>,
    pub code: Option<SecretString>,
    /// The provider's `error` (never shown or logged as such).
    pub error: Option<String>,
    pub iss: Option<String>,
}

/// The pending authorization opened from a flow's state.
enum Rest {
    Login(LoginState),
    Settings(SettingsState),
}

impl Rest {
    fn json(&self) -> Result<String, CoreError> {
        match self {
            Self::Login(s) => serde_json::to_string(&FlowState::Login(s.clone()))
                .map_err(|e| CoreError::Internal(format!("flow state encoding failed: {e}"))),
            Self::Settings(s) => Ok(s.to_json()),
        }
    }

    fn with_pending(&self, pending: PendingUpstream) -> Result<String, CoreError> {
        match self {
            Self::Login(s) => Self::Login(LoginState {
                upstream: Some(Box::new(pending)),
                ..s.clone()
            })
            .json(),
            Self::Settings(s) => Ok(s.clone().with_upstream(pending).to_json()),
        }
    }
}

struct Opened {
    pending: Option<PendingUpstream>,
    /// The state without the pending authorization.
    rest: Rest,
}

/// The flow state of a login or settings flow, with its pending authorization taken out.
fn open_pending(flow: &Flow) -> Result<Option<Opened>, CoreError> {
    let corrupt = |e: String| CoreError::Internal(format!("corrupt flow state: {e}"));
    match flow.kind {
        FlowKind::Login => {
            let FlowState::Login(mut s) =
                serde_json::from_str(&flow.state).map_err(|e| corrupt(e.to_string()))?
            else {
                return Err(corrupt("not a login state".into()));
            };
            let pending = s.upstream.take().map(|b| *b);
            Ok(Some(Opened {
                pending,
                rest: Rest::Login(s),
            }))
        }
        FlowKind::Settings => {
            let s = SettingsState::from_json(&flow.state).map_err(|e| corrupt(e.to_string()))?;
            let (s, pending) = s.take_upstream();
            Ok(Some(Opened {
                pending,
                rest: Rest::Settings(s),
            }))
        }
        _ => Ok(None),
    }
}

/// The callback URL registered at the provider (shown in the console by the admin API).
pub fn redirect_uri(issuer: &str, slug: &str) -> String {
    format!("{issuer}/ui/login/upstream/{slug}/callback")
}

/// Seals `value` into the flow `flow` (base64url).
fn seal(
    kek: &Kek,
    purpose: &str,
    tenant: TenantId,
    flow: FlowId,
    value: &[u8],
) -> Result<String, CoreError> {
    kek.seal(purpose, &upstream_aad(tenant, flow), value)
        .map(|s| b64url(&s))
        .map_err(|_| CoreError::Internal("sealing upstream flow data failed".into()))
}

/// Opens a value sealed with [`seal`]; `None` if it does not open (other flow or tenant).
fn open(kek: &Kek, purpose: &str, tenant: TenantId, flow: FlowId, sealed: &str) -> Option<Vec<u8>> {
    let raw = b64url_decode(sealed).ok()?;
    kek.open(purpose, &upstream_aad(tenant, flow), &raw)
        .ok()
        .map(|v| v.to_vec())
}

fn new_link(
    user: UserId,
    conn: &Connection,
    identity: &UpstreamIdentity,
    now: OffsetDateTime,
) -> NewIdentityLink {
    NewIdentityLink {
        id: IdentityLinkId::new_v7(),
        user_id: user,
        connection_id: conn.id,
        subject: identity.subject.clone(),
        email_at_link: identity.email.clone(),
        metadata: identity.metadata.clone(),
        created_at: now,
    }
}

/// Audit reason of an ID-token or profile rejection.
fn token_reason(e: &UpstreamTokenError) -> &'static str {
    match e {
        UpstreamTokenError::Signature | UpstreamTokenError::UnknownKey => "id_token_signature",
        UpstreamTokenError::Issuer => "id_token_issuer",
        UpstreamTokenError::HostedDomain => "hosted_domain",
        UpstreamTokenError::Audience => "id_token_audience",
        UpstreamTokenError::Expired | UpstreamTokenError::IssuedInFuture => "id_token_time",
        UpstreamTokenError::Nonce => "nonce_mismatch",
        UpstreamTokenError::MissingClaim(_) => "claim_missing",
    }
}

/// Links the identity waiting in a login flow to `user`, who just proved their account in that
/// flow (`identity_linked`, mode `confirmed`). A link that can no longer be created (connection
/// gone or disabled, subject linked meanwhile) is audited `upstream_login_failed` and does not
/// stop the sign-in.
pub(crate) async fn confirm_link(
    storage: &dyn Storage,
    kek: &Kek,
    audit: &AuditService,
    cx: &FlowContext<'_>,
    flow: FlowId,
    link: &PendingLink,
    user: UserId,
) -> Result<(), CoreError> {
    let tenant = cx.tenant.id;
    let identity: UpstreamIdentity = open(
        kek,
        UPSTREAM_IDENTITY_PURPOSE,
        tenant,
        flow,
        &link.identity_sealed,
    )
    .and_then(|raw| serde_json::from_slice::<SealedIdentity>(&raw).ok())
    .ok_or_else(|| CoreError::Internal("pending upstream identity does not open".into()))?
    .into();
    let failed = |reason: &'static str| {
        audit.record(
            tenant,
            AuditActor::user(user),
            AuditAction::UpstreamLoginFailed,
            Some(user.to_string()),
            AuditOutcome::Failure,
            cx.ctx,
            AuditDetails::reason(reason),
        )
    };
    let Some(conn) = storage
        .connections()
        .get(tenant, link.connection_id)
        .await?
        .filter(|c| c.enabled)
    else {
        return failed("connection_disabled").await;
    };
    match storage
        .connections()
        .create_link(tenant, &new_link(user, &conn, &identity, audit.clock.now()))
        .await
    {
        Ok(_) => {
            audit
                .record(
                    tenant,
                    AuditActor::user(user),
                    AuditAction::IdentityLinked,
                    Some(user.to_string()),
                    AuditOutcome::Success,
                    cx.ctx,
                    AuditDetails::link(&conn.slug, "confirmed"),
                )
                .await
        }
        Err(StorageError::Conflict(_)) => failed("link_conflict").await,
        Err(e) => Err(e.into()),
    }
}

/// Orchestrates upstream sign-in and linking over the ports.
pub struct UpstreamService<'a> {
    /// Sessions, MFA policy and the login flows the callback continues in.
    pub flows: &'a FlowService,
    /// The account page's settings flows (`Link` purpose).
    pub accounts: &'a AccountService,
    /// Outbound calls to the provider (discovery, JWKS, token, profile APIs).
    pub client: &'a dyn UpstreamClient,
}

/// What a failure answers: the login flow to restart from (its request is kept; only after the
/// callback proved the flow is the browser's), or a link failure.
#[derive(Clone, Copy)]
enum FailTo<'f> {
    Login(Option<&'f Flow>),
    Link,
}

impl UpstreamService<'_> {
    fn storage(&self) -> &dyn Storage {
        self.flows.storage.as_ref()
    }

    fn storage_arc(&self) -> Arc<dyn Storage> {
        Arc::clone(&self.flows.storage)
    }

    fn clock(&self) -> &dyn Clock {
        self.flows.clock.as_ref()
    }

    fn kek(&self) -> &Kek {
        &self.flows.kek
    }

    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage_arc(),
            clock: Arc::clone(&self.flows.clock),
        }
    }

    fn connections(&self) -> ConnectionService {
        ConnectionService {
            storage: self.storage_arc(),
            clock: Arc::clone(&self.flows.clock),
            kek: Arc::clone(&self.flows.kek),
            // Only used here to open connection secrets; never administers SAML connections.
            saml_enabled: false,
            saml_xml: None,
        }
    }

    /// Records `upstream_login_failed` with a reason code only.
    async fn audit_failure(
        &self,
        cx: &FlowContext<'_>,
        conn: Option<&Connection>,
        reason: &'static str,
    ) -> Result<(), CoreError> {
        let details = match conn {
            Some(c) => AuditDetails::connection(&c.slug, c.kind().as_str()),
            None => AuditDetails::empty(),
        };
        self.audit()
            .record(
                cx.tenant.id,
                AuditActor::anonymous(ActorKind::User),
                AuditAction::UpstreamLoginFailed,
                conn.map(|c| c.id.to_string()),
                AuditOutcome::Failure,
                cx.ctx,
                details.with(AuditDetails::reason(reason)),
            )
            .await
    }

    /// Records `upstream_login_failed` (reason code only) and builds the generic answer.
    async fn fail(
        &self,
        cx: &FlowContext<'_>,
        conn: Option<&Connection>,
        to: FailTo<'_>,
        reason: &'static str,
    ) -> Result<UpstreamOutcome, CoreError> {
        self.audit_failure(cx, conn, reason).await?;
        Ok(match to {
            FailTo::Login(old) => UpstreamOutcome::Continue {
                started: self.flows.restart_login_with(cx, old, FAILED_KEY).await?,
                request: old.and_then(|f| f.auth_request_id),
            },
            FailTo::Link => UpstreamOutcome::LinkFailed {
                key: if reason == "already_linked" {
                    ALREADY_LINKED_KEY
                } else {
                    LINK_FAILED_KEY
                },
            },
        })
    }

    /// Starts an upstream sign-in (`Login`, from a login flow) or link (`Link`, from the
    /// account page's settings flow) with connection `slug`. Errors: `Forbidden` (binding, or a
    /// settings flow without the owner's session), `NotFound` (no such enabled connection),
    /// `InvalidRequest` (the login is past its identify step, or changed concurrently).
    pub async fn start(
        &self,
        cx: &FlowContext<'_>,
        binding: &SettingsBinding<'_>,
        slug: &str,
        current: Option<&BrowserSession>,
    ) -> Result<StartResult, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock().now();
        let Some(flow) = self
            .storage()
            .flows()
            .get(tenant, binding.flow_id, now)
            .await?
        else {
            let started = self
                .flows
                .restart_login_with(cx, None, "flow.expired")
                .await?;
            return Ok(StartResult::Done(Box::new(UpstreamOutcome::Continue {
                started,
                request: None,
            })));
        };
        let (purpose, rest) = match flow.kind {
            FlowKind::Login => {
                match check_binding(&flow, binding.cookie_token, binding.csrf_token, now) {
                    Ok(()) => {}
                    Err(BindingError::Expired) => {
                        let started = self
                            .flows
                            .restart_login_with(cx, None, "flow.expired")
                            .await?;
                        return Ok(StartResult::Done(Box::new(UpstreamOutcome::Continue {
                            started,
                            request: None,
                        })));
                    }
                    Err(BindingError::Forbidden) => return Err(CoreError::Forbidden),
                }
                let Some(Opened {
                    rest: Rest::Login(s),
                    ..
                }) = open_pending(&flow)?
                else {
                    return Err(CoreError::Internal("login flow without login state".into()));
                };
                if s.step != LoginStep::Identify || s.step_up_session.is_some() {
                    return Err(CoreError::InvalidRequest(
                        "upstream sign-in is not available in this step".into(),
                    ));
                }
                (UpstreamPurpose::Login, Rest::Login(s))
            }
            FlowKind::Settings => {
                let Some(session) = current else {
                    return Err(CoreError::Forbidden);
                };
                match self
                    .accounts
                    .settings_flow_for(tenant, binding, session)
                    .await
                {
                    Ok((_, s)) => (UpstreamPurpose::Link { user_id: s.user }, Rest::Settings(s)),
                    Err(AccountError::Failure(f)) => {
                        return Ok(StartResult::Done(Box::new(UpstreamOutcome::LinkFailed {
                            key: f.key(),
                        })));
                    }
                    Err(AccountError::Core(e)) => return Err(e),
                }
            }
            _ => return Err(CoreError::Forbidden),
        };
        let to = match purpose {
            UpstreamPurpose::Login => FailTo::Login(Some(&flow)),
            UpstreamPurpose::Link { .. } => FailTo::Link,
        };
        let conn = self
            .storage()
            .connections()
            .get_by_slug(tenant, slug)
            .await?
            .filter(|c| c.enabled)
            .ok_or(CoreError::NotFound)?;
        let metadata = match self.metadata(&conn).await {
            Ok(m) => m,
            Err(reason) => {
                return self
                    .fail(cx, Some(&conn), to, reason)
                    .await
                    .map(|o| StartResult::Done(Box::new(o)));
            }
        };
        // `resolve` refuses SAML connections, which also have no OAuth client id.
        let resolved_and_client = resolve(&conn, metadata.as_ref())
            .ok()
            .and_then(|r| conn.config.client_id().map(|c| (r, c.to_owned())));
        let (resolved, client_id) = match resolved_and_client {
            Some(r) => r,
            None => {
                return self
                    .fail(cx, Some(&conn), to, "configuration")
                    .await
                    .map(|o| StartResult::Done(Box::new(o)));
            }
        };

        let state_param = format!("{}.{}", flow.id, random_token());
        let nonce = (resolved.protocol == Protocol::Oidc).then(random_token);
        let verifier = resolved.use_pkce.then(random_token);
        let challenge = verifier.as_deref().map(|v| b64url(&sha256(v.as_bytes())));
        let pkce_sealed = verifier
            .as_deref()
            .map(|v| {
                seal(
                    self.kek(),
                    UPSTREAM_PKCE_PURPOSE,
                    tenant,
                    flow.id,
                    v.as_bytes(),
                )
            })
            .transpose()?;
        let binding_value = random_token();
        let pending = PendingUpstream {
            connection_id: conn.id,
            state_hash: value_hash(&state_param),
            nonce: nonce.clone(),
            pkce_sealed,
            binding_hash: value_hash(&binding_value),
            purpose,
            started_at: now.unix_timestamp(),
            expected_iss: metadata
                .as_ref()
                .filter(|m| m.authorization_response_iss_parameter_supported)
                .map(|m| m.issuer.clone()),
            response_sealed: None,
        };
        let next = rest.with_pending(pending)?;
        if !self
            .storage()
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &next, now)
            .await?
        {
            return Err(CoreError::InvalidRequest(
                "the sign-in flow changed concurrently".into(),
            ));
        }
        let login_hint = match purpose {
            UpstreamPurpose::Login => self.login_hint(tenant, &flow, now).await?,
            UpstreamPurpose::Link { .. } => None,
        };
        let url = authorization_url(
            &resolved,
            &client_id,
            &redirect_uri(cx.issuer, &conn.slug),
            &state_param,
            nonce.as_deref(),
            challenge.as_deref(),
            login_hint.as_deref(),
        );
        Ok(StartResult::Redirect(UpstreamRedirect {
            url: url.to_string(),
            binding_cookie: SecretString::from(binding_value),
        }))
    }

    /// The flow's authorization request `login_hint`, when it is an email address.
    async fn login_hint(
        &self,
        tenant: TenantId,
        flow: &Flow,
        now: OffsetDateTime,
    ) -> Result<Option<String>, CoreError> {
        let Some(id) = flow.auth_request_id else {
            return Ok(None);
        };
        let request = self
            .storage()
            .grants()
            .get_authorization_request(tenant, id, now)
            .await?;
        Ok(request
            .and_then(|r| r.params.login_hint)
            .and_then(|h| normalize_email(h.trim()).ok()))
    }

    /// Discovery metadata of a generic OIDC connection (`None` for other kinds).
    async fn metadata(&self, conn: &Connection) -> Result<Option<ProviderMetadata>, &'static str> {
        match &conn.config {
            ConnectionConfig::Oidc(o) => match self.client.metadata(&o.issuer).await {
                Ok(m) => Ok(Some(m)),
                Err(_) => Err("discovery_failed"),
            },
            _ => Ok(None),
        }
    }

    /// Keeps an authorization response the provider posted (`form_post`, Apple) sealed in the
    /// flow, if `state` matches a fresh pending authorization of connection `slug` that has no
    /// posted response yet. The browser is then sent to the `GET` callback with `state` only,
    /// where its SameSite=Lax binding cookie is present and the callback is checked as usual.
    /// Returns whether the response was kept.
    pub async fn form_post(
        &self,
        cx: &FlowContext<'_>,
        slug: &str,
        state: &str,
        posted: PostedResponse,
    ) -> Result<bool, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock().now();
        let Some(flow_id) = split_state(state) else {
            return Ok(false);
        };
        let Some(flow) = self.storage().flows().get(tenant, flow_id, now).await? else {
            return Ok(false);
        };
        let Some(Opened {
            pending: Some(mut pending),
            rest,
        }) = open_pending(&flow)?
        else {
            return Ok(false);
        };
        let conn = self
            .storage()
            .connections()
            .get_by_slug(tenant, slug)
            .await?;
        let state_ok = anvil_jose::encoding::ct_eq(
            value_hash(state).as_bytes(),
            pending.state_hash.as_bytes(),
        );
        if !state_ok
            || conn.map(|c| c.id) != Some(pending.connection_id)
            || !is_fresh(&pending, now)
            || pending.response_sealed.is_some()
        {
            return Ok(false);
        }
        let json = serde_json::to_vec(&posted).map_err(|e| {
            CoreError::Internal(format!("encoding the posted response failed: {e}"))
        })?;
        pending.response_sealed = Some(seal(
            self.kek(),
            UPSTREAM_RESPONSE_PURPOSE,
            tenant,
            flow.id,
            &json,
        )?);
        let next = rest.with_pending(pending)?;
        Ok(self
            .storage()
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &next, now)
            .await?)
    }

    /// Handles the provider's return (module docs). `binding_cookie` is the browser's binding
    /// cookie; `current` its session (rotated on sign-in, required for `Link`).
    pub async fn callback(
        &self,
        cx: &FlowContext<'_>,
        slug: &str,
        params: CallbackParams,
        binding_cookie: Option<&str>,
        current: Option<&BrowserSession>,
    ) -> Result<CallbackResult, CoreError> {
        let mut binding_proved = false;
        let outcome = self
            .run_callback(
                cx,
                slug,
                params,
                binding_cookie,
                current,
                &mut binding_proved,
            )
            .await?;
        Ok(CallbackResult {
            outcome,
            binding_proved,
        })
    }

    /// [`Self::callback`]; sets `binding_proved` once [`check_callback`] passed.
    async fn run_callback(
        &self,
        cx: &FlowContext<'_>,
        slug: &str,
        params: CallbackParams,
        binding_cookie: Option<&str>,
        current: Option<&BrowserSession>,
        binding_proved: &mut bool,
    ) -> Result<UpstreamOutcome, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock().now();
        let conn = self
            .storage()
            .connections()
            .get_by_slug(tenant, slug)
            .await?;
        let c = conn.as_ref();
        let Some(state_param) = params.state.as_deref() else {
            return self.fail(cx, c, FailTo::Login(None), "state_missing").await;
        };
        let Some(flow_id) = split_state(state_param) else {
            return self.fail(cx, c, FailTo::Login(None), "state_invalid").await;
        };
        let Some(flow) = self.storage().flows().get(tenant, flow_id, now).await? else {
            return self.fail(cx, c, FailTo::Login(None), "flow_expired").await;
        };
        let Some(opened) = open_pending(&flow)? else {
            return self.fail(cx, c, FailTo::Login(None), "state_invalid").await;
        };
        // Until the callback is proved to belong to this browser, a failure never touches the
        // flow (no restart from it, no deletion).
        let unproved = match opened.rest {
            Rest::Login(_) => FailTo::Login(None),
            Rest::Settings(_) => FailTo::Link,
        };
        let Some(pending) = opened.pending else {
            return self.fail(cx, c, unproved, "replayed").await;
        };
        if let Err(reject) =
            check_callback(&pending, state_param, binding_cookie, c.map(|c| c.id), now)
        {
            return self.fail(cx, c, unproved, reject.reason()).await;
        }
        *binding_proved = true;
        // Single use: take the pending authorization out before anything else.
        if !self
            .storage()
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &opened.rest.json()?, now)
            .await?
        {
            return self.fail(cx, c, unproved, "replayed").await;
        }
        let to = match opened.rest {
            Rest::Login(_) => FailTo::Login(Some(&flow)),
            Rest::Settings(_) => FailTo::Link,
        };
        let Some(conn) = conn.as_ref().filter(|c| c.enabled) else {
            return self.fail(cx, c, to, "connection_disabled").await;
        };
        let posted = match pending.response_sealed.as_deref() {
            Some(sealed) => {
                match open(
                    self.kek(),
                    UPSTREAM_RESPONSE_PURPOSE,
                    tenant,
                    flow.id,
                    sealed,
                )
                .and_then(|raw| serde_json::from_slice::<PostedResponse>(&raw).ok())
                {
                    Some(p) => Some(p),
                    None => return self.fail(cx, Some(conn), to, "state_invalid").await,
                }
            }
            None => None,
        };
        let (code, error, iss, user_json) = match posted {
            Some(p) => (p.code.map(SecretString::from), p.error, p.iss, p.user),
            None => (params.code, params.error, params.iss, None),
        };
        if error.is_some() {
            return self.fail(cx, Some(conn), to, "provider_error").await;
        }
        let Some(code) = code.filter(|c| !c.expose_secret().is_empty()) else {
            return self.fail(cx, Some(conn), to, "code_missing").await;
        };
        let identity = match self
            .identity(
                cx,
                flow.id,
                conn,
                &pending,
                code,
                user_json.as_deref(),
                iss.as_deref(),
            )
            .await
        {
            Ok(i) => i,
            Err(reason) => return self.fail(cx, Some(conn), to, reason).await,
        };
        match (pending.purpose, opened.rest) {
            (UpstreamPurpose::Login, Rest::Login(state)) => {
                self.sign_in(cx, &flow, state, conn, identity, current)
                    .await
            }
            (UpstreamPurpose::Link { user_id }, Rest::Settings(s)) if s.user == user_id => {
                self.link(cx, conn, identity, user_id, current).await
            }
            _ => self.fail(cx, Some(conn), to, "purpose_mismatch").await,
        }
    }

    /// Exchanges the code and turns the provider's answer into one validated identity. `Err` is
    /// the audit reason.
    #[expect(
        clippy::too_many_arguments,
        reason = "the callback's checked inputs, passed through once"
    )]
    async fn identity(
        &self,
        cx: &FlowContext<'_>,
        flow: FlowId,
        conn: &Connection,
        pending: &PendingUpstream,
        code: SecretString,
        user_json: Option<&str>,
        iss: Option<&str>,
    ) -> Result<UpstreamIdentity, &'static str> {
        let tenant = cx.tenant.id;
        let metadata = self.metadata(conn).await?;
        // RFC 9207 §2.4: a provider that advertises `iss` must send it, and it must match.
        let known_issuer = pending
            .expected_iss
            .as_deref()
            .or(metadata.as_ref().map(|m| m.issuer.as_str()));
        match (pending.expected_iss.as_deref(), iss, known_issuer) {
            (Some(expected), got, _) if got != Some(expected) => return Err("iss_mismatch"),
            (None, Some(got), Some(known)) if got != known => return Err("iss_mismatch"),
            _ => {}
        }
        let resolved = resolve(conn, metadata.as_ref()).map_err(|_| "configuration")?;
        // SAML connections have no OAuth client (and `resolve` already refused them).
        let client_id = conn.config.client_id().ok_or("configuration")?;
        let client_secret = if conn.kind() == ConnectionKind::Apple {
            Some(
                self.apple_client_secret(conn, &resolved)
                    .map_err(|_| "configuration")?,
            )
        } else {
            self.connections()
                .open_secret(conn)
                .map_err(|_| "configuration")?
        };
        let code_verifier = match pending.pkce_sealed.as_deref() {
            Some(sealed) => {
                let raw = open(self.kek(), UPSTREAM_PKCE_PURPOSE, tenant, flow, sealed)
                    .ok_or("state_invalid")?;
                let v = String::from_utf8(raw).map_err(|_| "state_invalid")?;
                Some(SecretString::from(v))
            }
            None => None,
        };
        let tokens = self
            .client
            .exchange_code(&CodeExchange {
                token_endpoint: resolved.token_endpoint.clone(),
                client_id: client_id.to_owned(),
                client_secret,
                auth: resolved.token_auth,
                code,
                redirect_uri: redirect_uri(cx.issuer, &conn.slug),
                code_verifier,
            })
            .await
            .map_err(|_| "exchange_failed")?;
        let trust = conn.trust_email_verified;
        let profile_failed = |_: crate::ports::UpstreamError| "profile_failed";
        match resolved.protocol {
            Protocol::Oidc => {
                let id_token = tokens.id_token.as_deref().ok_or("id_token_missing")?;
                let mut claims = self
                    .validate(&resolved, id_token, client_id, pending.nonce.as_deref())
                    .await?;
                if conn.kind() == ConnectionKind::Apple {
                    return normalise_apple(&claims, user_json, trust)
                        .map_err(|e| token_reason(&e));
                }
                // Generic OIDC: UserInfo when configured, or as a fallback when the ID token has
                // no email (OIDC Core §5.4 allows `email` in UserInfo only).
                let fetch = match &conn.config {
                    ConnectionConfig::Oidc(o) if o.fetch_userinfo => Some(true),
                    ConnectionConfig::Oidc(_) if !claims.contains_key("email") => Some(false),
                    _ => None,
                };
                if let Some(configured) = fetch
                    && let Some(url) = resolved.userinfo_endpoint.as_deref()
                {
                    let info = match self
                        .client
                        .get_json(url, &tokens.access_token, ApiProfile::Standard)
                        .await
                    {
                        Ok(info) => Some(info),
                        Err(e) if configured => return Err(profile_failed(e)),
                        // The fallback is best effort: without an email the link decision
                        // still signs in through an existing link.
                        Err(_) => None,
                    };
                    if let Some(info) = info {
                        // OIDC Core §5.3.2: the UserInfo `sub` must equal the ID token's.
                        if info.get("sub") != claims.get("sub") {
                            return Err("userinfo_subject");
                        }
                        let keys: &[&str] = if configured {
                            &[
                                "email",
                                "email_verified",
                                "name",
                                "given_name",
                                "family_name",
                            ]
                        } else {
                            // The address and its verification come from UserInfo together.
                            claims.remove("email_verified");
                            &["email", "email_verified"]
                        };
                        for key in keys {
                            if let Some(v) = info.get(*key) {
                                claims.insert((*key).to_owned(), v.clone());
                            }
                        }
                    }
                }
                normalise_oidc(&claims, &resolved, trust).map_err(|e| token_reason(&e))
            }
            Protocol::OAuth2 => {
                let url = resolved
                    .userinfo_endpoint
                    .as_deref()
                    .ok_or("configuration")?;
                let profile = self
                    .client
                    .get_json(url, &tokens.access_token, resolved.api_profile)
                    .await
                    .map_err(profile_failed)?;
                match &conn.config {
                    ConnectionConfig::Oauth2(o) => {
                        normalise_oauth2(&profile, &o.mapping, trust).map_err(|e| token_reason(&e))
                    }
                    _ => {
                        let base = resolved.api_base_url.as_deref().ok_or("configuration")?;
                        let emails = self
                            .client
                            .get_json(
                                &format!("{base}/user/emails"),
                                &tokens.access_token,
                                resolved.api_profile,
                            )
                            .await
                            .unwrap_or(Value::Array(vec![]));
                        normalise_github(&profile, &emails, trust).map_err(|e| token_reason(&e))
                    }
                }
            }
        }
    }

    /// Validates an ID token against the provider's JWKS; an unknown `kid` refreshes the JWKS
    /// once (key rotation).
    async fn validate(
        &self,
        resolved: &ResolvedProvider,
        id_token: &str,
        client_id: &str,
        nonce: Option<&str>,
    ) -> Result<serde_json::Map<String, Value>, &'static str> {
        let uri = resolved.jwks_uri.as_deref().ok_or("configuration")?;
        let now = self.clock().now();
        let jwks_failed = |_: crate::ports::UpstreamError| "jwks_failed";
        let jwks = self.client.jwks(uri, false).await.map_err(jwks_failed)?;
        match validate_id_token(id_token, &jwks, resolved, client_id, nonce, now) {
            Err(UpstreamTokenError::UnknownKey) => {
                let jwks = self.client.jwks(uri, true).await.map_err(jwks_failed)?;
                validate_id_token(id_token, &jwks, resolved, client_id, nonce, now)
            }
            other => other,
        }
        .map_err(|e| token_reason(&e))
    }

    /// Apple's client secret: an ES256 JWT signed with the opened `.p8` key, minted per token
    /// request (`aud` = the resolved Apple audience, never a fallback).
    fn apple_client_secret(
        &self,
        conn: &Connection,
        resolved: &ResolvedProvider,
    ) -> Result<SecretString, CoreError> {
        let ConnectionConfig::Social(social) = &conn.config else {
            return Err(CoreError::Internal(
                "Apple connection is not a social preset".into(),
            ));
        };
        let apple = social.apple.as_ref().ok_or_else(|| {
            CoreError::Internal("Apple connection without team and key id".into())
        })?;
        let audience = resolved
            .apple_audience
            .as_deref()
            .ok_or_else(|| CoreError::Internal("Apple connection without an audience".into()))?;
        let pem = self
            .connections()
            .open_secret(conn)?
            .ok_or_else(|| CoreError::Internal("Apple connection without a key".into()))?;
        let key = SigningKey::from_pkcs8_pem(&apple.key_id, Alg::ES256, pem.expose_secret())
            .map_err(|_| CoreError::Internal("the Apple key is not an ES256 PKCS#8 key".into()))?;
        let claims = apple_client_secret_claims(
            &apple.team_id,
            &social.client_id,
            audience,
            self.clock().now(),
        );
        key.sign_jwt(None, &claims)
            .map(SecretString::from)
            .map_err(|_| CoreError::Internal("signing the Apple client secret failed".into()))
    }

    /// `Login` purpose: the link decision, then sign-in (with the MFA policy), link
    /// confirmation or just-in-time registration.
    async fn sign_in(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        state: LoginState,
        conn: &Connection,
        identity: UpstreamIdentity,
        current: Option<&BrowserSession>,
    ) -> Result<UpstreamOutcome, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock().now();
        let to = FailTo::Login(Some(flow));
        let storage = self.storage();
        let link = storage
            .connections()
            .find_link(tenant, conn.id, &identity.subject)
            .await?;
        let link_user = match &link {
            Some(l) => storage.users().get(tenant, l.user_id).await?,
            None => None,
        };
        let email = identity
            .email
            .as_deref()
            .and_then(|e| normalize_email(e).ok());
        let matched = match (&link, &email) {
            (None, Some(e)) => storage.users().get_by_email(tenant, e).await?,
            _ => None,
        };
        let settings = &cx.tenant.settings;
        let decision = link_decision(&LinkInputs {
            identity: &identity,
            existing_link: link.as_ref(),
            link_user_active: link_user
                .as_ref()
                .is_some_and(|u| u.status == UserStatus::Active),
            email_match: matched.as_ref().map(|u| EmailMatch {
                user_id: u.id,
                email_verified: u.email_verified,
            }),
            auto_link_enabled: settings.auto_link,
            connection_kind: conn.kind(),
            registration_allowed: settings
                .upstream_registration
                .unwrap_or(settings.registration == RegistrationMode::Open),
        });
        let mut just_created = false;
        let user: User = match decision {
            LinkDecision::SignIn(_) => {
                let (Some(l), Some(u)) = (link, link_user) else {
                    return Err(CoreError::Internal(
                        "sign-in decision without a link".into(),
                    ));
                };
                storage.connections().touch_link(tenant, l.id, now).await?;
                u
            }
            LinkDecision::AutoLink(id) => {
                let Some(u) = matched.filter(|u| u.id == id && u.status == UserStatus::Active)
                else {
                    return self.fail(cx, Some(conn), to, "inactive").await;
                };
                match storage
                    .connections()
                    .create_link(tenant, &new_link(u.id, conn, &identity, now))
                    .await
                {
                    Ok(_) => {}
                    Err(StorageError::Conflict(_)) => {
                        return self.fail(cx, Some(conn), to, "link_conflict").await;
                    }
                    Err(e) => return Err(e.into()),
                }
                self.audit()
                    .record(
                        tenant,
                        AuditActor::user(u.id),
                        AuditAction::IdentityLinked,
                        Some(u.id.to_string()),
                        AuditOutcome::Success,
                        cx.ctx,
                        AuditDetails::link(&conn.slug, "auto"),
                    )
                    .await?;
                u
            }
            LinkDecision::PendingLink { candidate } => {
                let candidate = matched.filter(|u| candidate == Some(u.id));
                return self
                    .pending_link(cx, flow, conn, &identity, candidate.as_ref())
                    .await;
            }
            LinkDecision::JitCreate { email_verified } => {
                let Some(email) = email else {
                    return self.fail(cx, Some(conn), to, "email_missing").await;
                };
                let new_user = NewUser {
                    id: UserId::new_v7(),
                    email,
                    email_verified,
                    username: None,
                    claims: StandardClaims {
                        name: identity.name.clone(),
                        given_name: identity.given_name.clone(),
                        family_name: identity.family_name.clone(),
                        ..StandardClaims::default()
                    },
                    status: UserStatus::Active,
                    created_at: now,
                };
                // An unverified address gets its verification email in the same transaction,
                // like local registration.
                let verification = if email_verified {
                    None
                } else {
                    Some(self_service_email(
                        self.kek(),
                        cx,
                        SelfServiceKind::Verification,
                        new_user.id,
                        &new_user.email,
                        now,
                    )?)
                };
                let created = storage
                    .connections()
                    .create_user_with_link(
                        tenant,
                        &new_user,
                        &new_link(new_user.id, conn, &identity, now),
                        verification.as_ref().map(|(t, _)| t),
                        verification.as_ref().map(|(_, e)| e),
                        None,
                    )
                    .await;
                let u = match created {
                    Ok(u) => u,
                    Err(StorageError::Conflict(_)) => {
                        return self.fail(cx, Some(conn), to, "conflict").await;
                    }
                    Err(e) => return Err(e.into()),
                };
                self.audit()
                    .record(
                        tenant,
                        AuditActor::user(u.id),
                        AuditAction::UserRegistered,
                        Some(u.id.to_string()),
                        AuditOutcome::Success,
                        cx.ctx,
                        AuditDetails::connection(&conn.slug, conn.kind().as_str()),
                    )
                    .await?;
                just_created = true;
                u
            }
            LinkDecision::Refuse(RefuseReason::Inactive) => {
                return self.fail(cx, Some(conn), to, "inactive").await;
            }
            LinkDecision::Refuse(RefuseReason::NoAccount) => {
                return self.fail(cx, Some(conn), to, "no_account").await;
            }
        };
        if cx.tenant.settings.require_verified_email && !user.email_verified {
            // Like a password or passkey sign-in: no session until the address is verified.
            self.audit_failure(cx, Some(conn), "email_not_verified")
                .await?;
            let message = if just_created {
                FormMessage::new(MessageLevel::Info, "registration.check_email")
            } else {
                FormMessage::error("login.email_not_verified")
            };
            return Ok(UpstreamOutcome::Continue {
                started: self
                    .flows
                    .restart_login_with_message(cx, Some(flow), message)
                    .await?,
                request: flow.auth_request_id,
            });
        }
        Ok(
            match self
                .flows
                .upstream_primary(cx, flow, state, &user, current.map(|s| s.id))
                .await?
            {
                UpstreamPrimary::SignedIn {
                    cookie,
                    continue_to,
                } => UpstreamOutcome::SignedIn {
                    cookie,
                    continue_to,
                },
                UpstreamPrimary::Continue(started) => UpstreamOutcome::Continue {
                    started,
                    request: flow.auth_request_id,
                },
            },
        )
    }

    /// Continues in a fresh login flow holding the sealed identity: the user signs in to an
    /// existing account to link it. `candidate` (and its email) only when the decision exposed
    /// it (verified and trusted upstream email).
    async fn pending_link(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        conn: &Connection,
        identity: &UpstreamIdentity,
        candidate: Option<&User>,
    ) -> Result<UpstreamOutcome, CoreError> {
        let id = FlowId::new_v7();
        let json = serde_json::to_vec(&SealedIdentity::from(identity))
            .map_err(|e| CoreError::Internal(format!("encoding the identity failed: {e}")))?;
        let link = PendingLink {
            connection_id: conn.id,
            identity_sealed: seal(
                self.kek(),
                UPSTREAM_IDENTITY_PURPOSE,
                cx.tenant.id,
                id,
                &json,
            )?,
            candidate_user: candidate.map(|u| u.id),
            provider_name: conn.display_name.clone(),
            candidate_email: candidate.map(|u| u.email.clone()),
        };
        let (state, form) = link_confirmation(link);
        let started = self
            .flows
            .continue_login(cx, Some(flow), id, &state, form)
            .await?;
        Ok(UpstreamOutcome::Continue {
            started,
            request: flow.auth_request_id,
        })
    }

    /// `Link` purpose: link the identity to `user_id`, who must still be signed in in this
    /// browser with a recent authentication.
    async fn link(
        &self,
        cx: &FlowContext<'_>,
        conn: &Connection,
        identity: UpstreamIdentity,
        user_id: UserId,
        current: Option<&BrowserSession>,
    ) -> Result<UpstreamOutcome, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock().now();
        let signed_in = current.is_some_and(|s| {
            s.user_id == user_id
                && s.tenant_id == tenant
                && s.revoked_at.is_none()
                && is_recent_auth(s.auth_time, now)
        });
        if !signed_in {
            return self
                .fail(cx, Some(conn), FailTo::Link, "reauth_required")
                .await;
        }
        let connections = self.storage().connections();
        match connections
            .find_link(tenant, conn.id, &identity.subject)
            .await?
        {
            Some(l) if l.user_id == user_id => {
                connections.touch_link(tenant, l.id, now).await?;
                return Ok(UpstreamOutcome::Linked);
            }
            Some(_) => {
                return self
                    .fail(cx, Some(conn), FailTo::Link, "already_linked")
                    .await;
            }
            None => {}
        }
        match connections
            .create_link(tenant, &new_link(user_id, conn, &identity, now))
            .await
        {
            Ok(_) => {}
            Err(StorageError::Conflict(_)) => {
                return self
                    .fail(cx, Some(conn), FailTo::Link, "already_linked")
                    .await;
            }
            Err(e) => return Err(e.into()),
        }
        self.audit()
            .record(
                tenant,
                AuditActor::user(user_id),
                AuditAction::IdentityLinked,
                Some(user_id.to_string()),
                AuditOutcome::Success,
                cx.ctx,
                AuditDetails::link(&conn.slug, "account"),
            )
            .await?;
        Ok(UpstreamOutcome::Linked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_matches_the_console_format() {
        assert_eq!(
            redirect_uri("https://id.example/t/acme", "google"),
            "https://id.example/t/acme/ui/login/upstream/google/callback"
        );
    }

    #[test]
    fn sealed_values_open_only_in_their_flow_and_tenant() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let f = FlowId::new_v7();
        let sealed = seal(&kek, UPSTREAM_PKCE_PURPOSE, t, f, b"verifier").unwrap();
        assert_eq!(
            open(&kek, UPSTREAM_PKCE_PURPOSE, t, f, &sealed).as_deref(),
            Some(&b"verifier"[..])
        );
        assert_eq!(
            open(&kek, UPSTREAM_PKCE_PURPOSE, t, FlowId::new_v7(), &sealed),
            None
        );
        assert_eq!(
            open(&kek, UPSTREAM_PKCE_PURPOSE, TenantId::new_v7(), f, &sealed),
            None
        );
        assert_eq!(open(&kek, UPSTREAM_IDENTITY_PURPOSE, t, f, &sealed), None);
        assert_eq!(open(&kek, UPSTREAM_PKCE_PURPOSE, t, f, "!!"), None);
    }

    #[test]
    fn token_errors_map_to_fixed_reasons() {
        assert_eq!(token_reason(&UpstreamTokenError::Nonce), "nonce_mismatch");
        assert_eq!(
            token_reason(&UpstreamTokenError::UnknownKey),
            "id_token_signature"
        );
        assert_eq!(
            token_reason(&UpstreamTokenError::MissingClaim("sub")),
            "claim_missing"
        );
    }
}
