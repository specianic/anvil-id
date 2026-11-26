//! The authorization endpoint service: validate, decide on the session and on consent, persist
//! requests that need a login or the consent screen, issue codes and resume after either.
//!
//! Consent (OIDC-13) is decided after the session: [`ConsentService::decide`] skips it for
//! `skip_first_party` clients and for grants covering the requested scopes, forces it for
//! `prompt=consent`, and answers `consent_required` for `prompt=none`. When it is needed the
//! request is stored and the user is sent to the consent screen ([`AuthorizeOutcome::Consent`]);
//! the screen's decision continues the request with [`AuthorizeService::finish_consent`].
//!
//! Step-up (AUTH-08): the effective MFA policy (strictest of tenant and client) and the
//! request's `acr` ([`requested_acr`]) go into [`decide`]. A usable single-factor session that
//! must add a second factor answers [`AuthorizeOutcome::Login`]; the login flow sees the stored
//! request and the session and starts at the second-factor (or enrolment) step for that user,
//! then upgrades the session in place (`FlowService::start_login`). `resume` decides again, so an
//! essential `acr` that is still unmet answers `unmet_authentication_requirements` through the
//! response mode, and a voluntary one issues the lower `acr` truthfully.
//!
//! Account chooser and registration (OIDC-14): `prompt=select_account` with a usable session
//! answers [`AuthorizeOutcome::SelectAccount`]; the chooser page opens a bound flow with
//! [`AuthorizeService::start_select_account`] and submits [`AuthorizeService::choose_account`]
//! (continue as the session's user, or sign in as someone else). `prompt=create` (Initiating
//! User Registration 1.0, only for tenants with open registration, see
//! [`crate::oauth::authorize_request::supported_prompt_values`]) answers
//! [`AuthorizeOutcome::Register`] whether or not a session exists; registering signs the user in
//! and the request resumes through [`AuthorizeService::resume`]. When the tenant requires email
//! verification before sign-in, the request cannot resume: the RP gets no answer until the user
//! verifies and signs in, and the stored request expires normally.
//!
//! The chooser flow is a `FlowKind::Consent` flow in its connected-apps form (bound to the
//! user, no pending consent), additionally bound to the request through the flow's
//! `auth_request_id`. That state can never approve a consent (the consent screen refuses a flow
//! without a pending request), and it grants nothing beyond what the same user's own pages allow.
//!
//! Organizations (ORG-02): right before a code is issued (after the session, step-up and consent
//! decisions) the active org is resolved from the client's organization policy, the request's
//! `organization` parameter and the user's memberships
//! ([`resolve_active_org`], [`bind_active_org`])
//! and bound to the code and its token family. It never comes from a cookie or the session.
//! When the client requires an org and the user belongs to several, none was requested and the
//! request is interactive, the request is stored and the user picks one on the organization
//! switcher ([`AuthorizeOutcome::SelectOrganization`], [`AuthorizeService::start_select_organization`],
//! [`AuthorizeService::choose_organization`]). The switcher lists only the user's own
//! memberships; the choice is written into the stored request's `organization` parameter, so the
//! normal resolution selects it. Switching orgs later is a new authorization request with
//! `organization=<other>` (also with `prompt=none` and an existing session); a token family keeps
//! the org it was issued for.
//!
//! The effective MFA policy is the strictest of tenant, active org and client
//! ([`effective_policy_for`]): once the session's user, the request's `organization` parameter
//! and the client's org policy select an org, its `mfa_policy` takes part in the step-up decision
//! before a code is issued.
//!
//! Pushed authorization requests (OIDC-18, RFC 9126): a `request_uri` with the PAR URN prefix is
//! handled before any parameter validation. [`AuthorizeService::resume_pushed_request`] is the
//! single resume path (also used by the native headless start): it consumes the pushed request
//! once ([`ParService::consume`]), checks the `client_id`, re-checks the client's current policy
//! ([`recheck_client_policy`]) and stores the request, which then continues like any stored
//! request. Every other front-channel parameter is ignored. A client with
//! `require_pushed_authorization_requests`, or any client of a tenant with
//! `par.require_pushed_authorization_requests`, is refused a plain request (`invalid_request`).
//!
//! The protocol decisions live in pure functions ([`crate::oauth::authorize_request::validate`],
//! [`crate::oauth::decision::decide`], [`build_code`], [`AuthorizationResponse`]);
//! this service only orchestrates the ports. It is tested end to end over HTTP on both backends.

use std::sync::Arc;

use anvil_jose::{ExpiryCheck, Jwks, verify_op_token_algs};
use secrecy::{ExposeSecret, SecretString};
use time::{Duration, OffsetDateTime};

use anvil_jose::encoding::{random_token, secret_hash};

use super::consent::{ConsentService, StartedConsentFlow};
use super::flow::{BindingError, FLOW_LIFETIME, check_binding};
use super::key_rotation::enabled_algs;
use crate::error::CoreError;
use crate::flow::consent::{ConsentDecision, ConsentState, requested_scopes};
use crate::flow::login::SecondFactorMethods;
use crate::model::{
    AuthRequestId, AuthorizationParams, BrowserSession, Client, FlowId, FlowKind, GrantType,
    NewAuthorizationCode, NewAuthorizationRequest, NewFlow, NewTokenFamily, OrgClientPolicy, OrgId,
    Organization, SecretHash, Tenant, TenantId, TokenFamilyId, UserId, UserStatus,
};
use crate::oauth::authorize_request::{AuthorizeError, PROMPT_CREATE, RawParams, validate};
use crate::oauth::decision::{MfaContext, SessionDecision, decide, requested_acr, session_is_mfa};
use crate::oauth::par::{is_pushed_request_uri, recheck_client_policy};
use crate::oauth::redirect::redirect_matches;
use crate::oauth::response_mode::AuthorizationResponse;
use crate::policy::mfa::effective_policy_for;
use crate::policy::org_claims::{ActiveOrg, resolve_active_org};
use crate::ports::{ClientMetadataFetcher, Clock, Storage};
use crate::service::client::{ClientPolicyView, validate_client_policy};
use crate::service::client_resolver::{ClientResolver, is_url_client_id};
use crate::service::par::{ParService, PushedRequestRefused};

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
    /// Send the signed-in user to the consent screen for the stored request, then call
    /// [`AuthorizeService::finish_consent`] with the decision.
    Consent { request_id: AuthRequestId },
    /// `prompt=select_account` with a session: send the user to the account chooser, which calls
    /// [`AuthorizeService::choose_account`].
    SelectAccount { request_id: AuthRequestId },
    /// The client requires an org and the user belongs to several, none requested: send the
    /// user to the organization switcher, which calls [`AuthorizeService::choose_organization`].
    SelectOrganization { request_id: AuthRequestId },
    /// `prompt=create`: send the user to the registration page for the stored request; the
    /// request resumes through [`AuthorizeService::resume`] once the new account is signed in.
    Register { request_id: AuthRequestId },
    /// Show an error page; never redirect. `error_key` is one of `invalid_request`,
    /// `unknown_client`, `redirect_uri_mismatch`, `flow_expired`.
    ErrorPage {
        error_key: &'static str,
        detail: String,
    },
}

/// A pushed authorization request that was consumed, matched to its client, re-checked against
/// the client's current policy and stored as an authorization request
/// ([`AuthorizeService::resume_pushed_request`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumedPushedRequest {
    pub request_id: AuthRequestId,
    /// The client as registered now.
    pub client: Client,
    /// The pushed parameters after the policy re-check.
    pub params: AuthorizationParams,
}

/// The JSON completion of a stored authorization request ([`AuthorizeService::complete`], the
/// headless native mode): the authorization response's parameters instead of a redirect.
pub enum Completion {
    /// A code was issued, by the same issuance as the redirect response (stored hash, PKCE
    /// challenge, token family). The client redeems it at the token endpoint with its
    /// `code_verifier`.
    Code {
        code: SecretString,
        iss: String,
        state: Option<String>,
    },
    /// The authorization ended with an error for the client (the redirect response's `error`,
    /// `error_description`, `state` and `iss`).
    Error {
        error: String,
        error_description: Option<String>,
        state: Option<String>,
        iss: String,
    },
    /// The request needs a page (consent, account or organization choice, step-up, registration)
    /// or ended on an error page: no code.
    Interaction(AuthorizeOutcome),
}

impl std::fmt::Debug for Completion {
    /// The code is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code { iss, state, .. } => f
                .debug_struct("Code")
                .field("code", &"[redacted]")
                .field("iss", iss)
                .field("state", state)
                .finish(),
            Self::Error {
                error,
                error_description,
                state,
                iss,
            } => f
                .debug_struct("Error")
                .field("error", error)
                .field("error_description", error_description)
                .field("state", state)
                .field("iss", iss)
                .finish(),
            Self::Interaction(o) => f.debug_tuple("Interaction").field(o).finish(),
        }
    }
}

impl Completion {
    /// The completion of an authorization outcome: a response's parameters (a code or an error),
    /// anything else needs a page.
    pub fn of(outcome: AuthorizeOutcome) -> Self {
        let AuthorizeOutcome::Respond(response) = outcome else {
            return Self::Interaction(outcome);
        };
        let get = |name: &str| {
            response
                .params
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        let iss = get("iss").unwrap_or_default();
        let state = get("state");
        match (get("code"), get("error")) {
            (Some(code), _) => Self::Code {
                code: SecretString::from(code),
                iss,
                state,
            },
            (None, error) => Self::Error {
                error: error.unwrap_or_else(|| "server_error".to_owned()),
                error_description: get("error_description"),
                state,
                iss,
            },
        }
    }
}

/// Whether `client` may start a native headless sign-in (research Pitfall 9: never a password
/// API for third parties): flagged `headless_native` by an administrator and still satisfying
/// every rule of [`validate_client_policy`] for that flag (administrator-registered, not an
/// agent, first-party consent, PKCE required). Checked again at use, so a stored client that
/// bypassed the write-path validation is still refused.
pub fn native_eligible(client: &Client) -> bool {
    let view = ClientPolicyView {
        consent_mode: client.consent_mode,
        require_pkce: client.require_pkce,
        client_kind: client.client_kind,
        headless_native: client.headless_native,
    };
    client.headless_native
        && client.grant_types.contains(&GrantType::AuthorizationCode)
        && validate_client_policy(&view, client.registration_source).is_ok()
}

/// Why a native headless start was refused ([`AuthorizeService::start_native`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeStartRefused {
    /// The client is unknown or not eligible ([`native_eligible`]). The `request_uri` was not
    /// consumed when the client was refused before the resume.
    NotEligible,
    /// The pushed request is unusable (unknown, expired, used, another client's) or failed its
    /// policy re-check: the outcome `/authorize` would show.
    Pushed(AuthorizeOutcome),
    /// The pushed request carries no PKCE challenge.
    PkceRequired,
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

/// The second factors `user` has: TOTP, unused recovery codes (only with TOTP) and passkeys.
/// The one place that answers "does this user have a second factor"
/// ([`SecondFactorMethods::any`]) for the login engine, the step-up path and [`mfa_context`].
pub(crate) async fn second_factor_methods(
    storage: &dyn Storage,
    tenant: TenantId,
    user: UserId,
) -> Result<SecondFactorMethods, CoreError> {
    let users = storage.users();
    let totp = users.totp(tenant, user).await?.is_some();
    let recovery = totp && users.recovery_codes_remaining(tenant, user).await? > 0;
    let passkey = !users.passkeys(tenant, user).await?.is_empty();
    Ok(SecondFactorMethods {
        totp,
        recovery,
        passkey,
    })
}

/// The active-org decision for `user` at `client` with the request's `organization` parameter
/// ([`resolve_active_org`] over the user's memberships). The one place that loads the
/// memberships for an authorization (MFA policy and the org bound to the code).
async fn active_org_of(
    storage: &dyn Storage,
    tenant: TenantId,
    client: &Client,
    params: &AuthorizationParams,
    user: UserId,
) -> Result<ActiveOrg, CoreError> {
    let memberships = if client.organization.is_off() {
        // `off` never selects an org, whatever the memberships.
        Vec::new()
    } else {
        storage
            .organizations()
            .memberships_of_user(tenant, user)
            .await?
    };
    Ok(resolve_active_org(
        client.organization,
        params.organization.as_deref(),
        &memberships,
    ))
}

/// The org MFA policy taking part in the effective policy: the selected org's own policy; none
/// while no org is selected (the switcher, a refusal, or no org at all).
fn org_mfa_policy(active: &ActiveOrg) -> Option<crate::model::MfaPolicy> {
    match active {
        ActiveOrg::Selected(org) => org.mfa_policy,
        _ => None,
    }
}

/// The MFA inputs of a request for `session`'s user: effective policy of tenant, active org and
/// client ([`effective_policy_for`]; the org once the session's user and the request select
/// one), the request's `acr`, and (only when a single-factor session would be checked) whether
/// the user has a second factor (TOTP or a passkey, [`second_factor_methods`]).
pub(crate) async fn mfa_context(
    storage: &dyn Storage,
    tenant: &Tenant,
    client: Option<&Client>,
    params: &AuthorizationParams,
    session: Option<&BrowserSession>,
) -> Result<MfaContext, CoreError> {
    let org = match (client, session) {
        (Some(c), Some(s)) => {
            org_mfa_policy(&active_org_of(storage, tenant.id, c, params, s.user_id).await?)
        }
        _ => None,
    };
    let mut ctx = MfaContext {
        policy: effective_policy_for(
            tenant.settings.mfa_policy,
            org,
            client.and_then(|c| c.mfa_policy),
        ),
        acr: requested_acr(params),
        user_has_factor: false,
    };
    if let Some(s) = session
        && !session_is_mfa(s)
        && ctx.wants_mfa()
    {
        ctx.user_has_factor = second_factor_methods(storage, tenant.id, s.user_id)
            .await?
            .any();
    }
    Ok(ctx)
}

/// The account chooser's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountChoice {
    /// Continue as the session's user (consent and step-up still apply).
    Continue,
    /// Sign in as someone else: the login page for the request. Signing in as another user
    /// revokes the current session (session switch).
    Other,
}

/// A chooser submission's binding to its flow (`?flow=`, flow cookie, `csrf_token` field).
#[derive(Debug, Clone, Copy)]
pub struct AccountChoiceBinding<'a> {
    pub flow_id: FlowId,
    pub cookie_token: Option<&'a str>,
    pub csrf_token: &'a str,
}

/// What the account chooser shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectAccountPage {
    pub request_id: AuthRequestId,
    pub client_name: String,
    /// The session user's name, if set.
    pub user_name: Option<String>,
    pub user_email: String,
}

/// Result of opening the account chooser.
#[derive(Debug)]
pub enum SelectAccountStart {
    Started {
        flow: StartedConsentFlow,
        page: SelectAccountPage,
    },
    /// The request expired, was used, or its client is gone.
    RequestExpired,
}

/// One org on the switcher (a membership of the signed-in user).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgOption {
    pub id: OrgId,
    pub slug: String,
    pub display_name: String,
}

/// What the organization switcher shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectOrganizationPage {
    pub request_id: AuthRequestId,
    pub client_name: String,
    /// The session user's memberships only, by display name.
    pub organizations: Vec<OrgOption>,
}

/// Result of opening the organization switcher.
#[derive(Debug)]
pub enum SelectOrganizationStart {
    Started {
        flow: StartedConsentFlow,
        page: SelectOrganizationPage,
    },
    /// The request expired, was used, its client is gone, or it does not need a choice (the
    /// client does not require an org, or the request already names one).
    RequestExpired,
}

/// The switcher's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgChoice {
    /// The choice was recorded; continue with this outcome.
    Continue(AuthorizeOutcome),
    /// The switcher flow expired or was already used (show the switcher again).
    FlowExpired,
    /// The submitted org is not one of the user's memberships; nothing changed.
    NotAMember,
}

/// Builds a code and its pre-created token family. Returns the plaintext code (sent to the
/// client only) and the records to store; only the code's hash is stored. `issuer` is the
/// issuer of this authorization response (and of the ID tokens issued from the code); storage
/// records it on the RP session for back-channel logout.
pub fn build_code(
    client: &Client,
    params: &AuthorizationParams,
    session: &BrowserSession,
    issuer: &str,
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
        resource: params.resource.clone(),
        org_id: None,
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
        issuer: issuer.to_owned(),
        expires_at: now + CODE_TTL,
        created_at: now,
        resource: params.resource.clone(),
        org_id: None,
    };
    (SecretString::from(plaintext), code, family)
}

/// Why an authorization cannot be bound to an org.
#[derive(Debug)]
pub enum OrgRefusal {
    /// Answer the client with this error through the response mode.
    Error(CoreError),
    /// The user must pick one of several orgs (no `prompt=none`): the organization switcher.
    SelectionRequired,
}

/// Maps the active-org decision to the org bound to the code and family:
///
/// | decision | result |
/// |---|---|
/// | `NoOrg` | `Ok(None)` |
/// | `Selected(org)` | `Ok(Some(org.id))` |
/// | `Denied` (not a member, or `required` without any membership) | `access_denied` |
/// | `Refused` (the client's policy is `off`) | `invalid_request` |
/// | `NeedsChoice` with `prompt=none` | `interaction_required` |
/// | `NeedsChoice` otherwise | [`OrgRefusal::SelectionRequired`] (the switcher) |
///
/// An org is never picked silently.
pub fn bind_active_org(active: ActiveOrg, prompt_none: bool) -> Result<Option<OrgId>, OrgRefusal> {
    match active {
        ActiveOrg::NoOrg => Ok(None),
        ActiveOrg::Selected(org) => Ok(Some(org.id)),
        ActiveOrg::Denied => Err(OrgRefusal::Error(CoreError::AccessDenied(
            "the user is not a member of the requested organization".to_owned(),
        ))),
        ActiveOrg::Refused => Err(OrgRefusal::Error(CoreError::InvalidRequest(
            "this client does not accept the organization parameter".to_owned(),
        ))),
        ActiveOrg::NeedsChoice if prompt_none => {
            Err(OrgRefusal::Error(CoreError::InteractionRequired))
        }
        ActiveOrg::NeedsChoice => Err(OrgRefusal::SelectionRequired),
    }
}

/// Where a stored authorization request continues from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "each stage names the step the request continues after"
)]
enum Stage {
    /// After the login flow: decide on the session, then on consent.
    AfterLogin,
    /// After the consent screen: `approved` (Allow) issues the code once the stored grant
    /// covers the request; Deny answers `access_denied`.
    AfterConsent { approved: bool },
    /// After "Continue as …" on the account chooser: decide again without `select_account`.
    AfterAccountChosen,
    /// After the organization switcher: the switcher comes after the consent decision, so
    /// `select_account` and `consent` were answered.
    AfterOrganizationChosen,
}

impl Stage {
    /// The prompt values the decision honours at this stage. The chooser comes before consent,
    /// so `select_account` is answered once the user chose; `consent` is answered after the
    /// consent screen.
    fn prompt(self, prompt: &[String]) -> Vec<String> {
        prompt
            .iter()
            .filter(|p| match self {
                Self::AfterLogin => true,
                Self::AfterAccountChosen => p.as_str() != "select_account",
                Self::AfterConsent { .. } | Self::AfterOrganizationChosen => {
                    p.as_str() != "select_account" && p.as_str() != "consent"
                }
            })
            .cloned()
            .collect()
    }
}

/// Authorization endpoint service.
pub struct AuthorizeService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// Client ID Metadata Document fetcher (`None` = URL client ids are not resolved).
    pub metadata_fetcher: Option<Arc<dyn ClientMetadataFetcher>>,
}

impl AuthorizeService {
    /// The client lookup at the authorization endpoint (materialises Client ID Metadata
    /// Document clients under the tenant's policy).
    fn resolver(&self) -> ClientResolver {
        ClientResolver {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
            fetcher: self.metadata_fetcher.clone(),
        }
    }

    fn consent(&self) -> ConsentService {
        ConsentService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Stores `params` as an authorization request (for the login flow or the consent screen).
    async fn store_request(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &AuthorizationParams,
        now: OffsetDateTime,
    ) -> Result<AuthRequestId, CoreError> {
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
        Ok(request_id)
    }

    /// The consent decision for `session`'s user. `prompt` is the request's prompt (after the
    /// consent screen without `consent`, so an Allow is not asked again).
    async fn consent_needed(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &AuthorizationParams,
        session: &BrowserSession,
        prompt: &[String],
    ) -> Result<Result<ConsentDecision, CoreError>, CoreError> {
        let requested = requested_scopes(&params.scope);
        match self
            .consent()
            .decide(
                tenant.id,
                session.user_id,
                client,
                &requested,
                &params.resource,
                prompt,
            )
            .await
        {
            Ok(d) => Ok(Ok(d)),
            Err(CoreError::ConsentRequired) => Ok(Err(CoreError::ConsentRequired)),
            Err(e) => Err(e),
        }
    }

    /// Handles an authorization request.
    pub async fn authorize(
        &self,
        tenant: &Tenant,
        issuer: &str,
        raw: RawParams,
        session: Option<BrowserSession>,
    ) -> Result<AuthorizeOutcome, CoreError> {
        // RFC 9126 §4: a pushed request replaces the front-channel parameters. Any other
        // `request_uri` value is refused by `validate` (`request_uri_not_supported`).
        if raw
            .0
            .iter()
            .any(|(k, v)| k == "request_uri" && is_pushed_request_uri(v))
        {
            return self.authorize_pushed(tenant, issuer, &raw, session).await;
        }
        let now = self.clock.now();
        let client = match raw.single("client_id") {
            Some(id) if id.len() <= MAX_CLIENT_ID_LEN || is_url_client_id(id) => {
                match self.resolver().resolve(tenant, id, now).await {
                    Ok(c) => c,
                    // A refused metadata document: the error page, never a redirect (the
                    // redirect URI is unverified). A transient failure is returned as is (503
                    // error page).
                    Err(CoreError::InvalidClient { .. }) => {
                        return Ok(AuthorizeOutcome::ErrorPage {
                            error_key: "unknown_client",
                            detail: "the client metadata document was refused".to_owned(),
                        });
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => None,
        };
        let validated = match validate(&raw, client.as_ref(), tenant.settings.registration) {
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

        // RFC 9126 §5/§6: a client (or a whole tenant) that requires pushed requests never
        // accepts the parameters on the front channel.
        if client.require_pushed_authorization_requests
            || tenant.settings.par.require_pushed_authorization_requests
        {
            return Ok(fail(CoreError::InvalidRequest(
                "this client must use a pushed authorization request".to_owned(),
            )));
        }

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

        // The user asked to create an account: registration, whether or not a session exists.
        if params.prompt.iter().any(|p| p == PROMPT_CREATE) {
            let request_id = self.store_request(tenant, &client, &params, now).await?;
            return Ok(AuthorizeOutcome::Register { request_id });
        }

        let session = self.usable_session(tenant, session).await?;
        let mfa = mfa_context(
            self.storage.as_ref(),
            tenant,
            Some(&client),
            &params,
            session.as_ref(),
        )
        .await?;
        match decide(
            &params.prompt,
            params.max_age,
            session.as_ref(),
            hint_sub.as_deref(),
            now,
            now,
            mfa,
        ) {
            SessionDecision::UseSession => {
                let session = session.ok_or_else(|| {
                    CoreError::Internal("UseSession decided without a session".to_owned())
                })?;
                match self
                    .consent_needed(tenant, &client, &params, &session, &params.prompt)
                    .await?
                {
                    Ok(ConsentDecision::Skip) => {
                        match self
                            .active_org(tenant, issuer, &client, &params, &session)
                            .await?
                        {
                            OrgStep::Bind(org) => {
                                self.issue(tenant, issuer, &client, &params, &session, org, now)
                                    .await
                            }
                            OrgStep::Answer(answer) => Ok(answer),
                            OrgStep::Choose => {
                                let request_id =
                                    self.store_request(tenant, &client, &params, now).await?;
                                Ok(AuthorizeOutcome::SelectOrganization { request_id })
                            }
                        }
                    }
                    Ok(ConsentDecision::Required) => {
                        let request_id = self.store_request(tenant, &client, &params, now).await?;
                        Ok(AuthorizeOutcome::Consent { request_id })
                    }
                    Err(error) => Ok(fail(error)),
                }
            }
            SessionDecision::RequireLogin | SessionDecision::StepUp => {
                let request_id = self.store_request(tenant, &client, &params, now).await?;
                Ok(AuthorizeOutcome::Login { request_id })
            }
            SessionDecision::SelectAccount => {
                let request_id = self.store_request(tenant, &client, &params, now).await?;
                Ok(AuthorizeOutcome::SelectAccount { request_id })
            }
            SessionDecision::Fail(error) => Ok(fail(error)),
        }
    }

    fn par(&self) -> ParService {
        ParService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
            metadata_fetcher: self.metadata_fetcher.clone(),
        }
    }

    /// The single resume path of a pushed authorization request (RFC 9126 §4), shared by
    /// `/authorize` and the native headless start: consumes the request (atomically, once),
    /// checks that `client_id` is the client that pushed it, re-checks the client's current
    /// policy (RFC 9126 §7.4) and stores the parameters as an authorization request through the
    /// normal path. `Ok(Err(outcome))` is the refusal to show: an error page while no redirect
    /// URI is trusted (unusable or mismatched `request_uri`, client gone, redirect URI removed),
    /// else an error response to the stored redirect URI.
    pub async fn resume_pushed_request(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client_id: &str,
        request_uri: &str,
    ) -> Result<Result<ResumedPushedRequest, AuthorizeOutcome>, CoreError> {
        let params = match self.par().consume(tenant, client_id, request_uri).await? {
            Ok(params) => params,
            Err(PushedRequestRefused::Unusable) => {
                return Ok(Err(AuthorizeOutcome::ErrorPage {
                    error_key: "invalid_request",
                    detail: "the request_uri is unknown, expired or already used".to_owned(),
                }));
            }
            Err(PushedRequestRefused::ClientMismatch) => {
                return Ok(Err(AuthorizeOutcome::ErrorPage {
                    error_key: "invalid_request",
                    detail: "the request_uri was not issued to this client".to_owned(),
                }));
            }
        };
        let Some(client) = self.storage.clients().get(tenant.id, client_id).await? else {
            return Ok(Err(AuthorizeOutcome::ErrorPage {
                error_key: "unknown_client",
                detail: "the client is no longer registered".to_owned(),
            }));
        };
        let params = match recheck_client_policy(&client, &params, tenant.settings.registration) {
            Ok(p) => p,
            Err(AuthorizeError::ErrorPage { error_key, detail }) => {
                return Ok(Err(AuthorizeOutcome::ErrorPage { error_key, detail }));
            }
            Err(AuthorizeError::Redirect {
                redirect_uri,
                state,
                response_mode,
                error,
            }) => {
                return Ok(Err(AuthorizeOutcome::Respond(
                    AuthorizationResponse::error(
                        &redirect_uri,
                        &error,
                        state.as_deref(),
                        issuer,
                        response_mode,
                    ),
                )));
            }
        };
        let request_id = self
            .store_request(tenant, &client, &params, self.clock.now())
            .await?;
        Ok(Ok(ResumedPushedRequest {
            request_id,
            client,
            params,
        }))
    }

    /// The start of a native headless sign-in: the client must be [`native_eligible`] (checked
    /// before the pushed request is consumed, and again on the client as registered after the
    /// resume), then the pushed request is resumed through [`Self::resume_pushed_request`]
    /// (single use, the same consume and policy re-check as `/authorize`) and must carry a PKCE
    /// challenge. The stored request is then continued by a token-bound login flow and finished
    /// with [`Self::complete`].
    pub async fn start_native(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client_id: &str,
        request_uri: &str,
    ) -> Result<Result<ResumedPushedRequest, NativeStartRefused>, CoreError> {
        if client_id.len() > MAX_CLIENT_ID_LEN || is_url_client_id(client_id) {
            return Ok(Err(NativeStartRefused::NotEligible));
        }
        match self.storage.clients().get(tenant.id, client_id).await? {
            Some(client) if native_eligible(&client) => {}
            _ => return Ok(Err(NativeStartRefused::NotEligible)),
        }
        let resumed = match self
            .resume_pushed_request(tenant, issuer, client_id, request_uri)
            .await?
        {
            Ok(r) => r,
            Err(outcome) => return Ok(Err(NativeStartRefused::Pushed(outcome))),
        };
        if !native_eligible(&resumed.client) {
            return Ok(Err(NativeStartRefused::NotEligible));
        }
        if resumed.params.code_challenge.is_none() {
            return Ok(Err(NativeStartRefused::PkceRequired));
        }
        Ok(Ok(resumed))
    }

    /// `/authorize` with a pushed `request_uri`: only `client_id` and `request_uri` are read
    /// ([`crate::oauth::par::FRONT_CHANNEL_PARAMETERS`]); the pushed parameters are the request.
    /// After [`Self::resume_pushed_request`] the request continues exactly like a stored one.
    async fn authorize_pushed(
        &self,
        tenant: &Tenant,
        issuer: &str,
        raw: &RawParams,
        session: Option<BrowserSession>,
    ) -> Result<AuthorizeOutcome, CoreError> {
        let page = |detail: &str| AuthorizeOutcome::ErrorPage {
            error_key: "invalid_request",
            detail: detail.to_owned(),
        };
        let Some(request_uri) = raw.single("request_uri") else {
            return Ok(page("request_uri is repeated"));
        };
        let Some(client_id) = raw.single("client_id") else {
            return Ok(page("client_id is missing or repeated"));
        };
        let resumed = match self
            .resume_pushed_request(tenant, issuer, client_id, request_uri)
            .await?
        {
            Ok(r) => r,
            Err(refusal) => return Ok(refusal),
        };
        if resumed.params.prompt.iter().any(|p| p == PROMPT_CREATE) {
            return Ok(AuthorizeOutcome::Register {
                request_id: resumed.request_id,
            });
        }
        self.continue_request(
            tenant,
            issuer,
            resumed.request_id,
            session,
            Stage::AfterLogin,
        )
        .await
    }

    /// Continues a stored authorization request after the login flow.
    pub async fn resume(
        &self,
        tenant: &Tenant,
        issuer: &str,
        request_id: AuthRequestId,
        session: Option<BrowserSession>,
    ) -> Result<AuthorizeOutcome, CoreError> {
        self.continue_request(tenant, issuer, request_id, session, Stage::AfterLogin)
            .await
    }

    /// Completes a stored authorization request for a sign-in that has no browser (the headless
    /// native mode): the same decision and code issuance as [`Self::resume`] (session, MFA,
    /// consent, organization, then `issue`), with the response's parameters returned as a
    /// [`Completion`] instead of a redirect. `session` is the server-side session the sign-in
    /// created; its cookie never leaves the server, so it can never be presented for single
    /// sign-on (the code and its token family need a session row to anchor the RP session and
    /// back-channel logout).
    pub async fn complete(
        &self,
        tenant: &Tenant,
        issuer: &str,
        request_id: AuthRequestId,
        session: BrowserSession,
    ) -> Result<Completion, CoreError> {
        let outcome = self
            .continue_request(tenant, issuer, request_id, Some(session), Stage::AfterLogin)
            .await?;
        Ok(Completion::of(outcome))
    }

    /// Continues a stored authorization request after the consent screen. Call only with a
    /// decision taken by [`ConsentService::approve`] / [`ConsentService::deny`] for this request
    /// and session. Allow issues the code once the stored grant covers the request (a grant
    /// revoked in between shows the screen again); Deny answers `access_denied` through the
    /// request's response mode. Either way the request is used up.
    pub async fn finish_consent(
        &self,
        tenant: &Tenant,
        issuer: &str,
        request_id: AuthRequestId,
        session: Option<BrowserSession>,
        approved: bool,
    ) -> Result<AuthorizeOutcome, CoreError> {
        self.continue_request(
            tenant,
            issuer,
            request_id,
            session,
            Stage::AfterConsent { approved },
        )
        .await
    }

    async fn continue_request(
        &self,
        tenant: &Tenant,
        issuer: &str,
        request_id: AuthRequestId,
        session: Option<BrowserSession>,
        stage: Stage,
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
        if stage == (Stage::AfterConsent { approved: false }) {
            if !self
                .storage
                .grants()
                .delete_authorization_request(tenant.id, request_id)
                .await?
            {
                return Ok(flow_expired());
            }
            return Ok(error_response(
                &params,
                &CoreError::AccessDenied("the user denied the request".to_owned()),
                issuer,
            ));
        }

        let session = self.usable_session(tenant, session).await?;
        let mfa = mfa_context(
            self.storage.as_ref(),
            tenant,
            Some(&client),
            &params,
            session.as_ref(),
        )
        .await?;
        // After an Allow the stored grant decides (`prompt=consent` was just honoured); after
        // the chooser `select_account` was.
        let prompt = stage.prompt(&params.prompt);
        match decide(
            &prompt,
            params.max_age,
            session.as_ref(),
            None,
            request.created_at,
            now,
            mfa,
        ) {
            SessionDecision::UseSession => {
                let session = session.ok_or_else(|| {
                    CoreError::Internal("UseSession decided without a session".to_owned())
                })?;
                match self
                    .consent_needed(tenant, &client, &params, &session, &prompt)
                    .await?
                {
                    Ok(ConsentDecision::Skip) => {}
                    Ok(ConsentDecision::Required) => {
                        return Ok(AuthorizeOutcome::Consent { request_id });
                    }
                    Err(error) => {
                        self.storage
                            .grants()
                            .delete_authorization_request(tenant.id, request_id)
                            .await?;
                        return Ok(error_response(&params, &error, issuer));
                    }
                }
                // The org is decided before the request is used up: the switcher keeps it.
                let org = match self
                    .active_org(tenant, issuer, &client, &params, &session)
                    .await?
                {
                    OrgStep::Bind(org) => org,
                    OrgStep::Choose => {
                        return Ok(AuthorizeOutcome::SelectOrganization { request_id });
                    }
                    OrgStep::Answer(answer) => {
                        self.storage
                            .grants()
                            .delete_authorization_request(tenant.id, request_id)
                            .await?;
                        return Ok(answer);
                    }
                };
                // Deleting first makes the request single-use: a concurrent resume loses.
                if !self
                    .storage
                    .grants()
                    .delete_authorization_request(tenant.id, request_id)
                    .await?
                {
                    return Ok(flow_expired());
                }
                self.issue(tenant, issuer, &client, &params, &session, org, now)
                    .await
            }
            SessionDecision::RequireLogin | SessionDecision::StepUp => {
                Ok(AuthorizeOutcome::Login { request_id })
            }
            SessionDecision::SelectAccount => Ok(AuthorizeOutcome::SelectAccount { request_id }),
            SessionDecision::Fail(error) => {
                self.storage
                    .grants()
                    .delete_authorization_request(tenant.id, request_id)
                    .await?;
                Ok(error_response(&params, &error, issuer))
            }
        }
    }

    /// Opens a flow bound to `session`'s user and to `request_id` (a `FlowKind::Consent` flow
    /// in its connected-apps form, see the module docs). Used by the account chooser and the
    /// organization switcher.
    async fn open_request_flow(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        request_id: AuthRequestId,
        now: OffsetDateTime,
    ) -> Result<StartedConsentFlow, CoreError> {
        let cookie = random_token();
        let csrf = random_token();
        let new = NewFlow {
            id: FlowId::new_v7(),
            kind: FlowKind::Consent,
            state: ConsentState::for_apps(session.user_id).to_json(),
            csrf_hash: SecretHash(secret_hash(&csrf)),
            cookie_hash: SecretHash(secret_hash(&cookie)),
            auth_request_id: Some(request_id),
            created_at: now,
            expires_at: now + FLOW_LIFETIME,
        };
        self.storage.flows().create(tenant.id, &new).await?;
        Ok(StartedConsentFlow {
            flow_id: new.id,
            cookie_token: SecretString::from(cookie),
            csrf_token: SecretString::from(csrf),
        })
    }

    /// Checks a submission against a flow opened by [`Self::open_request_flow`]: it must carry
    /// the flow's cookie and CSRF token, and the flow must belong to `session`'s user and to
    /// `request_id`; otherwise [`CoreError::Forbidden`]. `Ok(None)` when the flow expired or was
    /// already used. Does not use the flow up.
    async fn bound_request_flow(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        request_id: AuthRequestId,
        binding: &AccountChoiceBinding<'_>,
        now: OffsetDateTime,
    ) -> Result<Option<FlowId>, CoreError> {
        if session.tenant_id != tenant.id {
            return Err(CoreError::Forbidden);
        }
        let Some(flow) = self
            .storage
            .flows()
            .get(tenant.id, binding.flow_id, now)
            .await?
        else {
            return Ok(None);
        };
        if flow.kind != FlowKind::Consent {
            return Err(CoreError::Forbidden);
        }
        match check_binding(&flow, binding.cookie_token, binding.csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => return Ok(None),
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden),
        }
        let state =
            ConsentState::from_json(&flow.state).map_err(|e| CoreError::Internal(e.to_string()))?;
        if state.user != session.user_id
            || state.request.is_some()
            || flow.auth_request_id != Some(request_id)
        {
            return Err(CoreError::Forbidden);
        }
        Ok(Some(flow.id))
    }

    /// Opens the account chooser for a stored request: a flow bound to the session's user and
    /// to the request, and what the page shows.
    pub async fn start_select_account(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        request_id: AuthRequestId,
    ) -> Result<SelectAccountStart, CoreError> {
        if session.tenant_id != tenant.id {
            return Err(CoreError::Forbidden);
        }
        let now = self.clock.now();
        let Some(request) = self
            .storage
            .grants()
            .get_authorization_request(tenant.id, request_id, now)
            .await?
        else {
            return Ok(SelectAccountStart::RequestExpired);
        };
        let Some(client) = self
            .storage
            .clients()
            .get(tenant.id, &request.client_id)
            .await?
        else {
            return Ok(SelectAccountStart::RequestExpired);
        };
        let Some(user) = self.storage.users().get(tenant.id, session.user_id).await? else {
            return Err(CoreError::Forbidden);
        };
        let flow = self
            .open_request_flow(tenant, session, request_id, now)
            .await?;
        Ok(SelectAccountStart::Started {
            flow,
            page: SelectAccountPage {
                request_id,
                client_name: client.name,
                user_name: user.claims.name.filter(|n| !n.trim().is_empty()),
                user_email: user.email,
            },
        })
    }

    /// Applies the account chooser's answer for `request_id`. The submission must carry the
    /// chooser flow's cookie and CSRF token, and the flow must belong to the session's user and
    /// to this request; otherwise [`CoreError::Forbidden`]. The flow is used up first, so a
    /// page answers once. `Ok(None)` when the flow expired or was already used (show the
    /// chooser again).
    ///
    /// - [`AccountChoice::Continue`]: the request continues as if the session had been used
    ///   (consent and step-up still apply), without `select_account`.
    /// - [`AccountChoice::Other`]: [`AuthorizeOutcome::Login`]; the stored request answers only
    ///   to a sign-in during the request or to a later "Continue" on the chooser.
    pub async fn choose_account(
        &self,
        tenant: &Tenant,
        issuer: &str,
        request_id: AuthRequestId,
        session: BrowserSession,
        binding: &AccountChoiceBinding<'_>,
        choice: AccountChoice,
    ) -> Result<Option<AuthorizeOutcome>, CoreError> {
        let now = self.clock.now();
        let Some(flow_id) = self
            .bound_request_flow(tenant, &session, request_id, binding, now)
            .await?
        else {
            return Ok(None);
        };
        if !self.storage.flows().delete(tenant.id, flow_id).await? {
            return Ok(None);
        }
        match choice {
            AccountChoice::Continue => self
                .continue_request(
                    tenant,
                    issuer,
                    request_id,
                    Some(session),
                    Stage::AfterAccountChosen,
                )
                .await
                .map(Some),
            AccountChoice::Other => {
                if self
                    .storage
                    .grants()
                    .get_authorization_request(tenant.id, request_id, now)
                    .await?
                    .is_none()
                {
                    return Ok(Some(flow_expired()));
                }
                Ok(Some(AuthorizeOutcome::Login { request_id }))
            }
        }
    }

    /// The stored request and its client when the request waits for an org choice: the client
    /// requires an org and the request names none. `None` otherwise (expired, used, client gone,
    /// or no choice to make).
    async fn request_awaiting_org(
        &self,
        tenant: &Tenant,
        request_id: AuthRequestId,
        now: OffsetDateTime,
    ) -> Result<Option<(crate::model::AuthorizationRequest, Client)>, CoreError> {
        let Some(request) = self
            .storage
            .grants()
            .get_authorization_request(tenant.id, request_id, now)
            .await?
        else {
            return Ok(None);
        };
        let Some(client) = self
            .storage
            .clients()
            .get(tenant.id, &request.client_id)
            .await?
        else {
            return Ok(None);
        };
        if client.organization != OrgClientPolicy::Required || request.params.organization.is_some()
        {
            return Ok(None);
        }
        Ok(Some((request, client)))
    }

    /// Opens the organization switcher for a stored request: a flow bound to the session's user
    /// and to the request, and the user's own memberships (never another org of the tenant).
    pub async fn start_select_organization(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        request_id: AuthRequestId,
    ) -> Result<SelectOrganizationStart, CoreError> {
        if session.tenant_id != tenant.id {
            return Err(CoreError::Forbidden);
        }
        let now = self.clock.now();
        let Some((_, client)) = self.request_awaiting_org(tenant, request_id, now).await? else {
            return Ok(SelectOrganizationStart::RequestExpired);
        };
        let organizations = org_options(
            self.storage
                .organizations()
                .memberships_of_user(tenant.id, session.user_id)
                .await?,
        );
        let flow = self
            .open_request_flow(tenant, session, request_id, now)
            .await?;
        Ok(SelectOrganizationStart::Started {
            flow,
            page: SelectOrganizationPage {
                request_id,
                client_name: client.name,
                organizations,
            },
        })
    }

    /// Applies the switcher's choice of `org` for `request_id`. The submission must carry the
    /// switcher flow's cookie and CSRF token, and the flow must belong to the session's user and
    /// to this request; otherwise [`CoreError::Forbidden`].
    ///
    /// `org` must be one of the user's memberships ([`OrgChoice::NotAMember`] otherwise, nothing
    /// changes). The flow is then used up, and the choice is written into the stored request's
    /// `organization` parameter by compare-and-swap: the request is deleted (only one
    /// submission wins) and stored again under the same id with the org, keeping its creation
    /// and expiry times. A request that no longer waits for a choice (already chosen, used or
    /// expired) is the `flow_expired` page. The request then continues: the org's MFA policy
    /// applies (step-up before the code), and the code is bound to the org.
    pub async fn choose_organization(
        &self,
        tenant: &Tenant,
        issuer: &str,
        request_id: AuthRequestId,
        session: BrowserSession,
        binding: &AccountChoiceBinding<'_>,
        org: OrgId,
    ) -> Result<OrgChoice, CoreError> {
        let now = self.clock.now();
        let Some(flow_id) = self
            .bound_request_flow(tenant, &session, request_id, binding, now)
            .await?
        else {
            return Ok(OrgChoice::FlowExpired);
        };
        let Some((request, _)) = self.request_awaiting_org(tenant, request_id, now).await? else {
            return Ok(OrgChoice::Continue(flow_expired()));
        };
        let member = self
            .storage
            .organizations()
            .memberships_of_user(tenant.id, session.user_id)
            .await?
            .into_iter()
            .any(|o| o.id == org);
        if !member {
            return Ok(OrgChoice::NotAMember);
        }
        if !self.storage.flows().delete(tenant.id, flow_id).await? {
            return Ok(OrgChoice::FlowExpired);
        }
        // Compare-and-swap: only the submission whose delete succeeds writes the choice.
        if !self
            .storage
            .grants()
            .delete_authorization_request(tenant.id, request_id)
            .await?
        {
            return Ok(OrgChoice::Continue(flow_expired()));
        }
        let mut params = request.params;
        params.organization = Some(org.to_string());
        self.storage
            .grants()
            .create_authorization_request(
                tenant.id,
                &NewAuthorizationRequest {
                    id: request_id,
                    client_id: request.client_id,
                    params,
                    created_at: request.created_at,
                    expires_at: request.expires_at,
                },
            )
            .await?;
        self.continue_request(
            tenant,
            issuer,
            request_id,
            Some(session),
            Stage::AfterOrganizationChosen,
        )
        .await
        .map(OrgChoice::Continue)
    }

    /// The org this authorization is bound to, from the client's policy, the request's
    /// `organization` parameter and `session`'s user's memberships ([`bind_active_org`]).
    async fn active_org(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client: &Client,
        params: &AuthorizationParams,
        session: &BrowserSession,
    ) -> Result<OrgStep, CoreError> {
        let active = active_org_of(
            self.storage.as_ref(),
            tenant.id,
            client,
            params,
            session.user_id,
        )
        .await?;
        let prompt_none = params.prompt.iter().any(|p| p == "none");
        Ok(match bind_active_org(active, prompt_none) {
            Ok(org) => OrgStep::Bind(org),
            Err(OrgRefusal::Error(error)) => {
                OrgStep::Answer(error_response(params, &error, issuer))
            }
            Err(OrgRefusal::SelectionRequired) => OrgStep::Choose,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper; every argument is a distinct input of the issued code"
    )]
    async fn issue(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client: &Client,
        params: &AuthorizationParams,
        session: &BrowserSession,
        org: Option<OrgId>,
        now: OffsetDateTime,
    ) -> Result<AuthorizeOutcome, CoreError> {
        let (plaintext, mut code, mut family) = build_code(client, params, session, issuer, now);
        // The active org is bound to the grant (code and family), never to the session.
        code.org_id = org;
        family.org_id = org;
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
        // Every algorithm the tenant signs ID tokens with (RS256, ES256, Ed25519).
        let algs = enabled_algs(tenant)?;
        Ok(
            verify_op_token_algs(hint, &jwks, &algs, issuer, None, ExpiryCheck::Ignore, now)
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

/// What the authorization does about the org once the session and consent are settled.
#[derive(Debug)]
enum OrgStep {
    /// Bind this org (or none) to the code.
    Bind(Option<OrgId>),
    /// Answer the client (an error through the response mode).
    Answer(AuthorizeOutcome),
    /// Show the organization switcher.
    Choose,
}

/// The switcher's entries for `memberships`, by display name, then slug.
fn org_options(memberships: Vec<Organization>) -> Vec<OrgOption> {
    let mut out: Vec<OrgOption> = memberships
        .into_iter()
        .map(|o| OrgOption {
            id: o.id,
            slug: o.slug,
            display_name: o.display_name,
        })
        .collect();
    out.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
            .then_with(|| a.slug.cmp(&b.slug))
    });
    out
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

    #[test]
    fn native_eligibility_follows_the_client_policy() {
        use crate::model::{ClientKind, ClientSource, ConsentMode};
        let eligible = || Client {
            headless_native: true,
            consent_mode: ConsentMode::SkipFirstParty,
            require_pkce: true,
            ..client()
        };
        assert!(native_eligible(&eligible()));
        let refused: Vec<(&str, Client)> = vec![
            (
                "flag off",
                Client {
                    headless_native: false,
                    ..eligible()
                },
            ),
            (
                "dynamic",
                Client {
                    registration_source: ClientSource::Dynamic,
                    ..eligible()
                },
            ),
            (
                "cimd",
                Client {
                    registration_source: ClientSource::Cimd,
                    ..eligible()
                },
            ),
            (
                "agent",
                Client {
                    client_kind: ClientKind::Agent,
                    ..eligible()
                },
            ),
            (
                "third party",
                Client {
                    consent_mode: ConsentMode::Required,
                    ..eligible()
                },
            ),
            (
                "no pkce",
                Client {
                    require_pkce: false,
                    ..eligible()
                },
            ),
            (
                "no code grant",
                Client {
                    grant_types: vec![GrantType::ClientCredentials],
                    ..eligible()
                },
            ),
        ];
        for (name, c) in refused {
            assert!(!native_eligible(&c), "{name}");
        }
    }

    #[test]
    fn completion_carries_the_redirect_responses_parameters() {
        let ok = AuthorizationResponse::success(
            RP,
            "the-code",
            Some("st"),
            ISSUER,
            ResponseMode::FormPost,
        );
        match Completion::of(AuthorizeOutcome::Respond(ok)) {
            Completion::Code { code, iss, state } => {
                assert_eq!(code.expose_secret(), "the-code");
                assert_eq!(iss, ISSUER);
                assert_eq!(state.as_deref(), Some("st"));
            }
            other => panic!("expected a code, got {other:?}"),
        }
        let err = AuthorizationResponse::error(
            RP,
            &CoreError::AccessDenied("no".into()),
            None,
            ISSUER,
            ResponseMode::Query,
        );
        match Completion::of(AuthorizeOutcome::Respond(err)) {
            Completion::Error {
                error, state, iss, ..
            } => {
                assert_eq!(error, "access_denied");
                assert_eq!(state, None);
                assert_eq!(iss, ISSUER);
            }
            other => panic!("expected an error, got {other:?}"),
        }
        let consent = AuthorizeOutcome::Consent {
            request_id: AuthRequestId::new_v7(),
        };
        assert!(matches!(
            Completion::of(consent),
            Completion::Interaction(AuthorizeOutcome::Consent { .. })
        ));
        // The code never shows in debug output.
        let ok = AuthorizationResponse::success(RP, "the-code", None, ISSUER, ResponseMode::Query);
        assert!(
            !format!("{:?}", Completion::of(AuthorizeOutcome::Respond(ok))).contains("the-code")
        );
    }

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
            resource: vec![],
            organization: None,
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
        let (plain, code, family) = build_code(&c, &p, &s, ISSUER, NOW);
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
        assert_eq!(code.issuer, ISSUER);
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
        assert!(code.resource.is_empty() && family.resource.is_empty());
        // The granted resources go onto the code and the family (RFC 8707 §2.1).
        let mut with_resource = p.clone();
        with_resource.resource = vec!["https://api.example.test".to_owned()];
        let (_, rcode, rfamily) = build_code(&c, &with_resource, &s, ISSUER, NOW);
        assert_eq!(rcode.resource, with_resource.resource);
        assert_eq!(rfamily.resource, with_resource.resource);
        // Two codes never collide.
        let (other, _, other_family) = build_code(&c, &p, &s, ISSUER, NOW);
        assert_ne!(other.expose_secret(), plain);
        assert_ne!(other_family.id, family.id);
    }

    fn prompts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn each_stage_drops_the_prompt_values_already_answered() {
        let all = prompts(&["login", "consent", "select_account", "create"]);
        assert_eq!(Stage::AfterLogin.prompt(&all), all);
        assert_eq!(
            Stage::AfterAccountChosen.prompt(&all),
            prompts(&["login", "consent", "create"])
        );
        for approved in [true, false] {
            assert_eq!(
                Stage::AfterConsent { approved }.prompt(&all),
                prompts(&["login", "create"])
            );
        }
    }

    #[test]
    fn after_the_chooser_the_old_session_is_used_once_more() {
        // "Continue as …": the session predates the request, yet the decision without
        // select_account uses it (no second chooser, no forced login).
        let s = session();
        let created = NOW - Duration::seconds(10);
        let p = prompts(&["select_account"]);
        assert!(matches!(
            decide(&p, None, Some(&s), None, created, NOW, MfaContext::NONE),
            SessionDecision::SelectAccount
        ));
        let p = Stage::AfterAccountChosen.prompt(&p);
        assert!(matches!(
            decide(&p, None, Some(&s), None, created, NOW, MfaContext::NONE),
            SessionDecision::UseSession
        ));
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

    fn org(slug: &str) -> crate::model::Organization {
        crate::model::Organization {
            id: OrgId::new_v7(),
            tenant_id: TenantId::new_v7(),
            slug: slug.to_owned(),
            display_name: slug.to_owned(),
            mfa_policy: None,
            settings: crate::model::OrgSettings::default(),
            metadata: serde_json::json!({}),
            created_at: NOW,
            updated_at: NOW,
        }
    }

    fn error_code(r: Result<Option<OrgId>, OrgRefusal>) -> &'static str {
        match r {
            Err(OrgRefusal::Error(e)) => e.oauth_error(),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn active_org_binding() {
        use crate::model::OrgClientPolicy::{Off, Optional, Required};
        let (a, b) = (org("a"), org("b"));
        let one = std::slice::from_ref(&a);
        let two = [a.clone(), b.clone()];
        // A member asking by slug gets that org on the grant.
        assert_eq!(
            bind_active_org(resolve_active_org(Optional, Some("b"), &two), false).unwrap(),
            Some(b.id)
        );
        // Not a member: access_denied.
        assert_eq!(
            error_code(bind_active_org(
                resolve_active_org(Optional, Some("c"), &two),
                false
            )),
            "access_denied"
        );
        // Required with one membership and no parameter: that org.
        assert_eq!(
            bind_active_org(resolve_active_org(Required, None, one), false).unwrap(),
            Some(a.id)
        );
        // Required without membership: access_denied.
        assert_eq!(
            error_code(bind_active_org(
                resolve_active_org(Required, None, &[]),
                false
            )),
            "access_denied"
        );
        // Required with several memberships: interaction_required under prompt=none, the
        // selection page otherwise; never a silent pick.
        assert_eq!(
            error_code(bind_active_org(
                resolve_active_org(Required, None, &two),
                true
            )),
            "interaction_required"
        );
        assert!(matches!(
            bind_active_org(resolve_active_org(Required, None, &two), false),
            Err(OrgRefusal::SelectionRequired)
        ));
        // Off with a parameter (policy changed since validation): invalid_request.
        assert_eq!(
            error_code(bind_active_org(
                resolve_active_org(Off, Some("a"), one),
                false
            )),
            "invalid_request"
        );
        // Optional without parameter and off without parameter: no org.
        assert_eq!(
            bind_active_org(resolve_active_org(Optional, None, &two), false).unwrap(),
            None
        );
        assert_eq!(
            bind_active_org(resolve_active_org(Off, None, &two), true).unwrap(),
            None
        );
    }

    #[test]
    fn org_mfa_policy_is_part_of_the_strictest_policy() {
        use crate::model::MfaPolicy::{Off, Optional, Required};
        let mut strict = org("strict");
        strict.mfa_policy = Some(Required);
        let mut lax = org("lax");
        lax.mfa_policy = Some(Off);
        let policy = |tenant, active: &ActiveOrg, client| {
            effective_policy_for(tenant, org_mfa_policy(active), client)
        };
        // A stricter org raises the tenant's optional policy ...
        assert_eq!(
            policy(Optional, &ActiveOrg::Selected(strict.clone()), None),
            Required
        );
        // ... an org that is off never weakens the tenant or the client.
        assert_eq!(
            policy(Required, &ActiveOrg::Selected(lax.clone()), None),
            Required
        );
        assert_eq!(
            policy(Off, &ActiveOrg::Selected(lax.clone()), Some(Optional)),
            Optional
        );
        // An org without its own policy adds nothing.
        assert_eq!(
            policy(Optional, &ActiveOrg::Selected(org("plain")), None),
            Optional
        );
        // Until an org is selected only tenant and client count.
        for undecided in [
            ActiveOrg::NeedsChoice,
            ActiveOrg::NoOrg,
            ActiveOrg::Denied,
            ActiveOrg::Refused,
        ] {
            assert_eq!(org_mfa_policy(&undecided), None);
        }
    }

    #[test]
    fn switcher_lists_memberships_by_display_name() {
        let mut b = org("beta");
        b.display_name = "Beta".to_owned();
        let mut a = org("acme");
        a.display_name = "acme corp".to_owned();
        let options = org_options(vec![b.clone(), a.clone()]);
        assert_eq!(
            options.iter().map(|o| o.slug.as_str()).collect::<Vec<_>>(),
            ["acme", "beta"]
        );
        assert_eq!(options[0].id, a.id);
        assert_eq!(options[1].display_name, "Beta");
        assert!(org_options(Vec::new()).is_empty());
    }

    #[test]
    fn after_the_switcher_select_account_and_consent_are_answered() {
        let all = prompts(&["login", "consent", "select_account"]);
        assert_eq!(
            Stage::AfterOrganizationChosen.prompt(&all),
            prompts(&["login"])
        );
    }
}
