//! Consent (OIDC-13, ADM-04): decides when the consent screen is needed, runs the consent screen
//! (Allow / Deny), and lists and revokes the user's grants (connected apps).
//!
//! # Design
//!
//! Consent is its own small state machine ([`crate::flow::consent`], `FlowKind::Consent`) rather
//! than a step of the login engine, so it never touches the login flow. It reuses the flow
//! binding of [`super::flow`]: a consent flow stores the hashes of a flow cookie and a CSRF token
//! and every submission must present both ([`check_binding`]); a wrong binding is
//! [`CoreError::Forbidden`]. The flow belongs to the signed-in user that opened it.
//!
//! # Single decision
//!
//! Allow and Deny mark the flow state decided with `FlowRepo::swap_state` before anything else
//! happens, so of two submissions of the same page exactly one proceeds; the authorization
//! request itself is also deleted before a code is issued
//! ([`super::authorize::AuthorizeService::finish_consent`]).
//!
//! # Grants
//!
//! Allow stores the union of the granted and the requested scopes and RFC 8707 resources in one
//! `GrantRepo::upsert_consent` (resources merged as a sorted set) and records `consent_granted`.
//! A remembered grant skips the screen only when it covers every requested scope and every
//! requested resource ([`consent_decision`]); a grant stored before 0.4 has no resources, so the
//! first request with a resource asks once. Revoking a grant (scopes and resources) revokes every
//! token family of that user and client in the same transaction (`GrantRepo::revoke_consent`) and
//! records `consent_revoked`.
//!
//! # Clients from a metadata document
//!
//! For a CIMD client (`registration_source = cimd`) the client's name comes from a document the
//! client itself publishes, so [`ConsentPage::cimd_host`] carries the host of its `client_id` URL
//! for the screen to show as the client's identity.

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::audit::AuditService;
use super::flow::{BindingError, FLOW_LIFETIME, check_binding};
use crate::error::CoreError;
use crate::flow::consent::{
    ConsentCoverage, ConsentDecision, ConsentState, PendingConsent, consent_decision,
    requested_scopes,
};
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, AuthRequestId, BrowserSession, Client,
    ClientSource, ConsentId, Flow, FlowId, FlowKind, NewConsent, NewFlow, RequestContext,
    SecretHash, TenantId, UserId, normalize_resources,
};
use crate::ports::{Clock, Storage};

/// A submission's binding to its consent flow (`?flow=`, flow cookie, `csrf_token` field).
#[derive(Debug, Clone, Copy)]
pub struct ConsentBinding<'a> {
    pub flow_id: FlowId,
    pub cookie_token: Option<&'a str>,
    pub csrf_token: &'a str,
}

/// A newly created consent flow: the cookie and the CSRF token go to the browser.
#[derive(Debug)]
pub struct StartedConsentFlow {
    pub flow_id: FlowId,
    pub cookie_token: SecretString,
    pub csrf_token: SecretString,
}

/// What the consent screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentPage {
    pub request_id: AuthRequestId,
    pub client_id: String,
    pub client_name: String,
    /// The requested scopes, in request order.
    pub scopes: Vec<String>,
    /// The RFC 8707 resources the tokens will be audience-bound to, in request order (already
    /// validated against the client's allowed resources). Allow adds them to the stored grant;
    /// a later request for a resource outside the grant shows the screen again.
    pub resources: Vec<String>,
    /// For a CIMD client (`registration_source = cimd`): the host (with a non-default port) of
    /// its `client_id` URL, the only verified part of its identity. `client_name` then comes
    /// from the client's own metadata document and is unverified. `None` for other clients.
    pub cimd_host: Option<String>,
}

/// The host of a CIMD client's `client_id` URL, with the port when it is not the scheme's
/// default. `None` when `client_id` is not a URL with a host (never the case for a stored CIMD
/// client).
pub fn cimd_host(client_id: &str) -> Option<String> {
    let url = url::Url::parse(client_id).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

/// Result of opening the consent screen.
#[derive(Debug)]
pub enum ConsentStart {
    Started {
        flow: StartedConsentFlow,
        page: ConsentPage,
    },
    /// The authorization request expired, was used, or its client is gone.
    RequestExpired,
}

/// Result of an Allow or Deny submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentSubmission {
    /// Decided: continue the authorization request (code or `access_denied`).
    Decided(AuthRequestId),
    /// The flow expired, does not exist or was already decided; nothing changed. Show the
    /// consent screen again (if the request still exists).
    Expired,
}

/// A connected app of the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedApp {
    pub client_id: String,
    /// The client's name, or its id when the client no longer exists.
    pub client_name: String,
    pub scopes: Vec<String>,
    pub granted_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Result of a revocation from the connected-apps page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeResult {
    /// The grant and the client's token families of the user were revoked.
    Revoked,
    /// The user has no active grant for that client; nothing changed.
    NoGrant,
    /// The page's flow expired; nothing changed.
    FlowExpired,
}

/// Consent decisions, the consent screen and connected apps.
pub struct ConsentService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl ConsentService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Whether `user` must see the consent screen for `client`, the `requested` scopes and the
    /// requested RFC 8707 `resources` ([`consent_decision`]). `Err(ConsentRequired)` when it is
    /// needed and `prompt=none`.
    pub async fn decide(
        &self,
        tenant: TenantId,
        user: UserId,
        client: &Client,
        requested: &[String],
        resources: &[String],
        prompt: &[String],
    ) -> Result<ConsentDecision, CoreError> {
        let grant = match client.consent_mode {
            crate::model::ConsentMode::SkipFirstParty => None,
            crate::model::ConsentMode::Required => {
                self.storage
                    .grants()
                    .consent(tenant, user, &client.client_id)
                    .await?
            }
        };
        consent_decision(
            client.consent_mode,
            grant.as_ref().map(|g| ConsentCoverage {
                scopes: &g.scopes,
                resources: &g.resources,
            }),
            ConsentCoverage {
                scopes: requested,
                resources,
            },
            prompt,
        )
    }

    async fn create_flow(
        &self,
        tenant: TenantId,
        state: &ConsentState,
        request: Option<AuthRequestId>,
    ) -> Result<StartedConsentFlow, CoreError> {
        let now = self.clock.now();
        let cookie = random_token();
        let csrf = random_token();
        let new = NewFlow {
            id: FlowId::new_v7(),
            kind: FlowKind::Consent,
            state: state.to_json(),
            csrf_hash: SecretHash(secret_hash(&csrf)),
            cookie_hash: SecretHash(secret_hash(&cookie)),
            auth_request_id: request,
            created_at: now,
            expires_at: now + FLOW_LIFETIME,
        };
        self.storage.flows().create(tenant, &new).await?;
        Ok(StartedConsentFlow {
            flow_id: new.id,
            cookie_token: SecretString::from(cookie),
            csrf_token: SecretString::from(csrf),
        })
    }

    /// Opens the consent screen for a stored authorization request: a consent flow bound to the
    /// session's user, and what the page shows.
    pub async fn start(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        request_id: AuthRequestId,
    ) -> Result<ConsentStart, CoreError> {
        if session.tenant_id != tenant {
            return Err(CoreError::Forbidden);
        }
        let now = self.clock.now();
        let Some(request) = self
            .storage
            .grants()
            .get_authorization_request(tenant, request_id, now)
            .await?
        else {
            return Ok(ConsentStart::RequestExpired);
        };
        let Some(client) = self
            .storage
            .clients()
            .get(tenant, &request.client_id)
            .await?
        else {
            return Ok(ConsentStart::RequestExpired);
        };
        let scopes = requested_scopes(&request.params.scope);
        let state = ConsentState::for_request(
            session.user_id,
            PendingConsent {
                request_id,
                client_id: client.client_id.clone(),
                scopes: scopes.clone(),
                resources: request.params.resource.clone(),
            },
        );
        let flow = self.create_flow(tenant, &state, Some(request_id)).await?;
        let cimd_host = match client.registration_source {
            ClientSource::Cimd => cimd_host(&client.client_id),
            ClientSource::Static | ClientSource::Dynamic => None,
        };
        Ok(ConsentStart::Started {
            flow,
            page: ConsentPage {
                request_id,
                client_id: client.client_id,
                client_name: client.name,
                scopes,
                resources: request.params.resource.clone(),
                cimd_host,
            },
        })
    }

    /// Opens a consent flow for the connected-apps page (binds revocations to the page).
    pub async fn start_apps(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
    ) -> Result<StartedConsentFlow, CoreError> {
        if session.tenant_id != tenant {
            return Err(CoreError::Forbidden);
        }
        self.create_flow(tenant, &ConsentState::for_apps(session.user_id), None)
            .await
    }

    /// Checks kind, binding and owner of a consent flow. `None` when the flow expired or does
    /// not exist. Changes nothing.
    async fn open(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &ConsentBinding<'_>,
    ) -> Result<Option<(Flow, ConsentState)>, CoreError> {
        let now = self.clock.now();
        let Some(flow) = self
            .storage
            .flows()
            .get(tenant, binding.flow_id, now)
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
        if state.user != session.user_id || session.tenant_id != tenant {
            return Err(CoreError::Forbidden);
        }
        Ok(Some((flow, state)))
    }

    /// Opens the flow and takes the decision (compare-and-swap of the flow state). `None` when
    /// the flow expired, was already decided, lost a concurrent submission, or its request is
    /// gone.
    async fn take_decision(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &ConsentBinding<'_>,
    ) -> Result<Option<PendingConsent>, CoreError> {
        let Some((flow, state)) = self.open(tenant, session, binding).await? else {
            return Ok(None);
        };
        let (next, pending) = match state.decide() {
            Ok(d) => d,
            Err(crate::flow::consent::DecideError::AlreadyDecided) => return Ok(None),
            // A connected-apps flow posted to the consent screen.
            Err(crate::flow::consent::DecideError::NoRequest) => return Err(CoreError::Forbidden),
        };
        let now = self.clock.now();
        if !self
            .storage
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &next.to_json(), now)
            .await?
        {
            return Ok(None);
        }
        if self
            .storage
            .grants()
            .get_authorization_request(tenant, pending.request_id, now)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        Ok(Some(pending))
    }

    /// Allow: stores the grant (union of scopes and of resources), records `consent_granted` and returns the
    /// request to continue.
    pub async fn approve(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &ConsentBinding<'_>,
        ctx: &RequestContext,
    ) -> Result<ConsentSubmission, CoreError> {
        let Some(pending) = self.take_decision(tenant, session, binding).await? else {
            return Ok(ConsentSubmission::Expired);
        };
        let now = self.clock.now();
        let grant = self
            .storage
            .grants()
            .upsert_consent(
                tenant,
                &NewConsent {
                    id: ConsentId::new_v7(),
                    user_id: session.user_id,
                    client_id: pending.client_id.clone(),
                    scopes: pending.scopes.clone(),
                    created_at: now,
                    resources: normalize_resources(&pending.resources),
                },
                now,
            )
            .await?;
        self.audit()
            .record(
                tenant,
                AuditActor::user(session.user_id),
                AuditAction::ConsentGranted,
                Some(pending.client_id),
                AuditOutcome::Success,
                ctx,
                AuditDetails::scopes(&grant.scopes),
            )
            .await?;
        Ok(ConsentSubmission::Decided(pending.request_id))
    }

    /// Deny: nothing is stored; the request continues with `access_denied`.
    pub async fn deny(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &ConsentBinding<'_>,
    ) -> Result<ConsentSubmission, CoreError> {
        Ok(match self.take_decision(tenant, session, binding).await? {
            Some(pending) => ConsentSubmission::Decided(pending.request_id),
            None => ConsentSubmission::Expired,
        })
    }

    /// The user's active grants, in client id order.
    pub async fn list(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<ConnectedApp>, CoreError> {
        let grants = self.storage.grants().list_consents(tenant, user).await?;
        let mut apps = Vec::with_capacity(grants.len());
        for g in grants {
            let name = self
                .storage
                .clients()
                .get(tenant, &g.client_id)
                .await?
                .map_or_else(|| g.client_id.clone(), |c| c.name);
            apps.push(ConnectedApp {
                client_id: g.client_id,
                client_name: name,
                scopes: g.scopes,
                granted_at: g.created_at,
                updated_at: g.updated_at,
            });
        }
        Ok(apps)
    }

    /// Revokes the session user's grant for `client_id` and every token family of that user and
    /// client; records `consent_revoked`. A wrong binding is `Forbidden`.
    pub async fn revoke(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &ConsentBinding<'_>,
        client_id: &str,
        ctx: &RequestContext,
    ) -> Result<RevokeResult, CoreError> {
        if self.open(tenant, session, binding).await?.is_none() {
            return Ok(RevokeResult::FlowExpired);
        }
        Ok(
            if self
                .revoke_grant(tenant, session.user_id, client_id, ctx)
                .await?
            {
                RevokeResult::Revoked
            } else {
                RevokeResult::NoGrant
            },
        )
    }

    /// Revokes `user`'s grant for `client_id` (the binding was checked by the caller).
    async fn revoke_grant(
        &self,
        tenant: TenantId,
        user: UserId,
        client_id: &str,
        ctx: &RequestContext,
    ) -> Result<bool, CoreError> {
        let revoked = self
            .storage
            .grants()
            .revoke_consent(tenant, user, client_id, self.clock.now())
            .await?;
        if revoked {
            self.audit()
                .record(
                    tenant,
                    AuditActor::user(user),
                    AuditAction::ConsentRevoked,
                    Some(client_id.to_owned()),
                    AuditOutcome::Success,
                    ctx,
                    AuditDetails::empty(),
                )
                .await?;
        }
        Ok(revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::cimd_host;

    #[test]
    fn cimd_host_is_the_client_id_host_with_a_non_default_port() {
        assert_eq!(
            cimd_host("https://app.example.com/oauth/client.json").as_deref(),
            Some("app.example.com")
        );
        assert_eq!(
            cimd_host("https://app.example.com:443/c").as_deref(),
            Some("app.example.com")
        );
        assert_eq!(
            cimd_host("https://app.example.com:8443/c").as_deref(),
            Some("app.example.com:8443")
        );
        assert_eq!(
            cimd_host("http://127.0.0.1:9000/c").as_deref(),
            Some("127.0.0.1:9000")
        );
        assert_eq!(cimd_host("my-static-client"), None);
    }
}
