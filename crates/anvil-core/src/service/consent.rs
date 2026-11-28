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
//! client itself publishes, so [`Provenance::Cimd`] carries the host of its `client_id` URL for
//! the screen to show as the client's identity.
//!
//! # Agents and step-up (AGT-03)
//!
//! [`ConsentPage::view`] tells the screen whether the client is an AI agent
//! (`client_kind = agent`), who vouches for it ([`Provenance`]), and which requested scopes and
//! resources are new compared with the user's stored grant (the rest were already allowed).
//! Allow stores the union; Deny stores nothing, so denying a step-up leaves the existing grant
//! exactly as it was. Agents never skip consent through `skip_first_party` (refused at every
//! client write path by `service::client::validate_client_policy`).

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::audit::AuditService;
use super::flow::{BindingError, FLOW_LIFETIME, check_binding};
use crate::error::CoreError;
use crate::flow::consent::{
    ConsentCoverage, ConsentDecision, ConsentState, ConsentView, PendingConsent, Provenance,
    consent_decision, requested_scopes,
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
    /// The client (name, kind, provenance) and the requested scopes and RFC 8707 resources
    /// (request order, already validated against the client's allowed resources), split
    /// against the user's stored grant into new and already allowed ones. Allow adds every
    /// requested scope and resource to the grant.
    pub view: ConsentView,
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
        page: Box<ConsentPage>,
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
        let grant = self
            .storage
            .grants()
            .consent(tenant, session.user_id, &client.client_id)
            .await?;
        let provenance = match client.registration_source {
            ClientSource::Static => Provenance::Static,
            ClientSource::Dynamic => Provenance::Dynamic,
            ClientSource::Cimd => match cimd_host(&client.client_id) {
                Some(host) => Provenance::Cimd { host },
                // A stored CIMD client always has a URL client_id.
                None => {
                    return Err(CoreError::Internal(
                        "CIMD client without a URL client_id".into(),
                    ));
                }
            },
        };
        let view = ConsentView::new(
            client.name,
            client.client_kind,
            provenance,
            grant.as_ref().map(|g| ConsentCoverage {
                scopes: &g.scopes,
                resources: &g.resources,
            }),
            ConsentCoverage {
                scopes: &scopes,
                resources: &request.params.resource,
            },
        );
        let flow = self.create_flow(tenant, &state, Some(request_id)).await?;
        Ok(ConsentStart::Started {
            flow,
            page: Box::new(ConsentPage {
                request_id,
                client_id: client.client_id,
                view,
            }),
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

    /// Deny: nothing is stored and an existing grant is left untouched (denying a step-up
    /// neither revokes nor shrinks it); the request continues with `access_denied`.
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

    /// The email address of `session`'s user: the account the consent screen asks for.
    pub async fn account_email(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
    ) -> Result<String, CoreError> {
        if session.tenant_id != tenant {
            return Err(CoreError::Forbidden);
        }
        match self.storage.users().get(tenant, session.user_id).await? {
            Some(user) => Ok(user.email),
            None => Err(CoreError::Forbidden),
        }
    }

    /// "Use another account" on the consent screen: takes the decision like Allow or Deny (same
    /// binding, owner and single-use checks; [`CoreError::Forbidden`] for a bad binding) but
    /// stores nothing and leaves an existing grant untouched. Returns the request, which then
    /// goes to the login page
    /// ([`AuthorizeService::sign_in_as_other`](super::authorize::AuthorizeService::sign_in_as_other));
    /// the next user's consent is asked for that user.
    pub async fn switch_account(
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
    use super::*;
    use crate::model::*;
    use crate::ports::*;
    use std::sync::Mutex;
    use time::macros::datetime;

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

    // -----------------------------------------------------------------------------------------
    // Step-up Allow / Deny against a storage fake (clients, flows, grants and audit only).
    // -----------------------------------------------------------------------------------------

    const T0: OffsetDateTime = datetime!(2026-01-01 00:00 UTC);
    const ONLY: &str = "consent tests use clients, flows, grants and audit only";

    fn unsupported<T>() -> Result<T, StorageError> {
        Err(StorageError::Unsupported("consent fake"))
    }

    #[derive(Default)]
    struct Fake {
        clients: Mutex<Vec<Client>>,
        flows: Mutex<Vec<Flow>>,
        requests: Mutex<Vec<AuthorizationRequest>>,
        grants: Mutex<Vec<ConsentGrant>>,
        /// Every grant write (`upsert_consent`, `revoke_consent`), in call order.
        grant_writes: Mutex<Vec<&'static str>>,
    }

    #[async_trait::async_trait]
    impl ClientRepo for Fake {
        async fn create(&self, _: TenantId, _: &NewClient) -> Result<Client, StorageError> {
            unsupported()
        }
        async fn get(&self, _: TenantId, client_id: &str) -> Result<Option<Client>, StorageError> {
            Ok(self
                .clients
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.client_id == client_id)
                .cloned())
        }
        async fn list(&self, _: TenantId, _: PageRequest) -> Result<Page<Client>, StorageError> {
            unsupported()
        }
        async fn update(
            &self,
            _: TenantId,
            _: &str,
            _: &ClientUpdate,
            _: OffsetDateTime,
        ) -> Result<Option<Client>, StorageError> {
            unsupported()
        }
        async fn set_secret_hash(
            &self,
            _: TenantId,
            _: &str,
            _: Option<SecretHash>,
            _: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn delete(&self, _: TenantId, _: &str) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn upsert_cimd(
            &self,
            _: TenantId,
            _: &NewClient,
            _: OffsetDateTime,
            _: OffsetDateTime,
        ) -> Result<Client, StorageError> {
            unsupported()
        }
        async fn get_by_registration_token(
            &self,
            _: TenantId,
            _: &str,
            _: &SecretHash,
        ) -> Result<Option<Client>, StorageError> {
            unsupported()
        }
        async fn set_registration_token(
            &self,
            _: TenantId,
            _: &str,
            _: Option<&SecretHash>,
            _: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
    }

    #[async_trait::async_trait]
    impl FlowRepo for Fake {
        async fn create(&self, tenant: TenantId, f: &NewFlow) -> Result<(), StorageError> {
            self.flows.lock().unwrap().push(Flow {
                id: f.id,
                tenant_id: tenant,
                kind: f.kind,
                state: f.state.clone(),
                csrf_hash: f.csrf_hash,
                cookie_hash: f.cookie_hash,
                auth_request_id: f.auth_request_id,
                created_at: f.created_at,
                expires_at: f.expires_at,
            });
            Ok(())
        }
        async fn get(
            &self,
            _: TenantId,
            id: FlowId,
            now: OffsetDateTime,
        ) -> Result<Option<Flow>, StorageError> {
            Ok(self
                .flows
                .lock()
                .unwrap()
                .iter()
                .find(|f| f.id == id && f.expires_at > now)
                .cloned())
        }
        async fn update_state(
            &self,
            _: TenantId,
            _: FlowId,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn delete(&self, _: TenantId, _: FlowId) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn swap_state(
            &self,
            _: TenantId,
            id: FlowId,
            expected: &str,
            new: &str,
            _: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut flows = self.flows.lock().unwrap();
            match flows.iter_mut().find(|f| f.id == id && f.state == expected) {
                Some(f) => {
                    f.state = new.to_owned();
                    Ok(true)
                }
                None => Ok(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl GrantRepo for Fake {
        async fn create_authorization_request(
            &self,
            _: TenantId,
            _: &NewAuthorizationRequest,
        ) -> Result<(), StorageError> {
            unsupported()
        }
        async fn get_authorization_request(
            &self,
            _: TenantId,
            id: AuthRequestId,
            now: OffsetDateTime,
        ) -> Result<Option<AuthorizationRequest>, StorageError> {
            Ok(self
                .requests
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.id == id && r.expires_at > now)
                .cloned())
        }
        async fn delete_authorization_request(
            &self,
            _: TenantId,
            _: AuthRequestId,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn create_code(
            &self,
            _: TenantId,
            _: &NewAuthorizationCode,
            _: &NewTokenFamily,
        ) -> Result<(), StorageError> {
            unsupported()
        }
        async fn consume_code(
            &self,
            _: TenantId,
            _: &CodeHash,
            _: OffsetDateTime,
        ) -> Result<ConsumeOutcome, StorageError> {
            unsupported()
        }
        async fn get_family(
            &self,
            _: TenantId,
            _: TokenFamilyId,
        ) -> Result<Option<TokenFamily>, StorageError> {
            unsupported()
        }
        async fn revoke_family(
            &self,
            _: TenantId,
            _: TokenFamilyId,
            _: RevokeReason,
            _: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn create_refresh_token(
            &self,
            _: TenantId,
            _: &NewRefreshToken,
        ) -> Result<(), StorageError> {
            unsupported()
        }
        async fn find_refresh_token(
            &self,
            _: TenantId,
            _: &SecretHash,
        ) -> Result<Option<(RefreshToken, TokenFamily)>, StorageError> {
            unsupported()
        }
        async fn rotate_refresh(
            &self,
            _: TenantId,
            _: &SecretHash,
            _: &NewRefreshToken,
            _: OffsetDateTime,
        ) -> Result<RotateOutcome, StorageError> {
            unsupported()
        }
        async fn record_jti(
            &self,
            _: TenantId,
            _: ReplayKind,
            _: &SecretHash,
            _: OffsetDateTime,
            _: OffsetDateTime,
        ) -> Result<JtiOutcome, StorageError> {
            unsupported()
        }
        async fn create_family(&self, _: TenantId, _: &NewTokenFamily) -> Result<(), StorageError> {
            unsupported()
        }
        async fn create_access_token(
            &self,
            _: TenantId,
            _: &NewAccessToken,
        ) -> Result<(), StorageError> {
            unsupported()
        }
        async fn find_access_token(
            &self,
            _: TenantId,
            _: &SecretHash,
        ) -> Result<Option<(AccessTokenRecord, Option<TokenFamily>)>, StorageError> {
            unsupported()
        }
        async fn revoke_access_token(
            &self,
            _: TenantId,
            _: &SecretHash,
            _: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn consent(
            &self,
            _: TenantId,
            user: UserId,
            client_id: &str,
        ) -> Result<Option<ConsentGrant>, StorageError> {
            Ok(self
                .grants
                .lock()
                .unwrap()
                .iter()
                .find(|g| g.user_id == user && g.client_id == client_id && g.revoked_at.is_none())
                .cloned())
        }
        async fn list_consents(
            &self,
            _: TenantId,
            _: UserId,
        ) -> Result<Vec<ConsentGrant>, StorageError> {
            unsupported()
        }
        async fn upsert_consent(
            &self,
            _: TenantId,
            c: &NewConsent,
            now: OffsetDateTime,
        ) -> Result<ConsentGrant, StorageError> {
            self.grant_writes.lock().unwrap().push("upsert_consent");
            let mut grants = self.grants.lock().unwrap();
            let Some(g) = grants
                .iter_mut()
                .find(|g| g.user_id == c.user_id && g.client_id == c.client_id)
            else {
                unreachable!("the consent tests seed a grant first");
            };
            for s in &c.scopes {
                if !g.scopes.contains(s) {
                    g.scopes.push(s.clone());
                }
            }
            g.scopes.sort();
            g.resources = normalize_resources(&[g.resources.clone(), c.resources.clone()].concat());
            g.updated_at = now;
            Ok(g.clone())
        }
        async fn revoke_consent(
            &self,
            _: TenantId,
            _: UserId,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            self.grant_writes.lock().unwrap().push("revoke_consent");
            unsupported()
        }
        async fn families_for_user(
            &self,
            _: TenantId,
            _: UserId,
        ) -> Result<Vec<TokenFamily>, StorageError> {
            unsupported()
        }
        async fn create_pushed_request(
            &self,
            _: TenantId,
            _: &NewPushedRequest,
        ) -> Result<(), StorageError> {
            unsupported()
        }
        async fn consume_pushed_request(
            &self,
            _: TenantId,
            _: &RequestUriHash,
            _: OffsetDateTime,
        ) -> Result<Option<PushedRequest>, StorageError> {
            unsupported()
        }
    }

    #[async_trait::async_trait]
    impl AuditRepo for Fake {
        async fn append(&self, _: TenantId, _: &NewAuditEvent) -> Result<(), StorageError> {
            Ok(())
        }
        async fn query(
            &self,
            _: TenantId,
            _: &AuditQuery,
        ) -> Result<Page<AuditEvent>, StorageError> {
            unsupported()
        }
        async fn purge_before(&self, _: OffsetDateTime) -> Result<u64, StorageError> {
            unsupported()
        }
    }

    #[async_trait::async_trait]
    impl Storage for Fake {
        fn tenants(&self) -> &dyn TenantRepo {
            unreachable!("{ONLY}")
        }
        fn users(&self) -> &dyn UserRepo {
            unreachable!("{ONLY}")
        }
        fn clients(&self) -> &dyn ClientRepo {
            self
        }
        fn keys(&self) -> &dyn KeyRepo {
            unreachable!("{ONLY}")
        }
        fn sessions(&self) -> &dyn SessionRepo {
            unreachable!("{ONLY}")
        }
        fn flows(&self) -> &dyn FlowRepo {
            self
        }
        fn grants(&self) -> &dyn GrantRepo {
            self
        }
        fn setup(&self) -> &dyn SetupRepo {
            unreachable!("{ONLY}")
        }
        fn outbox(&self) -> &dyn OutboxRepo {
            unreachable!("{ONLY}")
        }
        fn audit(&self) -> &dyn AuditRepo {
            self
        }
        fn mail_settings(&self) -> &dyn MailSettingsRepo {
            unreachable!("{ONLY}")
        }
        fn jobs(&self) -> &dyn JobRepo {
            unreachable!("{ONLY}")
        }
        fn connections(&self) -> &dyn ConnectionRepo {
            unreachable!("{ONLY}")
        }
        fn branding(&self) -> &dyn BrandingRepo {
            unreachable!("{ONLY}")
        }
        fn logout(&self) -> &dyn LogoutRepo {
            unreachable!("{ONLY}")
        }
        fn roles(&self) -> &dyn RoleRepo {
            unreachable!("{ONLY}")
        }
        fn attributes(&self) -> &dyn AttributeRepo {
            unreachable!("{ONLY}")
        }
        fn webhooks(&self) -> &dyn WebhookRepo {
            unreachable!("{ONLY}")
        }
        fn registration(&self) -> &dyn RegistrationRepo {
            unreachable!("{ONLY}")
        }
        fn organizations(&self) -> &dyn OrgRepo {
            unreachable!("{ONLY}")
        }
        fn password_profiles(&self) -> &dyn PasswordProfileRepo {
            unreachable!("{ONLY}")
        }
        async fn purge_expired(&self, _: OffsetDateTime) -> Result<u64, StorageError> {
            unsupported()
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            T0
        }
    }

    const AGENT_ID: &str = "agent-1";
    const MCP: &str = "https://mcp.example/";
    const OTHER: &str = "https://other.example/";

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|v| (*v).to_owned()).collect()
    }

    fn agent(tenant: TenantId, source: ClientSource, client_id: &str) -> Client {
        Client {
            id: ClientId::new_v7(),
            tenant_id: tenant,
            client_id: client_id.into(),
            name: "Research agent".into(),
            client_type: ClientType::Public,
            application_type: ApplicationType::Web,
            auth_method: ClientAuthMethod::None,
            secret_hash: None,
            jwks: None,
            redirect_uris: vec!["https://rp.example/cb".into()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: strings(&["openid", "profile", "email"]),
            require_pkce: true,
            token_format: TokenFormat::Jwt,
            consent_mode: ConsentMode::Required,
            id_token_signed_response_alg: None,
            can_introspect: false,
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources: strings(&[MCP, OTHER]),
            mfa_policy: None,
            registration_source: source,
            metadata_expires_at: None,
            registration_access_token_hash: None,
            organization: OrgClientPolicy::Off,
            require_pushed_authorization_requests: false,
            client_kind: ClientKind::Agent,
            headless_native: false,
            created_at: T0,
            updated_at: T0,
            client_uri: None,
            initiate_login_uri: None,
        }
    }

    struct Harness {
        fake: Arc<Fake>,
        svc: ConsentService,
        tenant: TenantId,
        session: BrowserSession,
    }

    impl Harness {
        /// An agent client of `source`, a user with a grant of `granted` scopes and resources.
        fn new(source: ClientSource, client_id: &str, granted: (&[&str], &[&str])) -> Self {
            let tenant = TenantId::new_v7();
            let user = UserId::new_v7();
            let fake = Arc::new(Fake::default());
            fake.clients
                .lock()
                .unwrap()
                .push(agent(tenant, source, client_id));
            fake.grants.lock().unwrap().push(ConsentGrant {
                id: ConsentId::new_v7(),
                user_id: user,
                client_id: client_id.into(),
                scopes: strings(granted.0),
                resources: strings(granted.1),
                created_at: T0,
                updated_at: T0,
                revoked_at: None,
            });
            let session = BrowserSession {
                id: SessionId::new_v7(),
                tenant_id: tenant,
                user_id: user,
                token_hash: SecretHash([0; 32]),
                auth_time: T0,
                acr: "0".into(),
                amr: vec!["pwd".into()],
                created_at: T0,
                last_seen_at: T0,
                expires_at: T0 + time::Duration::hours(1),
                idle_expires_at: T0 + time::Duration::hours(1),
                revoked_at: None,
                ip: None,
                user_agent: None,
            };
            let svc = ConsentService {
                storage: fake.clone(),
                clock: Arc::new(FixedClock),
            };
            Self {
                fake,
                svc,
                tenant,
                session,
            }
        }

        fn request(&self, client_id: &str, scope: &str, resources: &[&str]) -> AuthRequestId {
            let id = AuthRequestId::new_v7();
            self.fake
                .requests
                .lock()
                .unwrap()
                .push(AuthorizationRequest {
                    id,
                    tenant_id: self.tenant,
                    client_id: client_id.into(),
                    params: AuthorizationParams {
                        redirect_uri: "https://rp.example/cb".into(),
                        scope: scope.into(),
                        state: None,
                        nonce: None,
                        code_challenge: Some("c".into()),
                        prompt: vec![],
                        max_age: None,
                        login_hint: None,
                        acr_values: vec![],
                        ui_locales: None,
                        claims: None,
                        response_mode: Default::default(),
                        resource: strings(resources),
                        organization: None,
                    },
                    created_at: T0,
                    expires_at: T0 + time::Duration::minutes(10),
                });
            id
        }

        async fn open(&self, request: AuthRequestId) -> (StartedConsentFlow, ConsentPage) {
            match self
                .svc
                .start(self.tenant, &self.session, request)
                .await
                .expect("start")
            {
                ConsentStart::Started { flow, page } => (flow, *page),
                ConsentStart::RequestExpired => panic!("request expired"),
            }
        }

        fn grant(&self) -> ConsentGrant {
            self.fake.grants.lock().unwrap()[0].clone()
        }
    }

    use secrecy::ExposeSecret as _;

    fn binding(flow: &StartedConsentFlow) -> ConsentBinding<'_> {
        ConsentBinding {
            flow_id: flow.flow_id,
            cookie_token: Some(flow.cookie_token.expose_secret()),
            csrf_token: flow.csrf_token.expose_secret(),
        }
    }

    #[tokio::test]
    async fn step_up_page_shows_only_the_new_scopes_and_resources() {
        let h = Harness::new(
            ClientSource::Dynamic,
            AGENT_ID,
            (&["openid", "profile"], &[MCP]),
        );
        let request = h.request(AGENT_ID, "openid profile email", &[MCP, OTHER]);
        let (_, page) = h.open(request).await;
        let v = &page.view;
        assert_eq!(v.client_kind, ClientKind::Agent);
        assert_eq!(v.provenance, Provenance::Dynamic);
        assert_eq!(v.new_scopes, strings(&["email"]));
        assert_eq!(v.granted_scopes, strings(&["openid", "profile"]));
        assert_eq!(v.new_resources, strings(&[OTHER]));
        assert_eq!(v.granted_resources, strings(&[MCP]));
    }

    #[tokio::test]
    async fn provenance_follows_the_registration_source() {
        for (source, client_id, expected) in [
            (ClientSource::Static, AGENT_ID, Provenance::Static),
            (ClientSource::Dynamic, AGENT_ID, Provenance::Dynamic),
            (
                ClientSource::Cimd,
                "https://agent.example:8443/client.json",
                Provenance::Cimd {
                    host: "agent.example:8443".into(),
                },
            ),
        ] {
            let h = Harness::new(source, client_id, (&[], &[]));
            let (_, page) = h.open(h.request(client_id, "openid", &[])).await;
            assert_eq!(page.view.provenance, expected, "{source:?}");
        }
    }

    #[tokio::test]
    async fn step_up_deny_leaves_the_grant_untouched() {
        let h = Harness::new(
            ClientSource::Static,
            AGENT_ID,
            (&["openid", "profile"], &[MCP]),
        );
        let before = h.grant();
        let request = h.request(AGENT_ID, "openid profile email", &[MCP, OTHER]);
        let (flow, _) = h.open(request).await;
        let result = h
            .svc
            .deny(h.tenant, &h.session, &binding(&flow))
            .await
            .expect("deny");
        assert_eq!(result, ConsentSubmission::Decided(request));
        assert_eq!(h.grant(), before, "deny must not change the stored grant");
        assert!(
            h.fake.grant_writes.lock().unwrap().is_empty(),
            "deny must not write grants"
        );
    }

    #[tokio::test]
    async fn step_up_allow_stores_the_union() {
        let h = Harness::new(
            ClientSource::Static,
            AGENT_ID,
            (&["openid", "profile"], &[MCP]),
        );
        let request = h.request(AGENT_ID, "openid email", &[OTHER]);
        let (flow, _) = h.open(request).await;
        let result = h
            .svc
            .approve(
                h.tenant,
                &h.session,
                &binding(&flow),
                &RequestContext::system(),
            )
            .await
            .expect("approve");
        assert_eq!(result, ConsentSubmission::Decided(request));
        let g = h.grant();
        assert_eq!(g.scopes, strings(&["email", "openid", "profile"]));
        assert_eq!(g.resources, strings(&[MCP, OTHER]));
    }
}
