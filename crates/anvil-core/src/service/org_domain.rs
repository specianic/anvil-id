//! Organization domains: claims, DNS TXT verification and routing settings (ORG-04, plan 06-17).
//!
//! - [`OrgDomainService::add`] normalises the domain with
//!   [`policy::home_realm::normalize_domain`](crate::policy::home_realm::normalize_domain)
//!   (refusals name the reason, field `domain`) and stores a **pending** claim with a fresh
//!   random challenge token. Several orgs of a tenant may hold pending claims on one domain.
//! - [`OrgDomainService::verify`] runs the single DNS check,
//!   [`domain_check::check_domain`](crate::service::domain_check::check_domain). Every failure
//!   (no record, wrong value, lookup error) gives the same [`VerifyOutcome::Pending`]; a match
//!   marks the claim verified, unless another org of the tenant already verified the domain
//!   (`Conflict`, decided by the storage's unique index). Only someone who published the record
//!   learns about the other org.
//! - [`OrgDomainService::update`] changes the routing settings: the routing target (an
//!   enabled connection of the same org), routing on/off and `allow_local_password` (default
//!   `true`, decision Q6/Q7). Rules on the resulting state:
//!   - routing needs a verified domain and a target connection of this org that is enabled;
//!   - `allow_local_password = false` (SSO enforced for the domain) additionally needs routing
//!     on and a target connection with at least one successful SSO sign-in
//!     (`ConnectionRepo::has_links`); otherwise `Conflict` (lockout guard). A brand-new
//!     connection can be routed with passwords still allowed; its first users arrive by JIT.
//!
//!   A connection that is disabled later stops routing on its own (`OrgRepo::routed_domain`
//!   ignores disabled connections). The recovery path is a tenant administrator (or the org
//!   admin) setting `routing = false, allow_local_password = true`, which always passes.
//!
//! Every change records one audit event in the tenant, target = the domain claim id, details =
//! the org (`org_id`, `org_slug`) and the domain (`org_domain_created`, `org_domain_verified`,
//! `org_domain_verification_failed`, `org_domain_updated` with the changed field names,
//! `org_domain_deleted`). `org_domain_verified` is published as the
//! `organization.domain_verified` webhook event.

use std::sync::Arc;

use anvil_jose::encoding::random_bytes;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, ConnectionId, NewOrgDomain, OrgDomain,
    OrgDomainId, OrgDomainStatus, OrgDomainUpdate, Organization, RequestContext, truncate_to_ms,
};
use crate::policy::domain_verification::new_token;
use crate::policy::home_realm::normalize_domain;
use crate::ports::{DomainTxtLookup, Storage, StorageError};
use crate::service::audit::AuditService;
use crate::service::domain_check::{self, DomainCheck};

/// Partial routing update; `None` leaves a field unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainPatch {
    /// `Some(None)` removes the routing target.
    pub connection_id: Option<Option<ConnectionId>>,
    pub routing: Option<bool>,
    pub allow_local_password: Option<bool>,
}

/// The answer of a verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The record was found (or the claim was already verified).
    Verified(OrgDomain),
    /// Not verified; the same answer for every cause.
    Pending(OrgDomain),
}

/// The routing settings a patch would produce, checked by [`check_routing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingState {
    pub verified: bool,
    pub routing: bool,
    pub allow_local_password: bool,
    /// The target connection: `(enabled, has at least one identity link)`; `None` = no target.
    pub target: Option<(bool, bool)>,
}

fn conflict(message: &str) -> CoreError {
    CoreError::Conflict(message.to_owned())
}

/// The routing rules on the state after an update (module docs). Pure.
pub fn check_routing(s: RoutingState) -> Result<(), CoreError> {
    if s.routing {
        if !s.verified {
            return Err(conflict(
                "routing needs a verified domain; verify the DNS record first",
            ));
        }
        match s.target {
            None => {
                return Err(conflict(
                    "routing needs a target connection of this organization",
                ));
            }
            Some((false, _)) => {
                return Err(conflict(
                    "the target connection is disabled; enable it before routing to it",
                ));
            }
            Some((true, _)) => {}
        }
    }
    if !s.allow_local_password {
        // Lockout guard: forcing SSO is only allowed once SSO has worked.
        match s.target {
            Some((true, true)) if s.routing => {}
            _ => {
                return Err(conflict(
                    "password sign-in can only be turned off for a routed domain whose \
                     connection has completed at least one sign-in; test the connection first",
                ));
            }
        }
    }
    Ok(())
}

/// Organization domain claims, verification and routing settings.
#[derive(Clone)]
pub struct OrgDomainService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// The bounded, uncached TXT lookup used for verification.
    pub lookup: Arc<dyn DomainTxtLookup>,
}

impl OrgDomainService {
    async fn record(
        &self,
        org: &Organization,
        domain: &OrgDomain,
        actor: AuditActor,
        action: AuditAction,
        ctx: &RequestContext,
        extra: AuditDetails,
    ) -> Result<(), CoreError> {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
        .record(
            org.tenant_id,
            actor,
            action,
            Some(domain.id.to_string()),
            AuditOutcome::Success,
            ctx,
            AuditDetails::org(org.id, &org.slug)
                .with(AuditDetails::domain(&domain.domain))
                .with(extra),
        )
        .await
    }

    /// The claims of `org`, in domain order.
    pub async fn list(&self, org: &Organization) -> Result<Vec<OrgDomain>, CoreError> {
        Ok(self
            .storage
            .organizations()
            .list_domains(org.tenant_id, org.id)
            .await?)
    }

    /// The claim `id` of `org`; `NotFound` for another org's claim.
    pub async fn get(&self, org: &Organization, id: OrgDomainId) -> Result<OrgDomain, CoreError> {
        self.storage
            .organizations()
            .get_domain(org.tenant_id, id)
            .await?
            .filter(|d| d.org_id == org.id)
            .ok_or(CoreError::NotFound)
    }

    /// Claims `raw` for `org` (pending, with a new challenge token). `Conflict` if the org
    /// already claimed it. Audited as `org_domain_created`.
    pub async fn add(
        &self,
        org: &Organization,
        raw: &str,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<OrgDomain, CoreError> {
        let domain = normalize_domain(raw)?;
        let new = NewOrgDomain {
            id: OrgDomainId::new_v7(),
            org_id: org.id,
            domain,
            token: new_token(random_bytes::<16>()),
            connection_id: None,
            routing: false,
            allow_local_password: true,
            created_at: truncate_to_ms(self.clock.now()),
        };
        let created = self
            .storage
            .organizations()
            .create_domain(org.tenant_id, &new)
            .await
            .map_err(|e| match e {
                StorageError::Conflict(_) => {
                    conflict("this organization has already claimed this domain")
                }
                other => other.into(),
            })?;
        self.record(
            org,
            &created,
            actor,
            AuditAction::OrgDomainCreated,
            ctx,
            AuditDetails::empty(),
        )
        .await?;
        Ok(created)
    }

    /// Checks the claim's TXT record once. A verified claim is returned as is. A match marks
    /// the claim verified (audited `org_domain_verified`); `Conflict` when another org of the
    /// tenant verified the domain first. Anything else is [`VerifyOutcome::Pending`] (audited
    /// `org_domain_verification_failed` without a cause).
    pub async fn verify(
        &self,
        org: &Organization,
        id: OrgDomainId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<VerifyOutcome, CoreError> {
        let claim = self.get(org, id).await?;
        if claim.status == OrgDomainStatus::Verified {
            return Ok(VerifyOutcome::Verified(claim));
        }
        match domain_check::check_domain(self.lookup.as_ref(), &claim.domain, &claim.token).await {
            DomainCheck::NotVerified => {
                self.record(
                    org,
                    &claim,
                    actor,
                    AuditAction::OrgDomainVerificationFailed,
                    ctx,
                    AuditDetails::empty(),
                )
                .await?;
                Ok(VerifyOutcome::Pending(claim))
            }
            DomainCheck::Verified => {
                let verified = self
                    .storage
                    .organizations()
                    .mark_verified(org.tenant_id, id, truncate_to_ms(self.clock.now()))
                    .await
                    .map_err(|e| match e {
                        StorageError::Conflict(_) => conflict(
                            "another organization of this tenant has already verified this \
                             domain",
                        ),
                        other => other.into(),
                    })?
                    .ok_or(CoreError::NotFound)?;
                self.record(
                    org,
                    &verified,
                    actor,
                    AuditAction::OrgDomainVerified,
                    ctx,
                    AuditDetails::empty(),
                )
                .await?;
                Ok(VerifyOutcome::Verified(verified))
            }
        }
    }

    /// Changes the routing settings ([`check_routing`] on the resulting state). The target
    /// must be a connection of this org (`Validation` on `connection_id` otherwise). Audited as
    /// `org_domain_updated` with the changed field names.
    pub async fn update(
        &self,
        org: &Organization,
        id: OrgDomainId,
        patch: DomainPatch,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<OrgDomain, CoreError> {
        let current = self.get(org, id).await?;
        let target_id = patch.connection_id.unwrap_or(current.connection_id);
        let target = match target_id {
            None => None,
            Some(cid) => {
                let conn = self
                    .storage
                    .connections()
                    .get(org.tenant_id, cid)
                    .await?
                    .filter(|c| c.org_id == Some(org.id))
                    .ok_or_else(|| CoreError::Validation {
                        field: "connection_id",
                        message: "must be a connection of this organization".to_owned(),
                    })?;
                let has_links = self
                    .storage
                    .connections()
                    .has_links(org.tenant_id, conn.id)
                    .await?;
                Some((conn.enabled, has_links))
            }
        };
        check_routing(RoutingState {
            verified: current.status == OrgDomainStatus::Verified,
            routing: patch.routing.unwrap_or(current.routing),
            allow_local_password: patch
                .allow_local_password
                .unwrap_or(current.allow_local_password),
            target,
        })?;
        let mut fields = Vec::new();
        if patch.connection_id.is_some() {
            fields.push("connection_id");
        }
        if patch.routing.is_some() {
            fields.push("routing");
        }
        if patch.allow_local_password.is_some() {
            fields.push("allow_local_password");
        }
        let updated = self
            .storage
            .organizations()
            .update_domain(
                org.tenant_id,
                id,
                &OrgDomainUpdate {
                    connection_id: patch.connection_id,
                    routing: patch.routing,
                    allow_local_password: patch.allow_local_password,
                },
                truncate_to_ms(self.clock.now()),
            )
            .await?
            .ok_or_else(|| CoreError::Validation {
                field: "connection_id",
                message: "must be a connection of this organization".to_owned(),
            })?;
        self.record(
            org,
            &updated,
            actor,
            AuditAction::OrgDomainUpdated,
            ctx,
            AuditDetails::fields(&fields),
        )
        .await?;
        Ok(updated)
    }

    /// Removes the claim (routing for the domain stops). Audited as `org_domain_deleted`.
    pub async fn delete(
        &self,
        org: &Organization,
        id: OrgDomainId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let claim = self.get(org, id).await?;
        if !self
            .storage
            .organizations()
            .delete_domain(org.tenant_id, id)
            .await?
        {
            return Err(CoreError::NotFound);
        }
        self.record(
            org,
            &claim,
            actor,
            AuditAction::OrgDomainDeleted,
            ctx,
            AuditDetails::empty(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(
        verified: bool,
        routing: bool,
        pwd: bool,
        target: Option<(bool, bool)>,
    ) -> RoutingState {
        RoutingState {
            verified,
            routing,
            allow_local_password: pwd,
            target,
        }
    }

    fn is_conflict(r: Result<(), CoreError>) -> bool {
        matches!(r, Err(CoreError::Conflict(_)))
    }

    #[test]
    fn routing_with_passwords_needs_a_verified_domain_and_an_enabled_target() {
        assert!(check_routing(state(true, true, true, Some((true, false)))).is_ok());
        assert!(is_conflict(check_routing(state(
            false,
            true,
            true,
            Some((true, true))
        ))));
        assert!(is_conflict(check_routing(state(true, true, true, None))));
        assert!(is_conflict(check_routing(state(
            true,
            true,
            true,
            Some((false, true))
        ))));
    }

    #[test]
    fn no_routing_with_passwords_is_always_allowed() {
        for verified in [false, true] {
            for target in [None, Some((false, false)), Some((true, true))] {
                assert!(check_routing(state(verified, false, true, target)).is_ok());
            }
        }
    }

    #[test]
    fn disabling_passwords_needs_routing_to_a_proven_connection() {
        assert!(check_routing(state(true, true, false, Some((true, true)))).is_ok());
        assert!(is_conflict(check_routing(state(
            true,
            true,
            false,
            Some((true, false))
        ))));
        assert!(is_conflict(check_routing(state(
            true,
            false,
            false,
            Some((true, true))
        ))));
        assert!(is_conflict(check_routing(state(true, false, false, None))));
        assert!(is_conflict(check_routing(state(
            false,
            true,
            false,
            Some((true, true))
        ))));
        assert!(is_conflict(check_routing(state(
            true,
            true,
            false,
            Some((false, true))
        ))));
    }
}
