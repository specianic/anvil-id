//! User export (ADM-09): a single user, a tenant's users in bulk, and a user's data-subject
//! (GDPR) bundle, read through the storage ports only. Shared by the admin API (plan 07-17) and
//! `anvilid users export`.
//!
//! # Allow-list
//!
//! Every exported shape is a dedicated `Serialize` struct of this module. Storage models are never
//! serialised for export, so a field added to a model is not exported until it is added here on
//! purpose. Secrets are never exported: no password hash (except the opt-in below), TOTP seed,
//! recovery code, passkey private material, sealed blob, token hash, client secret or signer key.
//! Credentials appear as metadata only (kind, label, dates).
//!
//! # Password hashes
//!
//! [`UserExportService::bulk`] takes [`ExportOptions`]; with `include_password_hashes` each
//! record carries the stored PHC string. Only the CLI (`anvilid users export
//! --include-password-hashes`, decision Q4) sets it. The HTTP layer uses
//! [`UserExportService::bulk_without_hashes`], which has no options parameter, so no HTTP path can
//! reach the flag. The single export and the GDPR bundle never carry a hash; [`GdprBundle`] has no
//! field for one at all.
//!
//! # Bulk paging
//!
//! [`BulkExport`] is a page iterator: each [`BulkExport::next_page`] reads one keyset page of
//! `UserRepo::list` (default [`BULK_PAGE_SIZE`]) and returns at most that many records, so memory
//! is bounded by the page size and the tenant's users are never loaded at once. Users come in id
//! order, each exactly once. It is a plain async page iterator (anvil-core has no stream
//! dependency); the NDJSON body of 07-17 wraps it with `futures::stream::unfold`.
//!
//! # GDPR bundle
//!
//! [`GdprBundle`] holds every category of personal data stored about the user: profile and
//! claims, custom attributes, credential metadata (TOTP enrolled yes/no, recovery codes as a
//! count), active sessions (with IP and user agent when stored), consent grants, token families
//! (never token hashes), identity links (the upstream source), organization memberships and
//! roles, audit events where the user is the actor or the target, and pending self-service tokens
//! as existence only (kind and expiry). Webhook deliveries that mention the user are excluded:
//! they are operational copies of the events above.
//!
//! Audit entries name other people (typically an administrator). In the bundle the actor is a
//! role label (`subject`, `administrator`, `another_user`, `system`, `client`), and a target that
//! is another user of the tenant becomes `another_user`, so the copy does not disclose other
//! people's identities.
//!
//! `operator_statement` is a slot for the operator's own statements (purposes, recipients,
//! retention). The software cannot know them and always leaves it `null`; operators fill it in
//! before handing the bundle over.
//!
//! # Audit
//!
//! Every export is audited as `user_exported` with the mode, the number of users and whether
//! password hashes were included.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde::Serialize;
use serde_json::{Map, Value};
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

use crate::error::CoreError;
use crate::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditEvent, AuditOutcome, AuditQuery,
    ConnectionId, CredentialKind, CredentialSummary, IdentityLink, PageRequest, RequestContext,
    Role, StandardClaims, TenantId, User, UserId,
};
use crate::ports::{Clock, Storage};
use crate::service::audit::AuditService;

/// Users read per page by the bulk export.
pub const BULK_PAGE_SIZE: u32 = 100;

/// Audit events read per page for the GDPR bundle.
const AUDIT_PAGE: u32 = PageRequest::MAX_LIMIT;

/// Version of the GDPR bundle format.
pub const GDPR_FORMAT_VERSION: u32 = 1;

/// Options of the bulk export. Only the CLI builds this (see the module docs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportOptions {
    /// Add each user's stored PHC string (`password_hash`). CLI only; audited.
    pub include_password_hashes: bool,
}

// ---------------------------------------------------------------------------------------------
// DTOs (allow-list)
// ---------------------------------------------------------------------------------------------

/// OIDC standard claims of a user (OIDC Core 5.1), exported field by field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimsExport {
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub address: Option<AddressExport>,
}

/// OIDC address claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressExport {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

impl From<&StandardClaims> for ClaimsExport {
    fn from(c: &StandardClaims) -> Self {
        Self {
            name: c.name.clone(),
            given_name: c.given_name.clone(),
            family_name: c.family_name.clone(),
            middle_name: c.middle_name.clone(),
            nickname: c.nickname.clone(),
            preferred_username: c.preferred_username.clone(),
            profile: c.profile.clone(),
            picture: c.picture.clone(),
            website: c.website.clone(),
            gender: c.gender.clone(),
            birthdate: c.birthdate.clone(),
            zoneinfo: c.zoneinfo.clone(),
            locale: c.locale.clone(),
            phone_number: c.phone_number.clone(),
            phone_number_verified: c.phone_number_verified,
            address: c.address.as_ref().map(|a| AddressExport {
                formatted: a.formatted.clone(),
                street_address: a.street_address.clone(),
                locality: a.locality.clone(),
                region: a.region.clone(),
                postal_code: a.postal_code.clone(),
                country: a.country.clone(),
            }),
        }
    }
}

/// A role by id and name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleRef {
    pub id: String,
    pub name: String,
}

impl From<&Role> for RoleRef {
    fn from(r: &Role) -> Self {
        Self {
            id: r.id.to_string(),
            name: r.name.clone(),
        }
    }
}

/// An organization membership and the roles held in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrgMembershipExport {
    pub org_id: String,
    pub slug: String,
    pub display_name: String,
    pub roles: Vec<RoleRef>,
}

/// An identity link: the connection and the upstream subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityLinkExport {
    pub connection_id: String,
    /// `None` if the connection was deleted in the meantime.
    pub connection: Option<String>,
    pub subject: String,
}

/// Credential metadata (never the secret, seed, hash or key material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialMetadata {
    pub id: String,
    /// `password`, `webauthn` or `totp`.
    pub kind: &'static str,
    pub label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

impl From<&CredentialSummary> for CredentialMetadata {
    fn from(c: &CredentialSummary) -> Self {
        Self {
            id: c.id.0.to_string(),
            kind: c.kind.as_str(),
            label: c.label.clone(),
            created_at: rfc3339(c.created_at),
            last_used_at: c.last_used_at.map(rfc3339),
        }
    }
}

/// One exported user (single export and each bulk line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserExportRecord {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub status: &'static str,
    pub claims: ClaimsExport,
    /// Custom attribute values (the stored JSON object).
    pub attributes: Map<String, Value>,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
    /// Tenant-wide roles.
    pub roles: Vec<RoleRef>,
    pub organizations: Vec<OrgMembershipExport>,
    pub identity_links: Vec<IdentityLinkExport>,
    pub credentials: Vec<CredentialMetadata>,
    /// The stored PHC string. Present only in the CLI bulk export with
    /// `--include-password-hashes`; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

/// The data subject's account in the GDPR bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprSubject {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub status: &'static str,
    pub claims: ClaimsExport,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
}

/// Credential metadata in the GDPR bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprCredentials {
    /// Every credential row (password, passkeys, TOTP) as metadata.
    pub items: Vec<CredentialMetadata>,
    pub password_set: bool,
    pub totp_enrolled: bool,
    pub recovery_codes_remaining: u32,
}

/// An active browser session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprSession {
    pub id: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub auth_time: String,
    pub expires_at: String,
    pub authentication_methods: Vec<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// A consent grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprConsent {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resources: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub revoked_at: Option<String>,
}

/// A token family (never a token or its hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprTokenFamily {
    pub id: String,
    pub client_id: String,
    pub scope: String,
    pub resources: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub revoked_reason: Option<&'static str>,
}

/// An identity link with the details stored at link time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprIdentityLink {
    pub connection_id: String,
    pub connection: Option<String>,
    pub subject: String,
    pub email_at_link: Option<String>,
    /// Provider identifiers stored with the link (e.g. a Microsoft tenant id).
    pub metadata: Map<String, Value>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// An audit event about or by the subject, with other people's identities replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprAuditEvent {
    pub id: String,
    pub at: String,
    pub action: &'static str,
    pub outcome: &'static str,
    /// `subject`, `administrator`, `another_user`, `system` or `client`.
    pub actor: &'static str,
    /// The client id when the actor is a client (an application, not a person).
    pub actor_client_id: Option<String>,
    /// `subject`, `another_user` or the target as stored (client id, session id, ...).
    pub target: Option<String>,
    /// IP and user agent, only on events the subject performed.
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub details: Map<String, Value>,
}

/// A pending self-service token (existence only: kind and expiry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprPendingToken {
    pub kind: &'static str,
    pub expires_at: String,
}

/// The operator's statements (GDPR Art. 15(1)): filled in by the operator, never by the software.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorStatement {
    pub purposes: String,
    pub recipients: String,
    pub retention: String,
}

/// The data-subject export of one user. Has no password-hash field (decision Q4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdprBundle {
    pub export_format_version: u32,
    pub generated_at: String,
    pub subject: GdprSubject,
    pub attributes: Map<String, Value>,
    pub credentials: GdprCredentials,
    pub sessions: Vec<GdprSession>,
    pub consents: Vec<GdprConsent>,
    pub token_families: Vec<GdprTokenFamily>,
    pub identity_links: Vec<GdprIdentityLink>,
    pub roles: Vec<RoleRef>,
    pub organizations: Vec<OrgMembershipExport>,
    pub audit_events: Vec<GdprAuditEvent>,
    pub pending_self_service_tokens: Vec<GdprPendingToken>,
    /// Always `null` from the software; see [`OperatorStatement`].
    pub operator_statement: Option<OperatorStatement>,
}

// ---------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------

/// User export (module docs). Built by the admin API and the CLI with the same fields; there is
/// no options parameter on construction.
#[derive(Clone)]
pub struct UserExportService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl UserExportService {
    /// Exports one user (no password hash) and audits `user_exported` (mode `single`).
    /// `NotFound` if the user does not exist in `tenant`.
    pub async fn export_user(
        &self,
        tenant: TenantId,
        user: UserId,
        actor: &AuditActor,
        ctx: &RequestContext,
    ) -> Result<UserExportRecord, CoreError> {
        let u = self
            .storage
            .users()
            .get(tenant, user)
            .await?
            .ok_or(CoreError::NotFound)?;
        let record = self.record(tenant, &u, false).await?;
        self.audit(
            tenant,
            actor,
            ctx,
            Some(user),
            "single",
            1,
            false,
            AuditOutcome::Success,
        )
        .await?;
        Ok(record)
    }

    /// The bulk export for the admin API: never includes password hashes.
    pub fn bulk_without_hashes(&self, tenant: TenantId) -> BulkExport {
        self.bulk(tenant, ExportOptions::default())
    }

    /// The bulk export with options (the CLI). Call [`BulkExport::finish`] at the end to audit.
    pub fn bulk(&self, tenant: TenantId, options: ExportOptions) -> BulkExport {
        BulkExport {
            service: self.clone(),
            tenant,
            options,
            page_size: BULK_PAGE_SIZE,
            after: None,
            done: false,
            failed: false,
            count: 0,
        }
    }

    /// The GDPR data-subject bundle of `user`; audits `user_exported` (mode `gdpr`). `NotFound`
    /// if the user does not exist in `tenant`.
    pub async fn gdpr_bundle(
        &self,
        tenant: TenantId,
        user: UserId,
        actor: &AuditActor,
        ctx: &RequestContext,
    ) -> Result<GdprBundle, CoreError> {
        let storage = &self.storage;
        let now = self.clock.now();
        let u = storage
            .users()
            .get(tenant, user)
            .await?
            .ok_or(CoreError::NotFound)?;
        let attributes = storage
            .attributes()
            .user_values(tenant, user)
            .await?
            .unwrap_or_default();

        let creds = storage.users().list_credentials(tenant, user).await?;
        let credentials = GdprCredentials {
            items: creds.iter().map(CredentialMetadata::from).collect(),
            password_set: creds.iter().any(|c| c.kind == CredentialKind::Password),
            totp_enrolled: creds.iter().any(|c| c.kind == CredentialKind::Totp),
            recovery_codes_remaining: storage
                .users()
                .recovery_codes_remaining(tenant, user)
                .await?,
        };

        let sessions = storage
            .sessions()
            .list_for_user(tenant, user, now)
            .await?
            .into_iter()
            .map(|s| GdprSession {
                id: s.id.to_string(),
                created_at: rfc3339(s.created_at),
                last_seen_at: rfc3339(s.last_seen_at),
                auth_time: rfc3339(s.auth_time),
                expires_at: rfc3339(s.expires_at),
                authentication_methods: s.amr,
                ip: s.ip,
                user_agent: s.user_agent,
            })
            .collect();

        let consents = storage
            .grants()
            .list_consents(tenant, user)
            .await?
            .into_iter()
            .map(|c| GdprConsent {
                client_id: c.client_id,
                scopes: c.scopes,
                resources: c.resources,
                created_at: rfc3339(c.created_at),
                updated_at: rfc3339(c.updated_at),
                revoked_at: c.revoked_at.map(rfc3339),
            })
            .collect();

        let token_families = storage
            .grants()
            .families_for_user(tenant, user)
            .await?
            .into_iter()
            .map(|f| GdprTokenFamily {
                id: f.id.to_string(),
                client_id: f.client_id,
                scope: f.scope,
                resources: f.resource,
                created_at: rfc3339(f.created_at),
                expires_at: rfc3339(f.absolute_expires_at),
                revoked_at: f.revoked_at.map(rfc3339),
                revoked_reason: f.revoked_reason.map(|r| r.as_str()),
            })
            .collect();

        let links = storage.connections().links_for_user(tenant, user).await?;
        let slugs = self.connection_slugs(tenant, &links).await?;
        let identity_links = links
            .into_iter()
            .map(|l| GdprIdentityLink {
                connection: slugs.get(&l.connection_id).cloned().flatten(),
                connection_id: l.connection_id.to_string(),
                subject: l.subject,
                email_at_link: l.email_at_link,
                metadata: l.metadata,
                created_at: rfc3339(l.created_at),
                last_used_at: l.last_used_at.map(rfc3339),
            })
            .collect();

        let roles = self.tenant_roles(tenant, user).await?;
        let organizations = self.organizations(tenant, user).await?;
        let audit_events = self.audit_events(tenant, user).await?;

        let pending_self_service_tokens = storage
            .users()
            .pending_self_service_tokens(tenant, user, now)
            .await?
            .into_iter()
            .map(|(kind, expires_at)| GdprPendingToken {
                kind: kind.as_str(),
                expires_at: rfc3339(expires_at),
            })
            .collect();

        let bundle = GdprBundle {
            export_format_version: GDPR_FORMAT_VERSION,
            generated_at: rfc3339(now),
            subject: GdprSubject {
                id: u.id.to_string(),
                email: u.email,
                email_verified: u.email_verified,
                username: u.username,
                status: u.status.as_str(),
                claims: ClaimsExport::from(&u.claims),
                created_at: rfc3339(u.created_at),
                updated_at: rfc3339(u.updated_at),
                last_login_at: u.last_login_at.map(rfc3339),
            },
            attributes,
            credentials,
            sessions,
            consents,
            token_families,
            identity_links,
            roles,
            organizations,
            audit_events,
            pending_self_service_tokens,
            operator_statement: None,
        };
        self.audit(
            tenant,
            actor,
            ctx,
            Some(user),
            "gdpr",
            1,
            false,
            AuditOutcome::Success,
        )
        .await?;
        Ok(bundle)
    }

    /// Builds the record of one user.
    async fn record(
        &self,
        tenant: TenantId,
        u: &User,
        include_password_hash: bool,
    ) -> Result<UserExportRecord, CoreError> {
        let storage = &self.storage;
        let attributes = storage
            .attributes()
            .user_values(tenant, u.id)
            .await?
            .unwrap_or_default();
        let links = storage.connections().links_for_user(tenant, u.id).await?;
        let slugs = self.connection_slugs(tenant, &links).await?;
        let identity_links = links
            .into_iter()
            .map(|l| IdentityLinkExport {
                connection: slugs.get(&l.connection_id).cloned().flatten(),
                connection_id: l.connection_id.to_string(),
                subject: l.subject,
            })
            .collect();
        let credentials = storage
            .users()
            .list_credentials(tenant, u.id)
            .await?
            .iter()
            .map(CredentialMetadata::from)
            .collect();
        let password_hash = if include_password_hash {
            storage.users().password(tenant, u.id).await?.map(|p| p.phc)
        } else {
            None
        };
        Ok(UserExportRecord {
            id: u.id.to_string(),
            email: u.email.clone(),
            email_verified: u.email_verified,
            username: u.username.clone(),
            status: u.status.as_str(),
            claims: ClaimsExport::from(&u.claims),
            attributes,
            created_at: rfc3339(u.created_at),
            updated_at: rfc3339(u.updated_at),
            last_login_at: u.last_login_at.map(rfc3339),
            roles: self.tenant_roles(tenant, u.id).await?,
            organizations: self.organizations(tenant, u.id).await?,
            identity_links,
            credentials,
            password_hash,
        })
    }

    async fn tenant_roles(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<RoleRef>, CoreError> {
        Ok(self
            .storage
            .roles()
            .roles_for_user(tenant, user)
            .await?
            .iter()
            .map(RoleRef::from)
            .collect())
    }

    async fn organizations(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<OrgMembershipExport>, CoreError> {
        let orgs = self
            .storage
            .organizations()
            .memberships_of_user(tenant, user)
            .await?;
        let mut out = Vec::with_capacity(orgs.len());
        for org in orgs {
            let roles = self
                .storage
                .roles()
                .roles_for_user_in_org(tenant, user, org.id)
                .await?;
            out.push(OrgMembershipExport {
                org_id: org.id.to_string(),
                slug: org.slug,
                display_name: org.display_name,
                roles: roles.iter().map(RoleRef::from).collect(),
            });
        }
        Ok(out)
    }

    /// Connection slugs of the links (`None` for a connection that no longer exists).
    async fn connection_slugs(
        &self,
        tenant: TenantId,
        links: &[IdentityLink],
    ) -> Result<HashMap<ConnectionId, Option<String>>, CoreError> {
        let mut slugs = HashMap::new();
        for link in links {
            if slugs.contains_key(&link.connection_id) {
                continue;
            }
            let slug = self
                .storage
                .connections()
                .get(tenant, link.connection_id)
                .await?
                .map(|c| c.slug);
            slugs.insert(link.connection_id, slug);
        }
        Ok(slugs)
    }

    /// Every audit event with `target = user` or `actor_id = user`, newest first, redacted.
    async fn audit_events(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<GdprAuditEvent>, CoreError> {
        let id = user.to_string();
        let mut events: BTreeMap<Uuid, AuditEvent> = BTreeMap::new();
        for by_actor in [false, true] {
            let mut before = None;
            loop {
                let query = AuditQuery {
                    from: None,
                    to: None,
                    actor_id: by_actor.then(|| id.clone()),
                    action: None,
                    outcome: None,
                    target: (!by_actor).then(|| id.clone()),
                    before,
                    limit: AUDIT_PAGE,
                };
                let page = self.storage.audit().query(tenant, &query).await?;
                for e in page.items {
                    events.insert(e.id.0, e);
                }
                match page.next_cursor {
                    Some(c) => before = Some(crate::model::AuditEventId(c)),
                    None => break,
                }
            }
        }
        let mut other_users: HashMap<String, bool> = HashMap::new();
        let mut out = Vec::with_capacity(events.len());
        // Newest first (ids are UUIDv7, time-ordered).
        for e in events.into_values().rev() {
            let by_subject = e.actor.id.as_deref() == Some(id.as_str())
                && matches!(e.actor.kind, ActorKind::User | ActorKind::Admin);
            let (actor, actor_client_id) = actor_label(&e.actor, by_subject);
            let target = match e.target {
                None => None,
                Some(t) if t == id => Some("subject".to_owned()),
                Some(t) => {
                    if self.is_other_user(tenant, &t, &mut other_users).await? {
                        Some("another_user".to_owned())
                    } else {
                        Some(t)
                    }
                }
            };
            let (ip, user_agent) = if by_subject {
                (e.ctx.ip.map(|ip| ip.to_string()), e.ctx.user_agent)
            } else {
                (None, None)
            };
            out.push(GdprAuditEvent {
                id: e.id.0.to_string(),
                at: rfc3339(e.at),
                action: e.action.as_str(),
                outcome: e.outcome.as_str(),
                actor,
                actor_client_id,
                target,
                ip,
                user_agent,
                details: redact_details(e.details.as_map(), &id),
            });
        }
        Ok(out)
    }

    /// Whether `target` is the id of a user of the tenant (other than the subject; callers have
    /// matched the subject already). Cached per bundle.
    async fn is_other_user(
        &self,
        tenant: TenantId,
        target: &str,
        cache: &mut HashMap<String, bool>,
    ) -> Result<bool, CoreError> {
        if let Some(known) = cache.get(target) {
            return Ok(*known);
        }
        let known = match Uuid::parse_str(target) {
            Ok(uuid) => self
                .storage
                .users()
                .get(tenant, UserId(uuid))
                .await?
                .is_some(),
            Err(_) => false,
        };
        cache.insert(target.to_owned(), known);
        Ok(known)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one audited export; every argument is a typed part of the event"
    )]
    async fn audit(
        &self,
        tenant: TenantId,
        actor: &AuditActor,
        ctx: &RequestContext,
        user: Option<UserId>,
        mode: &'static str,
        count: u64,
        include_password_hashes: bool,
        outcome: AuditOutcome,
    ) -> Result<(), CoreError> {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
        .record(
            tenant,
            actor.clone(),
            AuditAction::UserExported,
            user.map(|u| u.to_string()),
            outcome,
            ctx,
            AuditDetails::user_export(mode, count, include_password_hashes),
        )
        .await
    }
}

/// The role label of an audit actor in the GDPR bundle, plus the client id for client actors.
fn actor_label(actor: &AuditActor, by_subject: bool) -> (&'static str, Option<String>) {
    if by_subject {
        return ("subject", None);
    }
    match actor.kind {
        ActorKind::Admin => ("administrator", None),
        ActorKind::User => ("another_user", None),
        ActorKind::System => ("system", None),
        ActorKind::Client => ("client", actor.id.clone()),
    }
}

/// Audit details keep identifiers, names and counts. A string under a key that may name a person
/// (`*user*`, `*email*`, `*actor*`) is replaced by `redacted` unless it is the subject's own id.
/// The typed detail constructors never store a person's identity today; this is defence in depth.
fn redact_details(details: &Map<String, Value>, subject: &str) -> Map<String, Value> {
    details
        .iter()
        .map(|(k, v)| {
            let v = match v {
                Value::String(s) if s != subject && looks_like_user_ref(k) => {
                    Value::from("redacted")
                }
                other => other.clone(),
            };
            (k.clone(), v)
        })
        .collect()
}

/// Detail keys that may carry a person's identifier.
fn looks_like_user_ref(key: &str) -> bool {
    key.contains("user") || key.contains("email") || key.contains("actor")
}

/// RFC 3339 in UTC with milliseconds (the storage precision), e.g. `2026-11-26T17:46:57.123Z`.
pub fn rfc3339(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

/// A bulk export in progress: a page iterator over the tenant's users (module docs).
pub struct BulkExport {
    service: UserExportService,
    tenant: TenantId,
    options: ExportOptions,
    page_size: u32,
    after: Option<Uuid>,
    done: bool,
    failed: bool,
    count: u64,
}

impl BulkExport {
    /// Reads `page_size` users per page instead of [`BULK_PAGE_SIZE`] (clamped to 1..=200).
    pub fn with_page_size(mut self, page_size: u32) -> Self {
        self.page_size = page_size.clamp(1, PageRequest::MAX_LIMIT);
        self
    }

    /// The next page of records; `None` once every user was returned. An error ends the export
    /// (later calls return `None`) and makes [`BulkExport::finish`] record a failure.
    pub async fn next_page(&mut self) -> Result<Option<Vec<UserExportRecord>>, CoreError> {
        if self.done {
            return Ok(None);
        }
        match self.read_page().await {
            Ok(records) => Ok(records),
            Err(e) => {
                self.done = true;
                self.failed = true;
                Err(e)
            }
        }
    }

    async fn read_page(&mut self) -> Result<Option<Vec<UserExportRecord>>, CoreError> {
        let page = self
            .service
            .storage
            .users()
            .list(
                self.tenant,
                PageRequest {
                    after: self.after,
                    limit: self.page_size,
                },
            )
            .await?;
        let mut records = Vec::with_capacity(page.items.len());
        for u in &page.items {
            records.push(
                self.service
                    .record(self.tenant, u, self.options.include_password_hashes)
                    .await?,
            );
        }
        self.count += records.len() as u64;
        match page.next_cursor {
            Some(c) => self.after = Some(c),
            None => self.done = true,
        }
        if records.is_empty() && self.done {
            return Ok(None);
        }
        Ok(Some(records))
    }

    /// Marks the export as failed after a caller-side error (e.g. writing the output), so
    /// [`BulkExport::finish`] records a failure even when every page was read.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        self.done = true;
    }

    /// Users returned so far.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Whether the records carry password hashes.
    pub fn includes_password_hashes(&self) -> bool {
        self.options.include_password_hashes
    }

    /// Audits the export as `user_exported` (mode `bulk`, the count, the hash flag): success when
    /// every page was read, failure when it ended early or with an error.
    pub async fn finish(self, actor: &AuditActor, ctx: &RequestContext) -> Result<u64, CoreError> {
        let outcome = if self.done && !self.failed {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure
        };
        self.service
            .audit(
                self.tenant,
                actor,
                ctx,
                None,
                "bulk",
                self.count,
                self.options.include_password_hashes,
                outcome,
            )
            .await?;
        Ok(self.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ActorKind, AuditActor};
    use time::macros::datetime;

    #[test]
    fn rfc3339_is_utc_with_millis() {
        let t = datetime!(2026-11-26 18:46:57.123 +01:00);
        assert_eq!(rfc3339(t), "2026-11-26T17:46:57.123Z");
    }

    #[test]
    fn actor_labels_never_name_other_people() {
        let admin = AuditActor::admin("admin@example.test");
        assert_eq!(actor_label(&admin, false), ("administrator", None));
        let other = AuditActor::user("0190a000-0000-7000-8000-000000000001");
        assert_eq!(actor_label(&other, false), ("another_user", None));
        assert_eq!(actor_label(&AuditActor::system(), false), ("system", None));
        let client = AuditActor::client("app");
        assert_eq!(
            actor_label(&client, false),
            ("client", Some("app".to_owned()))
        );
        assert_eq!(actor_label(&other, true), ("subject", None));
        assert!(matches!(admin.kind, ActorKind::Admin));
    }

    #[test]
    fn details_drop_other_user_refs() {
        let mut m = Map::new();
        m.insert("invited_email".into(), Value::from("other@example.test"));
        m.insert("user_id".into(), Value::from("subject-id"));
        m.insert("role".into(), Value::from("editor"));
        let out = redact_details(&m, "subject-id");
        assert_eq!(out["invited_email"], "redacted");
        assert_eq!(out["user_id"], "subject-id");
        assert_eq!(out["role"], "editor");
    }

    #[test]
    fn export_options_default_has_no_hashes() {
        assert!(!ExportOptions::default().include_password_hashes);
    }
}
