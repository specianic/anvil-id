//! User management for the admin API.
//!
//! An admin creates a user either with a password (the password policy applies; hashing goes
//! through the [`PasswordHasher`] port) or with `invite: true`, which issues an `Invitation`
//! self-service token and enqueues the `invitation` email in the same transaction as the user.
//!
//! [`UserService::send_recovery`] sends an existing user the self-service password-reset email
//! through the one recovery email path ([`crate::service::flow::self_service_email`]: `Recovery`
//! token, one hour, the user's current address), audited as `user_recovery_sent`.
//!
//! Every mutating [`UserService`] method takes the acting administrator and the request context
//! and records exactly one audit event in the user's tenant (`user_created`, `user_updated`,
//! `user_deleted`, `user_recovery_sent`, target = user id) after the change commits. Failed calls record nothing;
//! details hold changed field names only (never the email, password or claims).

use std::collections::BTreeMap;
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::{ExposeSecret as _, SecretString};
use time::{Duration, OffsetDateTime};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, NewEmail, NewPasswordCredential,
    NewSelfServiceToken, NewUser, OutboxId, Page, PageRequest, RequestContext, SecretHash,
    SelfServiceKind, StandardClaims, Tenant, TenantId, User, UserId, UserStatus, UserUpdate,
    normalize_email, seal_payload,
};
use crate::policy::{PasswordPolicy, check_password};
use crate::ports::{PasswordHasher, RelyingParty, Storage, StorageError};
use crate::service::audit::AuditService;
use crate::service::flow::{FlowContext, self_service_email};
use crate::service::role::guard_user_removal;
use crate::service::tenant::admin_page;

/// Lifetime of an invitation link.
pub const INVITATION_TTL: Duration = Duration::days(7);
/// Human-readable form of [`INVITATION_TTL`] for the email.
pub const INVITATION_TTL_TEXT: &str = "7 days";
/// Email template for invitations.
pub const INVITATION_TEMPLATE: &str = "invitation";
/// Maximum username length in characters.
pub const MAX_USERNAME_LEN: usize = 64;

/// Input for [`UserService::create`]. Exactly one of `password` and `invite` must be given.
#[derive(Debug)]
pub struct UserInput {
    pub email: String,
    pub password: Option<SecretString>,
    pub invite: bool,
    pub email_verified: bool,
    pub username: Option<String>,
    pub claims: StandardClaims,
}

/// Partial user update. `username: Some(None)` clears the username. Setting `status` to
/// `Blocked` blocks the user (login and token issuance check the status).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserPatch {
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<Option<String>>,
    pub claims: Option<StandardClaims>,
    pub status: Option<UserStatus>,
}

/// An invitation: the stored token, its email, and the plaintext link (only inside the email).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub token: NewSelfServiceToken,
    pub email: NewEmail,
}

/// The validated, storage-ready form of a [`UserInput`] (before password hashing).
#[derive(Debug)]
pub struct UserPlan {
    pub user: NewUser,
    /// Plaintext password to hash, when the admin set one.
    pub password: Option<SecretString>,
    pub invitation: Option<Invitation>,
}

fn invalid(field: &'static str, message: &str) -> CoreError {
    CoreError::Validation {
        field,
        message: message.to_owned(),
    }
}

fn validate_username(raw: &str) -> Result<String, CoreError> {
    let u = raw.trim();
    if u.is_empty()
        || u.chars().count() > MAX_USERNAME_LEN
        || u.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid(
            "username",
            "must be 1-64 characters without whitespace",
        ));
    }
    Ok(u.to_owned())
}

/// Builds an `Invitation` token and its email. The link is `{issuer}/ui/recovery?token=…`; the
/// email payload is sealed with the KEK ([`seal_payload`]) because the link carries the token.
pub fn build_invitation(
    kek: &Kek,
    now: OffsetDateTime,
    tenant: &Tenant,
    issuer: &str,
    user_id: UserId,
    email: &str,
) -> Result<Invitation, CoreError> {
    let plaintext = random_token();
    let expires_at = now + INVITATION_TTL;
    let token = NewSelfServiceToken {
        token_hash: SecretHash(secret_hash(&plaintext)),
        kind: SelfServiceKind::Invitation,
        user_id,
        email: email.to_owned(),
        created_at: now,
        expires_at,
    };
    let payload = BTreeMap::from([
        ("tenant_name".to_owned(), tenant.display_name.clone()),
        ("email".to_owned(), email.to_owned()),
        (
            "link".to_owned(),
            format!(
                "{}/ui/recovery?token={plaintext}",
                issuer.trim_end_matches('/')
            ),
        ),
        ("expires_in".to_owned(), INVITATION_TTL_TEXT.to_owned()),
    ]);
    Ok(Invitation {
        token,
        email: NewEmail {
            id: OutboxId::new_v7(),
            to: email.to_owned(),
            template: INVITATION_TEMPLATE.to_owned(),
            payload: seal_payload(kek, tenant.id, &payload)?,
            created_at: now,
            expires_at,
        },
    })
}

/// Validates a [`UserInput`] and builds the records to store. Pure apart from randomness.
pub fn build_user_plan(
    kek: &Kek,
    now: OffsetDateTime,
    tenant: &Tenant,
    issuer: &str,
    policy: &PasswordPolicy,
    input: UserInput,
) -> Result<UserPlan, CoreError> {
    let email = normalize_email(&input.email)?;
    match (&input.password, input.invite) {
        (Some(_), true) => {
            return Err(invalid(
                "password",
                "set either a password or invite, not both",
            ));
        }
        (None, false) => {
            return Err(invalid("password", "a password or invite is required"));
        }
        (Some(p), false) => check_password(policy, p.expose_secret())?,
        (None, true) => {}
    }
    let username = input
        .username
        .as_deref()
        .map(validate_username)
        .transpose()?;
    let user = NewUser {
        id: UserId::new_v7(),
        email,
        email_verified: input.email_verified,
        username,
        claims: input.claims,
        status: UserStatus::Active,
        created_at: now,
    };
    let invitation = if input.invite {
        Some(build_invitation(
            kek,
            now,
            tenant,
            issuer,
            user.id,
            &user.email,
        )?)
    } else {
        None
    };
    Ok(UserPlan {
        user,
        password: input.password,
        invitation,
    })
}

/// Names of the fields a user update changes (for the audit event; never values).
fn changed_fields(patch: &UserPatch) -> Vec<&'static str> {
    [
        (patch.email.is_some(), "email"),
        (patch.email_verified.is_some(), "email_verified"),
        (patch.username.is_some(), "username"),
        (patch.claims.is_some(), "claims"),
        (patch.status.is_some(), "status"),
    ]
    .into_iter()
    .filter_map(|(set, name)| set.then_some(name))
    .collect()
}

fn map_conflict(e: StorageError) -> CoreError {
    match e {
        StorageError::Conflict(_) => {
            CoreError::Conflict("email or username already in use".to_owned())
        }
        other => other.into(),
    }
}

/// User management.
pub struct UserService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub policy: PasswordPolicy,
    /// Seals invitation email payloads (they carry the invitation token).
    pub kek: Arc<Kek>,
}

impl UserService {
    async fn record(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        action: AuditAction,
        user: UserId,
        ctx: &RequestContext,
        details: AuditDetails,
    ) -> Result<(), CoreError> {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            tenant,
            actor,
            action,
            Some(user.to_string()),
            AuditOutcome::Success,
            ctx,
            details,
        )
        .await
    }

    /// Creates a user with a password or an invitation. `issuer` is the tenant's issuer (the
    /// invitation link base). Audited as `user_created` (details: `reason` = `invitation` or
    /// `password_set`).
    pub async fn create(
        &self,
        tenant: &Tenant,
        issuer: &str,
        input: UserInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<User, CoreError> {
        let now = self.clock.now();
        let plan = build_user_plan(&self.kek, now, tenant, issuer, &self.policy, input)?;
        let credential = match &plan.password {
            Some(p) => Some(NewPasswordCredential {
                phc: self.hasher.hash(p.expose_secret()).await?,
                created_at: now,
            }),
            None => None,
        };
        let (token, email) = match &plan.invitation {
            Some(inv) => (Some(&inv.token), Some(&inv.email)),
            None => (None, None),
        };
        let user = self
            .storage
            .users()
            .create(tenant.id, &plan.user, credential.as_ref(), token, email)
            .await
            .map_err(map_conflict)?;
        let how = if plan.invitation.is_some() {
            "invitation"
        } else {
            "password_set"
        };
        self.record(
            tenant.id,
            actor,
            AuditAction::UserCreated,
            user.id,
            ctx,
            AuditDetails::reason(how),
        )
        .await?;
        Ok(user)
    }

    pub async fn get(&self, tenant: TenantId, id: UserId) -> Result<User, CoreError> {
        self.storage
            .users()
            .get(tenant, id)
            .await?
            .ok_or(CoreError::NotFound)
    }

    pub async fn list(&self, tenant: TenantId, page: PageRequest) -> Result<Page<User>, CoreError> {
        Ok(self.storage.users().list(tenant, admin_page(page)).await?)
    }

    /// The user with this address, compared after normalisation (trimmed, lowercased); a
    /// malformed address is a `Validation` error on `email`.
    pub async fn find_by_email(
        &self,
        tenant: TenantId,
        raw: &str,
    ) -> Result<Option<User>, CoreError> {
        let email = normalize_email(raw)?;
        Ok(self.storage.users().get_by_email(tenant, &email).await?)
    }

    /// Applies a patch (including block/unblock through `status`). Audited as `user_updated`
    /// with the changed field names. Blocking the last active `admin:write` holder of the system
    /// tenant is refused with `LastAdministrator`.
    pub async fn update(
        &self,
        tenant: TenantId,
        id: UserId,
        patch: UserPatch,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<User, CoreError> {
        let fields = changed_fields(&patch);
        if patch.status.is_some_and(|s| s != UserStatus::Active) {
            guard_user_removal(self.storage.as_ref(), tenant, id).await?;
        }
        let update = UserUpdate {
            email: patch.email.as_deref().map(normalize_email).transpose()?,
            email_verified: patch.email_verified,
            username: match patch.username {
                None => None,
                Some(None) => Some(None),
                Some(Some(u)) => Some(Some(validate_username(&u)?)),
            },
            claims: patch.claims,
            status: patch.status,
        };
        let user = self
            .storage
            .users()
            .update(tenant, id, &update, self.clock.now())
            .await
            .map_err(map_conflict)?
            .ok_or(CoreError::NotFound)?;
        self.record(
            tenant,
            actor,
            AuditAction::UserUpdated,
            id,
            ctx,
            AuditDetails::fields(&fields),
        )
        .await?;
        Ok(user)
    }

    /// Sends the user a password-reset email: the same `Recovery` token and `recovery` email as
    /// self-service recovery ([`self_service_email`]: one hour, link
    /// `{issuer}/ui/recovery?token=…`, sealed payload), to the user's current address, token and
    /// email stored in one transaction. `issuer` is the tenant's issuer. The token is never
    /// returned. An unknown user (or one of another tenant) is `NotFound`; a blocked user is
    /// `Conflict` (self-service recovery sends blocked users nothing either). Audited as
    /// `user_recovery_sent`.
    pub async fn send_recovery(
        &self,
        tenant: &Tenant,
        issuer: &str,
        id: UserId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let user = self.get(tenant.id, id).await?;
        if user.status != UserStatus::Active {
            return Err(CoreError::Conflict(
                "blocked users cannot reset their password; unblock the user first".to_owned(),
            ));
        }
        let ui_base = format!("{}/ui", issuer.trim_end_matches('/'));
        // Only passkey effects read the relying party; the recovery email does not.
        let rp: Result<RelyingParty, CoreError> = Err(CoreError::Internal(
            "passkeys are not used by an administrator-sent recovery email".to_owned(),
        ));
        let cx = FlowContext {
            tenant,
            issuer,
            ui_base: &ui_base,
            rp: &rp,
            ctx,
        };
        let (token, mail) = self_service_email(
            &self.kek,
            &cx,
            SelfServiceKind::Recovery,
            user.id,
            &user.email,
            self.clock.now(),
        )?;
        self.storage
            .users()
            .issue_self_service_token(tenant.id, &token, Some(&mail))
            .await?;
        self.record(
            tenant.id,
            actor,
            AuditAction::UserRecoverySent,
            user.id,
            ctx,
            AuditDetails::empty(),
        )
        .await
    }

    /// Deletes the user; the repository removes credentials, sessions and tokens and revokes
    /// token families. Audited as `user_deleted`. Deleting the last active `admin:write` holder
    /// of the system tenant is refused with `LastAdministrator`.
    pub async fn delete(
        &self,
        tenant: TenantId,
        id: UserId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        guard_user_removal(self.storage.as_ref(), tenant, id).await?;
        if !self.storage.users().delete(tenant, id).await? {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant,
            actor,
            AuditAction::UserDeleted,
            id,
            ctx,
            AuditDetails::empty(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SEALED_PAYLOAD_KEY, TenantSettings, open_payload};

    fn tenant() -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn input(password: Option<&str>, invite: bool) -> UserInput {
        UserInput {
            email: " Alice@Example.com ".into(),
            password: password.map(|p| SecretString::from(p.to_owned())),
            invite,
            email_verified: false,
            username: None,
            claims: StandardClaims::default(),
        }
    }

    fn plan(input: UserInput) -> Result<UserPlan, CoreError> {
        plan_for(&Kek::generate(), &tenant(), input)
    }

    fn plan_for(kek: &Kek, tenant: &Tenant, input: UserInput) -> Result<UserPlan, CoreError> {
        build_user_plan(
            kek,
            OffsetDateTime::UNIX_EPOCH,
            tenant,
            "https://id.example/t/acme",
            &PasswordPolicy::default(),
            input,
        )
    }

    fn field_of<T: std::fmt::Debug>(r: Result<T, CoreError>) -> &'static str {
        match r {
            Err(CoreError::Validation { field, .. }) => field,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn password_and_invite_are_mutually_exclusive() {
        assert_eq!(
            field_of(plan(input(Some("long enough pw"), true))),
            "password"
        );
        assert_eq!(field_of(plan(input(None, false))), "password");
    }

    #[test]
    fn password_policy_applies() {
        assert_eq!(field_of(plan(input(Some("short"), false))), "password");
        let p = plan(input(Some("long enough pw"), false)).unwrap();
        assert_eq!(p.user.email, "alice@example.com");
        assert!(p.password.is_some());
        assert!(p.invitation.is_none());
        assert_eq!(p.user.status, UserStatus::Active);
    }

    #[test]
    fn invalid_email_and_username_are_rejected() {
        let mut i = input(None, true);
        i.email = "not-an-email".into();
        assert_eq!(field_of(plan(i)), "email");
        let mut i = input(None, true);
        i.username = Some("has space".into());
        assert_eq!(field_of(plan(i)), "username");
        let mut i = input(None, true);
        i.username = Some("x".repeat(65));
        assert_eq!(field_of(plan(i)), "username");
    }

    #[test]
    fn invite_builds_invitation_token_and_email() {
        let kek = Kek::generate();
        let tenant = tenant();
        let p = plan_for(&kek, &tenant, input(None, true)).unwrap();
        assert!(p.password.is_none());
        let inv = p.invitation.expect("invitation");
        let now = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(inv.token.kind, SelfServiceKind::Invitation);
        assert_eq!(inv.token.user_id, p.user.id);
        assert_eq!(inv.token.email, "alice@example.com");
        assert_eq!(inv.token.expires_at, now + Duration::days(7));
        assert_eq!(inv.email.template, "invitation");
        assert_eq!(inv.email.to, "alice@example.com");
        assert_eq!(inv.email.expires_at, now + Duration::days(7));
        // The stored payload is sealed: one `sealed` entry, no plaintext link.
        assert_eq!(inv.email.payload.len(), 1);
        assert!(inv.email.payload.contains_key(SEALED_PAYLOAD_KEY));
        assert!(!inv.email.payload[SEALED_PAYLOAD_KEY].contains("token="));
        assert!(open_payload(&Kek::generate(), tenant.id, &inv.email.payload).is_err());
        let payload = open_payload(&kek, tenant.id, &inv.email.payload).unwrap();
        let link = &payload["link"];
        let token = link
            .strip_prefix("https://id.example/t/acme/ui/recovery?token=")
            .expect("link format");
        assert_eq!(token.len(), 43);
        // The stored hash belongs to the emailed token; the plaintext is not stored.
        assert_eq!(inv.token.token_hash, SecretHash(secret_hash(token)));
        assert!(!inv.email.payload[SEALED_PAYLOAD_KEY].contains(token));
        assert_eq!(payload["tenant_name"], "Acme");
        assert_eq!(payload["expires_in"], "7 days");
        assert_eq!(payload["email"], "alice@example.com");
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn changed_fields_name_only_what_the_patch_sets() {
        assert!(changed_fields(&UserPatch::default()).is_empty());
        let p = UserPatch {
            email: Some("x@example.com".into()),
            status: Some(UserStatus::Blocked),
            username: Some(None),
            ..UserPatch::default()
        };
        assert_eq!(changed_fields(&p), vec!["email", "username", "status"]);
    }
}
