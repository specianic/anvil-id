//! User management for the admin API.
//!
//! An admin creates a user either with a password (the password policy applies; hashing goes
//! through the [`PasswordHasher`] port) or with `invite: true`, which issues an `Invitation`
//! self-service token and enqueues the `invitation` email in the same transaction as the user.

use std::collections::BTreeMap;
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::{ExposeSecret as _, SecretString};
use time::{Duration, OffsetDateTime};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    NewEmail, NewPasswordCredential, NewSelfServiceToken, NewUser, OutboxId, Page, PageRequest,
    SecretHash, SelfServiceKind, StandardClaims, Tenant, TenantId, User, UserId, UserStatus,
    UserUpdate, normalize_email, seal_payload,
};
use crate::policy::{PasswordPolicy, check_password};
use crate::ports::{PasswordHasher, Storage, StorageError};
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
    /// Creates a user with a password or an invitation. `issuer` is the tenant's issuer (the
    /// invitation link base).
    pub async fn create(
        &self,
        tenant: &Tenant,
        issuer: &str,
        input: UserInput,
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
        self.storage
            .users()
            .create(tenant.id, &plan.user, credential.as_ref(), token, email)
            .await
            .map_err(map_conflict)
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

    /// Applies a patch (including block/unblock through `status`).
    pub async fn update(
        &self,
        tenant: TenantId,
        id: UserId,
        patch: UserPatch,
    ) -> Result<User, CoreError> {
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
        self.storage
            .users()
            .update(tenant, id, &update, self.clock.now())
            .await
            .map_err(map_conflict)?
            .ok_or(CoreError::NotFound)
    }

    /// Deletes the user; the repository removes credentials, sessions and tokens and revokes
    /// token families.
    pub async fn delete(&self, tenant: TenantId, id: UserId) -> Result<(), CoreError> {
        if self.storage.users().delete(tenant, id).await? {
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
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
}
