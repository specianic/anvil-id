//! Local administrator access recovery for the CLI (ADM-07, `anvilid admin recover`).
//!
//! Recovery needs a shell on the host (the database configuration and, for SQLite, the data
//! directory). There is deliberately no HTTP route that reaches this service: a network endpoint
//! would be a backdoor around authentication.
//!
//! - [`AdminRecoveryService::issue`] (`--email`): for an existing, active system-tenant user it
//!   ensures the `administrator` role, optionally removes the user's TOTP and passkeys
//!   (`--reset-mfa`), and issues a one-time password-reset link (a `Recovery` self-service token,
//!   1 h) to the system tenant's existing reset page. Nothing is emailed: the operator hands the
//!   link over. Completing it sets a new password and revokes the user's sessions.
//! - [`AdminRecoveryService::issue_fresh_admin`] (no `--email`): only when no active system user
//!   holds `admin:write` (lockout), it issues a setup URL (the same setup token as
//!   `anvilid admin setup-url`); completing setup creates a new user holding `administrator`.
//!   When an `admin:write` holder exists it refuses, so it cannot be used to add administrators
//!   silently.
//!
//! Both are audited as `admin_recovery_issued` with the system actor.

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::admin_scope::ADMIN_WRITE;
use super::audit::AuditService;
use super::bootstrap::{build_setup_token, setup_url};
use super::flow::RECOVERY_TOKEN_TTL;
use super::logout::canonical_issuer;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, CredentialKind, NewSelfServiceToken,
    PublicUrl, RequestContext, SYSTEM_ADMIN_ROLE, SYSTEM_TENANT_SLUG, SecretHash, SelfServiceKind,
    Tenant, User, UserStatus, normalize_email,
};
use crate::ports::{Clock, Storage};

/// What [`AdminRecoveryService::issue`] did. The URL is shown to the operator once.
#[derive(Debug)]
pub struct RecoveryIssued {
    /// `{system issuer}/ui/recovery?token=...`, valid for one use within one hour.
    pub url: SecretString,
    pub user: User,
    pub expires_at: OffsetDateTime,
    /// The user did not hold `administrator` and was assigned it.
    pub role_assigned: bool,
    /// TOTP and passkey credentials removed (`--reset-mfa`).
    pub mfa_removed: u32,
}

/// A `Recovery` token record for `user` (1 h, same TTL as the self-service flow) and its
/// plaintext.
pub fn build_recovery_token(
    user: &User,
    now: OffsetDateTime,
) -> (NewSelfServiceToken, SecretString) {
    let token = random_token();
    let record = NewSelfServiceToken {
        token_hash: SecretHash(secret_hash(&token)),
        kind: SelfServiceKind::Recovery,
        user_id: user.id,
        email: user.email.clone(),
        created_at: now,
        expires_at: now + RECOVERY_TOKEN_TTL,
    };
    (record, SecretString::from(token))
}

/// The reset page link of `tenant` for `token`: the same page the emailed recovery link opens.
pub fn recovery_url(public_url: &PublicUrl, tenant: &Tenant, token: &SecretString) -> SecretString {
    use secrecy::ExposeSecret as _;
    SecretString::from(format!(
        "{}/ui/recovery?token={}",
        canonical_issuer(public_url, tenant),
        token.expose_secret()
    ))
}

/// Local administrator access recovery (module docs).
pub struct AdminRecoveryService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub public_url: PublicUrl,
}

impl AdminRecoveryService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    async fn system_tenant(&self) -> Result<Tenant, CoreError> {
        self.storage
            .tenants()
            .get_by_slug(SYSTEM_TENANT_SLUG)
            .await?
            .ok_or_else(|| {
                CoreError::Conflict("not installed yet; start the server once to install".into())
            })
    }

    /// Recovers the system-tenant account `email` (module docs). `NotFound` if no system-tenant
    /// user has that address (users of other tenants are never found); `Conflict` if the user is
    /// not active or the `administrator` role is missing. Nothing is changed on an error.
    pub async fn issue(&self, email: &str, reset_mfa: bool) -> Result<RecoveryIssued, CoreError> {
        let email = normalize_email(email)?;
        let system = self.system_tenant().await?;
        let user = self
            .storage
            .users()
            .get_by_email(system.id, &email)
            .await?
            .ok_or(CoreError::NotFound)?;
        if user.status != UserStatus::Active {
            return Err(CoreError::Conflict(format!(
                "the account is {}; if no other administrator can sign in, run `anvilid admin \
                 recover` without --email to create a new administrator",
                user.status.as_str()
            )));
        }
        let roles = self.storage.roles();
        let admin_role = roles
            .get_by_name(system.id, SYSTEM_ADMIN_ROLE)
            .await?
            .ok_or_else(|| {
                CoreError::Conflict("the system tenant has no administrator role".into())
            })?;
        if !admin_role.permissions.iter().any(|p| p == ADMIN_WRITE) {
            return Err(CoreError::Conflict(format!(
                "the administrator role does not grant {ADMIN_WRITE}"
            )));
        }

        let now = self.clock.now();
        let held = roles
            .roles_for_user(system.id, user.id)
            .await?
            .iter()
            .any(|r| r.id == admin_role.id);
        let role_assigned = if held {
            false
        } else {
            if !roles.assign(system.id, admin_role.id, user.id, now).await? {
                return Err(CoreError::Conflict(
                    "the administrator role could not be assigned".into(),
                ));
            }
            true
        };

        let mut mfa_removed = 0;
        if reset_mfa {
            let users = self.storage.users();
            for cred in users.list_credentials(system.id, user.id).await? {
                if matches!(cred.kind, CredentialKind::Totp | CredentialKind::Webauthn)
                    && users.delete_credential(system.id, user.id, cred.id).await?
                {
                    mfa_removed += 1;
                }
            }
        }

        let (record, token) = build_recovery_token(&user, now);
        self.storage
            .users()
            .issue_self_service_token(system.id, &record, None)
            .await?;

        let mut fields = vec!["password_reset_link"];
        if role_assigned {
            fields.push("administrator_role");
        }
        if reset_mfa {
            fields.push("mfa");
        }
        self.audit()
            .record(
                system.id,
                AuditActor::system(),
                AuditAction::AdminRecoveryIssued,
                Some(user.id.to_string()),
                AuditOutcome::Success,
                &RequestContext::system(),
                AuditDetails::fields(&fields),
            )
            .await?;

        Ok(RecoveryIssued {
            url: recovery_url(&self.public_url, &system, &token),
            expires_at: record.expires_at,
            user,
            role_assigned,
            mfa_removed,
        })
    }

    /// Lockout recovery (module docs): a setup URL (1 h, one use) that creates a new system
    /// administrator, issued only when no active system-tenant user holds `admin:write`.
    /// `Conflict` (nothing issued) when a holder exists.
    pub async fn issue_fresh_admin(&self) -> Result<SecretString, CoreError> {
        if !self.storage.setup().is_installed().await? {
            return Err(CoreError::Conflict(
                "not installed yet; start the server once to install".to_owned(),
            ));
        }
        let system = self.system_tenant().await?;
        let holders = self
            .storage
            .roles()
            .holders_of_permission(system.id, ADMIN_WRITE)
            .await?;
        if holders > 0 {
            return Err(CoreError::Conflict(format!(
                "{holders} active administrator(s) hold {ADMIN_WRITE}; pass --email to recover \
                 one of those accounts"
            )));
        }
        let (token, plaintext) = build_setup_token(self.clock.now());
        self.storage.setup().create_setup_token(&token).await?;
        self.audit()
            .record(
                system.id,
                AuditActor::system(),
                AuditAction::AdminRecoveryIssued,
                None,
                AuditOutcome::Success,
                &RequestContext::system(),
                AuditDetails::reason("new_administrator_setup"),
            )
            .await?;
        Ok(setup_url(&self.public_url, &plaintext))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;
    use time::Duration;
    use time::macros::datetime;

    use super::*;
    use crate::model::{TenantId, TenantSettings, UserId};

    const NOW: OffsetDateTime = datetime!(2026-11-26 12:00 UTC);

    fn user() -> User {
        User {
            id: UserId::new_v7(),
            tenant_id: TenantId::new_v7(),
            email: "admin@example.test".to_owned(),
            email_verified: true,
            username: None,
            claims: Default::default(),
            status: UserStatus::Active,
            created_at: NOW,
            updated_at: NOW,
            last_login_at: None,
        }
    }

    #[test]
    fn recovery_token_is_a_one_hour_recovery_token_bound_to_the_user() {
        let u = user();
        let (record, token) = build_recovery_token(&u, NOW);
        assert_eq!(record.kind, SelfServiceKind::Recovery);
        assert_eq!(record.user_id, u.id);
        assert_eq!(record.email, u.email);
        assert_eq!(record.created_at, NOW);
        assert_eq!(record.expires_at, NOW + Duration::hours(1));
        assert_eq!(record.expires_at - record.created_at, RECOVERY_TOKEN_TTL);
        assert_eq!(
            record.token_hash,
            SecretHash(secret_hash(token.expose_secret()))
        );
        let (other, _) = build_recovery_token(&u, NOW);
        assert_ne!(other.token_hash, record.token_hash, "tokens are random");
    }

    #[test]
    fn recovery_url_targets_the_system_reset_page() {
        let public = PublicUrl::parse("https://id.example.test").expect("url");
        let mut tenant = Tenant {
            id: TenantId::new_v7(),
            slug: SYSTEM_TENANT_SLUG.to_owned(),
            display_name: "System".to_owned(),
            host: None,
            settings: TenantSettings::default(),
            created_at: NOW,
        };
        let token = SecretString::from("tok");
        assert_eq!(
            recovery_url(&public, &tenant, &token).expose_secret(),
            "https://id.example.test/t/system/ui/recovery?token=tok"
        );
        tenant.host = Some("admin.example.test".to_owned());
        assert_eq!(
            recovery_url(&public, &tenant, &token).expose_secret(),
            "https://admin.example.test/ui/recovery?token=tok"
        );
    }
}
