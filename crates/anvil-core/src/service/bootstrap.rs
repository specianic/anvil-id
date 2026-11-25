//! First start and first-admin setup (ADM-03).
//!
//! On an empty database [`BootstrapService::ensure_installed`] writes, in one
//! `SetupRepo::install` transaction, the `system` and `default` tenants, one active RS256 key
//! per tenant and a one-time setup token valid for one hour. No user or credential exists until
//! [`BootstrapService::complete_setup`] consumes that token and atomically creates the first
//! administrator and the management API client, whose secret is returned exactly once.
//!
//! The setup token and URL are never logged here; the binary prints the URL once.

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::{ExposeSecret as _, SecretString};
use time::{Duration, OffsetDateTime};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    ApplicationType, ClientAuthMethod, ClientId, ClientType, DEFAULT_TENANT_SLUG, GrantType,
    InstallPlan, KeyState, NewClient, NewPasswordCredential, NewSetupToken, NewTenant, NewUser,
    PublicUrl, RegistrationMode, SYSTEM_TENANT_SLUG, SecretHash, StandardClaims, TenantId,
    TenantSettings, User, UserId, UserStatus, normalize_email,
};
use crate::policy::{PasswordPolicy, check_password};
use crate::ports::{InstallOutcome, PasswordHasher, SetupOutcome, Storage, StorageError};
use crate::service::admin_scope::{ADMIN_READ, ADMIN_WRITE};
use crate::service::client::new_client_secret;
use crate::service::tenant::seal_new_key;

/// Lifetime of a setup token.
pub const SETUP_TOKEN_TTL: Duration = Duration::hours(1);
/// Prefix of the management client's `client_id`.
pub const MGMT_CLIENT_ID_PREFIX: &str = "mgmt-";

/// Result of [`BootstrapService::ensure_installed`].
#[derive(Debug)]
pub enum InstallResult {
    /// This call installed. The setup URL is to be shown to the operator once.
    Installed { setup_url: SecretString },
    /// An installation already exists; nothing was written.
    AlreadyInstalled,
}

/// Result of [`BootstrapService::complete_setup`]. The client secret is shown once.
#[derive(Debug)]
pub struct SetupResult {
    pub admin: User,
    pub mgmt_client_id: String,
    pub mgmt_client_secret: SecretString,
}

/// A new setup token record and its plaintext.
pub fn build_setup_token(now: OffsetDateTime) -> (NewSetupToken, SecretString) {
    let plaintext = random_token();
    let token = NewSetupToken {
        token_hash: SecretHash(secret_hash(&plaintext)),
        created_at: now,
        expires_at: now + SETUP_TOKEN_TTL,
    };
    (token, SecretString::from(plaintext))
}

/// `{public_url}/setup?token={token}`. `PublicUrl` never ends with `/`.
pub fn setup_url(public_url: &PublicUrl, token: &SecretString) -> SecretString {
    SecretString::from(format!(
        "{}/setup?token={}",
        public_url.as_str(),
        token.expose_secret()
    ))
}

fn bootstrap_tenant(
    now: OffsetDateTime,
    slug: &str,
    display_name: &str,
    registration: RegistrationMode,
) -> NewTenant {
    NewTenant {
        id: TenantId::new_v7(),
        slug: slug.to_owned(),
        display_name: display_name.to_owned(),
        host: None,
        settings: TenantSettings {
            registration,
            require_verified_email: false,
        },
        created_at: now,
    }
}

/// Everything first start writes: the `system` tenant (registration disabled), the `default`
/// tenant (registration open), one active key per tenant and a setup token (1 h). Returns the
/// plan and the plaintext setup token.
pub fn build_install_plan(
    now: OffsetDateTime,
    kek: &Kek,
) -> Result<(InstallPlan, SecretString), CoreError> {
    let system = bootstrap_tenant(
        now,
        SYSTEM_TENANT_SLUG,
        "System",
        RegistrationMode::Disabled,
    );
    let default = bootstrap_tenant(now, DEFAULT_TENANT_SLUG, "Default", RegistrationMode::Open);
    let keys = vec![
        (
            system.id,
            seal_new_key(kek, system.id, now, KeyState::Active)?,
        ),
        (
            default.id,
            seal_new_key(kek, default.id, now, KeyState::Active)?,
        ),
    ];
    let (setup_token, plaintext) = build_setup_token(now);
    Ok((
        InstallPlan {
            tenants: vec![system, default],
            keys,
            setup_token,
        },
        plaintext,
    ))
}

/// The management API client (system tenant): confidential, `client_secret_basic`,
/// `client_credentials` only, scopes `admin:read admin:write`. Returns the record (holding only
/// the secret hash) and the plaintext secret.
pub fn build_mgmt_client(now: OffsetDateTime) -> (NewClient, SecretString) {
    let (secret, hash) = new_client_secret();
    let client = NewClient {
        id: ClientId::new_v7(),
        client_id: format!("{MGMT_CLIENT_ID_PREFIX}{}", &random_token()[..16]),
        name: "Management API".to_owned(),
        client_type: ClientType::Confidential,
        application_type: ApplicationType::Web,
        auth_method: ClientAuthMethod::ClientSecretBasic,
        secret_hash: Some(hash),
        jwks: None,
        redirect_uris: Vec::new(),
        grant_types: vec![GrantType::ClientCredentials],
        scopes: vec![ADMIN_READ.to_owned(), ADMIN_WRITE.to_owned()],
        // Irrelevant for client_credentials; kept at the secure default.
        require_pkce: true,
        created_at: now,
    };
    (client, secret)
}

/// The first administrator. `email_verified` is true: the operator controls the console.
fn build_admin(now: OffsetDateTime, email: String) -> NewUser {
    NewUser {
        id: UserId::new_v7(),
        email,
        email_verified: true,
        username: None,
        claims: StandardClaims::default(),
        status: UserStatus::Active,
        created_at: now,
    }
}

/// Maps the setup outcome. Unknown, consumed and expired tokens are one `Forbidden`.
fn setup_outcome(outcome: SetupOutcome, secret: SecretString) -> Result<SetupResult, CoreError> {
    match outcome {
        SetupOutcome::Completed { user, client } => Ok(SetupResult {
            admin: user,
            mgmt_client_id: client.client_id,
            mgmt_client_secret: secret,
        }),
        SetupOutcome::InvalidToken => Err(CoreError::Forbidden),
    }
}

/// First start and setup.
pub struct BootstrapService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub kek: Arc<Kek>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub policy: PasswordPolicy,
    pub public_url: PublicUrl,
}

impl BootstrapService {
    /// Installs on an empty database (one `SetupRepo::install` transaction) and returns the
    /// setup URL; does nothing if an installation exists.
    pub async fn ensure_installed(&self) -> Result<InstallResult, CoreError> {
        if self.storage.setup().is_installed().await? {
            return Ok(InstallResult::AlreadyInstalled);
        }
        let (plan, token) = build_install_plan(self.clock.now(), &self.kek)?;
        match self.storage.setup().install(&plan).await? {
            InstallOutcome::Installed => Ok(InstallResult::Installed {
                setup_url: setup_url(&self.public_url, &token),
            }),
            InstallOutcome::AlreadyInstalled => Ok(InstallResult::AlreadyInstalled),
        }
    }

    /// Issues a new setup token (1 h) for `anvilid admin setup-url`. Requires an installation.
    /// Running it is an operator action with access to the database configuration.
    pub async fn new_setup_url(&self) -> Result<SecretString, CoreError> {
        if !self.storage.setup().is_installed().await? {
            return Err(CoreError::Conflict(
                "not installed yet; start the server once to install".to_owned(),
            ));
        }
        let (token, plaintext) = build_setup_token(self.clock.now());
        self.storage.setup().create_setup_token(&token).await?;
        Ok(setup_url(&self.public_url, &plaintext))
    }

    /// Whether `token` is a usable setup token (read-only; for rendering the setup page).
    pub async fn peek(&self, token: &str) -> Result<bool, CoreError> {
        let hash = SecretHash(secret_hash(token));
        Ok(self
            .storage
            .setup()
            .peek_setup_token(&hash, self.clock.now())
            .await?)
    }

    /// Consumes the setup token and creates the first administrator (system tenant) and the
    /// management client in one transaction. Input is validated first; an unknown, used or
    /// expired token is `Forbidden`.
    pub async fn complete_setup(
        &self,
        token: &str,
        email: &str,
        password: &SecretString,
    ) -> Result<SetupResult, CoreError> {
        let email = normalize_email(email)?;
        check_password(&self.policy, password.expose_secret())?;
        let now = self.clock.now();
        let hash = SecretHash(secret_hash(token));
        // Cheap pre-check so invalid tokens never cost an Argon2 hash. The atomic consume in
        // complete_setup below remains the authority.
        if !self.storage.setup().peek_setup_token(&hash, now).await? {
            return Err(CoreError::Forbidden);
        }
        let system = self
            .storage
            .tenants()
            .get_by_slug(SYSTEM_TENANT_SLUG)
            .await?
            .ok_or(CoreError::Forbidden)?;
        let credential = NewPasswordCredential {
            phc: self.hasher.hash(password.expose_secret()).await?,
            created_at: now,
        };
        let admin = build_admin(now, email);
        let (client, secret) = build_mgmt_client(now);
        let outcome = self
            .storage
            .setup()
            .complete_setup(
                &hash,
                now,
                system.id,
                &admin,
                &credential,
                system.id,
                &client,
            )
            .await
            .map_err(|e| match e {
                StorageError::Conflict(_) => {
                    CoreError::Conflict("administrator or client already exists".to_owned())
                }
                other => other.into(),
            })?;
        setup_outcome(outcome, secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Client, SIGNING_KEY_PURPOSE, signing_key_aad};

    const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    #[test]
    fn install_plan_has_two_tenants_two_active_keys_and_a_one_hour_token() {
        let kek = Kek::generate();
        let (plan, token) = build_install_plan(NOW, &kek).unwrap();
        assert_eq!(plan.tenants.len(), 2);
        let system = &plan.tenants[0];
        let default = &plan.tenants[1];
        assert_eq!(system.slug, "system");
        assert_eq!(system.settings.registration, RegistrationMode::Disabled);
        assert_eq!(default.slug, "default");
        assert_eq!(default.settings.registration, RegistrationMode::Open);
        assert_ne!(system.id, default.id);

        assert_eq!(plan.keys.len(), 2);
        assert_eq!(plan.keys[0].0, system.id);
        assert_eq!(plan.keys[1].0, default.id);
        for (_, key) in &plan.keys {
            assert_eq!(key.state, KeyState::Active);
            assert_eq!(key.alg, "RS256");
            kek.open(
                SIGNING_KEY_PURPOSE,
                &signing_key_aad(key.id),
                &key.private_key_enc,
            )
            .unwrap();
        }
        assert_ne!(plan.keys[0].1.kid, plan.keys[1].1.kid);

        assert_eq!(plan.setup_token.created_at, NOW);
        assert_eq!(plan.setup_token.expires_at, NOW + Duration::hours(1));
        assert_eq!(token.expose_secret().len(), 43);
        assert_eq!(
            plan.setup_token.token_hash,
            SecretHash(secret_hash(token.expose_secret()))
        );
    }

    #[test]
    fn mgmt_client_is_client_credentials_only_with_admin_scopes() {
        let (client, secret) = build_mgmt_client(NOW);
        assert!(client.client_id.starts_with("mgmt-"));
        assert_eq!(client.client_id.len(), 5 + 16);
        assert_eq!(client.client_type, ClientType::Confidential);
        assert_eq!(client.auth_method, ClientAuthMethod::ClientSecretBasic);
        assert_eq!(client.grant_types, vec![GrantType::ClientCredentials]);
        assert_eq!(client.scopes, vec!["admin:read", "admin:write"]);
        assert!(client.redirect_uris.is_empty());
        assert!(client.require_pkce);
        assert_eq!(
            client.secret_hash,
            Some(SecretHash(secret_hash(secret.expose_secret())))
        );
        // The plaintext secret appears nowhere in the stored record.
        assert!(!format!("{client:?}").contains(secret.expose_secret()));
        let (other, _) = build_mgmt_client(NOW);
        assert_ne!(client.client_id, other.client_id);
    }

    #[test]
    fn setup_url_format() {
        let token = SecretString::from("t".repeat(43));
        for (base, expected) in [
            ("https://id.example", "https://id.example/setup?token="),
            ("https://id.example/", "https://id.example/setup?token="),
            (
                "https://example.test/idp/",
                "https://example.test/idp/setup?token=",
            ),
        ] {
            let url = setup_url(&PublicUrl::parse(base).unwrap(), &token);
            assert_eq!(url.expose_secret(), format!("{expected}{}", "t".repeat(43)));
        }
        let (_, real) = build_setup_token(NOW);
        let url = setup_url(&PublicUrl::parse("http://localhost:8080").unwrap(), &real);
        let tok = url
            .expose_secret()
            .strip_prefix("http://localhost:8080/setup?token=")
            .unwrap();
        assert_eq!(tok.len(), 43);
        assert!(!format!("{url:?}").contains(tok));
    }

    #[test]
    fn invalid_setup_token_is_forbidden() {
        assert!(matches!(
            setup_outcome(
                SetupOutcome::InvalidToken,
                SecretString::from("s".to_owned())
            ),
            Err(CoreError::Forbidden)
        ));
    }

    #[test]
    fn completed_setup_returns_client_id_and_secret() {
        let (new_client, secret) = build_mgmt_client(NOW);
        let admin = build_admin(NOW, "root@example.com".into());
        assert!(admin.email_verified);
        let tenant = TenantId::new_v7();
        let user = User {
            id: admin.id,
            tenant_id: tenant,
            email: admin.email.clone(),
            email_verified: true,
            username: None,
            claims: StandardClaims::default(),
            status: UserStatus::Active,
            created_at: NOW,
            updated_at: NOW,
            last_login_at: None,
        };
        let client = Client {
            id: new_client.id,
            tenant_id: tenant,
            client_id: new_client.client_id.clone(),
            name: new_client.name.clone(),
            client_type: new_client.client_type,
            application_type: new_client.application_type,
            auth_method: new_client.auth_method,
            secret_hash: new_client.secret_hash,
            jwks: None,
            redirect_uris: vec![],
            grant_types: new_client.grant_types.clone(),
            scopes: new_client.scopes.clone(),
            require_pkce: true,
            created_at: NOW,
            updated_at: NOW,
        };
        let expected_secret = secret.expose_secret().to_owned();
        let r = setup_outcome(SetupOutcome::Completed { user, client }, secret).unwrap();
        assert_eq!(r.admin.email, "root@example.com");
        assert_eq!(r.mgmt_client_id, new_client.client_id);
        assert_eq!(r.mgmt_client_secret.expose_secret(), expected_secret);
    }
}
