//! First start and first-admin setup (ADM-03).
//!
//! On an empty database [`BootstrapService::ensure_installed`] writes, in one
//! `SetupRepo::install` transaction, the `system` and `default` tenants, one active RS256 key
//! per tenant and a one-time setup token valid for one hour. No user or credential exists until
//! [`BootstrapService::complete_setup`] consumes that token and atomically creates the first
//! administrator and the management API client, whose secret is returned exactly once.
//!
//! The setup token and URL are never logged here; the binary prints the URL once.
//!
//! # The console client and the system tenant (Research Open Question 5)
//!
//! Users of the system tenant are the installation's administrators, and the admin console signs
//! in as the built-in public client `anvil-console` of the system tenant. That client is product
//! configuration, not operator data: [`BootstrapService::ensure_console_client`] runs at every
//! start and reconciles it with values derived from the public URL (there is no switch to turn it
//! off in 0.2). The same call enforces `registration = disabled` for the system tenant on
//! installations created before this rule, so nobody can sign themselves up as an administrator.
//! Admin scopes only exist on system-tenant clients, so a user of any other tenant can never
//! obtain them.

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::{ExposeSecret as _, SecretString};
use time::{Duration, OffsetDateTime};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    ApplicationType, AuditAction, AuditActor, AuditDetails, AuditOutcome, Client, ClientAuthMethod,
    ClientId, ClientType, ClientUpdate, ConsentMode, DEFAULT_TENANT_SLUG, GrantType, InstallPlan,
    KeyState, NewClient, NewPasswordCredential, NewSetupToken, NewTenant, NewUser, PublicUrl,
    RegistrationMode, RequestContext, SYSTEM_TENANT_SLUG, SecretHash, StandardClaims, Tenant,
    TenantId, TenantSettings, TenantUpdate, TokenFormat, User, UserId, UserStatus, normalize_email,
};
use crate::policy::{PasswordPolicy, check_password};
use crate::ports::{InstallOutcome, PasswordHasher, SetupOutcome, Storage, StorageError};
use crate::service::admin_scope::{ADMIN_READ, ADMIN_WRITE};
use crate::service::audit::AuditService;
use crate::service::client::new_client_secret;
use crate::service::tenant::seal_new_key;

/// Lifetime of a setup token.
pub const SETUP_TOKEN_TTL: Duration = Duration::hours(1);
/// Prefix of the management client's `client_id`.
pub const MGMT_CLIENT_ID_PREFIX: &str = "mgmt-";

/// `client_id` of the built-in admin console client (system tenant).
pub const CONSOLE_CLIENT_ID: &str = "anvil-console";
/// Path of the console's OAuth callback below the public URL.
pub const CONSOLE_CALLBACK_PATH: &str = "/console/callback";
/// Display name of the console client.
pub const CONSOLE_CLIENT_NAME: &str = "AnvilID Console";

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
    /// Set when the `admin_setup_completed` audit event could not be stored. Setup itself has
    /// committed and the secret must still be shown once, so the caller logs this and continues.
    pub audit_error: Option<CoreError>,
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
            ..TenantSettings::default()
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
        token_format: crate::model::TokenFormat::Jwt,
        consent_mode: crate::model::ConsentMode::Required,
        id_token_signed_response_alg: None,
        can_introspect: false,
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        allowed_resources: vec![],
        mfa_policy: None,
        metadata_expires_at: None,
        registration_access_token_hash: None,
        registration_source: crate::model::ClientSource::Static,
    };
    (client, secret)
}

/// `{public_url}/console/callback`. `PublicUrl` never ends with `/`.
pub fn console_redirect_uri(public_url: &PublicUrl) -> String {
    format!("{}{CONSOLE_CALLBACK_PATH}", public_url.as_str())
}

/// The built-in console client (system tenant): public, auth method `none`, PKCE required,
/// redirect `{public_url}/console/callback`, grants `authorization_code` + `refresh_token`,
/// scopes `openid admin:read admin:write`, consent skipped (first party), JWT access tokens.
pub fn build_console_client(now: OffsetDateTime, public_url: &PublicUrl) -> NewClient {
    let mut grant_types = vec![GrantType::AuthorizationCode, GrantType::RefreshToken];
    grant_types.sort();
    NewClient {
        id: ClientId::new_v7(),
        client_id: CONSOLE_CLIENT_ID.to_owned(),
        name: CONSOLE_CLIENT_NAME.to_owned(),
        client_type: ClientType::Public,
        application_type: ApplicationType::Web,
        auth_method: ClientAuthMethod::None,
        secret_hash: None,
        jwks: None,
        redirect_uris: vec![console_redirect_uri(public_url)],
        grant_types,
        scopes: vec![
            "openid".to_owned(),
            ADMIN_READ.to_owned(),
            ADMIN_WRITE.to_owned(),
        ],
        require_pkce: true,
        created_at: now,
        token_format: TokenFormat::Jwt,
        consent_mode: ConsentMode::SkipFirstParty,
        id_token_signed_response_alg: None,
        can_introspect: false,
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        allowed_resources: vec![],
        mfa_policy: None,
        metadata_expires_at: None,
        registration_access_token_hash: None,
        registration_source: crate::model::ClientSource::Static,
    }
}

/// The update that brings a stored console client back to `desired`, with the changed field
/// names; `None` when it already matches. Type, application type and auth method cannot be
/// updated; a mismatch there means the row was altered outside AnvilID and is an error.
pub fn console_client_drift(
    current: &Client,
    desired: &NewClient,
) -> Result<Option<(ClientUpdate, Vec<&'static str>)>, CoreError> {
    if current.client_type != desired.client_type
        || current.application_type != desired.application_type
        || current.auth_method != desired.auth_method
    {
        return Err(CoreError::Internal(format!(
            "the built-in {CONSOLE_CLIENT_ID} client has an unexpected type or auth method"
        )));
    }
    let mut update = ClientUpdate::default();
    let mut fields = Vec::new();
    if current.name != desired.name {
        update.name = Some(desired.name.clone());
        fields.push("name");
    }
    if current.redirect_uris != desired.redirect_uris {
        update.redirect_uris = Some(desired.redirect_uris.clone());
        fields.push("redirect_uris");
    }
    let mut grants = current.grant_types.clone();
    grants.sort();
    if grants != desired.grant_types {
        update.grant_types = Some(desired.grant_types.clone());
        fields.push("grant_types");
    }
    if current.scopes != desired.scopes {
        update.scopes = Some(desired.scopes.clone());
        fields.push("scopes");
    }
    if current.require_pkce != desired.require_pkce {
        update.require_pkce = Some(desired.require_pkce);
        fields.push("require_pkce");
    }
    if current.jwks.is_some() {
        update.jwks = Some(None);
        fields.push("jwks");
    }
    if current.token_format != desired.token_format {
        update.token_format = Some(desired.token_format);
        fields.push("token_format");
    }
    if current.consent_mode != desired.consent_mode {
        update.consent_mode = Some(desired.consent_mode);
        fields.push("consent_mode");
    }
    if current.id_token_signed_response_alg != desired.id_token_signed_response_alg {
        update.id_token_signed_response_alg = Some(desired.id_token_signed_response_alg.clone());
        fields.push("id_token_signed_response_alg");
    }
    if current.can_introspect != desired.can_introspect {
        update.can_introspect = Some(desired.can_introspect);
        fields.push("can_introspect");
    }
    Ok((!fields.is_empty()).then_some((update, fields)))
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
            audit_error: None,
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

    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
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

    /// Reconciles the built-in console client and the system tenant's policy. Called at every
    /// start (after [`Self::ensure_installed`]) with the configured public URL:
    ///
    /// - the system tenant's registration mode is set to `disabled` if it is not (audited as
    ///   `tenant_updated` by the system actor);
    /// - `anvil-console` is created ([`build_console_client`], audited `client_created`) or
    ///   updated to match ([`console_client_drift`], audited `client_updated`), e.g. when the
    ///   public URL changed. When everything already matches nothing is written or audited.
    pub async fn ensure_console_client(&self, public_url: &PublicUrl) -> Result<(), CoreError> {
        let system = self.system_tenant().await?;
        let ctx = RequestContext::system();
        if system.settings.registration != RegistrationMode::Disabled {
            let settings = TenantSettings {
                registration: RegistrationMode::Disabled,
                ..system.settings.clone()
            };
            self.storage
                .tenants()
                .update(
                    system.id,
                    &TenantUpdate {
                        settings: Some(settings),
                        ..TenantUpdate::default()
                    },
                )
                .await?
                .ok_or(CoreError::NotFound)?;
            self.audit()
                .record(
                    system.id,
                    AuditActor::system(),
                    AuditAction::TenantUpdated,
                    Some(system.id.to_string()),
                    AuditOutcome::Success,
                    &ctx,
                    AuditDetails::fields(&["settings.registration"]),
                )
                .await?;
        }

        let desired = build_console_client(self.clock.now(), public_url);
        let clients = self.storage.clients();
        let current = match clients.get(system.id, CONSOLE_CLIENT_ID).await? {
            Some(c) => c,
            None => match clients.create(system.id, &desired).await {
                Ok(_) => {
                    return self
                        .audit()
                        .record(
                            system.id,
                            AuditActor::system(),
                            AuditAction::ClientCreated,
                            Some(CONSOLE_CLIENT_ID.to_owned()),
                            AuditOutcome::Success,
                            &ctx,
                            AuditDetails::empty(),
                        )
                        .await;
                }
                // Another instance created it concurrently: reconcile what it wrote.
                Err(StorageError::Conflict(_)) => clients
                    .get(system.id, CONSOLE_CLIENT_ID)
                    .await?
                    .ok_or_else(|| {
                        CoreError::Internal("console client conflict without a row".into())
                    })?,
                Err(e) => return Err(e.into()),
            },
        };
        let now = self.clock.now();
        let mut fields = Vec::new();
        if let Some((update, changed)) = console_client_drift(&current, &desired)? {
            clients
                .update(system.id, CONSOLE_CLIENT_ID, &update, now)
                .await?
                .ok_or(CoreError::NotFound)?;
            fields = changed;
        }
        if current.secret_hash.is_some() {
            clients
                .set_secret_hash(system.id, CONSOLE_CLIENT_ID, None, now)
                .await?;
            fields.push("secret");
        }
        if fields.is_empty() {
            return Ok(());
        }
        self.audit()
            .record(
                system.id,
                AuditActor::system(),
                AuditAction::ClientUpdated,
                Some(CONSOLE_CLIENT_ID.to_owned()),
                AuditOutcome::Success,
                &ctx,
                AuditDetails::fields(&fields),
            )
            .await
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
    /// expired token is `Forbidden`. On success `admin_setup_completed` is audited in the system
    /// tenant (actor = the new administrator, `ctx` = the setup request); an audit failure is
    /// returned in [`SetupResult::audit_error`] because the one-time secret must still be shown.
    pub async fn complete_setup(
        &self,
        token: &str,
        email: &str,
        password: &SecretString,
        ctx: &RequestContext,
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
        let mut result = setup_outcome(outcome, secret)?;
        result.audit_error = self
            .audit()
            .record(
                system.id,
                AuditActor::admin(result.admin.id),
                AuditAction::AdminSetupCompleted,
                Some(result.admin.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::empty(),
            )
            .await
            .err();
        Ok(result)
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

    fn stored(new: &NewClient) -> Client {
        Client {
            id: new.id,
            tenant_id: TenantId::new_v7(),
            client_id: new.client_id.clone(),
            name: new.name.clone(),
            client_type: new.client_type,
            application_type: new.application_type,
            auth_method: new.auth_method,
            secret_hash: new.secret_hash,
            jwks: new.jwks.clone(),
            redirect_uris: new.redirect_uris.clone(),
            grant_types: new.grant_types.clone(),
            scopes: new.scopes.clone(),
            require_pkce: new.require_pkce,
            created_at: NOW,
            updated_at: NOW,
            token_format: new.token_format,
            consent_mode: new.consent_mode,
            id_token_signed_response_alg: new.id_token_signed_response_alg.clone(),
            can_introspect: new.can_introspect,
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources: vec![],
            mfa_policy: None,
            metadata_expires_at: None,
            registration_access_token_hash: None,
            registration_source: crate::model::ClientSource::Static,
        }
    }

    #[test]
    fn console_client_values_derive_from_the_public_url() {
        let url = PublicUrl::parse("https://id.example/").unwrap();
        let c = build_console_client(NOW, &url);
        assert_eq!(c.client_id, "anvil-console");
        assert_eq!(c.client_type, ClientType::Public);
        assert_eq!(c.auth_method, ClientAuthMethod::None);
        assert!(c.secret_hash.is_none());
        assert!(c.require_pkce);
        assert_eq!(c.redirect_uris, vec!["https://id.example/console/callback"]);
        assert_eq!(
            c.grant_types,
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
        );
        assert_eq!(c.scopes, vec!["openid", "admin:read", "admin:write"]);
        assert_eq!(c.consent_mode, ConsentMode::SkipFirstParty);
        assert_eq!(c.token_format, TokenFormat::Jwt);
        assert!(!c.can_introspect);
    }

    #[test]
    fn console_drift_detects_changes_and_refuses_type_changes() {
        let a = build_console_client(NOW, &PublicUrl::parse("https://a.example").unwrap());
        let b = build_console_client(NOW, &PublicUrl::parse("https://b.example").unwrap());
        assert!(console_client_drift(&stored(&a), &a).unwrap().is_none());
        let (update, fields) = console_client_drift(&stored(&a), &b).unwrap().unwrap();
        assert_eq!(fields, vec!["redirect_uris"]);
        assert_eq!(
            update.redirect_uris,
            Some(vec!["https://b.example/console/callback".to_owned()])
        );

        let mut tampered = stored(&a);
        tampered.scopes.push("admin:users:write".into());
        tampered.consent_mode = ConsentMode::Required;
        tampered.require_pkce = false;
        let (_, fields) = console_client_drift(&tampered, &a).unwrap().unwrap();
        assert_eq!(fields, vec!["scopes", "require_pkce", "consent_mode"]);

        let mut confidential = stored(&a);
        confidential.client_type = ClientType::Confidential;
        assert!(console_client_drift(&confidential, &a).is_err());
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
            token_format: crate::model::TokenFormat::Jwt,
            consent_mode: crate::model::ConsentMode::Required,
            id_token_signed_response_alg: None,
            can_introspect: false,
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources: vec![],
            mfa_policy: None,
            metadata_expires_at: None,
            registration_access_token_hash: None,
            registration_source: crate::model::ClientSource::Static,
        };
        let expected_secret = secret.expose_secret().to_owned();
        let r = setup_outcome(SetupOutcome::Completed { user, client }, secret).unwrap();
        assert_eq!(r.admin.email, "root@example.com");
        assert_eq!(r.mgmt_client_id, new_client.client_id);
        assert_eq!(r.mgmt_client_secret.expose_secret(), expected_secret);
    }

    // --- concurrent first start (OPS-03): this node loses every race ---------------------

    use super::race_fake::RaceFake;
    use crate::ports::PasswordCheck;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Never reached by install or console reconciliation.
    struct NoHasher;

    #[async_trait::async_trait]
    impl PasswordHasher for NoHasher {
        async fn hash(&self, _password: &str) -> Result<String, CoreError> {
            Err(CoreError::Internal("race test: no hashing".into()))
        }
        async fn verify(
            &self,
            _phc: Option<&str>,
            _password: &str,
        ) -> Result<PasswordCheck, CoreError> {
            Err(CoreError::Internal("race test: no hashing".into()))
        }
    }

    fn race_service(fake: Arc<RaceFake>) -> BootstrapService {
        BootstrapService {
            storage: fake,
            clock: Arc::new(crate::clock::SystemClock),
            kek: Arc::new(Kek::generate()),
            hasher: Arc::new(NoHasher),
            policy: PasswordPolicy::default(),
            public_url: PublicUrl::parse("https://id.example/").unwrap(),
        }
    }

    fn system_tenant() -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: SYSTEM_TENANT_SLUG.to_owned(),
            display_name: "System".to_owned(),
            host: None,
            settings: TenantSettings {
                registration: RegistrationMode::Disabled,
                ..TenantSettings::default()
            },
            created_at: NOW,
        }
    }

    #[tokio::test]
    async fn concurrent_install_loser_gets_already_installed_and_no_setup_url() {
        let fake = Arc::new(RaceFake {
            installed: false,
            install: Some(InstallOutcome::AlreadyInstalled),
            ..RaceFake::default()
        });
        let result = race_service(fake.clone()).ensure_installed().await.unwrap();
        assert!(matches!(result, InstallResult::AlreadyInstalled));
        assert_eq!(fake.audit_count(), 0);
    }

    #[tokio::test]
    async fn console_client_conflict_rereads_the_winners_row_and_does_not_audit() {
        let url = PublicUrl::parse("https://id.example/").unwrap();
        // What the winner wrote: exactly what this node wants.
        let winner = stored(&build_console_client(NOW, &url));
        let fake = Arc::new(RaceFake {
            system: Some(system_tenant()),
            client_gets: Mutex::new(VecDeque::from([None, Some(winner)])),
            client_create_conflict: true,
            ..RaceFake::default()
        });
        race_service(fake.clone())
            .ensure_console_client(&url)
            .await
            .expect("a concurrent winner's unique violation is success");
        assert_eq!(
            fake.audit_count(),
            0,
            "only the winner audits client_created"
        );
    }

    #[tokio::test]
    async fn console_client_conflict_without_a_row_is_an_error() {
        let url = PublicUrl::parse("https://id.example/").unwrap();
        let fake = Arc::new(RaceFake {
            system: Some(system_tenant()),
            client_gets: Mutex::new(VecDeque::from([None, None])),
            client_create_conflict: true,
            ..RaceFake::default()
        });
        let err = race_service(fake.clone())
            .ensure_console_client(&url)
            .await
            .expect_err("a conflict nobody won is not hidden");
        assert!(matches!(err, CoreError::Internal(_)), "{err:?}");
        assert_eq!(fake.audit_count(), 0);
    }
}

/// A storage fake that plays the loser of a concurrent first start (several nodes on one empty
/// database, OPS-03): the client, key and setup repositories answer as if another node had just
/// won. Shared by the bootstrap and key-rotation tests; only the methods those use are backed.
#[cfg(test)]
pub(crate) mod race_fake {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use time::OffsetDateTime;

    use crate::model::{
        AuditEvent, AuditQuery, Client, InstallPlan, NewAuditEvent, NewClient,
        NewPasswordCredential, NewSetupToken, NewSigningKey, NewTenant, NewUser, Page, PageRequest,
        SecretHash, SigningKey, SigningKeyId, Tenant, TenantId, TenantUpdate,
    };
    use crate::ports::{
        AttributeRepo, AuditRepo, BrandingRepo, ClientRepo, ConnectionRepo, FlowRepo, GrantRepo,
        InstallOutcome, JobRepo, KeyRepo, LogoutRepo, MailSettingsRepo, OutboxRepo,
        RegistrationRepo, RoleRepo, SessionRepo, SetupOutcome, SetupRepo, Storage, StorageError,
        TenantRepo, UserRepo, WebhookRepo,
    };

    fn unsupported<T>() -> Result<T, StorageError> {
        Err(StorageError::Unsupported("race fake"))
    }

    /// Scripted answers, consumed in order; an exhausted queue answers `None`.
    #[derive(Default)]
    pub(crate) struct RaceFake {
        pub system: Option<Tenant>,
        pub installed: bool,
        pub install: Option<InstallOutcome>,
        /// `clients().get` answers.
        pub client_gets: Mutex<VecDeque<Option<Client>>>,
        /// `clients().create` fails with `Conflict` (a concurrent winner's unique violation).
        pub client_create_conflict: bool,
        /// `keys().active` answers.
        pub active_keys: Mutex<VecDeque<Option<SigningKey>>>,
        /// `keys().insert` fails with `Conflict` (the one-active-key index).
        pub key_insert_conflict: bool,
        pub key_inserts: Mutex<u32>,
        pub audits: Mutex<Vec<NewAuditEvent>>,
    }

    impl RaceFake {
        pub(crate) fn audit_count(&self) -> usize {
            self.audits.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl TenantRepo for RaceFake {
        async fn create(&self, _tenant: &NewTenant) -> Result<Tenant, StorageError> {
            unsupported()
        }
        async fn get(&self, _id: TenantId) -> Result<Option<Tenant>, StorageError> {
            unsupported()
        }
        async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError> {
            Ok(self.system.clone().filter(|t| t.slug == slug))
        }
        async fn get_by_host(&self, _host: &str) -> Result<Option<Tenant>, StorageError> {
            unsupported()
        }
        async fn list(&self, _page: PageRequest) -> Result<Page<Tenant>, StorageError> {
            unsupported()
        }
        async fn update(
            &self,
            _id: TenantId,
            _update: &TenantUpdate,
        ) -> Result<Option<Tenant>, StorageError> {
            unsupported()
        }
        async fn delete(&self, _id: TenantId) -> Result<bool, StorageError> {
            unsupported()
        }
    }

    #[async_trait::async_trait]
    impl ClientRepo for RaceFake {
        async fn create(&self, _t: TenantId, _client: &NewClient) -> Result<Client, StorageError> {
            if self.client_create_conflict {
                Err(StorageError::Conflict("client_id".into()))
            } else {
                unsupported()
            }
        }
        async fn get(
            &self,
            _t: TenantId,
            _client_id: &str,
        ) -> Result<Option<Client>, StorageError> {
            Ok(self.client_gets.lock().unwrap().pop_front().flatten())
        }
        async fn list(
            &self,
            _t: TenantId,
            _page: PageRequest,
        ) -> Result<Page<Client>, StorageError> {
            unsupported()
        }
        async fn update(
            &self,
            _t: TenantId,
            _client_id: &str,
            _update: &crate::model::ClientUpdate,
            _now: OffsetDateTime,
        ) -> Result<Option<Client>, StorageError> {
            unsupported()
        }
        async fn set_secret_hash(
            &self,
            _t: TenantId,
            _client_id: &str,
            _secret_hash: Option<SecretHash>,
            _now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn delete(&self, _t: TenantId, _client_id: &str) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn upsert_cimd(
            &self,
            _t: TenantId,
            _client: &NewClient,
            _metadata_expires_at: OffsetDateTime,
            _now: OffsetDateTime,
        ) -> Result<Client, StorageError> {
            unsupported()
        }
        async fn get_by_registration_token(
            &self,
            _t: TenantId,
            _client_id: &str,
            _token_hash: &SecretHash,
        ) -> Result<Option<Client>, StorageError> {
            unsupported()
        }
        async fn set_registration_token(
            &self,
            _t: TenantId,
            _client_id: &str,
            _token_hash: Option<&SecretHash>,
            _now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
    }

    #[async_trait::async_trait]
    impl KeyRepo for RaceFake {
        async fn insert(&self, _t: TenantId, _key: &NewSigningKey) -> Result<(), StorageError> {
            *self.key_inserts.lock().unwrap() += 1;
            if self.key_insert_conflict {
                Err(StorageError::Conflict("one active key per alg".into()))
            } else {
                Ok(())
            }
        }
        async fn active(
            &self,
            _t: TenantId,
            _alg: &str,
        ) -> Result<Option<SigningKey>, StorageError> {
            Ok(self.active_keys.lock().unwrap().pop_front().flatten())
        }
        async fn published(
            &self,
            _t: TenantId,
            _now: OffsetDateTime,
        ) -> Result<Vec<SigningKey>, StorageError> {
            unsupported()
        }
        async fn list(&self, _t: TenantId) -> Result<Vec<SigningKey>, StorageError> {
            unsupported()
        }
        async fn promote(
            &self,
            _t: TenantId,
            _retire: Option<(SigningKeyId, OffsetDateTime)>,
            _activate: SigningKeyId,
            _now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn delete_expired(
            &self,
            _t: TenantId,
            _now: OffsetDateTime,
        ) -> Result<u64, StorageError> {
            unsupported()
        }
    }

    #[async_trait::async_trait]
    impl SetupRepo for RaceFake {
        async fn is_installed(&self) -> Result<bool, StorageError> {
            Ok(self.installed)
        }
        async fn install(&self, _plan: &InstallPlan) -> Result<InstallOutcome, StorageError> {
            self.install
                .ok_or(StorageError::Unsupported("race fake: install"))
        }
        async fn create_setup_token(&self, _token: &NewSetupToken) -> Result<(), StorageError> {
            unsupported()
        }
        async fn peek_setup_token(
            &self,
            _hash: &SecretHash,
            _now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            unsupported()
        }
        async fn complete_setup(
            &self,
            _hash: &SecretHash,
            _now: OffsetDateTime,
            _admin_tenant: TenantId,
            _admin: &NewUser,
            _password: &NewPasswordCredential,
            _client_tenant: TenantId,
            _client: &NewClient,
        ) -> Result<SetupOutcome, StorageError> {
            unsupported()
        }
    }

    #[async_trait::async_trait]
    impl AuditRepo for RaceFake {
        async fn append(&self, _t: TenantId, event: &NewAuditEvent) -> Result<(), StorageError> {
            self.audits.lock().unwrap().push(event.clone());
            Ok(())
        }
        async fn query(
            &self,
            _t: TenantId,
            _query: &AuditQuery,
        ) -> Result<Page<AuditEvent>, StorageError> {
            unsupported()
        }
        async fn purge_before(&self, _cutoff: OffsetDateTime) -> Result<u64, StorageError> {
            unsupported()
        }
    }

    /// Tenants, clients, keys, setup and audit are backed; nothing else is reached.
    #[async_trait::async_trait]
    impl Storage for RaceFake {
        fn tenants(&self) -> &dyn TenantRepo {
            self
        }
        fn users(&self) -> &dyn UserRepo {
            unreachable!("race fake: users")
        }
        fn clients(&self) -> &dyn ClientRepo {
            self
        }
        fn keys(&self) -> &dyn KeyRepo {
            self
        }
        fn sessions(&self) -> &dyn SessionRepo {
            unreachable!("race fake: sessions")
        }
        fn flows(&self) -> &dyn FlowRepo {
            unreachable!("race fake: flows")
        }
        fn grants(&self) -> &dyn GrantRepo {
            unreachable!("race fake: grants")
        }
        fn setup(&self) -> &dyn SetupRepo {
            self
        }
        fn outbox(&self) -> &dyn OutboxRepo {
            unreachable!("race fake: outbox")
        }
        fn audit(&self) -> &dyn AuditRepo {
            self
        }
        fn mail_settings(&self) -> &dyn MailSettingsRepo {
            unreachable!("race fake: mail settings")
        }
        fn jobs(&self) -> &dyn JobRepo {
            unreachable!("race fake: jobs")
        }
        fn connections(&self) -> &dyn ConnectionRepo {
            unreachable!("race fake: connections")
        }
        fn branding(&self) -> &dyn BrandingRepo {
            unreachable!("race fake: branding")
        }
        fn logout(&self) -> &dyn LogoutRepo {
            unreachable!("race fake: logout")
        }
        fn roles(&self) -> &dyn RoleRepo {
            unreachable!("race fake: roles")
        }
        fn attributes(&self) -> &dyn AttributeRepo {
            unreachable!("race fake: attributes")
        }
        fn webhooks(&self) -> &dyn WebhookRepo {
            unreachable!("race fake: webhooks")
        }
        fn registration(&self) -> &dyn RegistrationRepo {
            unreachable!("race fake: registration")
        }
        async fn purge_expired(&self, _now: OffsetDateTime) -> Result<u64, StorageError> {
            unsupported()
        }
    }
}
