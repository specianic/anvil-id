//! Dynamic client registration (RFC 7591), client configuration (RFC 7592) and initial access
//! tokens (OIDC-17).
//!
//! # Policy
//!
//! The tenant's effective DCR policy ([`Tenant::effective_dcr`]; the system tenant is always
//! `disabled`) decides whether the endpoints exist:
//!
//! - `disabled`: every method answers [`CoreError::NotFound`] (the web layer renders the 404 of a
//!   route that does not exist);
//! - `allow_listed`: registration needs a Bearer initial access token issued by an administrator
//!   ([`RegistrationService::issue_iat`]), and the redirect-host allow-list applies when it is set;
//! - `open`: anyone may register.
//!
//! Both open policies are capped by [`DcrSettings::max_clients`] (counted before the insert, so
//! concurrent registrations can overshoot the cap by at most the number of requests in flight).
//!
//! # Scopes
//!
//! [`effective_settings`] resolves an empty [`DcrSettings::allowed_scopes`] ("the tenant's
//! default scopes") to [`DEFAULT_DCR_SCOPES`], the standard scopes the provider supports (also
//! published as `scopes_supported` in discovery), before `oauth::registration::validate`, which
//! fails closed on an empty list.
//!
//! # Informational metadata
//!
//! `logo_uri`, `client_uri`, `policy_uri` and `tos_uri` are validated (absolute https, length
//! cap) but neither stored nor echoed: the client model has no columns for them, and RFC 7591
//! §3.2.1 requires the registration response to contain what was registered, which the RFC 7592
//! read response must then repeat. Echoing values that a later `GET` would not return would
//! misstate the registration, so the server ignores them (RFC 7591 §2 lets it ignore or
//! substitute requested values). Consent shows the `client_name`.
//!
//! # Tokens
//!
//! Initial access tokens and registration access tokens are 256-bit random values (base64url),
//! returned once and stored as SHA-256 digests only. An initial access token has an expiry
//! (default [`IAT_DEFAULT_TTL`], at most [`IAT_MAX_TTL`]) and an optional use count; a use is
//! consumed by one conditional update ([`crate::ports::RegistrationRepo::consume_iat`]) only after
//! the metadata validated, so a rejected request does not burn a single-use token.
//!
//! # Audit
//!
//! `client_registered`, `client_registration_updated` and `client_registration_deleted` (actor:
//! the client) are recorded by [`ClientService`]; `initial_access_token_created` and
//! `initial_access_token_revoked` (actor: the administrator, target: the token id) here.

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Map, Value};
use time::Duration;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, Client, ClientSource, ConsentMode,
    DcrPolicy, DcrSettings, GrantType, InitialAccessToken, InitialAccessTokenId,
    NewInitialAccessToken, RequestContext, SYSTEM_TENANT_SLUG, SecretHash, Tenant, TenantId,
};
use crate::oauth::registration::{self, DcrMode, ValidatedRegistration};
use crate::ports::Storage;
use crate::service::audit::AuditService;
use crate::service::client::{
    ClientOptionsPatch, ClientPatch, ClientService, CreatedClient, RedirectValidator,
};

/// Scopes a registered client may ask for when the tenant lists none
/// ([`DcrSettings::allowed_scopes`] empty): the standard scopes the provider supports.
pub const DEFAULT_DCR_SCOPES: &[&str] = &["openid", "profile", "email", "address", "phone"];

/// Lifetime of an initial access token issued without an explicit one.
pub const IAT_DEFAULT_TTL: Duration = Duration::days(1);
/// Longest lifetime of an initial access token.
pub const IAT_MAX_TTL: Duration = Duration::days(365);
/// Shortest lifetime of an initial access token.
pub const IAT_MIN_TTL: Duration = Duration::minutes(1);
/// Longest initial access token description (characters).
pub const MAX_IAT_DESCRIPTION_LEN: usize = 200;
/// Largest use count of an initial access token.
pub const MAX_IAT_USES: u32 = 100_000;

/// Members a client must not send in an RFC 7592 update (RFC 7592 §2.2): they are provisioned
/// by the server.
const SERVER_MANAGED: &[&str] = &[
    "registration_access_token",
    "registration_client_uri",
    "client_id_issued_at",
    "client_secret_expires_at",
];

/// The tenant's DCR settings in force, with "empty `allowed_scopes` = the tenant defaults"
/// resolved to [`DEFAULT_DCR_SCOPES`]. The system tenant's policy is always `disabled`.
pub fn effective_settings(tenant: &Tenant) -> DcrSettings {
    let mut dcr = tenant.effective_dcr();
    if dcr.allowed_scopes.is_empty() {
        dcr.allowed_scopes = DEFAULT_DCR_SCOPES.iter().map(|s| (*s).to_owned()).collect();
    }
    dcr
}

/// The validation mode of the tenant's policy; `NotFound` when registration is disabled.
fn mode_of(tenant: &Tenant) -> Result<(DcrSettings, DcrMode), CoreError> {
    let settings = effective_settings(tenant);
    let mode = match settings.policy {
        DcrPolicy::Disabled => return Err(CoreError::NotFound),
        DcrPolicy::AllowListed => DcrMode::AllowListed,
        DcrPolicy::Open => DcrMode::Open,
    };
    Ok((settings, mode))
}

/// The RFC 7591 §3.2.1 registered metadata of a stored client (without `client_id` and the
/// registration-access members): exactly what was stored, with every substituted value.
pub fn client_metadata(client: &Client) -> Map<String, Value> {
    let strings = |v: &[String]| Value::Array(v.iter().cloned().map(Value::String).collect());
    let mut m = Map::new();
    m.insert("redirect_uris".into(), strings(&client.redirect_uris));
    m.insert(
        "token_endpoint_auth_method".into(),
        client.auth_method.as_str().into(),
    );
    m.insert(
        "grant_types".into(),
        Value::Array(
            client
                .grant_types
                .iter()
                .map(|g| g.as_str().into())
                .collect(),
        ),
    );
    let response_types: &[&str] = if client.grant_types.contains(&GrantType::AuthorizationCode) {
        &["code"]
    } else {
        &[]
    };
    m.insert("response_types".into(), response_types.into());
    m.insert(
        "application_type".into(),
        client.application_type.as_str().into(),
    );
    m.insert("client_name".into(), client.name.clone().into());
    m.insert("scope".into(), client.scopes.join(" ").into());
    m.insert(
        "allowed_resources".into(),
        strings(&client.allowed_resources),
    );
    if let Some(jwks) = client
        .jwks
        .as_deref()
        .and_then(|j| serde_json::from_str::<Value>(j).ok())
    {
        m.insert("jwks".into(), jwks);
    }
    if !client.post_logout_redirect_uris.is_empty() {
        m.insert(
            "post_logout_redirect_uris".into(),
            strings(&client.post_logout_redirect_uris),
        );
    }
    if let Some(uri) = &client.backchannel_logout_uri {
        m.insert("backchannel_logout_uri".into(), uri.clone().into());
        m.insert(
            "backchannel_logout_session_required".into(),
            client.backchannel_logout_session_required.into(),
        );
    }
    m
}

/// `{issuer}/register/{client_id}`: the RFC 7592 client configuration endpoint of a client.
pub fn registration_client_uri(issuer: &str, client_id: &str) -> String {
    format!("{issuer}/register/{client_id}")
}

/// The client information response (RFC 7591 §3.2.1, RFC 7592 §3): the registered metadata,
/// `client_id`, `client_id_issued_at` and `registration_client_uri`, plus the secret
/// (`client_secret_expires_at: 0`, it does not expire) and the registration access token when
/// they were just issued.
pub fn client_information(
    client: &Client,
    issuer: &str,
    client_secret: Option<&SecretString>,
    registration_access_token: Option<&SecretString>,
) -> Map<String, Value> {
    let mut m = client_metadata(client);
    m.insert("client_id".into(), client.client_id.clone().into());
    m.insert(
        "client_id_issued_at".into(),
        client.created_at.unix_timestamp().into(),
    );
    m.insert(
        "registration_client_uri".into(),
        registration_client_uri(issuer, &client.client_id).into(),
    );
    if let Some(secret) = client_secret {
        m.insert("client_secret".into(), secret.expose_secret().into());
        m.insert("client_secret_expires_at".into(), 0.into());
    }
    if let Some(rat) = registration_access_token {
        m.insert(
            "registration_access_token".into(),
            rat.expose_secret().into(),
        );
    }
    m
}

/// A registered client. The secret (secret-based auth methods only) and the registration access
/// token are the plaintext values, returned exactly once; only their hashes are stored.
#[derive(Debug)]
pub struct Registration {
    pub client: Client,
    pub client_secret: Option<SecretString>,
    pub registration_access_token: SecretString,
}

impl Registration {
    /// The RFC 7591 §3.2.1 response body.
    pub fn response(&self, issuer: &str) -> Map<String, Value> {
        client_information(
            &self.client,
            issuer,
            self.client_secret.as_ref(),
            Some(&self.registration_access_token),
        )
    }
}

/// An initial access token to issue.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IatRequest {
    pub description: String,
    /// `None` = [`IAT_DEFAULT_TTL`]; [`IAT_MIN_TTL`]`..=`[`IAT_MAX_TTL`].
    pub expires_in: Option<Duration>,
    /// `None` = unlimited until expiry or revocation; `1..=`[`MAX_IAT_USES`].
    pub uses: Option<u32>,
}

/// An issued initial access token: the stored row and the plaintext value, returned once.
#[derive(Debug)]
pub struct IssuedIat {
    pub token: InitialAccessToken,
    pub value: SecretString,
}

fn invalid_iat() -> CoreError {
    CoreError::InvalidToken("the initial access token is invalid, expired or used up".to_owned())
}

fn missing_iat() -> CoreError {
    CoreError::InvalidToken("an initial access token is required".to_owned())
}

fn invalid_rat() -> CoreError {
    CoreError::InvalidToken("the registration access token is invalid".to_owned())
}

fn meta(message: impl Into<String>) -> CoreError {
    CoreError::InvalidClientMetadata(message.into())
}

/// `ClientService` re-checks the client rules `registration::validate` already applied; should
/// one still fail, it is reported as an RFC 7591 error, never as a generic `invalid_request`.
fn registration_error(e: CoreError) -> CoreError {
    match e {
        CoreError::Validation {
            field: "redirect_uris" | "redirect_uri" | "post_logout_redirect_uris",
            message,
        } => CoreError::InvalidRedirectUri(message),
        CoreError::Validation { field, message } => meta(format!("{field}: {message}")),
        other => other,
    }
}

fn token_hash(token: &str) -> SecretHash {
    SecretHash(secret_hash(token))
}

/// A fresh 256-bit token (base64url) and its storage hash.
fn new_token() -> (SecretString, SecretHash) {
    let token = random_token();
    let hash = token_hash(&token);
    (SecretString::from(token), hash)
}

/// Whether `token` can be used at `now` (unrevoked, unexpired, uses left).
fn usable(token: &InitialAccessToken, now: time::OffsetDateTime) -> bool {
    token.revoked_at.is_none()
        && token.expires_at.is_none_or(|e| e > now)
        && token.uses_remaining.is_none_or(|u| u > 0)
}

/// Dynamic client registration and initial access tokens.
pub struct RegistrationService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub redirect_validator: RedirectValidator,
}

impl RegistrationService {
    fn clients(&self) -> ClientService {
        ClientService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
            redirect_validator: self.redirect_validator,
        }
    }

    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// RFC 7591 registration. Order: policy (`NotFound` when disabled), initial access token
    /// presence and validity under `allow_listed` (`InvalidToken`), metadata
    /// (`InvalidSoftwareStatement` / `InvalidRedirectUri` / `InvalidClientMetadata`), the
    /// `max_clients` cap (`InvalidClientMetadata`), then the atomic token use and the insert.
    pub async fn register(
        &self,
        tenant: &Tenant,
        request: &Value,
        initial_access_token: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<Registration, CoreError> {
        let (settings, mode) = mode_of(tenant)?;
        let iat_hash = match mode {
            DcrMode::Open => None,
            DcrMode::AllowListed => {
                let token = initial_access_token
                    .filter(|t| !t.is_empty())
                    .ok_or_else(missing_iat)?;
                let hash = token_hash(token);
                // Checked (without consuming) before the metadata, so an unauthenticated caller
                // learns nothing more than 401.
                let now = self.clock.now();
                let known = self
                    .storage
                    .registration()
                    .list_iats(tenant.id)
                    .await?
                    .into_iter()
                    .any(|t| t.token_hash == hash && usable(&t, now));
                if !known {
                    return Err(invalid_iat());
                }
                Some(hash)
            }
        };

        let validated = registration::validate(request, &settings, mode)?;

        let count = self
            .storage
            .registration()
            .count_clients_by_source(tenant.id, ClientSource::Dynamic)
            .await?;
        if count >= u64::from(settings.max_clients) {
            return Err(meta(format!(
                "this tenant has reached its limit of {} dynamically registered clients",
                settings.max_clients
            )));
        }

        if let Some(hash) = &iat_hash
            && self
                .storage
                .registration()
                .consume_iat(tenant.id, hash, self.clock.now())
                .await?
                .is_none()
        {
            // Used up, revoked or expired since the check above (a concurrent registration).
            return Err(invalid_iat());
        }

        let ValidatedRegistration {
            client, options, ..
        } = validated;
        let (rat, rat_hash) = new_token();
        let CreatedClient {
            client,
            client_secret,
        } = self
            .clients()
            .create_dynamic(tenant, client, options, rat_hash, ctx)
            .await
            .map_err(registration_error)?;
        Ok(Registration {
            client,
            client_secret,
            registration_access_token: rat,
        })
    }

    /// The dynamic client `client_id` authenticated by its registration access token. A missing
    /// or wrong token, an unknown client and a non-dynamic client are all `InvalidToken` (401).
    async fn authenticate(
        &self,
        tenant: &Tenant,
        client_id: &str,
        registration_access_token: Option<&str>,
    ) -> Result<Client, CoreError> {
        let token = registration_access_token
            .filter(|t| !t.is_empty())
            .ok_or_else(invalid_rat)?;
        self.storage
            .clients()
            .get_by_registration_token(tenant.id, client_id, &token_hash(token))
            .await?
            .filter(|c| c.registration_source == ClientSource::Dynamic)
            .ok_or_else(invalid_rat)
    }

    /// RFC 7592 §2.1 read.
    pub async fn read(
        &self,
        tenant: &Tenant,
        client_id: &str,
        registration_access_token: Option<&str>,
    ) -> Result<Client, CoreError> {
        mode_of(tenant)?;
        self.authenticate(tenant, client_id, registration_access_token)
            .await
    }

    /// RFC 7592 §2.2 update: the request replaces every client metadata value (omitted values
    /// take their defaults). It must carry the matching `client_id`, must not carry the
    /// server-provisioned members, and an included `client_secret` must be the current one. The
    /// metadata goes through `oauth::registration::validate` under the tenant's current policy
    /// (including the redirect-host allow-list); the authentication method and application type
    /// are fixed at registration.
    pub async fn update(
        &self,
        tenant: &Tenant,
        client_id: &str,
        registration_access_token: Option<&str>,
        request: &Value,
        ctx: &RequestContext,
    ) -> Result<Client, CoreError> {
        let (settings, mode) = mode_of(tenant)?;
        let current = self
            .authenticate(tenant, client_id, registration_access_token)
            .await?;
        let obj = request
            .as_object()
            .ok_or_else(|| meta("the update request must be a JSON object"))?;
        match obj.get("client_id") {
            Some(Value::String(id)) if id == client_id => {}
            _ => return Err(meta("client_id must be present and match the client")),
        }
        if let Some(key) = SERVER_MANAGED.iter().find(|k| obj.contains_key(**k)) {
            return Err(meta(format!("{key} must not be included in an update")));
        }
        match obj.get("client_secret") {
            None => {}
            Some(Value::String(secret))
                if current
                    .secret_hash
                    .as_ref()
                    .is_some_and(|h| *h == token_hash(secret)) => {}
            Some(_) => return Err(meta("client_secret does not match the client's secret")),
        }

        let validated = registration::validate(request, &settings, mode)?;
        let c = validated.client;
        if c.auth_method != current.auth_method {
            return Err(meta(
                "token_endpoint_auth_method cannot be changed; register a new client instead",
            ));
        }
        if c.application_type != current.application_type {
            return Err(meta(
                "application_type cannot be changed; register a new client instead",
            ));
        }
        let o = validated.options;
        let patch = ClientPatch {
            name: Some(c.name),
            redirect_uris: Some(c.redirect_uris),
            grant_types: Some(c.grant_types),
            scopes: Some(c.scopes),
            require_pkce: Some(true),
            jwks: Some(c.jwks),
        };
        let options = ClientOptionsPatch {
            consent_mode: Some(ConsentMode::Required),
            post_logout_redirect_uris: Some(o.post_logout_redirect_uris),
            backchannel_logout_uri: Some(o.backchannel_logout_uri),
            backchannel_logout_session_required: Some(o.backchannel_logout_session_required),
            allowed_resources: Some(o.allowed_resources),
            ..ClientOptionsPatch::default()
        };
        self.clients()
            .update_dynamic(tenant, client_id, patch, options, ctx)
            .await
            .map_err(registration_error)
    }

    /// RFC 7592 §2.3 delete: removes the client and revokes its token families.
    pub async fn delete(
        &self,
        tenant: &Tenant,
        client_id: &str,
        registration_access_token: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        mode_of(tenant)?;
        self.authenticate(tenant, client_id, registration_access_token)
            .await?;
        self.clients()
            .delete_dynamic(tenant.id, client_id, ctx)
            .await
    }

    /// Issues an initial access token; the value is returned once. Refused for the system
    /// tenant (it never accepts dynamic registration). Tokens may be issued under any policy, so
    /// an administrator can prepare them before switching to `allow_listed`. Audited as
    /// `initial_access_token_created` (target = token id).
    pub async fn issue_iat(
        &self,
        tenant: &Tenant,
        request: IatRequest,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<IssuedIat, CoreError> {
        if tenant.slug == SYSTEM_TENANT_SLUG {
            return Err(CoreError::Validation {
                field: "tenant",
                message: "the system tenant does not accept dynamic client registration".to_owned(),
            });
        }
        let description = request.description.trim().to_owned();
        if description.chars().count() > MAX_IAT_DESCRIPTION_LEN
            || description.chars().any(char::is_control)
        {
            return Err(CoreError::Validation {
                field: "description",
                message: format!(
                    "at most {MAX_IAT_DESCRIPTION_LEN} characters, no control characters"
                ),
            });
        }
        let ttl = request.expires_in.unwrap_or(IAT_DEFAULT_TTL);
        if !(IAT_MIN_TTL..=IAT_MAX_TTL).contains(&ttl) {
            return Err(CoreError::Validation {
                field: "expires_in",
                message: "must be between one minute and 365 days".to_owned(),
            });
        }
        if request.uses.is_some_and(|u| u == 0 || u > MAX_IAT_USES) {
            return Err(CoreError::Validation {
                field: "uses",
                message: format!("must be between 1 and {MAX_IAT_USES}"),
            });
        }
        let now = self.clock.now();
        let (value, hash) = new_token();
        let token = self
            .storage
            .registration()
            .create_iat(
                tenant.id,
                &NewInitialAccessToken {
                    id: InitialAccessTokenId::new_v7(),
                    description,
                    token_hash: hash,
                    expires_at: Some(now + ttl),
                    uses_remaining: request.uses,
                    created_at: now,
                },
            )
            .await?;
        self.audit()
            .record(
                tenant.id,
                actor,
                AuditAction::InitialAccessTokenCreated,
                Some(token.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::empty(),
            )
            .await?;
        Ok(IssuedIat { token, value })
    }

    /// Every initial access token of the tenant (hashes only, never values), in id order.
    pub async fn list_iats(&self, tenant: TenantId) -> Result<Vec<InitialAccessToken>, CoreError> {
        Ok(self.storage.registration().list_iats(tenant).await?)
    }

    /// Revokes an initial access token. `NotFound` if unknown or already revoked. Audited as
    /// `initial_access_token_revoked` (target = token id).
    pub async fn revoke_iat(
        &self,
        tenant: TenantId,
        id: InitialAccessTokenId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        if !self
            .storage
            .registration()
            .revoke_iat(tenant, id, self.clock.now())
            .await?
        {
            return Err(CoreError::NotFound);
        }
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::InitialAccessTokenRevoked,
                Some(id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::empty(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;
    use time::OffsetDateTime;
    use time::macros::datetime;

    use super::*;
    use crate::model::{
        ApplicationType, AuditEvent, AuditQuery, ClientAuthMethod, ClientType, ClientUpdate,
        NewAuditEvent, NewClient, Page, PageRequest, TenantSettings,
    };
    use crate::oauth::redirect::validate_redirect_uri;
    use crate::ports::{
        AttributeRepo, AuditRepo, BrandingRepo, ClientRepo, ConnectionRepo, FlowRepo, GrantRepo,
        JobRepo, KeyRepo, LogoutRepo, MailSettingsRepo, OrgRepo, OutboxRepo, RegistrationRepo,
        RoleRepo, SessionRepo, SetupRepo, StorageError, TenantRepo, UserRepo, WebhookRepo,
    };

    const T0: OffsetDateTime = datetime!(2026-11-25 12:00 UTC);
    const RP: &str = "https://rp.example/cb";

    /// Clients, initial access tokens and audit rows in memory; nothing else is used.
    #[derive(Default)]
    struct Fake {
        clients: Mutex<Vec<(TenantId, Client)>>,
        iats: Mutex<Vec<InitialAccessToken>>,
        audit: Mutex<Vec<NewAuditEvent>>,
        /// Clients deleted through `ClientRepo::delete` (their families revoked there).
        deleted: Mutex<Vec<String>>,
    }

    fn unsupported<T>() -> Result<T, StorageError> {
        Err(StorageError::Unsupported("registration fake"))
    }

    #[async_trait::async_trait]
    impl ClientRepo for Fake {
        async fn create(&self, tenant: TenantId, c: &NewClient) -> Result<Client, StorageError> {
            let client = Client {
                id: c.id,
                tenant_id: tenant,
                client_id: c.client_id.clone(),
                name: c.name.clone(),
                client_type: c.client_type,
                application_type: c.application_type,
                auth_method: c.auth_method,
                secret_hash: c.secret_hash,
                jwks: c.jwks.clone(),
                redirect_uris: c.redirect_uris.clone(),
                grant_types: c.grant_types.clone(),
                scopes: c.scopes.clone(),
                require_pkce: c.require_pkce,
                token_format: c.token_format,
                consent_mode: c.consent_mode,
                id_token_signed_response_alg: c.id_token_signed_response_alg.clone(),
                can_introspect: c.can_introspect,
                post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
                backchannel_logout_uri: c.backchannel_logout_uri.clone(),
                backchannel_logout_session_required: c.backchannel_logout_session_required,
                allowed_resources: c.allowed_resources.clone(),
                mfa_policy: c.mfa_policy,
                registration_source: c.registration_source,
                metadata_expires_at: c.metadata_expires_at,
                registration_access_token_hash: c.registration_access_token_hash,
                created_at: c.created_at,
                updated_at: c.created_at,
                organization: crate::model::OrgClientPolicy::Off,
                require_pushed_authorization_requests: c.require_pushed_authorization_requests,
                client_kind: c.client_kind,
                headless_native: c.headless_native,
            };
            self.clients.lock().unwrap().push((tenant, client.clone()));
            Ok(client)
        }
        async fn get(&self, tenant: TenantId, id: &str) -> Result<Option<Client>, StorageError> {
            Ok(self
                .clients
                .lock()
                .unwrap()
                .iter()
                .find(|(t, c)| *t == tenant && c.client_id == id)
                .map(|(_, c)| c.clone()))
        }
        async fn list(&self, _: TenantId, _: PageRequest) -> Result<Page<Client>, StorageError> {
            unsupported()
        }
        async fn update(
            &self,
            tenant: TenantId,
            id: &str,
            u: &ClientUpdate,
            now: OffsetDateTime,
        ) -> Result<Option<Client>, StorageError> {
            let mut clients = self.clients.lock().unwrap();
            let Some((_, c)) = clients
                .iter_mut()
                .find(|(t, c)| *t == tenant && c.client_id == id)
            else {
                return Ok(None);
            };
            if let Some(v) = &u.name {
                c.name = v.clone();
            }
            if let Some(v) = &u.redirect_uris {
                c.redirect_uris = v.clone();
            }
            if let Some(v) = &u.grant_types {
                c.grant_types = v.clone();
            }
            if let Some(v) = &u.scopes {
                c.scopes = v.clone();
            }
            if let Some(v) = u.require_pkce {
                c.require_pkce = v;
            }
            if let Some(v) = &u.jwks {
                c.jwks = v.clone();
            }
            if let Some(v) = u.consent_mode {
                c.consent_mode = v;
            }
            if let Some(v) = &u.post_logout_redirect_uris {
                c.post_logout_redirect_uris = v.clone();
            }
            if let Some(v) = &u.backchannel_logout_uri {
                c.backchannel_logout_uri = v.clone();
            }
            if let Some(v) = &u.allowed_resources {
                c.allowed_resources = v.clone();
            }
            c.updated_at = now;
            Ok(Some(c.clone()))
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
        async fn delete(&self, tenant: TenantId, id: &str) -> Result<bool, StorageError> {
            let mut clients = self.clients.lock().unwrap();
            let before = clients.len();
            clients.retain(|(t, c)| !(*t == tenant && c.client_id == id));
            let deleted = clients.len() < before;
            if deleted {
                self.deleted.lock().unwrap().push(id.to_owned());
            }
            Ok(deleted)
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
            tenant: TenantId,
            id: &str,
            hash: &SecretHash,
        ) -> Result<Option<Client>, StorageError> {
            Ok(self.get(tenant, id).await?.filter(|c| {
                c.registration_source == ClientSource::Dynamic
                    && c.registration_access_token_hash.as_ref() == Some(hash)
            }))
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
    impl RegistrationRepo for Fake {
        async fn create_iat(
            &self,
            tenant: TenantId,
            t: &NewInitialAccessToken,
        ) -> Result<InitialAccessToken, StorageError> {
            let token = InitialAccessToken {
                id: t.id,
                tenant_id: tenant,
                description: t.description.clone(),
                token_hash: t.token_hash,
                expires_at: t.expires_at,
                uses_remaining: t.uses_remaining,
                created_at: t.created_at,
                revoked_at: None,
            };
            self.iats.lock().unwrap().push(token.clone());
            Ok(token)
        }
        async fn list_iats(
            &self,
            tenant: TenantId,
        ) -> Result<Vec<InitialAccessToken>, StorageError> {
            Ok(self
                .iats
                .lock()
                .unwrap()
                .iter()
                .filter(|t| t.tenant_id == tenant)
                .cloned()
                .collect())
        }
        async fn revoke_iat(
            &self,
            tenant: TenantId,
            id: InitialAccessTokenId,
            now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut iats = self.iats.lock().unwrap();
            match iats
                .iter_mut()
                .find(|t| t.tenant_id == tenant && t.id == id && t.revoked_at.is_none())
            {
                Some(t) => {
                    t.revoked_at = Some(now);
                    Ok(true)
                }
                None => Ok(false),
            }
        }
        async fn consume_iat(
            &self,
            tenant: TenantId,
            hash: &SecretHash,
            now: OffsetDateTime,
        ) -> Result<Option<InitialAccessToken>, StorageError> {
            let mut iats = self.iats.lock().unwrap();
            let Some(t) = iats
                .iter_mut()
                .find(|t| t.tenant_id == tenant && t.token_hash == *hash && usable(t, now))
            else {
                return Ok(None);
            };
            if let Some(u) = t.uses_remaining.as_mut() {
                *u -= 1;
            }
            Ok(Some(t.clone()))
        }
        async fn count_clients_by_source(
            &self,
            tenant: TenantId,
            source: ClientSource,
        ) -> Result<u64, StorageError> {
            Ok(self
                .clients
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, c)| *t == tenant && c.registration_source == source)
                .count() as u64)
        }
    }

    #[async_trait::async_trait]
    impl AuditRepo for Fake {
        async fn append(&self, _: TenantId, e: &NewAuditEvent) -> Result<(), StorageError> {
            self.audit.lock().unwrap().push(e.clone());
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

    const ONLY: &str = "registration tests use clients, registration and audit only";

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
            unreachable!("{ONLY}")
        }
        fn grants(&self) -> &dyn GrantRepo {
            unreachable!("{ONLY}")
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
            self
        }
        fn organizations(&self) -> &dyn OrgRepo {
            unreachable!("registration service tests do not use organizations")
        }
        fn password_profiles(&self) -> &dyn crate::ports::PasswordProfileRepo {
            unreachable!("not used by this test")
        }
        async fn purge_expired(&self, _: OffsetDateTime) -> Result<u64, StorageError> {
            unsupported()
        }
    }

    struct FixedClock(Mutex<OffsetDateTime>);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    struct Harness {
        fake: Arc<Fake>,
        clock: Arc<FixedClock>,
        svc: RegistrationService,
        tenant: Tenant,
    }

    fn tenant_with(slug: &str, policy: DcrPolicy) -> Tenant {
        let mut settings = TenantSettings::default();
        settings.dcr.policy = policy;
        Tenant {
            id: TenantId::new_v7(),
            slug: slug.into(),
            display_name: slug.into(),
            host: None,
            settings,
            created_at: T0,
        }
    }

    impl Harness {
        fn new(policy: DcrPolicy) -> Self {
            let fake = Arc::new(Fake::default());
            let clock = Arc::new(FixedClock(Mutex::new(T0)));
            let svc = RegistrationService {
                storage: fake.clone(),
                clock: clock.clone(),
                redirect_validator: validate_redirect_uri,
            };
            Self {
                fake,
                clock,
                svc,
                tenant: tenant_with("acme", policy),
            }
        }

        fn advance(&self, d: Duration) {
            *self.clock.0.lock().unwrap() += d;
        }

        fn actions(&self) -> Vec<AuditAction> {
            self.fake
                .audit
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.action)
                .collect()
        }

        async fn iat(&self, uses: Option<u32>) -> IssuedIat {
            self.svc
                .issue_iat(
                    &self.tenant,
                    IatRequest {
                        description: "partner".into(),
                        expires_in: None,
                        uses,
                    },
                    AuditActor::admin("admin-1"),
                    &RequestContext::system(),
                )
                .await
                .unwrap()
        }

        async fn register(
            &self,
            body: &Value,
            iat: Option<&str>,
        ) -> Result<Registration, CoreError> {
            self.svc
                .register(&self.tenant, body, iat, &RequestContext::system())
                .await
        }
    }

    fn web() -> Value {
        json!({"redirect_uris": [RP], "client_name": "Partner app"})
    }

    fn is_invalid_token(r: &Result<impl std::fmt::Debug, CoreError>) -> bool {
        matches!(r, Err(CoreError::InvalidToken(_)))
    }

    #[tokio::test]
    async fn open_policy_registers_a_dynamic_client_with_consent_required() {
        let h = Harness::new(DcrPolicy::Open);
        let reg = h.register(&web(), None).await.unwrap();
        let stored = h.fake.clients.lock().unwrap()[0].1.clone();
        assert_eq!(stored.registration_source, ClientSource::Dynamic);
        assert_eq!(stored.consent_mode, ConsentMode::Required);
        assert!(stored.require_pkce);
        assert_eq!(stored.client_type, ClientType::Confidential);
        assert_eq!(stored.auth_method, ClientAuthMethod::ClientSecretBasic);
        // Default scopes resolved from the tenant defaults (allowed_scopes empty).
        assert_eq!(stored.scopes, DEFAULT_DCR_SCOPES);
        // Secret and registration access token: plaintext returned once, hashes stored.
        let secret = reg.client_secret.as_ref().expect("confidential client");
        assert_eq!(stored.secret_hash, Some(token_hash(secret.expose_secret())));
        let rat = reg.registration_access_token.expose_secret();
        assert!(rat.len() >= 43, "256-bit token");
        assert_eq!(stored.registration_access_token_hash, Some(token_hash(rat)));
        assert_eq!(h.actions(), [AuditAction::ClientRegistered]);
        let event = h.fake.audit.lock().unwrap()[0].clone();
        assert_eq!(event.actor, AuditActor::client(&stored.client_id));
        assert_eq!(event.target.as_deref(), Some(stored.client_id.as_str()));

        let body = reg.response("https://op.test/t/acme");
        assert_eq!(body["client_id"], stored.client_id.as_str());
        assert_eq!(body["client_secret"], secret.expose_secret());
        assert_eq!(body["client_secret_expires_at"], 0);
        assert_eq!(body["client_id_issued_at"], T0.unix_timestamp());
        assert_eq!(body["registration_access_token"], rat);
        assert_eq!(
            body["registration_client_uri"],
            format!("https://op.test/t/acme/register/{}", stored.client_id)
        );
        assert_eq!(body["response_types"], json!(["code"]));
        assert_eq!(body["client_name"], "Partner app");
    }

    #[tokio::test]
    async fn public_client_gets_no_secret() {
        let h = Harness::new(DcrPolicy::Open);
        let body = json!({"redirect_uris": [RP], "token_endpoint_auth_method": "none"});
        let reg = h.register(&body, None).await.unwrap();
        assert!(reg.client_secret.is_none());
        let resp = reg.response("https://op.test");
        assert!(!resp.contains_key("client_secret"));
        assert!(!resp.contains_key("client_secret_expires_at"));
    }

    #[tokio::test]
    async fn informational_uris_are_validated_but_neither_stored_nor_echoed() {
        let h = Harness::new(DcrPolicy::Open);
        let mut body = web();
        body["logo_uri"] = json!("https://rp.example/logo.png");
        body["tos_uri"] = json!("https://rp.example/tos");
        let reg = h.register(&body, None).await.unwrap();
        let resp = reg.response("https://op.test");
        for key in ["logo_uri", "client_uri", "policy_uri", "tos_uri"] {
            assert!(!resp.contains_key(key), "{key} echoed");
        }
        // Read returns the same metadata as the registration response.
        let read = h
            .svc
            .read(
                &h.tenant,
                &reg.client.client_id,
                Some(reg.registration_access_token.expose_secret()),
            )
            .await
            .unwrap();
        assert_eq!(client_metadata(&read), client_metadata(&reg.client));

        body["logo_uri"] = json!("http://rp.example/logo.png");
        assert!(matches!(
            h.register(&body, None).await,
            Err(CoreError::InvalidClientMetadata(_))
        ));
    }

    #[tokio::test]
    async fn configured_allowed_scopes_replace_the_defaults() {
        let mut h = Harness::new(DcrPolicy::Open);
        h.tenant.settings.dcr.allowed_scopes = vec!["openid".into(), "mcp:tools".into()];
        let reg = h.register(&web(), None).await.unwrap();
        assert_eq!(reg.client.scopes, ["openid", "mcp:tools"]);
        let body = json!({"redirect_uris": [RP], "scope": "openid email"});
        assert!(matches!(
            h.register(&body, None).await,
            Err(CoreError::InvalidClientMetadata(_))
        ));
    }

    #[tokio::test]
    async fn dcr_disabled_policy_is_not_found() {
        let h = Harness::new(DcrPolicy::Disabled);
        assert!(matches!(
            h.register(&web(), None).await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            h.svc.read(&h.tenant, "x", Some("y")).await,
            Err(CoreError::NotFound)
        ));
        assert!(h.fake.clients.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dcr_system_tenant_always_not_found() {
        let mut h = Harness::new(DcrPolicy::Open);
        h.tenant = tenant_with(SYSTEM_TENANT_SLUG, DcrPolicy::Open);
        assert!(matches!(
            h.register(&web(), None).await,
            Err(CoreError::NotFound)
        ));
        h.tenant.settings.dcr.policy = DcrPolicy::AllowListed;
        assert!(matches!(
            h.register(&web(), Some("anything")).await,
            Err(CoreError::NotFound)
        ));
        // No initial access tokens for the system tenant either.
        let r = h
            .svc
            .issue_iat(
                &h.tenant,
                IatRequest::default(),
                AuditActor::admin("a"),
                &RequestContext::system(),
            )
            .await;
        assert!(matches!(
            r,
            Err(CoreError::Validation {
                field: "tenant",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn dcr_allow_listed_requires_initial_access_token() {
        let h = Harness::new(DcrPolicy::AllowListed);
        assert!(is_invalid_token(&h.register(&web(), None).await));
        assert!(is_invalid_token(&h.register(&web(), Some("")).await));
        assert!(is_invalid_token(
            &h.register(&web(), Some("not-a-token")).await
        ));
        // A token of another tenant is unknown here.
        let other = tenant_with("other", DcrPolicy::AllowListed);
        let foreign = h
            .svc
            .issue_iat(
                &other,
                IatRequest::default(),
                AuditActor::admin("a"),
                &RequestContext::system(),
            )
            .await
            .unwrap();
        assert!(is_invalid_token(
            &h.register(&web(), Some(foreign.value.expose_secret()))
                .await
        ));
        assert!(h.fake.clients.lock().unwrap().is_empty());
        // A valid token registers.
        let iat = h.iat(None).await;
        h.register(&web(), Some(iat.value.expose_secret()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dcr_initial_access_token_single_use() {
        let h = Harness::new(DcrPolicy::AllowListed);
        let iat = h.iat(Some(1)).await;
        let v = iat.value.expose_secret();
        h.register(&web(), Some(v)).await.unwrap();
        assert!(is_invalid_token(&h.register(&web(), Some(v)).await));
        assert_eq!(h.fake.clients.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejected_metadata_does_not_burn_a_single_use_token() {
        let h = Harness::new(DcrPolicy::AllowListed);
        let iat = h.iat(Some(1)).await;
        let v = iat.value.expose_secret();
        let bad = json!({"redirect_uris": ["http://rp.example/cb"]});
        assert!(matches!(
            h.register(&bad, Some(v)).await,
            Err(CoreError::InvalidRedirectUri(_))
        ));
        h.register(&web(), Some(v)).await.unwrap();
    }

    #[tokio::test]
    async fn dcr_expired_initial_access_token_refused() {
        let h = Harness::new(DcrPolicy::AllowListed);
        let iat = h.iat(None).await;
        h.advance(IAT_DEFAULT_TTL);
        assert!(is_invalid_token(
            &h.register(&web(), Some(iat.value.expose_secret())).await
        ));
    }

    #[tokio::test]
    async fn dcr_revoked_initial_access_token_refused() {
        let h = Harness::new(DcrPolicy::AllowListed);
        let iat = h.iat(None).await;
        h.svc
            .revoke_iat(
                h.tenant.id,
                iat.token.id,
                AuditActor::admin("a"),
                &RequestContext::system(),
            )
            .await
            .unwrap();
        assert!(is_invalid_token(
            &h.register(&web(), Some(iat.value.expose_secret())).await
        ));
        // Revoking twice (or an unknown id) is NotFound.
        assert!(matches!(
            h.svc
                .revoke_iat(
                    h.tenant.id,
                    iat.token.id,
                    AuditActor::admin("a"),
                    &RequestContext::system()
                )
                .await,
            Err(CoreError::NotFound)
        ));
        assert_eq!(
            h.actions(),
            [
                AuditAction::InitialAccessTokenCreated,
                AuditAction::InitialAccessTokenRevoked
            ]
        );
    }

    #[tokio::test]
    async fn dcr_redirect_host_allow_list_enforced() {
        let mut h = Harness::new(DcrPolicy::AllowListed);
        h.tenant.settings.dcr.allowed_redirect_hosts = vec!["partner.example".into()];
        let iat = h.iat(None).await;
        let v = iat.value.expose_secret();
        assert!(matches!(
            h.register(&web(), Some(v)).await,
            Err(CoreError::InvalidRedirectUri(_))
        ));
        let ok = json!({"redirect_uris": ["https://partner.example/cb"]});
        let reg = h.register(&ok, Some(v)).await.unwrap();
        // The allow-list also binds RFC 7592 updates.
        let update = json!({"client_id": reg.client.client_id, "redirect_uris": [RP]});
        assert!(matches!(
            h.svc
                .update(
                    &h.tenant,
                    &reg.client.client_id,
                    Some(reg.registration_access_token.expose_secret()),
                    &update,
                    &RequestContext::system()
                )
                .await,
            Err(CoreError::InvalidRedirectUri(_))
        ));
    }

    #[tokio::test]
    async fn dcr_max_clients_enforced() {
        let mut h = Harness::new(DcrPolicy::Open);
        h.tenant.settings.dcr.max_clients = 2;
        h.register(&web(), None).await.unwrap();
        h.register(&web(), None).await.unwrap();
        match h.register(&web(), None).await {
            Err(CoreError::InvalidClientMetadata(m)) => assert!(m.contains("limit of 2"), "{m}"),
            other => panic!("expected invalid_client_metadata, got {other:?}"),
        }
        assert_eq!(h.fake.clients.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn max_clients_refusal_does_not_burn_the_token() {
        let mut h = Harness::new(DcrPolicy::AllowListed);
        h.tenant.settings.dcr.max_clients = 0;
        let iat = h.iat(Some(1)).await;
        assert!(matches!(
            h.register(&web(), Some(iat.value.expose_secret())).await,
            Err(CoreError::InvalidClientMetadata(_))
        ));
        assert_eq!(h.fake.iats.lock().unwrap()[0].uses_remaining, Some(1));
    }

    #[tokio::test]
    async fn dcr_software_statement_and_admin_scope_rejected() {
        let h = Harness::new(DcrPolicy::Open);
        let mut body = web();
        body["software_statement"] = json!("eyJ...");
        assert!(matches!(
            h.register(&body, None).await,
            Err(CoreError::InvalidSoftwareStatement)
        ));
        let mut h = Harness::new(DcrPolicy::Open);
        // Even a misconfigured allow-list never makes an admin scope registrable.
        h.tenant.settings.dcr.allowed_scopes = vec!["openid".into(), "admin:write".into()];
        let body = json!({"redirect_uris": [RP], "scope": "openid admin:write"});
        assert!(matches!(
            h.register(&body, None).await,
            Err(CoreError::InvalidClientMetadata(_))
        ));
        let reg = h.register(&web(), None).await.unwrap();
        assert_eq!(reg.client.scopes, ["openid"]);
    }

    async fn registered(h: &Harness) -> (Client, String) {
        let reg = h.register(&web(), None).await.unwrap();
        (
            reg.client,
            reg.registration_access_token.expose_secret().to_owned(),
        )
    }

    #[tokio::test]
    async fn dcr_registration_access_token_required() {
        let h = Harness::new(DcrPolicy::Open);
        let (client, _) = registered(&h).await;
        let id = &client.client_id;
        let ctx = RequestContext::system();
        assert!(is_invalid_token(&h.svc.read(&h.tenant, id, None).await));
        assert!(is_invalid_token(&h.svc.read(&h.tenant, id, Some("")).await));
        assert!(is_invalid_token(
            &h.svc
                .update(
                    &h.tenant,
                    id,
                    None,
                    &json!({"client_id": id, "redirect_uris": [RP]}),
                    &ctx
                )
                .await
        ));
        assert!(is_invalid_token(
            &h.svc.delete(&h.tenant, id, None, &ctx).await
        ));
        assert_eq!(h.fake.clients.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dcr_wrong_registration_access_token_refused() {
        let h = Harness::new(DcrPolicy::Open);
        let (a, _) = registered(&h).await;
        let (_, rat_b) = registered(&h).await;
        let ctx = RequestContext::system();
        // Another client's token, a random token and an unknown client: all InvalidToken.
        assert!(is_invalid_token(
            &h.svc.read(&h.tenant, &a.client_id, Some(&rat_b)).await
        ));
        assert!(is_invalid_token(
            &h.svc
                .read(&h.tenant, &a.client_id, Some(&random_token()))
                .await
        ));
        assert!(is_invalid_token(
            &h.svc.read(&h.tenant, "unknown", Some(&rat_b)).await
        ));
        assert!(is_invalid_token(
            &h.svc
                .delete(&h.tenant, &a.client_id, Some(&rat_b), &ctx)
                .await
        ));
        // The same token in another tenant does not authenticate.
        let mut other = h.tenant.clone();
        other.id = TenantId::new_v7();
        assert!(is_invalid_token(
            &h.svc.read(&other, &a.client_id, Some(&rat_b)).await
        ));
    }

    #[tokio::test]
    async fn static_client_is_never_managed_through_rfc_7592() {
        let h = Harness::new(DcrPolicy::Open);
        let (client, rat) = registered(&h).await;
        // Turn it into a static client with the same token hash: not manageable.
        h.fake.clients.lock().unwrap()[0].1.registration_source = ClientSource::Static;
        assert!(is_invalid_token(
            &h.svc.read(&h.tenant, &client.client_id, Some(&rat)).await
        ));
    }

    #[tokio::test]
    async fn update_replaces_metadata() {
        let h = Harness::new(DcrPolicy::Open);
        let (client, rat) = registered(&h).await;
        let id = client.client_id.clone();
        let update = json!({
            "client_id": id,
            "redirect_uris": ["https://rp.example/new"],
            "client_name": "Renamed",
            "scope": "openid email",
        });
        let updated = h
            .svc
            .update(
                &h.tenant,
                &id,
                Some(&rat),
                &update,
                &RequestContext::system(),
            )
            .await
            .unwrap();
        assert_eq!(updated.redirect_uris, ["https://rp.example/new"]);
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.scopes, ["openid", "email"]);
        assert_eq!(updated.consent_mode, ConsentMode::Required);
        assert_eq!(
            h.actions(),
            [
                AuditAction::ClientRegistered,
                AuditAction::ClientRegistrationUpdated
            ]
        );
        // The token keeps working after an update.
        h.svc.read(&h.tenant, &id, Some(&rat)).await.unwrap();
    }

    #[tokio::test]
    async fn update_constraints_rejected() {
        let h = Harness::new(DcrPolicy::Open);
        let reg = h.register(&web(), None).await.unwrap();
        let id = reg.client.client_id.clone();
        let rat = reg.registration_access_token.expose_secret();
        let secret = reg.client_secret.as_ref().unwrap().expose_secret();
        let ctx = RequestContext::system();
        let base = json!({"client_id": id, "redirect_uris": [RP]});
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            b
        };
        let cases = [
            json!({"redirect_uris": [RP]}),
            with("client_id", json!("someone-else")),
            with("client_id", json!(1)),
            with("registration_access_token", json!(rat)),
            with(
                "registration_client_uri",
                json!("https://op.test/register/x"),
            ),
            with("client_id_issued_at", json!(1)),
            with("client_secret_expires_at", json!(0)),
            with("client_secret", json!("wrong")),
            with("client_secret", json!(5)),
            with("token_endpoint_auth_method", json!("none")),
            with("application_type", json!("native")),
            json!(["not", "an", "object"]),
        ];
        for case in cases {
            let r = h.svc.update(&h.tenant, &id, Some(rat), &case, &ctx).await;
            assert!(
                matches!(
                    r,
                    Err(CoreError::InvalidClientMetadata(_) | CoreError::InvalidRedirectUri(_))
                ),
                "{case}: {r:?}"
            );
        }
        // The matching secret is accepted.
        h.svc
            .update(
                &h.tenant,
                &id,
                Some(rat),
                &with("client_secret", json!(secret)),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            h.actions(),
            [
                AuditAction::ClientRegistered,
                AuditAction::ClientRegistrationUpdated
            ]
        );
    }

    #[tokio::test]
    async fn delete_removes_the_client_and_revokes_families() {
        let h = Harness::new(DcrPolicy::Open);
        let (client, rat) = registered(&h).await;
        h.svc
            .delete(
                &h.tenant,
                &client.client_id,
                Some(&rat),
                &RequestContext::system(),
            )
            .await
            .unwrap();
        // ClientRepo::delete is the path that revokes the token families.
        assert_eq!(
            *h.fake.deleted.lock().unwrap(),
            std::slice::from_ref(&client.client_id)
        );
        assert!(is_invalid_token(
            &h.svc.read(&h.tenant, &client.client_id, Some(&rat)).await
        ));
        assert_eq!(
            h.actions(),
            [
                AuditAction::ClientRegistered,
                AuditAction::ClientRegistrationDeleted
            ]
        );
    }

    #[tokio::test]
    async fn iat_lifecycle_hashes_and_validates() {
        let h = Harness::new(DcrPolicy::Disabled);
        let issued = h.iat(Some(3)).await;
        assert_eq!(
            issued.token.token_hash,
            token_hash(issued.value.expose_secret())
        );
        assert_eq!(issued.token.expires_at, Some(T0 + IAT_DEFAULT_TTL));
        assert_eq!(issued.token.uses_remaining, Some(3));
        let listed = h.svc.list_iats(h.tenant.id).await.unwrap();
        assert_eq!(listed, std::slice::from_ref(&issued.token));
        let event = h.fake.audit.lock().unwrap()[0].clone();
        assert_eq!(event.action, AuditAction::InitialAccessTokenCreated);
        assert_eq!(event.target, Some(issued.token.id.to_string()));
        assert_eq!(event.actor, AuditActor::admin("admin-1"));
        assert!(!format!("{:?}", event.details).contains(issued.value.expose_secret()));

        let bad = [
            IatRequest {
                expires_in: Some(Duration::seconds(30)),
                ..IatRequest::default()
            },
            IatRequest {
                expires_in: Some(IAT_MAX_TTL + Duration::seconds(1)),
                ..IatRequest::default()
            },
            IatRequest {
                uses: Some(0),
                ..IatRequest::default()
            },
            IatRequest {
                uses: Some(MAX_IAT_USES + 1),
                ..IatRequest::default()
            },
            IatRequest {
                description: "x".repeat(MAX_IAT_DESCRIPTION_LEN + 1),
                ..IatRequest::default()
            },
            IatRequest {
                description: "a\nb".into(),
                ..IatRequest::default()
            },
        ];
        for req in bad {
            let r = h
                .svc
                .issue_iat(
                    &h.tenant,
                    req.clone(),
                    AuditActor::admin("a"),
                    &RequestContext::system(),
                )
                .await;
            assert!(matches!(r, Err(CoreError::Validation { .. })), "{req:?}");
        }
        assert_eq!(h.fake.iats.lock().unwrap().len(), 1);
    }

    #[test]
    fn effective_settings_resolves_default_scopes() {
        let t = tenant_with("acme", DcrPolicy::Open);
        assert_eq!(effective_settings(&t).allowed_scopes, DEFAULT_DCR_SCOPES);
        let s = tenant_with(SYSTEM_TENANT_SLUG, DcrPolicy::Open);
        assert_eq!(effective_settings(&s).policy, DcrPolicy::Disabled);
        let mut t = t;
        t.settings.dcr.allowed_scopes = vec!["openid".into()];
        assert_eq!(effective_settings(&t).allowed_scopes, ["openid"]);
    }

    #[test]
    fn client_metadata_matches_the_validator_metadata() {
        let v = registration::validate(
            &json!({"redirect_uris": [RP], "client_name": "X", "post_logout_redirect_uris": [RP]}),
            &effective_settings(&tenant_with("acme", DcrPolicy::Open)),
            DcrMode::Open,
        )
        .unwrap();
        let c = v.client.clone();
        let client = Client {
            id: crate::model::ClientId::new_v7(),
            tenant_id: TenantId::new_v7(),
            client_id: "c".into(),
            name: c.name.clone(),
            client_type: c.client_type,
            application_type: ApplicationType::Web,
            auth_method: c.auth_method,
            secret_hash: None,
            jwks: None,
            redirect_uris: c.redirect_uris.clone(),
            grant_types: c.grant_types.clone(),
            scopes: c.scopes.clone(),
            require_pkce: true,
            token_format: v.options.token_format,
            consent_mode: ConsentMode::Required,
            id_token_signed_response_alg: None,
            can_introspect: false,
            post_logout_redirect_uris: v.options.post_logout_redirect_uris.clone(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources: vec![],
            mfa_policy: None,
            registration_source: ClientSource::Dynamic,
            metadata_expires_at: None,
            registration_access_token_hash: None,
            created_at: T0,
            updated_at: T0,
            organization: crate::model::OrgClientPolicy::Off,
            require_pushed_authorization_requests: false,
            client_kind: crate::model::ClientKind::Application,
            headless_native: false,
        };
        assert_eq!(client_metadata(&client), v.metadata());
    }
}
