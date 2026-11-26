//! Client registration and management.
//!
//! [`validate_client`] holds every registration rule: redirect URIs (through the injected
//! [`RedirectValidator`]), the PKCE rule (only confidential clients may opt out), auth-method and
//! grant consistency, and the inline-JWKS rules for `private_key_jwt`.
//! [`validate_client_options`] checks the 0.2 client options (token format, consent mode, ID-token
//! signing algorithm, tenant-wide introspection) against the client and its tenant, and
//! [`validate_client_phase4`] the 0.3 options: post-logout redirect URIs (the redirect URI rules),
//! the back-channel logout URI (absolute, no fragment, https or loopback http), allowed
//! resource indicators (RFC 8707 rules of `oauth::resource::parse_resources`) and the client
//! MFA policy.
//!
//! Every mutating [`ClientService`] method takes the acting administrator and the request context
//! and records exactly one audit event after the change commits (`client_created`,
//! `client_updated`, `client_deleted`, `client_secret_rotated`). Failed calls record nothing.
//! Audit details never carry a secret: updates list the changed field names only.

use std::sync::Arc;

use anvil_jose::Jwks;
use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::SecretString;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    ApplicationType, AuditAction, AuditActor, AuditDetails, AuditOutcome, Client, ClientAuthMethod,
    ClientId, ClientType, ClientUpdate, ConsentMode, GrantType, MfaPolicy, NewClient, Page,
    PageRequest, RequestContext, Scope, SecretHash, Tenant, TenantId, TenantSettings, TokenFormat,
};
use crate::oauth::resource::parse_resources;
use crate::ports::{Storage, StorageError};
use crate::service::audit::AuditService;
use crate::service::tenant::{MAX_DISPLAY_NAME_LEN, admin_page};

/// Validates one redirect URI for an application type. Wired to
/// `oauth::redirect::validate_redirect_uri` by the binary; tests inject their own.
pub type RedirectValidator = fn(&str, ApplicationType) -> Result<(), CoreError>;

/// Length of generated `client_id`s (base64url characters, 132 bits).
pub const CLIENT_ID_LEN: usize = 22;

/// Maximum number of redirect URIs per client.
pub const MAX_REDIRECT_URIS: usize = 50;

/// A client registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInput {
    pub name: String,
    pub client_type: ClientType,
    pub application_type: ApplicationType,
    pub auth_method: ClientAuthMethod,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub scopes: Vec<String>,
    /// Defaults to `true`. Only confidential clients may set `false`.
    pub require_pkce: Option<bool>,
    /// Inline JWKS JSON (public keys only), required for `private_key_jwt`.
    pub jwks: Option<String>,
    /// Not supported in this release; any value is rejected.
    pub jwks_uri: Option<String>,
}

/// Partial update of a registered client. Type, application type and auth method are fixed at
/// creation (they decide whether a secret exists). `jwks: Some(None)` clears the JWKS.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientPatch {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<GrantType>>,
    pub scopes: Option<Vec<String>>,
    pub require_pkce: Option<bool>,
    pub jwks: Option<Option<String>>,
}

/// The 0.2 client options. Kept apart from [`ClientInput`] so registrations written before 0.2
/// keep their shape; `Default` is the secure default (JWT access tokens, consent required, RS256
/// ID tokens, no tenant-wide introspection).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientOptions {
    pub token_format: TokenFormat,
    pub consent_mode: ConsentMode,
    /// ID-token signing algorithm; `None` = RS256. Must be enabled for the tenant.
    pub id_token_signed_response_alg: Option<String>,
    /// May introspect any token of the tenant. Confidential clients only.
    pub can_introspect: bool,
    /// Where RP-initiated logout may redirect (OIDC RP-Initiated Logout); redirect URI rules.
    pub post_logout_redirect_uris: Vec<String>,
    /// OIDC Back-Channel Logout endpoint of the client.
    pub backchannel_logout_uri: Option<String>,
    /// The logout token must carry `sid`.
    pub backchannel_logout_session_required: bool,
    /// Resource indicators (RFC 8707) the client may request; empty = none.
    pub allowed_resources: Vec<String>,
    /// Client MFA policy; `None` = the tenant's. The strictest of tenant and client wins.
    pub mfa_policy: Option<MfaPolicy>,
}

/// Partial update of [`ClientOptions`]. `id_token_signed_response_alg: Some(None)` resets the
/// algorithm to RS256.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientOptionsPatch {
    pub token_format: Option<TokenFormat>,
    pub consent_mode: Option<ConsentMode>,
    pub id_token_signed_response_alg: Option<Option<String>>,
    pub can_introspect: Option<bool>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// `Some(None)` removes the back-channel logout URI.
    pub backchannel_logout_uri: Option<Option<String>>,
    pub backchannel_logout_session_required: Option<bool>,
    pub allowed_resources: Option<Vec<String>>,
    /// `Some(None)` falls back to the tenant policy.
    pub mfa_policy: Option<Option<MfaPolicy>>,
}

/// A created client. `client_secret` is the plaintext secret, returned exactly once and only for
/// secret-based auth methods; only its hash is stored.
#[derive(Debug)]
pub struct CreatedClient {
    pub client: Client,
    pub client_secret: Option<SecretString>,
}

fn invalid(field: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        field,
        message: message.into(),
    }
}

/// Whether the auth method authenticates with a shared secret.
pub fn uses_secret(method: ClientAuthMethod) -> bool {
    matches!(
        method,
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost
    )
}

/// A fresh client secret (256-bit random, base64url) and its storage hash.
pub fn new_client_secret() -> (SecretString, SecretHash) {
    let secret = random_token();
    let hash = SecretHash(secret_hash(&secret));
    (SecretString::from(secret), hash)
}

/// Checks every registration rule. Errors are `Validation` with the offending field.
pub fn validate_client(
    input: &ClientInput,
    redirect_validator: RedirectValidator,
) -> Result<(), CoreError> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(invalid("name", "is required"));
    }
    if name.chars().count() > MAX_DISPLAY_NAME_LEN || name.chars().any(char::is_control) {
        return Err(invalid(
            "name",
            "must be at most 200 characters without control characters",
        ));
    }

    if input.jwks_uri.is_some() {
        return Err(invalid("jwks_uri", "not supported in this release"));
    }

    // Grants.
    if input.grant_types.is_empty() {
        return Err(invalid(
            "grant_types",
            "at least one grant type is required",
        ));
    }
    let has = |g: GrantType| input.grant_types.contains(&g);
    if has(GrantType::RefreshToken) && !has(GrantType::AuthorizationCode) {
        return Err(invalid(
            "grant_types",
            "refresh_token requires authorization_code",
        ));
    }

    // Client type and auth method consistency.
    match input.client_type {
        ClientType::Public => {
            if input.auth_method != ClientAuthMethod::None {
                return Err(invalid(
                    "auth_method",
                    "public clients must use token endpoint auth method none",
                ));
            }
            if input.require_pkce == Some(false) {
                return Err(invalid(
                    "require_pkce",
                    "public clients must use PKCE; only confidential clients may disable it",
                ));
            }
            if has(GrantType::ClientCredentials) {
                return Err(invalid(
                    "grant_types",
                    "public clients may not use client_credentials",
                ));
            }
        }
        ClientType::Confidential => {
            if input.auth_method == ClientAuthMethod::None {
                return Err(invalid(
                    "auth_method",
                    "confidential clients must authenticate at the token endpoint",
                ));
            }
        }
    }

    // JWKS.
    match (&input.jwks, input.auth_method) {
        (None, ClientAuthMethod::PrivateKeyJwt) => {
            return Err(invalid("jwks", "private_key_jwt requires an inline jwks"));
        }
        (Some(jwks), ClientAuthMethod::PrivateKeyJwt) => {
            let parsed = Jwks::parse(jwks).map_err(|_| {
                invalid(
                    "jwks",
                    "must be a JWK Set of public keys (private members are not allowed)",
                )
            })?;
            if parsed.keys.is_empty() {
                return Err(invalid("jwks", "must contain at least one key"));
            }
        }
        (Some(_), _) => {
            return Err(invalid("jwks", "only allowed with private_key_jwt"));
        }
        (None, _) => {}
    }

    // Redirect URIs.
    if has(GrantType::AuthorizationCode) && input.redirect_uris.is_empty() {
        return Err(invalid(
            "redirect_uris",
            "authorization_code requires at least one redirect URI",
        ));
    }
    if input.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid("redirect_uris", "too many redirect URIs"));
    }
    for uri in &input.redirect_uris {
        redirect_validator(uri, input.application_type).map_err(|e| {
            let message = match e {
                CoreError::Validation { message, .. } => message,
                other => other.to_string(),
            };
            invalid("redirect_uris", message)
        })?;
    }

    // Scopes: each entry is a single scope token.
    for s in &input.scopes {
        if s.contains(' ') || Scope::parse(s).is_err() {
            return Err(invalid("scopes", format!("invalid scope token {s:?}")));
        }
    }
    Ok(())
}

/// Checks the 0.2 options of a registration against its tenant: the ID-token algorithm must be
/// one the tenant has enabled ([`TenantSettings::effective_signing_algs`]), and only confidential
/// clients may introspect tenant-wide. Token format and consent mode are enums, so any value is
/// valid here (unknown strings are rejected when the wire value is parsed).
pub fn validate_client_options(
    input: &ClientInput,
    options: &ClientOptions,
    settings: &TenantSettings,
) -> Result<(), CoreError> {
    if let Some(alg) = &options.id_token_signed_response_alg
        && !settings.effective_signing_algs().contains(alg)
    {
        return Err(invalid(
            "id_token_signed_response_alg",
            format!("{alg:?} is not enabled for this tenant"),
        ));
    }
    if options.can_introspect && input.client_type != ClientType::Confidential {
        return Err(invalid(
            "can_introspect",
            "only confidential clients may introspect tokens",
        ));
    }
    Ok(())
}

/// Maximum number of allowed resource indicators per client.
pub const MAX_ALLOWED_RESOURCES: usize = 50;

/// Checks the 0.3 client options: post-logout redirect URIs follow the redirect URI rules of the
/// client's application type; the back-channel logout URI is absolute without fragment (https,
/// or http to a loopback host, i.e. the web redirect URI rules); allowed resources follow RFC 8707
/// (absolute, no fragment, no query). Errors are `Validation` on the offending field.
pub fn validate_client_phase4(
    input: &ClientInput,
    options: &ClientOptions,
    redirect_validator: RedirectValidator,
) -> Result<(), CoreError> {
    let message_of = |e: CoreError| match e {
        CoreError::Validation { message, .. } => message,
        other => other.to_string(),
    };
    if options.post_logout_redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid(
            "post_logout_redirect_uris",
            "too many post-logout redirect URIs",
        ));
    }
    for uri in &options.post_logout_redirect_uris {
        redirect_validator(uri, input.application_type)
            .map_err(|e| invalid("post_logout_redirect_uris", message_of(e)))?;
    }
    if let Some(uri) = &options.backchannel_logout_uri {
        redirect_validator(uri, ApplicationType::Web).map_err(|e| {
            invalid(
                "backchannel_logout_uri",
                message_of(e).replace("redirect URI", "back-channel logout URI"),
            )
        })?;
    }
    if options.allowed_resources.len() > MAX_ALLOWED_RESOURCES {
        return Err(invalid("allowed_resources", "too many resource indicators"));
    }
    parse_resources(&options.allowed_resources).map_err(|e| {
        let message = match e {
            CoreError::InvalidTarget(m) => m,
            other => other.to_string(),
        };
        invalid("allowed_resources", message)
    })?;
    Ok(())
}

fn options_of(client: &Client) -> ClientOptions {
    ClientOptions {
        token_format: client.token_format,
        consent_mode: client.consent_mode,
        id_token_signed_response_alg: client.id_token_signed_response_alg.clone(),
        can_introspect: client.can_introspect,
        post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: client.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: client.backchannel_logout_session_required,
        allowed_resources: client.allowed_resources.clone(),
        mfa_policy: client.mfa_policy,
    }
}

/// Names of the fields a client update changes (for the audit event; never values).
fn changed_fields(patch: &ClientPatch, options: &ClientOptionsPatch) -> Vec<&'static str> {
    let mut f = Vec::new();
    let mut push = |set: bool, name: &'static str| {
        if set {
            f.push(name);
        }
    };
    push(patch.name.is_some(), "name");
    push(patch.redirect_uris.is_some(), "redirect_uris");
    push(patch.grant_types.is_some(), "grant_types");
    push(patch.scopes.is_some(), "scopes");
    push(patch.require_pkce.is_some(), "require_pkce");
    push(patch.jwks.is_some(), "jwks");
    push(options.token_format.is_some(), "token_format");
    push(options.consent_mode.is_some(), "consent_mode");
    push(
        options.id_token_signed_response_alg.is_some(),
        "id_token_signed_response_alg",
    );
    push(options.can_introspect.is_some(), "can_introspect");
    push(
        options.post_logout_redirect_uris.is_some(),
        "post_logout_redirect_uris",
    );
    push(
        options.backchannel_logout_uri.is_some(),
        "backchannel_logout_uri",
    );
    push(
        options.backchannel_logout_session_required.is_some(),
        "backchannel_logout_session_required",
    );
    push(options.allowed_resources.is_some(), "allowed_resources");
    push(options.mfa_policy.is_some(), "mfa_policy");
    f
}

fn normalized_grants(grants: &[GrantType]) -> Vec<GrantType> {
    let mut g = grants.to_vec();
    g.sort();
    g.dedup();
    g
}

fn normalized_list(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}

/// A freshly generated `client_id`.
pub fn new_client_id() -> String {
    random_token()[..CLIENT_ID_LEN].to_owned()
}

/// Client management.
pub struct ClientService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub redirect_validator: RedirectValidator,
}

impl ClientService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    async fn record(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        action: AuditAction,
        client_id: &str,
        ctx: &RequestContext,
        details: AuditDetails,
    ) -> Result<(), CoreError> {
        self.audit()
            .record(
                tenant,
                actor,
                action,
                Some(client_id.to_owned()),
                AuditOutcome::Success,
                ctx,
                details,
            )
            .await
    }

    /// Validates and registers a client in `tenant`. Secret-based clients get a new secret,
    /// returned once. Audited as `client_created` (target = client_id).
    pub async fn create(
        &self,
        tenant: &Tenant,
        input: ClientInput,
        options: ClientOptions,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<CreatedClient, CoreError> {
        self.insert(tenant, input, options, None, Some(actor), ctx)
            .await
    }

    /// Registers a dynamic client (RFC 7591) with the same rules as [`Self::create`]: the row has
    /// `registration_source = Dynamic` and the registration access token hash. Audited as
    /// `client_registered`, with the new client as the actor.
    pub async fn create_dynamic(
        &self,
        tenant: &Tenant,
        input: ClientInput,
        options: ClientOptions,
        registration_access_token_hash: SecretHash,
        ctx: &RequestContext,
    ) -> Result<CreatedClient, CoreError> {
        self.insert(
            tenant,
            input,
            options,
            Some(registration_access_token_hash),
            None,
            ctx,
        )
        .await
    }

    /// The one client insertion path. `dynamic = Some(hash)` stores a dynamic client with its
    /// registration access token hash; `actor = None` audits the new client as the actor.
    async fn insert(
        &self,
        tenant: &Tenant,
        input: ClientInput,
        options: ClientOptions,
        dynamic: Option<SecretHash>,
        actor: Option<AuditActor>,
        ctx: &RequestContext,
    ) -> Result<CreatedClient, CoreError> {
        validate_client(&input, self.redirect_validator)?;
        validate_client_options(&input, &options, &tenant.settings)?;
        validate_client_phase4(&input, &options, self.redirect_validator)?;
        let allowed_resources = parse_resources(&options.allowed_resources)?;
        let (secret, hash) = if uses_secret(input.auth_method) {
            let (s, h) = new_client_secret();
            (Some(s), Some(h))
        } else {
            (None, None)
        };
        let now = self.clock.now();
        let mut new = NewClient {
            id: ClientId::new_v7(),
            client_id: new_client_id(),
            name: input.name.trim().to_owned(),
            client_type: input.client_type,
            application_type: input.application_type,
            auth_method: input.auth_method,
            secret_hash: hash,
            jwks: input.jwks,
            redirect_uris: normalized_list(&input.redirect_uris),
            grant_types: normalized_grants(&input.grant_types),
            scopes: normalized_list(&input.scopes),
            require_pkce: input.require_pkce.unwrap_or(true),
            created_at: now,
            token_format: options.token_format,
            consent_mode: options.consent_mode,
            id_token_signed_response_alg: options.id_token_signed_response_alg,
            can_introspect: options.can_introspect,
            post_logout_redirect_uris: normalized_list(&options.post_logout_redirect_uris),
            backchannel_logout_uri: options.backchannel_logout_uri,
            backchannel_logout_session_required: options.backchannel_logout_session_required,
            allowed_resources,
            mfa_policy: options.mfa_policy,
            metadata_expires_at: None,
            registration_source: if dynamic.is_some() {
                crate::model::ClientSource::Dynamic
            } else {
                crate::model::ClientSource::Static
            },
            registration_access_token_hash: dynamic,
        };
        let action = if new.registration_access_token_hash.is_some() {
            AuditAction::ClientRegistered
        } else {
            AuditAction::ClientCreated
        };
        // A client_id collision is astronomically unlikely; retry once with a fresh id.
        let client = match self.storage.clients().create(tenant.id, &new).await {
            Err(StorageError::Conflict(_)) => {
                new.id = ClientId::new_v7();
                new.client_id = new_client_id();
                self.storage
                    .clients()
                    .create(tenant.id, &new)
                    .await
                    .map_err(|e| match e {
                        StorageError::Conflict(_) => {
                            CoreError::Conflict("client_id already in use".to_owned())
                        }
                        other => other.into(),
                    })?
            }
            other => other?,
        };
        let actor = actor.unwrap_or_else(|| AuditActor::client(&client.client_id));
        self.record(
            tenant.id,
            actor,
            action,
            &client.client_id,
            ctx,
            AuditDetails::empty(),
        )
        .await?;
        Ok(CreatedClient {
            client,
            client_secret: secret,
        })
    }

    pub async fn get(&self, tenant: TenantId, client_id: &str) -> Result<Client, CoreError> {
        self.storage
            .clients()
            .get(tenant, client_id)
            .await?
            .ok_or(CoreError::NotFound)
    }

    pub async fn list(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<Client>, CoreError> {
        Ok(self
            .storage
            .clients()
            .list(tenant, admin_page(page))
            .await?)
    }

    /// Applies a patch. The merged registration and options are re-validated with the same rules
    /// as create (so an ID-token algorithm the tenant no longer enables must be changed with the
    /// next update). Audited as `client_updated` with the changed field names.
    pub async fn update(
        &self,
        tenant: &Tenant,
        client_id: &str,
        patch: ClientPatch,
        options: ClientOptionsPatch,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Client, CoreError> {
        self.apply_update(
            tenant,
            client_id,
            patch,
            options,
            AuditAction::ClientUpdated,
            actor,
            ctx,
        )
        .await
    }

    /// RFC 7592 update of a dynamic client: [`Self::update`]'s rules, audited as
    /// `client_registration_updated` with the client as the actor. The caller has authenticated
    /// the registration access token.
    pub async fn update_dynamic(
        &self,
        tenant: &Tenant,
        client_id: &str,
        patch: ClientPatch,
        options: ClientOptionsPatch,
        ctx: &RequestContext,
    ) -> Result<Client, CoreError> {
        self.apply_update(
            tenant,
            client_id,
            patch,
            options,
            AuditAction::ClientRegistrationUpdated,
            AuditActor::client(client_id),
            ctx,
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the shared body of update and update_dynamic"
    )]
    async fn apply_update(
        &self,
        tenant: &Tenant,
        client_id: &str,
        patch: ClientPatch,
        options: ClientOptionsPatch,
        action: AuditAction,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Client, CoreError> {
        let current = self.get(tenant.id, client_id).await?;
        let merged = ClientInput {
            name: patch.name.clone().unwrap_or_else(|| current.name.clone()),
            client_type: current.client_type,
            application_type: current.application_type,
            auth_method: current.auth_method,
            redirect_uris: patch
                .redirect_uris
                .clone()
                .unwrap_or_else(|| current.redirect_uris.clone()),
            grant_types: patch
                .grant_types
                .clone()
                .unwrap_or_else(|| current.grant_types.clone()),
            scopes: patch
                .scopes
                .clone()
                .unwrap_or_else(|| current.scopes.clone()),
            require_pkce: Some(patch.require_pkce.unwrap_or(current.require_pkce)),
            jwks: match &patch.jwks {
                None => current.jwks.clone(),
                Some(j) => j.clone(),
            },
            jwks_uri: None,
        };
        validate_client(&merged, self.redirect_validator)?;
        let mut merged_options = options_of(&current);
        if let Some(f) = options.token_format {
            merged_options.token_format = f;
        }
        if let Some(m) = options.consent_mode {
            merged_options.consent_mode = m;
        }
        if let Some(a) = &options.id_token_signed_response_alg {
            merged_options.id_token_signed_response_alg = a.clone();
        }
        if let Some(i) = options.can_introspect {
            merged_options.can_introspect = i;
        }
        if let Some(u) = &options.post_logout_redirect_uris {
            merged_options.post_logout_redirect_uris = u.clone();
        }
        if let Some(u) = &options.backchannel_logout_uri {
            merged_options.backchannel_logout_uri = u.clone();
        }
        if let Some(r) = options.backchannel_logout_session_required {
            merged_options.backchannel_logout_session_required = r;
        }
        if let Some(r) = &options.allowed_resources {
            merged_options.allowed_resources = r.clone();
        }
        if let Some(m) = options.mfa_policy {
            merged_options.mfa_policy = m;
        }
        validate_client_options(&merged, &merged_options, &tenant.settings)?;
        validate_client_phase4(&merged, &merged_options, self.redirect_validator)?;
        let fields = changed_fields(&patch, &options);
        let update = ClientUpdate {
            name: patch.name.map(|n| n.trim().to_owned()),
            redirect_uris: patch.redirect_uris.as_deref().map(normalized_list),
            grant_types: patch.grant_types.as_deref().map(normalized_grants),
            scopes: patch.scopes.as_deref().map(normalized_list),
            require_pkce: patch.require_pkce,
            jwks: patch.jwks,
            token_format: options.token_format,
            consent_mode: options.consent_mode,
            id_token_signed_response_alg: options.id_token_signed_response_alg.clone(),
            can_introspect: options.can_introspect,
            post_logout_redirect_uris: options
                .post_logout_redirect_uris
                .as_deref()
                .map(normalized_list),
            backchannel_logout_uri: options.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: options.backchannel_logout_session_required,
            allowed_resources: options
                .allowed_resources
                .as_deref()
                .map(parse_resources)
                .transpose()?,
            mfa_policy: options.mfa_policy,
            metadata_expires_at: None,
            registration_access_token_hash: None,
        };
        let client = self
            .storage
            .clients()
            .update(tenant.id, client_id, &update, self.clock.now())
            .await?
            .ok_or(CoreError::NotFound)?;
        self.record(
            tenant.id,
            actor,
            action,
            client_id,
            ctx,
            AuditDetails::fields(&fields),
        )
        .await?;
        Ok(client)
    }

    /// Replaces the secret of a secret-based client. The new secret is returned once; the old
    /// one stops working immediately. Audited as `client_secret_rotated` (no secret in details).
    pub async fn rotate_secret(
        &self,
        tenant: TenantId,
        client_id: &str,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<SecretString, CoreError> {
        let current = self.get(tenant, client_id).await?;
        if !uses_secret(current.auth_method) {
            return Err(invalid(
                "auth_method",
                "only clients using client_secret_basic or client_secret_post have a secret",
            ));
        }
        let (secret, hash) = new_client_secret();
        if !self
            .storage
            .clients()
            .set_secret_hash(tenant, client_id, Some(hash), self.clock.now())
            .await?
        {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant,
            actor,
            AuditAction::ClientSecretRotated,
            client_id,
            ctx,
            AuditDetails::empty(),
        )
        .await?;
        Ok(secret)
    }

    /// Deletes the client; its token families are revoked by the repository. Audited as
    /// `client_deleted`.
    pub async fn delete(
        &self,
        tenant: TenantId,
        client_id: &str,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        self.remove(tenant, client_id, AuditAction::ClientDeleted, actor, ctx)
            .await
    }

    /// RFC 7592 deletion of a dynamic client: [`Self::delete`] (token families revoked by the
    /// repository), audited as `client_registration_deleted` with the client as the actor.
    pub async fn delete_dynamic(
        &self,
        tenant: TenantId,
        client_id: &str,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        self.remove(
            tenant,
            client_id,
            AuditAction::ClientRegistrationDeleted,
            AuditActor::client(client_id),
            ctx,
        )
        .await
    }

    async fn remove(
        &self,
        tenant: TenantId,
        client_id: &str,
        action: AuditAction,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        if !self.storage.clients().delete(tenant, client_id).await? {
            return Err(CoreError::NotFound);
        }
        self.record(tenant, actor, action, client_id, ctx, AuditDetails::empty())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    /// Test validator: accepts https URIs, and http loopback URIs for native clients.
    fn test_validator(uri: &str, app: ApplicationType) -> Result<(), CoreError> {
        if uri.starts_with("https://")
            || (app == ApplicationType::Native && uri.starts_with("http://127.0.0.1"))
        {
            Ok(())
        } else {
            Err(CoreError::Validation {
                field: "redirect_uri",
                message: "redirect URI rejected by test validator".to_owned(),
            })
        }
    }

    fn confidential() -> ClientInput {
        ClientInput {
            name: "Web app".into(),
            client_type: ClientType::Confidential,
            application_type: ApplicationType::Web,
            auth_method: ClientAuthMethod::ClientSecretBasic,
            redirect_uris: vec!["https://app.example/cb".into()],
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes: vec!["openid".into(), "profile".into()],
            require_pkce: None,
            jwks: None,
            jwks_uri: None,
        }
    }

    fn public() -> ClientInput {
        ClientInput {
            name: "SPA".into(),
            client_type: ClientType::Public,
            auth_method: ClientAuthMethod::None,
            ..confidential()
        }
    }

    const PUBLIC_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;

    fn field_of(r: Result<(), CoreError>) -> &'static str {
        match r {
            Err(CoreError::Validation { field, .. }) => field,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    fn check(input: &ClientInput) -> Result<(), CoreError> {
        validate_client(input, test_validator)
    }

    #[test]
    fn valid_registrations_pass() {
        assert!(check(&confidential()).is_ok());
        assert!(check(&public()).is_ok());
        let m2m = ClientInput {
            redirect_uris: vec![],
            grant_types: vec![GrantType::ClientCredentials],
            ..confidential()
        };
        assert!(check(&m2m).is_ok());
    }

    #[test]
    fn confidential_client_may_disable_pkce_c1() {
        let c = ClientInput {
            require_pkce: Some(false),
            grant_types: vec![GrantType::AuthorizationCode],
            ..confidential()
        };
        assert!(check(&c).is_ok());
    }

    #[test]
    fn public_client_may_not_disable_pkce() {
        let c = ClientInput {
            require_pkce: Some(false),
            ..public()
        };
        assert_eq!(field_of(check(&c)), "require_pkce");
    }

    #[test]
    fn public_client_must_use_auth_method_none() {
        for m in [
            ClientAuthMethod::ClientSecretBasic,
            ClientAuthMethod::ClientSecretPost,
            ClientAuthMethod::PrivateKeyJwt,
        ] {
            let c = ClientInput {
                auth_method: m,
                ..public()
            };
            assert_eq!(field_of(check(&c)), "auth_method", "{m:?}");
        }
    }

    #[test]
    fn confidential_client_must_authenticate() {
        let c = ClientInput {
            auth_method: ClientAuthMethod::None,
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "auth_method");
    }

    #[test]
    fn public_client_may_not_use_client_credentials() {
        let c = ClientInput {
            grant_types: vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
            ..public()
        };
        assert_eq!(field_of(check(&c)), "grant_types");
    }

    #[test]
    fn private_key_jwt_requires_public_inline_jwks() {
        let base = ClientInput {
            auth_method: ClientAuthMethod::PrivateKeyJwt,
            ..confidential()
        };
        assert_eq!(field_of(check(&base)), "jwks");

        let ok = ClientInput {
            jwks: Some(PUBLIC_JWKS.into()),
            ..base.clone()
        };
        assert!(check(&ok).is_ok());

        let private = PUBLIC_JWKS.replace(r#""e":"AQAB""#, r#""e":"AQAB","d":"c2VjcmV0""#);
        let with_d = ClientInput {
            jwks: Some(private),
            ..base.clone()
        };
        assert_eq!(field_of(check(&with_d)), "jwks");

        for bad in ["not json", r#"{"keys":[]}"#, r#"{"nokeys":1}"#] {
            let c = ClientInput {
                jwks: Some(bad.into()),
                ..base.clone()
            };
            assert_eq!(field_of(check(&c)), "jwks", "{bad}");
        }
    }

    #[test]
    fn jwks_only_with_private_key_jwt() {
        let c = ClientInput {
            jwks: Some(PUBLIC_JWKS.into()),
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "jwks");
    }

    #[test]
    fn jwks_uri_is_not_supported() {
        let c = ClientInput {
            auth_method: ClientAuthMethod::PrivateKeyJwt,
            jwks: Some(PUBLIC_JWKS.into()),
            jwks_uri: Some("https://app.example/jwks".into()),
            ..confidential()
        };
        match check(&c) {
            Err(CoreError::Validation { field, message }) => {
                assert_eq!(field, "jwks_uri");
                assert!(message.contains("not supported in this release"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn authorization_code_requires_redirect_uris() {
        let c = ClientInput {
            redirect_uris: vec![],
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "redirect_uris");
    }

    #[test]
    fn redirect_validator_error_is_propagated_as_redirect_uris() {
        let c = ClientInput {
            redirect_uris: vec![
                "https://ok.example/cb".into(),
                "http://evil.example/cb".into(),
            ],
            ..confidential()
        };
        match check(&c) {
            Err(CoreError::Validation { field, message }) => {
                assert_eq!(field, "redirect_uris");
                assert!(message.contains("test validator"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // The application type is passed to the validator.
        let native = ClientInput {
            application_type: ApplicationType::Native,
            redirect_uris: vec!["http://127.0.0.1:4000/cb".into()],
            ..public()
        };
        assert!(check(&native).is_ok());
        let web = ClientInput {
            application_type: ApplicationType::Web,
            ..native
        };
        assert_eq!(field_of(check(&web)), "redirect_uris");
    }

    #[test]
    fn refresh_token_requires_authorization_code() {
        let c = ClientInput {
            grant_types: vec![GrantType::RefreshToken, GrantType::ClientCredentials],
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "grant_types");
        let none = ClientInput {
            grant_types: vec![],
            ..confidential()
        };
        assert_eq!(field_of(check(&none)), "grant_types");
    }

    #[test]
    fn name_and_scopes_are_validated() {
        let c = ClientInput {
            name: "  ".into(),
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "name");
        for bad in ["open id", "", "a\"b"] {
            let c = ClientInput {
                scopes: vec![bad.into()],
                ..confidential()
            };
            assert_eq!(field_of(check(&c)), "scopes", "{bad:?}");
        }
    }

    #[test]
    fn secrets_and_ids_are_random_and_hashed() {
        let (s1, h1) = new_client_secret();
        let (s2, h2) = new_client_secret();
        assert_eq!(s1.expose_secret().len(), 43);
        assert_ne!(s1.expose_secret(), s2.expose_secret());
        assert_ne!(h1, h2);
        assert_eq!(h1, SecretHash(secret_hash(s1.expose_secret())));
        assert!(!format!("{s1:?}").contains(s1.expose_secret()));
        let id = new_client_id();
        assert_eq!(id.len(), CLIENT_ID_LEN);
        assert_ne!(id, new_client_id());
        assert!(uses_secret(ClientAuthMethod::ClientSecretPost));
        assert!(!uses_secret(ClientAuthMethod::PrivateKeyJwt));
        assert!(!uses_secret(ClientAuthMethod::None));
    }

    fn settings(algs: &[&str]) -> TenantSettings {
        TenantSettings {
            signing_algs: algs.iter().map(|a| (*a).to_owned()).collect(),
            ..TenantSettings::default()
        }
    }

    fn opts_field(r: Result<(), CoreError>) -> &'static str {
        field_of(r)
    }

    #[test]
    fn id_token_alg_must_be_enabled_for_the_tenant() {
        let es256 = ClientOptions {
            id_token_signed_response_alg: Some("ES256".into()),
            ..ClientOptions::default()
        };
        assert_eq!(
            opts_field(validate_client_options(
                &confidential(),
                &es256,
                &settings(&["RS256"])
            )),
            "id_token_signed_response_alg"
        );
        assert!(
            validate_client_options(&confidential(), &es256, &settings(&["RS256", "ES256"]))
                .is_ok()
        );
        // RS256 is always enabled, even when the stored list omits it.
        let rs256 = ClientOptions {
            id_token_signed_response_alg: Some("RS256".into()),
            ..ClientOptions::default()
        };
        assert!(validate_client_options(&confidential(), &rs256, &settings(&["ES256"])).is_ok());
        // Unknown / wrongly cased names are never enabled.
        for bad in ["HS256", "none", "es256", "EdDSA"] {
            let o = ClientOptions {
                id_token_signed_response_alg: Some(bad.into()),
                ..ClientOptions::default()
            };
            assert_eq!(
                opts_field(validate_client_options(
                    &confidential(),
                    &o,
                    &settings(&["RS256", "ES256", "Ed25519"])
                )),
                "id_token_signed_response_alg",
                "{bad}"
            );
        }
    }

    #[test]
    fn only_confidential_clients_may_introspect() {
        let o = ClientOptions {
            can_introspect: true,
            ..ClientOptions::default()
        };
        assert_eq!(
            opts_field(validate_client_options(
                &public(),
                &o,
                &TenantSettings::default()
            )),
            "can_introspect"
        );
        assert!(validate_client_options(&confidential(), &o, &TenantSettings::default()).is_ok());
    }

    #[test]
    fn option_defaults_are_secure() {
        let d = ClientOptions::default();
        assert_eq!(d.token_format, TokenFormat::Jwt);
        assert_eq!(d.consent_mode, ConsentMode::Required);
        assert_eq!(d.id_token_signed_response_alg, None);
        assert!(!d.can_introspect);
        assert!(validate_client_options(&public(), &d, &TenantSettings::default()).is_ok());
        for f in [TokenFormat::Jwt, TokenFormat::Opaque] {
            for m in [ConsentMode::Required, ConsentMode::SkipFirstParty] {
                let o = ClientOptions {
                    token_format: f,
                    consent_mode: m,
                    ..ClientOptions::default()
                };
                assert!(validate_client_options(&public(), &o, &TenantSettings::default()).is_ok());
            }
        }
    }

    #[test]
    fn changed_fields_list_names_only() {
        let patch = ClientPatch {
            name: Some("x".into()),
            jwks: Some(None),
            ..ClientPatch::default()
        };
        let opts = ClientOptionsPatch {
            id_token_signed_response_alg: Some(None),
            can_introspect: Some(true),
            ..ClientOptionsPatch::default()
        };
        assert_eq!(
            changed_fields(&patch, &opts),
            vec![
                "name",
                "jwks",
                "id_token_signed_response_alg",
                "can_introspect"
            ]
        );
        assert!(changed_fields(&ClientPatch::default(), &ClientOptionsPatch::default()).is_empty());
    }

    #[test]
    fn normalisation_dedups() {
        assert_eq!(
            normalized_grants(&[
                GrantType::RefreshToken,
                GrantType::AuthorizationCode,
                GrantType::RefreshToken
            ]),
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
        );
        assert_eq!(
            normalized_list(&["b".into(), "a".into(), "b".into()]),
            vec!["b".to_owned(), "a".to_owned()]
        );
    }

    fn phase4(o: ClientOptions) -> Result<(), CoreError> {
        validate_client_phase4(
            &confidential(),
            &o,
            crate::oauth::redirect::validate_redirect_uri,
        )
    }

    #[test]
    fn backchannel_logout_uri_must_be_absolute_without_fragment() {
        let with = |uri: &str| ClientOptions {
            backchannel_logout_uri: Some(uri.into()),
            ..ClientOptions::default()
        };
        for bad in [
            "https://rp.example/bcl#frag",
            "/logout",
            "rp.example/logout",
            "http://rp.example/logout",
            "javascript:alert(1)",
            "",
        ] {
            assert_eq!(
                field_of(phase4(with(bad))),
                "backchannel_logout_uri",
                "{bad:?}"
            );
        }
        for ok in [
            "https://rp.example/bcl",
            "https://rp.example/bcl?tenant=a",
            "http://127.0.0.1:8080/bcl",
        ] {
            assert!(phase4(with(ok)).is_ok(), "{ok}");
        }
    }

    #[test]
    fn post_logout_redirect_uris_follow_redirect_rules() {
        let with = |uri: &str| ClientOptions {
            post_logout_redirect_uris: vec![uri.into()],
            ..ClientOptions::default()
        };
        for bad in [
            "https://rp.example/out#x",
            "https://*.rp.example/out",
            "relative",
            "http://rp.example/out",
        ] {
            assert_eq!(
                field_of(phase4(with(bad))),
                "post_logout_redirect_uris",
                "{bad:?}"
            );
        }
        assert!(phase4(with("https://rp.example/out")).is_ok());
        let many = ClientOptions {
            post_logout_redirect_uris: (0..=MAX_REDIRECT_URIS)
                .map(|i| format!("https://rp.example/{i}"))
                .collect(),
            ..ClientOptions::default()
        };
        assert_eq!(field_of(phase4(many)), "post_logout_redirect_uris");
    }

    #[test]
    fn allowed_resources_follow_rfc8707() {
        let with = |r: &str| ClientOptions {
            allowed_resources: vec![r.into()],
            ..ClientOptions::default()
        };
        for bad in [
            "https://api.example/#frag",
            "https://api.example/?q=1",
            "api.example",
            "",
            "https://api .example",
        ] {
            assert_eq!(field_of(phase4(with(bad))), "allowed_resources", "{bad:?}");
        }
        assert!(phase4(with("https://api.example/v1")).is_ok());
        assert!(phase4(with("urn:example:api")).is_ok());
    }

    #[test]
    fn phase4_changed_fields() {
        let opts = ClientOptionsPatch {
            post_logout_redirect_uris: Some(vec![]),
            backchannel_logout_uri: Some(None),
            backchannel_logout_session_required: Some(true),
            allowed_resources: Some(vec![]),
            mfa_policy: Some(Some(MfaPolicy::Required)),
            ..ClientOptionsPatch::default()
        };
        assert_eq!(
            changed_fields(&ClientPatch::default(), &opts),
            vec![
                "post_logout_redirect_uris",
                "backchannel_logout_uri",
                "backchannel_logout_session_required",
                "allowed_resources",
                "mfa_policy"
            ]
        );
        let d = ClientOptions::default();
        assert!(d.post_logout_redirect_uris.is_empty() && d.allowed_resources.is_empty());
        assert_eq!(d.backchannel_logout_uri, None);
        assert_eq!(d.mfa_policy, None);
    }
}
