//! Connection administration: create, update, delete and secret sealing (AUTH-07, SEC-03).
//!
//! An upstream connection's client secret (Apple: the `.p8` private key PEM) is write-only:
//! it enters as plaintext, is validated, sealed with the KEK ([`CONNECTION_SECRET_PURPOSE`],
//! AAD [`connection_aad`] = tenant id || connection id) by [`seal_secret`] before it reaches
//! storage, and is opened again only by [`ConnectionService::open_secret`] (the sign-in flow,
//! plan 04-21). Nothing in this module returns, logs or audits secret material.
//!
//! Configuration is validated statically when it is written: identifiers and scopes, absolute
//! `https` URLs (plain `http` only for loopback hosts, for development and test IdPs), provider
//! specific options only on the provider they belong to, and finally
//! [`upstream::providers::resolve`](crate::upstream::providers::resolve) for every kind that
//! does not need discovery. Checks that need the provider's metadata (generic OIDC discovery,
//! algorithms) run at sign-in time.
//!
//! Email trust (`trust_email_verified`) defaults per kind
//! ([`ConnectionKind::default_email_trust`]). Microsoft accounts can carry addresses that an
//! Entra tenant administrator set without verification ("nOAuth"), so trusting them needs the
//! explicit `accept_email_trust_risk` flag and the event records that the risk was accepted.
//! The Microsoft preset never auto-links on email either way (see `upstream::linking`).
//!
//! Every mutation records exactly one audit event in the connection's tenant
//! (`connection_created`, `connection_updated`, `connection_secret_rotated`,
//! `connection_deleted`), target = the connection id, details = slug and kind (plus changed
//! field names for updates, and `org_id` / `org_slug` for an organization's connection). Failed
//! calls record nothing.
//!
//! **Owners** ([`ConnectionOwner`]): a connection belongs to the tenant (sign-in buttons) or to
//! one organization (enterprise SSO, ORG-03). Both share the tenant's slug namespace and callback
//! URL format. Organization connections are OIDC or SAML; they are managed only through the
//! organization (the tenant-level calls see them but refuse to change them, 409). SAML
//! connections (decision Q3) exist only per organization (tenant level: 422) and only while the
//! operator flag `saml_experimental` is on: creating one, and every change to one except
//! disabling it, answers `FeatureDisabled("saml")` (403) when the flag is off. Deleting stays
//! possible. A SAML connection has no client secret.
//!
//! **Enabling** (decision 5 of 07.1): a connection can always be created, edited, disabled and
//! deleted while it is disabled, but turning it on (create with `enabled = true`, a patch with
//! `enabled = true`, or a config change of an enabled connection) is refused with 422 naming the
//! first missing field ([`ConnectionConfig::missing_for_enable`]: client id, secret, issuer or
//! endpoints, SAML entity id / SSO URL / certificate) until it is complete. For generic OIDC the
//! issuer must also pass discovery: `{issuer}/.well-known/openid-configuration` is fetched
//! through the [`UpstreamClient`] port (the SSRF-guarded outbound adapter, which also checks the
//! document's `issuer`), and the refusal names the problem without echoing fetched content. The
//! check runs before anything is written, for tenant and organization connections alike.

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::keys::{Alg, SigningKey};
use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, CONNECTION_SECRET_PURPOSE, ClaimMapping,
    Connection, ConnectionConfig, ConnectionId, ConnectionKind, ConnectionUpdate,
    EndpointOverrides, IdpMetadata, NewConnection, OAuth2Config, OidcConfig, OrgId, Organization,
    RequestContext, SamlConfig, Scope, SocialConfig, SocialProvider, TenantId, connection_aad,
    truncate_to_ms,
};
use crate::ports::{SamlXml, Storage, StorageError, UpstreamClient, UpstreamError};
use crate::service::audit::AuditService;
use crate::service::tenant::validate_display_name;
use crate::upstream::providers;

/// Longest accepted connection secret in bytes (an Apple `.p8` PEM is about 250 bytes; the PEM
/// parser caps input at 16 KiB).
pub const MAX_CONNECTION_SECRET_LEN: usize = 16 * 1024;
/// Longest accepted plain client secret (non-Apple kinds) in bytes.
pub const MAX_CLIENT_SECRET_LEN: usize = 1024;
/// Longest accepted upstream `client_id`.
pub const MAX_UPSTREAM_CLIENT_ID_LEN: usize = 512;
/// Longest accepted upstream URL.
pub const MAX_UPSTREAM_URL_LEN: usize = 2048;
/// Most scopes / allow-list entries per connection.
pub const MAX_LIST_LEN: usize = 50;

/// A connection as submitted by an administrator.
#[derive(Debug, Clone)]
pub struct NewConnectionInput {
    /// `^[a-z0-9][a-z0-9-]{0,62}$`; unique per tenant, immutable, part of the callback URL.
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub config: ConnectionConfig,
    /// Client secret (Apple: the `.p8` PEM). `None` = no secret yet.
    pub secret: Option<SecretString>,
    /// `None` = [`ConnectionKind::default_email_trust`].
    pub trust_email_verified: Option<bool>,
    /// Required to trust Microsoft-asserted email addresses (nOAuth risk).
    pub accept_email_trust_risk: bool,
}

/// Partial connection update; `None` leaves a field unchanged. The slug is immutable and the
/// kind cannot change (a new config must be of the same kind). The secret changes only through
/// [`ConnectionService::set_secret`].
#[derive(Debug, Clone, Default)]
pub struct ConnectionPatch {
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<ConnectionConfig>,
    pub trust_email_verified: Option<bool>,
    /// Required when this patch turns on email trust for a Microsoft connection.
    pub accept_email_trust_risk: bool,
}

fn invalid(field: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        field,
        message: message.into(),
    }
}

/// Connection slug syntax: `^[a-z0-9][a-z0-9-]{0,62}$` (a URL path segment).
pub fn validate_connection_slug(slug: &str) -> Result<(), CoreError> {
    let b = slug.as_bytes();
    let ok = (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    if ok {
        Ok(())
    } else {
        Err(invalid(
            "slug",
            "must be 1-63 characters of a-z, 0-9 and '-', starting with a letter or digit",
        ))
    }
}

/// An absolute upstream URL: `https` with a host, or `http` to a loopback host (`localhost`,
/// `127.0.0.0/8`, `::1`) for development IdPs; no userinfo, no fragment, no whitespace.
pub fn validate_upstream_url(field: &'static str, raw: &str) -> Result<(), CoreError> {
    if raw.is_empty() || raw.len() > MAX_UPSTREAM_URL_LEN {
        return Err(invalid(field, "must be an absolute https URL"));
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) || raw.contains('#') {
        return Err(invalid(
            field,
            "must be an absolute https URL without whitespace or fragment",
        ));
    }
    let url = Url::parse(raw).map_err(|_| invalid(field, "must be an absolute https URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(field, "must not contain userinfo"));
    }
    match url.scheme() {
        "https" if url.host_str().is_some_and(|h| !h.is_empty()) => Ok(()),
        "http" => {
            let loopback = match url.host() {
                Some(url::Host::Domain(d)) => d == "localhost",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if loopback {
                Ok(())
            } else {
                Err(invalid(
                    field,
                    "must use https (plain http only for loopback addresses)",
                ))
            }
        }
        _ => Err(invalid(field, "must be an absolute https URL")),
    }
}

fn validate_client_id(client_id: &str) -> Result<(), CoreError> {
    if client_id.is_empty()
        || client_id.len() > MAX_UPSTREAM_CLIENT_ID_LEN
        || client_id
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid(
            "config.client_id",
            "must be 1-512 characters without whitespace",
        ));
    }
    Ok(())
}

fn validate_scopes(scopes: &[String]) -> Result<(), CoreError> {
    if scopes.len() > MAX_LIST_LEN {
        return Err(invalid("config.scopes", "too many scopes"));
    }
    for s in scopes {
        if s.contains(' ') || Scope::parse(s).is_err() {
            return Err(invalid(
                "config.scopes",
                format!("invalid scope token {s:?}"),
            ));
        }
    }
    Ok(())
}

/// A short identifier list entry (tenant ids, hosted domains): 1-253 visible characters.
fn validate_list(field: &'static str, values: &[String]) -> Result<(), CoreError> {
    if values.len() > MAX_LIST_LEN {
        return Err(invalid(field, "too many entries"));
    }
    if values.iter().any(|v| {
        v.is_empty() || v.len() > 253 || v.chars().any(|c| c.is_control() || c.is_whitespace())
    }) {
        return Err(invalid(
            field,
            "entries must be 1-253 characters without whitespace",
        ));
    }
    Ok(())
}

fn validate_overrides(o: &EndpointOverrides) -> Result<(), CoreError> {
    let fields: [(&'static str, &Option<String>); 6] = [
        ("config.endpoints.issuer", &o.issuer),
        (
            "config.endpoints.authorization_endpoint",
            &o.authorization_endpoint,
        ),
        ("config.endpoints.token_endpoint", &o.token_endpoint),
        ("config.endpoints.userinfo_endpoint", &o.userinfo_endpoint),
        ("config.endpoints.jwks_uri", &o.jwks_uri),
        ("config.endpoints.api_base_url", &o.api_base_url),
    ];
    for (field, value) in fields {
        if let Some(v) = value {
            validate_upstream_url(field, v)?;
        }
    }
    Ok(())
}

/// Apple team and key identifiers: 1-64 ASCII letters and digits.
fn validate_apple_id(field: &'static str, v: &str) -> Result<(), CoreError> {
    if v.is_empty() || v.len() > 64 || !v.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid(field, "must be 1-64 letters and digits"));
    }
    Ok(())
}

fn validate_social(s: &SocialConfig) -> Result<(), CoreError> {
    validate_client_id(&s.client_id)?;
    validate_scopes(&s.scopes)?;
    validate_overrides(&s.endpoints)?;
    let p = s.provider;
    if p != SocialProvider::Microsoft
        && (s.microsoft_tenant.is_some() || !s.allowed_tenants.is_empty())
    {
        return Err(invalid(
            "config.microsoft_tenant",
            "microsoft_tenant and allowed_tenants are Microsoft options",
        ));
    }
    if p != SocialProvider::Google && !s.hosted_domains.is_empty() {
        return Err(invalid(
            "config.hosted_domains",
            "hosted_domains is a Google option",
        ));
    }
    if p != SocialProvider::Github && s.endpoints.api_base_url.is_some() {
        return Err(invalid(
            "config.endpoints.api_base_url",
            "api_base_url is a GitHub option",
        ));
    }
    validate_list("config.allowed_tenants", &s.allowed_tenants)?;
    validate_list("config.hosted_domains", &s.hosted_domains)?;
    match (p, &s.apple) {
        (SocialProvider::Apple, None) => Err(invalid(
            "config.apple",
            "Apple connections need team_id and key_id",
        )),
        (SocialProvider::Apple, Some(a)) => {
            validate_apple_id("config.apple.team_id", &a.team_id)?;
            validate_apple_id("config.apple.key_id", &a.key_id)
        }
        (_, Some(_)) => Err(invalid("config.apple", "apple is an Apple option")),
        (_, None) => Ok(()),
    }
}

fn validate_oidc(o: &OidcConfig) -> Result<(), CoreError> {
    validate_upstream_url("config.issuer", &o.issuer)?;
    if o.issuer.contains('?') {
        return Err(invalid("config.issuer", "an issuer has no query component"));
    }
    validate_client_id(&o.client_id)?;
    validate_scopes(&o.scopes)
}

/// A JSON pointer into the profile response (RFC 6901): `/` followed by the path.
fn validate_pointer(field: &'static str, p: &str) -> Result<(), CoreError> {
    if !p.starts_with('/') || p.len() > 256 || p.chars().any(char::is_control) {
        return Err(invalid(
            field,
            "must be a JSON pointer such as /id (RFC 6901)",
        ));
    }
    Ok(())
}

fn validate_mapping(m: &ClaimMapping) -> Result<(), CoreError> {
    validate_pointer("config.mapping.subject", &m.subject)?;
    let optional = [
        ("config.mapping.email", &m.email),
        ("config.mapping.email_verified", &m.email_verified),
        ("config.mapping.name", &m.name),
    ];
    for (field, value) in optional {
        if let Some(p) = value {
            validate_pointer(field, p)?;
        }
    }
    Ok(())
}

fn validate_oauth2(o: &OAuth2Config) -> Result<(), CoreError> {
    validate_upstream_url("config.authorization_endpoint", &o.authorization_endpoint)?;
    validate_upstream_url("config.token_endpoint", &o.token_endpoint)?;
    validate_upstream_url("config.userinfo_endpoint", &o.userinfo_endpoint)?;
    validate_client_id(&o.client_id)?;
    validate_scopes(&o.scopes)?;
    validate_mapping(&o.mapping)
}

/// Static validation of a **tenant-level** connection config (admin API, tenant YAML). A SAML
/// config is refused here: SAML connections belong to an organization
/// ([`validate_config_for`]).
pub fn validate_config(config: &ConnectionConfig) -> Result<(), CoreError> {
    validate_config_for(config, false)
}

/// The `config.`-prefixed name of a field reported by [`SamlConfig::validate`].
fn saml_field(field: &'static str) -> &'static str {
    match field {
        "idp_entity_id" => "config.idp_entity_id",
        "sso_url" => "config.sso_url",
        "signing_certs" => "config.signing_certs",
        "name_id_format" => "config.name_id_format",
        "metadata_url" => "config.metadata_url",
        _ => "config",
    }
}

/// Static validation of a SAML config ([`SamlConfig::validate`], fields `config.*`). Whether
/// each certificate parses as X.509 is checked by the caller with the SAML adapter's loader
/// (anvil-core has no X.509 parser).
pub fn validate_saml(c: &SamlConfig) -> Result<(), CoreError> {
    c.validate().map_err(|e| match e {
        CoreError::Validation { field, message } => CoreError::Validation {
            field: saml_field(field),
            message,
        },
        other => other,
    })
}

/// Static validation of a connection config for its owner (`in_org`: an organization's
/// connection). Kinds that need no discovery are also resolved with [`providers::resolve`] (the
/// sign-in flow resolves them the same way), so a config that is stored can be resolved later.
/// Organization connections are OIDC or SAML; SAML is refused at tenant level.
pub fn validate_config_for(config: &ConnectionConfig, in_org: bool) -> Result<(), CoreError> {
    if in_org
        && !matches!(
            config,
            ConnectionConfig::Oidc(_) | ConnectionConfig::Saml(_)
        )
    {
        return Err(invalid(
            "config",
            "an organization connection is an OIDC or SAML connection",
        ));
    }
    match config {
        ConnectionConfig::Social(s) => validate_social(s)?,
        ConnectionConfig::Oidc(o) => return validate_oidc(o),
        ConnectionConfig::Oauth2(o) => validate_oauth2(o)?,
        ConnectionConfig::Saml(c) => {
            if !in_org {
                return Err(invalid(
                    "config",
                    "SAML connections belong to an organization; create them under the \
                     organization's connections",
                ));
            }
            return validate_saml(c);
        }
    }
    let probe = Connection {
        id: ConnectionId(uuid::Uuid::nil()),
        tenant_id: TenantId(uuid::Uuid::nil()),
        slug: String::new(),
        display_name: String::new(),
        enabled: false,
        config: config.clone(),
        secret_enc: None,
        trust_email_verified: false,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
        org_id: None,
    };
    providers::resolve(&probe, None)
        .map(|_| ())
        .map_err(|e| match e {
            CoreError::Validation { field, message } => CoreError::Validation {
                field: prefixed(field),
                message,
            },
            other => other,
        })
}

/// The `config.`-prefixed name of a field reported by [`providers::resolve`].
fn prefixed(field: &'static str) -> &'static str {
    match field {
        "issuer" => "config.endpoints.issuer",
        "authorization_endpoint" => "config.authorization_endpoint",
        "token_endpoint" => "config.token_endpoint",
        "userinfo_endpoint" => "config.userinfo_endpoint",
        "jwks_uri" => "config.endpoints.jwks_uri",
        "microsoft_tenant" => "config.microsoft_tenant",
        "apple" => "config.apple",
        other if other.starts_with("config") => other,
        _ => "config",
    }
}

/// Validates a secret for a connection of `kind`. Apple: an ES256 PKCS#8 `PRIVATE KEY` PEM
/// (checked with the single PEM parser, `SigningKey::from_pkcs8_pem`); other kinds: 1-1024
/// bytes without control characters. Errors never contain the secret.
pub fn validate_secret(kind: ConnectionKind, secret: &SecretString) -> Result<(), CoreError> {
    let s = secret.expose_secret();
    if kind == ConnectionKind::Apple {
        if s.len() > MAX_CONNECTION_SECRET_LEN
            || SigningKey::from_pkcs8_pem("apple", Alg::ES256, s).is_err()
        {
            return Err(invalid(
                "secret",
                "must be the Apple .p8 key: an ES256 private key in PKCS#8 PEM form",
            ));
        }
        return Ok(());
    }
    if s.is_empty() || s.len() > MAX_CLIENT_SECRET_LEN || s.chars().any(char::is_control) {
        return Err(invalid(
            "secret",
            "must be 1-1024 characters without control characters",
        ));
    }
    Ok(())
}

/// Seals a connection secret for (`tenant`, `id`) with [`CONNECTION_SECRET_PURPOSE`] and
/// [`connection_aad`].
pub fn seal_secret(
    kek: &Kek,
    tenant: TenantId,
    id: ConnectionId,
    secret: &SecretString,
) -> Result<Vec<u8>, CoreError> {
    kek.seal(
        CONNECTION_SECRET_PURPOSE,
        &connection_aad(tenant, id),
        secret.expose_secret().as_bytes(),
    )
    .map_err(|_| CoreError::Internal("connection secret could not be sealed".into()))
}

/// Opens the sealed secret of `conn`. The error is generic: it never contains the sealed or
/// opened value. Private: [`ConnectionService::open_secret`] is the only entry point.
fn open_sealed(kek: &Kek, conn: &Connection) -> Result<Option<SecretString>, CoreError> {
    let Some(sealed) = &conn.secret_enc else {
        return Ok(None);
    };
    let undecryptable = || CoreError::Internal("connection secret could not be decrypted".into());
    let raw = kek
        .open(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(conn.tenant_id, conn.id),
            sealed,
        )
        .map_err(|_| undecryptable())?;
    let text = std::str::from_utf8(&raw).map_err(|_| undecryptable())?;
    Ok(Some(SecretString::from(text.to_owned())))
}

/// The nOAuth guard: trusting Microsoft-asserted email needs the explicit flag.
fn check_email_trust(
    kind: ConnectionKind,
    turning_on: bool,
    accepted: bool,
) -> Result<(), CoreError> {
    if kind == ConnectionKind::Microsoft && turning_on && !accepted {
        return Err(invalid(
            "trust_email_verified",
            "Microsoft accounts can carry email addresses their tenant administrator set without \
             verification (nOAuth); set accept_email_trust_risk to trust them anyway",
        ));
    }
    Ok(())
}

/// Validates a create request of a tenant-level connection and builds the row to insert
/// (secret sealed for the new id). Returns whether a Microsoft email-trust risk was accepted
/// (for the audit event).
pub fn plan_create(
    kek: &Kek,
    tenant: TenantId,
    input: NewConnectionInput,
    now: time::OffsetDateTime,
) -> Result<(NewConnection, bool), CoreError> {
    plan_create_for(kek, tenant, None, input, now)
}

/// [`plan_create`] for an owner: `org` = the organization the connection belongs to.
pub fn plan_create_for(
    kek: &Kek,
    tenant: TenantId,
    org: Option<OrgId>,
    input: NewConnectionInput,
    now: time::OffsetDateTime,
) -> Result<(NewConnection, bool), CoreError> {
    validate_connection_slug(&input.slug)?;
    let display_name = validate_display_name(&input.display_name)?;
    validate_config_for(&input.config, org.is_some())?;
    let kind = input.config.kind();
    if kind == ConnectionKind::Saml && input.secret.is_some() {
        return Err(no_saml_secret());
    }
    let trust = input
        .trust_email_verified
        .unwrap_or_else(|| kind.default_email_trust());
    check_email_trust(kind, trust, input.accept_email_trust_risk)?;
    let id = ConnectionId::new_v7();
    let secret_enc = match &input.secret {
        None => None,
        Some(s) => {
            validate_secret(kind, s)?;
            Some(seal_secret(kek, tenant, id, s)?)
        }
    };
    let risk = kind == ConnectionKind::Microsoft && trust;
    Ok((
        NewConnection {
            id,
            slug: input.slug,
            display_name,
            enabled: input.enabled,
            config: input.config,
            secret_enc,
            trust_email_verified: trust,
            created_at: now,
            org_id: org,
        },
        risk,
    ))
}

fn no_saml_secret() -> CoreError {
    invalid("secret", "a SAML connection has no client secret")
}

/// Validates a patch against the current connection and builds the storage update plus the
/// changed field names. The third value tells whether the patch accepted the Microsoft
/// email-trust risk.
pub fn plan_update(
    current: &Connection,
    patch: ConnectionPatch,
) -> Result<(ConnectionUpdate, Vec<&'static str>, bool), CoreError> {
    let mut fields = Vec::new();
    let display_name = match patch.display_name {
        None => None,
        Some(n) => {
            fields.push("display_name");
            Some(validate_display_name(&n)?)
        }
    };
    if patch.enabled.is_some() {
        fields.push("enabled");
    }
    if let Some(config) = &patch.config {
        if config.kind() != current.kind() {
            return Err(invalid(
                "config",
                "the kind of a connection cannot change; create a new connection instead",
            ));
        }
        validate_config_for(config, current.org_id.is_some())?;
        fields.push("config");
    }
    let kind = current.kind();
    let turning_on = patch.trust_email_verified == Some(true) && !current.trust_email_verified;
    check_email_trust(kind, turning_on, patch.accept_email_trust_risk)?;
    if patch.trust_email_verified.is_some() {
        fields.push("trust_email_verified");
    }
    let risk = kind == ConnectionKind::Microsoft && turning_on;
    Ok((
        ConnectionUpdate {
            display_name,
            enabled: patch.enabled,
            config: patch.config,
            trust_email_verified: patch.trust_email_verified,
        },
        fields,
        risk,
    ))
}

/// Who owns a connection: the tenant, or one organization of it.
#[derive(Debug, Clone, Copy)]
pub enum ConnectionOwner<'a> {
    /// Tenant-level calls (admin API `…/connections`, tenant YAML): they see every connection
    /// of the tenant but change only tenant-level ones.
    Tenant,
    /// An organization's calls: they see and change only that organization's connections.
    Org(&'a Organization),
}

impl ConnectionOwner<'_> {
    fn org_id(&self) -> Option<OrgId> {
        match self {
            Self::Tenant => None,
            Self::Org(o) => Some(o.id),
        }
    }
}

/// Upstream connection administration and the single place connection secrets are opened.
#[derive(Clone)]
pub struct ConnectionService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// Seals and opens connection secrets; must be the KEK the sign-in flow uses.
    pub kek: Arc<Kek>,
    /// The operator flag `saml_experimental` (decision Q3, off by default). SAML connections
    /// can only be created, enabled or changed while it is on (disabling and deleting always
    /// work).
    pub saml_enabled: bool,
    /// Parses IdP metadata for SAML connections (the admin API's metadata import). `None` where
    /// SAML is never configured (CLI tenant config apply, the upstream sign-in flow opening
    /// secrets).
    pub saml_xml: Option<Arc<dyn SamlXml>>,
    /// Checks a generic OIDC issuer (discovery) before a connection is enabled: the
    /// SSRF-guarded upstream adapter. `None` where connections are never enabled (the upstream
    /// sign-in flow opening secrets); enabling an OIDC connection then fails (`Internal`).
    pub upstream: Option<Arc<dyn UpstreamClient>>,
}

/// The refusal for a field [`ConnectionConfig::missing_for_enable`] reported.
fn missing_for_enable_error(field: &'static str) -> CoreError {
    let message = if field == "secret" {
        "a client secret is required before the connection can be enabled; set the secret, \
         then enable the connection"
    } else {
        "is required before the connection can be enabled; save the connection disabled and \
         enable it once it is complete"
    };
    invalid(field, message)
}

/// The refusal for a failed issuer discovery. Names the problem only: never the fetched body,
/// a resolved address or a redirect target.
fn issuer_check_error(e: &UpstreamError) -> CoreError {
    let message = match e {
        UpstreamError::Blocked => "the issuer's address is not allowed for outbound requests \
             (private, loopback or reserved network); the connection cannot be enabled"
            .to_owned(),
        UpstreamError::Network | UpstreamError::Timeout => {
            "the issuer could not be reached to fetch its discovery document \
             (/.well-known/openid-configuration); the connection cannot be enabled"
                .to_owned()
        }
        UpstreamError::Status(code) => format!(
            "the issuer's discovery document (/.well-known/openid-configuration) answered HTTP \
             {code}; the connection cannot be enabled"
        ),
        UpstreamError::TooLarge => "the issuer's discovery document is too large; the \
             connection cannot be enabled"
            .to_owned(),
        UpstreamError::InvalidResponse("issuer mismatch") => "the issuer named in the discovery \
             document does not equal the configured issuer; the connection cannot be enabled"
            .to_owned(),
        UpstreamError::InvalidResponse(reason) => format!(
            "the issuer's discovery document is not usable ({reason}); the connection cannot be \
             enabled"
        ),
    };
    invalid("config.issuer", message)
}

/// Refuses to enable a connection with `config` (`has_secret`: a secret is stored or supplied)
/// unless it is complete and, for generic OIDC, its issuer passes discovery through `upstream`
/// (the SSRF-guarded port; `None` = no way to check, `Internal`). See the module docs.
pub async fn check_enable(
    config: &ConnectionConfig,
    has_secret: bool,
    upstream: Option<&dyn UpstreamClient>,
) -> Result<(), CoreError> {
    if let Some(field) = config.missing_for_enable(has_secret).first() {
        return Err(missing_for_enable_error(field));
    }
    if let ConnectionConfig::Oidc(o) = config {
        let client = upstream
            .ok_or_else(|| CoreError::Internal("no upstream client to check the issuer".into()))?;
        client
            .metadata(&o.issuer)
            .await
            .map_err(|e| issuer_check_error(&e))?;
    }
    Ok(())
}

/// Whether a patch only disables the connection (allowed for SAML with the flag off, so an
/// operator can always switch a connection off).
fn only_disables(patch: &ConnectionPatch) -> bool {
    patch.enabled == Some(false)
        && patch.display_name.is_none()
        && patch.config.is_none()
        && patch.trust_email_verified.is_none()
}

impl ConnectionService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    async fn record(
        &self,
        conn: &Connection,
        owner: ConnectionOwner<'_>,
        actor: AuditActor,
        action: AuditAction,
        ctx: &RequestContext,
        extra: AuditDetails,
    ) -> Result<(), CoreError> {
        let mut details = AuditDetails::connection(&conn.slug, conn.kind().as_str()).with(extra);
        if let ConnectionOwner::Org(org) = owner {
            details = details.with(AuditDetails::org(org.id, &org.slug));
        }
        self.audit()
            .record(
                conn.tenant_id,
                actor,
                action,
                Some(conn.id.to_string()),
                AuditOutcome::Success,
                ctx,
                details,
            )
            .await
    }

    /// `FeatureDisabled("saml")` unless the operator flag is on.
    fn require_saml(&self) -> Result<(), CoreError> {
        if self.saml_enabled {
            Ok(())
        } else {
            Err(CoreError::FeatureDisabled("saml"))
        }
    }

    /// [`check_enable`] with this service's upstream port.
    pub async fn check_enable(
        &self,
        config: &ConnectionConfig,
        has_secret: bool,
    ) -> Result<(), CoreError> {
        check_enable(config, has_secret, self.upstream.as_deref()).await
    }

    /// Every connection of the tenant (tenant-level and organizations'), in slug order.
    pub async fn list(&self, tenant: TenantId) -> Result<Vec<Connection>, CoreError> {
        Ok(self.storage.connections().list(tenant).await?)
    }

    /// The connections of `org`, in slug order.
    pub async fn list_for_org(
        &self,
        tenant: TenantId,
        org: &Organization,
    ) -> Result<Vec<Connection>, CoreError> {
        Ok(self
            .storage
            .connections()
            .list_for_org(tenant, org.id)
            .await?)
    }

    /// The connection `id` of `tenant`; `NotFound` for another tenant's connection.
    pub async fn get(&self, tenant: TenantId, id: ConnectionId) -> Result<Connection, CoreError> {
        self.storage
            .connections()
            .get(tenant, id)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// The connection `id` as seen by `owner`: an organization sees only its own connections
    /// (`NotFound` for every other one); the tenant sees all.
    pub async fn get_owned(
        &self,
        tenant: TenantId,
        owner: ConnectionOwner<'_>,
        id: ConnectionId,
    ) -> Result<Connection, CoreError> {
        let conn = self.get(tenant, id).await?;
        match owner {
            ConnectionOwner::Org(org) if conn.org_id != Some(org.id) => Err(CoreError::NotFound),
            _ => Ok(conn),
        }
    }

    /// The connection `owner` may change: its own, and for the tenant only tenant-level ones (an
    /// organization's connection is managed through the organization, `Conflict`).
    async fn get_mutable(
        &self,
        tenant: TenantId,
        owner: ConnectionOwner<'_>,
        id: ConnectionId,
    ) -> Result<Connection, CoreError> {
        let conn = self.get_owned(tenant, owner, id).await?;
        if matches!(owner, ConnectionOwner::Tenant) && conn.org_id.is_some() {
            return Err(CoreError::Conflict(
                "this connection belongs to an organization; change it under the \
                 organization's connections"
                    .into(),
            ));
        }
        Ok(conn)
    }

    /// Validates and creates a tenant-level connection (secret sealed before it is stored).
    /// Audited as `connection_created`; a duplicate slug is `Conflict`.
    pub async fn create(
        &self,
        tenant: TenantId,
        input: NewConnectionInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Connection, CoreError> {
        self.create_as(tenant, ConnectionOwner::Tenant, input, actor, ctx)
            .await
    }

    /// [`Self::create`] for `owner`. An organization's connection is OIDC or SAML; SAML needs
    /// the operator flag (`FeatureDisabled`) and an organization (422 at tenant level).
    pub async fn create_as(
        &self,
        tenant: TenantId,
        owner: ConnectionOwner<'_>,
        input: NewConnectionInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Connection, CoreError> {
        let now = truncate_to_ms(self.clock.now());
        let (new, risk) = plan_create_for(&self.kek, tenant, owner.org_id(), input, now)?;
        if new.config.kind() == ConnectionKind::Saml {
            self.require_saml()?;
        }
        if new.enabled {
            self.check_enable(&new.config, new.secret_enc.is_some())
                .await?;
        }
        let conn = self
            .storage
            .connections()
            .create(tenant, &new)
            .await
            .map_err(|e| match e {
                StorageError::Conflict(_) => {
                    CoreError::Conflict("a connection with this slug already exists".into())
                }
                other => other.into(),
            })?;
        let extra = if risk {
            AuditDetails::reason("email_trust_risk_accepted")
        } else {
            AuditDetails::empty()
        };
        self.record(
            &conn,
            owner,
            actor,
            AuditAction::ConnectionCreated,
            ctx,
            extra,
        )
        .await?;
        Ok(conn)
    }

    /// Applies a patch to a tenant-level connection (slug and kind are fixed). Audited as
    /// `connection_updated` with the changed field names.
    pub async fn update(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        patch: ConnectionPatch,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Connection, CoreError> {
        self.update_as(tenant, ConnectionOwner::Tenant, id, patch, actor, ctx)
            .await
    }

    /// [`Self::update`] for `owner`. Every change to a SAML connection except disabling it needs
    /// the operator flag.
    pub async fn update_as(
        &self,
        tenant: TenantId,
        owner: ConnectionOwner<'_>,
        id: ConnectionId,
        patch: ConnectionPatch,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Connection, CoreError> {
        let current = self.get_mutable(tenant, owner, id).await?;
        if current.kind() == ConnectionKind::Saml && !only_disables(&patch) {
            self.require_saml()?;
        }
        let (update, fields, risk) = plan_update(&current, patch)?;
        let enabled_after = update.enabled.unwrap_or(current.enabled);
        if enabled_after && (update.enabled == Some(true) || update.config.is_some()) {
            let config = update.config.as_ref().unwrap_or(&current.config);
            self.check_enable(config, current.secret_enc.is_some())
                .await?;
        }
        let conn = self
            .storage
            .connections()
            .update(tenant, id, &update, truncate_to_ms(self.clock.now()))
            .await?
            .ok_or(CoreError::NotFound)?;
        let mut extra = AuditDetails::fields(&fields);
        if risk {
            extra = extra.with(AuditDetails::reason("email_trust_risk_accepted"));
        }
        self.record(
            &conn,
            owner,
            actor,
            AuditAction::ConnectionUpdated,
            ctx,
            extra,
        )
        .await?;
        Ok(conn)
    }

    /// Replaces (`Some`, validated and sealed) or clears (`None`) the secret of a tenant-level
    /// connection. Audited as `connection_secret_rotated` (reason `cleared` when cleared); never
    /// with the secret.
    pub async fn set_secret(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        secret: Option<SecretString>,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Connection, CoreError> {
        self.set_secret_as(tenant, ConnectionOwner::Tenant, id, secret, actor, ctx)
            .await
    }

    /// [`Self::set_secret`] for `owner`. A SAML connection has no secret (422).
    pub async fn set_secret_as(
        &self,
        tenant: TenantId,
        owner: ConnectionOwner<'_>,
        id: ConnectionId,
        secret: Option<SecretString>,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Connection, CoreError> {
        let current = self.get_mutable(tenant, owner, id).await?;
        if current.kind() == ConnectionKind::Saml {
            return Err(no_saml_secret());
        }
        let sealed = match &secret {
            None => None,
            Some(s) => {
                validate_secret(current.kind(), s)?;
                Some(seal_secret(&self.kek, tenant, id, s)?)
            }
        };
        if !self
            .storage
            .connections()
            .set_secret(
                tenant,
                id,
                sealed.as_deref(),
                truncate_to_ms(self.clock.now()),
            )
            .await?
        {
            return Err(CoreError::NotFound);
        }
        let conn = self.get(tenant, id).await?;
        let extra = if secret.is_none() {
            AuditDetails::reason("cleared")
        } else {
            AuditDetails::empty()
        };
        self.record(
            &conn,
            owner,
            actor,
            AuditAction::ConnectionSecretRotated,
            ctx,
            extra,
        )
        .await?;
        Ok(conn)
    }

    /// Deletes a tenant-level connection and its identity links. Audited as
    /// `connection_deleted`.
    pub async fn delete(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        self.delete_as(tenant, ConnectionOwner::Tenant, id, actor, ctx)
            .await
    }

    /// [`Self::delete`] for `owner` (also for SAML with the flag off). Domains routed to the
    /// connection keep their claim and lose the routing target (storage).
    pub async fn delete_as(
        &self,
        tenant: TenantId,
        owner: ConnectionOwner<'_>,
        id: ConnectionId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let current = self.get_mutable(tenant, owner, id).await?;
        if !self.storage.connections().delete(tenant, id).await? {
            return Err(CoreError::NotFound);
        }
        self.record(
            &current,
            owner,
            actor,
            AuditAction::ConnectionDeleted,
            ctx,
            AuditDetails::empty(),
        )
        .await
    }

    /// Parses pasted or fetched IdP metadata (`md:EntityDescriptor`) into the values an
    /// administrator may import. Needs the operator flag; persists nothing. The error names the
    /// adapter's reason code only.
    pub fn parse_idp_metadata(
        &self,
        field: &'static str,
        xml: &[u8],
    ) -> Result<IdpMetadata, CoreError> {
        self.require_saml()?;
        let parser = self
            .saml_xml
            .as_ref()
            .ok_or_else(|| CoreError::Internal("no SAML XML adapter configured".into()))?;
        parser
            .parse_metadata(xml)
            .map_err(|reason| CoreError::Validation {
                field,
                message: format!("is not usable SAML IdP metadata ({reason})"),
            })
    }

    /// The plaintext secret of `conn` (`None` when none is configured). This is the only place
    /// a connection secret is opened (used by the upstream sign-in flow, 04-21); callers must
    /// not log, store or return it. A secret sealed for another tenant or connection does not
    /// open (`Internal`, without the value).
    pub fn open_secret(&self, conn: &Connection) -> Result<Option<SecretString>, CoreError> {
        open_sealed(&self.kek, conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppleConfig;
    use anvil_jose::encoding::b64std;

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn social(provider: SocialProvider) -> SocialConfig {
        SocialConfig {
            provider,
            client_id: "client-123".into(),
            scopes: vec![],
            endpoints: EndpointOverrides::default(),
            microsoft_tenant: None,
            allowed_tenants: vec![],
            hosted_domains: vec![],
            apple: (provider == SocialProvider::Apple).then(|| AppleConfig {
                team_id: "TEAM123456".into(),
                key_id: "KEY1234567".into(),
            }),
        }
    }

    fn input(slug: &str, config: ConnectionConfig, secret: Option<&str>) -> NewConnectionInput {
        NewConnectionInput {
            slug: slug.into(),
            display_name: "Upstream".into(),
            enabled: true,
            config,
            secret: secret.map(|s| SecretString::from(s.to_owned())),
            trust_email_verified: None,
            accept_email_trust_risk: false,
        }
    }

    fn field(r: Result<impl Sized, CoreError>) -> &'static str {
        match r {
            Err(CoreError::Validation { field, .. }) => field,
            Err(other) => panic!("expected a validation error, got {other:?}"),
            Ok(_) => panic!("expected a validation error, got Ok"),
        }
    }

    fn pem_of(der: &[u8]) -> String {
        let b64 = b64std(der);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem
    }

    fn es256_pem() -> String {
        pem_of(&anvil_jose::generate(Alg::ES256).unwrap().pkcs8)
    }

    fn row(tenant: TenantId, new: &NewConnection) -> Connection {
        Connection {
            id: new.id,
            tenant_id: tenant,
            slug: new.slug.clone(),
            display_name: new.display_name.clone(),
            enabled: new.enabled,
            config: new.config.clone(),
            secret_enc: new.secret_enc.clone(),
            trust_email_verified: new.trust_email_verified,
            created_at: new.created_at,
            updated_at: new.created_at,
            org_id: None,
        }
    }

    fn service(kek: Kek) -> impl Fn(&Connection) -> Result<Option<SecretString>, CoreError> {
        move |c| open_sealed(&kek, c)
    }

    #[test]
    fn secret_is_sealed_with_tenant_and_connection_aad() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let cfg = ConnectionConfig::Social(social(SocialProvider::Google));
        let (new, _) =
            plan_create(&kek, tenant, input("google", cfg, Some("s3cr3t")), now()).unwrap();
        let sealed = new.secret_enc.clone().expect("sealed");
        assert!(
            !sealed.windows(6).any(|w| w == b"s3cr3t"),
            "plaintext must not appear in the sealed bytes"
        );
        let opened = kek
            .open(
                CONNECTION_SECRET_PURPOSE,
                &connection_aad(tenant, new.id),
                &sealed,
            )
            .unwrap();
        assert_eq!(&opened[..], b"s3cr3t");
        assert!(
            kek.open(
                CONNECTION_SECRET_PURPOSE,
                &connection_aad(TenantId::new_v7(), new.id),
                &sealed
            )
            .is_err(),
            "another tenant's AAD must not open it"
        );
        assert!(
            kek.open(
                CONNECTION_SECRET_PURPOSE,
                &connection_aad(tenant, ConnectionId::new_v7()),
                &sealed
            )
            .is_err(),
            "another connection's AAD must not open it"
        );

        // open_secret: round trip, None without secret, generic error when moved.
        let open = service(kek);
        let conn = row(tenant, &new);
        assert_eq!(open(&conn).unwrap().unwrap().expose_secret(), "s3cr3t");
        let mut moved = conn.clone();
        moved.tenant_id = TenantId::new_v7();
        let err = open(&moved).unwrap_err();
        assert!(!format!("{err:?}").contains("s3cr3t"));
        let mut none = conn;
        none.secret_enc = None;
        assert!(open(&none).unwrap().is_none());
    }

    #[test]
    fn slug_syntax() {
        for ok in ["g", "google", "my-idp-2", "0", &"a".repeat(63)] {
            assert!(validate_connection_slug(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-google",
            "Google",
            "go_ogle",
            "go/ogle",
            "go ogle",
            "é",
            &"a".repeat(64),
        ] {
            assert_eq!(field(validate_connection_slug(bad)), "slug", "{bad:?}");
        }
    }

    #[test]
    fn oidc_issuer_must_be_https_or_loopback_http() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let oidc = |issuer: &str| {
            ConnectionConfig::Oidc(OidcConfig {
                issuer: issuer.into(),
                client_id: "c".into(),
                scopes: vec![],
                use_pkce: true,
                fetch_userinfo: false,
            })
        };
        for bad in [
            "http://example.com",
            "ftp://idp.example",
            "idp.example",
            "https://user:pw@idp.example",
            "https://idp.example/#frag",
            "https://idp.example/?q=1",
            "https://idp .example",
            "",
        ] {
            assert_eq!(
                field(plan_create(&kek, t, input("o", oidc(bad), None), now())),
                "config.issuer",
                "{bad:?}"
            );
        }
        for ok in [
            "https://idp.example",
            "https://idp.example/realms/a",
            "http://127.0.0.1:9000",
            "http://localhost:8080/idp",
            "http://[::1]:9000",
        ] {
            assert!(
                plan_create(&kek, t, input("o", oidc(ok), None), now()).is_ok(),
                "{ok}"
            );
        }
    }

    #[test]
    fn endpoint_overrides_and_oauth2_endpoints_are_checked() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let mut g = social(SocialProvider::Google);
        g.endpoints.token_endpoint = Some("http://10.0.0.1/token".into());
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("g", ConnectionConfig::Social(g), None),
                now()
            )),
            "config.endpoints.token_endpoint"
        );

        let oauth2 = |userinfo: &str, subject: &str| {
            ConnectionConfig::Oauth2(OAuth2Config {
                authorization_endpoint: "https://a.example/auth".into(),
                token_endpoint: "https://a.example/token".into(),
                userinfo_endpoint: userinfo.into(),
                client_id: "c".into(),
                scopes: vec!["read".into()],
                use_pkce: true,
                mapping: ClaimMapping {
                    subject: subject.into(),
                    email: None,
                    email_verified: None,
                    name: None,
                },
            })
        };
        assert!(
            plan_create(
                &kek,
                t,
                input("a", oauth2("https://a.example/me", "/id"), None),
                now()
            )
            .is_ok()
        );
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("a", oauth2("http://a.example/me", "/id"), None),
                now()
            )),
            "config.userinfo_endpoint"
        );
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("a", oauth2("https://a.example/me", "id"), None),
                now()
            )),
            "config.mapping.subject"
        );
    }

    #[test]
    fn provider_options_belong_to_their_provider() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let mut g = social(SocialProvider::Github);
        g.hosted_domains = vec!["example.com".into()];
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("x", ConnectionConfig::Social(g), None),
                now()
            )),
            "config.hosted_domains"
        );
        let mut m = social(SocialProvider::Microsoft);
        m.microsoft_tenant = Some("not a tenant".into());
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("x", ConnectionConfig::Social(m), None),
                now()
            )),
            "config.microsoft_tenant"
        );
        let mut g2 = social(SocialProvider::Google);
        g2.apple = Some(AppleConfig {
            team_id: "T".into(),
            key_id: "K".into(),
        });
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("x", ConnectionConfig::Social(g2), None),
                now()
            )),
            "config.apple"
        );
        let mut s = social(SocialProvider::Google);
        s.scopes = vec!["bad scope".into()];
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("x", ConnectionConfig::Social(s), None),
                now()
            )),
            "config.scopes"
        );
        let mut c = social(SocialProvider::Google);
        c.client_id = String::new();
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("x", ConnectionConfig::Social(c), None),
                now()
            )),
            "config.client_id"
        );
    }

    #[test]
    fn apple_needs_team_key_and_an_es256_pkcs8_key() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let apple = || ConnectionConfig::Social(social(SocialProvider::Apple));
        let pem = es256_pem();
        let (new, _) = plan_create(&kek, t, input("apple", apple(), Some(&pem)), now()).unwrap();
        assert!(new.secret_enc.is_some());
        assert!(
            new.trust_email_verified,
            "Apple trusts verified email by default"
        );

        let mut no_team = social(SocialProvider::Apple);
        no_team.apple = None;
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("a", ConnectionConfig::Social(no_team), Some(&pem)),
                now()
            )),
            "config.apple"
        );
        let mut empty_key_id = social(SocialProvider::Apple);
        empty_key_id.apple = Some(AppleConfig {
            team_id: "TEAM123456".into(),
            key_id: String::new(),
        });
        assert_eq!(
            field(plan_create(
                &kek,
                t,
                input("a", ConnectionConfig::Social(empty_key_id), Some(&pem)),
                now()
            )),
            "config.apple.key_id"
        );

        let rsa = pem_of(&anvil_jose::generate(Alg::RS256).unwrap().pkcs8);
        let ed = pem_of(&anvil_jose::generate(Alg::Ed25519).unwrap().pkcs8);
        let wrong_label = pem.replace("PRIVATE KEY", "EC PRIVATE KEY");
        let junk = format!("junk\n{pem}");
        for bad in [rsa.as_str(), &ed, &wrong_label, &junk, "not a pem", "x"] {
            let err = plan_create(&kek, t, input("a", apple(), Some(bad)), now()).unwrap_err();
            match &err {
                CoreError::Validation { field, message } => {
                    assert_eq!(*field, "secret");
                    assert!(!message.contains("BEGIN"), "no key material in the message");
                }
                other => panic!("unexpected {other:?}"),
            }
            assert!(!format!("{err:?}").contains("BEGIN"));
        }
    }

    #[test]
    fn plain_secrets_are_bounded() {
        let g = ConnectionKind::Google;
        assert!(validate_secret(g, &SecretString::from("abc".to_owned())).is_ok());
        assert_eq!(
            field(validate_secret(g, &SecretString::from(String::new()))),
            "secret"
        );
        assert_eq!(
            field(validate_secret(g, &SecretString::from("a\nb".to_owned()))),
            "secret"
        );
        assert_eq!(
            field(validate_secret(g, &SecretString::from("a".repeat(1025)))),
            "secret"
        );
    }

    #[test]
    fn email_trust_defaults_per_kind_and_microsoft_needs_the_flag() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        for (p, trusted) in [
            (SocialProvider::Google, true),
            (SocialProvider::Github, true),
            (SocialProvider::Microsoft, false),
        ] {
            let (new, risk) = plan_create(
                &kek,
                t,
                input("x", ConnectionConfig::Social(social(p)), None),
                now(),
            )
            .unwrap();
            assert_eq!(new.trust_email_verified, trusted, "{p:?}");
            assert!(!risk);
        }
        let ms = || ConnectionConfig::Social(social(SocialProvider::Microsoft));
        let mut i = input("ms", ms(), None);
        i.trust_email_verified = Some(true);
        assert_eq!(
            field(plan_create(&kek, t, i.clone(), now())),
            "trust_email_verified"
        );
        i.accept_email_trust_risk = true;
        let (new, risk) = plan_create(&kek, t, i, now()).unwrap();
        assert!(new.trust_email_verified && risk);

        // Update: turning trust on needs the flag; keeping it needs nothing.
        let (new, _) = plan_create(&kek, t, input("ms", ms(), None), now()).unwrap();
        let conn = row(t, &new);
        let on = ConnectionPatch {
            trust_email_verified: Some(true),
            ..ConnectionPatch::default()
        };
        assert_eq!(
            field(plan_update(&conn, on.clone())),
            "trust_email_verified"
        );
        let (u, fields, risk) = plan_update(
            &conn,
            ConnectionPatch {
                accept_email_trust_risk: true,
                ..on
            },
        )
        .unwrap();
        assert_eq!(u.trust_email_verified, Some(true));
        assert_eq!(fields, vec!["trust_email_verified"]);
        assert!(risk);
        // Generic OIDC may be trusted without the flag (the operator controls the IdP).
        let oidc = ConnectionConfig::Oidc(OidcConfig {
            issuer: "https://idp.example".into(),
            client_id: "c".into(),
            scopes: vec![],
            use_pkce: true,
            fetch_userinfo: false,
        });
        let mut o = input("o", oidc, None);
        o.trust_email_verified = Some(true);
        assert!(
            plan_create(&kek, t, o, now())
                .unwrap()
                .0
                .trust_email_verified
        );
    }

    #[test]
    fn update_keeps_kind_and_lists_changed_fields() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let (new, _) = plan_create(
            &kek,
            t,
            input(
                "g",
                ConnectionConfig::Social(social(SocialProvider::Google)),
                None,
            ),
            now(),
        )
        .unwrap();
        let conn = row(t, &new);
        let to_github = ConnectionPatch {
            config: Some(ConnectionConfig::Social(social(SocialProvider::Github))),
            ..ConnectionPatch::default()
        };
        assert_eq!(field(plan_update(&conn, to_github)), "config");
        let (u, fields, _) = plan_update(
            &conn,
            ConnectionPatch {
                display_name: Some("  Google  ".into()),
                enabled: Some(false),
                ..ConnectionPatch::default()
            },
        )
        .unwrap();
        assert_eq!(u.display_name.as_deref(), Some("Google"));
        assert_eq!(fields, vec!["display_name", "enabled"]);
        assert_eq!(
            field(plan_update(
                &conn,
                ConnectionPatch {
                    display_name: Some(" ".into()),
                    ..ConnectionPatch::default()
                }
            )),
            "display_name"
        );
    }

    #[test]
    fn debug_of_inputs_hides_the_secret() {
        let i = input(
            "g",
            ConnectionConfig::Social(social(SocialProvider::Google)),
            Some("very-secret-value"),
        );
        assert!(!format!("{i:?}").contains("very-secret-value"));
    }

    const CERT: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ==\n-----END CERTIFICATE-----\n";

    fn saml() -> ConnectionConfig {
        ConnectionConfig::Saml(SamlConfig {
            idp_entity_id: "https://idp.example.test/entity".into(),
            sso_url: "https://idp.example.test/sso".into(),
            signing_certs: vec![CERT.into()],
            name_id_format: crate::model::NameIdFormat::Persistent,
            attributes: crate::model::SamlAttributeMapping::default(),
            metadata_url: None,
        })
    }

    fn oidc_config() -> ConnectionConfig {
        ConnectionConfig::Oidc(OidcConfig {
            issuer: "https://idp.example.test".into(),
            client_id: "client-123".into(),
            scopes: vec![],
            use_pkce: true,
            fetch_userinfo: false,
        })
    }

    #[test]
    fn saml_is_refused_at_tenant_level() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        assert_eq!(field(validate_config(&saml())), "config");
        assert_eq!(
            field(plan_create(&kek, t, input("s", saml(), None), now())),
            "config"
        );
    }

    #[test]
    fn org_connections_are_oidc_or_saml() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let org = Some(OrgId::new_v7());
        let (new, _) = plan_create_for(&kek, t, org, input("s", saml(), None), now()).unwrap();
        assert_eq!(new.org_id, org);
        let (new, _) =
            plan_create_for(&kek, t, org, input("o", oidc_config(), Some("x")), now()).unwrap();
        assert_eq!(new.org_id, org);
        let social = ConnectionConfig::Social(social(SocialProvider::Google));
        assert_eq!(
            field(plan_create_for(
                &kek,
                t,
                org,
                input("g", social, None),
                now()
            )),
            "config"
        );
    }

    type Mutation = dyn Fn(&mut SamlConfig);

    #[test]
    fn saml_rules_name_config_fields_and_refuse_a_secret() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let org = Some(OrgId::new_v7());
        let with = |f: &dyn Fn(&mut SamlConfig)| {
            let ConnectionConfig::Saml(mut c) = saml() else {
                unreachable!()
            };
            f(&mut c);
            ConnectionConfig::Saml(c)
        };
        let cases: [(&Mutation, &str); 5] = [
            (
                &|c| c.sso_url = "http://idp.example.test/sso".into(),
                "config.sso_url",
            ),
            (
                &|c| c.signing_certs = vec![CERT.into(); 4],
                "config.signing_certs",
            ),
            (
                &|c| c.signing_certs = vec!["not a cert".into()],
                "config.signing_certs",
            ),
            (&|c| c.idp_entity_id = " ".into(), "config.idp_entity_id"),
            (
                &|c| c.name_id_format = crate::model::NameIdFormat::Transient,
                "config.name_id_format",
            ),
        ];
        for (mutate, expected) in cases {
            assert_eq!(
                field(plan_create_for(
                    &kek,
                    t,
                    org,
                    input("s", with(mutate), None),
                    now()
                )),
                expected
            );
        }
        assert_eq!(
            field(plan_create_for(
                &kek,
                t,
                org,
                input("s", saml(), Some("x")),
                now()
            )),
            "secret"
        );
    }

    #[test]
    fn only_disabling_counts_as_disabling() {
        let off = ConnectionPatch {
            enabled: Some(false),
            ..ConnectionPatch::default()
        };
        assert!(only_disables(&off));
        assert!(!only_disables(&ConnectionPatch::default()));
        assert!(!only_disables(&ConnectionPatch {
            enabled: Some(true),
            ..ConnectionPatch::default()
        }));
        assert!(!only_disables(&ConnectionPatch {
            display_name: Some("x".into()),
            ..off
        }));
    }

    /// A discovery port answering with a fixed result (test double; the real adapter is tested
    /// in anvil-web's `security_connection_enable`).
    struct FixedDiscovery(Result<(), UpstreamError>, std::sync::Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl UpstreamClient for FixedDiscovery {
        async fn metadata(
            &self,
            issuer: &str,
        ) -> Result<crate::ports::ProviderMetadata, UpstreamError> {
            self.1.lock().unwrap().push(issuer.to_owned());
            self.0.clone().map(|()| crate::ports::ProviderMetadata {
                issuer: issuer.to_owned(),
                authorization_endpoint: format!("{issuer}/authorize"),
                token_endpoint: format!("{issuer}/token"),
                userinfo_endpoint: None,
                jwks_uri: format!("{issuer}/jwks"),
                id_token_signing_alg_values_supported: vec!["RS256".into()],
                authorization_response_iss_parameter_supported: false,
                code_challenge_methods_supported: vec!["S256".into()],
            })
        }
        async fn jwks(&self, _: &str, _: bool) -> Result<anvil_jose::Jwks, UpstreamError> {
            Err(UpstreamError::Network)
        }
        async fn exchange_code(
            &self,
            _: &crate::ports::CodeExchange,
        ) -> Result<crate::ports::TokenSet, UpstreamError> {
            Err(UpstreamError::Network)
        }
        async fn get_json(
            &self,
            _: &str,
            _: &SecretString,
            _: crate::ports::ApiProfile,
        ) -> Result<serde_json::Value, UpstreamError> {
            Err(UpstreamError::Network)
        }
    }

    fn fixed(r: Result<(), UpstreamError>) -> FixedDiscovery {
        FixedDiscovery(r, std::sync::Mutex::new(Vec::new()))
    }

    fn field_of(e: CoreError) -> (&'static str, String) {
        match e {
            CoreError::Validation { field, message } => (field, message),
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enabling_needs_every_field_before_discovery_runs() {
        let ok = fixed(Ok(()));
        let cfg = oidc_config();
        let (field, _) = field_of(check_enable(&cfg, false, Some(&ok)).await.unwrap_err());
        assert_eq!(field, "secret");
        assert!(
            ok.1.lock().unwrap().is_empty(),
            "an incomplete connection is refused before anything is fetched"
        );
        check_enable(&cfg, true, Some(&ok)).await.expect("complete");
        assert_eq!(*ok.1.lock().unwrap(), ["https://idp.example.test"]);

        // Kinds without discovery need no port; generic OIDC without one cannot be checked.
        let google = ConnectionConfig::Social(social(SocialProvider::Google));
        check_enable(&google, true, None).await.expect("google");
        assert!(matches!(
            check_enable(&cfg, true, None).await,
            Err(CoreError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn failed_discovery_refuses_with_the_issuer_field_and_no_fetched_content() {
        let cfg = oidc_config();
        for (err, needle) in [
            (UpstreamError::Blocked, "not allowed"),
            (UpstreamError::Network, "could not be reached"),
            (UpstreamError::Timeout, "could not be reached"),
            (UpstreamError::Status(404), "HTTP 404"),
            (UpstreamError::TooLarge, "too large"),
            (
                UpstreamError::InvalidResponse("issuer mismatch"),
                "does not equal",
            ),
            (
                UpstreamError::InvalidResponse("malformed discovery document"),
                "not usable",
            ),
        ] {
            let (field, message) = field_of(
                check_enable(&cfg, true, Some(&fixed(Err(err.clone()))))
                    .await
                    .unwrap_err(),
            );
            assert_eq!(field, "config.issuer", "{err:?}");
            assert!(message.contains(needle), "{err:?}: {message}");
            assert!(!message.contains("idp.example"), "{message}");
        }
    }
}
