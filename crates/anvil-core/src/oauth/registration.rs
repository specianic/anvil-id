//! RFC 7591 dynamic client registration request validation (OIDC-17).
//!
//! [`validate`] is a pure function: it turns a registration request (the JSON body of
//! `POST /register`) into a [`ValidatedRegistration`] holding the exact [`ClientInput`] and
//! [`ClientOptions`] that `ClientService` stores, with every defaulted value substituted, or into an
//! RFC 7591 §3.2.2 error:
//!
//! - [`CoreError::InvalidSoftwareStatement`] for any `software_statement` (we do not verify them,
//!   so we do not silently accept their claims);
//! - [`CoreError::InvalidRedirectUri`] for a bad, missing or not allow-listed `redirect_uris` value;
//! - [`CoreError::InvalidClientMetadata`] for every other rule.
//!
//! The client rules themselves (name, auth method and grant consistency, inline JWKS, redirect URI
//! syntax, back-channel logout URI, RFC 8707 resource syntax) are the ones of
//! [`crate::service::client::validate_client`] and
//! [`crate::service::client::validate_client_phase4`], called here; this module only adds what is
//! specific to self-service registration:
//!
//! - unknown metadata is ignored (RFC 7591 §2 MUST); JSON `null` counts as absent;
//! - `application_type` `web` (default) needs https redirect URIs; `native` needs a loopback http
//!   or private-use scheme redirect URI (OpenID Connect Dynamic Client Registration 1.0 §2);
//! - `grant_types` ⊆ {`authorization_code`, `refresh_token`}, plus `client_credentials` only when
//!   [`DcrSettings::allow_client_credentials`] is set; default `authorization_code`;
//! - `response_types` ⊆ {`code`}, consistent with the grants (RFC 7591 §2.1); default `code` when
//!   `authorization_code` is registered;
//! - `token_endpoint_auth_method` ∈ {`none`, `client_secret_basic`, `client_secret_post`,
//!   `private_key_jwt`}, default `client_secret_basic` (RFC 7591 §2); `none` makes a public client;
//! - `jwks_uri` is rejected: no remote key fetching for dynamic clients in 0.4, so
//!   `private_key_jwt` needs an inline `jwks`;
//! - `scope` ⊆ [`DcrSettings::allowed_scopes`], never an `admin:` scope or `org:admin`; default:
//!   the allowed scopes;
//! - `allowed_resources` (RFC 8707) ⊆ [`DcrSettings::allowed_resources`]; default: all of them;
//! - in [`DcrMode::AllowListed`], when [`DcrSettings::allowed_redirect_hosts`] is not empty, every
//!   redirect and post-logout redirect URI host must be listed (a URI without host is refused);
//! - `backchannel_logout_uri` must be https; `consent_mode` is always `required` and PKCE is always
//!   required, whatever the request says;
//! - `require_pushed_authorization_requests` (RFC 9126 §6) is a boolean, default `false`, stored
//!   and echoed;
//! - `client_kind` and `headless_native` are administrator-only fields: like every other unknown
//!   member they are ignored, never mapped, and the result always carries `application` and
//!   `false`. [`crate::service::client::validate_client_policy`] runs with source `dynamic` as
//!   for every client write;
//! - `client_name` and the informational `logo_uri`, `policy_uri`, `tos_uri` are length-capped,
//!   and the URIs must be absolute https URIs;
//! - `client_uri` and `initiate_login_uri` pass the shared
//!   [`crate::service::client::validate_client_home_uri`] (https only, no fragment) and are
//!   stored in [`ClientOptions`]; the end-user UI never renders them for a dynamic client.
//!
//! Callers resolve "empty `allowed_scopes` means the tenant defaults" before calling: here an empty
//! list allows no scope at all (fail closed).

use serde_json::{Map, Value};

use crate::error::CoreError;
use crate::model::{
    ApplicationType, ClientAuthMethod, ClientKind, ClientSource, ClientType, ConsentMode,
    DcrSettings, GrantType, Scope, TokenFormat,
};
use crate::oauth::redirect::{MAX_REDIRECT_URI_LEN, validate_redirect_uri};
use crate::oauth::resource::parse_resources;
use crate::service::admin_scope::{ORG_ADMIN_SCOPE, is_reserved_admin_token};
use crate::service::client::{
    ClientInput, ClientOptions, ClientPolicyView, MAX_REDIRECT_URIS, validate_client,
    validate_client_home_uri, validate_client_phase4, validate_client_policy,
};

/// Whether a scope token can never be obtained by self-registration (DCR, CIMD, and the tenant's
/// `dcr.allowed_scopes`): the reserved admin API tokens ([`is_reserved_admin_token`]) and the
/// organization admin scope [`ORG_ADMIN_SCOPE`] (decision Q1: only static clients of application
/// tenants may hold it).
pub fn is_registration_forbidden_scope(token: &str) -> bool {
    is_reserved_admin_token(token) || token == ORG_ADMIN_SCOPE
}

/// Name given to a registered client that sent no `client_name`.
pub const DEFAULT_CLIENT_NAME: &str = "Dynamically registered client";

/// Longest accepted `logo_uri`, `policy_uri` and `tos_uri` (`client_uri` and
/// `initiate_login_uri`: [`crate::service::client::MAX_HOME_URI_LEN`], the same value).
pub const MAX_METADATA_URI_LEN: usize = MAX_REDIRECT_URI_LEN;

/// The registration policy the request arrived under. A disabled policy never reaches validation
/// (the endpoint does not exist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcrMode {
    /// Initial access token presented; the redirect-host allow-list applies when set.
    AllowListed,
    /// Anyone may register; the redirect-host allow-list does not apply.
    Open,
}

/// A registration request that passed every rule, with defaults substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRegistration {
    /// What `ClientService::create` stores. `jwks_uri` is always `None`, `require_pkce` is
    /// always `Some(true)`.
    pub client: ClientInput,
    /// Client options. `consent_mode` is always [`ConsentMode::Required`]; `client_uri` and
    /// `initiate_login_uri` are the validated request values.
    pub options: ClientOptions,
    /// The `client_name` as sent (trimmed); `None` when absent ([`DEFAULT_CLIENT_NAME`] is
    /// stored instead).
    pub client_name: Option<String>,
    /// Registered `response_types` (`["code"]` or empty).
    pub response_types: Vec<String>,
    /// Informational metadata, validated and echoed in the response; never fetched.
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
}

impl ValidatedRegistration {
    /// The registered client metadata for the RFC 7591 §3.2.1 response, with every substituted
    /// value (without `client_id`, secrets or registration-access fields, which the service adds).
    pub fn metadata(&self) -> Map<String, Value> {
        let c = &self.client;
        let o = &self.options;
        let strings = |v: &[String]| Value::Array(v.iter().cloned().map(Value::String).collect());
        let mut m = Map::new();
        m.insert("redirect_uris".into(), strings(&c.redirect_uris));
        m.insert(
            "token_endpoint_auth_method".into(),
            c.auth_method.as_str().into(),
        );
        m.insert(
            "grant_types".into(),
            Value::Array(c.grant_types.iter().map(|g| g.as_str().into()).collect()),
        );
        m.insert("response_types".into(), strings(&self.response_types));
        m.insert(
            "application_type".into(),
            c.application_type.as_str().into(),
        );
        m.insert("scope".into(), c.scopes.join(" ").into());
        m.insert("allowed_resources".into(), strings(&o.allowed_resources));
        m.insert(
            "require_pushed_authorization_requests".into(),
            o.require_pushed_authorization_requests.into(),
        );
        if let Some(name) = &self.client_name {
            m.insert("client_name".into(), name.clone().into());
        }
        if let Some(jwks) = c.jwks.as_deref().and_then(|j| serde_json::from_str(j).ok()) {
            m.insert("jwks".into(), jwks);
        }
        if !o.post_logout_redirect_uris.is_empty() {
            m.insert(
                "post_logout_redirect_uris".into(),
                strings(&o.post_logout_redirect_uris),
            );
        }
        if let Some(uri) = &o.backchannel_logout_uri {
            m.insert("backchannel_logout_uri".into(), uri.clone().into());
            m.insert(
                "backchannel_logout_session_required".into(),
                o.backchannel_logout_session_required.into(),
            );
        }
        for (key, value) in [
            ("logo_uri", &self.logo_uri),
            ("client_uri", &o.client_uri),
            ("initiate_login_uri", &o.initiate_login_uri),
            ("policy_uri", &self.policy_uri),
            ("tos_uri", &self.tos_uri),
        ] {
            if let Some(v) = value {
                m.insert(key.into(), v.clone().into());
            }
        }
        m
    }
}

fn meta(message: impl Into<String>) -> CoreError {
    CoreError::InvalidClientMetadata(message.into())
}

fn redirect_error(message: impl Into<String>) -> CoreError {
    CoreError::InvalidRedirectUri(message.into())
}

/// A metadata member; JSON `null` counts as absent.
fn member<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    obj.get(key).filter(|v| !v.is_null())
}

fn opt_str<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, CoreError> {
    match member(obj, key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(meta(format!("{key} must be a string"))),
    }
}

fn opt_bool(obj: &Map<String, Value>, key: &str) -> Result<Option<bool>, CoreError> {
    match member(obj, key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(meta(format!("{key} must be a boolean"))),
    }
}

fn opt_str_array(
    obj: &Map<String, Value>,
    key: &str,
    error: fn(String) -> CoreError,
) -> Result<Option<Vec<String>>, CoreError> {
    let Some(value) = member(obj, key) else {
        return Ok(None);
    };
    let not_strings = || error(format!("{key} must be an array of strings"));
    let items = value.as_array().ok_or_else(not_strings)?;
    items
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or_else(not_strings))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

/// The shared redirect URI rules plus the application-type rule of OIDC Dynamic Client
/// Registration 1.0 §2: web clients use https only (no loopback http), native clients use a
/// loopback http or private-use scheme URI (never https). Returns the error message.
fn check_redirect(uri: &str, app: ApplicationType) -> Result<(), String> {
    validate_redirect_uri(uri, app).map_err(|e| match e {
        CoreError::Validation { message, .. } => message,
        other => other.to_string(),
    })?;
    // `validate_redirect_uri` succeeded, so the URI parses.
    let scheme = url::Url::parse(uri)
        .map(|u| u.scheme().to_owned())
        .unwrap_or_default();
    match (app, scheme.as_str()) {
        (ApplicationType::Web, "https") => Ok(()),
        (ApplicationType::Web, _) => Err("web clients must use https redirect URIs".to_owned()),
        (ApplicationType::Native, "https") => Err(
            "native clients must use a loopback http or a private-use scheme redirect URI"
                .to_owned(),
        ),
        (ApplicationType::Native, _) => Ok(()),
    }
}

/// Whether the URI's host is on the allow-list (ASCII case-insensitive). URIs without a host
/// (private-use schemes) are never allow-listed.
fn host_allowed(uri: &str, allowed: &[String]) -> bool {
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    match parsed.host_str() {
        Some(host) if !host.is_empty() => allowed.iter().any(|a| a.eq_ignore_ascii_case(host)),
        _ => false,
    }
}

/// `logo_uri`, `policy_uri`, `tos_uri`: absolute https, with a host, no userinfo,
/// no whitespace, at most [`MAX_METADATA_URI_LEN`] bytes.
fn check_https_uri(key: &str, value: &str) -> Result<(), CoreError> {
    let bad = || meta(format!("{key} must be an absolute https URI"));
    if value.is_empty()
        || value.len() > MAX_METADATA_URI_LEN
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(bad());
    }
    let parsed = url::Url::parse(value).map_err(|_| bad())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none_or(str::is_empty)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(bad());
    }
    Ok(())
}

/// Maps a `ClientService` validation error to its RFC 7591 error.
fn map_client_error(e: CoreError) -> CoreError {
    match e {
        CoreError::Validation {
            field: "redirect_uris",
            message,
        } => redirect_error(message),
        CoreError::Validation { field, message } => meta(format!("{field}: {message}")),
        other => meta(other.to_string()),
    }
}

/// Validates an RFC 7591 registration request. Pure: no I/O, no clock, no randomness.
pub fn validate(
    request: &Value,
    settings: &DcrSettings,
    mode: DcrMode,
) -> Result<ValidatedRegistration, CoreError> {
    let obj = request
        .as_object()
        .ok_or_else(|| meta("the registration request must be a JSON object"))?;

    // RFC 7591 §3.2.2: we verify no software statements, so we accept none.
    if member(obj, "software_statement").is_some() {
        return Err(CoreError::InvalidSoftwareStatement);
    }
    // 0.4: no remote key fetching for dynamic clients.
    if member(obj, "jwks_uri").is_some() {
        return Err(meta(
            "jwks_uri is not supported in this release; register the keys inline with jwks",
        ));
    }

    let application_type = match opt_str(obj, "application_type")? {
        None | Some("web") => ApplicationType::Web,
        Some("native") => ApplicationType::Native,
        Some(_) => return Err(meta("application_type must be web or native")),
    };

    let auth_method = match opt_str(obj, "token_endpoint_auth_method")? {
        None => ClientAuthMethod::ClientSecretBasic,
        Some(s) => ClientAuthMethod::parse(s)
            .ok_or_else(|| meta("token_endpoint_auth_method is not supported"))?,
    };
    let client_type = if auth_method == ClientAuthMethod::None {
        ClientType::Public
    } else {
        ClientType::Confidential
    };

    // Grants.
    let grant_names = opt_str_array(obj, "grant_types", meta)?
        .unwrap_or_else(|| vec![GrantType::AuthorizationCode.as_str().to_owned()]);
    if grant_names.is_empty() {
        return Err(meta("grant_types must not be empty"));
    }
    let mut grant_types: Vec<GrantType> = Vec::with_capacity(grant_names.len());
    for name in &grant_names {
        let grant = GrantType::parse(name)
            .ok_or_else(|| meta("grant_types contains an unsupported grant type"))?;
        if grant == GrantType::ClientCredentials && !settings.allow_client_credentials {
            return Err(meta(
                "client_credentials is not allowed for dynamically registered clients",
            ));
        }
        if !grant_types.contains(&grant) {
            grant_types.push(grant);
        }
    }
    let has_code_grant = grant_types.contains(&GrantType::AuthorizationCode);

    // Response types (RFC 7591 §2.1: `code` <-> `authorization_code`).
    let response_types = dedup(
        opt_str_array(obj, "response_types", meta)?.unwrap_or_else(|| {
            if has_code_grant {
                vec!["code".to_owned()]
            } else {
                Vec::new()
            }
        }),
    );
    if response_types.iter().any(|r| r != "code") {
        return Err(meta("response_types contains an unsupported response type"));
    }
    if response_types.is_empty() == has_code_grant {
        return Err(meta(
            "response_types and grant_types are inconsistent: code requires authorization_code and vice versa",
        ));
    }

    // Redirect URIs.
    let allow_list = match mode {
        DcrMode::AllowListed if !settings.allowed_redirect_hosts.is_empty() => {
            Some(settings.allowed_redirect_hosts.as_slice())
        }
        _ => None,
    };
    let raw_redirects = opt_str_array(obj, "redirect_uris", redirect_error)?.unwrap_or_default();
    if has_code_grant && raw_redirects.is_empty() {
        return Err(redirect_error(
            "redirect_uris is required for the authorization_code grant",
        ));
    }
    if raw_redirects.len() > MAX_REDIRECT_URIS {
        return Err(redirect_error("too many redirect URIs"));
    }
    for uri in &raw_redirects {
        check_redirect(uri, application_type).map_err(redirect_error)?;
        if let Some(hosts) = allow_list
            && !host_allowed(uri, hosts)
        {
            return Err(redirect_error(
                "redirect URI host is not on the registration allow-list",
            ));
        }
    }
    let redirect_uris = dedup(raw_redirects);

    let post_logout_redirect_uris =
        dedup(opt_str_array(obj, "post_logout_redirect_uris", meta)?.unwrap_or_default());
    for uri in &post_logout_redirect_uris {
        check_redirect(uri, application_type)
            .map_err(|m| meta(format!("post_logout_redirect_uris: {m}")))?;
        if let Some(hosts) = allow_list
            && !host_allowed(uri, hosts)
        {
            return Err(meta(
                "post_logout_redirect_uris: host is not on the registration allow-list",
            ));
        }
    }

    // Scopes.
    let scopes: Vec<String> = match opt_str(obj, "scope")? {
        Some(raw) => {
            Scope::parse(raw).map_err(|_| meta("scope is not a valid scope string"))?;
            let tokens = dedup(raw.split(' ').map(str::to_owned).collect());
            if tokens.iter().any(|t| is_registration_forbidden_scope(t)) {
                return Err(meta("admin scopes cannot be registered"));
            }
            if tokens.iter().any(|t| !settings.allowed_scopes.contains(t)) {
                return Err(meta(
                    "scope contains a value not allowed for dynamic registration",
                ));
            }
            tokens
        }
        None => dedup(
            settings
                .allowed_scopes
                .iter()
                .filter(|t| {
                    !is_registration_forbidden_scope(t)
                        && Scope::parse(t).is_ok()
                        && !t.contains(' ')
                })
                .cloned()
                .collect(),
        ),
    };

    // RFC 8707 resources.
    let allowed_resources = match opt_str_array(obj, "allowed_resources", meta)? {
        Some(requested) => {
            let parsed = parse_resources(&requested).map_err(|e| match e {
                CoreError::InvalidTarget(m) => meta(format!("allowed_resources: {m}")),
                other => meta(other.to_string()),
            })?;
            if parsed
                .iter()
                .any(|r| !settings.allowed_resources.contains(r))
            {
                return Err(meta(
                    "allowed_resources contains a resource not allowed for dynamic registration",
                ));
            }
            parsed
        }
        None => dedup(settings.allowed_resources.clone()),
    };

    // Keys: inline JWK Set object only.
    let jwks = match member(obj, "jwks") {
        None => None,
        Some(v @ Value::Object(_)) => Some(v.to_string()),
        Some(_) => return Err(meta("jwks must be a JWK Set object")),
    };

    // Back-channel logout: https only.
    let backchannel_logout_uri = opt_str(obj, "backchannel_logout_uri")?.map(str::to_owned);
    if let Some(uri) = &backchannel_logout_uri
        && url::Url::parse(uri)
            .map(|u| u.scheme() != "https")
            .unwrap_or(true)
    {
        return Err(meta("backchannel_logout_uri must be an https URI"));
    }
    let backchannel_logout_session_required =
        opt_bool(obj, "backchannel_logout_session_required")?.unwrap_or(false);
    // RFC 9126 §6 client metadata.
    let require_pushed_authorization_requests =
        opt_bool(obj, "require_pushed_authorization_requests")?.unwrap_or(false);

    // Display metadata.
    let client_name = match opt_str(obj, "client_name")? {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(meta("client_name must not be empty"));
            }
            Some(trimmed.to_owned())
        }
    };
    let mut info = [None, None, None];
    for (slot, key) in info.iter_mut().zip(["logo_uri", "policy_uri", "tos_uri"]) {
        if let Some(value) = opt_str(obj, key)? {
            check_https_uri(key, value)?;
            *slot = Some(value.to_owned());
        }
    }
    let [logo_uri, policy_uri, tos_uri] = info;
    // Home URLs: the one rule of every client write path, https only for DCR.
    let mut home = [None, None];
    for (slot, key) in home.iter_mut().zip(["client_uri", "initiate_login_uri"]) {
        if let Some(value) = opt_str(obj, key)? {
            validate_client_home_uri(key, value, false).map_err(map_client_error)?;
            *slot = Some(value.to_owned());
        }
    }
    let [client_uri, initiate_login_uri] = home;

    let client = ClientInput {
        name: client_name
            .clone()
            .unwrap_or_else(|| DEFAULT_CLIENT_NAME.to_owned()),
        client_type,
        application_type,
        auth_method,
        redirect_uris,
        grant_types,
        scopes,
        require_pkce: Some(true),
        jwks,
        jwks_uri: None,
    };
    let options = ClientOptions {
        token_format: TokenFormat::Jwt,
        consent_mode: ConsentMode::Required,
        id_token_signed_response_alg: None,
        can_introspect: false,
        post_logout_redirect_uris,
        backchannel_logout_uri,
        backchannel_logout_session_required,
        allowed_resources,
        mfa_policy: None,
        organization: crate::model::OrgClientPolicy::Off,
        require_pushed_authorization_requests,
        // Administrator-only fields: never taken from the request.
        client_kind: ClientKind::Application,
        headless_native: false,
        client_uri,
        initiate_login_uri,
    };

    // The client rules every client obeys (one implementation: `service::client`).
    validate_client(&client, validate_redirect_uri).map_err(map_client_error)?;
    validate_client_phase4(&client, &options, validate_redirect_uri).map_err(map_client_error)?;
    validate_client_policy(
        &ClientPolicyView::of(&client, &options),
        ClientSource::Dynamic,
    )
    .map_err(map_client_error)?;

    Ok(ValidatedRegistration {
        client,
        options,
        client_name,
        response_types,
        logo_uri,
        policy_uri,
        tos_uri,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    const PUBLIC_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;

    fn settings() -> DcrSettings {
        DcrSettings {
            allowed_scopes: ["openid", "profile", "email", "offline_access"]
                .map(String::from)
                .to_vec(),
            allowed_resources: vec!["https://mcp.example/".to_owned()],
            ..DcrSettings::default()
        }
    }

    fn open(req: Value) -> Result<ValidatedRegistration, CoreError> {
        validate(&req, &settings(), DcrMode::Open)
    }

    fn jwks() -> Value {
        serde_json::from_str(PUBLIC_JWKS).unwrap()
    }

    #[track_caller]
    fn assert_meta(r: Result<ValidatedRegistration, CoreError>) {
        match r {
            Err(CoreError::InvalidClientMetadata(_)) => {}
            other => panic!("expected invalid_client_metadata, got {other:?}"),
        }
    }

    #[track_caller]
    fn assert_redirect(r: Result<ValidatedRegistration, CoreError>) {
        match r {
            Err(CoreError::InvalidRedirectUri(_)) => {}
            other => panic!("expected invalid_redirect_uri, got {other:?}"),
        }
    }

    // ---- accepted requests and substituted values ----

    #[test]
    fn dcr_minimal_web_client_gets_rfc7591_defaults() {
        let v = open(json!({"redirect_uris": ["https://app.example/cb"]})).unwrap();
        assert_eq!(v.client.auth_method, ClientAuthMethod::ClientSecretBasic);
        assert_eq!(v.client.client_type, ClientType::Confidential);
        assert_eq!(v.client.application_type, ApplicationType::Web);
        assert_eq!(v.client.grant_types, vec![GrantType::AuthorizationCode]);
        assert_eq!(v.response_types, vec!["code".to_owned()]);
        assert_eq!(v.client.redirect_uris, vec!["https://app.example/cb"]);
        assert_eq!(v.client.name, DEFAULT_CLIENT_NAME);
        assert_eq!(v.client_name, None);
        assert_eq!(v.client.scopes, settings().allowed_scopes);
        assert_eq!(v.options.allowed_resources, settings().allowed_resources);
        assert_eq!(v.client.require_pkce, Some(true));
        assert_eq!(v.client.jwks_uri, None);
        assert_eq!(v.options.consent_mode, ConsentMode::Required);
        assert_eq!(v.options.token_format, TokenFormat::Jwt);
        assert!(!v.options.can_introspect);
    }

    #[test]
    fn dcr_metadata_lists_substituted_values() {
        let v = open(json!({"redirect_uris": ["https://app.example/cb"], "client_name": " App "}))
            .unwrap();
        let m = v.metadata();
        assert_eq!(m["token_endpoint_auth_method"], "client_secret_basic");
        assert_eq!(m["grant_types"], json!(["authorization_code"]));
        assert_eq!(m["response_types"], json!(["code"]));
        assert_eq!(m["application_type"], "web");
        assert_eq!(m["redirect_uris"], json!(["https://app.example/cb"]));
        assert_eq!(m["scope"], "openid profile email offline_access");
        assert_eq!(m["client_name"], "App");
        assert_eq!(m["allowed_resources"], json!(["https://mcp.example/"]));
        assert!(!m.contains_key("jwks_uri"));
    }

    #[test]
    fn dcr_full_public_native_client() {
        let v = open(json!({
            "application_type": "native",
            "redirect_uris": ["http://127.0.0.1:8080/cb", "com.example.app:/cb"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid offline_access",
            "allowed_resources": ["https://mcp.example/"],
            "client_name": "Desktop",
            "logo_uri": "https://app.example/logo.png",
            "client_uri": "https://app.example/",
            "policy_uri": "https://app.example/privacy",
            "tos_uri": "https://app.example/tos",
        }))
        .unwrap();
        assert_eq!(v.client.client_type, ClientType::Public);
        assert_eq!(v.client.application_type, ApplicationType::Native);
        assert_eq!(
            v.client.grant_types,
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
        );
        assert_eq!(v.client.scopes, vec!["openid", "offline_access"]);
        assert_eq!(v.client.name, "Desktop");
        assert_eq!(v.logo_uri.as_deref(), Some("https://app.example/logo.png"));
        assert_eq!(v.tos_uri.as_deref(), Some("https://app.example/tos"));
        assert_eq!(
            v.options.client_uri.as_deref(),
            Some("https://app.example/")
        );
        assert_eq!(v.metadata()["client_uri"], "https://app.example/");
    }

    #[test]
    fn dcr_unknown_metadata_is_ignored() {
        let v = open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "foo": {"bar": [1, 2]},
            "client_name#ja-Jpan-JP": "x",
            "consent_mode": "skip_first_party",
            "require_pkce": false,
            "can_introspect": true,
        }))
        .unwrap();
        assert_eq!(v.options.consent_mode, ConsentMode::Required);
        assert_eq!(v.client.require_pkce, Some(true));
        assert!(!v.options.can_introspect);
    }

    #[test]
    fn dcr_require_par_is_stored_and_echoed() {
        let v = open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "require_pushed_authorization_requests": true,
        }))
        .unwrap();
        assert!(v.options.require_pushed_authorization_requests);
        assert_eq!(v.metadata()["require_pushed_authorization_requests"], true);
        let default = open(json!({"redirect_uris": ["https://app.example/cb"]})).unwrap();
        assert!(!default.options.require_pushed_authorization_requests);
        assert_eq!(
            default.metadata()["require_pushed_authorization_requests"],
            false
        );
        for bad in [json!("yes"), json!(1), json!(["true"])] {
            assert_meta(open(json!({
                "redirect_uris": ["https://app.example/cb"],
                "require_pushed_authorization_requests": bad,
            })));
        }
    }

    #[test]
    fn client_kind_agent_refused_via_dcr_metadata_injection() {
        let v = open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "client_kind": "agent",
            "headless_native": true,
            "consent_mode": "skip_first_party",
        }))
        .unwrap();
        assert_eq!(v.options.client_kind, ClientKind::Application);
        assert!(!v.options.headless_native);
        assert_eq!(v.options.consent_mode, ConsentMode::Required);
        let m = v.metadata();
        assert!(m.get("client_kind").is_none() && m.get("headless_native").is_none());
    }

    #[test]
    fn dcr_null_counts_as_absent() {
        let v = open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "software_statement": null,
            "jwks_uri": null,
            "scope": null,
        }))
        .unwrap();
        assert_eq!(v.client.scopes, settings().allowed_scopes);
    }

    #[test]
    fn dcr_private_key_jwt_with_inline_jwks_is_accepted() {
        let v = open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks(),
        }))
        .unwrap();
        assert_eq!(v.client.auth_method, ClientAuthMethod::PrivateKeyJwt);
        assert!(v.client.jwks.as_deref().unwrap().contains("\"kid\":\"k1\""));
    }

    #[test]
    fn dcr_client_credentials_when_allowed() {
        let s = DcrSettings {
            allow_client_credentials: true,
            ..settings()
        };
        let v = validate(
            &json!({"grant_types": ["client_credentials"], "token_endpoint_auth_method": "client_secret_post"}),
            &s,
            DcrMode::Open,
        )
        .unwrap();
        assert_eq!(v.client.grant_types, vec![GrantType::ClientCredentials]);
        assert!(v.response_types.is_empty());
        assert!(v.client.redirect_uris.is_empty());
    }

    #[test]
    fn dcr_allow_listed_host_is_accepted_case_insensitively() {
        let s = DcrSettings {
            allowed_redirect_hosts: vec!["app.example".to_owned()],
            ..settings()
        };
        let v = validate(
            &json!({"redirect_uris": ["https://APP.example/cb"]}),
            &s,
            DcrMode::AllowListed,
        )
        .unwrap();
        assert_eq!(v.client.redirect_uris, vec!["https://APP.example/cb"]);
    }

    #[test]
    fn dcr_open_mode_ignores_host_allow_list() {
        let s = DcrSettings {
            allowed_redirect_hosts: vec!["app.example".to_owned()],
            ..settings()
        };
        assert!(
            validate(
                &json!({"redirect_uris": ["https://other.example/cb"]}),
                &s,
                DcrMode::Open
            )
            .is_ok()
        );
    }

    #[test]
    fn dcr_backchannel_logout_https_accepted() {
        let v = open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "backchannel_logout_uri": "https://app.example/bcl",
            "backchannel_logout_session_required": true,
        }))
        .unwrap();
        assert_eq!(
            v.options.backchannel_logout_uri.as_deref(),
            Some("https://app.example/bcl")
        );
        assert!(v.options.backchannel_logout_session_required);
    }

    // ---- rejections: request shape ----

    #[test]
    fn dcr_non_object_request_rejected() {
        for v in [json!(null), json!([]), json!("x"), json!(1)] {
            assert_meta(open(v));
        }
    }

    #[test]
    fn dcr_software_statement_rejected() {
        match open(
            json!({"redirect_uris": ["https://app.example/cb"], "software_statement": "eyJ.x.y"}),
        ) {
            Err(CoreError::InvalidSoftwareStatement) => {}
            other => panic!("expected invalid_software_statement, got {other:?}"),
        }
    }

    #[test]
    fn dcr_wrongly_typed_metadata_rejected() {
        assert_redirect(open(json!({"redirect_uris": "https://app.example/cb"})));
        assert_redirect(open(json!({"redirect_uris": [1]})));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "grant_types": "authorization_code"}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "scope": ["openid"]}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "client_name": 5}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "backchannel_logout_session_required": "yes"}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": 1}),
        ));
    }

    // ---- rejections: redirect URIs ----

    #[test]
    fn dcr_redirect_uri_rules_rejected() {
        // http to a non-loopback host
        assert_redirect(open(json!({"redirect_uris": ["http://app.example/cb"]})));
        // fragment
        assert_redirect(open(json!({"redirect_uris": ["https://app.example/cb#x"]})));
        // empty or missing with authorization_code
        assert_redirect(open(json!({"redirect_uris": []})));
        assert_redirect(open(json!({})));
        // relative, wildcard, userinfo
        assert_redirect(open(json!({"redirect_uris": ["/cb"]})));
        assert_redirect(open(json!({"redirect_uris": ["https://*.app.example/cb"]})));
        assert_redirect(open(
            json!({"redirect_uris": ["https://u:p@app.example/cb"]}),
        ));
        // too many
        let many: Vec<String> = (0..=MAX_REDIRECT_URIS)
            .map(|i| format!("https://app.example/cb{i}"))
            .collect();
        assert_redirect(open(json!({ "redirect_uris": many })));
    }

    #[test]
    fn dcr_web_client_loopback_http_rejected() {
        assert_redirect(open(json!({"redirect_uris": ["http://127.0.0.1:8080/cb"]})));
        assert_redirect(open(json!({"redirect_uris": ["http://localhost/cb"]})));
        assert_redirect(open(json!({"redirect_uris": ["com.example.app:/cb"]})));
    }

    #[test]
    fn dcr_native_client_redirect_rules_rejected() {
        let native = |uri: &str| {
            open(
                json!({"application_type": "native", "token_endpoint_auth_method": "none", "redirect_uris": [uri]}),
            )
        };
        assert_redirect(native("https://app.example/cb"));
        assert_redirect(native("http://app.example/cb"));
        assert_redirect(native("javascript:alert(1)"));
        assert!(native("http://[::1]/cb").is_ok());
    }

    #[test]
    fn dcr_redirect_host_allow_list_enforced() {
        let s = DcrSettings {
            allowed_redirect_hosts: vec!["app.example".to_owned()],
            ..settings()
        };
        let al = |req: Value| validate(&req, &s, DcrMode::AllowListed);
        assert_redirect(al(json!({"redirect_uris": ["https://other.example/cb"]})));
        assert_redirect(al(
            json!({"redirect_uris": ["https://app.example/cb", "https://other.example/cb"]}),
        ));
        assert_redirect(al(
            json!({"redirect_uris": ["https://app.example.evil/cb"]}),
        ));
        // a private-use scheme URI has no host to check
        assert_redirect(al(
            json!({"application_type": "native", "token_endpoint_auth_method": "none", "redirect_uris": ["com.example.app:/cb"]}),
        ));
        // post-logout redirect URIs obey the same allow-list
        assert_meta(al(
            json!({"redirect_uris": ["https://app.example/cb"], "post_logout_redirect_uris": ["https://other.example/bye"]}),
        ));
    }

    #[test]
    fn dcr_post_logout_redirect_uri_rules_rejected() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "post_logout_redirect_uris": ["http://app.example/bye"]}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "post_logout_redirect_uris": ["https://app.example/bye#f"]}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "post_logout_redirect_uris": "https://app.example/bye"}),
        ));
    }

    // ---- rejections: application type, grants, response types, auth method ----

    #[test]
    fn dcr_unknown_application_type_rejected() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "application_type": "service"}),
        ));
    }

    #[test]
    fn dcr_client_credentials_without_allow_rejected() {
        assert_meta(open(json!({"grant_types": ["client_credentials"]})));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "grant_types": ["authorization_code", "client_credentials"]}),
        ));
    }

    #[test]
    fn dcr_unsupported_grant_types_rejected() {
        for g in [
            "implicit",
            "password",
            "urn:ietf:params:oauth:grant-type:device_code",
            "",
        ] {
            assert_meta(open(
                json!({"redirect_uris": ["https://app.example/cb"], "grant_types": [g]}),
            ));
        }
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "grant_types": []}),
        ));
    }

    #[test]
    fn dcr_refresh_token_without_authorization_code_rejected() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "grant_types": ["refresh_token"], "response_types": []}),
        ));
    }

    #[test]
    fn dcr_public_client_credentials_rejected() {
        let s = DcrSettings {
            allow_client_credentials: true,
            ..settings()
        };
        assert_meta(validate(
            &json!({"grant_types": ["client_credentials"], "token_endpoint_auth_method": "none"}),
            &s,
            DcrMode::Open,
        ));
    }

    #[test]
    fn dcr_response_types_rejected() {
        // unsupported values
        for r in ["token", "id_token", "code id_token", "none"] {
            assert_meta(open(
                json!({"redirect_uris": ["https://app.example/cb"], "response_types": [r]}),
            ));
        }
        // inconsistent with grant_types (RFC 7591 §2.1)
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "response_types": []}),
        ));
        let s = DcrSettings {
            allow_client_credentials: true,
            ..settings()
        };
        assert_meta(validate(
            &json!({"grant_types": ["client_credentials"], "response_types": ["code"]}),
            &s,
            DcrMode::Open,
        ));
    }

    #[test]
    fn dcr_unsupported_auth_methods_rejected() {
        for m in [
            "client_secret_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth",
            "None",
            "",
        ] {
            assert_meta(open(
                json!({"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": m}),
            ));
        }
    }

    // ---- rejections: keys ----

    #[test]
    fn dcr_jwks_uri_rejected() {
        // alone
        assert_meta(open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://app.example/jwks",
        })));
        // with jwks
        assert_meta(open(json!({
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks(),
            "jwks_uri": "https://app.example/jwks",
        })));
        // with a secret-based method
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "jwks_uri": "https://app.example/jwks"}),
        ));
    }

    #[test]
    fn dcr_private_key_jwt_requires_inline_jwks() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": "private_key_jwt"}),
        ));
        // jwks must be a JWK Set object of public keys
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": "private_key_jwt", "jwks": PUBLIC_JWKS}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": "private_key_jwt", "jwks": {"keys": []}}),
        ));
        let private: Value = serde_json::from_str(
            &PUBLIC_JWKS.replace(r#""e":"AQAB""#, r#""e":"AQAB","d":"c2VjcmV0""#),
        )
        .unwrap();
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": "private_key_jwt", "jwks": private}),
        ));
    }

    #[test]
    fn dcr_jwks_without_private_key_jwt_rejected() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "jwks": jwks()}),
        ));
    }

    // ---- rejections: scopes and resources ----

    #[test]
    fn dcr_admin_scope_never_registrable() {
        let s = DcrSettings {
            allowed_scopes: vec![
                "openid".to_owned(),
                "admin:write".to_owned(),
                "admin:custom".to_owned(),
            ],
            ..settings()
        };
        for scope in [
            "openid admin:write",
            "admin:read",
            "admin:custom",
            "openid admin:clients:write",
        ] {
            assert_meta(validate(
                &json!({"redirect_uris": ["https://app.example/cb"], "scope": scope}),
                &s,
                DcrMode::Open,
            ));
        }
        // a misconfigured allow-list never leaks admin scopes into the default
        let v = validate(
            &json!({"redirect_uris": ["https://app.example/cb"]}),
            &s,
            DcrMode::Open,
        )
        .unwrap();
        assert_eq!(v.client.scopes, vec!["openid"]);
    }

    #[test]
    fn dcr_scope_outside_allowed_scopes_rejected() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "scope": "openid phone"}),
        ));
        // fail closed: an empty allow-list allows nothing
        let s = DcrSettings {
            allowed_scopes: vec![],
            ..settings()
        };
        assert_meta(validate(
            &json!({"redirect_uris": ["https://app.example/cb"], "scope": "openid"}),
            &s,
            DcrMode::Open,
        ));
    }

    #[test]
    fn dcr_malformed_scope_rejected() {
        for scope in ["", "openid  profile", " openid", "openid\"x"] {
            assert_meta(open(
                json!({"redirect_uris": ["https://app.example/cb"], "scope": scope}),
            ));
        }
    }

    #[test]
    fn dcr_resource_outside_allowed_resources_rejected() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "allowed_resources": ["https://other.example/"]}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "allowed_resources": ["https://mcp.example/#f"]}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "allowed_resources": "https://mcp.example/"}),
        ));
    }

    // ---- rejections: logout and informational metadata ----

    #[test]
    fn dcr_backchannel_logout_uri_must_be_https() {
        for uri in [
            "http://app.example/bcl",
            "http://127.0.0.1/bcl",
            "https://app.example/bcl#f",
            "/bcl",
        ] {
            assert_meta(open(
                json!({"redirect_uris": ["https://app.example/cb"], "backchannel_logout_uri": uri}),
            ));
        }
    }

    #[test]
    fn dcr_client_name_rules_rejected() {
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "client_name": "   "}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "client_name": "a".repeat(201)}),
        ));
        assert_meta(open(
            json!({"redirect_uris": ["https://app.example/cb"], "client_name": "bad\u{7}name"}),
        ));
    }

    #[test]
    fn dcr_informational_uris_must_be_capped_https() {
        for key in [
            "logo_uri",
            "client_uri",
            "initiate_login_uri",
            "policy_uri",
            "tos_uri",
        ] {
            for bad in [
                "http://app.example/x".to_owned(),
                "javascript:alert(1)".to_owned(),
                "data:image/png;base64,AAAA".to_owned(),
                "/relative".to_owned(),
                "https://u@app.example/x".to_owned(),
                "https://app.example/ x".to_owned(),
                format!("https://app.example/{}", "a".repeat(MAX_METADATA_URI_LEN)),
            ] {
                let mut req = json!({"redirect_uris": ["https://app.example/cb"]});
                req[key] = Value::String(bad.clone());
                assert_meta(open(req));
            }
            let mut req = json!({"redirect_uris": ["https://app.example/cb"]});
            req[key] = json!(5);
            assert_meta(open(req));
        }
    }

    // ---- never panics ----

    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| json!(n)),
            "[ -~]{0,40}".prop_map(Value::String),
            prop_oneof![
                Just("https://app.example/cb"),
                Just("http://127.0.0.1:1/cb"),
                Just("com.example.app:/cb"),
                Just("authorization_code"),
                Just("client_credentials"),
                Just("private_key_jwt"),
                Just("none"),
                Just("native"),
                Just("code"),
                Just("openid admin:write"),
            ]
            .prop_map(|s| Value::String(s.to_owned())),
        ];
        let keys = prop_oneof![
            Just("redirect_uris"),
            Just("grant_types"),
            Just("response_types"),
            Just("token_endpoint_auth_method"),
            Just("application_type"),
            Just("scope"),
            Just("jwks"),
            Just("jwks_uri"),
            Just("software_statement"),
            Just("allowed_resources"),
            Just("post_logout_redirect_uris"),
            Just("backchannel_logout_uri"),
            Just("backchannel_logout_session_required"),
            Just("require_pushed_authorization_requests"),
            Just("client_name"),
            Just("logo_uri"),
            Just("keys"),
            Just("x"),
        ]
        .prop_map(str::to_owned);
        leaf.prop_recursive(4, 48, 8, move |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::btree_map(keys.clone(), inner, 0..8)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #[test]
        fn dcr_validate_never_panics(v in arb_json(), cc in any::<bool>(), allow_listed in any::<bool>()) {
            let s = DcrSettings {
                allow_client_credentials: cc,
                allowed_redirect_hosts: vec!["app.example".to_owned()],
                ..settings()
            };
            let mode = if allow_listed { DcrMode::AllowListed } else { DcrMode::Open };
            let _ = validate(&v, &s, mode);
        }
    }

    #[test]
    fn registration_forbidden_scopes() {
        for t in ["admin", "admin:read", "admin:clients:write", "org:admin"] {
            assert!(is_registration_forbidden_scope(t), "{t}");
        }
        for t in ["openid", "org", "org:admin:x", "organization", "Org:Admin"] {
            assert!(!is_registration_forbidden_scope(t), "{t}");
        }
    }
}
