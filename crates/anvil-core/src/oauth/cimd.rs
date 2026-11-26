//! Client ID Metadata Document URL checks and document validation (AGT-02).
//!
//! Implements draft-ietf-oauth-client-id-metadata-document-03 as pure functions; fetching (through
//! the single SSRF-guarded outbound client) and caching live in the service and adapter layers.
//!
//! [`check_url`] runs before any fetch:
//!
//! - `https` only; no userinfo, no fragment, no query, a path other than `/`, no `.`/`..` path
//!   segments (also percent-encoded), no backslash, whitespace or control characters;
//! - `http` is accepted only when `allow_http_loopback` is true **and** the host is a loopback
//!   literal (`127.0.0.0/8`, `::1`) or `localhost`. Callers derive the flag solely from the
//!   development-mode outbound policy (`ClientMetadataFetcher::allow_http_loopback`), never from
//!   tenant settings or request input. In production any http URL is rejected, loopback included.
//!
//! [`validate`] checks the fetched document:
//!
//! - at most [`MAX_DOCUMENT_BYTES`] (5 KiB), a JSON object;
//! - `client_id` equals the document URL by plain string comparison (never normalised);
//! - no `client_secret` / `client_secret_expires_at`, no shared-secret auth method;
//! - a missing `token_endpoint_auth_method` means `none` (never the RFC 7591 default);
//! - `jwks_uri` is rejected in 0.4 (alone or with `jwks`): `private_key_jwt` needs an inline
//!   `jwks`, and such a client is confidential; every other client is public;
//! - `redirect_uris` is required and follows the shared redirect URI rules;
//! - `grant_types` / `response_types` are intersected with the server's [`ServerCaps`]; an empty
//!   intersection is rejected;
//! - `scope` never contains an `admin:` scope; when absent, [`ServerCaps::default_scopes`] apply.
//!
//! The client rules shared with every other client (name, auth method and grant consistency,
//! inline JWKS, redirect URI syntax) are those of [`crate::service::client::validate_client`].
//! Errors are [`CimdError`]; the service maps them to `CoreError` at its boundary.

use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::error::CoreError;
use crate::model::{
    ApplicationType, ClientAuthMethod, ClientId, ClientSource, ClientType, ConsentMode, GrantType,
    NewClient, Scope, TokenFormat,
};
use crate::oauth::redirect::validate_redirect_uri;
use crate::service::admin_scope::is_reserved_admin_token;
use crate::service::client::{ClientInput, MAX_REDIRECT_URIS, uses_secret, validate_client};

/// Largest accepted metadata document (draft-03 §4: 5 kilobytes).
pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024;

/// Longest accepted client id URL.
pub const MAX_URL_LEN: usize = 2048;

/// Why a client id URL or its metadata document was refused. Messages are fixed text: the
/// document is third-party input and is never echoed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CimdError {
    #[error("invalid client id metadata document URL: {0}")]
    InvalidUrl(&'static str),
    #[error("invalid client id metadata document: {0}")]
    InvalidDocument(String),
    #[error("client id metadata document exceeds {MAX_DOCUMENT_BYTES} bytes")]
    TooLarge,
}

/// What this server supports for CIMD clients. Documents are intersected with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCaps {
    pub grant_types: Vec<GrantType>,
    pub response_types: Vec<String>,
    /// Shared-secret methods are refused whatever this list says.
    pub auth_methods: Vec<ClientAuthMethod>,
    /// Scopes a document without `scope` gets.
    pub default_scopes: Vec<String>,
}

impl Default for ServerCaps {
    /// Authorization code (+ refresh) with `code`, public (`none`) or `private_key_jwt` clients,
    /// `openid` by default.
    fn default() -> Self {
        Self {
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            response_types: vec!["code".to_owned()],
            auth_methods: vec![ClientAuthMethod::None, ClientAuthMethod::PrivateKeyJwt],
            default_scopes: vec!["openid".to_owned()],
        }
    }
}

/// A validated metadata document, ready to be materialised as a client row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClientMetadata {
    /// The document URL (equal to the document's `client_id`).
    pub client_id: String,
    /// Stored client name: `client_name` when present, else the URL host. Untrusted either way:
    /// the consent screen shows the `client_id` host prominently.
    pub name: String,
    /// The document's `client_name` (trimmed), if any.
    pub client_name: Option<String>,
    pub client_type: ClientType,
    pub application_type: ApplicationType,
    pub auth_method: ClientAuthMethod,
    /// Inline JWKS JSON (only with `private_key_jwt`).
    pub jwks: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
}

impl NewClientMetadata {
    /// The client row for `ClientRepo::upsert_cimd`: source `cimd`, consent always required,
    /// PKCE always required, JWT access tokens, no secret, no tenant-wide introspection.
    pub fn to_new_client(
        &self,
        id: ClientId,
        created_at: OffsetDateTime,
        metadata_expires_at: OffsetDateTime,
        allowed_resources: Vec<String>,
    ) -> NewClient {
        NewClient {
            id,
            client_id: self.client_id.clone(),
            name: self.name.clone(),
            client_type: self.client_type,
            application_type: self.application_type,
            auth_method: self.auth_method,
            secret_hash: None,
            jwks: self.jwks.clone(),
            redirect_uris: self.redirect_uris.clone(),
            grant_types: self.grant_types.clone(),
            scopes: self.scopes.clone(),
            require_pkce: true,
            token_format: TokenFormat::Jwt,
            consent_mode: ConsentMode::Required,
            id_token_signed_response_alg: None,
            can_introspect: false,
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources,
            mfa_policy: None,
            registration_source: ClientSource::Cimd,
            metadata_expires_at: Some(metadata_expires_at),
            registration_access_token_hash: None,
            created_at,
            organization: crate::model::OrgClientPolicy::Off,
        }
    }
}

/// Checks a client id URL before anything is fetched. See the module docs for the rules.
pub fn check_url(url: &str, allow_http_loopback: bool) -> Result<(), CimdError> {
    let bad = |why| Err(CimdError::InvalidUrl(why));
    if url.is_empty() || url.len() > MAX_URL_LEN {
        return bad("empty or too long");
    }
    if url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return bad("contains whitespace, control characters or a backslash");
    }
    // The scheme is compared literally: the client id is compared as a string, never normalised.
    let (is_http, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (false, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (true, rest)
    } else {
        return bad("must use https");
    };
    if is_http && !allow_http_loopback {
        return bad("must use https");
    }
    if url.contains('#') {
        return bad("must not contain a fragment");
    }
    if url.contains('?') {
        return bad("must not contain a query");
    }
    let Some(path_start) = rest.find('/') else {
        return bad("must have a path");
    };
    let (authority, path) = rest.split_at(path_start);
    if authority.contains('@') {
        return bad("must not contain userinfo");
    }
    if authority.is_empty() {
        return bad("must have a host");
    }
    if path == "/" {
        return bad("path must not be /");
    }
    if path.split('/').any(|segment| {
        let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
        decoded == "." || decoded == ".."
    }) {
        return bad("must not contain dot path segments");
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return bad("is not a valid URL");
    };
    let Some(host) = parsed.host() else {
        return bad("must have a host");
    };
    if is_http {
        let loopback = match host {
            url::Host::Domain(d) => d == "localhost",
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
        };
        if !loopback {
            return bad("http is only allowed for loopback hosts in development mode");
        }
    }
    Ok(())
}

/// Validates a fetched metadata document for `url` (which is checked with [`check_url`] and the
/// same `allow_http_loopback` flag first).
pub fn validate(
    url: &str,
    body: &[u8],
    caps: &ServerCaps,
    allow_http_loopback: bool,
) -> Result<NewClientMetadata, CimdError> {
    check_url(url, allow_http_loopback)?;
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(CimdError::TooLarge);
    }
    let document: Value =
        serde_json::from_slice(body).map_err(|_| invalid("the document is not valid JSON"))?;
    let obj = document
        .as_object()
        .ok_or_else(|| invalid("the document must be a JSON object"))?;

    // draft-03: the client_id is the document URL, compared as strings.
    match member(obj, "client_id") {
        Some(Value::String(id)) if id == url => {}
        _ => return Err(invalid("client_id does not equal the document URL")),
    }
    if member(obj, "client_secret").is_some() || member(obj, "client_secret_expires_at").is_some() {
        return Err(invalid(
            "a metadata document must not contain a client secret",
        ));
    }
    if member(obj, "jwks_uri").is_some() {
        return Err(invalid(
            "jwks_uri is not supported in this release; publish the keys inline with jwks",
        ));
    }

    // Auth method: missing means none; shared secrets are impossible for a public document.
    let auth_method = match opt_str(obj, "token_endpoint_auth_method")? {
        None => ClientAuthMethod::None,
        Some("client_secret_basic" | "client_secret_post" | "client_secret_jwt") => {
            return Err(invalid(
                "shared-secret authentication methods are not allowed",
            ));
        }
        Some(s) => match ClientAuthMethod::parse(s) {
            Some(m) if caps.auth_methods.contains(&m) && !uses_secret(m) => m,
            _ => return Err(invalid("token_endpoint_auth_method is not supported")),
        },
    };
    let client_type = if auth_method == ClientAuthMethod::PrivateKeyJwt {
        ClientType::Confidential
    } else {
        ClientType::Public
    };
    let jwks = match member(obj, "jwks") {
        None => None,
        Some(v @ Value::Object(_)) => Some(v.to_string()),
        Some(_) => return Err(invalid("jwks must be a JWK Set object")),
    };

    let application_type = match opt_str(obj, "application_type")? {
        None | Some("web") => ApplicationType::Web,
        Some("native") => ApplicationType::Native,
        Some(_) => return Err(invalid("application_type must be web or native")),
    };

    // Redirect URIs: required.
    let redirect_uris = dedup(opt_str_array(obj, "redirect_uris")?.unwrap_or_default());
    if redirect_uris.is_empty() {
        return Err(invalid("redirect_uris is required"));
    }
    if redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid("too many redirect URIs"));
    }
    let post_logout_redirect_uris =
        dedup(opt_str_array(obj, "post_logout_redirect_uris")?.unwrap_or_default());
    if post_logout_redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid("too many post-logout redirect URIs"));
    }
    for uri in &post_logout_redirect_uris {
        validate_redirect_uri(uri, application_type)
            .map_err(|_| invalid("post_logout_redirect_uris contains an invalid URI"))?;
    }

    // Grant and response types: intersection with what we support; empty is an error.
    let grant_names = opt_str_array(obj, "grant_types")?
        .unwrap_or_else(|| vec![GrantType::AuthorizationCode.as_str().to_owned()]);
    let mut grant_types: Vec<GrantType> = Vec::new();
    for g in grant_names.iter().filter_map(|n| GrantType::parse(n)) {
        if caps.grant_types.contains(&g) && !grant_types.contains(&g) {
            grant_types.push(g);
        }
    }
    if grant_types.is_empty() {
        return Err(invalid("no supported grant type"));
    }
    let response_names =
        opt_str_array(obj, "response_types")?.unwrap_or_else(|| vec!["code".to_owned()]);
    let response_types = dedup(
        response_names
            .into_iter()
            .filter(|r| caps.response_types.contains(r))
            .collect(),
    );
    if response_types.is_empty() {
        return Err(invalid("no supported response type"));
    }
    if response_types.iter().any(|r| r == "code")
        != grant_types.contains(&GrantType::AuthorizationCode)
    {
        return Err(invalid(
            "response_types and grant_types are inconsistent: code requires authorization_code",
        ));
    }

    // Scopes: never admin scopes.
    let scopes = match opt_str(obj, "scope")? {
        Some(raw) => {
            Scope::parse(raw).map_err(|_| invalid("scope is not a valid scope string"))?;
            let tokens = dedup(raw.split(' ').map(str::to_owned).collect());
            if tokens.iter().any(|t| is_reserved_admin_token(t)) {
                return Err(invalid("admin scopes are not allowed"));
            }
            tokens
        }
        None => caps.default_scopes.clone(),
    };

    let client_name = match opt_str(obj, "client_name")? {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(invalid("client_name must not be empty"));
            }
            Some(trimmed.to_owned())
        }
    };
    // check_url guarantees a host.
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    let name = client_name.clone().unwrap_or(host);

    // The rules every client obeys (one implementation: `service::client`).
    let input = ClientInput {
        name: name.clone(),
        client_type,
        application_type,
        auth_method,
        redirect_uris: redirect_uris.clone(),
        grant_types: grant_types.clone(),
        scopes: scopes.clone(),
        require_pkce: Some(true),
        jwks: jwks.clone(),
        jwks_uri: None,
    };
    validate_client(&input, validate_redirect_uri).map_err(|e| match e {
        CoreError::Validation { field, message } => invalid(format!("{field}: {message}")),
        other => invalid(other.to_string()),
    })?;

    Ok(NewClientMetadata {
        client_id: url.to_owned(),
        name,
        client_name,
        client_type,
        application_type,
        auth_method,
        jwks,
        redirect_uris,
        grant_types,
        response_types,
        scopes,
        post_logout_redirect_uris,
    })
}

fn invalid(message: impl Into<String>) -> CimdError {
    CimdError::InvalidDocument(message.into())
}

/// A document member; JSON `null` counts as absent.
fn member<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    obj.get(key).filter(|v| !v.is_null())
}

fn opt_str<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, CimdError> {
    match member(obj, key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(invalid(format!("{key} must be a string"))),
    }
}

fn opt_str_array(obj: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>, CimdError> {
    let Some(value) = member(obj, key) else {
        return Ok(None);
    };
    let not_strings = || invalid(format!("{key} must be an array of strings"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    const URL: &str = "https://app.example/client.json";
    const PUBLIC_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;

    fn doc() -> Value {
        json!({
            "client_id": URL,
            "client_name": "Example MCP client",
            "redirect_uris": ["http://127.0.0.1:33418/callback"],
        })
    }

    fn check(v: &Value) -> Result<NewClientMetadata, CimdError> {
        validate(URL, v.to_string().as_bytes(), &ServerCaps::default(), false)
    }

    fn with(key: &str, value: Value) -> Value {
        let mut d = doc();
        d[key] = value;
        d
    }

    #[track_caller]
    fn assert_url_rejected(url: &str, allow_http_loopback: bool) {
        match check_url(url, allow_http_loopback) {
            Err(CimdError::InvalidUrl(_)) => {}
            other => {
                panic!("{url} (dev={allow_http_loopback}): expected InvalidUrl, got {other:?}")
            }
        }
    }

    #[track_caller]
    fn assert_doc_rejected(r: Result<NewClientMetadata, CimdError>) {
        match r {
            Err(CimdError::InvalidDocument(_)) => {}
            other => panic!("expected InvalidDocument, got {other:?}"),
        }
    }

    // ---- check_url ----

    #[test]
    fn cimd_https_url_accepted_in_both_modes() {
        for dev in [false, true] {
            for url in [
                URL,
                "https://app.example/a/b/client.json",
                "https://app.example:8443/c",
                "https://[2001:db8::1]/c.json",
            ] {
                assert_eq!(check_url(url, dev), Ok(()), "{url} dev={dev}");
            }
        }
    }

    #[test]
    fn cimd_http_rejected_in_production_including_loopback() {
        for url in [
            "http://h/x",
            "http://127.0.0.1:8080/client.json",
            "http://localhost/x",
            "http://[::1]/c.json",
        ] {
            assert_url_rejected(url, false);
        }
    }

    #[test]
    fn cimd_dev_mode_accepts_only_loopback_http() {
        for url in [
            "http://127.0.0.1:8080/client.json",
            "http://127.1.2.3/c.json",
            "http://[::1]/c.json",
            "http://localhost:3000/c.json",
        ] {
            assert_eq!(check_url(url, true), Ok(()), "{url}");
        }
        for url in [
            "http://example.com/c.json",
            "http://10.0.0.5/c.json",
            "http://192.168.1.1/c.json",
            "http://[::ffff:127.0.0.1]/c.json",
            "http://localhost.example.com/c.json",
            "http://0.0.0.0/c.json",
        ] {
            assert_url_rejected(url, true);
        }
    }

    #[test]
    fn cimd_url_shape_rules_rejected_in_both_modes() {
        for dev in [false, true] {
            for url in [
                "https://u@h/x",
                "https://u:p@h/x",
                "https://@h/x",
                "https://h/",
                "https://h",
                "https://h/a#f",
                "https://h/a#",
                "https://h/a?q",
                "https://h/a?",
                "https://h/a/../b",
                "https://h/./a",
                "https://h/a/..",
                "https://h/a/%2e%2E/b",
                "https://h/%2e/a",
                "https://h\\a/b",
                "https://h/a\\..\\b",
                "https:///a",
                "https://h/a b",
                "https://h/a\tb",
                "HTTPS://h/a",
                "ftp://h/a",
                "h/a",
                "",
                "http://127.0.0.1/",
                "http://127.0.0.1/a#f",
                "http://u@127.0.0.1/a",
            ] {
                assert_url_rejected(url, dev);
            }
            let long = format!("https://h/{}", "a".repeat(MAX_URL_LEN));
            assert_url_rejected(&long, dev);
        }
    }

    // ---- validate: accepted documents ----

    #[test]
    fn cimd_minimal_document_is_a_public_client() {
        let m = check(&doc()).unwrap();
        assert_eq!(m.client_id, URL);
        assert_eq!(m.auth_method, ClientAuthMethod::None);
        assert_eq!(m.client_type, ClientType::Public);
        assert_eq!(m.application_type, ApplicationType::Web);
        assert_eq!(m.grant_types, vec![GrantType::AuthorizationCode]);
        assert_eq!(m.response_types, vec!["code".to_owned()]);
        assert_eq!(m.scopes, vec!["openid".to_owned()]);
        assert_eq!(m.name, "Example MCP client");
        assert_eq!(m.redirect_uris, vec!["http://127.0.0.1:33418/callback"]);
    }

    #[test]
    fn cimd_name_defaults_to_url_host() {
        let mut d = doc();
        d.as_object_mut().unwrap().remove("client_name");
        let m = check(&d).unwrap();
        assert_eq!(m.name, "app.example");
        assert_eq!(m.client_name, None);
    }

    #[test]
    fn cimd_private_key_jwt_with_jwks_is_confidential() {
        let mut d = with("token_endpoint_auth_method", json!("private_key_jwt"));
        d["jwks"] = serde_json::from_str(PUBLIC_JWKS).unwrap();
        let m = check(&d).unwrap();
        assert_eq!(m.client_type, ClientType::Confidential);
        assert_eq!(m.auth_method, ClientAuthMethod::PrivateKeyJwt);
        assert!(m.jwks.is_some());
    }

    #[test]
    fn cimd_grants_and_response_types_are_intersected() {
        let mut d = with(
            "grant_types",
            json!(["authorization_code", "refresh_token", "password", "urn:x"]),
        );
        d["response_types"] = json!(["code", "token"]);
        let m = check(&d).unwrap();
        assert_eq!(
            m.grant_types,
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
        );
        assert_eq!(m.response_types, vec!["code".to_owned()]);
    }

    #[test]
    fn cimd_unknown_members_ignored_and_scope_kept() {
        let mut d = with("scope", json!("openid offline_access"));
        d["software_id"] = json!("x");
        d["logo_uri"] = json!("https://app.example/logo.png");
        let m = check(&d).unwrap();
        assert_eq!(m.scopes, vec!["openid", "offline_access"]);
    }

    #[test]
    fn cimd_document_at_exactly_5k_is_accepted() {
        let mut d = doc();
        let base = d.to_string().len();
        d["padding"] = json!("");
        let pad = MAX_DOCUMENT_BYTES - base - r#","padding":"""#.len();
        d["padding"] = json!("p".repeat(pad));
        let body = d.to_string();
        assert_eq!(body.len(), MAX_DOCUMENT_BYTES);
        assert!(validate(URL, body.as_bytes(), &ServerCaps::default(), false).is_ok());
    }

    #[test]
    fn cimd_dev_mode_http_document_validates() {
        let url = "http://127.0.0.1:8080/client.json";
        let d = json!({"client_id": url, "redirect_uris": ["http://127.0.0.1:9/cb"]});
        let body = d.to_string();
        assert!(validate(url, body.as_bytes(), &ServerCaps::default(), true).is_ok());
        // the same document in production is refused at the URL check
        assert!(matches!(
            validate(url, body.as_bytes(), &ServerCaps::default(), false),
            Err(CimdError::InvalidUrl(_))
        ));
    }

    #[test]
    fn cimd_to_new_client_is_locked_down() {
        let m = check(&doc()).unwrap();
        let now = OffsetDateTime::UNIX_EPOCH;
        let exp = now + time::Duration::minutes(5);
        let c = m.to_new_client(
            ClientId::new_v7(),
            now,
            exp,
            vec!["https://mcp.example/".to_owned()],
        );
        assert_eq!(c.client_id, URL);
        assert_eq!(c.registration_source, ClientSource::Cimd);
        assert_eq!(c.metadata_expires_at, Some(exp));
        assert_eq!(c.consent_mode, ConsentMode::Required);
        assert!(c.require_pkce);
        assert_eq!(c.secret_hash, None);
        assert_eq!(c.registration_access_token_hash, None);
        assert!(!c.can_introspect);
        assert_eq!(c.token_format, TokenFormat::Jwt);
        assert_eq!(c.allowed_resources, vec!["https://mcp.example/"]);
        assert_eq!(c.client_type, ClientType::Public);
    }

    // ---- validate: rejections ----

    #[test]
    fn cimd_url_checked_before_document() {
        let body = doc().to_string();
        assert!(matches!(
            validate(
                "https://app.example/",
                body.as_bytes(),
                &ServerCaps::default(),
                false
            ),
            Err(CimdError::InvalidUrl(_))
        ));
    }

    #[test]
    fn cimd_document_over_5k_rejected() {
        let body = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        assert_eq!(body.len(), 5121);
        assert_eq!(
            validate(URL, &body, &ServerCaps::default(), false),
            Err(CimdError::TooLarge)
        );
    }

    #[test]
    fn cimd_non_json_or_non_object_rejected() {
        for body in [&b"not json"[..], b"[]", b"\"x\"", b"null", b"", b"\xff\xfe"] {
            assert_doc_rejected(validate(URL, body, &ServerCaps::default(), false));
        }
    }

    #[test]
    fn cimd_client_id_mismatch_rejected() {
        for id in [
            json!("https://app.example/client.json/"),
            json!("https://APP.example/client.json"),
            json!("https://app.example/Client.json"),
            json!("https://app.example:443/client.json"),
            json!("https://app.example/other.json"),
            json!(" https://app.example/client.json"),
            json!(null),
            json!(1),
        ] {
            assert_doc_rejected(check(&with("client_id", id)));
        }
        let mut d = doc();
        d.as_object_mut().unwrap().remove("client_id");
        assert_doc_rejected(check(&d));
    }

    #[test]
    fn cimd_client_secret_rejected() {
        assert_doc_rejected(check(&with("client_secret", json!("s3cret"))));
        assert_doc_rejected(check(&with("client_secret_expires_at", json!(0))));
    }

    #[test]
    fn cimd_shared_secret_method_rejected() {
        for m in [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
        ] {
            assert_doc_rejected(check(&with("token_endpoint_auth_method", json!(m))));
        }
    }

    #[test]
    fn cimd_unsupported_auth_method_rejected() {
        for m in [json!("tls_client_auth"), json!(""), json!(1)] {
            assert_doc_rejected(check(&with("token_endpoint_auth_method", m)));
        }
        // a method the server caps exclude
        let caps = ServerCaps {
            auth_methods: vec![ClientAuthMethod::None],
            ..ServerCaps::default()
        };
        let mut d = with("token_endpoint_auth_method", json!("private_key_jwt"));
        d["jwks"] = serde_json::from_str(PUBLIC_JWKS).unwrap();
        assert_doc_rejected(validate(URL, d.to_string().as_bytes(), &caps, false));
    }

    #[test]
    fn cimd_jwks_uri_rejected() {
        // alone
        let mut d = with("token_endpoint_auth_method", json!("private_key_jwt"));
        d["jwks_uri"] = json!("https://app.example/jwks");
        assert_doc_rejected(check(&d));
        // with jwks
        d["jwks"] = serde_json::from_str(PUBLIC_JWKS).unwrap();
        assert_doc_rejected(check(&d));
        // with a public client
        assert_doc_rejected(check(&with("jwks_uri", json!("https://app.example/jwks"))));
    }

    #[test]
    fn cimd_private_key_jwt_requires_inline_jwks() {
        assert_doc_rejected(check(&with(
            "token_endpoint_auth_method",
            json!("private_key_jwt"),
        )));
        let mut d = with("token_endpoint_auth_method", json!("private_key_jwt"));
        d["jwks"] = json!(PUBLIC_JWKS);
        assert_doc_rejected(check(&d));
        d["jwks"] = json!({"keys": []});
        assert_doc_rejected(check(&d));
        // jwks without private_key_jwt
        assert_doc_rejected(check(&with(
            "jwks",
            serde_json::from_str(PUBLIC_JWKS).unwrap(),
        )));
    }

    #[test]
    fn cimd_missing_or_bad_redirect_uris_rejected() {
        let mut d = doc();
        d.as_object_mut().unwrap().remove("redirect_uris");
        assert_doc_rejected(check(&d));
        for v in [
            json!([]),
            json!("http://127.0.0.1/cb"),
            json!([1]),
            json!(["https://app.example/cb#f"]),
            json!(["http://app.example/cb"]),
            json!(["javascript:alert(1)"]),
        ] {
            assert_doc_rejected(check(&with("redirect_uris", v)));
        }
        let many: Vec<String> = (0..=MAX_REDIRECT_URIS)
            .map(|i| format!("https://app.example/cb{i}"))
            .collect();
        assert_doc_rejected(check(&with("redirect_uris", json!(many))));
    }

    #[test]
    fn cimd_empty_grant_intersection_rejected() {
        assert_doc_rejected(check(&with("grant_types", json!(["password"]))));
        assert_doc_rejected(check(&with("grant_types", json!([]))));
        assert_doc_rejected(check(&with("grant_types", json!(["client_credentials"]))));
        assert_doc_rejected(check(&with("grant_types", json!("authorization_code"))));
    }

    #[test]
    fn cimd_empty_response_type_intersection_rejected() {
        assert_doc_rejected(check(&with("response_types", json!(["token"]))));
        assert_doc_rejected(check(&with("response_types", json!([]))));
    }

    #[test]
    fn cimd_refresh_token_without_authorization_code_rejected() {
        assert_doc_rejected(check(&with("grant_types", json!(["refresh_token"]))));
    }

    #[test]
    fn cimd_admin_scope_rejected() {
        for s in ["openid admin:write", "admin:read", "admin:anything"] {
            assert_doc_rejected(check(&with("scope", json!(s))));
        }
        for s in [json!(""), json!("openid  x"), json!(["openid"])] {
            assert_doc_rejected(check(&with("scope", s)));
        }
    }

    #[test]
    fn cimd_client_name_rules_rejected() {
        for n in [
            json!("  "),
            json!("a".repeat(201)),
            json!("bad\u{0}"),
            json!(5),
        ] {
            assert_doc_rejected(check(&with("client_name", n)));
        }
    }

    #[test]
    fn cimd_bad_application_type_or_post_logout_rejected() {
        assert_doc_rejected(check(&with("application_type", json!("service"))));
        assert_doc_rejected(check(&with(
            "post_logout_redirect_uris",
            json!(["https://app.example/bye#f"]),
        )));
        assert_doc_rejected(check(&with("post_logout_redirect_uris", json!("x"))));
    }

    // ---- never panics ----

    proptest! {
        #[test]
        fn cimd_validate_never_panics_on_bytes(body in prop::collection::vec(any::<u8>(), 0..6000), dev in any::<bool>()) {
            let _ = validate(URL, &body, &ServerCaps::default(), dev);
        }

        #[test]
        fn cimd_check_url_never_panics(url in "\\PC{0,80}", dev in any::<bool>()) {
            let _ = check_url(&url, dev);
        }

        #[test]
        fn cimd_accepted_url_is_https_or_dev_loopback(url in "(https?://)?[a-z0-9.:@\\[\\]/%?#\\\\-]{0,40}", dev in any::<bool>()) {
            if check_url(&url, dev).is_ok() {
                prop_assert!(url.starts_with("https://") || (dev && url.starts_with("http://")));
                prop_assert!(!url.contains('#') && !url.contains('?') && !url.contains('@'));
            }
        }

        #[test]
        fn cimd_validate_never_panics_on_documents(
            id_matches in any::<bool>(),
            method in prop::option::of(prop_oneof![Just("none"), Just("private_key_jwt"), Just("client_secret_basic"), Just("x")]),
            grants in prop::collection::vec(prop_oneof![Just("authorization_code"), Just("refresh_token"), Just("password")], 0..4),
            redirects in prop::collection::vec("\\PC{0,30}", 0..3),
            scope in prop::option::of("\\PC{0,20}"),
        ) {
            let mut d = Map::new();
            d.insert("client_id".into(), json!(if id_matches { URL } else { "https://x.example/c" }));
            if let Some(m) = method { d.insert("token_endpoint_auth_method".into(), json!(m)); }
            d.insert("grant_types".into(), json!(grants));
            d.insert("redirect_uris".into(), json!(redirects));
            if let Some(s) = scope { d.insert("scope".into(), json!(s)); }
            let body = Value::Object(d).to_string();
            if let Ok(m) = validate(URL, body.as_bytes(), &ServerCaps::default(), false) {
                prop_assert_eq!(m.client_id, URL);
                prop_assert!(!m.scopes.iter().any(|s| s.starts_with("admin")));
                prop_assert!(m.auth_method == ClientAuthMethod::None || m.auth_method == ClientAuthMethod::PrivateKeyJwt);
            }
        }
    }
}
