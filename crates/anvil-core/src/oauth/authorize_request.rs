//! Authorization request parsing and validation (RFC 6749 §4.1.1, OIDC Core §3.1.2.1).
//!
//! [`validate`] is pure. It checks in the order that decides how an error is reported
//! (RFC 6749 §4.1.2.1, RFC 9700 §4.1): until the client and the redirect URI are trusted, every
//! error is an error page; after that, every error is a redirect to that URI.
//!
//! Order: client_id (missing or duplicated → page) → client (unknown → page) → redirect_uri
//! (duplicated or not matching → page; required when the client has more than one registered,
//! else defaults to the single one) → response_mode (an unsupported value is reported with the
//! default `query` mode; every later error uses the requested mode) → other duplicated
//! parameters → response_type →
//! request / request_uri → PKCE (public clients and `require_pkce` clients only; opted-out
//! confidential clients may omit both PKCE and nonce) → scope → redirect_uri required for OpenID
//! requests → prompt (values supported by the tenant: `create` only with open registration;
//! `none` and `create`/`select_account` exclusive) / max_age → claims → resource (the only parameter that may repeat;
//! RFC 8707 §2.1, errors are `invalid_target`) → organization (at most
//! [`MAX_ORGANIZATION_LEN`] bytes, refused for clients whose organization policy is `off`; a
//! repeated value is a duplicated parameter like any other).

use crate::error::CoreError;
use crate::model::{AuthorizationParams, Client, ClientType, RegistrationMode, Scope};
use crate::oauth::claims_request::parse_claims;
use crate::oauth::redirect::redirect_matches;
use crate::oauth::response_mode::ResponseMode;

/// The only authorization request parameter that may repeat (RFC 8707 §2).
const REPEATABLE: &str = "resource";

/// Longest accepted `organization` value (an org id or slug), in bytes.
pub const MAX_ORGANIZATION_LEN: usize = 128;

/// Raw authorization request parameters, in arrival order, from the query (GET) or the form
/// body (POST). Built by the web layer or by [`parse_raw`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawParams(pub Vec<(String, String)>);

impl RawParams {
    /// Number of occurrences of `name` (empty values included).
    fn count(&self, name: &str) -> usize {
        self.0.iter().filter(|(k, _)| k == name).count()
    }

    /// The value of a parameter. RFC 6749 §3.1: a parameter sent without a value is treated as
    /// omitted. With duplicates, the first value is returned (callers check duplicates first).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    /// The single value of a parameter, `None` when it is absent, empty or duplicated.
    pub fn single(&self, name: &str) -> Option<&str> {
        if self.count(name) == 1 {
            self.get(name)
        } else {
            None
        }
    }

    /// Every non-empty value of a parameter that may repeat, in arrival order. Empty values are
    /// treated as omitted (RFC 6749 §3.1).
    pub fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// The first parameter that occurs more than once. `resource` is the only parameter allowed
    /// to repeat (RFC 8707 §2) and is never reported.
    fn first_duplicate(&self) -> Option<&str> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, (k, _))| k != REPEATABLE)
            .find(|(i, (k, _))| self.0[..*i].iter().any(|(p, _)| p == k))
            .map(|(_, (k, _))| k.as_str())
    }
}

impl From<Vec<(String, String)>> for RawParams {
    fn from(v: Vec<(String, String)>) -> Self {
        Self(v)
    }
}

/// Parses an `application/x-www-form-urlencoded` query string or form body.
pub fn parse_raw(bytes: &[u8]) -> RawParams {
    RawParams(
        url::form_urlencoded::parse(bytes)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    )
}

/// A request that passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthorize {
    pub client: Client,
    pub params: AuthorizationParams,
    /// The raw `id_token_hint`; verified by the service. Never logged.
    pub id_token_hint: Option<String>,
}

/// Why validation failed, and how the failure must be reported.
#[derive(Debug)]
pub enum AuthorizeError {
    /// The client or the redirect URI is not trusted: show an error page, never redirect.
    /// `error_key` is one of `invalid_request`, `unknown_client`, `redirect_uri_mismatch`.
    ErrorPage {
        error_key: &'static str,
        detail: String,
    },
    /// Deliver the error to the trusted `redirect_uri` with `response_mode`.
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        response_mode: ResponseMode,
        error: CoreError,
    },
}

fn page(error_key: &'static str, detail: &str) -> AuthorizeError {
    AuthorizeError::ErrorPage {
        error_key,
        detail: detail.to_owned(),
    }
}

/// `prompt` values every tenant supports (OIDC Core §3.1.2.1).
pub const PROMPT_VALUES: [&str; 4] = ["none", "login", "consent", "select_account"];

/// `prompt=create` (Initiating User Registration 1.0): supported only by tenants whose
/// registration is open.
pub const PROMPT_CREATE: &str = "create";

/// The `prompt` values a tenant with `registration` supports: [`PROMPT_VALUES`], plus
/// [`PROMPT_CREATE`] when registration is open. Validation and discovery both use this.
pub fn supported_prompt_values(registration: RegistrationMode) -> Vec<&'static str> {
    let mut values = PROMPT_VALUES.to_vec();
    if registration == RegistrationMode::Open {
        values.push(PROMPT_CREATE);
    }
    values
}

/// Validates an authorization request. `client` is the client looked up by the request's
/// `client_id` (`None` when unknown); `registration` is the tenant's registration mode, which
/// decides whether `prompt=create` is supported.
pub fn validate(
    raw: &RawParams,
    client: Option<&Client>,
    registration: RegistrationMode,
) -> Result<ValidatedAuthorize, AuthorizeError> {
    // 1. client_id
    if raw.count("client_id") > 1 {
        return Err(page("invalid_request", "client_id is repeated"));
    }
    let Some(client_id) = raw.get("client_id") else {
        return Err(page("invalid_request", "client_id is missing"));
    };
    let client = match client {
        Some(c) if c.client_id == client_id => c,
        _ => return Err(page("unknown_client", "the client is not registered")),
    };

    // 2. redirect_uri
    if raw.count("redirect_uri") > 1 {
        return Err(page("invalid_request", "redirect_uri is repeated"));
    }
    let explicit_redirect = raw.get("redirect_uri");
    let redirect_uri = match explicit_redirect {
        Some(r) => {
            if !redirect_matches(&client.redirect_uris, r, client.application_type) {
                return Err(page(
                    "redirect_uri_mismatch",
                    "redirect_uri does not match a registered redirect URI",
                ));
            }
            r.to_owned()
        }
        None => match client.redirect_uris.as_slice() {
            [only] => only.clone(),
            _ => return Err(page("invalid_request", "redirect_uri is missing")),
        },
    };

    // From here on the redirect URI is trusted.
    let state = raw.single("state").map(str::to_owned);

    // 3. response_mode. An unsupported or repeated value cannot select the delivery, so that
    // error goes out with the default query mode; every later error uses the requested mode.
    let response_mode = match ResponseMode::parse(raw.single("response_mode")) {
        Ok(mode) => mode,
        Err(error) => {
            return Err(AuthorizeError::Redirect {
                redirect_uri,
                state,
                response_mode: ResponseMode::Query,
                error,
            });
        }
    };
    if raw.count("response_mode") > 1 {
        return Err(AuthorizeError::Redirect {
            redirect_uri,
            state,
            response_mode: ResponseMode::Query,
            error: CoreError::InvalidRequest("parameter response_mode is repeated".to_owned()),
        });
    }
    let fail = |error: CoreError| AuthorizeError::Redirect {
        redirect_uri: redirect_uri.clone(),
        state: state.clone(),
        response_mode,
        error,
    };
    let invalid = |m: &str| fail(CoreError::InvalidRequest(m.to_owned()));

    // 3b. any other duplicated parameter
    if let Some(dup) = raw.first_duplicate() {
        return Err(invalid(&format!("parameter {dup} is repeated")));
    }

    // 4. response_type
    match raw.get("response_type") {
        None => return Err(invalid("response_type is missing")),
        Some("code") => {}
        Some(_) => return Err(fail(CoreError::UnsupportedResponseType)),
    }

    // 5. request objects. They are not supported, but OIDC Core §6.1 lets `response_mode` and
    // `state` travel only inside the object, so the rejection is delivered the way the client
    // asked: outer parameters first, then the object's (read unverified, never trusted for
    // anything but this error's delivery). A `request_uri` is never fetched.
    if let Some(object) = raw.get("request") {
        let hints = peek_request_object(object);
        let response_mode = if raw.single("response_mode").is_some() {
            response_mode
        } else {
            hints
                .as_ref()
                .map_or(ResponseMode::Query, |h| h.response_mode)
        };
        let state = state.or_else(|| hints.and_then(|h| h.state));
        return Err(AuthorizeError::Redirect {
            redirect_uri,
            state,
            response_mode,
            error: CoreError::RequestNotSupported,
        });
    }
    // A pushed `request_uri` (RFC 9126, `urn:ietf:params:oauth:request_uri:`) is resolved by
    // the service layer before validation (`AuthorizeService::resume_pushed_request`) and never
    // reaches this function; every value that does is a request object by reference.
    if raw.get("request_uri").is_some() {
        return Err(fail(CoreError::RequestUriNotSupported));
    }

    // 6. PKCE (RFC 7636, RFC 9700 §2.1.1: S256 only)
    let challenge = raw.get("code_challenge");
    match (challenge, raw.get("code_challenge_method")) {
        (Some(c), Some("S256")) => {
            if !anvil_jose::pkce::is_valid_challenge(c) {
                return Err(invalid("code_challenge must be 43 base64url characters"));
            }
        }
        (Some(_), None) => {
            return Err(invalid(
                "code_challenge_method is required and must be S256",
            ));
        }
        (_, Some("S256")) => return Err(invalid("code_challenge_method without code_challenge")),
        (_, Some(_)) => return Err(invalid("code_challenge_method must be S256")),
        (None, None) => {}
    }
    // Public clients always need PKCE, whatever the stored flag says (defence in depth).
    let pkce_required = client.require_pkce || client.client_type == ClientType::Public;
    if pkce_required && challenge.is_none() {
        return Err(invalid("code_challenge is required for this client"));
    }

    // 7. scope: drop scopes the client may not use; 0.1 serves OpenID requests only.
    let requested = match raw.get("scope") {
        Some(s) => Scope::parse(s).map_err(&fail)?,
        None => Scope::default(),
    };
    let scope: Scope = requested
        .iter()
        .filter(|t| client.scopes.iter().any(|a| a == t))
        .map(str::to_owned)
        .collect();
    if !scope.contains("openid") {
        return Err(fail(CoreError::InvalidScope(
            "the openid scope is required".to_owned(),
        )));
    }

    // 8. OIDC Core §3.1.2.1: redirect_uri is REQUIRED in OpenID requests. The single-URI default
    // above only serves to report errors; a code is never bound to an implicit redirect URI.
    if explicit_redirect.is_none() {
        return Err(invalid("redirect_uri is required"));
    }

    // 9. nonce is optional for the code flow (OIDC Core §3.1.2.1). After step 6, a request
    // without PKCE can only come from a confidential client an admin set to
    // `require_pkce = false`; its code stays bound to the client's authentication at the token
    // endpoint. Public clients and `require_pkce = true` clients never get here without PKCE.
    let nonce = raw.get("nonce").map(str::to_owned);
    debug_assert!(
        challenge.is_some()
            || (client.client_type == ClientType::Confidential && !client.require_pkce)
    );

    // 10. prompt and max_age
    let prompt: Vec<String> = raw
        .get("prompt")
        .map(|p| p.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let supported = supported_prompt_values(registration);
    if let Some(bad) = prompt.iter().find(|p| !supported.contains(&p.as_str())) {
        return Err(invalid(&format!("unsupported prompt value {bad}")));
    }
    if prompt.iter().any(|p| p == "none") && prompt.len() > 1 {
        return Err(invalid("prompt=none cannot be combined with other values"));
    }
    // Creating an account and choosing an existing one contradict each other.
    if prompt.iter().any(|p| p == PROMPT_CREATE) && prompt.iter().any(|p| p == "select_account") {
        return Err(invalid(
            "prompt=create cannot be combined with select_account",
        ));
    }
    let max_age = match raw.get("max_age") {
        None => None,
        Some(m) => {
            if m.is_empty() || m.len() > 10 || !m.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("max_age must be a non-negative integer"));
            }
            Some(
                m.parse::<i64>()
                    .map_err(|_| invalid("max_age must be a non-negative integer"))?,
            )
        }
    };

    // 11. claims
    let claims = match raw.get("claims") {
        Some(c) => Some(parse_claims(c).map_err(&fail)?),
        None => None,
    };

    // 12. resource indicators (RFC 8707 §2.1): absolute URIs without fragment or query, each one
    // of the client's allowed resources; anything else is invalid_target.
    let resource = crate::oauth::resource::parse_resources(&raw.all("resource")).map_err(&fail)?;
    crate::oauth::resource::validate_resources(&resource, &client.allowed_resources)
        .map_err(&fail)?;

    // 13. organization (ORG-02): an org id or slug, resolved against the user's memberships
    // only after sign-in. A client that does not use organizations never accepts one.
    let organization = match raw.get("organization") {
        None => None,
        Some(o) if o.len() > MAX_ORGANIZATION_LEN || o.chars().any(char::is_control) => {
            return Err(invalid(&format!(
                "organization must be at most {MAX_ORGANIZATION_LEN} bytes without control characters"
            )));
        }
        Some(_) if client.organization.is_off() => {
            return Err(invalid(
                "this client does not accept the organization parameter",
            ));
        }
        Some(o) => Some(o.to_owned()),
    };

    let acr_values = raw
        .get("acr_values")
        .map(|a| a.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();

    Ok(ValidatedAuthorize {
        client: client.clone(),
        params: AuthorizationParams {
            redirect_uri: redirect_uri.clone(),
            scope: scope.to_string(),
            state: state.clone(),
            nonce,
            code_challenge: challenge.map(str::to_owned),
            prompt,
            max_age,
            login_hint: raw.get("login_hint").map(str::to_owned),
            acr_values,
            ui_locales: raw.get("ui_locales").map(str::to_owned),
            claims,
            response_mode,
            resource,
            organization,
        },
        id_token_hint: raw.get("id_token_hint").map(str::to_owned),
    })
}

/// Largest request object [`peek_request_object`] looks into.
const MAX_PEEKED_REQUEST_OBJECT: usize = 8 * 1024;

/// Error-delivery hints read from an unsupported request object.
#[derive(Debug)]
struct RequestObjectHints {
    /// `form_post` only when the object says exactly that; anything else is `query`.
    response_mode: ResponseMode,
    state: Option<String>,
}

/// Reads `response_mode` and `state` from the claims of a compact JWS request object WITHOUT
/// verifying it. The result only chooses how `request_not_supported` is delivered to an already
/// validated redirect URI (and echoes `state`); it never authorizes anything. `None` when the
/// object is larger than [`MAX_PEEKED_REQUEST_OBJECT`], not three dot-separated segments, or its
/// payload is not strict base64url of a JSON object.
fn peek_request_object(object: &str) -> Option<RequestObjectHints> {
    if object.len() > MAX_PEEKED_REQUEST_OBJECT {
        return None;
    }
    let mut parts = object.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = anvil_jose::encoding::b64url_decode(payload).ok()?;
    let serde_json::Value::Object(claims) = serde_json::from_slice(&bytes).ok()? else {
        return None;
    };
    let response_mode = match claims.get("response_mode").and_then(|v| v.as_str()) {
        Some("form_post") => ResponseMode::FormPost,
        _ => ResponseMode::Query,
    };
    let state = claims
        .get("state")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Some(RequestObjectHints {
        response_mode,
        state,
    })
}

/// Appends `pairs` to `redirect_uri` as percent-encoded query parameters, keeping any query the
/// registered URI already has.
pub fn redirect_with(redirect_uri: &str, pairs: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    let query = ser.finish();
    let mut out = String::with_capacity(redirect_uri.len() + query.len() + 1);
    out.push_str(redirect_uri);
    if query.is_empty() {
        return out;
    }
    match redirect_uri.find('?') {
        None => out.push('?'),
        Some(_) if redirect_uri.ends_with('?') || redirect_uri.ends_with('&') => {}
        Some(_) => out.push('&'),
    }
    out.push_str(&query);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{ApplicationType, ClientAuthMethod, ClientId, GrantType, TenantId};
    use time::macros::datetime;

    pub(crate) const RP: &str = "https://rp.example.test/cb";
    pub(crate) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    pub(crate) fn client() -> Client {
        Client {
            id: ClientId::new_v7(),
            tenant_id: TenantId::new_v7(),
            client_id: "rp".to_owned(),
            name: "RP".to_owned(),
            client_type: ClientType::Confidential,
            application_type: ApplicationType::Web,
            auth_method: ClientAuthMethod::ClientSecretBasic,
            secret_hash: None,
            jwks: None,
            redirect_uris: vec![RP.to_owned(), "https://rp.example.test/other".to_owned()],
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            require_pkce: true,
            created_at: datetime!(2026-11-25 00:00 UTC),
            updated_at: datetime!(2026-11-25 00:00 UTC),
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
            organization: crate::model::OrgClientPolicy::Off,
            require_pushed_authorization_requests: false,
            client_kind: crate::model::ClientKind::Application,
            headless_native: false,
        }
    }

    pub(crate) fn base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("client_id", "rp"),
            ("redirect_uri", RP),
            ("response_type", "code"),
            ("scope", "openid profile"),
            ("state", "st"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ]
    }

    fn raw(pairs: &[(&str, &str)]) -> RawParams {
        RawParams(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    fn with(changes: &[(&'static str, Option<&'static str>)]) -> RawParams {
        let mut p = base();
        for (k, v) in changes {
            p.retain(|(pk, _)| pk != k);
            if let Some(v) = v {
                p.push((k, v));
            }
        }
        raw(&p)
    }

    fn page_key(r: Result<ValidatedAuthorize, AuthorizeError>) -> &'static str {
        match r {
            Err(AuthorizeError::ErrorPage { error_key, .. }) => error_key,
            other => panic!("expected error page, got {other:?}"),
        }
    }

    fn redirect_err(
        r: Result<ValidatedAuthorize, AuthorizeError>,
    ) -> (&'static str, Option<String>) {
        match r {
            Err(AuthorizeError::Redirect {
                redirect_uri,
                state,
                error,
                ..
            }) => {
                assert_eq!(redirect_uri, RP);
                (error.oauth_error(), state)
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    fn redirect_mode(
        r: Result<ValidatedAuthorize, AuthorizeError>,
    ) -> (&'static str, ResponseMode) {
        match r {
            Err(AuthorizeError::Redirect {
                error,
                response_mode,
                ..
            }) => (error.oauth_error(), response_mode),
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[test]
    fn response_mode_parsing() {
        let c = client();
        let v = validate(&raw(&base()), Some(&c), RegistrationMode::Open).unwrap();
        assert_eq!(v.params.response_mode, ResponseMode::Query);
        let v = validate(
            &with(&[("response_mode", Some("query"))]),
            Some(&c),
            RegistrationMode::Open,
        )
        .unwrap();
        assert_eq!(v.params.response_mode, ResponseMode::Query);
        let v = validate(
            &with(&[("response_mode", Some("form_post"))]),
            Some(&c),
            RegistrationMode::Open,
        )
        .unwrap();
        assert_eq!(v.params.response_mode, ResponseMode::FormPost);
        // An empty value is treated as omitted (RFC 6749 §3.1).
        let v = validate(
            &with(&[("response_mode", Some(""))]),
            Some(&c),
            RegistrationMode::Open,
        )
        .unwrap();
        assert_eq!(v.params.response_mode, ResponseMode::Query);
        for bad in ["fragment", "FORM_POST", "x"] {
            let r = with(&[("response_mode", Some(bad))]);
            assert_eq!(
                redirect_mode(validate(&r, Some(&c), RegistrationMode::Open)),
                ("invalid_request", ResponseMode::Query),
                "{bad}"
            );
        }
    }

    #[test]
    fn repeated_response_mode_is_invalid_request_via_query() {
        let c = client();
        for second in ["form_post", "query"] {
            let mut p = base();
            p.push(("response_mode", "form_post"));
            p.push(("response_mode", second));
            assert_eq!(
                redirect_mode(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
                ("invalid_request", ResponseMode::Query)
            );
        }
    }

    #[test]
    fn later_errors_use_the_requested_mode() {
        let c = client();
        let r = with(&[
            ("response_mode", Some("form_post")),
            ("response_type", Some("token")),
        ]);
        assert_eq!(
            redirect_mode(validate(&r, Some(&c), RegistrationMode::Open)),
            ("unsupported_response_type", ResponseMode::FormPost)
        );
        let r = with(&[
            ("response_mode", Some("form_post")),
            ("scope", Some("profile")),
        ]);
        assert_eq!(
            redirect_mode(validate(&r, Some(&c), RegistrationMode::Open)),
            ("invalid_scope", ResponseMode::FormPost)
        );
        let mut p = base();
        p.push(("response_mode", "form_post"));
        p.push(("scope", "openid"));
        assert_eq!(
            redirect_mode(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            ("invalid_request", ResponseMode::FormPost)
        );
    }

    #[test]
    fn invalid_redirect_with_form_post_is_still_an_error_page() {
        let c = client();
        let r = with(&[
            ("redirect_uri", Some("https://evil.example.test/cb")),
            ("response_mode", Some("form_post")),
        ]);
        assert_eq!(
            page_key(validate(&r, Some(&c), RegistrationMode::Open)),
            "redirect_uri_mismatch"
        );
        let r = with(&[
            ("response_mode", Some("fragment")),
            ("client_id", Some("nope")),
        ]);
        assert_eq!(
            page_key(validate(&r, Some(&c), RegistrationMode::Open)),
            "unknown_client"
        );
    }

    #[test]
    fn valid_request() {
        let c = client();
        let v = validate(&raw(&base()), Some(&c), RegistrationMode::Open).unwrap();
        assert_eq!(v.params.redirect_uri, RP);
        assert_eq!(v.params.scope, "openid profile");
        assert_eq!(v.params.state.as_deref(), Some("st"));
        assert_eq!(v.params.code_challenge.as_deref(), Some(CHALLENGE));
        assert!(v.id_token_hint.is_none());
    }

    #[test]
    fn unknown_client_is_error_page() {
        assert_eq!(
            page_key(validate(&raw(&base()), None, RegistrationMode::Open)),
            "unknown_client"
        );
        let mut other = client();
        other.client_id = "someone-else".into();
        assert_eq!(
            page_key(validate(
                &raw(&base()),
                Some(&other),
                RegistrationMode::Open
            )),
            "unknown_client"
        );
        let c = client();
        assert_eq!(
            page_key(validate(
                &with(&[("client_id", None)]),
                Some(&c),
                RegistrationMode::Open,
            )),
            "invalid_request"
        );
    }

    #[test]
    fn mismatched_redirect_is_error_page_even_with_bad_response_type() {
        let c = client();
        let r = with(&[
            ("redirect_uri", Some("https://evil.example.test/cb")),
            ("response_type", Some("token")),
        ]);
        assert_eq!(
            page_key(validate(&r, Some(&c), RegistrationMode::Open)),
            "redirect_uri_mismatch"
        );
        let r = with(&[("redirect_uri", Some("https://rp.example.test/cb/"))]);
        assert_eq!(
            page_key(validate(&r, Some(&c), RegistrationMode::Open)),
            "redirect_uri_mismatch"
        );
    }

    #[test]
    fn duplicate_redirect_uri_or_client_id_is_error_page() {
        let c = client();
        let mut p = base();
        p.push(("redirect_uri", RP));
        assert_eq!(
            page_key(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            "invalid_request"
        );
        let mut p = base();
        p.push(("client_id", "rp"));
        assert_eq!(
            page_key(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            "invalid_request"
        );
    }

    #[test]
    fn missing_redirect_with_several_registered_is_error_page() {
        let c = client();
        assert_eq!(
            page_key(validate(
                &with(&[("redirect_uri", None)]),
                Some(&c),
                RegistrationMode::Open,
            )),
            "invalid_request"
        );
    }

    #[test]
    fn missing_redirect_with_single_registered_redirects_error() {
        let mut c = client();
        c.redirect_uris = vec![RP.to_owned()];
        // Trusted for error reporting, but an OpenID request must name it explicitly.
        let r = with(&[("redirect_uri", None)]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_request"
        );
        let r = with(&[("redirect_uri", None), ("response_type", Some("token"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "unsupported_response_type"
        );
    }

    #[test]
    fn response_type_errors_redirect() {
        let c = client();
        assert_eq!(
            redirect_err(validate(
                &with(&[("response_type", None)]),
                Some(&c),
                RegistrationMode::Open,
            )),
            ("invalid_request", Some("st".to_owned()))
        );
        for rt in ["token", "id_token", "code id_token", "code token"] {
            let r = with(&[("response_type", Some(rt))]);
            assert_eq!(
                redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
                "unsupported_response_type",
                "{rt}"
            );
        }
    }

    #[test]
    fn request_objects_not_supported() {
        let c = client();
        let r = with(&[("request", Some("eyJ.x.y"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "request_not_supported"
        );
        let r = with(&[("request_uri", Some("https://rp.example.test/r"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "request_uri_not_supported"
        );
    }

    /// An unsecured (`alg: none`) JWT with `payload` as its claims.
    fn unsigned_jwt(payload: &str) -> String {
        format!(
            "{}.{}.",
            anvil_jose::encoding::b64url(br#"{"alg":"none"}"#),
            anvil_jose::encoding::b64url(payload.as_bytes())
        )
    }

    /// `base()` with `remove` dropped and `add` appended (owned values).
    fn with_owned(remove: &[&str], add: &[(&str, String)]) -> RawParams {
        let mut p: Vec<(String, String)> = base()
            .into_iter()
            .filter(|(k, _)| !remove.contains(k))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        p.extend(add.iter().map(|(k, v)| ((*k).to_owned(), v.clone())));
        RawParams(p)
    }

    fn rejected(r: Result<ValidatedAuthorize, AuthorizeError>) -> (ResponseMode, Option<String>) {
        match r {
            Err(AuthorizeError::Redirect {
                redirect_uri,
                state,
                response_mode,
                error,
            }) => {
                assert_eq!(redirect_uri, RP);
                assert_eq!(error.oauth_error(), "request_not_supported");
                (response_mode, state)
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[test]
    fn rejected_request_object_uses_its_response_mode_and_state() {
        let c = client();
        let jwt = unsigned_jwt(r#"{"response_mode":"form_post","state":"obj-st"}"#);
        let r = with_owned(&["state"], &[("request", jwt)]);
        assert_eq!(
            rejected(validate(&r, Some(&c), RegistrationMode::Open)),
            (ResponseMode::FormPost, Some("obj-st".to_owned()))
        );
    }

    #[test]
    fn outer_response_mode_and_state_win_over_the_request_object() {
        let c = client();
        let jwt = unsigned_jwt(r#"{"response_mode":"form_post","state":"obj-st"}"#);
        let r = with_owned(
            &[],
            &[("response_mode", "query".to_owned()), ("request", jwt)],
        );
        assert_eq!(
            rejected(validate(&r, Some(&c), RegistrationMode::Open)),
            (ResponseMode::Query, Some("st".to_owned()))
        );
        let jwt = unsigned_jwt(r#"{"response_mode":"query"}"#);
        let r = with_owned(
            &[],
            &[("response_mode", "form_post".to_owned()), ("request", jwt)],
        );
        assert_eq!(
            rejected(validate(&r, Some(&c), RegistrationMode::Open)),
            (ResponseMode::FormPost, Some("st".to_owned()))
        );
    }

    #[test]
    fn unknown_response_mode_in_request_object_falls_back_to_query() {
        let c = client();
        for payload in [
            r#"{"response_mode":"fragment","state":"obj-st"}"#,
            r#"{"response_mode":"FORM_POST","state":"obj-st"}"#,
            r#"{"response_mode":"form_post.jwt","state":"obj-st"}"#,
            r#"{"response_mode":["form_post"],"state":"obj-st"}"#,
            r#"{"response_mode":1,"state":"obj-st"}"#,
            r#"{"state":"obj-st"}"#,
        ] {
            let r = with_owned(&["state"], &[("request", unsigned_jwt(payload))]);
            assert_eq!(
                rejected(validate(&r, Some(&c), RegistrationMode::Open)),
                (ResponseMode::Query, Some("obj-st".to_owned())),
                "{payload}"
            );
        }
        // A non-string state is not echoed.
        let jwt = unsigned_jwt(r#"{"response_mode":"form_post","state":42}"#);
        let r = with_owned(&["state"], &[("request", jwt)]);
        assert_eq!(
            rejected(validate(&r, Some(&c), RegistrationMode::Open)),
            (ResponseMode::FormPost, None)
        );
    }

    #[test]
    fn malformed_or_oversized_request_object_falls_back_to_outer_params() {
        let c = client();
        let fp = r#"{"response_mode":"form_post","state":"obj-st"}"#;
        let good_payload = anvil_jose::encoding::b64url(fp.as_bytes());
        let big = format!(
            r#"{{"response_mode":"form_post","state":"obj-st","pad":"{}"}}"#,
            "a".repeat(8 * 1024)
        );
        let malformed = [
            "not-a-jwt".to_owned(),
            "a.b".to_owned(),
            format!("x.{good_payload}.y.z"),
            format!("x.{good_payload}.y.z.w"),
            "x.!!!.".to_owned(),
            format!("x.{good_payload}=."),
            unsigned_jwt("not json"),
            unsigned_jwt(r#"["form_post"]"#),
            unsigned_jwt(&big),
        ];
        for jwt in malformed {
            // Outer state present: echoed; outer mode absent: query.
            let r = with_owned(&[], &[("request", jwt.clone())]);
            assert_eq!(
                rejected(validate(&r, Some(&c), RegistrationMode::Open)),
                (ResponseMode::Query, Some("st".to_owned())),
                "{jwt:.40}"
            );
            // Outer form_post is still honoured.
            let r = with_owned(
                &[],
                &[("response_mode", "form_post".to_owned()), ("request", jwt)],
            );
            assert_eq!(
                rejected(validate(&r, Some(&c), RegistrationMode::Open)).0,
                ResponseMode::FormPost
            );
        }
        // Just under the cap is still read.
        let jwt = unsigned_jwt(fp);
        assert!(jwt.len() <= 8 * 1024);
        let r = with_owned(&["state"], &[("request", jwt)]);
        assert_eq!(
            rejected(validate(&r, Some(&c), RegistrationMode::Open)).0,
            ResponseMode::FormPost
        );
    }

    #[test]
    fn request_object_never_rescues_an_untrusted_redirect() {
        let c = client();
        let jwt = unsigned_jwt(
            r#"{"response_mode":"form_post","redirect_uri":"https://rp.example.test/cb","client_id":"rp"}"#,
        );
        let r = with_owned(
            &["redirect_uri"],
            &[
                ("redirect_uri", "https://evil.example.test/cb".to_owned()),
                ("request", jwt.clone()),
            ],
        );
        assert_eq!(
            page_key(validate(&r, Some(&c), RegistrationMode::Open)),
            "redirect_uri_mismatch"
        );
        // No outer redirect_uri with several registered: still the page, even though the object
        // names one.
        let r = with_owned(&["redirect_uri"], &[("request", jwt.clone())]);
        assert_eq!(
            page_key(validate(&r, Some(&c), RegistrationMode::Open)),
            "invalid_request"
        );
        // Unknown client.
        let r = with_owned(
            &["client_id"],
            &[("client_id", "x".to_owned()), ("request", jwt)],
        );
        assert_eq!(
            page_key(validate(&r, Some(&c), RegistrationMode::Open)),
            "unknown_client"
        );
    }

    #[test]
    fn request_uri_uses_only_the_outer_response_mode() {
        let c = client();
        let r = with_owned(
            &[],
            &[
                ("response_mode", "form_post".to_owned()),
                ("request_uri", "https://rp.example.test/r".to_owned()),
            ],
        );
        assert_eq!(
            redirect_mode(validate(&r, Some(&c), RegistrationMode::Open)),
            ("request_uri_not_supported", ResponseMode::FormPost)
        );
    }

    #[test]
    fn duplicate_state_or_other_param_redirects_invalid_request() {
        let c = client();
        let mut p = base();
        p.push(("state", "again"));
        assert_eq!(
            redirect_err(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            ("invalid_request", None)
        );
        let mut p = base();
        p.push(("scope", "openid"));
        assert_eq!(
            redirect_err(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            ("invalid_request", Some("st".to_owned()))
        );
    }

    #[test]
    fn pkce_rules() {
        let c = client();
        let cases: Vec<RawParams> = vec![
            with(&[("code_challenge_method", Some("plain"))]),
            with(&[("code_challenge_method", None)]),
            with(&[("code_challenge", Some("short"))]),
            with(&[(
                "code_challenge",
                Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"),
            )]),
            with(&[("code_challenge", None)]),
            with(&[("code_challenge", None), ("code_challenge_method", None)]),
        ];
        for r in cases {
            assert_eq!(
                redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
                "invalid_request",
                "{r:?}"
            );
        }
    }

    #[test]
    fn opted_out_confidential_client_may_omit_pkce_and_nonce() {
        let mut c = client();
        c.require_pkce = false;
        let no_pkce = [("code_challenge", None), ("code_challenge_method", None)];
        let v = validate(&with(&no_pkce), Some(&c), RegistrationMode::Open).unwrap();
        assert!(v.params.nonce.is_none());
        assert!(v.params.code_challenge.is_none());
        let mut changes = no_pkce.to_vec();
        changes.push(("nonce", Some("n-123")));
        let v = validate(&with(&changes), Some(&c), RegistrationMode::Open).unwrap();
        assert_eq!(v.params.nonce.as_deref(), Some("n-123"));
        // Opting out does not relax the S256-only rule or partial PKCE parameters.
        for bad in [
            vec![("code_challenge_method", Some("plain"))],
            vec![("code_challenge_method", None)],
            vec![("code_challenge", None)],
        ] {
            assert_eq!(
                redirect_err(validate(&with(&bad), Some(&c), RegistrationMode::Open)).0,
                "invalid_request",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn require_pkce_client_without_pkce_is_rejected_even_with_nonce() {
        let c = client();
        assert!(c.require_pkce);
        let r = with(&[
            ("code_challenge", None),
            ("code_challenge_method", None),
            ("nonce", Some("n")),
        ]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_request"
        );
    }

    #[test]
    fn public_client_always_needs_pkce() {
        let mut c = client();
        c.require_pkce = false;
        c.client_type = ClientType::Public;
        let r = with(&[
            ("code_challenge", None),
            ("code_challenge_method", None),
            ("nonce", Some("n")),
        ]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_request"
        );
        let r = with(&[("code_challenge", None), ("code_challenge_method", None)]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_request"
        );
    }

    #[test]
    fn scope_filtering_and_openid_requirement() {
        let c = client();
        let r = with(&[("scope", Some("openid admin email"))]);
        assert_eq!(
            validate(&r, Some(&c), RegistrationMode::Open)
                .unwrap()
                .params
                .scope,
            "email openid"
        );
        let r = with(&[("scope", Some("profile"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_scope"
        );
        let r = with(&[("scope", None)]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_scope"
        );
        let r = with(&[("scope", Some("openid  profile"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_scope"
        );
    }

    #[test]
    fn prompt_and_max_age() {
        let c = client();
        let r = with(&[("prompt", Some("none login"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_request"
        );
        let r = with(&[("prompt", Some("bogus"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_request"
        );
        for bad in ["-1", "abc", "+5", "1.5", "99999999999"] {
            let r = with(&[("max_age", Some(bad))]);
            assert_eq!(
                redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
                "invalid_request",
                "{bad}"
            );
        }
        let r = with(&[("prompt", Some("login consent")), ("max_age", Some("0"))]);
        let v = validate(&r, Some(&c), RegistrationMode::Open).unwrap();
        assert_eq!(v.params.prompt, vec!["login", "consent"]);
        assert_eq!(v.params.max_age, Some(0));
        let r = with(&[("prompt", Some("select_account"))]);
        let v = validate(&r, Some(&c), RegistrationMode::Disabled).unwrap();
        assert_eq!(v.params.prompt, vec!["select_account"]);
        let r = with(&[("prompt", Some("none select_account"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)),
            ("invalid_request", Some("st".to_owned()))
        );
    }

    #[test]
    fn prompt_create_needs_open_registration() {
        let c = client();
        let r = with(&[("prompt", Some("create"))]);
        let v = validate(&r, Some(&c), RegistrationMode::Open).unwrap();
        assert_eq!(v.params.prompt, vec!["create"]);
        for closed in [RegistrationMode::InviteOnly, RegistrationMode::Disabled] {
            let Err(AuthorizeError::Redirect { error, state, .. }) = validate(&r, Some(&c), closed)
            else {
                panic!("create must be rejected for {closed:?}");
            };
            assert_eq!(error.oauth_error(), "invalid_request");
            assert_eq!(state.as_deref(), Some("st"));
            assert!(
                error
                    .to_string()
                    .contains("unsupported prompt value create")
            );
        }
        // Never combined with none or select_account, even on an open tenant.
        for bad in ["create none", "none create", "create select_account"] {
            let r = with(&[("prompt", Some(bad))]);
            assert_eq!(
                redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
                "invalid_request",
                "{bad}"
            );
        }
        // Combining with login or consent is allowed (not recommended by the spec).
        let r = with(&[("prompt", Some("create consent"))]);
        assert!(validate(&r, Some(&c), RegistrationMode::Open).is_ok());
    }

    #[test]
    fn supported_prompt_values_follow_the_registration_mode() {
        assert_eq!(
            supported_prompt_values(RegistrationMode::Open),
            ["none", "login", "consent", "select_account", "create"]
        );
        for closed in [RegistrationMode::InviteOnly, RegistrationMode::Disabled] {
            assert_eq!(
                supported_prompt_values(closed),
                ["none", "login", "consent", "select_account"]
            );
        }
    }

    #[test]
    fn optional_parameters_are_accepted() {
        let c = client();
        let r = with(&[
            ("display", Some("popup")),
            ("ui_locales", Some("de en")),
            ("claims_locales", Some("de")),
            ("login_hint", Some("alice@example.test")),
            ("acr_values", Some("urn:anvilid:acr:pwd other")),
            ("unknown", Some("x")),
            ("id_token_hint", Some("a.b.c")),
        ]);
        let v = validate(&r, Some(&c), RegistrationMode::Open).unwrap();
        assert_eq!(v.params.ui_locales.as_deref(), Some("de en"));
        assert_eq!(v.params.login_hint.as_deref(), Some("alice@example.test"));
        assert_eq!(v.params.acr_values, vec!["urn:anvilid:acr:pwd", "other"]);
        assert_eq!(v.id_token_hint.as_deref(), Some("a.b.c"));
    }

    #[test]
    fn claims_parameter() {
        let c = client();
        let r = with(&[(
            "claims",
            Some(r#"{"userinfo":{"name":{"essential":true}}}"#),
        )]);
        let v = validate(&r, Some(&c), RegistrationMode::Open).unwrap();
        assert!(v.params.claims.unwrap().userinfo[0].essential);
        let r = with(&[("claims", Some("{not json"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c), RegistrationMode::Open)).0,
            "invalid_request"
        );
    }

    #[test]
    fn empty_values_are_treated_as_omitted() {
        let c = client();
        let r = with(&[("request", Some("")), ("prompt", Some(""))]);
        assert!(validate(&r, Some(&c), RegistrationMode::Open).is_ok());
    }

    #[test]
    fn parse_raw_decodes_form() {
        let p =
            parse_raw(b"client_id=rp&redirect_uri=https%3A%2F%2Frp.example.test%2Fcb&state=a+b");
        assert_eq!(p.get("client_id"), Some("rp"));
        assert_eq!(p.get("redirect_uri"), Some(RP));
        assert_eq!(p.get("state"), Some("a b"));
        assert_eq!(p.get("missing"), None);
    }

    #[test]
    fn redirect_with_appends_query() {
        assert_eq!(
            redirect_with(RP, &[("code", "abc"), ("state", "a b&c")]),
            "https://rp.example.test/cb?code=abc&state=a+b%26c"
        );
        assert_eq!(
            redirect_with("https://rp.example.test/cb?x=1", &[("code", "abc")]),
            "https://rp.example.test/cb?x=1&code=abc"
        );
        assert_eq!(
            redirect_with("https://rp.example.test/cb?", &[("code", "abc")]),
            "https://rp.example.test/cb?code=abc"
        );
        assert_eq!(redirect_with(RP, &[]), RP);
    }

    const API: &str = "https://api.example.test";
    const MCP: &str = "https://mcp.example.test/mcp";

    fn resource_client() -> Client {
        let mut c = client();
        c.allowed_resources = vec![API.to_owned(), MCP.to_owned()];
        c
    }

    #[test]
    fn resource_may_repeat_and_is_stored() {
        let c = resource_client();
        let mut p = base();
        p.push(("resource", MCP));
        p.push(("resource", API));
        p.push(("resource", MCP));
        p.push(("resource", ""));
        let ok = validate(&raw(&p), Some(&c), RegistrationMode::Open).unwrap();
        assert_eq!(ok.params.resource, vec![MCP.to_owned(), API.to_owned()]);
    }

    #[test]
    fn no_resource_is_empty() {
        let c = resource_client();
        let ok = validate(&raw(&base()), Some(&c), RegistrationMode::Open).unwrap();
        assert!(ok.params.resource.is_empty());
        let ok = validate(
            &with(&[("resource", Some(""))]),
            Some(&c),
            RegistrationMode::Open,
        )
        .unwrap();
        assert!(ok.params.resource.is_empty());
    }

    #[test]
    fn repeated_resource_does_not_exempt_other_parameters() {
        let c = resource_client();
        let mut p = base();
        p.push(("resource", API));
        p.push(("resource", MCP));
        p.push(("scope", "openid"));
        assert_eq!(
            redirect_err(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            ("invalid_request", Some("st".to_owned()))
        );
    }

    #[test]
    fn bad_resources_redirect_invalid_target() {
        let c = resource_client();
        for bad in [
            "https://other.example.test",
            "https://api.example.test/",
            "/relative",
            "https://api.example.test#frag",
            "https://api.example.test?q=1",
            "api",
        ] {
            let mut p = base();
            p.push(("resource", API));
            p.push(("resource", bad));
            assert_eq!(
                redirect_err(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
                ("invalid_target", Some("st".to_owned())),
                "{bad}"
            );
        }
        // A client without allowed resources may not ask for any.
        let mut p = base();
        p.push(("resource", API));
        assert_eq!(
            redirect_err(validate(&raw(&p), Some(&client()), RegistrationMode::Open)).0,
            "invalid_target"
        );
    }

    #[test]
    fn bad_resource_with_untrusted_redirect_is_still_an_error_page() {
        let c = resource_client();
        let mut p = base();
        p.retain(|(k, _)| *k != "redirect_uri");
        p.push(("redirect_uri", "https://evil.example.test/cb"));
        p.push(("resource", "https://other.example.test"));
        assert_eq!(
            page_key(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            "redirect_uri_mismatch"
        );
    }

    fn org_client(policy: crate::model::OrgClientPolicy) -> Client {
        let mut c = client();
        c.organization = policy;
        c
    }

    #[test]
    fn organization_is_parsed_for_org_clients() {
        use crate::model::OrgClientPolicy::{Optional, Required};
        for policy in [Optional, Required] {
            let c = org_client(policy);
            let ok = validate(&raw(&base()), Some(&c), RegistrationMode::Open).unwrap();
            assert_eq!(ok.params.organization, None);
            let ok = validate(
                &with(&[("organization", Some("acme"))]),
                Some(&c),
                RegistrationMode::Open,
            )
            .unwrap();
            assert_eq!(ok.params.organization.as_deref(), Some("acme"));
            // An empty value is treated as omitted (RFC 6749 §3.1).
            let ok = validate(
                &with(&[("organization", Some(""))]),
                Some(&c),
                RegistrationMode::Open,
            )
            .unwrap();
            assert_eq!(ok.params.organization, None);
            let max = "a".repeat(MAX_ORGANIZATION_LEN);
            let ok = validate(
                &with_owned(&[], &[("organization", max.clone())]),
                Some(&c),
                RegistrationMode::Open,
            )
            .unwrap();
            assert_eq!(ok.params.organization, Some(max));
        }
    }

    #[test]
    fn repeated_organization_is_invalid_request() {
        let c = org_client(crate::model::OrgClientPolicy::Optional);
        let mut p = base();
        p.push(("organization", "acme"));
        p.push(("organization", "other"));
        assert_eq!(
            redirect_err(validate(&raw(&p), Some(&c), RegistrationMode::Open)),
            ("invalid_request", Some("st".to_owned()))
        );
    }

    #[test]
    fn oversized_or_control_organization_is_invalid_request() {
        let c = org_client(crate::model::OrgClientPolicy::Required);
        for bad in [
            "a".repeat(MAX_ORGANIZATION_LEN + 1),
            "acme\u{0}".to_owned(),
            "ac\nme".to_owned(),
        ] {
            assert_eq!(
                redirect_err(validate(
                    &with_owned(&[], &[("organization", bad)]),
                    Some(&c),
                    RegistrationMode::Open
                )),
                ("invalid_request", Some("st".to_owned()))
            );
        }
    }

    #[test]
    fn organization_is_refused_for_clients_without_organizations() {
        let c = org_client(crate::model::OrgClientPolicy::Off);
        assert_eq!(
            redirect_err(validate(
                &with(&[("organization", Some("acme"))]),
                Some(&c),
                RegistrationMode::Open
            )),
            ("invalid_request", Some("st".to_owned()))
        );
        // Without the parameter the client works as before.
        assert!(validate(&raw(&base()), Some(&c), RegistrationMode::Open).is_ok());
    }
}
