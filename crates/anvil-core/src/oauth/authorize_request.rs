//! Authorization request parsing and validation (RFC 6749 §4.1.1, OIDC Core §3.1.2.1).
//!
//! [`validate`] is pure. It checks in the order that decides how an error is reported
//! (RFC 6749 §4.1.2.1, RFC 9700 §4.1): until the client and the redirect URI are trusted, every
//! error is an error page; after that, every error is a redirect to that URI.
//!
//! Order: client_id (missing or duplicated → page) → client (unknown → page) → redirect_uri
//! (duplicated or not matching → page; required when the client has more than one registered,
//! else defaults to the single one) → other duplicated parameters → response_type →
//! request / request_uri → PKCE (public clients and `require_pkce` clients only; opted-out
//! confidential clients may omit both PKCE and nonce) → scope → redirect_uri required for OpenID
//! requests → prompt / max_age → claims.

use crate::error::CoreError;
use crate::model::{AuthorizationParams, Client, ClientType, Scope};
use crate::oauth::claims_request::parse_claims;
use crate::oauth::redirect::redirect_matches;

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

    fn first_duplicate(&self) -> Option<&str> {
        self.0
            .iter()
            .enumerate()
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
    /// Redirect the error to the trusted `redirect_uri`.
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        error: CoreError,
    },
}

fn page(error_key: &'static str, detail: &str) -> AuthorizeError {
    AuthorizeError::ErrorPage {
        error_key,
        detail: detail.to_owned(),
    }
}

/// Supported `prompt` values. `consent` and `select_account` are accepted and have no effect in
/// 0.1 (no consent screen, one account per session).
const PROMPT_VALUES: [&str; 4] = ["none", "login", "consent", "select_account"];

/// Validates an authorization request. `client` is the client looked up by the request's
/// `client_id` (`None` when unknown).
pub fn validate(
    raw: &RawParams,
    client: Option<&Client>,
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
    let fail = |error: CoreError| AuthorizeError::Redirect {
        redirect_uri: redirect_uri.clone(),
        state: state.clone(),
        error,
    };
    let invalid = |m: &str| fail(CoreError::InvalidRequest(m.to_owned()));

    // 3. any other duplicated parameter
    if let Some(dup) = raw.first_duplicate() {
        return Err(invalid(&format!("parameter {dup} is repeated")));
    }

    // 4. response_type
    match raw.get("response_type") {
        None => return Err(invalid("response_type is missing")),
        Some("code") => {}
        Some(_) => return Err(fail(CoreError::UnsupportedResponseType)),
    }

    // 5. request objects
    if raw.get("request").is_some() {
        return Err(fail(CoreError::RequestNotSupported));
    }
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
    if let Some(bad) = prompt.iter().find(|p| !PROMPT_VALUES.contains(&p.as_str())) {
        return Err(invalid(&format!("unsupported prompt value {bad}")));
    }
    if prompt.iter().any(|p| p == "none") && prompt.len() > 1 {
        return Err(invalid("prompt=none cannot be combined with other values"));
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
        },
        id_token_hint: raw.get("id_token_hint").map(str::to_owned),
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
            }) => {
                assert_eq!(redirect_uri, RP);
                (error.oauth_error(), state)
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[test]
    fn valid_request() {
        let c = client();
        let v = validate(&raw(&base()), Some(&c)).unwrap();
        assert_eq!(v.params.redirect_uri, RP);
        assert_eq!(v.params.scope, "openid profile");
        assert_eq!(v.params.state.as_deref(), Some("st"));
        assert_eq!(v.params.code_challenge.as_deref(), Some(CHALLENGE));
        assert!(v.id_token_hint.is_none());
    }

    #[test]
    fn unknown_client_is_error_page() {
        assert_eq!(page_key(validate(&raw(&base()), None)), "unknown_client");
        let mut other = client();
        other.client_id = "someone-else".into();
        assert_eq!(
            page_key(validate(&raw(&base()), Some(&other))),
            "unknown_client"
        );
        let c = client();
        assert_eq!(
            page_key(validate(&with(&[("client_id", None)]), Some(&c))),
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
        assert_eq!(page_key(validate(&r, Some(&c))), "redirect_uri_mismatch");
        let r = with(&[("redirect_uri", Some("https://rp.example.test/cb/"))]);
        assert_eq!(page_key(validate(&r, Some(&c))), "redirect_uri_mismatch");
    }

    #[test]
    fn duplicate_redirect_uri_or_client_id_is_error_page() {
        let c = client();
        let mut p = base();
        p.push(("redirect_uri", RP));
        assert_eq!(page_key(validate(&raw(&p), Some(&c))), "invalid_request");
        let mut p = base();
        p.push(("client_id", "rp"));
        assert_eq!(page_key(validate(&raw(&p), Some(&c))), "invalid_request");
    }

    #[test]
    fn missing_redirect_with_several_registered_is_error_page() {
        let c = client();
        assert_eq!(
            page_key(validate(&with(&[("redirect_uri", None)]), Some(&c))),
            "invalid_request"
        );
    }

    #[test]
    fn missing_redirect_with_single_registered_redirects_error() {
        let mut c = client();
        c.redirect_uris = vec![RP.to_owned()];
        // Trusted for error reporting, but an OpenID request must name it explicitly.
        let r = with(&[("redirect_uri", None)]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_request");
        let r = with(&[("redirect_uri", None), ("response_type", Some("token"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c))).0,
            "unsupported_response_type"
        );
    }

    #[test]
    fn response_type_errors_redirect() {
        let c = client();
        assert_eq!(
            redirect_err(validate(&with(&[("response_type", None)]), Some(&c))),
            ("invalid_request", Some("st".to_owned()))
        );
        for rt in ["token", "id_token", "code id_token", "code token"] {
            let r = with(&[("response_type", Some(rt))]);
            assert_eq!(
                redirect_err(validate(&r, Some(&c))).0,
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
            redirect_err(validate(&r, Some(&c))).0,
            "request_not_supported"
        );
        let r = with(&[("request_uri", Some("https://rp.example.test/r"))]);
        assert_eq!(
            redirect_err(validate(&r, Some(&c))).0,
            "request_uri_not_supported"
        );
    }

    #[test]
    fn duplicate_state_or_other_param_redirects_invalid_request() {
        let c = client();
        let mut p = base();
        p.push(("state", "again"));
        assert_eq!(
            redirect_err(validate(&raw(&p), Some(&c))),
            ("invalid_request", None)
        );
        let mut p = base();
        p.push(("scope", "openid"));
        assert_eq!(
            redirect_err(validate(&raw(&p), Some(&c))),
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
                redirect_err(validate(&r, Some(&c))).0,
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
        let v = validate(&with(&no_pkce), Some(&c)).unwrap();
        assert!(v.params.nonce.is_none());
        assert!(v.params.code_challenge.is_none());
        let mut changes = no_pkce.to_vec();
        changes.push(("nonce", Some("n-123")));
        let v = validate(&with(&changes), Some(&c)).unwrap();
        assert_eq!(v.params.nonce.as_deref(), Some("n-123"));
        // Opting out does not relax the S256-only rule or partial PKCE parameters.
        for bad in [
            vec![("code_challenge_method", Some("plain"))],
            vec![("code_challenge_method", None)],
            vec![("code_challenge", None)],
        ] {
            assert_eq!(
                redirect_err(validate(&with(&bad), Some(&c))).0,
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
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_request");
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
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_request");
        let r = with(&[("code_challenge", None), ("code_challenge_method", None)]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_request");
    }

    #[test]
    fn scope_filtering_and_openid_requirement() {
        let c = client();
        let r = with(&[("scope", Some("openid admin email"))]);
        assert_eq!(validate(&r, Some(&c)).unwrap().params.scope, "email openid");
        let r = with(&[("scope", Some("profile"))]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_scope");
        let r = with(&[("scope", None)]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_scope");
        let r = with(&[("scope", Some("openid  profile"))]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_scope");
    }

    #[test]
    fn prompt_and_max_age() {
        let c = client();
        let r = with(&[("prompt", Some("none login"))]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_request");
        let r = with(&[("prompt", Some("bogus"))]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_request");
        for bad in ["-1", "abc", "+5", "1.5", "99999999999"] {
            let r = with(&[("max_age", Some(bad))]);
            assert_eq!(
                redirect_err(validate(&r, Some(&c))).0,
                "invalid_request",
                "{bad}"
            );
        }
        let r = with(&[("prompt", Some("login consent")), ("max_age", Some("0"))]);
        let v = validate(&r, Some(&c)).unwrap();
        assert_eq!(v.params.prompt, vec!["login", "consent"]);
        assert_eq!(v.params.max_age, Some(0));
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
        let v = validate(&r, Some(&c)).unwrap();
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
        let v = validate(&r, Some(&c)).unwrap();
        assert!(v.params.claims.unwrap().userinfo[0].essential);
        let r = with(&[("claims", Some("{not json"))]);
        assert_eq!(redirect_err(validate(&r, Some(&c))).0, "invalid_request");
    }

    #[test]
    fn empty_values_are_treated_as_omitted() {
        let c = client();
        let r = with(&[("request", Some("")), ("prompt", Some(""))]);
        assert!(validate(&r, Some(&c)).is_ok());
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
}
