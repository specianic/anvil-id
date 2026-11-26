//! Pushed authorization request rules (RFC 9126, OIDC-18): the `request_uri` format, its
//! lifetime, which front-channel parameters are honoured, and the client policy re-check when a
//! pushed request is used (RFC 9126 §7.4).
//!
//! These functions are pure; [`crate::service::par::ParService`] and
//! [`crate::service::authorize::AuthorizeService::resume_pushed_request`] orchestrate the ports.
//!
//! - A `request_uri` is [`REQUEST_URI_PREFIX`] followed by exactly [`REQUEST_URI_RANDOM_CHARS`]
//!   base64url characters (32 random bytes). Only its SHA-256 is stored ([`RequestUriHash`]).
//! - It lives [`LIFETIME`] and is strictly single-use (a browser reload gets an error page; RFC
//!   9126 §7.3 allows that).
//! - At the authorization endpoint only [`FRONT_CHANNEL_PARAMETERS`] are read. Every other
//!   front-channel parameter is ignored; the pushed parameters are the request.

use time::Duration;

use anvil_jose::encoding::{b64url, secret_hash};

use crate::error::CoreError;
use crate::model::{
    AuthorizationParams, Client, ClientType, GrantType, RegistrationMode, RequestUriHash,
    SecretHash,
};
use crate::oauth::authorize_request::{AuthorizeError, PROMPT_CREATE};
use crate::oauth::redirect::redirect_matches;

/// RFC 9126 §2.2: the URN prefix of every `request_uri` issued by the PAR endpoint.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Lifetime of a pushed request (`expires_in`). Short on purpose: the client redirects the user
/// right after pushing.
pub const LIFETIME: Duration = Duration::seconds(60);

/// Number of base64url characters after the prefix (32 random bytes, unpadded).
pub const REQUEST_URI_RANDOM_CHARS: usize = 43;

/// The only front-channel parameters read when `/authorize` carries a pushed `request_uri`
/// (RFC 9126 §4). Everything else in the query is ignored.
pub const FRONT_CHANNEL_PARAMETERS: [&str; 2] = ["client_id", "request_uri"];

/// The `request_uri` for 32 random bytes, and the hash under which it is stored.
pub fn new_request_uri(random32: [u8; 32]) -> (String, RequestUriHash) {
    let uri = format!("{REQUEST_URI_PREFIX}{}", b64url(&random32));
    let hash = SecretHash(secret_hash(&uri));
    (uri, hash)
}

/// Whether `value` claims to be a pushed `request_uri` (has the PAR URN prefix). Such a value
/// is resolved by the service layer; any other `request_uri` stays `request_uri_not_supported`.
pub fn is_pushed_request_uri(value: &str) -> bool {
    value.starts_with(REQUEST_URI_PREFIX)
}

/// The lookup hash of a well-formed `request_uri`: the prefix and exactly
/// [`REQUEST_URI_RANDOM_CHARS`] base64url characters. `None` for anything else.
pub fn parse_request_uri(value: &str) -> Option<RequestUriHash> {
    let random = value.strip_prefix(REQUEST_URI_PREFIX)?;
    if random.len() != REQUEST_URI_RANDOM_CHARS
        || !random
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(SecretHash(secret_hash(value)))
}

/// Parameters of a pushed body that carry client credentials. They are read by client
/// authentication and are not authorization request parameters.
pub const CLIENT_AUTH_PARAMETERS: [&str; 3] =
    ["client_secret", "client_assertion_type", "client_assertion"];

/// Maps a validation failure at the PAR endpoint to its JSON error (RFC 9126 §2.3: errors are
/// RFC 6749 §5.2 responses, never redirects). Errors that would be an error page at
/// `/authorize` (repeated or mismatched `redirect_uri`, ...) are `invalid_request`.
pub fn push_error(error: AuthorizeError) -> CoreError {
    match error {
        AuthorizeError::ErrorPage { detail, .. } => CoreError::InvalidRequest(detail),
        AuthorizeError::Redirect { error, .. } => error,
    }
}

/// RFC 9126 §7.4: the client may have changed between push and use. Re-checks the stored,
/// already validated `params` against the client's current registration and the tenant's
/// registration mode, and returns the parameters to continue with (scopes the client may no
/// longer use are dropped, as `/authorize` would).
///
/// A redirect URI that is no longer registered is an error page; every other refusal is
/// delivered to that (still registered) redirect URI.
pub fn recheck_client_policy(
    client: &Client,
    params: &AuthorizationParams,
    registration: RegistrationMode,
) -> Result<AuthorizationParams, AuthorizeError> {
    if !redirect_matches(
        &client.redirect_uris,
        &params.redirect_uri,
        client.application_type,
    ) {
        return Err(AuthorizeError::ErrorPage {
            error_key: "redirect_uri_mismatch",
            detail: "redirect_uri is no longer registered".to_owned(),
        });
    }
    let fail = |error: CoreError| AuthorizeError::Redirect {
        redirect_uri: params.redirect_uri.clone(),
        state: params.state.clone(),
        response_mode: params.response_mode,
        error,
    };
    let invalid = |m: &str| fail(CoreError::InvalidRequest(m.to_owned()));
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(fail(CoreError::UnauthorizedClient(
            "the client may not use the authorization code grant".to_owned(),
        )));
    }
    let pkce_required = client.require_pkce || client.client_type == ClientType::Public;
    if pkce_required && params.code_challenge.is_none() {
        return Err(invalid("code_challenge is required for this client"));
    }
    let scope: crate::model::Scope = params
        .scope
        .split_whitespace()
        .filter(|t| client.scopes.iter().any(|a| a == t))
        .map(str::to_owned)
        .collect();
    if !scope.contains("openid") {
        return Err(fail(CoreError::InvalidScope(
            "the openid scope is required".to_owned(),
        )));
    }
    crate::oauth::resource::validate_resources(&params.resource, &client.allowed_resources)
        .map_err(&fail)?;
    if params.organization.is_some() && client.organization.is_off() {
        return Err(invalid(
            "this client does not accept the organization parameter",
        ));
    }
    if params.prompt.iter().any(|p| p == PROMPT_CREATE) && registration != RegistrationMode::Open {
        return Err(invalid(&format!(
            "unsupported prompt value {PROMPT_CREATE}"
        )));
    }
    let mut params = params.clone();
    params.scope = scope.to_string();
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::authorize_request::tests::{CHALLENGE, RP, client};

    fn params() -> AuthorizationParams {
        AuthorizationParams {
            redirect_uri: RP.to_owned(),
            scope: "openid profile".to_owned(),
            state: Some("st".to_owned()),
            nonce: Some("n".to_owned()),
            code_challenge: Some(CHALLENGE.to_owned()),
            prompt: vec![],
            max_age: None,
            login_hint: None,
            acr_values: vec![],
            ui_locales: None,
            claims: None,
            response_mode: Default::default(),
            resource: vec![],
            organization: None,
        }
    }

    fn redirect_error(r: Result<AuthorizationParams, AuthorizeError>) -> &'static str {
        match r {
            Err(AuthorizeError::Redirect { error, .. }) => error.oauth_error(),
            other => panic!("expected a redirect error, got {other:?}"),
        }
    }

    #[test]
    fn new_request_uri_has_the_prefix_43_chars_and_its_hash() {
        let (uri, hash) = new_request_uri([7u8; 32]);
        let random = uri.strip_prefix(REQUEST_URI_PREFIX).expect("prefix");
        assert_eq!(random.len(), REQUEST_URI_RANDOM_CHARS);
        assert_eq!(hash, SecretHash(secret_hash(&uri)));
        assert_eq!(parse_request_uri(&uri), Some(hash));
        let (other, other_hash) = new_request_uri([8u8; 32]);
        assert_ne!(uri, other);
        assert_ne!(hash, other_hash);
    }

    #[test]
    fn parse_request_uri_rejects_malformed_values() {
        let good = format!("{REQUEST_URI_PREFIX}{}", "a".repeat(43));
        assert!(parse_request_uri(&good).is_some());
        assert!(parse_request_uri(&format!("{REQUEST_URI_PREFIX}{}", "a".repeat(42))).is_none());
        assert!(parse_request_uri(&format!("{REQUEST_URI_PREFIX}{}", "a".repeat(44))).is_none());
        assert!(
            parse_request_uri(&format!("{REQUEST_URI_PREFIX}{}+", "a".repeat(42))).is_none(),
            "standard base64 is not base64url"
        );
        assert!(parse_request_uri(&format!("{REQUEST_URI_PREFIX}{}=", "a".repeat(42))).is_none());
        assert!(parse_request_uri(&format!("urn:example:{}", "a".repeat(43))).is_none());
        assert!(
            parse_request_uri(&format!(
                "URN:IETF:PARAMS:OAUTH:REQUEST_URI:{}",
                "a".repeat(43)
            ))
            .is_none()
        );
        assert!(parse_request_uri("https://rp.example.test/r").is_none());
        assert!(!is_pushed_request_uri("https://rp.example.test/r"));
        assert!(is_pushed_request_uri(&good));
    }

    #[test]
    fn push_errors_are_json_errors_never_pages() {
        let e = push_error(AuthorizeError::ErrorPage {
            error_key: "redirect_uri_mismatch",
            detail: "nope".to_owned(),
        });
        assert_eq!(e.oauth_error(), "invalid_request");
    }

    #[test]
    fn recheck_accepts_an_unchanged_client() {
        let p = recheck_client_policy(&client(), &params(), RegistrationMode::Disabled)
            .expect("unchanged client");
        assert_eq!(p, params());
    }

    #[test]
    fn recheck_refuses_a_removed_redirect_uri_with_an_error_page() {
        let mut c = client();
        c.redirect_uris = vec!["https://rp.example.test/other".to_owned()];
        assert!(matches!(
            recheck_client_policy(&c, &params(), RegistrationMode::Disabled),
            Err(AuthorizeError::ErrorPage {
                error_key: "redirect_uri_mismatch",
                ..
            })
        ));
    }

    #[test]
    fn recheck_follows_policy_changes() {
        let mut c = client();
        c.grant_types = vec![GrantType::ClientCredentials];
        assert_eq!(
            redirect_error(recheck_client_policy(
                &c,
                &params(),
                RegistrationMode::Disabled
            )),
            "unauthorized_client"
        );

        let mut p = params();
        p.code_challenge = None;
        assert_eq!(
            redirect_error(recheck_client_policy(
                &client(),
                &p,
                RegistrationMode::Disabled
            )),
            "invalid_request"
        );

        let mut c = client();
        c.scopes = vec!["profile".into()];
        assert_eq!(
            redirect_error(recheck_client_policy(
                &c,
                &params(),
                RegistrationMode::Disabled
            )),
            "invalid_scope"
        );

        let mut c = client();
        c.scopes = vec!["openid".into()];
        let p = recheck_client_policy(&c, &params(), RegistrationMode::Disabled).expect("narrowed");
        assert_eq!(p.scope, "openid");

        let mut p = params();
        p.resource = vec!["https://api.example.test".to_owned()];
        assert_eq!(
            redirect_error(recheck_client_policy(
                &client(),
                &p,
                RegistrationMode::Disabled
            )),
            "invalid_target"
        );

        let mut p = params();
        p.organization = Some("acme".to_owned());
        assert_eq!(
            redirect_error(recheck_client_policy(
                &client(),
                &p,
                RegistrationMode::Disabled
            )),
            "invalid_request"
        );

        let mut p = params();
        p.prompt = vec![PROMPT_CREATE.to_owned()];
        assert_eq!(
            redirect_error(recheck_client_policy(
                &client(),
                &p,
                RegistrationMode::Disabled
            )),
            "invalid_request"
        );
        assert!(recheck_client_policy(&client(), &p, RegistrationMode::Open).is_ok());
    }
}
