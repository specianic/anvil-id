//! OAuth 2.0 response modes and the single authorization-response builder (OIDC-25).
//!
//! Supported modes: `query` (RFC 6749 §4.1.2, the default for `response_type=code`) and
//! `form_post` (OAuth 2.0 Form Post Response Mode). `fragment` is not supported: it only makes
//! sense for implicit/hybrid responses, which AnvilID does not issue.
//!
//! Every authorization response (success, and every error once the redirect URI is trusted) is
//! built here as an [`AuthorizationResponse`]: the redirect URI, the ordered parameters and the
//! mode. The web layer turns it into a `303` (query) or an auto-submitting form (form_post).

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::oauth::authorize_request::redirect_with;

/// How the authorization response parameters are delivered to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// Parameters appended to the redirect URI's query (`303 See Other`).
    #[default]
    Query,
    /// Parameters POSTed to the redirect URI by an auto-submitting HTML form.
    FormPost,
}

/// The `response_modes_supported` values (published in discovery).
pub const SUPPORTED: &[&str] = &["query", "form_post"];

impl ResponseMode {
    /// Parses the `response_mode` parameter. Absent → [`ResponseMode::Query`]. Values are
    /// case-sensitive; anything else (including `fragment`) is `invalid_request`.
    pub fn parse(value: Option<&str>) -> Result<Self, CoreError> {
        match value {
            None | Some("query") => Ok(Self::Query),
            Some("form_post") => Ok(Self::FormPost),
            Some(_) => Err(CoreError::InvalidRequest(
                "unsupported response_mode".to_owned(),
            )),
        }
    }

    /// The protocol value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }
}

/// An authorization response to deliver to a trusted redirect URI.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationResponse {
    /// The validated (registered) redirect URI.
    pub redirect_uri: String,
    /// Response parameters in order: `code` or `error`/`error_description`, `state`, `iss`.
    pub params: Vec<(String, String)>,
    pub mode: ResponseMode,
}

impl std::fmt::Debug for AuthorizationResponse {
    /// The authorization code is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<(&str, &str)> = self
            .params
            .iter()
            .map(|(k, v)| {
                let v = if k == "code" {
                    "[redacted]"
                } else {
                    v.as_str()
                };
                (k.as_str(), v)
            })
            .collect();
        f.debug_struct("AuthorizationResponse")
            .field("redirect_uri", &self.redirect_uri)
            .field("params", &params)
            .field("mode", &self.mode)
            .finish()
    }
}

fn push_state_and_iss(params: &mut Vec<(String, String)>, state: Option<&str>, issuer: &str) {
    if let Some(s) = state {
        params.push(("state".to_owned(), s.to_owned()));
    }
    // RFC 9207: always identify the issuer.
    params.push(("iss".to_owned(), issuer.to_owned()));
}

impl AuthorizationResponse {
    /// A success response: `code`, `state` (if any) and `iss`.
    pub fn success(
        redirect_uri: &str,
        code: &str,
        state: Option<&str>,
        issuer: &str,
        mode: ResponseMode,
    ) -> Self {
        let mut params = vec![("code".to_owned(), code.to_owned())];
        push_state_and_iss(&mut params, state, issuer);
        Self {
            redirect_uri: redirect_uri.to_owned(),
            params,
            mode,
        }
    }

    /// An error response: `error`, `error_description` (client-safe), `state` (if any) and `iss`.
    pub fn error(
        redirect_uri: &str,
        error: &CoreError,
        state: Option<&str>,
        issuer: &str,
        mode: ResponseMode,
    ) -> Self {
        let mut params = vec![
            ("error".to_owned(), error.oauth_error().to_owned()),
            ("error_description".to_owned(), error.description()),
        ];
        push_state_and_iss(&mut params, state, issuer);
        Self {
            redirect_uri: redirect_uri.to_owned(),
            params,
            mode,
        }
    }

    /// The redirect URI with the parameters appended to its query (the `query` delivery).
    pub fn to_redirect_url(&self) -> String {
        let pairs: Vec<(&str, &str)> = self
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        redirect_with(&self.redirect_uri, &pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AuthorizationParams;

    const RP: &str = "https://rp.example.test/cb";
    const ISSUER: &str = "https://id.example.test/t/acme";

    fn query(url: &str) -> Vec<(String, String)> {
        let q = url.split_once('?').map_or("", |(_, q)| q);
        url::form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn count(q: &[(String, String)], name: &str) -> usize {
        q.iter().filter(|(k, _)| k == name).count()
    }

    fn value<'a>(q: &'a [(String, String)], name: &str) -> &'a str {
        &q.iter().find(|(k, _)| k == name).unwrap().1
    }

    #[test]
    fn parse_accepts_only_query_and_form_post() {
        assert_eq!(ResponseMode::parse(None).unwrap(), ResponseMode::Query);
        assert_eq!(
            ResponseMode::parse(Some("query")).unwrap(),
            ResponseMode::Query
        );
        assert_eq!(
            ResponseMode::parse(Some("form_post")).unwrap(),
            ResponseMode::FormPost
        );
        for bad in [
            "fragment",
            "FORM_POST",
            "Query",
            "x",
            "form_post ",
            "query.jwt",
        ] {
            let err = ResponseMode::parse(Some(bad)).unwrap_err();
            assert_eq!(err.oauth_error(), "invalid_request", "{bad}");
        }
        assert_eq!(SUPPORTED, &["query", "form_post"]);
        assert_eq!(ResponseMode::FormPost.as_str(), "form_post");
        assert_eq!(ResponseMode::Query.as_str(), "query");
    }

    #[test]
    fn success_params_are_code_state_iss_in_order() {
        let r = AuthorizationResponse::success(
            RP,
            "the-code",
            Some("st"),
            ISSUER,
            ResponseMode::FormPost,
        );
        let keys: Vec<&str> = r.params.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["code", "state", "iss"]);
        assert_eq!(r.redirect_uri, RP);
        assert_eq!(r.mode, ResponseMode::FormPost);
        let r = AuthorizationResponse::success(RP, "c", None, ISSUER, ResponseMode::Query);
        let keys: Vec<&str> = r.params.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["code", "iss"]);
    }

    #[test]
    fn error_params_are_error_description_state_iss_in_order() {
        let r = AuthorizationResponse::error(
            RP,
            &CoreError::LoginRequired,
            Some("st"),
            ISSUER,
            ResponseMode::FormPost,
        );
        let keys: Vec<&str> = r.params.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["error", "error_description", "state", "iss"]);
        assert_eq!(r.params[0].1, "login_required");
        assert!(!r.params[1].1.is_empty());
    }

    #[test]
    fn query_url_matches_the_0_1_redirects() {
        // Regression: the 0.1 success_redirect / error_redirect output.
        let r =
            AuthorizationResponse::success(RP, "abc", Some("a b&c"), ISSUER, ResponseMode::Query);
        assert_eq!(
            r.to_redirect_url(),
            "https://rp.example.test/cb?code=abc&state=a+b%26c&iss=https%3A%2F%2Fid.example.test%2Ft%2Facme"
        );
        let r = AuthorizationResponse::error(
            "https://rp.example.test/cb?keep=1",
            &CoreError::UnsupportedResponseType,
            None,
            ISSUER,
            ResponseMode::Query,
        );
        let expected = redirect_with(
            "https://rp.example.test/cb?keep=1",
            &[
                ("error", "unsupported_response_type"),
                (
                    "error_description",
                    CoreError::UnsupportedResponseType.description().as_str(),
                ),
                ("iss", ISSUER),
            ],
        );
        assert_eq!(r.to_redirect_url(), expected);
        let q = query(&expected);
        assert_eq!(value(&q, "keep"), "1");
        assert_eq!(count(&q, "state"), 0);
        assert_eq!(count(&q, "iss"), 1);
    }

    #[test]
    fn long_state_and_iss_appear_once() {
        let state = "a b&c=d/é".repeat(200);
        let r = AuthorizationResponse::error(
            RP,
            &CoreError::LoginRequired,
            Some(&state),
            ISSUER,
            ResponseMode::Query,
        );
        let q = query(&r.to_redirect_url());
        assert_eq!(count(&q, "iss"), 1);
        assert_eq!(value(&q, "iss"), ISSUER);
        assert_eq!(value(&q, "state"), state);
        assert_eq!(value(&q, "error"), "login_required");
    }

    #[test]
    fn errors_never_leak_internal_details() {
        let r = AuthorizationResponse::error(
            RP,
            &CoreError::Internal("db password hunter2".to_owned()),
            None,
            ISSUER,
            ResponseMode::FormPost,
        );
        assert!(!r.to_redirect_url().contains("hunter2"));
        assert!(r.params.iter().all(|(_, v)| !v.contains("hunter2")));
        assert_eq!(r.params[0].1, "server_error");
    }

    #[test]
    fn debug_redacts_the_code() {
        let r = AuthorizationResponse::success(
            RP,
            "secret-code-value",
            None,
            ISSUER,
            ResponseMode::Query,
        );
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("secret-code-value"), "{dbg}");
        assert!(dbg.contains("[redacted]"));
    }

    #[test]
    fn stored_0_1_request_without_response_mode_decodes_as_query() {
        let json = r#"{"redirect_uri":"https://rp.example.test/cb","scope":"openid",
            "state":"st","nonce":null,"code_challenge":null,"prompt":[],"max_age":null,
            "login_hint":null,"acr_values":[],"ui_locales":null,"claims":null}"#;
        let p: AuthorizationParams = serde_json::from_str(json).unwrap();
        assert_eq!(p.response_mode, ResponseMode::Query);

        let mut p = p;
        p.response_mode = ResponseMode::FormPost;
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains(r#""response_mode":"form_post""#), "{s}");
        let back: AuthorizationParams = serde_json::from_str(&s).unwrap();
        assert_eq!(back.response_mode, ResponseMode::FormPost);
    }
}
