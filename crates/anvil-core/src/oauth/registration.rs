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
//! - `scope` ⊆ [`DcrSettings::allowed_scopes`], never an `admin:` scope; default: the allowed scopes;
//! - `allowed_resources` (RFC 8707) ⊆ [`DcrSettings::allowed_resources`]; default: all of them;
//! - in [`DcrMode::AllowListed`], when [`DcrSettings::allowed_redirect_hosts`] is not empty, every
//!   redirect and post-logout redirect URI host must be listed (a URI without host is refused);
//! - `backchannel_logout_uri` must be https; `consent_mode` is always `required` and PKCE is always
//!   required, whatever the request says;
//! - `client_name` and the informational `logo_uri`, `client_uri`, `policy_uri`, `tos_uri` are
//!   length-capped, and the URIs must be absolute https URIs.
//!
//! Callers resolve "empty `allowed_scopes` means the tenant defaults" before calling: here an empty
//! list allows no scope at all (fail closed).

use serde_json::{Map, Value};

use crate::error::CoreError;
use crate::model::{
    ApplicationType, ClientAuthMethod, ClientType, ConsentMode, DcrSettings, GrantType, Scope,
    TokenFormat,
};
use crate::oauth::redirect::{MAX_REDIRECT_URI_LEN, validate_redirect_uri};
use crate::oauth::resource::parse_resources;
use crate::service::admin_scope::is_admin_scope;
use crate::service::client::{
    ClientInput, ClientOptions, MAX_REDIRECT_URIS, validate_client, validate_client_phase4,
};

/// Name given to a registered client that sent no `client_name`.
pub const DEFAULT_CLIENT_NAME: &str = "Dynamically registered client";

/// Longest accepted `logo_uri`, `client_uri`, `policy_uri` and `tos_uri`.
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
    /// Client options. `consent_mode` is always [`ConsentMode::Required`].
    pub options: ClientOptions,
    /// The `client_name` as sent (trimmed); `None` when absent ([`DEFAULT_CLIENT_NAME`] is
    /// stored instead).
    pub client_name: Option<String>,
    /// Registered `response_types` (`["code"]` or empty).
    pub response_types: Vec<String>,
    /// Informational metadata, validated and echoed in the response; never fetched.
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
}

impl ValidatedRegistration {
    /// The registered client metadata for the RFC 7591 §3.2.1 response, with every substituted
    /// value (without `client_id`, secrets or registration-access fields, which the service adds).
    pub fn metadata(&self) -> Map<String, Value> {
        todo!("05-09 GREEN")
    }
}

/// Validates an RFC 7591 registration request. Pure: no I/O, no clock, no randomness.
pub fn validate(
    request: &Value,
    settings: &DcrSettings,
    mode: DcrMode,
) -> Result<ValidatedRegistration, CoreError> {
    let _ = (request, settings, mode);
    todo!("05-09 GREEN")
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
        for key in ["logo_uri", "client_uri", "policy_uri", "tos_uri"] {
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
}
