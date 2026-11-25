//! Authorization-request parsing and validation (SEC-07).
//!
//! The input is a query string / form body. It goes through `parse_raw` and then `validate`
//! against no client, a fixed confidential web client and a fixed public native client.
//! Security invariants checked on every input:
//! - with no client, the result is always an error page (never a redirect, never success);
//! - a redirect (error or success) only ever targets a URI that `redirect_matches` the client's
//!   registered list;
//! - a successful request belongs to the client it was validated against, and a public client
//!   always carries a PKCE challenge, even with `require_pkce = false`.
#![no_main]

use std::sync::OnceLock;

use anvil_core::model::{
    ApplicationType, Client, ClientAuthMethod, ClientId, ClientType, ConsentMode, GrantType,
    TenantId, TokenFormat,
};
use anvil_core::oauth::authorize_request::{AuthorizeError, parse_raw, validate};
use anvil_core::oauth::redirect::redirect_matches;
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

struct Fixture {
    confidential: Client,
    public: Client,
}

fn client(
    client_id: &str,
    client_type: ClientType,
    application_type: ApplicationType,
    auth_method: ClientAuthMethod,
    redirect_uris: &[&str],
    require_pkce: bool,
) -> Client {
    let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed time");
    Client {
        id: ClientId::new_v7(),
        tenant_id: TenantId::new_v7(),
        client_id: client_id.to_owned(),
        name: client_id.to_owned(),
        client_type,
        application_type,
        auth_method,
        secret_hash: None,
        jwks: None,
        redirect_uris: redirect_uris.iter().map(|s| (*s).to_owned()).collect(),
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        require_pkce,
        token_format: TokenFormat::Jwt,
        consent_mode: ConsentMode::Required,
        id_token_signed_response_alg: None,
        can_introspect: false,
        created_at: at,
        updated_at: at,
    }
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| Fixture {
        confidential: client(
            "rp",
            ClientType::Confidential,
            ApplicationType::Web,
            ClientAuthMethod::ClientSecretBasic,
            &["https://rp.example.test/cb", "https://rp.example.test/other"],
            true,
        ),
        public: client(
            "app",
            ClientType::Public,
            ApplicationType::Native,
            ClientAuthMethod::None,
            &["http://127.0.0.1/cb"],
            false,
        ),
    })
}

fn check(c: &Client, data: &[u8]) {
    let raw = parse_raw(data);
    match validate(&raw, Some(c)) {
        Ok(v) => {
            assert_eq!(v.client.client_id, c.client_id);
            assert!(
                redirect_matches(&c.redirect_uris, &v.params.redirect_uri, c.application_type),
                "accepted unregistered redirect_uri {:?}",
                v.params.redirect_uri
            );
            if c.client_type == ClientType::Public || c.require_pkce {
                assert!(v.params.code_challenge.is_some(), "PKCE not enforced");
            }
        }
        Err(AuthorizeError::Redirect { redirect_uri, .. }) => {
            assert!(
                redirect_matches(&c.redirect_uris, &redirect_uri, c.application_type),
                "error redirected to unregistered URI {redirect_uri:?}"
            );
        }
        Err(AuthorizeError::ErrorPage { .. }) => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let raw = parse_raw(data);
    assert!(matches!(
        validate(&raw, None),
        Err(AuthorizeError::ErrorPage { .. })
    ));
    check(&f.confidential, data);
    check(&f.public, data);
});
