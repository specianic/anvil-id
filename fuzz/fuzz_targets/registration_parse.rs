//! RFC 7591 registration request validation (OIDC-17).
//!
//! Bytes -> JSON -> `oauth::registration::validate` under an open policy and an allow-listed one.
//!
//! Invariants (besides never panicking):
//! - an accepted registration never carries `jwks_uri`, an `admin:` scope, a scope or resource
//!   outside the allow-lists, or a consent mode other than `required`, and always requires PKCE;
//! - under the allow-listed mode every redirect URI host is on the host allow-list.
#![no_main]

use anvil_core::model::{ConsentMode, DcrSettings};
use anvil_core::oauth::registration::{DcrMode, validate};
use libfuzzer_sys::fuzz_target;

fn settings() -> DcrSettings {
    DcrSettings {
        allowed_redirect_hosts: vec!["app.example".to_owned(), "127.0.0.1".to_owned()],
        allowed_scopes: ["openid", "profile", "email", "offline_access"]
            .map(String::from)
            .to_vec(),
        allowed_resources: vec!["https://mcp.example/".to_owned()],
        allow_client_credentials: true,
        ..DcrSettings::default()
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(request) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let s = settings();
    for mode in [DcrMode::Open, DcrMode::AllowListed] {
        let Ok(v) = validate(&request, &s, mode) else {
            continue;
        };
        assert!(v.client.jwks_uri.is_none());
        assert_eq!(v.client.require_pkce, Some(true));
        assert_eq!(v.options.consent_mode, ConsentMode::Required);
        for scope in &v.client.scopes {
            assert!(
                !scope.starts_with("admin"),
                "admin scope {scope:?} registered"
            );
            assert!(s.allowed_scopes.contains(scope));
        }
        for resource in &v.options.allowed_resources {
            assert!(s.allowed_resources.contains(resource));
        }
        if mode == DcrMode::AllowListed {
            for uri in &v.client.redirect_uris {
                let host = url::Url::parse(uri)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
                assert!(
                    host.is_some_and(|h| s.allowed_redirect_hosts.contains(&h)),
                    "redirect {uri:?} outside the allow-list"
                );
            }
        }
    }
});
