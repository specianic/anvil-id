//! Management API 0.2 behaviour on the selected backend (`ANVILID_TEST_DB`): client options,
//! tenant signing algorithms and CAPTCHA (merge semantics, write-only secret, refusing to disable
//! an algorithm in use), sessions, credentials, the audit-log query, and email templates / SMTP
//! settings end to end (HTTP, service, storage and audit).
//!
//! The admin route-class limit is raised so that one test can make many calls from the single
//! test peer (rate limiting itself is tested in `security_ratelimit.rs`).

mod admin_support;
mod support;
mod ui_helpers;

use std::collections::BTreeSet;
use std::sync::Arc;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuditAction, AuditOutcome, AuditQuery, CredentialId, NewTotp, RequestContext, SessionId,
    TOTP_SEED_PURPOSE, Tenant, UserId, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_core::service::session::SessionService;
use anvil_jose::otp::TotpSecret;
use anvil_web::cookies::CookiePolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use support::{TestApp, TestClock, TestResponse, json as body_json};
use ui_helpers::{default_tenant, login, register};

const FULL: &str = "admin:read admin:write";

async fn app() -> TestApp {
    TestApp::with(|c| {
        c.rate_limits.admin = RateQuota::per_second(100_000, 100_000);
        c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
    })
    .await
}

/// An app and a full admin token; also returns the token's subject (the admin client id).
async fn app_and_token() -> (TestApp, String, String) {
    let app = app().await;
    let client_id = system_client(&app, &["admin:read", "admin:write"]).await;
    let system = app.system.as_ref().expect("installed");
    let token = mint_access_token(&app, system, &system_issuer(&app), &client_id, FULL).await;
    (app, token, client_id)
}

async fn get(app: &TestApp, t: &str, path: &str) -> TestResponse {
    call(app, Method::GET, &format!("{API}{path}"), Some(t), None).await
}

async fn post(app: &TestApp, t: &str, path: &str, body: Value) -> TestResponse {
    call(
        app,
        Method::POST,
        &format!("{API}{path}"),
        Some(t),
        Some(body),
    )
    .await
}

async fn patch(app: &TestApp, t: &str, path: &str, body: Value) -> TestResponse {
    call(
        app,
        Method::PATCH,
        &format!("{API}{path}"),
        Some(t),
        Some(body),
    )
    .await
}

async fn put(app: &TestApp, t: &str, path: &str, body: Value) -> TestResponse {
    call(
        app,
        Method::PUT,
        &format!("{API}{path}"),
        Some(t),
        Some(body),
    )
    .await
}

async fn delete(app: &TestApp, t: &str, path: &str) -> TestResponse {
    call(app, Method::DELETE, &format!("{API}{path}"), Some(t), None).await
}

fn ok(resp: &TestResponse, status: u16) -> Value {
    assert_eq!(resp.status.as_u16(), status, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    if resp.body.is_empty() {
        Value::Null
    } else {
        body_json(resp)
    }
}

fn web_client(name: &str) -> Value {
    json!({
        "name": name,
        "client_type": "confidential",
        "redirect_uris": ["https://app.example.com/cb"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
    })
}

fn with(mut base: Value, extra: Value) -> Value {
    for (k, v) in extra.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

async fn audit(app: &TestApp, tenant: &Tenant) -> Vec<anvil_core::model::AuditEvent> {
    app.storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

// ---------------------------------------------------------------------------------------------
// Clients and tenant settings
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn client_options_round_trip_and_the_id_token_alg_is_gated_by_the_tenant() {
    let (app, t, _) = app_and_token().await;

    // Defaults are the secure ones.
    let created = ok(
        &post(&app, &t, "/tenants/default/clients", web_client("Plain")).await,
        201,
    );
    assert_eq!(created["token_format"], "jwt");
    assert_eq!(created["consent_mode"], "required");
    assert_eq!(created["id_token_signed_response_alg"], "RS256");
    assert_eq!(created["can_introspect"], false);

    // Opaque, first-party, introspecting client.
    let body = with(
        web_client("Opaque"),
        json!({"token_format": "opaque", "consent_mode": "skip_first_party", "can_introspect": true}),
    );
    let created = ok(&post(&app, &t, "/tenants/default/clients", body).await, 201);
    let id = created["client_id"].as_str().unwrap().to_owned();
    let got = ok(
        &get(&app, &t, &format!("/tenants/default/clients/{id}")).await,
        200,
    );
    assert_eq!(got["token_format"], "opaque");
    assert_eq!(got["consent_mode"], "skip_first_party");
    assert_eq!(got["can_introspect"], true);
    let stored = app
        .storage()
        .clients()
        .get(default_tenant(&app).id, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.token_format, anvil_core::model::TokenFormat::Opaque);
    assert_eq!(
        stored.consent_mode,
        anvil_core::model::ConsentMode::SkipFirstParty
    );

    // Unknown enum values and introspection on a public client are refused.
    let bad = with(web_client("Bad"), json!({"token_format": "paseto"}));
    assert_field_error(
        &post(&app, &t, "/tenants/default/clients", bad).await,
        "body",
    );
    let public = json!({
        "name": "SPA", "client_type": "public",
        "redirect_uris": ["https://spa.example.com/cb"], "can_introspect": true,
    });
    assert_field_error(
        &post(&app, &t, "/tenants/default/clients", public).await,
        "can_introspect",
    );

    // ES256 is not enabled yet.
    let es = with(
        web_client("ES"),
        json!({"id_token_signed_response_alg": "ES256"}),
    );
    assert_field_error(
        &post(&app, &t, "/tenants/default/clients", es.clone()).await,
        "id_token_signed_response_alg",
    );

    let tenant = ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"signing_algs": ["ES256"]}}),
        )
        .await,
        200,
    );
    assert_eq!(
        tenant["settings"]["signing_algs"],
        json!(["RS256", "ES256"])
    );
    let created = ok(&post(&app, &t, "/tenants/default/clients", es).await, 201);
    assert_eq!(created["id_token_signed_response_alg"], "ES256");
    let es_id = created["client_id"].as_str().unwrap().to_owned();

    // PATCH: options change; `null` resets the algorithm to RS256.
    let updated = ok(
        &patch(
            &app,
            &t,
            &format!("/tenants/default/clients/{es_id}"),
            json!({"consent_mode": "skip_first_party", "token_format": "opaque", "id_token_signed_response_alg": null}),
        )
        .await,
        200,
    );
    assert_eq!(updated["consent_mode"], "skip_first_party");
    assert_eq!(updated["token_format"], "opaque");
    assert_eq!(updated["id_token_signed_response_alg"], "RS256");
    assert_field_error(
        &patch(
            &app,
            &t,
            &format!("/tenants/default/clients/{es_id}"),
            json!({"id_token_signed_response_alg": "HS256"}),
        )
        .await,
        "id_token_signed_response_alg",
    );
}

#[tokio::test]
async fn tenant_settings_updates_merge_with_the_current_settings() {
    let (app, t, _) = app_and_token().await;
    let secret = "captcha-secret-merge-0123";
    ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {
                "signing_algs": ["ES256", "Ed25519"],
                "captcha": {"provider": "turnstile", "site_key": "site-1", "secret": secret},
            }}),
        )
        .await,
        200,
    );
    let sealed_before = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap()
        .settings
        .captcha
        .expect("captcha stored")
        .secret_sealed;

    // Changing one setting keeps every other one.
    let resp = ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"registration": "invite_only"}}),
        )
        .await,
        200,
    );
    let s = &resp["settings"];
    assert_eq!(s["registration"], "invite_only");
    assert_eq!(s["require_verified_email"], false);
    assert_eq!(s["signing_algs"], json!(["RS256", "ES256", "Ed25519"]));
    assert_eq!(s["captcha"]["configured"], true);

    let resp = ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"require_verified_email": true}}),
        )
        .await,
        200,
    );
    assert_eq!(resp["settings"]["registration"], "invite_only");
    assert_eq!(resp["settings"]["require_verified_email"], true);

    // A display-name-only update does not touch the settings.
    let resp = ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"display_name": "Default Org"}),
        )
        .await,
        200,
    );
    assert_eq!(
        resp["settings"]["signing_algs"],
        json!(["RS256", "ES256", "Ed25519"])
    );
    let stored = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.settings.signing_algs,
        vec!["RS256", "ES256", "Ed25519"]
    );
    assert_eq!(
        stored
            .settings
            .captcha
            .expect("still configured")
            .secret_sealed,
        sealed_before,
        "the sealed CAPTCHA secret is carried over unchanged"
    );

    // Unknown settings fields are refused.
    assert_field_error(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"captcha_secret": "x"}}),
        )
        .await,
        "body",
    );
}

#[tokio::test]
async fn captcha_secret_is_write_only() {
    let (app, t, _) = app_and_token().await;
    let secret = "0x4AAAAAAA-very-secret-value";
    let resp = patch(
        &app,
        &t,
        "/tenants/default",
        json!({"settings": {"captcha": {"provider": "hcaptcha", "site_key": "site-key-9", "secret": secret}}}),
    )
    .await;
    let body = ok(&resp, 200);
    assert_eq!(
        body["settings"]["captcha"],
        json!({"provider": "hcaptcha", "site_key": "site-key-9", "configured": true})
    );
    let sealed = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap()
        .settings
        .captcha
        .unwrap()
        .secret_sealed;
    for resp in [
        resp,
        get(&app, &t, "/tenants/default").await,
        get(&app, &t, "/tenants?limit=200").await,
        get(&app, &t, "/tenants/system/audit-events").await,
    ] {
        assert_eq!(resp.status, 200, "{}", resp.text());
        let text = resp.text();
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains(&sealed), "{text}");
        assert!(!text.contains("secret_sealed"), "{text}");
    }

    // `captcha: null` disables it.
    let body = ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"captcha": null}}),
        )
        .await,
        200,
    );
    assert_eq!(body["settings"]["captcha"], Value::Null);
    // Invalid values are field errors.
    assert_field_error(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"captcha": {"provider": "turnstile", "site_key": "has space", "secret": "x"}}}),
        )
        .await,
        "captcha.site_key",
    );
}

#[tokio::test]
async fn disabling_a_signing_algorithm_in_use_is_refused_with_the_client_ids() {
    let (app, t, _) = app_and_token().await;
    ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"signing_algs": ["ES256", "Ed25519"]}}),
        )
        .await,
        200,
    );
    let mut ids = Vec::new();
    for name in ["Uses ES256 a", "Uses ES256 b"] {
        let body = with(
            web_client(name),
            json!({"id_token_signed_response_alg": "ES256"}),
        );
        let c = ok(&post(&app, &t, "/tenants/default/clients", body).await, 201);
        ids.push(c["client_id"].as_str().unwrap().to_owned());
    }
    let audit_before = audit(&app, &ui_helpers::system_tenant(&app)).await.len();

    // Dropping ES256 (keeping Ed25519) is refused and names both clients.
    let resp = patch(
        &app,
        &t,
        "/tenants/default",
        json!({"settings": {"signing_algs": ["Ed25519"]}}),
    )
    .await;
    let problem = assert_problem(&resp, 409);
    let detail = problem["detail"].as_str().unwrap();
    assert!(detail.contains("ES256"), "{detail}");
    for id in &ids {
        assert!(detail.contains(id.as_str()), "{detail}");
    }
    let stored = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.settings.signing_algs,
        vec!["RS256", "ES256", "Ed25519"]
    );
    assert_eq!(
        audit(&app, &ui_helpers::system_tenant(&app)).await.len(),
        audit_before,
        "a refused update records nothing"
    );

    // Dropping Ed25519 (unused) alone is fine.
    ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"signing_algs": ["ES256"]}}),
        )
        .await,
        200,
    );

    // After one client moves to RS256 only the other is named.
    ok(
        &patch(
            &app,
            &t,
            &format!("/tenants/default/clients/{}", ids[0]),
            json!({"id_token_signed_response_alg": "RS256"}),
        )
        .await,
        200,
    );
    let resp = patch(
        &app,
        &t,
        "/tenants/default",
        json!({"settings": {"signing_algs": []}}),
    )
    .await;
    let detail = assert_problem(&resp, 409)["detail"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(detail.contains(ids[1].as_str()) && !detail.contains(ids[0].as_str()));

    ok(
        &patch(
            &app,
            &t,
            &format!("/tenants/default/clients/{}", ids[1]),
            json!({"id_token_signed_response_alg": null}),
        )
        .await,
        200,
    );
    let body = ok(
        &patch(
            &app,
            &t,
            "/tenants/default",
            json!({"settings": {"signing_algs": []}}),
        )
        .await,
        200,
    );
    assert_eq!(body["settings"]["signing_algs"], json!(["RS256"]));
}

// ---------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------

async fn new_user(app: &TestApp, t: &str, email: &str) -> String {
    let body = ok(
        &post(
            app,
            t,
            "/tenants/default/users",
            json!({"email": email, "password": "correct horse battery"}),
        )
        .await,
        201,
    );
    body["id"].as_str().unwrap().to_owned()
}

/// Signs `user` in through the production `SessionService::create`; returns the session id and
/// the `Cookie` header of that browser.
async fn sign_in(app: &TestApp, user: &str, ua: &str) -> (SessionId, String) {
    let tenant = default_tenant(app);
    let service = SessionService {
        storage: app.storage_arc(),
        clock: Arc::new(TestClock::new(app.clock().now())),
    };
    let ctx = RequestContext::new(Some("203.0.113.7".parse().unwrap()), Some(ua), None);
    let created = service
        .create(
            tenant.id,
            UserId(user.parse().unwrap()),
            "",
            &["pwd".into()],
            None,
            &ctx,
        )
        .await
        .expect("session");
    let name = CookiePolicy::new(app.config.is_https()).session_name(&tenant);
    (
        created.session.id,
        format!("{name}={}", created.token.expose_secret()),
    )
}

/// Whether the browser with `cookie` is signed in (the account sessions page answers 200; a
/// signed-out browser is sent to the sign-in page).
async fn signed_in(app: &TestApp, cookie: &str) -> bool {
    let req = Request::get("/ui/account/sessions")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.send(req).await;
    match resp.status.as_u16() {
        200 => true,
        303 => false,
        other => panic!("unexpected {other}: {}", resp.text()),
    }
}

#[tokio::test]
async fn admins_list_and_revoke_sessions() {
    let (app, t, admin) = app_and_token().await;
    let alice = new_user(&app, &t, "alice@example.com").await;
    let bob = new_user(&app, &t, "bob@example.com").await;
    let (a1, a1_cookie) = sign_in(&app, &alice, "Firefox").await;
    let (a2, a2_cookie) = sign_in(&app, &alice, "Safari").await;
    let (_b1, b1_cookie) = sign_in(&app, &bob, "Chrome").await;
    assert!(signed_in(&app, &a1_cookie).await);

    // A user's sessions, with the documented fields and no token.
    let list = ok(
        &get(
            &app,
            &t,
            &format!("/tenants/default/users/{alice}/sessions"),
        )
        .await,
        200,
    );
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let keys: BTreeSet<&str> = items[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "id",
            "user_id",
            "created_at",
            "last_seen_at",
            "auth_time",
            "expires_at",
            "idle_expires_at",
            "ip",
            "user_agent",
            "acr",
            "amr",
        ])
    );
    assert_eq!(items[0]["ip"], "203.0.113.7");
    assert_eq!(items[0]["amr"], json!(["pwd"]));
    assert!(list["next_cursor"].is_null());

    // The tenant list pages through all three without overlap.
    let mut seen = BTreeSet::new();
    let mut after: Option<String> = None;
    loop {
        let path = match &after {
            Some(a) => format!("/tenants/default/sessions?limit=2&after={a}"),
            None => "/tenants/default/sessions?limit=2".to_owned(),
        };
        let page = ok(&get(&app, &t, &path).await, 200);
        for s in page["items"].as_array().unwrap() {
            assert!(seen.insert(s["id"].as_str().unwrap().to_owned()));
        }
        match page["next_cursor"].as_str() {
            Some(c) => after = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 3);
    assert_field_error(
        &get(&app, &t, "/tenants/default/sessions?limit=0").await,
        "limit",
    );

    // Revoke one: that browser is signed out, the other is not.
    ok(
        &delete(&app, &t, &format!("/tenants/default/sessions/{}", a1.0)).await,
        204,
    );
    assert!(!signed_in(&app, &a1_cookie).await);
    assert!(signed_in(&app, &a2_cookie).await);
    assert_problem(
        &delete(&app, &t, &format!("/tenants/default/sessions/{}", a1.0)).await,
        404,
    );
    assert_problem(
        &delete(&app, &t, "/tenants/default/sessions/not-a-uuid").await,
        404,
    );

    // Revoke all of alice's: her remaining browser is signed out, bob's is not.
    let body = ok(
        &delete(
            &app,
            &t,
            &format!("/tenants/default/users/{alice}/sessions"),
        )
        .await,
        200,
    );
    assert_eq!(body["revoked"], 1);
    assert!(!signed_in(&app, &a2_cookie).await);
    assert!(signed_in(&app, &b1_cookie).await);
    let list = ok(
        &get(
            &app,
            &t,
            &format!("/tenants/default/users/{alice}/sessions"),
        )
        .await,
        200,
    );
    assert!(list["items"].as_array().unwrap().is_empty());
    let _ = a2;

    // Unknown users are 404.
    let unknown = UserId::new_v7();
    assert_problem(
        &get(
            &app,
            &t,
            &format!("/tenants/default/users/{unknown}/sessions"),
        )
        .await,
        404,
    );
    assert_problem(
        &delete(
            &app,
            &t,
            &format!("/tenants/default/users/{unknown}/sessions"),
        )
        .await,
        404,
    );

    // Audited with the admin actor.
    let events = audit(&app, &default_tenant(&app)).await;
    let revoked: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.action,
                AuditAction::SessionRevoked | AuditAction::SessionsRevokedAll
            )
        })
        .collect();
    assert_eq!(revoked.len(), 2);
    for e in revoked {
        assert_eq!(e.actor.kind, anvil_core::model::ActorKind::Admin);
        assert_eq!(e.actor.id.as_deref(), Some(admin.as_str()));
    }
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

const EMAIL: &str = "carol@example.com";
const PASSWORD: &str = "correct horse battery";

async fn enrol_totp(app: &TestApp, user: UserId) -> CredentialId {
    let id = CredentialId::new_v7();
    let seed = TotpSecret::generate();
    let secret_enc = app
        .kek()
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal");
    let (_codes, hashes) = new_recovery_codes(app.kek()).expect("codes");
    let now = app.clock().now();
    app.storage()
        .users()
        .create_totp(
            default_tenant(app).id,
            user,
            &NewTotp {
                id,
                secret_enc,
                created_at: now,
            },
            &hashes,
            now,
        )
        .await
        .expect("totp");
    id
}

async fn asks_for_second_factor(app: &TestApp) -> bool {
    app.clear_cookies();
    let resp = login(app, "", EMAIL, PASSWORD).await;
    assert!(
        resp.status == 200 || resp.status == 303,
        "{} {}",
        resp.status,
        resp.text()
    );
    let second = resp.html().contains("id=\"second-factor\"");
    app.clear_cookies();
    second
}

#[tokio::test]
async fn admins_list_and_remove_credentials() {
    let (app, t, _) = app_and_token().await;
    register(&app, "", EMAIL, PASSWORD).await;
    let user = app
        .storage()
        .users()
        .get_by_email(default_tenant(&app).id, EMAIL)
        .await
        .unwrap()
        .unwrap()
        .id;
    let totp = enrol_totp(&app, user).await;
    assert!(asks_for_second_factor(&app).await);

    let resp = get(
        &app,
        &t,
        &format!("/tenants/default/users/{user}/credentials"),
    )
    .await;
    let list = ok(&resp, 200);
    let items = list["items"].as_array().unwrap();
    let kinds: BTreeSet<&str> = items.iter().map(|c| c["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, BTreeSet::from(["password", "totp"]));
    for c in items {
        let keys: BTreeSet<&str> = c.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            BTreeSet::from(["id", "kind", "label", "created_at", "last_used_at"])
        );
    }
    let text = resp.text();
    for needle in ["secret", "argon2", "hash", "seed"] {
        assert!(!text.to_lowercase().contains(needle), "{needle}: {text}");
    }

    // The password cannot be removed here; unknown or malformed ids are 404.
    let password_id = items.iter().find(|c| c["kind"] == "password").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for id in [password_id, CredentialId::new_v7().to_string(), "x".into()] {
        assert_problem(
            &delete(
                &app,
                &t,
                &format!("/tenants/default/users/{user}/credentials/{id}"),
            )
            .await,
            404,
        );
    }

    // Removing the TOTP: sign-in no longer asks for a second factor.
    ok(
        &delete(
            &app,
            &t,
            &format!("/tenants/default/users/{user}/credentials/{}", totp.0),
        )
        .await,
        204,
    );
    assert!(!asks_for_second_factor(&app).await);
    let list = ok(
        &get(
            &app,
            &t,
            &format!("/tenants/default/users/{user}/credentials"),
        )
        .await,
        200,
    );
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    let removed = audit(&app, &default_tenant(&app))
        .await
        .into_iter()
        .filter(|e| e.action == AuditAction::TotpRemoved)
        .count();
    assert_eq!(removed, 1);
}

// ---------------------------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn audit_events_are_queryable_with_filters_and_cursor_paging() {
    let (app, t, admin) = app_and_token().await;
    let mut created = Vec::new();
    for i in 0..5 {
        app.clock().advance(std::time::Duration::from_secs(1));
        let c = ok(
            &post(
                &app,
                &t,
                "/tenants/default/clients",
                web_client(&format!("App {i}")),
            )
            .await,
            201,
        );
        created.push(c["client_id"].as_str().unwrap().to_owned());
    }
    app.clock().advance(std::time::Duration::from_secs(1));
    let midpoint = app.clock().now();
    ok(
        &delete(
            &app,
            &t,
            &format!("/tenants/default/clients/{}", created[0]),
        )
        .await,
        204,
    );
    // Another tenant's events are not visible.
    ok(
        &post(
            &app,
            &t,
            "/tenants",
            json!({"slug": "acme", "display_name": "Acme"}),
        )
        .await,
        201,
    );
    let acme_client = ok(
        &post(&app, &t, "/tenants/acme/clients", web_client("Acme app")).await,
        201,
    )["client_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // By action, newest first.
    let page = ok(
        &get(
            &app,
            &t,
            "/tenants/default/audit-events?action=client_created",
        )
        .await,
        200,
    );
    let items = page["items"].as_array().unwrap();
    let targets: Vec<&str> = items
        .iter()
        .map(|e| e["target"].as_str().unwrap())
        .collect();
    let mut expected: Vec<&str> = created.iter().map(String::as_str).collect();
    expected.reverse();
    assert_eq!(targets, expected);
    assert!(!targets.contains(&acme_client.as_str()));
    let e = &items[0];
    assert_eq!(e["actor"], json!({"kind": "admin", "id": admin}));
    assert_eq!(e["outcome"], "success");
    assert_eq!(e["action"], "client_created");
    assert!(e["at"].as_str().unwrap().ends_with('Z'));
    for key in ["id", "ip", "user_agent", "trace_id", "details"] {
        assert!(e.get(key).is_some(), "{key}");
    }

    // Actor, outcome and target filters.
    let page = ok(
        &get(
            &app,
            &t,
            &format!("/tenants/default/audit-events?actor={admin}&outcome=success"),
        )
        .await,
        200,
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 6);
    let page = ok(
        &get(
            &app,
            &t,
            &format!("/tenants/default/audit-events?target={}", created[0]),
        )
        .await,
        200,
    );
    let actions: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, vec!["client_deleted", "client_created"]);
    let page = ok(
        &get(&app, &t, "/tenants/default/audit-events?outcome=failure").await,
        200,
    );
    assert!(page["items"].as_array().unwrap().is_empty());

    // Time window: from is inclusive, to exclusive.
    let mid = midpoint
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let page = ok(
        &get(
            &app,
            &t,
            &format!("/tenants/default/audit-events?from={}", urlencode(&mid)),
        )
        .await,
        200,
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let page = ok(
        &get(
            &app,
            &t,
            &format!("/tenants/default/audit-events?to={}", urlencode(&mid)),
        )
        .await,
        200,
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 5);

    // Cursor paging: complete, newest first, non-overlapping.
    let mut ids: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(c) => format!("/tenants/default/audit-events?limit=2&cursor={c}"),
            None => "/tenants/default/audit-events?limit=2".to_owned(),
        };
        let page = ok(&get(&app, &t, &path).await, 200);
        pages += 1;
        for e in page["items"].as_array().unwrap() {
            ids.push(e["id"].as_str().unwrap().to_owned());
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(ids.len(), 6);
    assert_eq!(pages, 3);
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.reverse();
    assert_eq!(ids, sorted, "UUIDv7 ids, newest first");

    // The other tenant's log has its own client event.
    let page = ok(
        &get(&app, &t, "/tenants/acme/audit-events?action=client_created").await,
        200,
    );
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{page}");
    assert_eq!(items[0]["target"], acme_client.as_str());

    // Invalid filters name their field; unknown tenants are 404.
    for (query, field) in [
        ("action=drop", "action"),
        ("outcome=maybe", "outcome"),
        ("from=yesterday", "from"),
        ("limit=500", "limit"),
        ("cursor=nope", "query"),
        ("color=red", "query"),
    ] {
        assert_field_error(
            &get(&app, &t, &format!("/tenants/default/audit-events?{query}")).await,
            field,
        );
    }
    assert_problem(&get(&app, &t, "/tenants/nope/audit-events").await, 404);
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ---------------------------------------------------------------------------------------------
// Email templates and SMTP (full path: HTTP, MailSettingsService, storage, audit)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn email_templates_default_override_validation_and_reset() {
    let (app, t, admin) = app_and_token().await;
    let list = ok(
        &get(&app, &t, "/tenants/default/email-templates").await,
        200,
    );
    let items = list["items"].as_array().unwrap();
    let kinds: Vec<&str> = items.iter().map(|i| i["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        vec![
            "verification",
            "recovery",
            "invitation",
            "password_changed",
            "recovery_code_used",
            "login_code",
            "email_change",
            "email_changed"
        ]
    );
    assert!(items.iter().all(|i| i["customized"] == false));

    let default = ok(
        &get(&app, &t, "/tenants/default/email-templates/verification").await,
        200,
    );
    assert_eq!(default["customized"], false);
    assert!(default["updated_at"].is_null());
    assert!(
        default["subject"]
            .as_str()
            .unwrap()
            .contains("{{ tenant_name }}")
    );
    assert!(
        default["body_html"]
            .as_str()
            .unwrap()
            .contains("{{ link }}")
    );
    assert!(!default["body_text"].as_str().unwrap().is_empty());
    assert_eq!(
        default["variables"],
        json!(["tenant_name", "email", "link", "expires_in"])
    );

    // The default, saved as an override, is valid as is.
    let echo = json!({
        "subject": default["subject"], "body_html": default["body_html"], "body_text": default["body_text"],
    });
    ok(
        &put(
            &app,
            &t,
            "/tenants/default/email-templates/verification",
            echo,
        )
        .await,
        200,
    );

    // login_code: `code` and `link` are optional (email_otp / magic_link), so an override that
    // prints either unguarded is refused; the shipped default (guarded) saves as is.
    let resp = put(
        &app,
        &t,
        "/tenants/default/email-templates/login_code",
        json!({
            "subject": "Sign in to {{ tenant_name }}",
            "body_html": "<p>{% if link is defined %}{{ link }}{% endif %}</p>",
            "body_text": "Your code:\n{{ code }}\n",
        }),
    )
    .await;
    let problem = assert_problem(&resp, 422);
    assert_eq!(problem["errors"][0]["field"], "body_text", "{problem}");
    assert_eq!(problem["errors"][0]["line"], 2, "{problem}");
    let resp = put(
        &app,
        &t,
        "/tenants/default/email-templates/login_code",
        json!({
            "subject": "Sign in to {{ tenant_name }}",
            "body_html": "<a href=\"{{ link }}\">Sign in</a>",
            "body_text": "{% if code is defined %}{{ code }}{% endif %}",
        }),
    )
    .await;
    let problem = assert_problem(&resp, 422);
    assert_eq!(problem["errors"][0]["field"], "body_html", "{problem}");
    let login_default = ok(
        &get(&app, &t, "/tenants/default/email-templates/login_code").await,
        200,
    );
    assert_eq!(
        login_default["variables"],
        json!(["tenant_name", "code", "link", "expires_minutes"])
    );
    let echo = json!({
        "subject": login_default["subject"],
        "body_html": login_default["body_html"],
        "body_text": login_default["body_text"],
    });
    ok(
        &put(
            &app,
            &t,
            "/tenants/default/email-templates/login_code",
            echo,
        )
        .await,
        200,
    );
    ok(
        &delete(&app, &t, "/tenants/default/email-templates/login_code").await,
        204,
    );

    // Invalid: unknown variable on line 3 of the text body.
    let resp = put(
        &app,
        &t,
        "/tenants/default/email-templates/recovery",
        json!({
            "subject": "Reset for {{ tenant_name }}",
            "body_html": "<p>{{ link }}</p>",
            "body_text": "Hello\n\n{{ password }}\n",
        }),
    )
    .await;
    let problem = assert_problem(&resp, 422);
    assert_eq!(problem["errors"][0]["field"], "body_text", "{problem}");
    assert_eq!(problem["errors"][0]["line"], 3, "{problem}");
    // Syntax error in the HTML body.
    let resp = put(
        &app,
        &t,
        "/tenants/default/email-templates/recovery",
        json!({
            "subject": "Reset",
            "body_html": "<p>\n{% if link %}\n",
            "body_text": "{{ link }}",
        }),
    )
    .await;
    let problem = assert_problem(&resp, 422);
    assert_eq!(problem["errors"][0]["field"], "body_html", "{problem}");
    assert!(
        app.storage()
            .mail_settings()
            .template(
                default_tenant(&app).id,
                anvil_core::model::EmailKind::Recovery
            )
            .await
            .unwrap()
            .is_none(),
        "nothing stored for invalid templates"
    );

    // Valid override.
    let saved = ok(
        &put(
            &app,
            &t,
            "/tenants/default/email-templates/recovery",
            json!({
                "subject": "Reset your {{ tenant_name }} password",
                "body_html": "<p><a href=\"{{ link }}\">Reset</a> ({{ expires_in }})</p>",
                "body_text": "Reset: {{ link }}",
            }),
        )
        .await,
        200,
    );
    assert_eq!(saved["customized"], true);
    let got = ok(
        &get(&app, &t, "/tenants/default/email-templates/recovery").await,
        200,
    );
    assert_eq!(got["customized"], true);
    assert_eq!(got["subject"], "Reset your {{ tenant_name }} password");
    assert!(got["updated_at"].is_string());

    // Reset: back to the default; idempotent.
    ok(
        &delete(&app, &t, "/tenants/default/email-templates/recovery").await,
        204,
    );
    let got = ok(
        &get(&app, &t, "/tenants/default/email-templates/recovery").await,
        200,
    );
    assert_eq!(got["customized"], false);
    ok(
        &delete(&app, &t, "/tenants/default/email-templates/recovery").await,
        204,
    );
    assert_problem(
        &get(&app, &t, "/tenants/default/email-templates/newsletter").await,
        404,
    );
    assert_field_error(
        &put(
            &app,
            &t,
            "/tenants/default/email-templates/recovery",
            json!({"subject": "x", "body_html": "x"}),
        )
        .await,
        "body",
    );

    // Audit: three updates, two resets (the second recovery DELETE had nothing to reset).
    let events = audit(&app, &default_tenant(&app)).await;
    let count = |a: AuditAction| events.iter().filter(|e| e.action == a).count();
    assert_eq!(count(AuditAction::EmailTemplateUpdated), 3);
    assert_eq!(count(AuditAction::EmailTemplateReset), 2);
    let mut resets: Vec<_> = events
        .iter()
        .filter(|e| e.action == AuditAction::EmailTemplateReset)
        .collect();
    resets.sort_by_key(|e| e.target.clone());
    let targets: Vec<_> = resets.iter().map(|e| e.target.as_deref()).collect();
    assert_eq!(targets, [Some("login_code"), Some("recovery")]);
    assert!(
        resets
            .iter()
            .all(|e| e.actor.id.as_deref() == Some(admin.as_str()))
    );
}

/// A local TCP port with nothing listening.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
async fn smtp_settings_password_is_write_only_and_test_send_reports_the_outcome() {
    let (app, t, _) = app_and_token().await;
    let password = "smtp-password-Xy9-unique";
    assert_problem(&get(&app, &t, "/tenants/default/smtp").await, 404);
    // Without settings there is nothing to test.
    assert_field_error(
        &post(
            &app,
            &t,
            "/tenants/default/smtp/test",
            json!({"to": "ops@example.com"}),
        )
        .await,
        "smtp",
    );

    let port = closed_port();
    let resp = put(
        &app,
        &t,
        "/tenants/default/smtp",
        json!({
            "host": "127.0.0.1", "port": port, "username": "mailer",
            "password": password, "from": "Example <noreply@example.com>", "tls": "none",
        }),
    )
    .await;
    let body = ok(&resp, 200);
    assert_eq!(body["password_set"], true);
    assert_eq!(body["port"], port);
    assert_eq!(body["tls"], "none");
    assert!(body.get("password").is_none());
    assert!(!resp.text().contains(password));
    let resp = get(&app, &t, "/tenants/default/smtp").await;
    let body = ok(&resp, 200);
    assert_eq!(body["username"], "mailer");
    assert!(!resp.text().contains(password));
    let stored = app
        .storage()
        .mail_settings()
        .smtp(default_tenant(&app).id)
        .await
        .unwrap()
        .expect("stored");
    let enc = stored.password_enc.expect("sealed password stored");
    assert!(
        !enc.windows(password.len())
            .any(|w| w == password.as_bytes()),
        "stored sealed, not in plaintext"
    );

    // An update without a password keeps the stored one.
    let body = ok(
        &put(
            &app,
            &t,
            "/tenants/default/smtp",
            json!({"host": "127.0.0.1", "port": port, "username": "mailer", "from": "noreply@example.com", "tls": "none"}),
        )
        .await,
        200,
    );
    assert_eq!(body["password_set"], true);

    // Test send against a closed port: the call succeeds and reports the failure.
    let resp = post(
        &app,
        &t,
        "/tenants/default/smtp/test",
        json!({"to": "ops@example.com"}),
    )
    .await;
    let body = ok(&resp, 200);
    assert_eq!(body["delivered"], false);
    assert!(!body["error"].as_str().unwrap().is_empty(), "{body}");
    assert!(!resp.text().contains(password));
    assert_field_error(
        &post(
            &app,
            &t,
            "/tenants/default/smtp/test",
            json!({"to": "not an address"}),
        )
        .await,
        "email",
    );

    // Invalid settings are field errors.
    assert_field_error(
        &put(
            &app,
            &t,
            "/tenants/default/smtp",
            json!({"host": "smtp://mail.example.com", "port": 25, "from": "noreply@example.com"}),
        )
        .await,
        "host",
    );

    // Audit: two updates and one failed test send; no secret or SMTP error text stored.
    let events = audit(&app, &default_tenant(&app)).await;
    let tests: Vec<_> = events
        .iter()
        .filter(|e| e.action == AuditAction::SmtpTestSent)
        .collect();
    assert_eq!(tests.len(), 1);
    assert_eq!(tests[0].outcome, AuditOutcome::Failure);
    assert_eq!(
        events
            .iter()
            .filter(|e| e.action == AuditAction::SmtpSettingsUpdated)
            .count(),
        2
    );
    let audit_text = get(&app, &t, "/tenants/default/audit-events").await.text();
    assert!(!audit_text.contains(password));
    assert!(!audit_text.contains("ops@example.com"));

    // Delete: back to the installation SMTP; idempotent.
    ok(&delete(&app, &t, "/tenants/default/smtp").await, 204);
    assert_problem(&get(&app, &t, "/tenants/default/smtp").await, 404);
    ok(&delete(&app, &t, "/tenants/default/smtp").await, 204);
}
