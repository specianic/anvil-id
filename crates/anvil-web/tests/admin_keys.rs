//! Signing keys management API end to end (ADM-02): listing (newest first, lifecycle timestamps,
//! never private material), on-demand rotation through `KeyRotationService::rotate_now` (new kid
//! in the list and in `/jwks`, audited with the admin actor), and the negative paths: disabled
//! algorithm, scopes, the system tenant's stricter write rule and tenant isolation.

mod admin_support;
mod support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use anvil_core::model::{ActorKind, AuditAction, AuditEvent, AuditQuery, Tenant};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

fn keys_path(slug: &str) -> String {
    format!("{API}/tenants/{slug}/keys")
}

fn rotate_path(slug: &str) -> String {
    format!("{API}/tenants/{slug}/keys/rotate")
}

async fn list(app: &TestApp, token: &str, slug: &str) -> TestResponse {
    call(app, Method::GET, &keys_path(slug), Some(token), None).await
}

async fn rotate(app: &TestApp, token: &str, slug: &str, body: Value) -> TestResponse {
    call(
        app,
        Method::POST,
        &rotate_path(slug),
        Some(token),
        Some(body),
    )
    .await
}

fn items(resp: &TestResponse) -> Vec<Value> {
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(resp)["items"].as_array().expect("items").clone()
}

fn kids(resp: &TestResponse) -> Vec<String> {
    items(resp)
        .iter()
        .map(|k| k["kid"].as_str().expect("kid").to_owned())
        .collect()
}

fn find<'a>(items: &'a [Value], kid: &str) -> &'a Value {
    items
        .iter()
        .find(|k| k["kid"] == kid)
        .unwrap_or_else(|| panic!("{kid} not listed: {items:?}"))
}

async fn jwks_kids(app: &TestApp) -> Vec<String> {
    let resp = app.get("/jwks").await;
    assert_eq!(resp.status, 200);
    body_json(&resp)["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|k| k["kid"].as_str().expect("kid").to_owned())
        .collect()
}

async fn tenant(app: &TestApp, slug: &str) -> Tenant {
    app.storage()
        .tenants()
        .get_by_slug(slug)
        .await
        .unwrap()
        .unwrap()
}

async fn audit(app: &TestApp, tenant: &Tenant) -> Vec<AuditEvent> {
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

/// Asserts that no JSON object anywhere in `v` carries private key material.
fn assert_no_private_members(v: &Value, raw: &str) {
    const PRIVATE: [&str; 8] = ["private_key_enc", "d", "p", "q", "dp", "dq", "qi", "k"];
    match v {
        Value::Object(map) => {
            for name in PRIVATE {
                assert!(
                    !map.contains_key(name),
                    "member `{name}` must never be returned: {raw}"
                );
            }
            for (key, child) in map {
                assert_ne!(key, "public_jwk", "no JWK in the key view: {raw}");
                assert_no_private_members(child, raw);
            }
        }
        Value::Array(a) => a.iter().for_each(|c| assert_no_private_members(c, raw)),
        _ => {}
    }
}

#[tokio::test]
async fn keys_list_shows_active_and_published_keys() {
    let app = app().await;
    let t = admin_token(&app, "admin:settings:read admin:settings:write").await;
    let installed = app.default.as_ref().unwrap();

    let before = items(&list(&app, &t, "default").await);
    assert_eq!(before.len(), 1, "{before:?}");
    let active = find(&before, &installed.kid);
    assert_eq!(active["alg"], "RS256");
    assert_eq!(active["state"], "active");
    assert!(
        active["created_at"]
            .as_str()
            .is_some_and(|s| s.contains('T'))
    );
    assert!(active["activated_at"].as_str().is_some());
    assert!(active["retired_at"].is_null());
    assert!(active["expires_at"].is_null());

    // A prepublished key is listed first (newest first) in state `next`.
    app.clock().advance(std::time::Duration::from_secs(5));
    let resp = rotate(&app, &t, "default", json!({"alg": "RS256"})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let next_kid = body_json(&resp)["kid"].as_str().unwrap().to_owned();
    let after = items(&list(&app, &t, "default").await);
    assert_eq!(after.len(), 2);
    assert_eq!(after[0]["kid"], next_kid.as_str());
    assert_eq!(after[0]["state"], "next");
    assert!(after[0]["activated_at"].is_null());
    assert_eq!(after[1]["kid"], installed.kid.as_str());
    assert_eq!(after[1]["state"], "active");
}

#[tokio::test]
async fn keys_list_never_contains_private_material() {
    let app = app().await;
    let t = admin_token(&app, "admin:read admin:write").await;
    // Next, active and retired keys of every kind of state are present.
    let resp = rotate(
        &app,
        &t,
        "default",
        json!({"alg": "RS256", "immediate": true}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = rotate(&app, &t, "default", json!({"alg": "RS256"})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    for slug in ["default", "system"] {
        let resp = list(&app, &t, slug).await;
        let body = body_json(&resp);
        assert!(!items(&resp).is_empty());
        assert_no_private_members(&body, &resp.text());
        assert!(!resp.text().contains("private_key_enc"));
        assert!(!resp.text().contains("PRIVATE KEY"));
        for item in items(&resp) {
            let mut members: Vec<&str> = item
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            members.sort_unstable();
            assert_eq!(
                members,
                [
                    "activated_at",
                    "alg",
                    "created_at",
                    "expires_at",
                    "kid",
                    "retired_at",
                    "state"
                ],
                "only the documented members"
            );
        }
    }
    // The sealed bytes never appear, even encoded.
    let rows = app
        .storage()
        .keys()
        .list(tenant(&app, "default").await.id)
        .await
        .unwrap();
    let text = list(&app, &t, "default").await.text();
    for row in rows {
        let b64 = anvil_jose::encoding::b64std(&row.private_key_enc);
        assert!(!text.contains(&b64[..32.min(b64.len())]));
    }
}

#[tokio::test]
async fn keys_rotate_returns_new_kid_and_audits() {
    let app = app().await;
    let client_id = system_client(&app, &["admin:settings:write"]).await;
    let system = app.system.as_ref().unwrap();
    let t = mint_access_token(
        &app,
        system,
        &system_issuer(&app),
        &client_id,
        "admin:settings:write",
    )
    .await;
    let old_kid = app.default.as_ref().unwrap().kid.clone();

    // Prepublish: the new key is `next`, already in /jwks, the old one still signs.
    let resp = rotate(
        &app,
        &t,
        "default",
        json!({"alg": "RS256", "immediate": false}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let next_kid = body_json(&resp)["kid"].as_str().unwrap().to_owned();
    assert_ne!(next_kid, old_kid);
    let listed = items(&list(&app, &t, "default").await);
    assert_eq!(find(&listed, &next_kid)["state"], "next");
    assert_eq!(find(&listed, &old_kid)["state"], "active");
    let published = jwks_kids(&app).await;
    assert!(published.contains(&next_kid) && published.contains(&old_kid));

    // Asking again keeps the existing next key.
    let resp = rotate(&app, &t, "default", json!({"alg": "RS256"})).await;
    assert_eq!(body_json(&resp)["kid"], next_kid.as_str());

    // Immediate: a fresh key signs at once; the old active key leaves /jwks.
    app.clock().advance(std::time::Duration::from_secs(5));
    let resp = rotate(
        &app,
        &t,
        "default",
        json!({"alg": "RS256", "immediate": true}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let new_kid = body_json(&resp)["kid"].as_str().unwrap().to_owned();
    assert!(new_kid != old_kid && new_kid != next_kid);
    let listed = items(&list(&app, &t, "default").await);
    assert_eq!(find(&listed, &new_kid)["state"], "active");
    let old = find(&listed, &old_kid);
    assert_eq!(old["state"], "retired");
    assert!(old["retired_at"].as_str().is_some() && old["expires_at"].as_str().is_some());
    let published = jwks_kids(&app).await;
    assert!(published.contains(&new_kid));
    assert!(!published.contains(&old_kid));

    // Audited in the tenant, by the admin client.
    let events = audit(&app, &tenant(&app, "default").await).await;
    let requested: Vec<&AuditEvent> = events
        .iter()
        .filter(|e| e.action == AuditAction::KeyRotationRequested)
        .collect();
    assert_eq!(requested.len(), 3, "{requested:?}");
    for e in &requested {
        assert_eq!(e.actor.kind, ActorKind::Admin, "{e:?}");
        assert_eq!(e.actor.id.as_deref(), Some(client_id.as_str()));
    }
    assert!(
        events.iter().any(|e| e.action == AuditAction::KeyGenerated
            && e.target.as_deref() == Some(new_kid.as_str()))
    );
}

#[tokio::test]
async fn keys_rotate_disabled_alg_is_422() {
    let app = app().await;
    let t = admin_token(&app, "admin:write").await;
    for alg in ["ES256", "Ed25519"] {
        let resp = rotate(&app, &t, "default", json!({"alg": alg})).await;
        assert_field_error(&resp, "alg");
    }
    // An unknown algorithm or an unknown member is refused before the service runs.
    for body in [
        json!({"alg": "HS256"}),
        json!({"alg": "RS256", "private_key": "x"}),
        json!({}),
    ] {
        let resp = rotate(&app, &t, "default", body.clone()).await;
        assert!(
            resp.status.is_client_error(),
            "{body}: {} {}",
            resp.status,
            resp.text()
        );
    }
    // Nothing was generated.
    let listed = items(&list(&app, &t, "default").await);
    assert_eq!(listed.len(), 1, "{listed:?}");
}

#[tokio::test]
async fn keys_routes_require_scopes() {
    let app = app().await;

    // No token, or a garbage token: 401 on both routes.
    for token in [None, Some("not-a-jwt")] {
        let resp = call(&app, Method::GET, &keys_path("default"), token, None).await;
        assert_problem(&resp, 401);
        let resp = call(
            &app,
            Method::POST,
            &rotate_path("default"),
            token,
            Some(json!({"alg": "RS256"})),
        )
        .await;
        assert_problem(&resp, 401);
    }

    // Unrelated scopes: neither read nor rotate.
    let unrelated = admin_token(&app, "admin:users:write admin:clients:write").await;
    assert_problem(&list(&app, &unrelated, "default").await, 403);
    assert_problem(
        &rotate(&app, &unrelated, "default", json!({"alg": "RS256"})).await,
        403,
    );

    // Read scopes can list but not rotate.
    for scope in ["admin:settings:read", "admin:read"] {
        let read = admin_token(&app, scope).await;
        assert_eq!(list(&app, &read, "default").await.status, 200, "{scope}");
        let resp = rotate(&app, &read, "default", json!({"alg": "RS256"})).await;
        assert_problem(&resp, 403);
    }

    // admin:settings:write rotates a regular tenant, but not the system tenant.
    let settings = admin_token(&app, "admin:settings:write").await;
    assert_eq!(list(&app, &settings, "system").await.status, 200);
    let system_before = kids(&list(&app, &settings, "system").await);
    let resp = rotate(&app, &settings, "system", json!({"alg": "RS256"})).await;
    assert_problem(&resp, 403);
    assert_eq!(kids(&list(&app, &settings, "system").await), system_before);
    let resp = rotate(&app, &settings, "default", json!({"alg": "RS256"})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // admin:write may rotate the system tenant.
    let full = admin_token(&app, "admin:write").await;
    let resp = rotate(&app, &full, "system", json!({"alg": "RS256"})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(kids(&list(&app, &full, "system").await).len(), 2);
}

#[tokio::test]
async fn keys_routes_isolate_tenants() {
    let app = app().await;
    let default = app.default.as_ref().unwrap();
    let client_id = system_client(&app, &["admin:read", "admin:write"]).await;

    // Tokens of the default tenant (its own issuer, or its key claiming the system issuer) are
    // not admin tokens, whichever tenant they address.
    let foreign = [
        mint_access_token(
            &app,
            default,
            &app.issuer(None),
            &client_id,
            "admin:read admin:write",
        )
        .await,
        mint_access_token(
            &app,
            default,
            &system_issuer(&app),
            &client_id,
            "admin:read admin:write",
        )
        .await,
    ];
    for token in &foreign {
        for slug in ["default", "system"] {
            let resp = list(&app, token, slug).await;
            assert_problem(&resp, 401);
            assert!(!resp.text().contains(&default.kid));
            let resp = rotate(&app, token, slug, json!({"alg": "RS256"})).await;
            assert_problem(&resp, 401);
        }
    }

    // A tenant's list holds only its own keys.
    let full = admin_token(&app, "admin:read admin:write").await;
    let system_kid = app.system.as_ref().unwrap().kid.clone();
    let default_kids = kids(&list(&app, &full, "default").await);
    let system_kids = kids(&list(&app, &full, "system").await);
    assert_eq!(default_kids, vec![default.kid.clone()]);
    assert_eq!(system_kids, vec![system_kid.clone()]);

    // Rotating one tenant leaves the other untouched.
    let resp = rotate(&app, &full, "default", json!({"alg": "RS256"})).await;
    let new_kid = body_json(&resp)["kid"].as_str().unwrap().to_owned();
    assert!(!kids(&list(&app, &full, "system").await).contains(&new_kid));
    assert_eq!(kids(&list(&app, &full, "system").await), vec![system_kid]);

    // Unknown tenants are 404 for both routes.
    assert_problem(&list(&app, &full, "nope").await, 404);
    assert_problem(
        &rotate(&app, &full, "nope", json!({"alg": "RS256"})).await,
        404,
    );

    // The API is installation-level: a tenant-addressed base does not serve it.
    let resp = call(
        &app,
        Method::GET,
        &format!("/t/default{API}/tenants/default/keys"),
        Some(&full),
        None,
    )
    .await;
    assert_eq!(resp.status, 404, "{}", resp.text());
}
