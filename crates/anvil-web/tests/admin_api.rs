//! Management API behaviour: tenant, client and user CRUD, pagination, problem responses and the
//! registration rules enforced through `ClientService` / `UserService`.

mod admin_support;
mod support;

use std::time::Duration;

use admin_support::*;
use anvil_core::model::UserId;
use anvil_core::ports::{Clock as _, PasswordHasher as _};
use anvil_core::service::client_auth::secret_matches;
use anvil_web::adapters::argon2::Argon2Pool;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};

const FULL: &str = "admin:read admin:write";

async fn app_and_token() -> (TestApp, String) {
    let app = TestApp::new().await;
    let token = admin_token(&app, FULL).await;
    (app, token)
}

// ---------------------------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tenant_crud_and_pagination() {
    let (app, t) = app_and_token().await;

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&t),
        Some(json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(resp.header("location"), Some("/api/admin/v1/tenants/acme"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let created = body_json(&resp);
    assert_eq!(created["slug"], "acme");
    assert_eq!(created["display_name"], "Acme");
    assert_eq!(created["settings"]["registration"], "open");

    // The new tenant has an active signing key.
    let acme = app
        .storage()
        .tenants()
        .get_by_slug("acme")
        .await
        .unwrap()
        .expect("tenant stored");
    assert!(
        app.storage()
            .keys()
            .active(acme.id, "RS256")
            .await
            .unwrap()
            .is_some()
    );

    // system, default, acme: limit 1 pages through all three.
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let path = match &after {
            Some(a) => format!("{API}/tenants?limit=1&after={a}"),
            None => format!("{API}/tenants?limit=1"),
        };
        let resp = call(&app, Method::GET, &path, Some(&t), None).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        let page = body_json(&resp);
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        seen.push(items[0]["slug"].as_str().unwrap().to_owned());
        match page["next_cursor"].as_str() {
            Some(c) => after = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen, ["system", "default", "acme"]);

    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/acme"),
        Some(&t),
        Some(json!({"display_name": "Acme Corp"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["display_name"], "Acme Corp");

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/acme"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["display_name"], "Acme Corp");

    // Duplicate slug → 409; reserved / malformed slug → 422.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&t),
        Some(json!({"slug": "acme", "display_name": "Again"})),
    )
    .await;
    assert_problem(&resp, 409);
    for slug in ["default", "Bad_Slug"] {
        let resp = call(
            &app,
            Method::POST,
            &format!("{API}/tenants"),
            Some(&t),
            Some(json!({"slug": slug, "display_name": "X"})),
        )
        .await;
        assert_field_error(&resp, "slug");
    }

    // Protected tenants cannot be deleted.
    for slug in ["system", "default"] {
        let resp = call(
            &app,
            Method::DELETE,
            &format!("{API}/tenants/{slug}"),
            Some(&t),
            None,
        )
        .await;
        let body = assert_problem(&resp, 403);
        assert_eq!(body["type"], "urn:anvilid:problem:forbidden");
    }

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/acme"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    assert!(resp.body.is_empty());
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/acme"),
        Some(&t),
        None,
    )
    .await;
    assert_problem(&resp, 404);
}

#[tokio::test]
async fn list_query_is_validated() {
    let (app, t) = app_and_token().await;
    for q in ["limit=0", "limit=201", "after=not-a-uuid", "colour=blue"] {
        let resp = call(
            &app,
            Method::GET,
            &format!("{API}/tenants?{q}"),
            Some(&t),
            None,
        )
        .await;
        assert_problem(&resp, 422);
    }
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants?limit=200"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    let page = body_json(&resp);
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(page["next_cursor"], Value::Null);
}

#[tokio::test]
async fn bodies_and_unknown_routes_give_problems() {
    let (app, t) = app_and_token().await;
    // Unknown field (typo) → 422 instead of being silently ignored.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&t),
        Some(json!({"slug": "acme", "displayName": "Acme"})),
    )
    .await;
    assert_field_error(&resp, "body");

    // Malformed JSON → 400 problem.
    let req = axum::http::Request::post(format!("{API}/tenants"))
        .header("authorization", format!("Bearer {t}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{not json"))
        .unwrap();
    let resp = app.send(req).await;
    assert_problem(&resp, 400);

    let resp = call(&app, Method::GET, &format!("{API}/nope"), Some(&t), None).await;
    assert_problem(&resp, 404);
}

// ---------------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------------

fn confidential_client() -> Value {
    json!({
        "name": "Web app",
        "client_type": "confidential",
        "auth_method": "client_secret_basic",
        "redirect_uris": ["https://rp.example/cb"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "email", "offline_access"],
    })
}

#[tokio::test]
async fn client_create_get_rotate_update_delete() {
    let (app, t) = app_and_token().await;
    let base = format!("{API}/tenants/default/clients");

    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(confidential_client()),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let created = body_json(&resp);
    let client_id = created["client_id"].as_str().unwrap().to_owned();
    let secret = created["client_secret"].as_str().unwrap().to_owned();
    assert!(secret.len() >= 43, "secret has 256 bits");
    assert_eq!(created["require_pkce"], true);
    assert_eq!(
        resp.header("location"),
        Some(format!("{base}/{client_id}").as_str())
    );

    let resp = call(
        &app,
        Method::GET,
        &format!("{base}/{client_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    let fetched = body_json(&resp);
    assert!(fetched.get("client_secret").is_none(), "{fetched}");
    assert!(!resp.text().contains(&secret));
    assert_eq!(
        fetched["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );

    let resp = call(
        &app,
        Method::GET,
        &format!("{base}?limit=10"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    let list = body_json(&resp);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert!(!resp.text().contains(&secret));

    // Rotation: a new secret; the old one no longer authenticates the client.
    let resp = call(
        &app,
        Method::POST,
        &format!("{base}/{client_id}/secret"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let rotated = body_json(&resp);
    let new_secret = rotated["client_secret"].as_str().unwrap().to_owned();
    assert_ne!(new_secret, secret);
    let default = app.default.as_ref().unwrap();
    let stored = app
        .storage()
        .clients()
        .get(default.tenant.id, &client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!secret_matches(stored.secret_hash.as_ref(), &secret));
    assert!(secret_matches(stored.secret_hash.as_ref(), &new_secret));

    let resp = call(
        &app,
        Method::PATCH,
        &format!("{base}/{client_id}"),
        Some(&t),
        Some(json!({"name": "Renamed", "redirect_uris": ["https://rp.example/cb2"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let updated = body_json(&resp);
    assert_eq!(updated["name"], "Renamed");
    assert_eq!(updated["redirect_uris"], json!(["https://rp.example/cb2"]));

    // PATCH re-validates the merged registration.
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{base}/{client_id}"),
        Some(&t),
        Some(json!({"redirect_uris": ["http://evil.example/cb"]})),
    )
    .await;
    assert_field_error(&resp, "redirect_uris");

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{base}/{client_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 204);
    let resp = call(
        &app,
        Method::GET,
        &format!("{base}/{client_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::POST,
        &format!("{base}/{client_id}/secret"),
        Some(&t),
        None,
    )
    .await;
    assert_problem(&resp, 404);
}

#[tokio::test]
async fn client_registration_rules_are_enforced() {
    let (app, t) = app_and_token().await;
    let base = format!("{API}/tenants/default/clients");

    // C1: public clients cannot disable PKCE.
    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(json!({
            "name": "SPA",
            "client_type": "public",
            "auth_method": "none",
            "redirect_uris": ["https://spa.example/cb"],
            "require_pkce": false,
        })),
    )
    .await;
    assert_field_error(&resp, "require_pkce");

    // A confidential client may disable PKCE (C1).
    let mut c = confidential_client();
    c["require_pkce"] = json!(false);
    let resp = call(&app, Method::POST, &base, Some(&t), Some(c)).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(body_json(&resp)["require_pkce"], false);

    // jwks_uri is not supported.
    let mut c = confidential_client();
    c["jwks_uri"] = json!("https://rp.example/jwks");
    let resp = call(&app, Method::POST, &base, Some(&t), Some(c)).await;
    assert_field_error(&resp, "jwks_uri");

    // Redirect URI validation (fragment, plain http on a public host, wildcard).
    for uri in [
        "https://rp.example/cb#frag",
        "http://rp.example/cb",
        "https://*.rp.example/cb",
    ] {
        let mut c = confidential_client();
        c["redirect_uris"] = json!([uri]);
        let resp = call(&app, Method::POST, &base, Some(&t), Some(c)).await;
        assert_field_error(&resp, "redirect_uris");
    }

    // Unknown enum value → 422.
    let mut c = confidential_client();
    c["client_type"] = json!("trusted");
    let resp = call(&app, Method::POST, &base, Some(&t), Some(c)).await;
    assert_field_error(&resp, "body");

    // A public client gets no secret; rotating it is refused.
    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(json!({
            "name": "SPA",
            "client_type": "public",
            "redirect_uris": ["https://spa.example/cb"],
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let public = body_json(&resp);
    assert_eq!(public["auth_method"], "none");
    assert!(public.get("client_secret").is_none());
    let resp = call(
        &app,
        Method::POST,
        &format!("{base}/{}/secret", public["client_id"].as_str().unwrap()),
        Some(&t),
        None,
    )
    .await;
    assert_field_error(&resp, "auth_method");

    // Unknown tenant.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/nope/clients"),
        Some(&t),
        Some(confidential_client()),
    )
    .await;
    assert_problem(&resp, 404);
}

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn user_with_password_can_log_in() {
    let (app, t) = app_and_token().await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&t),
        Some(json!({
            "email": "Alice@Example.com",
            "password": "correct horse battery staple",
            "email_verified": true,
            "username": "alice",
            "claims": {"given_name": "Alice", "address": {"country": "NL"}},
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let user = body_json(&resp);
    assert_eq!(user["email"], "alice@example.com");
    assert_eq!(user["email_verified"], true);
    assert_eq!(user["claims"]["given_name"], "Alice");
    assert_eq!(user["claims"]["address"]["country"], "NL");
    assert_eq!(user["status"], "active");
    let text = resp.text();
    assert!(
        !text.contains("password") && !text.contains("correct horse"),
        "{text}"
    );
    let id = user["id"].as_str().unwrap();
    assert_eq!(
        resp.header("location"),
        Some(format!("{API}/tenants/default/users/{id}").as_str())
    );

    // The stored credential verifies with the password hasher.
    let default = app.default.as_ref().unwrap();
    let cred = app
        .storage()
        .users()
        .password(default.tenant.id, UserId(id.parse().unwrap()))
        .await
        .unwrap()
        .expect("password credential stored");
    let hasher = Argon2Pool::new(argon2::Params::new(256, 1, 1, None).unwrap(), 1).unwrap();
    let ok = hasher
        .verify(Some(&cred.phc), "correct horse battery staple")
        .await
        .unwrap();
    assert!(ok.valid);
    let bad = hasher
        .verify(Some(&cred.phc), "wrong password")
        .await
        .unwrap();
    assert!(!bad.valid);
}

#[tokio::test]
async fn invite_enqueues_an_invitation_email() {
    let (app, t) = app_and_token().await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&t),
        Some(json!({"email": "bob@example.com", "invite": true})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());

    let due = app
        .storage()
        .outbox()
        .claim_due(app.clock().now(), 10, Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].template, "invitation");
    assert_eq!(due[0].to, "bob@example.com");
    assert_eq!(due[0].tenant_id, app.default.as_ref().unwrap().tenant.id);

    // No password credential exists for an invited user.
    let id: uuid::Uuid = body_json(&resp)["id"].as_str().unwrap().parse().unwrap();
    let cred = app
        .storage()
        .users()
        .password(app.default.as_ref().unwrap().tenant.id, UserId(id))
        .await
        .unwrap();
    assert!(cred.is_none());
}

#[tokio::test]
async fn user_update_block_delete_and_conflicts() {
    let (app, t) = app_and_token().await;
    let base = format!("{API}/tenants/default/users");
    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(json!({"email": "carol@example.com", "password": "a long enough password"})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let id = body_json(&resp)["id"].as_str().unwrap().to_owned();

    // Duplicate email (case-insensitive after normalisation) → 409.
    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(json!({"email": "CAROL@example.com", "invite": true})),
    )
    .await;
    assert_problem(&resp, 409);

    // Both or neither of password/invite → 422; weak password → 422.
    for body in [
        json!({"email": "d@example.com", "password": "a long enough password", "invite": true}),
        json!({"email": "d@example.com"}),
        json!({"email": "d@example.com", "password": "short"}),
    ] {
        let resp = call(&app, Method::POST, &base, Some(&t), Some(body)).await;
        assert_field_error(&resp, "password");
    }

    app.clock().advance(Duration::from_secs(5));
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(json!({"status": "blocked", "claims": {"name": "Carol C"}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let user = body_json(&resp);
    assert_eq!(user["status"], "blocked");
    assert_eq!(user["claims"]["name"], "Carol C");
    assert_ne!(user["updated_at"], user["created_at"]);

    let resp = call(&app, Method::GET, &format!("{base}/{id}"), Some(&t), None).await;
    assert_eq!(body_json(&resp)["status"], "blocked");

    let resp = call(
        &app,
        Method::GET,
        &format!("{base}?limit=5"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["items"].as_array().unwrap().len(), 1);

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 204);
    let resp = call(&app, Method::GET, &format!("{base}/{id}"), Some(&t), None).await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&t),
        None,
    )
    .await;
    assert_problem(&resp, 404);

    // A path segment that is not a UUID cannot name a user.
    let resp = call(
        &app,
        Method::GET,
        &format!("{base}/not-a-uuid"),
        Some(&t),
        None,
    )
    .await;
    assert_problem(&resp, 404);
}
