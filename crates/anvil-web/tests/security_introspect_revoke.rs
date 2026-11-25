//! Security controls of `POST /introspect` (RFC 7662) and `POST /revoke` (RFC 7009): caller
//! authentication, caller visibility, the exact inactive answer, revocation effects at `/token`,
//! UserInfo and introspection, the no-oracle rule for other clients' tokens, and the audit trail.
//! Runs on the selected backend (`ANVILID_TEST_DB`).

mod support;
mod token_support;

use std::time::Duration;

use anvil_core::model::{
    AuditAction, AuditEvent, AuditQuery, ClientAuthMethod, ClientUpdate, TenantId, TokenFormat,
};
use axum::body::Body;
use axum::http::{Request, header};
use serde_json::Value;
use support::{DEFAULT_PEER, TestApp, TestResponse, json};
use token_support::*;

const SCOPE: &str = "openid email";

fn field(body: &Value, name: &str) -> String {
    body[name].as_str().expect(name).to_owned()
}

async fn update(app: &TestApp, tenant: TenantId, rp: &Rp, update: ClientUpdate) {
    app.storage()
        .clients()
        .update(tenant, rp.id(), &update, app.clock_now())
        .await
        .expect("client update")
        .expect("client exists");
}

/// A confidential resource server (client credentials, basic auth), optionally `can_introspect`.
async fn resource_server(app: &TestApp, tenant: TenantId, can_introspect: bool) -> Rp {
    let rs = register(app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    if can_introspect {
        update(
            app,
            tenant,
            &rs,
            ClientUpdate {
                can_introspect: Some(true),
                ..ClientUpdate::default()
            },
        )
        .await;
    }
    rs
}

/// Runs a code flow for a new user of `rp` at `{prefix}/token` and returns the token response.
async fn user_tokens(app: &TestApp, tenant: TenantId, prefix: &str, rp: &Rp, email: &str) -> Value {
    let user = seed_user(app, tenant, email).await;
    let session = seed_session(app, tenant, &user).await;
    let code = issue_code(app, tenant, rp, &session, &params(SCOPE, Some(CHALLENGE))).await;
    let resp = token_at(
        app,
        &format!("{prefix}/token"),
        &rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    json(&resp)
}

async fn introspect_as(app: &TestApp, caller: &Rp, token: &str) -> TestResponse {
    token_at(app, "/introspect", &caller.auth(), &[("token", token)]).await
}

/// Introspects and asserts the 200 + no-store envelope; returns the body.
async fn introspection(app: &TestApp, caller: &Rp, token: &str) -> Value {
    let resp = introspect_as(app, caller, token).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.header("pragma"), Some("no-cache"));
    json(&resp)
}

async fn assert_inactive(app: &TestApp, caller: &Rp, token: &str) {
    let resp = introspect_as(app, caller, token).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    // Exactly {"active":false}: nothing tells the caller why.
    assert_eq!(resp.text(), r#"{"active":false}"#);
}

async fn revoke_as(app: &TestApp, caller: &Rp, token: &str, hint: Option<&str>) -> TestResponse {
    let mut pairs = vec![("token", token)];
    if let Some(h) = hint {
        pairs.push(("token_type_hint", h));
    }
    token_at(app, "/revoke", &caller.auth(), &pairs).await
}

fn assert_revoked_ok(resp: &TestResponse) {
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(resp.body.is_empty(), "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
}

async fn audit(app: &TestApp, tenant: TenantId, action: AuditAction) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            tenant,
            &AuditQuery {
                action: Some(action),
                limit: 50,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

fn fid_of(at: &str) -> String {
    field(&jwt_claims(at), "fid")
}

// ---------------------------------------------------------------------------------------------
// /introspect: caller authentication and request shape
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn introspect_requires_confidential_client_authentication() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let at = field(&body, "access_token");

    // No client authentication at all.
    let resp = post_raw(&app, "/introspect", None, &[("token", &at)]).await;
    assert_oauth_error(&resp, 401, "invalid_client");

    // Wrong Basic secret: 401 with a Basic challenge.
    let resp = token_at(
        &app,
        "/introspect",
        &Auth::Basic(flow.rp.id().into(), "wrong".into()),
        &[("token", &at)],
    )
    .await;
    assert_oauth_error(&resp, 401, "invalid_client");
    assert!(
        resp.header("www-authenticate")
            .is_some_and(|h| h.starts_with("Basic")),
        "{:?}",
        resp.header("www-authenticate")
    );

    // A public client authenticates with client_id only, but may not introspect.
    let public = register(&app, flow.tenant, public_input()).await;
    let resp = introspect_as(&app, &public, &at).await;
    assert_oauth_error(&resp, 401, "invalid_client");
    // Same description as every client-authentication failure.
    assert_eq!(
        json(&resp)["error_description"],
        "client authentication failed"
    );
}

#[tokio::test]
async fn introspect_request_shape_is_enforced() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rs = resource_server(&app, tenant, true).await;

    assert_eq!(app.get("/introspect").await.status, 405);

    let json_body = app
        .send(
            Request::post("/introspect")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, basic(rs.id(), rs.secret()))
                .body(Body::from(r#"{"token":"x"}"#))
                .expect("request"),
        )
        .await;
    assert_oauth_error(&json_body, 400, "invalid_request");

    let repeated = token_at(
        &app,
        "/introspect",
        &rs.auth(),
        &[("token", "a"), ("token", "b")],
    )
    .await;
    assert_oauth_error(&repeated, 400, "invalid_request");

    let missing = token_at(&app, "/introspect", &rs.auth(), &[]).await;
    assert_oauth_error(&missing, 400, "invalid_request");
    let empty = token_at(&app, "/introspect", &rs.auth(), &[("token", "")]).await;
    assert_oauth_error(&empty, 400, "invalid_request");
}

// ---------------------------------------------------------------------------------------------
// /introspect: visibility and inactive cases
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn own_access_token_is_active_with_rfc7662_fields() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let at = field(&body, "access_token");
    let claims = jwt_claims(&at);
    let i = introspection(&app, &flow.rp, &at).await;
    assert_eq!(i["active"], true);
    assert_eq!(i["scope"], "email openid");
    assert_eq!(i["client_id"], flow.rp.id());
    assert_eq!(i["aud"], flow.rp.id());
    assert_eq!(i["sub"], flow.user.id.to_string());
    assert_eq!(i["iss"], "https://op.test");
    assert_eq!(i["exp"], claims["exp"]);
    assert_eq!(i["iat"], claims["iat"]);
    assert_eq!(i["jti"], claims["jti"]);
    assert_eq!(i["token_type"], "Bearer");
    // An unknown hint is ignored at introspection (RFC 7662 §2.1).
    let resp = token_at(
        &app,
        "/introspect",
        &flow.rp.auth(),
        &[("token", &at), ("token_type_hint", "id_token")],
    )
    .await;
    assert_eq!(json(&resp)["active"], true, "{}", resp.text());
}

#[tokio::test]
async fn other_clients_token_needs_can_introspect() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let at = field(&body, "access_token");
    let rt = field(&body, "refresh_token");

    let plain = resource_server(&app, flow.tenant, false).await;
    assert_inactive(&app, &plain, &at).await;
    assert_inactive(&app, &plain, &rt).await;

    let privileged = resource_server(&app, flow.tenant, true).await;
    let i = introspection(&app, &privileged, &at).await;
    assert_eq!(i["active"], true);
    assert_eq!(
        i["client_id"],
        flow.rp.id(),
        "the token's client, not the caller"
    );
    let i = introspection(&app, &privileged, &rt).await;
    assert_eq!(i["active"], true);
    assert_eq!(i["token_type"], "refresh_token");
}

#[tokio::test]
async fn garbage_expired_and_other_tenant_tokens_are_inactive() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rs = resource_server(&app, tenant, true).await;
    for garbage in [
        "garbage",
        "a.b.c",
        "eyJhbGciOiJub25lIn0.e30.",
        &"x".repeat(43),
    ] {
        assert_inactive(&app, &rs, garbage).await;
    }

    // Another tenant's tokens (JWT, opaque, refresh) are unknown here, even with can_introspect.
    let acme = acme(&app).await;
    let acme_rp = register(
        &app,
        acme.id,
        web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let jwt_body = user_tokens(&app, acme.id, "/t/acme", &acme_rp, "a@acme.test").await;
    update(
        &app,
        acme.id,
        &acme_rp,
        ClientUpdate {
            token_format: Some(TokenFormat::Opaque),
            ..ClientUpdate::default()
        },
    )
    .await;
    let opaque_body = user_tokens(&app, acme.id, "/t/acme", &acme_rp, "b@acme.test").await;
    for t in [
        field(&jwt_body, "access_token"),
        field(&jwt_body, "refresh_token"),
        field(&opaque_body, "access_token"),
    ] {
        assert_inactive(&app, &rs, &t).await;
    }

    // Expired tokens (TestClock past the 10-minute access token lifetime).
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let body = user_tokens(&app, tenant, "", &rp, "e@example.test").await;
    let at = field(&body, "access_token");
    assert_eq!(introspection(&app, &rs, &at).await["active"], true);
    app.clock().advance(Duration::from_secs(601));
    assert_inactive(&app, &rs, &at).await;
}

#[tokio::test]
async fn consumed_refresh_token_is_inactive() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let rt = field(&body, "refresh_token");
    let i = introspection(&app, &flow.rp, &rt).await;
    assert_eq!(i["active"], true);
    assert_eq!(i["token_type"], "refresh_token");
    assert_eq!(i["sub"], flow.user.id.to_string());
    let resp = refresh(&app, &flow.rp, &rt, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_inactive(&app, &flow.rp, &rt).await;
    // The rotated child is active.
    let child = field(&json(&resp), "refresh_token");
    assert_eq!(introspection(&app, &flow.rp, &child).await["active"], true);
}

// ---------------------------------------------------------------------------------------------
// /revoke
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn revoke_requires_client_authentication_and_post() {
    let app = TestApp::new().await;
    assert_eq!(app.get("/revoke").await.status, 405);
    let resp = post_raw(&app, "/revoke", None, &[("token", "x")]).await;
    assert_oauth_error(&resp, 401, "invalid_client");
    let tenant = default_tenant(&app);
    let rs = resource_server(&app, tenant, false).await;
    let missing = token_at(&app, "/revoke", &rs.auth(), &[]).await;
    assert_oauth_error(&missing, 400, "invalid_request");
}

#[tokio::test]
async fn unknown_token_is_200_without_effect() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    for t in ["unknown", "a.b.c", &"y".repeat(43)] {
        assert_revoked_ok(&revoke_as(&app, &flow.rp, t, None).await);
    }
    assert_eq!(
        userinfo_get(&app, &field(&body, "access_token"))
            .await
            .status,
        200
    );
    assert!(
        audit(&app, flow.tenant, AuditAction::TokenRevoked)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn unsupported_hint_is_rejected() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let rt = field(&body, "refresh_token");
    let resp = revoke_as(&app, &flow.rp, &rt, Some("id_token")).await;
    assert_oauth_error(&resp, 400, "unsupported_token_type");
    // Nothing was revoked.
    assert_eq!(introspection(&app, &flow.rp, &rt).await["active"], true);
}

#[tokio::test]
async fn revoking_a_refresh_token_revokes_the_family() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let at = field(&body, "access_token");
    let rt = field(&body, "refresh_token");

    assert_revoked_ok(&revoke_as(&app, &flow.rp, &rt, Some("refresh_token")).await);
    assert_oauth_error(
        &refresh(&app, &flow.rp, &rt, None).await,
        400,
        "invalid_grant",
    );
    assert_inactive(&app, &flow.rp, &rt).await;
    // The access token of the same family dies with it.
    assert_invalid_token(&userinfo_get(&app, &at).await);
    assert_inactive(&app, &flow.rp, &at).await;

    let events = audit(&app, flow.tenant, AuditAction::TokenRevoked).await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(
        e.target.as_deref(),
        Some(fid_of(&at).as_str()),
        "target = family"
    );
    assert_eq!(e.actor.id.as_deref(), Some(flow.rp.id()));
    assert!(e.ctx.ip.is_some(), "request context recorded");
    // The token itself never reaches the audit trail.
    let dump = format!("{e:?}");
    assert!(!dump.contains(&rt) && !dump.contains(&at));

    // Revoking again is still 200 and not audited twice.
    assert_revoked_ok(&revoke_as(&app, &flow.rp, &rt, None).await);
    assert_eq!(
        audit(&app, flow.tenant, AuditAction::TokenRevoked)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn revoking_a_jwt_access_token_revokes_its_family() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let at = field(&body, "access_token");
    let rt = field(&body, "refresh_token");
    assert_eq!(userinfo_get(&app, &at).await.status, 200);

    assert_revoked_ok(&revoke_as(&app, &flow.rp, &at, Some("access_token")).await);
    assert_invalid_token(&userinfo_get(&app, &at).await);
    assert_inactive(&app, &flow.rp, &at).await;
    assert_oauth_error(
        &refresh(&app, &flow.rp, &rt, None).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn revoking_an_opaque_access_token_revokes_it_and_its_family() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, SCOPE).await;
    update(
        &app,
        flow.tenant,
        &flow.rp,
        ClientUpdate {
            token_format: Some(TokenFormat::Opaque),
            ..ClientUpdate::default()
        },
    )
    .await;
    let body = json(&exchange(&app, &flow.rp, &flow.code).await);
    let at = field(&body, "access_token");
    let rt = field(&body, "refresh_token");
    assert_eq!(userinfo_get(&app, &at).await.status, 200);

    // No hint: access tokens are searched first.
    assert_revoked_ok(&revoke_as(&app, &flow.rp, &at, None).await);
    assert_invalid_token(&userinfo_get(&app, &at).await);
    assert_inactive(&app, &flow.rp, &at).await;
    assert_oauth_error(
        &refresh(&app, &flow.rp, &rt, None).await,
        400,
        "invalid_grant",
    );
    let (record, family) = app
        .storage()
        .grants()
        .find_access_token(
            flow.tenant,
            &anvil_core::model::SecretHash(anvil_jose::encoding::secret_hash(&at)),
        )
        .await
        .expect("lookup")
        .expect("stored");
    assert!(record.revoked_at.is_some());
    assert!(family.expect("family").revoked_at.is_some());
    assert_eq!(
        audit(&app, flow.tenant, AuditAction::TokenRevoked)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn another_clients_token_is_not_revoked() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let at = field(&body, "access_token");
    let rt = field(&body, "refresh_token");
    // Even a client allowed to introspect everything cannot revoke others' tokens.
    let other = resource_server(&app, flow.tenant, true).await;

    for (t, hint) in [(&rt, Some("refresh_token")), (&at, None), (&rt, None)] {
        // 200, exactly like an unknown token: no oracle.
        assert_revoked_ok(&revoke_as(&app, &other, t, hint).await);
    }
    assert_eq!(userinfo_get(&app, &at).await.status, 200);
    let resp = refresh(&app, &flow.rp, &rt, None).await;
    assert_eq!(
        resp.status,
        200,
        "the refresh token still works: {}",
        resp.text()
    );
    assert!(
        audit(&app, flow.tenant, AuditAction::TokenRevoked)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn public_client_revokes_its_own_refresh_token() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let public = register(&app, tenant, public_input()).await;
    let body = user_tokens(&app, tenant, "", &public, "p@example.test").await;
    let rt = field(&body, "refresh_token");

    // client_id only, no secret.
    let resp = token_at(
        &app,
        "/revoke",
        &Auth::None(public.id().into()),
        &[("token", &rt)],
    )
    .await;
    assert_revoked_ok(&resp);
    assert_oauth_error(
        &refresh(&app, &public, &rt, None).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn jwt_client_credentials_token_cannot_be_revoked() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let svc = resource_server(&app, tenant, false).await;
    let resp = token(&app, &svc.auth(), &[("grant_type", "client_credentials")]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let at = field(&json(&resp), "access_token");
    assert!(jwt_claims(&at).get("fid").is_none());

    let resp = revoke_as(&app, &svc, &at, None).await;
    assert_oauth_error(&resp, 400, "unsupported_token_type");
    // Its own token is still active (self-contained JWT).
    assert_eq!(introspection(&app, &svc, &at).await["active"], true);

    // An opaque client-credentials token can be revoked.
    update(
        &app,
        tenant,
        &svc,
        ClientUpdate {
            token_format: Some(TokenFormat::Opaque),
            ..ClientUpdate::default()
        },
    )
    .await;
    let resp = token(&app, &svc.auth(), &[("grant_type", "client_credentials")]).await;
    let opaque = field(&json(&resp), "access_token");
    assert_eq!(introspection(&app, &svc, &opaque).await["active"], true);
    assert_revoked_ok(&revoke_as(&app, &svc, &opaque, None).await);
    assert_inactive(&app, &svc, &opaque).await;
    let events = audit(&app, tenant, AuditAction::TokenRevoked).await;
    assert_eq!(events.len(), 1);
    assert!(events[0].target.is_none(), "no family, and never the token");
}

// ---------------------------------------------------------------------------------------------
// Reuse detection is audited
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn refresh_and_code_reuse_are_audited() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let fid = fid_of(&field(&body, "access_token"));

    // Code replay.
    assert_oauth_error(
        &exchange(&app, &flow.rp, &flow.code).await,
        400,
        "invalid_grant",
    );
    let events = audit(&app, flow.tenant, AuditAction::CodeReuseDetected).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].target.as_deref(), Some(fid.as_str()));
    assert_eq!(events[0].actor.id.as_deref(), Some(flow.rp.id()));
    // The event carries the real request context of the replaying /token call.
    assert_eq!(events[0].ctx.ip, Some(DEFAULT_PEER.ip()));

    // Refresh replay (on a fresh family).
    let rp = register(
        &app,
        flow.tenant,
        web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let body = user_tokens(&app, flow.tenant, "", &rp, "r@example.test").await;
    let fid = fid_of(&field(&body, "access_token"));
    let rt = field(&body, "refresh_token");
    assert_eq!(refresh(&app, &rp, &rt, None).await.status, 200);
    assert_oauth_error(&refresh(&app, &rp, &rt, None).await, 400, "invalid_grant");
    let events = audit(&app, flow.tenant, AuditAction::RefreshReuseDetected).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].target.as_deref(), Some(fid.as_str()));
    assert_eq!(events[0].action, AuditAction::RefreshReuseDetected);
    assert_eq!(events[0].ctx.ip, Some(DEFAULT_PEER.ip()));
}
