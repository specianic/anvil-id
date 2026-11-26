//! Signing-key rotation over a fake clock against the real backend (SQLite by default, Postgres
//! with `ANVILID_TEST_DB=postgres`), and the `/jwks` cache headers.

mod support;
mod token_support;

use std::sync::Arc;

use anvil_core::error::CoreError;
use anvil_core::model::{
    ActorKind, AuditAction, AuditActor, AuditQuery, KeyState, Tenant, TenantId, TenantSettings,
    TenantUpdate,
};
use anvil_core::ports::Clock;
use anvil_core::service::key::KeyService;
use anvil_core::service::key_rotation::{JWKS_MAX_AGE, KeyRotationService, RotationPolicy};
use anvil_jose::jws::verify_jwt;
use anvil_jose::keys::Alg;
use axum::body::Body;
use axum::http::{Request, header};
use support::{TestApp, TestResponse, json};
use time::{Duration, OffsetDateTime};
use token_support::*;

/// A clock frozen at the harness clock's current time (the service is rebuilt per step).
struct Frozen(OffsetDateTime);

impl Clock for Frozen {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// Moves the harness clock by a `time::Duration` (the harness takes `std::time::Duration`).
fn advance(app: &TestApp, d: Duration) {
    app.clock().set(app.clock_now() + d);
}

fn rotation(app: &TestApp) -> KeyRotationService {
    KeyRotationService {
        storage: app.storage_arc(),
        kek: app.kek_arc(),
        clock: Arc::new(Frozen(app.clock_now())),
        policy: RotationPolicy::default(),
    }
}

fn default(app: &TestApp) -> Tenant {
    app.default.as_ref().expect("installed").tenant.clone()
}

async fn active_kid(app: &TestApp, tenant: TenantId, alg: Alg) -> String {
    KeyService {
        storage: app.storage_arc(),
        kek: app.kek_arc(),
        clock: Arc::new(Frozen(app.clock_now())),
    }
    .signer_for(tenant, alg)
    .await
    .expect("active key")
    .kid()
    .to_owned()
}

async fn jwks_kids(app: &TestApp) -> Vec<String> {
    let resp = app.get("/jwks").await;
    assert_eq!(resp.status, 200);
    json(&resp)["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|k| k["kid"].as_str().expect("kid").to_owned())
        .collect()
}

async fn get_jwks(app: &TestApp, if_none_match: Option<&str>) -> TestResponse {
    let mut req = Request::get("/jwks");
    if let Some(tag) = if_none_match {
        req = req.header(header::IF_NONE_MATCH, tag);
    }
    app.send(req.body(Body::empty()).expect("request")).await
}

#[tokio::test]
async fn jwks_has_cache_headers_etag_and_304() {
    let app = TestApp::new().await;
    let first = get_jwks(&app, None).await;
    assert_eq!(first.status, 200);
    assert_eq!(first.header("cache-control"), Some("public, max-age=3600"));
    assert!(
        first
            .header("content-type")
            .is_some_and(|c| c.starts_with("application/json"))
    );
    let etag = first.header("etag").expect("etag").to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"') && !etag.starts_with("W/"));
    assert_eq!(etag.len(), 66, "quoted hex SHA-256");

    // Same tag → 304, empty body, headers repeated.
    let cached = get_jwks(&app, Some(&etag)).await;
    assert_eq!(cached.status, 304);
    assert!(cached.body.is_empty());
    assert_eq!(cached.header("etag"), Some(etag.as_str()));
    assert_eq!(cached.header("cache-control"), Some("public, max-age=3600"));
    assert_eq!(get_jwks(&app, Some("*")).await.status, 304);

    // Another tag → full response.
    let other = get_jwks(&app, Some("\"0000\"")).await;
    assert_eq!(other.status, 200);
    assert_eq!(other.body, first.body);

    // Publishing a next key changes the set and its tag; the old tag no longer matches.
    let tenant = default(&app);
    rotation(&app)
        .rotate_now(&tenant, Alg::RS256, false, AuditActor::system())
        .await
        .expect("rotate");
    let after = get_jwks(&app, Some(&etag)).await;
    assert_eq!(after.status, 200);
    assert_ne!(after.header("etag"), Some(etag.as_str()));
    assert_eq!(json(&after)["keys"].as_array().expect("keys").len(), 2);
}

#[tokio::test]
async fn full_rotation_cycle_over_a_fake_clock() {
    let app = TestApp::new().await;
    let tenant = default(&app);
    let policy = RotationPolicy::default();
    let original = active_kid(&app, tenant.id, Alg::RS256).await;

    // Installed tenants already have their RS256 key; nothing is due yet.
    assert_eq!(
        rotation(&app).ensure_tenant(&tenant).await.expect("ensure"),
        0
    );
    let report = rotation(&app).run_once().await.expect("run");
    assert_eq!(
        (report.tenants, report.generated, report.promoted),
        (2, 0, 0)
    );
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(jwks_kids(&app).await, vec![original.clone()]);

    // period − prepublish: a next key is published (both tenants), signing key unchanged.
    advance(&app, policy.period() - policy.prepublish());
    let published_at = app.clock_now();
    let report = rotation(&app).run_once().await.expect("run");
    assert_eq!((report.generated, report.promoted), (2, 0));
    let kids = jwks_kids(&app).await;
    assert_eq!(kids.len(), 2);
    assert!(kids.contains(&original));
    let next = kids.iter().find(|k| **k != original).expect("next").clone();
    assert_eq!(active_kid(&app, tenant.id, Alg::RS256).await, original);

    // A run before prepublish has elapsed changes nothing.
    advance(&app, policy.prepublish() - Duration::hours(1));
    let report = rotation(&app).run_once().await.expect("run");
    assert_eq!(
        (report.generated, report.promoted, report.deleted),
        (0, 0, 0)
    );
    assert_eq!(active_kid(&app, tenant.id, Alg::RS256).await, original);

    // + prepublish: the next key is promoted; it has been in the JWKS for ≥ one cache lifetime.
    advance(&app, Duration::hours(1));
    let report = rotation(&app).run_once().await.expect("run");
    assert_eq!((report.generated, report.promoted), (0, 2));
    assert_eq!(active_kid(&app, tenant.id, Alg::RS256).await, next);
    assert!(app.clock_now() - published_at >= JWKS_MAX_AGE);
    assert!(app.clock_now() - published_at >= policy.prepublish());
    // The retired key is still published for tokens it signed.
    let kids = jwks_kids(&app).await;
    assert_eq!(kids.len(), 2);
    assert!(kids.contains(&original) && kids.contains(&next));

    // Tokens are now signed by the promoted key and verify against /jwks.
    let (_, body) = tokens(&app, "openid").await;
    let id_token = body["id_token"].as_str().expect("id_token");
    assert_eq!(jwt_header(id_token)["kid"], next.as_str());
    let jwks: anvil_jose::Jwks =
        serde_json::from_slice(&app.get("/jwks").await.body).expect("jwks");
    verify_jwt(id_token, &jwks, &[Alg::RS256]).expect("verifies against /jwks");

    // The retired key stays until max token lifetime + skew (1 h 5 min) after retirement.
    advance(
        &app,
        Duration::hours(1) + Duration::minutes(5) - Duration::seconds(1),
    );
    let report = rotation(&app).run_once().await.expect("run");
    assert_eq!(report.deleted, 0);
    assert_eq!(jwks_kids(&app).await.len(), 2);
    advance(&app, Duration::seconds(1));
    let report = rotation(&app).run_once().await.expect("run");
    assert_eq!(report.deleted, 2, "one retired key per tenant");
    assert_eq!(jwks_kids(&app).await, vec![next.clone()]);
    let rows = app.storage().keys().list(tenant.id).await.expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, KeyState::Active);

    // Every step was audited with the system actor.
    let events = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit");
    let of = |action: AuditAction| {
        events
            .items
            .iter()
            .filter(|e| e.action == action)
            .collect::<Vec<_>>()
    };
    let generated = of(AuditAction::KeyGenerated);
    let retired = of(AuditAction::KeyRetired);
    let activated = of(AuditAction::KeyActivated);
    assert_eq!(generated.len(), 1);
    assert_eq!(generated[0].target.as_deref(), Some(next.as_str()));
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].target.as_deref(), Some(original.as_str()));
    assert_eq!(activated.len(), 1);
    assert_eq!(activated[0].target.as_deref(), Some(next.as_str()));
    for e in generated.iter().chain(&retired).chain(&activated) {
        assert_eq!(e.actor.kind, ActorKind::System);
    }
}

async fn enable_algs(app: &TestApp, tenant: &Tenant, algs: &[&str]) -> Tenant {
    app.storage()
        .tenants()
        .update(
            tenant.id,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    signing_algs: algs.iter().map(|a| (*a).to_owned()).collect(),
                    ..tenant.settings.clone()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("update")
        .expect("tenant exists")
}

#[tokio::test]
async fn ensure_tenant_generates_keys_for_newly_enabled_algs_once() {
    let app = TestApp::new().await;
    let tenant = enable_algs(&app, &default(&app), &["RS256", "ES256", "Ed25519"]).await;
    let svc = rotation(&app);
    // Concurrent ensures: the active-key index lets exactly one key per alg through.
    let (a, b) = tokio::join!(svc.ensure_tenant(&tenant), svc.ensure_tenant(&tenant));
    assert_eq!(a.expect("ensure") + b.expect("ensure"), 2);
    assert_eq!(svc.ensure_tenant(&tenant).await.expect("ensure"), 0);

    let rows = app.storage().keys().list(tenant.id).await.expect("list");
    for alg in ["RS256", "ES256", "Ed25519"] {
        let active = rows
            .iter()
            .filter(|k| k.alg == alg && k.state == KeyState::Active)
            .count();
        assert_eq!(active, 1, "{alg}");
    }
    let resp = app.get("/jwks").await;
    let kty: Vec<String> = json(&resp)["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|k| k["kty"].as_str().expect("kty").to_owned())
        .collect();
    assert!(
        kty.contains(&"RSA".into()) && kty.contains(&"EC".into()) && kty.contains(&"OKP".into())
    );
}

#[tokio::test]
async fn concurrent_runs_promote_exactly_once() {
    let app = TestApp::new().await;
    let tenant = default(&app);
    let policy = RotationPolicy::default();
    advance(&app, policy.period() - policy.prepublish());
    rotation(&app).run_once().await.expect("publish next");
    advance(&app, policy.prepublish());

    let svc = rotation(&app);
    let (a, b) = tokio::join!(svc.run_once(), svc.run_once());
    let (a, b) = (a.expect("run"), b.expect("run"));
    assert!(a.failures.is_empty() && b.failures.is_empty());
    assert_eq!(a.promoted + b.promoted, 2, "one promotion per tenant");
    let rows = app.storage().keys().list(tenant.id).await.expect("list");
    assert_eq!(
        rows.iter().filter(|k| k.state == KeyState::Active).count(),
        1
    );
    assert_eq!(
        rows.iter().filter(|k| k.state == KeyState::Retired).count(),
        1
    );
}

#[tokio::test]
async fn immediate_rotation_drops_the_old_key_from_jwks_at_once() {
    let app = TestApp::new().await;
    let tenant = default(&app);
    let original = active_kid(&app, tenant.id, Alg::RS256).await;

    let kid = rotation(&app)
        .rotate_now(&tenant, Alg::RS256, true, AuditActor::admin("ops"))
        .await
        .expect("rotate");
    assert_ne!(kid, original);
    assert_eq!(active_kid(&app, tenant.id, Alg::RS256).await, kid);
    assert_eq!(jwks_kids(&app).await, vec![kid.clone()]);

    let events = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::KeyRotationRequested),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit");
    assert_eq!(events.items.len(), 1);
    assert_eq!(events.items[0].actor.kind, ActorKind::Admin);
    assert_eq!(events.items[0].target.as_deref(), Some(original.as_str()));

    // The retired key is deleted by the next run (expires_at = retirement time).
    let report = rotation(&app).run_once().await.expect("run");
    assert_eq!(report.deleted, 1);
}

#[tokio::test]
async fn scheduled_rotate_now_keeps_signing_until_promotion() {
    let app = TestApp::new().await;
    let tenant = default(&app);
    let original = active_kid(&app, tenant.id, Alg::RS256).await;
    let svc = rotation(&app);
    let next = svc
        .rotate_now(&tenant, Alg::RS256, false, AuditActor::system())
        .await
        .expect("rotate");
    // Idempotent while a next key exists.
    assert_eq!(
        svc.rotate_now(&tenant, Alg::RS256, false, AuditActor::system())
            .await
            .expect("rotate"),
        next
    );
    assert_eq!(active_kid(&app, tenant.id, Alg::RS256).await, original);
    assert_eq!(jwks_kids(&app).await.len(), 2);
}

#[tokio::test]
async fn rotate_now_rejects_an_alg_the_tenant_has_not_enabled() {
    let app = TestApp::new().await;
    let tenant = default(&app);
    let err = rotation(&app)
        .rotate_now(&tenant, Alg::ES256, true, AuditActor::system())
        .await
        .expect_err("not enabled");
    assert!(matches!(err, CoreError::Validation { field: "alg", .. }));
    assert_eq!(
        app.storage()
            .keys()
            .list(tenant.id)
            .await
            .expect("list")
            .len(),
        1
    );
}

/// The signer cache (05-18) never outlives a rotation: tokens from `POST /token` carry the active
/// kid before, and the new kid on the very first request after an immediate rotation; once the
/// retired key is deleted, tokens still verify against the published set.
#[tokio::test]
async fn token_endpoint_signs_with_the_new_key_right_after_immediate_rotation() {
    use anvil_core::model::ClientAuthMethod;

    let app = TestApp::new().await;
    let tenant = default(&app);
    let rp = register(
        &app,
        tenant.id,
        cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let kid_of_new_token = || async {
        let resp = token(&app, &rp.auth(), &[("grant_type", "client_credentials")]).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        let at = json(&resp)["access_token"]
            .as_str()
            .expect("access_token")
            .to_owned();
        let jwks = published(&app, tenant.id).await;
        verify_jwt(&at, &jwks, &[Alg::RS256]).expect("token verifies against the JWKS");
        jwt_header(&at)["kid"].as_str().expect("kid").to_owned()
    };

    let original = active_kid(&app, tenant.id, Alg::RS256).await;
    assert_eq!(kid_of_new_token().await, original);
    assert_eq!(kid_of_new_token().await, original);

    let rotated = rotation(&app)
        .rotate_now(&tenant, Alg::RS256, true, AuditActor::admin("ops"))
        .await
        .expect("rotate");
    assert_ne!(rotated, original);
    assert_eq!(kid_of_new_token().await, rotated);

    // The retired key row is deleted by the next run; signing is unaffected.
    assert_eq!(rotation(&app).run_once().await.expect("run").deleted, 1);
    assert_eq!(kid_of_new_token().await, rotated);
    assert_eq!(jwks_kids(&app).await, vec![rotated.clone()]);

    // A second immediate rotation is picked up just as fast.
    let again = rotation(&app)
        .rotate_now(&tenant, Alg::RS256, true, AuditActor::admin("ops"))
        .await
        .expect("rotate");
    assert_ne!(again, rotated);
    assert_eq!(kid_of_new_token().await, again);
}
