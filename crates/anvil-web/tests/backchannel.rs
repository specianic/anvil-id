//! Back-channel logout delivery (OIDC-12, OpenID Connect Back-Channel Logout 1.0) against a
//! wiremock RP on 127.0.0.1, on the selected backend (`ANVILID_TEST_DB`): an RP-initiated logout
//! enqueues a delivery and the worker POSTs exactly one form body holding only `logout_token`,
//! whose token verifies against the tenant JWKS with the client's ID-token algorithm, has
//! `typ: logout+jwt` and exactly the spec claims (`sid` = the ID token's `sid`, no `nonce`);
//! 204 delivers; 400 gives up after one attempt with an audit row; 500 retries with backoff and
//! gives up (audited) at the 24 h deadline; a blocked destination and a removed URI give up;
//! the URI's query string is preserved; session revocation by the user/admin intents and user
//! deletion deliver too; the wake runs the worker without waiting for the poll.

mod logout_support;
mod support;
mod token_support;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::{AuditAction, ClientUpdate, LogoutDelivery, TenantSettings, TenantUpdate};
use anvil_core::ports::Clock;
use anvil_core::service::key_rotation::{KeyRotationService, RotationPolicy};
use anvil_jose::keys::Alg;
use anvil_jose::{ExpiryCheck, verify_op_token_algs};
use anvil_web::adapters::backchannel::{LogoutDeliveryWorker, RunReport};
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use logout_support::*;
use serde_json::Value;
use time::OffsetDateTime;
use token_support::{CHALLENGE, issue_code, params, published};
use tokio::sync::Notify;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The app's test clock, shared with the worker (the fixture lives for the whole test).
struct AppClock(&'static Fx);

impl Clock for AppClock {
    fn now(&self) -> OffsetDateTime {
        self.0.app.clock().now()
    }
}

/// The fixture, leaked so the worker can hold its clock.
async fn leaked() -> &'static Fx {
    Box::leak(Box::new(fixture().await))
}

fn worker_with(f: &'static Fx, policy: &OutboundPolicy, wake: Arc<Notify>) -> LogoutDeliveryWorker {
    LogoutDeliveryWorker::new(
        f.app.storage_arc(),
        Arc::new(AppClock(f)),
        f.app.kek_arc(),
        f.app.config.public_url.clone(),
        Arc::new(OutboundClient::new(policy).expect("outbound client")),
        wake,
    )
}

/// A worker allowed to reach the loopback RP over plain http (development policy).
fn worker(f: &'static Fx) -> LogoutDeliveryWorker {
    worker_with(f, &OutboundPolicy::loopback_dev(), Arc::new(Notify::new()))
}

/// Points the fixture client's back-channel logout URI at `uri` (`None` removes it).
async fn set_uri(f: &Fx, uri: Option<String>) {
    f.app
        .storage()
        .clients()
        .update(
            f.tenant.id,
            f.rp.id(),
            &ClientUpdate {
                backchannel_logout_uri: Some(uri),
                ..ClientUpdate::default()
            },
            f.app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
}

/// A mock RP answering `status` on `POST /bc`.
async fn rp_answering(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bc"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

/// Signs in to the RP (records the RP session), then logs out through `/logout` with the ID
/// token as hint. Returns the ID token.
async fn sign_in_and_log_out(f: &Fx) -> String {
    let id_token = f.id_token().await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", BYE),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(f.deliveries().await, 1, "one delivery enqueued");
    id_token
}

async fn rows(f: &Fx) -> Vec<LogoutDelivery> {
    f.app
        .storage()
        .logout()
        .deliveries_for_client(f.tenant.id, f.rp.id())
        .await
        .expect("deliveries")
}

async fn received(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.expect("recording on")
}

fn jwt_part(token: &str, i: usize) -> Value {
    let part = token.split('.').nth(i).expect("jwt part");
    serde_json::from_slice(&anvil_jose::encoding::b64url_decode(part).expect("b64")).expect("json")
}

/// The body's form pairs.
fn form(req: &wiremock::Request) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&req.body)
        .into_owned()
        .collect()
}

/// Asserts the give-up audit row: system actor, the delivery as target, fixed details.
async fn assert_failed_audit(f: &Fx, attempts: u32, reason: &str) {
    let events = f.audit(AuditAction::BackchannelLogoutFailed).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    let row = &rows(f).await[0];
    assert_eq!(e.target.as_deref(), Some(row.id.to_string().as_str()));
    let details = Value::Object(e.details.as_map().clone());
    assert_eq!(
        details,
        serde_json::json!({ "client_id": f.rp.id(), "attempts": attempts, "reason": reason })
    );
}

#[tokio::test]
async fn logout_delivers_only_a_spec_logout_token_and_204_marks_delivered() {
    let f = leaked().await;
    let server = rp_answering(204).await;
    set_uri(f, Some(format!("{}/bc?tenant=a&x=1", server.uri()))).await;
    let id_token = sign_in_and_log_out(f).await;

    let report = worker(f).run_once().await.expect("run");
    assert_eq!(
        report,
        RunReport {
            claimed: 1,
            delivered: 1,
            ..RunReport::default()
        }
    );
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 1, "exactly one POST");
    let req = &reqs[0];
    // The registered query string is preserved.
    assert_eq!(req.url.query(), Some("tenant=a&x=1"));
    assert_eq!(
        req.headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/x-www-form-urlencoded")
    );
    let pairs = form(req);
    assert_eq!(pairs.len(), 1, "only logout_token: {pairs:?}");
    assert_eq!(pairs[0].0, "logout_token");
    let token = &pairs[0].1;

    let jwks = published(&f.app, f.tenant.id).await;
    let jwt = verify_op_token_algs(
        token,
        &jwks,
        &[Alg::RS256],
        &f.iss,
        Some("logout+jwt"),
        ExpiryCheck::Enforce,
        f.app.clock().now(),
    )
    .expect("logout token verifies against the tenant JWKS");
    assert_eq!(jwt.header.typ.as_deref(), Some("logout+jwt"));
    let claims = &jwt.claims;
    let mut names: Vec<&str> = claims.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["aud", "events", "exp", "iat", "iss", "jti", "sid", "sub"]
    );
    let id_claims = jwt_part(&id_token, 1);
    assert_eq!(claims["sid"], id_claims["sid"], "sid = the ID token's sid");
    assert_eq!(claims["sid"], f.session.id.to_string());
    assert_eq!(claims["sub"], id_claims["sub"]);
    assert_eq!(claims["aud"], f.rp.id());
    assert_eq!(claims["iss"], f.iss.as_str());
    let iat = claims["iat"].as_i64().expect("iat");
    assert_eq!(claims["exp"].as_i64().expect("exp") - iat, 120);
    assert_eq!(
        claims["events"],
        serde_json::json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
    );
    assert!(claims.get("nonce").is_none());

    let row = &rows(f).await[0];
    assert!(row.delivered_at.is_some());
    // Delivered rows are never claimed again.
    assert_eq!(worker(f).run_once().await.expect("run").claimed, 0);
    assert_eq!(received(&server).await.len(), 1);
    assert!(
        f.audit(AuditAction::BackchannelLogoutFailed)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn token_is_signed_with_the_clients_id_token_alg() {
    let f = leaked().await;
    let tenant = f
        .app
        .storage()
        .tenants()
        .update(
            f.tenant.id,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    signing_algs: vec!["RS256".into(), "ES256".into()],
                    ..f.tenant.settings.clone()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");
    KeyRotationService {
        storage: f.app.storage_arc(),
        kek: f.app.kek_arc(),
        clock: Arc::new(AppClock(f)),
        policy: RotationPolicy::default(),
    }
    .ensure_tenant(&tenant)
    .await
    .expect("ES256 key");
    f.app
        .storage()
        .clients()
        .update(
            f.tenant.id,
            f.rp.id(),
            &ClientUpdate {
                id_token_signed_response_alg: Some(Some("ES256".into())),
                ..ClientUpdate::default()
            },
            f.app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    let server = rp_answering(200).await;
    set_uri(f, Some(format!("{}/bc", server.uri()))).await;
    sign_in_and_log_out(f).await;

    assert_eq!(worker(f).run_once().await.expect("run").delivered, 1);
    let reqs = received(&server).await;
    let token = &form(&reqs[0])[0].1;
    assert_eq!(jwt_part(token, 0)["alg"], "ES256");
    let jwks = published(&f.app, f.tenant.id).await;
    verify_op_token_algs(
        token,
        &jwks,
        &[Alg::ES256],
        &f.iss,
        Some("logout+jwt"),
        ExpiryCheck::Enforce,
        f.app.clock().now(),
    )
    .expect("ES256 logout token verifies");
}

#[tokio::test]
async fn status_400_gives_up_after_one_attempt_and_is_audited_without_token() {
    let f = leaked().await;
    let server = rp_answering(400).await;
    set_uri(f, Some(format!("{}/bc", server.uri()))).await;
    sign_in_and_log_out(f).await;

    let report = worker(f).run_once().await.expect("run");
    assert_eq!(report.given_up, 1);
    let row = &rows(f).await[0];
    assert_eq!(row.attempts, 1);
    assert!(row.delivered_at.is_none());
    assert_eq!(row.last_error.as_deref(), Some("status 400"));
    assert_failed_audit(f, 1, "status").await;
    // Not retried, even much later.
    f.app.clock().advance(Duration::from_secs(3600));
    assert_eq!(worker(f).run_once().await.expect("run").claimed, 0);
    assert_eq!(received(&server).await.len(), 1);
}

#[tokio::test]
async fn status_500_retries_with_backoff_and_gives_up_at_the_deadline() {
    let f = leaked().await;
    let server = rp_answering(500).await;
    set_uri(f, Some(format!("{}/bc", server.uri()))).await;
    sign_in_and_log_out(f).await;
    let created = rows(f).await[0].created_at;

    let w = worker(f);
    assert_eq!(w.run_once().await.expect("run").retried, 1);
    let row = &rows(f).await[0];
    assert_eq!(row.attempts, 1);
    assert_eq!(
        row.next_attempt_at,
        f.app.clock().now() + time::Duration::seconds(10)
    );
    // Not due yet.
    assert_eq!(w.run_once().await.expect("run").claimed, 0);
    f.app.clock().advance(Duration::from_secs(10));
    assert_eq!(w.run_once().await.expect("run").retried, 1);
    assert_eq!(received(&server).await.len(), 2);
    let row = &rows(f).await[0];
    assert_eq!(row.attempts, 2);
    assert_eq!(
        row.next_attempt_at,
        f.app.clock().now() + time::Duration::seconds(20)
    );
    assert!(
        f.audit(AuditAction::BackchannelLogoutFailed)
            .await
            .is_empty()
    );

    // The last attempt before the 24 h deadline gives up (a retry would never be claimed).
    f.app
        .clock()
        .set(created + time::Duration::hours(24) - time::Duration::seconds(5));
    assert_eq!(w.run_once().await.expect("run").given_up, 1);
    assert_eq!(received(&server).await.len(), 3);
    assert_failed_audit(f, 3, "expired").await;
    f.app.clock().advance(Duration::from_secs(3600));
    assert_eq!(w.run_once().await.expect("run").claimed, 0);
}

#[tokio::test]
async fn blocked_destination_gives_up_without_a_request() {
    let f = leaked().await;
    let server = rp_answering(204).await;
    // Production policy: loopback is a blocked destination, even over https.
    let port = server.address().port();
    set_uri(f, Some(format!("https://127.0.0.1:{port}/bc"))).await;
    sign_in_and_log_out(f).await;

    let w = worker_with(f, &OutboundPolicy::default(), Arc::new(Notify::new()));
    assert_eq!(w.run_once().await.expect("run").given_up, 1);
    assert!(received(&server).await.is_empty(), "nothing was sent");
    assert_failed_audit(f, 1, "blocked").await;
}

#[tokio::test]
async fn removed_uri_gives_up() {
    let f = leaked().await;
    let server = rp_answering(204).await;
    set_uri(f, Some(format!("{}/bc", server.uri()))).await;
    sign_in_and_log_out(f).await;
    set_uri(f, None).await;

    assert_eq!(worker(f).run_once().await.expect("run").given_up, 1);
    assert!(received(&server).await.is_empty());
    assert_failed_audit(f, 1, "client_removed").await;
}

#[tokio::test]
async fn session_revocation_intents_and_user_deletion_deliver() {
    let f = leaked().await;
    let server = rp_answering(204).await;
    set_uri(f, Some(format!("{}/bc", server.uri()))).await;
    let storage = f.app.storage();

    // "Sign out everywhere" / admin revoke: revoke_all_for_user.
    f.id_token().await;
    let n = storage
        .sessions()
        .revoke_all_for_user(f.tenant.id, f.user.id, None, f.app.clock().now())
        .await
        .expect("revoke all");
    assert_eq!(n, 1);
    assert_eq!(worker(f).run_once().await.expect("run").delivered, 1);

    // User deletion: a new session signed in to the RP, then the user is deleted.
    let (session, _) = session_for(&f.app, &f.tenant, &f.user).await;
    issue_code(
        &f.app,
        f.tenant.id,
        &f.rp,
        &session,
        &params("openid", Some(CHALLENGE)),
    )
    .await;
    assert!(
        storage
            .users()
            .delete(f.tenant.id, f.user.id)
            .await
            .expect("delete")
    );
    // UserRepo::delete enqueues on the storage (wall) clock: run the worker no earlier.
    let wall = OffsetDateTime::now_utc() + time::Duration::seconds(1);
    if wall > f.app.clock().now() {
        f.app.clock().set(wall);
    }
    assert_eq!(worker(f).run_once().await.expect("run").delivered, 1);

    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 2);
    let sids: Vec<Value> = reqs
        .iter()
        .map(|r| jwt_part(&form(r)[0].1, 1)["sid"].clone())
        .collect();
    assert_eq!(
        sids,
        [
            Value::from(f.session.id.to_string()),
            Value::from(session.id.to_string())
        ]
    );
}

#[tokio::test]
async fn wake_runs_the_worker_without_waiting_for_the_poll() {
    let f = leaked().await;
    let server = rp_answering(204).await;
    set_uri(f, Some(format!("{}/bc", server.uri()))).await;
    let wake = Arc::new(Notify::new());
    let mut w = worker_with(f, &OutboundPolicy::loopback_dev(), Arc::clone(&wake));
    w.poll = Duration::from_secs(3600);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(w.run(async {
        let _ = stop_rx.await;
    }));
    // Let the first (empty) batch run so the worker is waiting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    sign_in_and_log_out(f).await;
    wake.notify_one();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received(&server).await.is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "not delivered after the wake"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop_tx.send(()).expect("worker running");
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("worker stops on shutdown")
        .expect("worker task");
}
