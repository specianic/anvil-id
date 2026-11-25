//! LogoutRepo contract: RP sessions recorded by `create_code`, back-channel logout deliveries
//! enqueued by every revoking intent (in the same transaction), and the leased delivery queue.

use std::collections::HashSet;

use anvil_core::model::{
    Client, DeliveryResult, LOGOUT_DELIVERY_TTL, LogoutDelivery, LogoutDeliveryId,
    NewAuthorizationCode, NewBrowserSession, SelfServiceKind, TenantId, User,
};
use time::{Duration, OffsetDateTime};

use super::TestStorage;
use super::fixtures::*;

const BC_URI: &str = "https://rp.example.test/backchannel";

/// A user with one session signed in to a back-channel client and to a plain client.
struct LogoutCtx {
    tenant: TenantId,
    user: User,
    session: NewBrowserSession,
    bc: Client,
    plain: Client,
}

async fn seed_logout_ctx(s: &TestStorage) -> LogoutCtx {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let session = seed_session(s, tenant, user.id).await;
    let bc = seed_backchannel_client(s, tenant, BC_URI).await;
    let plain = seed_client(s, tenant).await;
    sign_in_to_rp(s, tenant, &user, &session, &bc).await;
    sign_in_to_rp(s, tenant, &user, &session, &plain).await;
    LogoutCtx {
        tenant,
        user,
        session,
        bc,
        plain,
    }
}

/// Checks one freshly enqueued delivery. `now = None` when the intent uses the storage clock.
fn assert_fresh_delivery(
    d: &LogoutDelivery,
    ctx: &LogoutCtx,
    session: &NewBrowserSession,
    now: Option<OffsetDateTime>,
) {
    assert_eq!(d.tenant_id, ctx.tenant);
    assert_eq!(d.client_id, ctx.bc.client_id);
    assert_eq!(d.uri, BC_URI, "the uri is copied from the client");
    assert_eq!(d.sub, ctx.user.id.to_string(), "sub is the user id");
    assert_eq!(
        d.sid,
        session.id.to_string(),
        "sid is the browser session id"
    );
    assert_eq!(
        d.issuer.as_deref(),
        Some(TEST_ISSUER),
        "the issuer is copied from the RP session"
    );
    assert_eq!(d.attempts, 0);
    assert_eq!(d.delivered_at, None);
    assert_eq!(d.last_error, None);
    assert_eq!(d.give_up_at - d.next_attempt_at, LOGOUT_DELIVERY_TTL);
    if let Some(now) = now {
        assert_eq!(d.next_attempt_at, now);
        assert_eq!(d.give_up_at, now + LOGOUT_DELIVERY_TTL);
    }
}

async fn assert_no_plain_deliveries(s: &TestStorage, ctx: &LogoutCtx) {
    assert!(
        deliveries(s, ctx.tenant, &ctx.plain.client_id)
            .await
            .is_empty(),
        "an RP without backchannel_logout_uri gets no delivery"
    );
}

pub async fn create_code_records_rp_session_once(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    let other = seed_tenant(s).await;
    // A second code for the same session and client adds no row.
    sign_in_to_rp(s, ctx.tenant, &ctx.user, &ctx.session, &ctx.bc).await;
    let rps = s
        .storage
        .logout()
        .rp_sessions(ctx.tenant, ctx.session.id)
        .await
        .expect("rp_sessions");
    let mut want = vec![ctx.bc.client_id.clone(), ctx.plain.client_id.clone()];
    want.sort();
    assert_eq!(
        rps.iter().map(|r| r.client_id.clone()).collect::<Vec<_>>(),
        want,
        "one RP session per (session, client), in client id order"
    );
    for r in &rps {
        assert_eq!(r.tenant_id, ctx.tenant);
        assert_eq!(r.session_id, ctx.session.id);
    }
    assert!(
        s.storage
            .logout()
            .rp_sessions(other, ctx.session.id)
            .await
            .expect("rp_sessions")
            .is_empty(),
        "RP sessions are tenant-scoped"
    );
    assert!(
        deliveries(s, ctx.tenant, &ctx.bc.client_id)
            .await
            .is_empty(),
        "signing in enqueues nothing"
    );
}

pub async fn rp_session_records_issuer_and_deliveries_copy_it(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    let grants = s.storage.grants();
    let gctx = GrantCtx {
        tenant: ctx.tenant,
        user: ctx.user.clone(),
        client: ctx.bc.clone(),
        session: ctx.session.clone(),
    };
    let issued_with = |issuer: &str| {
        let family = new_family(&gctx, Duration::days(30));
        let code = NewAuthorizationCode {
            issuer: issuer.to_owned(),
            ..new_code(&gctx, &family, Duration::minutes(5))
        };
        (code, family)
    };
    let bc_issuer = |rps: &[anvil_core::model::RpSession]| {
        rps.iter()
            .find(|r| r.client_id == ctx.bc.client_id)
            .expect("bc rp session")
            .issuer
            .clone()
    };

    let (code, family) = issued_with("https://a.example.test/t/acme");
    grants
        .create_code(ctx.tenant, &code, &family)
        .await
        .expect("create_code");
    let rps = s
        .storage
        .logout()
        .rp_sessions(ctx.tenant, ctx.session.id)
        .await
        .expect("rp_sessions");
    assert_eq!(
        bc_issuer(&rps).as_deref(),
        Some("https://a.example.test/t/acme"),
        "create_code records the code's issuer"
    );
    let plain = rps
        .iter()
        .find(|r| r.client_id == ctx.plain.client_id)
        .expect("plain rp session");
    assert_eq!(
        plain.issuer.as_deref(),
        Some(TEST_ISSUER),
        "another client's RP session keeps its own issuer"
    );

    // The latest code for the same session and client wins.
    let (code, family) = issued_with("https://login.acme.test");
    grants
        .create_code(ctx.tenant, &code, &family)
        .await
        .expect("create_code");
    let rps = s
        .storage
        .logout()
        .rp_sessions(ctx.tenant, ctx.session.id)
        .await
        .expect("rp_sessions");
    assert_eq!(rps.len(), 2, "still one row per (session, client)");
    assert_eq!(bc_issuer(&rps).as_deref(), Some("https://login.acme.test"));

    let now = now_ms();
    assert!(
        s.storage
            .sessions()
            .revoke_with_families(ctx.tenant, ctx.session.id, now)
            .await
            .expect("revoke_with_families")
    );
    let d = deliveries(s, ctx.tenant, &ctx.bc.client_id).await;
    assert_eq!(d.len(), 1);
    assert_eq!(
        d[0].issuer.as_deref(),
        Some("https://login.acme.test"),
        "the delivery copies the RP session's issuer"
    );
    let claimed = s
        .storage
        .logout()
        .claim_due_deliveries(now + Duration::minutes(1), now, 10)
        .await
        .expect("claim");
    let mine = claimed
        .iter()
        .find(|c| c.id == d[0].id)
        .expect("the delivery is due");
    assert_eq!(
        mine.issuer.as_deref(),
        Some("https://login.acme.test"),
        "claimed deliveries carry the issuer"
    );
}

pub async fn revoke_enqueues_backchannel_delivery(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    let now = now_ms();
    assert!(
        s.storage
            .sessions()
            .revoke(ctx.tenant, ctx.session.id, now)
            .await
            .expect("revoke")
    );
    let d = deliveries(s, ctx.tenant, &ctx.bc.client_id).await;
    assert_eq!(d.len(), 1, "exactly one delivery per back-channel RP");
    assert_fresh_delivery(&d[0], &ctx, &ctx.session, Some(now));
    assert_no_plain_deliveries(s, &ctx).await;
}

pub async fn revoke_with_families_enqueues_backchannel_delivery(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    let now = now_ms();
    assert!(
        s.storage
            .sessions()
            .revoke_with_families(ctx.tenant, ctx.session.id, now)
            .await
            .expect("revoke_with_families")
    );
    let d = deliveries(s, ctx.tenant, &ctx.bc.client_id).await;
    assert_eq!(d.len(), 1);
    assert_fresh_delivery(&d[0], &ctx, &ctx.session, Some(now));
    assert_no_plain_deliveries(s, &ctx).await;
}

pub async fn revoke_all_for_user_enqueues_backchannel_delivery(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    let second = seed_session(s, ctx.tenant, ctx.user.id).await;
    let kept = seed_session(s, ctx.tenant, ctx.user.id).await;
    sign_in_to_rp(s, ctx.tenant, &ctx.user, &second, &ctx.bc).await;
    sign_in_to_rp(s, ctx.tenant, &ctx.user, &kept, &ctx.bc).await;
    let now = now_ms();
    assert_eq!(
        s.storage
            .sessions()
            .revoke_all_for_user(ctx.tenant, ctx.user.id, Some(kept.id), now)
            .await
            .expect("revoke_all_for_user"),
        2
    );
    let d = deliveries(s, ctx.tenant, &ctx.bc.client_id).await;
    assert_eq!(d.len(), 2, "one delivery per revoked session");
    let mut sessions = [&ctx.session, &second];
    sessions.sort_by_key(|x| x.id.to_string());
    for (delivery, session) in d.iter().zip(sessions) {
        assert_fresh_delivery(delivery, &ctx, session, Some(now));
    }
    assert!(
        d.iter().all(|x| x.sid != kept.id.to_string()),
        "the kept session is not logged out"
    );
    assert_no_plain_deliveries(s, &ctx).await;
}

pub async fn complete_recovery_enqueues_backchannel_delivery(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    let token = new_self_service_token(
        SelfServiceKind::Recovery,
        ctx.user.id,
        &ctx.user.email,
        Duration::hours(1),
    );
    s.storage
        .users()
        .issue_self_service_token(ctx.tenant, &token, None)
        .await
        .expect("issue");
    let now = now_ms();
    s.storage
        .users()
        .complete_recovery(ctx.tenant, &token.token_hash, "$argon2id$new", now, None)
        .await
        .expect("complete_recovery")
        .expect("recovered");
    let d = deliveries(s, ctx.tenant, &ctx.bc.client_id).await;
    assert_eq!(d.len(), 1);
    assert_fresh_delivery(&d[0], &ctx, &ctx.session, Some(now));
    assert_no_plain_deliveries(s, &ctx).await;
}

pub async fn user_delete_enqueues_backchannel_delivery(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    assert!(
        s.storage
            .users()
            .delete(ctx.tenant, ctx.user.id)
            .await
            .expect("delete")
    );
    let d = deliveries(s, ctx.tenant, &ctx.bc.client_id).await;
    assert_eq!(d.len(), 1, "deleting a user logs out its sessions");
    assert_fresh_delivery(&d[0], &ctx, &ctx.session, None);
    assert_no_plain_deliveries(s, &ctx).await;
}

pub async fn revoke_noop_enqueues_nothing(s: &TestStorage) {
    let ctx = seed_logout_ctx(s).await;
    let sessions = s.storage.sessions();
    assert!(
        sessions
            .revoke(ctx.tenant, ctx.session.id, now_ms())
            .await
            .expect("revoke")
    );
    assert_eq!(deliveries(s, ctx.tenant, &ctx.bc.client_id).await.len(), 1);

    // Every revoking intent on an already revoked session changes nothing and enqueues nothing.
    assert!(
        !sessions
            .revoke(ctx.tenant, ctx.session.id, now_ms())
            .await
            .expect("revoke")
    );
    assert!(
        !sessions
            .revoke_with_families(ctx.tenant, ctx.session.id, now_ms())
            .await
            .expect("revoke_with_families")
    );
    assert_eq!(
        sessions
            .revoke_all_for_user(ctx.tenant, ctx.user.id, None, now_ms())
            .await
            .expect("revoke_all_for_user"),
        0
    );
    let token = new_self_service_token(
        SelfServiceKind::Recovery,
        ctx.user.id,
        &ctx.user.email,
        Duration::hours(1),
    );
    s.storage
        .users()
        .issue_self_service_token(ctx.tenant, &token, None)
        .await
        .expect("issue");
    s.storage
        .users()
        .complete_recovery(ctx.tenant, &token.token_hash, "$x", now_ms(), None)
        .await
        .expect("complete_recovery")
        .expect("recovered");
    assert_eq!(
        deliveries(s, ctx.tenant, &ctx.bc.client_id).await.len(),
        1,
        "nothing is enqueued when no session is revoked"
    );
    // Unknown session: nothing.
    assert!(
        !sessions
            .revoke(ctx.tenant, anvil_core::model::SessionId::new_v7(), now_ms())
            .await
            .expect("revoke")
    );
    assert_eq!(deliveries(s, ctx.tenant, &ctx.bc.client_id).await.len(), 1);
}

/// `n` sessions of one user signed in to the back-channel client, all revoked at `now`.
async fn seed_due_deliveries(s: &TestStorage, n: usize, now: OffsetDateTime) -> LogoutCtx {
    let ctx = seed_logout_ctx(s).await;
    for _ in 1..n {
        let session = seed_session(s, ctx.tenant, ctx.user.id).await;
        sign_in_to_rp(s, ctx.tenant, &ctx.user, &session, &ctx.bc).await;
    }
    let revoked = s
        .storage
        .sessions()
        .revoke_all_for_user(ctx.tenant, ctx.user.id, None, now)
        .await
        .expect("revoke_all_for_user");
    assert_eq!(revoked, n as u64);
    assert_eq!(deliveries(s, ctx.tenant, &ctx.bc.client_id).await.len(), n);
    ctx
}

pub async fn delivery_claim_leases_due_rows(s: &TestStorage) {
    let now = now_ms();
    let ctx = seed_due_deliveries(s, 3, now).await;
    let repo = s.storage.logout();
    let lease = now + Duration::seconds(60);

    assert!(
        repo.claim_due_deliveries(lease, now - Duration::seconds(1), 10)
            .await
            .expect("claim")
            .is_empty(),
        "rows are not due before next_attempt_at"
    );
    let first = repo
        .claim_due_deliveries(lease, now, 2)
        .await
        .expect("claim");
    assert_eq!(first.len(), 2, "limit is honoured");
    let second = repo
        .claim_due_deliveries(lease, now, 10)
        .await
        .expect("claim");
    assert_eq!(second.len(), 1, "leased rows are skipped");
    let ids: HashSet<LogoutDeliveryId> = first.iter().chain(&second).map(|d| d.id).collect();
    assert_eq!(ids.len(), 3);
    for d in deliveries(s, ctx.tenant, &ctx.bc.client_id).await {
        assert_eq!(d.next_attempt_at, lease, "claiming leases the row");
    }
    assert!(
        repo.claim_due_deliveries(lease + Duration::seconds(60), now, 10)
            .await
            .expect("claim")
            .is_empty(),
        "nothing is due while leased"
    );
    let again = repo
        .claim_due_deliveries(lease + Duration::seconds(60), lease, 10)
        .await
        .expect("claim");
    assert_eq!(again.len(), 3, "an expired lease makes rows due again");
    assert!(
        repo.claim_due_deliveries(now + Duration::days(2), now + LOGOUT_DELIVERY_TTL, 10)
            .await
            .expect("claim")
            .is_empty(),
        "rows past give_up_at are never claimed"
    );
}

pub async fn delivery_claim_concurrent_each_row_once(s: &TestStorage) {
    const ROWS: usize = 12;
    const CLAIMERS: usize = 8;
    let now = now_ms();
    let ctx = seed_due_deliveries(s, ROWS, now).await;
    let lease = now + Duration::seconds(60);
    let storage = s.storage.clone();
    let results = race(CLAIMERS, move |_| {
        let storage = storage.clone();
        async move { storage.logout().claim_due_deliveries(lease, now, 3).await }
    })
    .await;
    let mut seen = HashSet::new();
    for r in results {
        for d in r.expect("no storage errors allowed") {
            assert!(seen.insert(d.id), "a row was claimed twice");
        }
    }
    // Whatever the racers skipped is still claimable exactly once.
    let rest = s
        .storage
        .logout()
        .claim_due_deliveries(lease, now, 100)
        .await
        .expect("claim");
    for d in rest {
        assert!(seen.insert(d.id), "a leased row was claimed again");
    }
    assert_eq!(seen.len(), ROWS);
    assert_eq!(
        deliveries(s, ctx.tenant, &ctx.bc.client_id).await.len(),
        ROWS
    );
}

pub async fn delivery_complete_semantics(s: &TestStorage) {
    let now = now_ms();
    let ctx = seed_due_deliveries(s, 3, now).await;
    let repo = s.storage.logout();
    let lease = now + Duration::seconds(60);
    let claimed = repo
        .claim_due_deliveries(lease, now, 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 3);
    let (delivered, retried, given_up) = (claimed[0].id, claimed[1].id, claimed[2].id);

    let done_at = now + Duration::seconds(1);
    assert!(
        repo.complete_delivery(delivered, &DeliveryResult::Delivered, done_at)
            .await
            .expect("complete")
    );
    let retry_at = now + Duration::minutes(5);
    assert!(
        repo.complete_delivery(
            retried,
            &DeliveryResult::Retry {
                next_attempt_at: retry_at,
                error: "timeout".into(),
            },
            done_at,
        )
        .await
        .expect("complete")
    );
    assert!(
        repo.complete_delivery(
            given_up,
            &DeliveryResult::GiveUp {
                error: "status 404".into(),
            },
            done_at,
        )
        .await
        .expect("complete")
    );
    assert!(
        !repo
            .complete_delivery(
                LogoutDeliveryId::new_v7(),
                &DeliveryResult::Delivered,
                done_at
            )
            .await
            .expect("complete"),
        "unknown delivery"
    );

    let all = deliveries(s, ctx.tenant, &ctx.bc.client_id).await;
    let by_id = |id| all.iter().find(|d| d.id == id).expect("delivery");
    let d = by_id(delivered);
    assert_eq!(d.delivered_at, Some(done_at));
    let r = by_id(retried);
    assert_eq!(r.attempts, 1);
    assert_eq!(r.next_attempt_at, retry_at);
    assert_eq!(r.last_error.as_deref(), Some("timeout"));
    assert_eq!(r.delivered_at, None);
    let g = by_id(given_up);
    assert_eq!(g.give_up_at, done_at);
    assert_eq!(g.last_error.as_deref(), Some("status 404"));
    assert_eq!(g.delivered_at, None);

    // Long after every lease: only the retried row is ever claimed again.
    let later = now + Duration::hours(1);
    let again = repo
        .claim_due_deliveries(later + Duration::seconds(60), later, 10)
        .await
        .expect("claim");
    assert_eq!(
        again.iter().map(|d| d.id).collect::<Vec<_>>(),
        vec![retried],
        "delivered and given-up rows are never claimed again"
    );
}
