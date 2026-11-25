//! SessionRepo contract.

use anvil_core::model::{BrowserSession, NewBrowserSession, SessionId, TenantId};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn expected_session(tenant: TenantId, n: &NewBrowserSession) -> BrowserSession {
    BrowserSession {
        id: n.id,
        tenant_id: tenant,
        user_id: n.user_id,
        token_hash: n.token_hash,
        auth_time: n.auth_time,
        acr: n.acr.clone(),
        amr: n.amr.clone(),
        created_at: n.created_at,
        last_seen_at: n.created_at,
        expires_at: n.expires_at,
        idle_expires_at: n.idle_expires_at,
        revoked_at: None,
    }
}

pub async fn session_get_active_by_hash(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let session = seed_session(s, tenant, user.id).await;
    assert_eq!(
        s.storage
            .sessions()
            .get_active(tenant, &session.token_hash, now_ms())
            .await
            .expect("get_active"),
        Some(expected_session(tenant, &session))
    );
    assert_eq!(
        s.storage
            .sessions()
            .get_active(tenant, &unique_hash(), now_ms())
            .await
            .expect("get_active"),
        None
    );
    assert_eq!(
        s.storage
            .sessions()
            .get_active(other, &session.token_hash, now_ms())
            .await
            .expect("get_active"),
        None,
        "sessions must be tenant-scoped"
    );
}

pub async fn session_expired_or_idle_not_returned(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let sessions = s.storage.sessions();

    let expired = new_session(user.id, Duration::seconds(-1), Duration::minutes(30));
    let idle = new_session(user.id, Duration::hours(8), Duration::seconds(-1));
    for n in [&expired, &idle] {
        sessions.create(tenant, n).await.expect("create");
    }
    assert_eq!(
        sessions
            .get_active(tenant, &expired.token_hash, now_ms())
            .await
            .expect("get_active"),
        None,
        "an absolutely expired session must not be returned"
    );
    assert_eq!(
        sessions
            .get_active(tenant, &idle.token_hash, now_ms())
            .await
            .expect("get_active"),
        None,
        "an idle-expired session must not be returned"
    );

    // Expiry is strict.
    let live = seed_session(s, tenant, user.id).await;
    assert_eq!(
        sessions
            .get_active(tenant, &live.token_hash, live.idle_expires_at)
            .await
            .expect("get_active"),
        None,
        "a session must not be active at exactly idle_expires_at"
    );
}

pub async fn session_touch_extends_idle(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let session = seed_session(s, tenant, user.id).await;
    let sessions = s.storage.sessions();
    let later = now_ms() + Duration::minutes(10);
    let idle = later + Duration::minutes(30);
    assert!(
        sessions
            .touch(tenant, session.id, later, idle)
            .await
            .expect("touch")
    );
    let got = sessions
        .get_active(tenant, &session.token_hash, later)
        .await
        .expect("get_active")
        .expect("session");
    assert_eq!(got.last_seen_at, later);
    assert_eq!(got.idle_expires_at, idle);
    assert_eq!(
        got.expires_at, session.expires_at,
        "touch never extends the absolute expiry"
    );

    assert!(
        !sessions
            .touch(tenant, SessionId::new_v7(), later, idle)
            .await
            .expect("touch"),
        "touching an unknown session must return false"
    );
    sessions
        .revoke(tenant, session.id, later)
        .await
        .expect("revoke");
    assert!(
        !sessions
            .touch(tenant, session.id, later, idle)
            .await
            .expect("touch"),
        "touching a revoked session must return false"
    );
}

pub async fn session_revoke(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let session = seed_session(s, tenant, user.id).await;
    let sessions = s.storage.sessions();
    assert!(
        !sessions
            .revoke(other, session.id, now_ms())
            .await
            .expect("revoke"),
        "another tenant must not revoke the session"
    );
    assert!(
        sessions
            .revoke(tenant, session.id, now_ms())
            .await
            .expect("revoke")
    );
    assert_eq!(
        sessions
            .get_active(tenant, &session.token_hash, now_ms())
            .await
            .expect("get_active"),
        None,
        "a revoked session must not be returned"
    );
    assert!(
        !sessions
            .revoke(tenant, session.id, now_ms())
            .await
            .expect("revoke"),
        "a second revoke must return false"
    );
}
