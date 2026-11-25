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
        ip: n.ip.clone(),
        user_agent: n.user_agent.clone(),
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

/// A session of `user` created `age` ago (so listing order is deterministic).
async fn seed_session_aged(
    s: &TestStorage,
    tenant: TenantId,
    user: anvil_core::model::UserId,
    age: Duration,
) -> NewBrowserSession {
    let mut n = new_session(user, Duration::hours(8), Duration::minutes(30));
    n.created_at -= age;
    n.auth_time = n.created_at;
    s.storage
        .sessions()
        .create(tenant, &n)
        .await
        .expect("create");
    n
}

/// A code-issued family bound to `session`.
async fn seed_family_for(
    s: &TestStorage,
    ctx: &GrantCtx,
    session: &NewBrowserSession,
) -> anvil_core::model::TokenFamilyId {
    let ctx = GrantCtx {
        tenant: ctx.tenant,
        user: ctx.user.clone(),
        client: ctx.client.clone(),
        session: session.clone(),
    };
    seed_code(s, &ctx, Duration::minutes(5)).await.1.id
}

pub async fn session_request_context_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let n = NewBrowserSession {
        ip: Some("2001:db8::7".to_owned()),
        user_agent: Some("Mozilla/5.0 (contract)".to_owned()),
        ..new_session(user.id, Duration::hours(8), Duration::minutes(30))
    };
    s.storage
        .sessions()
        .create(tenant, &n)
        .await
        .expect("create");
    assert_eq!(
        s.storage
            .sessions()
            .get_active(tenant, &n.token_hash, now_ms())
            .await
            .expect("get_active"),
        Some(expected_session(tenant, &n))
    );
}

pub async fn session_get_in_any_state(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let n = seed_session(s, tenant, user.id).await;
    let repo = s.storage.sessions();
    assert_eq!(
        repo.get(tenant, n.id).await.expect("get"),
        Some(expected_session(tenant, &n))
    );
    let now = now_ms();
    assert!(repo.revoke(tenant, n.id, now).await.expect("revoke"));
    let revoked = repo.get(tenant, n.id).await.expect("get").expect("session");
    assert_eq!(
        revoked.revoked_at,
        Some(now),
        "revoked sessions are still returned"
    );
    assert_eq!(repo.get(other, n.id).await.expect("get"), None);
    assert_eq!(
        repo.get(tenant, SessionId::new_v7()).await.expect("get"),
        None
    );
}

pub async fn session_list_for_user_active_newest_first(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let someone_else = seed_user(s, tenant).await;
    let repo = s.storage.sessions();
    let oldest = seed_session_aged(s, tenant, user.id, Duration::minutes(3)).await;
    let revoked = seed_session_aged(s, tenant, user.id, Duration::minutes(2)).await;
    let newest = seed_session_aged(s, tenant, user.id, Duration::minutes(1)).await;
    repo.revoke(tenant, revoked.id, now_ms())
        .await
        .expect("revoke");
    let expired = new_session(user.id, Duration::seconds(-1), Duration::minutes(30));
    repo.create(tenant, &expired).await.expect("create");
    let idle = new_session(user.id, Duration::hours(8), Duration::seconds(-1));
    repo.create(tenant, &idle).await.expect("create");
    seed_session(s, tenant, someone_else.id).await;

    let ids: Vec<_> = repo
        .list_for_user(tenant, user.id, now_ms())
        .await
        .expect("list_for_user")
        .into_iter()
        .map(|x| x.id)
        .collect();
    assert_eq!(ids, vec![newest.id, oldest.id], "active only, newest first");
}

pub async fn session_list_tenant_wide_paging(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let a = seed_user(s, tenant).await;
    let b = seed_user(s, tenant).await;
    let c = seed_user(s, other).await;
    let mut active = Vec::new();
    for user in [a.id, b.id, a.id, b.id, a.id] {
        active.push(seed_session(s, tenant, user).await.id);
    }
    let revoked = seed_session(s, tenant, a.id).await;
    s.storage
        .sessions()
        .revoke(tenant, revoked.id, now_ms())
        .await
        .expect("revoke");
    seed_session(s, other, c.id).await;

    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = s
            .storage
            .sessions()
            .list(
                tenant,
                now_ms(),
                anvil_core::model::PageRequest { after, limit: 2 },
            )
            .await
            .expect("list");
        assert!(page.items.len() <= 2);
        seen.extend(page.items.iter().map(|x| x.id));
        match page.next_cursor {
            Some(cur) => after = Some(cur),
            None => break,
        }
    }
    assert_eq!(
        seen, active,
        "active sessions of this tenant, id order, no gaps"
    );
}

pub async fn session_revoke_with_families_only_its_own(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let repo = s.storage.sessions();
    let grants = s.storage.grants();
    let fa = seed_family_for(s, &ctx, &ctx.session).await;
    let other_session = seed_session(s, ctx.tenant, ctx.user.id).await;
    let fb = seed_family_for(s, &ctx, &other_session).await;

    let now = now_ms();
    assert!(
        repo.revoke_with_families(ctx.tenant, ctx.session.id, now)
            .await
            .expect("revoke_with_families")
    );
    assert_eq!(
        repo.get(ctx.tenant, ctx.session.id)
            .await
            .expect("get")
            .expect("session")
            .revoked_at,
        Some(now)
    );
    let a = grants
        .get_family(ctx.tenant, fa)
        .await
        .expect("get")
        .expect("family");
    assert_eq!(
        a.revoked_reason,
        Some(anvil_core::model::RevokeReason::SessionRevoked)
    );
    let b = grants
        .get_family(ctx.tenant, fb)
        .await
        .expect("get")
        .expect("family");
    assert_eq!(b.revoked_at, None, "another session's family stays valid");
    assert!(
        repo.get_active(ctx.tenant, &other_session.token_hash, now_ms())
            .await
            .expect("get_active")
            .is_some()
    );
    assert!(
        !repo
            .revoke_with_families(ctx.tenant, ctx.session.id, now_ms())
            .await
            .expect("revoke_with_families"),
        "already revoked"
    );
}

pub async fn session_revoke_all_for_user_keeps_except(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let repo = s.storage.sessions();
    let grants = s.storage.grants();
    let keep = seed_session(s, ctx.tenant, ctx.user.id).await;
    let third = seed_session(s, ctx.tenant, ctx.user.id).await;
    let f_first = seed_family_for(s, &ctx, &ctx.session).await;
    let f_keep = seed_family_for(s, &ctx, &keep).await;
    let f_third = seed_family_for(s, &ctx, &third).await;
    let stranger = seed_user(s, ctx.tenant).await;
    let theirs = seed_session(s, ctx.tenant, stranger.id).await;

    assert_eq!(
        repo.revoke_all_for_user(ctx.tenant, ctx.user.id, Some(keep.id), now_ms())
            .await
            .expect("revoke_all_for_user"),
        2
    );
    let active: Vec<_> = repo
        .list_for_user(ctx.tenant, ctx.user.id, now_ms())
        .await
        .expect("list")
        .into_iter()
        .map(|x| x.id)
        .collect();
    assert_eq!(active, vec![keep.id], "only the excepted session survives");
    for (f, revoked) in [(f_first, true), (f_keep, false), (f_third, true)] {
        let fam = grants
            .get_family(ctx.tenant, f)
            .await
            .expect("get")
            .expect("family");
        assert_eq!(fam.revoked_at.is_some(), revoked, "family {f}");
        if revoked {
            assert_eq!(
                fam.revoked_reason,
                Some(anvil_core::model::RevokeReason::SessionRevoked)
            );
        }
    }
    assert!(
        repo.get_active(ctx.tenant, &theirs.token_hash, now_ms())
            .await
            .expect("get_active")
            .is_some(),
        "other users are untouched"
    );
    assert_eq!(
        repo.revoke_all_for_user(ctx.tenant, ctx.user.id, None, now_ms())
            .await
            .expect("revoke_all_for_user"),
        1
    );
}

// ---- Phase 4 (plan 04-01); backends implement it in 04-04 / 04-05 ----

pub async fn session_upgrade_auth(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let session = seed_session(s, tenant, user.id).await;
    let sessions = s.storage.sessions();
    let amr = vec!["pwd".to_owned(), "otp".to_owned(), "mfa".to_owned()];
    let auth_time = now_ms();

    assert!(
        sessions
            .upgrade_auth(
                tenant,
                session.id,
                anvil_core::model::ACR_MFA,
                &amr,
                auth_time,
                now_ms()
            )
            .await
            .expect("upgrade_auth")
    );
    let got = sessions
        .get(tenant, session.id)
        .await
        .expect("get")
        .expect("session");
    assert_eq!(got.acr, anvil_core::model::ACR_MFA);
    assert_eq!(got.amr, amr);
    assert_eq!(got.auth_time, auth_time);
    assert_eq!(got.user_id, user.id, "nothing else changes");

    assert!(
        !sessions
            .upgrade_auth(other, session.id, "x", &amr, auth_time, now_ms())
            .await
            .expect("upgrade_auth"),
        "another tenant's session is missing"
    );
    assert!(
        !sessions
            .upgrade_auth(tenant, SessionId::new_v7(), "x", &amr, auth_time, now_ms())
            .await
            .expect("upgrade_auth"),
        "unknown session"
    );

    let expired = new_session(user.id, Duration::seconds(-1), Duration::minutes(30));
    sessions.create(tenant, &expired).await.expect("create");
    let idle = new_session(user.id, Duration::hours(1), Duration::seconds(-1));
    sessions.create(tenant, &idle).await.expect("create");
    for id in [expired.id, idle.id] {
        assert!(
            !sessions
                .upgrade_auth(tenant, id, "x", &amr, auth_time, now_ms())
                .await
                .expect("upgrade_auth"),
            "an expired session cannot be upgraded"
        );
    }

    sessions
        .revoke(tenant, session.id, now_ms())
        .await
        .expect("revoke");
    assert!(
        !sessions
            .upgrade_auth(tenant, session.id, "x", &amr, auth_time, now_ms())
            .await
            .expect("upgrade_auth"),
        "a revoked session cannot be upgraded"
    );
    assert_eq!(
        sessions
            .get(tenant, session.id)
            .await
            .expect("get")
            .expect("session")
            .acr,
        anvil_core::model::ACR_MFA,
        "a refused upgrade changes nothing"
    );
}
