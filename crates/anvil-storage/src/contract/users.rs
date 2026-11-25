//! UserRepo contract: users, passwords and self-service tokens.

use std::sync::Arc;

use anvil_core::model::{
    PageRequest, RevokeReason, SelfServiceKind, StandardClaims, UserId, UserStatus, UserUpdate,
};
use anvil_core::ports::{RotateOutcome, StorageError};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn user_create_round_trip_all_fields(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let mut new = new_user();
    new.email_verified = true;
    let created = s
        .storage
        .users()
        .create(tenant, &new, None, None, None)
        .await
        .expect("create must succeed");
    assert_eq!(
        created,
        expected_user(tenant, &new),
        "create must return every field"
    );
    assert_eq!(
        s.storage.users().get(tenant, new.id).await.expect("get"),
        Some(created),
        "get must return every field, including all standard claims and the address"
    );
    assert_eq!(
        s.storage
            .users()
            .get(tenant, UserId::new_v7())
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        s.storage
            .users()
            .password(tenant, new.id)
            .await
            .expect("password"),
        None,
        "a user created without a password has none"
    );
}

pub async fn user_email_conflict_persists_nothing(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let first = seed_user(s, tenant).await;

    let mut dup = new_user();
    dup.email = first.email.clone();
    let token = new_self_service_token(
        SelfServiceKind::Verification,
        dup.id,
        &dup.email,
        Duration::hours(1),
    );
    let email = new_email(&dup.email);
    match s
        .storage
        .users()
        .create(
            tenant,
            &dup,
            Some(&new_password()),
            Some(&token),
            Some(&email),
        )
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("duplicate email must be rejected with Conflict, got {other:?}"),
    }

    assert_eq!(
        s.storage.users().get(tenant, dup.id).await.expect("get"),
        None
    );
    assert_eq!(
        s.storage
            .users()
            .password(tenant, dup.id)
            .await
            .expect("password"),
        None,
        "no credential may remain after a conflict"
    );
    assert!(
        s.storage
            .outbox()
            .claim_due(now_ms(), 100, LEASE)
            .await
            .expect("claim_due")
            .is_empty(),
        "no outbox row may remain after a conflict"
    );
    // The token hash is still free: issuing it now must not conflict.
    let retry = anvil_core::model::NewSelfServiceToken {
        user_id: first.id,
        email: first.email.clone(),
        ..token
    };
    s.storage
        .users()
        .issue_self_service_token(tenant, &retry, None)
        .await
        .expect("no self-service token may remain after a conflict");
}

pub async fn user_username_conflict(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let first = seed_user(s, tenant).await;

    let mut dup = new_user();
    dup.username = first.username.clone();
    match s
        .storage
        .users()
        .create(tenant, &dup, None, None, None)
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("duplicate username must be rejected with Conflict, got {other:?}"),
    }
    assert_eq!(
        s.storage.users().get(tenant, dup.id).await.expect("get"),
        None
    );

    for _ in 0..2 {
        let mut u = new_user();
        u.username = None;
        s.storage
            .users()
            .create(tenant, &u, None, None, None)
            .await
            .expect("several users without a username must be allowed");
    }
}

pub async fn user_get_by_email(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    assert_eq!(
        s.storage
            .users()
            .get_by_email(tenant, &user.email)
            .await
            .expect("get_by_email"),
        Some(user.clone())
    );
    assert_eq!(
        s.storage
            .users()
            .get_by_email(tenant, "nobody@example.test")
            .await
            .expect("get_by_email"),
        None
    );
    assert_eq!(
        s.storage
            .users()
            .get_by_email(other, &user.email)
            .await
            .expect("get_by_email"),
        None,
        "lookup by email must be tenant-scoped"
    );
}

pub async fn user_list_pagination(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    seed_user(s, other).await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(seed_user(s, tenant).await.id);
    }
    let first = s
        .storage
        .users()
        .list(
            tenant,
            PageRequest {
                after: None,
                limit: 2,
            },
        )
        .await
        .expect("list");
    assert_eq!(
        first.items.iter().map(|u| u.id).collect::<Vec<_>>(),
        ids[..2]
    );
    assert_eq!(first.next_cursor, Some(ids[1].0));
    let second = s
        .storage
        .users()
        .list(
            tenant,
            PageRequest {
                after: first.next_cursor,
                limit: 2,
            },
        )
        .await
        .expect("list");
    assert_eq!(
        second.items.iter().map(|u| u.id).collect::<Vec<_>>(),
        ids[2..],
        "list must only return users of the tenant"
    );
    assert_eq!(second.next_cursor, None);
}

pub async fn user_update_and_conflict(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let other = seed_user(s, tenant).await;
    let later = now_ms() + Duration::seconds(10);

    let claims = StandardClaims {
        name: Some("Grace Hopper".into()),
        ..StandardClaims::default()
    };
    let updated = s
        .storage
        .users()
        .update(
            tenant,
            user.id,
            &UserUpdate {
                email: Some(format!("new-{}", user.email)),
                email_verified: Some(true),
                username: Some(None),
                claims: Some(claims.clone()),
                status: Some(UserStatus::Blocked),
            },
            later,
        )
        .await
        .expect("update")
        .expect("updating an existing user must return it");
    assert_eq!(updated.email, format!("new-{}", user.email));
    assert!(updated.email_verified);
    assert_eq!(updated.username, None, "username Some(None) must clear it");
    assert_eq!(updated.claims, claims);
    assert_eq!(updated.status, UserStatus::Blocked);
    assert_eq!(
        updated.updated_at, later,
        "update must set updated_at = now"
    );
    assert_eq!(updated.created_at, user.created_at);
    assert_eq!(
        s.storage.users().get(tenant, user.id).await.expect("get"),
        Some(updated.clone())
    );

    match s
        .storage
        .users()
        .update(
            tenant,
            user.id,
            &UserUpdate {
                email: Some(other.email.clone()),
                ..UserUpdate::default()
            },
            later,
        )
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        r => panic!("updating to a taken email must conflict, got {r:?}"),
    }
    match s
        .storage
        .users()
        .update(
            tenant,
            user.id,
            &UserUpdate {
                username: Some(other.username.clone()),
                ..UserUpdate::default()
            },
            later,
        )
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        r => panic!("updating to a taken username must conflict, got {r:?}"),
    }
    assert_eq!(
        s.storage.users().get(tenant, user.id).await.expect("get"),
        Some(updated),
        "a conflicting update must change nothing"
    );
    assert_eq!(
        s.storage
            .users()
            .update(tenant, UserId::new_v7(), &UserUpdate::default(), later)
            .await
            .expect("update"),
        None
    );
}

pub async fn user_password_set_and_get(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let new = new_user();
    let pw = new_password();
    s.storage
        .users()
        .create(tenant, &new, Some(&pw), None, None)
        .await
        .expect("create");
    let stored = s
        .storage
        .users()
        .password(tenant, new.id)
        .await
        .expect("password")
        .expect("the password must be stored with the user");
    assert_eq!(stored.user_id, new.id);
    assert_eq!(stored.phc, pw.phc);
    assert_eq!(stored.created_at, pw.created_at);
    assert_eq!(stored.updated_at, pw.created_at);

    let later = now_ms() + Duration::seconds(10);
    assert!(
        s.storage
            .users()
            .set_password(tenant, new.id, "$argon2id$replaced", later)
            .await
            .expect("set_password")
    );
    let replaced = s
        .storage
        .users()
        .password(tenant, new.id)
        .await
        .expect("password")
        .expect("password");
    assert_eq!(replaced.phc, "$argon2id$replaced");
    assert_eq!(replaced.updated_at, later);
    assert_eq!(
        replaced.created_at, pw.created_at,
        "an update keeps created_at"
    );

    // Upsert: a user without a password gets one.
    let bare = new_user();
    s.storage
        .users()
        .create(tenant, &bare, None, None, None)
        .await
        .expect("create");
    assert!(
        s.storage
            .users()
            .set_password(tenant, bare.id, "$argon2id$first", later)
            .await
            .expect("set_password")
    );
    let inserted = s
        .storage
        .users()
        .password(tenant, bare.id)
        .await
        .expect("password")
        .expect("set_password must insert a missing credential");
    assert_eq!(inserted.phc, "$argon2id$first");
    assert_eq!((inserted.created_at, inserted.updated_at), (later, later));

    assert!(
        !s.storage
            .users()
            .set_password(tenant, UserId::new_v7(), "$argon2id$x", later)
            .await
            .expect("set_password"),
        "set_password for an unknown user must return false"
    );
}

pub async fn user_record_login(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let at = now_ms() + Duration::seconds(3);
    s.storage
        .users()
        .record_login(tenant, user.id, at)
        .await
        .expect("record_login");
    let got = s
        .storage
        .users()
        .get(tenant, user.id)
        .await
        .expect("get")
        .expect("user");
    assert_eq!(got.last_login_at, Some(at));
    s.storage
        .users()
        .record_login(tenant, UserId::new_v7(), at)
        .await
        .expect("record_login for an unknown user is not an error");
}

pub async fn user_delete_cascades_sessions_and_revokes_families(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let (family, refresh) = seed_refresh(s, &ctx).await;
    let keep = seed_grant_ctx_in(s, ctx.tenant).await;

    assert!(
        s.storage
            .users()
            .delete(ctx.tenant, ctx.user.id)
            .await
            .expect("delete")
    );
    assert_eq!(
        s.storage
            .users()
            .get(ctx.tenant, ctx.user.id)
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        s.storage
            .users()
            .password(ctx.tenant, ctx.user.id)
            .await
            .expect("password"),
        None,
        "credentials must be deleted with the user"
    );
    assert_eq!(
        s.storage
            .sessions()
            .get_active(ctx.tenant, &ctx.session.token_hash, now_ms())
            .await
            .expect("get_active"),
        None,
        "sessions must be deleted with the user"
    );
    if let Some(f) = s
        .storage
        .grants()
        .get_family(ctx.tenant, family.id)
        .await
        .expect("get_family")
    {
        assert!(
            f.revoked_at.is_some(),
            "the user's families must be revoked"
        );
        assert_eq!(f.revoked_reason, Some(RevokeReason::UserDeleted));
    }
    let child = new_refresh(family.id, Some(refresh.token_hash), Duration::days(1));
    assert_eq!(
        s.storage
            .grants()
            .rotate_refresh(ctx.tenant, &refresh.token_hash, &child, now_ms())
            .await
            .expect("rotate_refresh"),
        RotateOutcome::NotFound,
        "refresh tokens of a deleted user must not rotate"
    );
    assert!(
        !s.storage
            .users()
            .delete(ctx.tenant, ctx.user.id)
            .await
            .expect("delete"),
        "deleting a missing user must return false"
    );

    // Another user of the tenant is untouched.
    assert!(
        s.storage
            .sessions()
            .get_active(keep.tenant, &keep.session.token_hash, now_ms())
            .await
            .expect("get_active")
            .is_some()
    );
}

pub async fn user_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    let now = now_ms();

    assert_eq!(users.get(other, user.id).await.expect("get"), None);
    assert_eq!(
        users.password(other, user.id).await.expect("password"),
        None
    );
    assert!(
        !users
            .set_password(other, user.id, "$x", now)
            .await
            .expect("set_password")
    );
    assert_eq!(
        users
            .update(other, user.id, &UserUpdate::default(), now)
            .await
            .expect("update"),
        None
    );
    assert!(!users.delete(other, user.id).await.expect("delete"));
    assert!(users.get(tenant, user.id).await.expect("get").is_some());

    // Uniqueness is per tenant.
    let mut same = new_user();
    same.email = user.email.clone();
    same.username = user.username.clone();
    users
        .create(other, &same, None, None, None)
        .await
        .expect("the same email and username must be allowed in another tenant");
}

// ---------------------------------------------------------------------------------------------
// Self-service tokens

pub async fn verification_completes_once(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    assert!(!user.email_verified);
    let token = new_self_service_token(
        SelfServiceKind::Verification,
        user.id,
        &user.email,
        Duration::hours(1),
    );
    let email = new_email(&user.email);
    s.storage
        .users()
        .issue_self_service_token(tenant, &token, Some(&email))
        .await
        .expect("issue_self_service_token");
    let claimed = s
        .storage
        .outbox()
        .claim_due(now_ms(), 10, LEASE)
        .await
        .expect("claim_due");
    assert_eq!(
        claimed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![email.id],
        "issuing a token must enqueue its email"
    );
    match s
        .storage
        .users()
        .issue_self_service_token(tenant, &token, None)
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        r => panic!("a duplicate token hash must conflict, got {r:?}"),
    }

    let verified = s
        .storage
        .users()
        .complete_verification(tenant, &token.token_hash, now_ms())
        .await
        .expect("complete_verification")
        .expect("a valid verification token must complete");
    assert_eq!(verified.id, user.id);
    assert!(verified.email_verified);
    assert!(
        s.storage
            .users()
            .get(tenant, user.id)
            .await
            .expect("get")
            .expect("user")
            .email_verified
    );
    assert_eq!(
        s.storage
            .users()
            .complete_verification(tenant, &token.token_hash, now_ms())
            .await
            .expect("complete_verification"),
        None,
        "a verification token is single-use"
    );
}

pub async fn verification_rejects_changed_email(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let token = new_self_service_token(
        SelfServiceKind::Verification,
        user.id,
        &user.email,
        Duration::hours(1),
    );
    s.storage
        .users()
        .issue_self_service_token(tenant, &token, None)
        .await
        .expect("issue");
    s.storage
        .users()
        .update(
            tenant,
            user.id,
            &UserUpdate {
                email: Some(format!("changed-{}", user.email)),
                ..UserUpdate::default()
            },
            now_ms(),
        )
        .await
        .expect("update");
    assert_eq!(
        s.storage
            .users()
            .complete_verification(tenant, &token.token_hash, now_ms())
            .await
            .expect("complete_verification"),
        None,
        "a token for an old email must not verify the new one"
    );
    assert!(
        !s.storage
            .users()
            .get(tenant, user.id)
            .await
            .expect("get")
            .expect("user")
            .email_verified
    );
}

pub async fn verification_expired_none(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();

    let expired = new_self_service_token(
        SelfServiceKind::Verification,
        user.id,
        &user.email,
        Duration::seconds(-1),
    );
    users
        .issue_self_service_token(tenant, &expired, None)
        .await
        .expect("issue");
    assert_eq!(
        users
            .complete_verification(tenant, &expired.token_hash, now_ms())
            .await
            .expect("complete_verification"),
        None,
        "an expired token must not verify"
    );

    let wrong_kind = new_self_service_token(
        SelfServiceKind::Recovery,
        user.id,
        &user.email,
        Duration::hours(1),
    );
    users
        .issue_self_service_token(tenant, &wrong_kind, None)
        .await
        .expect("issue");
    assert_eq!(
        users
            .complete_verification(tenant, &wrong_kind.token_hash, now_ms())
            .await
            .expect("complete_verification"),
        None,
        "a recovery token must not verify an email"
    );

    let valid = new_self_service_token(
        SelfServiceKind::Verification,
        user.id,
        &user.email,
        Duration::hours(1),
    );
    users
        .issue_self_service_token(tenant, &valid, None)
        .await
        .expect("issue");
    assert_eq!(
        users
            .complete_verification(other, &valid.token_hash, now_ms())
            .await
            .expect("complete_verification"),
        None,
        "another tenant must not be able to use the token"
    );
    assert_eq!(
        users
            .complete_verification(tenant, &unique_hash(), now_ms())
            .await
            .expect("complete_verification"),
        None,
        "an unknown token must not verify"
    );
}

pub async fn recovery_sets_password_verifies_email_revokes_sessions_and_families_and_enqueues_notice(
    s: &TestStorage,
) {
    let ctx = seed_grant_ctx(s).await;
    let (family, _refresh) = seed_refresh(s, &ctx).await;
    let users = s.storage.users();

    let wrong_kind = new_self_service_token(
        SelfServiceKind::Verification,
        ctx.user.id,
        &ctx.user.email,
        Duration::hours(1),
    );
    users
        .issue_self_service_token(ctx.tenant, &wrong_kind, None)
        .await
        .expect("issue");
    assert_eq!(
        users
            .complete_recovery(ctx.tenant, &wrong_kind.token_hash, "$x", now_ms(), None)
            .await
            .expect("complete_recovery"),
        None,
        "a verification token must not recover an account"
    );

    let token = new_self_service_token(
        SelfServiceKind::Recovery,
        ctx.user.id,
        &ctx.user.email,
        Duration::hours(1),
    );
    users
        .issue_self_service_token(ctx.tenant, &token, None)
        .await
        .expect("issue");
    let notice = new_recovery_notice();
    let now = now_ms();
    let recovered = users
        .complete_recovery(
            ctx.tenant,
            &token.token_hash,
            "$argon2id$recovered",
            now,
            Some(&notice),
        )
        .await
        .expect("complete_recovery")
        .expect("a valid recovery token must complete");
    assert_eq!(recovered.id, ctx.user.id);
    assert!(
        recovered.email_verified,
        "recovery proves control of the email"
    );

    let pw = users
        .password(ctx.tenant, ctx.user.id)
        .await
        .expect("password")
        .expect("password");
    assert_eq!(pw.phc, "$argon2id$recovered");
    assert_eq!(
        s.storage
            .sessions()
            .get_active(ctx.tenant, &ctx.session.token_hash, now_ms())
            .await
            .expect("get_active"),
        None,
        "recovery must revoke every session"
    );
    let f = s
        .storage
        .grants()
        .get_family(ctx.tenant, family.id)
        .await
        .expect("get_family")
        .expect("family");
    assert!(
        f.revoked_at.is_some(),
        "recovery must revoke every token family"
    );
    assert_eq!(f.revoked_reason, Some(RevokeReason::UserRecovery));
    let claimed = s
        .storage
        .outbox()
        .claim_due(now_ms(), 10, LEASE)
        .await
        .expect("claim_due");
    assert_eq!(
        claimed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![notice.id],
        "recovery must enqueue the notice"
    );
    assert_eq!(
        claimed[0].to, ctx.user.email,
        "the notice goes to the address the consumed token was sent to"
    );
    assert_eq!(claimed[0].template, notice.template);
    assert_eq!(claimed[0].payload, notice.payload);

    assert_eq!(
        users
            .complete_recovery(ctx.tenant, &token.token_hash, "$again", now_ms(), None)
            .await
            .expect("complete_recovery"),
        None,
        "a recovery token is single-use"
    );

    // Invitations complete through the same method.
    let invited = seed_user(s, ctx.tenant).await;
    let invitation = new_self_service_token(
        SelfServiceKind::Invitation,
        invited.id,
        &invited.email,
        Duration::hours(1),
    );
    users
        .issue_self_service_token(ctx.tenant, &invitation, None)
        .await
        .expect("issue");
    assert!(
        users
            .complete_recovery(
                ctx.tenant,
                &invitation.token_hash,
                "$invited",
                now_ms(),
                None
            )
            .await
            .expect("complete_recovery")
            .is_some(),
        "an invitation token must complete through complete_recovery"
    );

    let expired = new_self_service_token(
        SelfServiceKind::Recovery,
        ctx.user.id,
        &ctx.user.email,
        Duration::seconds(-1),
    );
    users
        .issue_self_service_token(ctx.tenant, &expired, None)
        .await
        .expect("issue");
    assert_eq!(
        users
            .complete_recovery(ctx.tenant, &expired.token_hash, "$late", now_ms(), None)
            .await
            .expect("complete_recovery"),
        None,
        "an expired recovery token must not complete"
    );
    assert_eq!(
        users
            .password(ctx.tenant, ctx.user.id)
            .await
            .expect("password")
            .expect("password")
            .phc,
        "$argon2id$recovered",
        "a failed recovery must not change the password"
    );
}

pub async fn recovery_token_single_use_concurrent(s: &TestStorage) {
    const N: usize = 16;
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let token = new_self_service_token(
        SelfServiceKind::Recovery,
        user.id,
        &user.email,
        Duration::hours(1),
    );
    s.storage
        .users()
        .issue_self_service_token(tenant, &token, None)
        .await
        .expect("issue");

    let hash = token.token_hash;
    let barrier = Arc::new(tokio::sync::Barrier::new(N));
    let mut set = tokio::task::JoinSet::new();
    for i in 0..N {
        let storage = Arc::clone(&s.storage);
        let barrier = Arc::clone(&barrier);
        set.spawn(async move {
            barrier.wait().await;
            storage
                .users()
                .complete_recovery(tenant, &hash, &format!("$argon2id$p{i}"), now_ms(), None)
                .await
        });
    }
    let mut won = 0usize;
    while let Some(joined) = set.join_next().await {
        match joined.expect("recovery task panicked") {
            Ok(Some(_)) => won += 1,
            Ok(None) => {}
            Err(e) => panic!("no storage errors allowed, got {e:?}"),
        }
    }
    assert_eq!(won, 1, "exactly one concurrent recovery must win");
}

pub async fn recovery_notice_not_enqueued_for_invalid_token(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let users = s.storage.users();
    let before = users
        .password(ctx.tenant, ctx.user.id)
        .await
        .expect("password")
        .expect("password");

    let unknown = new_recovery_notice();
    assert_eq!(
        users
            .complete_recovery(ctx.tenant, &unique_hash(), "$x", now_ms(), Some(&unknown))
            .await
            .expect("complete_recovery"),
        None
    );

    let token = new_self_service_token(
        SelfServiceKind::Recovery,
        ctx.user.id,
        &ctx.user.email,
        Duration::hours(1),
    );
    users
        .issue_self_service_token(ctx.tenant, &token, None)
        .await
        .expect("issue");
    users
        .complete_recovery(ctx.tenant, &token.token_hash, "$first", now_ms(), None)
        .await
        .expect("complete_recovery")
        .expect("first use completes");
    let replay = new_recovery_notice();
    assert_eq!(
        users
            .complete_recovery(
                ctx.tenant,
                &token.token_hash,
                "$second",
                now_ms(),
                Some(&replay)
            )
            .await
            .expect("complete_recovery"),
        None,
        "a consumed token must not complete"
    );

    let claimed = s
        .storage
        .outbox()
        .claim_due(now_ms(), 10, LEASE)
        .await
        .expect("claim_due");
    assert!(
        claimed.is_empty(),
        "no notice for an invalid or consumed token: {claimed:?}"
    );
    let after = users
        .password(ctx.tenant, ctx.user.id)
        .await
        .expect("password")
        .expect("password");
    assert_eq!(after.phc, "$first", "the replay changed nothing");
    assert_ne!(before.phc, after.phc);
}
