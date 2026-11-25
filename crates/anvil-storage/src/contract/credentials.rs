//! UserRepo credential contract: passkeys, TOTP (step replay guard) and recovery codes,
//! including the concurrency guarantees the flows rely on.

use std::sync::Arc;

use anvil_core::model::{CounterOutcome, CredentialId, CredentialKind, TenantId, UserId};
use anvil_core::ports::StorageError;

use super::TestStorage;
use super::fixtures::*;

async fn seed_passkey(
    s: &TestStorage,
    tenant: TenantId,
    user: UserId,
) -> anvil_core::model::NewPasskey {
    let p = new_passkey();
    s.storage
        .users()
        .create_passkey(tenant, user, &p)
        .await
        .expect("creating a passkey must succeed");
    p
}

async fn seed_totp(
    s: &TestStorage,
    tenant: TenantId,
    user: UserId,
    codes: usize,
) -> Vec<anvil_core::model::RecoveryCodeHash> {
    let codes = recovery_codes(codes);
    s.storage
        .users()
        .create_totp(tenant, user, &new_totp(), &codes, now_ms())
        .await
        .expect("creating a TOTP credential must succeed");
    codes
}

pub async fn passkey_create_list_find(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    assert!(
        users
            .passkeys(tenant, user.id)
            .await
            .expect("passkeys")
            .is_empty()
    );

    let a = seed_passkey(s, tenant, user.id).await;
    let b = seed_passkey(s, tenant, user.id).await;
    assert_eq!(
        users.passkeys(tenant, user.id).await.expect("passkeys"),
        vec![expected_passkey(user.id, &a), expected_passkey(user.id, &b)],
        "passkeys are listed oldest first with every field"
    );
    assert_eq!(
        users
            .find_passkey(tenant, &b.credential_id)
            .await
            .expect("find_passkey"),
        Some(expected_passkey(user.id, &b))
    );
    assert_eq!(
        users
            .find_passkey(tenant, b"unknown-credential")
            .await
            .expect("find_passkey"),
        None
    );
}

pub async fn passkey_duplicate_credential_id_conflicts(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other_tenant = seed_tenant(s).await;
    let alice = seed_user(s, tenant).await;
    let bob = seed_user(s, tenant).await;
    let carol = seed_user(s, other_tenant).await;
    let users = s.storage.users();
    let first = seed_passkey(s, tenant, alice.id).await;

    for (who, user) in [("same user", alice.id), ("another user", bob.id)] {
        let dup = anvil_core::model::NewPasskey {
            id: CredentialId::new_v7(),
            ..first.clone()
        };
        let err = users
            .create_passkey(tenant, user, &dup)
            .await
            .expect_err("a credential id must never be registered twice in a tenant");
        assert!(
            matches!(err, StorageError::Conflict(_)),
            "{who}: expected Conflict, got {err:?}"
        );
    }
    assert!(
        users
            .passkeys(tenant, bob.id)
            .await
            .expect("passkeys")
            .is_empty()
    );

    let elsewhere = anvil_core::model::NewPasskey {
        id: CredentialId::new_v7(),
        ..first.clone()
    };
    users
        .create_passkey(other_tenant, carol.id, &elsewhere)
        .await
        .expect("the same credential id in another tenant is a different credential");
}

pub async fn passkey_update_counter_compare_and_swap(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();

    // Authenticators without a counter always report 0.
    let zero = seed_passkey(s, tenant, user.id).await;
    let t1 = now_ms();
    assert_eq!(
        users
            .update_passkey(tenant, zero.id, r#"{"v":1}"#, 0, t1)
            .await
            .expect("update_passkey"),
        CounterOutcome::Advanced,
        "0/0 must be accepted"
    );

    let p = seed_passkey(s, tenant, user.id).await;
    assert_eq!(
        users
            .update_passkey(tenant, p.id, r#"{"v":5}"#, 5, t1)
            .await
            .expect("update_passkey"),
        CounterOutcome::Advanced
    );
    for (counter, why) in [
        (5, "an equal counter"),
        (3, "a lower counter"),
        (0, "a reset to 0"),
    ] {
        assert_eq!(
            users
                .update_passkey(tenant, p.id, r#"{"v":"stale"}"#, counter, now_ms())
                .await
                .expect("update_passkey"),
            CounterOutcome::Stale,
            "{why} must be Stale"
        );
    }
    let stored = users
        .find_passkey(tenant, &p.credential_id)
        .await
        .expect("find_passkey")
        .expect("passkey");
    assert_eq!(stored.counter, 5);
    assert_eq!(
        stored.passkey_json, r#"{"v":5}"#,
        "a Stale update changes nothing"
    );
    assert_eq!(stored.last_used_at, Some(t1));

    assert_eq!(
        users
            .update_passkey(tenant, p.id, r#"{"v":6}"#, 6, now_ms())
            .await
            .expect("update_passkey"),
        CounterOutcome::Advanced
    );
    assert_eq!(
        users
            .update_passkey(tenant, CredentialId::new_v7(), "{}", 99, now_ms())
            .await
            .expect("update_passkey"),
        CounterOutcome::Stale,
        "an unknown credential is Stale"
    );
}

pub async fn passkey_concurrent_updates_never_move_counter_backwards(s: &TestStorage) {
    const N: usize = 16;
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let p = seed_passkey(s, tenant, user.id).await;
    let id = p.id;
    let results = race(N, |i| {
        let storage = Arc::clone(&s.storage);
        // Distinct counters 1..=N in an interleaved order.
        let counter = ((i * 7) % N + 1) as u32;
        async move {
            storage
                .users()
                .update_passkey(
                    tenant,
                    id,
                    &format!(r#"{{"c":{counter}}}"#),
                    counter,
                    now_ms(),
                )
                .await
        }
    })
    .await;
    assert!(
        results.iter().all(Result::is_ok),
        "no storage errors allowed: {results:?}"
    );
    let stored = s
        .storage
        .users()
        .find_passkey(tenant, &p.credential_id)
        .await
        .expect("find_passkey")
        .expect("passkey");
    assert_eq!(
        stored.counter, N as u32,
        "the stored counter must be the maximum"
    );
    assert_eq!(stored.passkey_json, format!(r#"{{"c":{N}}}"#));
}

pub async fn totp_create_get_and_conflict(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    assert_eq!(users.totp(tenant, user.id).await.expect("totp"), None);

    let totp = new_totp();
    let codes = recovery_codes(10);
    let now = now_ms();
    users
        .create_totp(tenant, user.id, &totp, &codes, now)
        .await
        .expect("create_totp");
    let stored = users
        .totp(tenant, user.id)
        .await
        .expect("totp")
        .expect("totp");
    assert_eq!(stored.id, totp.id);
    assert_eq!(stored.user_id, user.id);
    assert_eq!(stored.secret_enc, totp.secret_enc);
    assert_eq!(stored.last_step, None);
    assert_eq!(stored.created_at, totp.created_at);
    assert_eq!(stored.last_used_at, None);
    assert_eq!(
        users
            .recovery_codes_remaining(tenant, user.id)
            .await
            .expect("remaining"),
        10
    );

    let err = users
        .create_totp(tenant, user.id, &new_totp(), &recovery_codes(3), now_ms())
        .await
        .expect_err("a second TOTP credential must conflict");
    assert!(matches!(err, StorageError::Conflict(_)), "{err:?}");
    assert_eq!(
        users
            .recovery_codes_remaining(tenant, user.id)
            .await
            .expect("remaining"),
        10,
        "a conflicting create_totp must not replace the recovery codes"
    );
    assert_eq!(
        users
            .totp(tenant, user.id)
            .await
            .expect("totp")
            .map(|t| t.id),
        Some(totp.id)
    );
}

pub async fn totp_step_accepted_once(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    assert_eq!(
        users
            .advance_totp_step(tenant, user.id, 100, now_ms())
            .await
            .expect("advance"),
        CounterOutcome::Stale,
        "no TOTP credential: Stale"
    );
    seed_totp(s, tenant, user.id, 0).await;
    let t1 = now_ms();
    let step = |n| users.advance_totp_step(tenant, user.id, n, t1);
    assert_eq!(step(100).await.expect("advance"), CounterOutcome::Advanced);
    assert_eq!(
        step(100).await.expect("advance"),
        CounterOutcome::Stale,
        "the same step must not be accepted twice"
    );
    assert_eq!(step(99).await.expect("advance"), CounterOutcome::Stale);
    assert_eq!(step(101).await.expect("advance"), CounterOutcome::Advanced);
    let stored = users
        .totp(tenant, user.id)
        .await
        .expect("totp")
        .expect("totp");
    assert_eq!(stored.last_step, Some(101));
    assert_eq!(stored.last_used_at, Some(t1));
}

pub async fn totp_step_concurrent_single_winner(s: &TestStorage) {
    const ROUNDS: usize = 10;
    let tenant = seed_tenant(s).await;
    for round in 0..ROUNDS {
        for n in [2usize, 8] {
            let user = seed_user(s, tenant).await;
            seed_totp(s, tenant, user.id, 0).await;
            let user_id = user.id;
            let results = race(n, |_| {
                let storage = Arc::clone(&s.storage);
                async move {
                    storage
                        .users()
                        .advance_totp_step(tenant, user_id, 5_000, now_ms())
                        .await
                }
            })
            .await;
            let won = results
                .iter()
                .map(|r| r.as_ref().expect("no storage errors allowed"))
                .filter(|o| **o == CounterOutcome::Advanced)
                .count();
            assert_eq!(won, 1, "round {round}, {n} callers: exactly one Advanced");
        }
    }
}

pub async fn recovery_code_consumed_once(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    let codes = seed_totp(s, tenant, user.id, 3).await;

    let now = now_ms();
    assert!(
        users
            .consume_recovery_code(tenant, user.id, &codes[0], now, None)
            .await
            .expect("consume")
    );
    assert!(
        !users
            .consume_recovery_code(tenant, user.id, &codes[0], now_ms(), None)
            .await
            .expect("consume"),
        "a recovery code is single-use"
    );
    assert!(
        !users
            .consume_recovery_code(tenant, user.id, &recovery_codes(1)[0], now_ms(), None)
            .await
            .expect("consume"),
        "an unknown code must not be accepted"
    );
    assert_eq!(
        users
            .recovery_codes_remaining(tenant, user.id)
            .await
            .expect("remaining"),
        2
    );

    let fresh = recovery_codes(4);
    users
        .replace_recovery_codes(tenant, user.id, &fresh, now_ms())
        .await
        .expect("replace");
    assert_eq!(
        users
            .recovery_codes_remaining(tenant, user.id)
            .await
            .expect("remaining"),
        4
    );
    assert!(
        !users
            .consume_recovery_code(tenant, user.id, &codes[1], now_ms(), None)
            .await
            .expect("consume"),
        "replaced codes stop working"
    );
    assert!(
        users
            .consume_recovery_code(tenant, user.id, &fresh[3], now_ms(), None)
            .await
            .expect("consume")
    );
}

pub async fn recovery_code_concurrent_single_winner(s: &TestStorage) {
    const N: usize = 16;
    const ROUNDS: usize = 5;
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let codes = seed_totp(s, tenant, user.id, ROUNDS).await;
    for (round, code) in codes.into_iter().enumerate() {
        let user_id = user.id;
        let results = race(N, |_| {
            let storage = Arc::clone(&s.storage);
            async move {
                storage
                    .users()
                    .consume_recovery_code(tenant, user_id, &code, now_ms(), None)
                    .await
            }
        })
        .await;
        let won = results
            .iter()
            .map(|r| *r.as_ref().expect("no storage errors allowed"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(
            won, 1,
            "round {round}: exactly one concurrent consume must win"
        );
    }
}

pub async fn recovery_code_notice_enqueued_only_on_success(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    let codes = seed_totp(s, tenant, user.id, 2).await;

    let notice = new_email(&user.email);
    assert!(
        users
            .consume_recovery_code(tenant, user.id, &codes[0], now_ms(), Some(&notice))
            .await
            .expect("consume")
    );
    let replay = new_email(&user.email);
    assert!(
        !users
            .consume_recovery_code(tenant, user.id, &codes[0], now_ms(), Some(&replay))
            .await
            .expect("consume")
    );
    let unknown = new_email(&user.email);
    assert!(
        !users
            .consume_recovery_code(
                tenant,
                user.id,
                &recovery_codes(1)[0],
                now_ms(),
                Some(&unknown)
            )
            .await
            .expect("consume")
    );
    let claimed = s
        .storage
        .outbox()
        .claim_due(now_ms(), 10, LEASE)
        .await
        .expect("claim_due");
    assert_eq!(
        claimed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![notice.id],
        "exactly the notice of the successful consume is enqueued"
    );
}

pub async fn delete_totp_removes_recovery_codes(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    let codes = seed_totp(s, tenant, user.id, 5).await;
    let totp_id = users
        .totp(tenant, user.id)
        .await
        .expect("totp")
        .expect("totp")
        .id;

    assert!(
        users
            .delete_credential(tenant, user.id, totp_id)
            .await
            .expect("delete")
    );
    assert_eq!(users.totp(tenant, user.id).await.expect("totp"), None);
    assert_eq!(
        users
            .recovery_codes_remaining(tenant, user.id)
            .await
            .expect("remaining"),
        0,
        "deleting TOTP deletes the recovery codes"
    );
    assert!(
        !users
            .consume_recovery_code(tenant, user.id, &codes[0], now_ms(), None)
            .await
            .expect("consume")
    );
    assert!(
        !users
            .delete_credential(tenant, user.id, totp_id)
            .await
            .expect("delete"),
        "a deleted credential is gone"
    );
    // A new enrolment is possible afterwards.
    seed_totp(s, tenant, user.id, 1).await;
}

pub async fn delete_credential_only_own_and_never_password(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let alice = seed_user(s, tenant).await;
    let bob = seed_user(s, tenant).await;
    let users = s.storage.users();
    let key = seed_passkey(s, tenant, alice.id).await;

    assert!(
        !users
            .delete_credential(tenant, bob.id, key.id)
            .await
            .expect("delete"),
        "another user's credential must not be deleted"
    );
    assert_eq!(
        users
            .passkeys(tenant, alice.id)
            .await
            .expect("passkeys")
            .len(),
        1
    );

    let password_id = users
        .list_credentials(tenant, alice.id)
        .await
        .expect("list_credentials")
        .into_iter()
        .find(|c| c.kind == CredentialKind::Password)
        .expect("the seed user has a password")
        .id;
    assert!(
        !users
            .delete_credential(tenant, alice.id, password_id)
            .await
            .expect("delete"),
        "passwords cannot be deleted through delete_credential"
    );
    assert!(
        users
            .password(tenant, alice.id)
            .await
            .expect("password")
            .is_some()
    );

    assert!(
        users
            .delete_credential(tenant, alice.id, key.id)
            .await
            .expect("delete")
    );
    assert!(
        users
            .passkeys(tenant, alice.id)
            .await
            .expect("passkeys")
            .is_empty()
    );
    assert_eq!(
        users
            .find_passkey(tenant, &key.credential_id)
            .await
            .expect("find"),
        None
    );
}

pub async fn list_credentials_summarises_every_kind(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    let key = seed_passkey(s, tenant, user.id).await;
    seed_totp(s, tenant, user.id, 1).await;

    let list = users.list_credentials(tenant, user.id).await.expect("list");
    let kinds: Vec<CredentialKind> = list.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CredentialKind::Password,
            CredentialKind::Webauthn,
            CredentialKind::Totp
        ],
        "oldest first"
    );
    let summary = list
        .iter()
        .find(|c| c.id == key.id)
        .expect("passkey summary");
    assert_eq!(summary.label, key.label);
    assert_eq!(summary.created_at, key.created_at);
    assert_eq!(summary.last_used_at, None);
}

pub async fn credentials_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let users = s.storage.users();
    let key = seed_passkey(s, tenant, user.id).await;
    let codes = seed_totp(s, tenant, user.id, 2).await;

    assert!(
        users
            .passkeys(other, user.id)
            .await
            .expect("passkeys")
            .is_empty()
    );
    assert_eq!(
        users
            .find_passkey(other, &key.credential_id)
            .await
            .expect("find"),
        None
    );
    assert!(
        users
            .list_credentials(other, user.id)
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(users.totp(other, user.id).await.expect("totp"), None);
    assert_eq!(
        users
            .recovery_codes_remaining(other, user.id)
            .await
            .expect("remaining"),
        0
    );
    assert_eq!(
        users
            .update_passkey(other, key.id, "{}", 10, now_ms())
            .await
            .expect("update"),
        CounterOutcome::Stale
    );
    assert_eq!(
        users
            .advance_totp_step(other, user.id, 10, now_ms())
            .await
            .expect("advance"),
        CounterOutcome::Stale
    );
    assert!(
        !users
            .consume_recovery_code(other, user.id, &codes[0], now_ms(), None)
            .await
            .expect("consume")
    );
    assert!(
        !users
            .delete_credential(other, user.id, key.id)
            .await
            .expect("delete")
    );
    // Nothing changed in the owning tenant.
    assert_eq!(
        users
            .recovery_codes_remaining(tenant, user.id)
            .await
            .expect("remaining"),
        2
    );
    assert_eq!(
        users
            .find_passkey(tenant, &key.credential_id)
            .await
            .expect("find")
            .map(|p| p.counter),
        Some(0)
    );
}
