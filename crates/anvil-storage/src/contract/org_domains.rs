//! OrgRepo contract, domains: several pending claims per domain but one verified org per
//! domain and tenant (also under concurrency), routing only to an enabled connection of the same
//! org, re-check bookkeeping, the installation-wide re-check scan and tenant isolation.
//!
//! The SQLite and Postgres backends refuse these methods with `StorageError::Unsupported` until
//! 06-07 / 06-08 implement them.

use std::sync::Arc;

use anvil_core::model::{
    ConnectionId, ConnectionUpdate, OrgDomainId, OrgDomainStatus, OrgDomainUpdate,
};
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn domain_create_list_get_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let a = seed_org(s, tenant).await;
    let b = seed_org(s, tenant).await;
    let domain = unique_domain();

    let claim_a = new_org_domain(a.id, &domain, None);
    let created = repo.create_domain(tenant, &claim_a).await.expect("create");
    assert_eq!(created, expected_domain(tenant, &claim_a));
    // Another org may hold a pending claim for the same domain.
    let claim_b = new_org_domain(b.id, &domain, None);
    repo.create_domain(tenant, &claim_b)
        .await
        .expect("pending claim of another org");
    // The same org claiming the same domain twice conflicts.
    assert!(matches!(
        repo.create_domain(tenant, &new_org_domain(a.id, &domain, None))
            .await,
        Err(StorageError::Conflict(_))
    ));

    let second = new_org_domain(a.id, &format!("a{domain}"), None);
    repo.create_domain(tenant, &second).await.expect("create");
    let mut want = vec![
        expected_domain(tenant, &claim_a),
        expected_domain(tenant, &second),
    ];
    want.sort_by(|x, y| x.domain.cmp(&y.domain));
    assert_eq!(
        repo.list_domains(tenant, a.id).await.expect("list"),
        want,
        "domain order, only this org"
    );
    assert_eq!(
        repo.get_domain(tenant, claim_b.id).await.expect("get"),
        Some(expected_domain(tenant, &claim_b))
    );

    assert!(
        repo.delete_domain(tenant, claim_a.id)
            .await
            .expect("delete")
    );
    assert!(
        !repo
            .delete_domain(tenant, claim_a.id)
            .await
            .expect("delete again")
    );
    assert_eq!(
        repo.get_domain(tenant, claim_a.id).await.expect("get"),
        None
    );
    assert!(
        repo.get_domain(tenant, claim_b.id)
            .await
            .expect("get")
            .is_some()
    );
}

pub async fn domain_create_refuses_foreign_routing_connection(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let a = seed_org(s, tenant).await;
    let b = seed_org(s, tenant).await;
    let conn_b = seed_org_connection(s, tenant, b.id).await;
    let tenant_conn = seed_connection(s, tenant).await;
    for target in [conn_b.id, tenant_conn.id, ConnectionId::new_v7()] {
        let claim = new_org_domain(a.id, &unique_domain(), Some(target));
        assert!(
            matches!(
                repo.create_domain(tenant, &claim).await,
                Err(StorageError::Conflict(_))
            ),
            "routing to a connection outside the org is refused"
        );
        assert_eq!(repo.get_domain(tenant, claim.id).await.expect("get"), None);
    }
}

pub async fn domain_mark_verified_one_org_per_domain(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other_tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let a = seed_org(s, tenant).await;
    let b = seed_org(s, tenant).await;
    let elsewhere = seed_org(s, other_tenant).await;
    let domain = unique_domain();
    let claim_a = new_org_domain(a.id, &domain, None);
    let claim_b = new_org_domain(b.id, &domain, None);
    let claim_other = new_org_domain(elsewhere.id, &domain, None);
    repo.create_domain(tenant, &claim_a).await.expect("create");
    repo.create_domain(tenant, &claim_b).await.expect("create");
    repo.create_domain(other_tenant, &claim_other)
        .await
        .expect("create");

    let now = now_ms();
    let verified = repo
        .mark_verified(tenant, claim_a.id, now)
        .await
        .expect("verify")
        .expect("claim exists");
    assert_eq!(verified.status, OrgDomainStatus::Verified);
    assert_eq!(verified.verified_at, Some(now));
    assert_eq!(verified.last_checked_at, Some(now));
    assert_eq!(verified.failing_since, None);
    assert_eq!(
        repo.get_domain(tenant, claim_a.id).await.expect("get"),
        Some(verified.clone())
    );

    // Verifying again is idempotent.
    assert_eq!(
        repo.mark_verified(tenant, claim_a.id, now + Duration::seconds(1))
            .await
            .expect("verify again"),
        Some(verified.clone())
    );
    // Another org of the same tenant cannot verify the domain too.
    assert!(matches!(
        repo.mark_verified(tenant, claim_b.id, now_ms()).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(
        repo.get_domain(tenant, claim_b.id).await.expect("get"),
        Some(expected_domain(tenant, &claim_b)),
        "the refused claim stays pending"
    );
    // Another tenant is independent.
    assert_eq!(
        repo.mark_verified(other_tenant, claim_other.id, now_ms())
            .await
            .expect("verify in another tenant")
            .expect("claim exists")
            .status,
        OrgDomainStatus::Verified
    );
    // Unknown claim.
    assert_eq!(
        repo.mark_verified(tenant, OrgDomainId::new_v7(), now_ms())
            .await
            .expect("verify unknown"),
        None
    );
    // Once the first org's claim is gone, the other may verify.
    assert!(
        repo.delete_domain(tenant, claim_a.id)
            .await
            .expect("delete")
    );
    assert!(
        repo.mark_verified(tenant, claim_b.id, now_ms())
            .await
            .expect("verify b")
            .is_some()
    );
}

pub async fn domain_mark_verified_concurrent_single_winner(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let domain = unique_domain();
    let mut claims = Vec::new();
    for _ in 0..8 {
        let org = seed_org(s, tenant).await;
        let claim = new_org_domain(org.id, &domain, None);
        s.storage
            .organizations()
            .create_domain(tenant, &claim)
            .await
            .expect("create");
        claims.push(claim.id);
    }
    let claims = Arc::new(claims);
    let storage = Arc::clone(&s.storage);
    let results = race(8, |i| {
        let storage = Arc::clone(&storage);
        let claims = Arc::clone(&claims);
        async move {
            storage
                .organizations()
                .mark_verified(tenant, claims[i], now_ms())
                .await
        }
    })
    .await;
    let winners = results.iter().filter(|r| matches!(r, Ok(Some(_)))).count();
    assert_eq!(winners, 1, "exactly one org verifies the domain");
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Ok(Some(_)) | Err(StorageError::Conflict(_)))),
        "the losers get Conflict"
    );
    let mut verified = 0;
    for id in claims.iter() {
        let d = s
            .storage
            .organizations()
            .get_domain(tenant, *id)
            .await
            .expect("get")
            .expect("claim");
        if d.status == OrgDomainStatus::Verified {
            verified += 1;
        }
    }
    assert_eq!(verified, 1);
}

pub async fn domain_update_routing_connection_same_org_only(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let a = seed_org(s, tenant).await;
    let b = seed_org(s, tenant).await;
    let conn_a = seed_org_connection(s, tenant, a.id).await;
    let conn_b = seed_org_connection(s, tenant, b.id).await;
    let claim = new_org_domain(a.id, &unique_domain(), None);
    repo.create_domain(tenant, &claim).await.expect("create");

    let updated = repo
        .update_domain(
            tenant,
            claim.id,
            &OrgDomainUpdate {
                connection_id: Some(Some(conn_a.id)),
                routing: Some(true),
                allow_local_password: Some(false),
            },
            now_ms(),
        )
        .await
        .expect("update")
        .expect("claim exists");
    assert_eq!(updated.connection_id, Some(conn_a.id));
    assert!(updated.routing);
    assert!(!updated.allow_local_password);
    assert_eq!(
        repo.get_domain(tenant, claim.id).await.expect("get"),
        Some(updated.clone())
    );

    // Another org's connection: refused, nothing changed.
    assert_eq!(
        repo.update_domain(
            tenant,
            claim.id,
            &OrgDomainUpdate {
                connection_id: Some(Some(conn_b.id)),
                ..Default::default()
            },
            now_ms(),
        )
        .await
        .expect("update"),
        None
    );
    assert_eq!(
        repo.get_domain(tenant, claim.id).await.expect("get"),
        Some(updated.clone())
    );

    // Clearing the connection; an empty update keeps everything.
    let cleared = repo
        .update_domain(
            tenant,
            claim.id,
            &OrgDomainUpdate {
                connection_id: Some(None),
                routing: Some(false),
                ..Default::default()
            },
            now_ms(),
        )
        .await
        .expect("update")
        .expect("claim exists");
    assert_eq!(cleared.connection_id, None);
    assert!(!cleared.routing);
    assert!(!cleared.allow_local_password);
    assert_eq!(
        repo.update_domain(tenant, claim.id, &OrgDomainUpdate::default(), now_ms())
            .await
            .expect("update"),
        Some(cleared)
    );
    assert_eq!(
        repo.update_domain(
            tenant,
            OrgDomainId::new_v7(),
            &OrgDomainUpdate::default(),
            now_ms()
        )
        .await
        .expect("update unknown"),
        None
    );
}

pub async fn domain_routed_domain_requires_verified_routing_enabled_connection(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let connections = s.storage.connections();
    let org = seed_org(s, tenant).await;
    let conn = seed_org_connection(s, tenant, org.id).await;
    let domain = unique_domain();
    let claim = new_org_domain(org.id, &domain, Some(conn.id));
    repo.create_domain(tenant, &claim).await.expect("create");

    // Pending: no routing.
    assert_eq!(
        repo.routed_domain(tenant, &domain).await.expect("routed"),
        None
    );
    assert!(!repo.tenant_has_routing(tenant).await.expect("has routing"));

    repo.mark_verified(tenant, claim.id, now_ms())
        .await
        .expect("verify");
    let (d, c) = repo
        .routed_domain(tenant, &domain)
        .await
        .expect("routed")
        .expect("verified + routing + enabled");
    assert_eq!(d.id, claim.id);
    assert_eq!(c.id, conn.id);
    assert_eq!(c.org_id, Some(org.id));
    assert!(repo.tenant_has_routing(tenant).await.expect("has routing"));
    // Exact match only: a subdomain or a parent is not routed.
    assert_eq!(
        repo.routed_domain(tenant, &format!("sub.{domain}"))
            .await
            .expect("routed"),
        None
    );

    // Routing off: no route.
    repo.update_domain(
        tenant,
        claim.id,
        &OrgDomainUpdate {
            routing: Some(false),
            ..Default::default()
        },
        now_ms(),
    )
    .await
    .expect("update");
    assert_eq!(
        repo.routed_domain(tenant, &domain).await.expect("routed"),
        None
    );
    assert!(!repo.tenant_has_routing(tenant).await.expect("has routing"));
    repo.update_domain(
        tenant,
        claim.id,
        &OrgDomainUpdate {
            routing: Some(true),
            ..Default::default()
        },
        now_ms(),
    )
    .await
    .expect("update");

    // A disabled connection stops routing.
    connections
        .update(
            tenant,
            conn.id,
            &ConnectionUpdate {
                enabled: Some(false),
                ..Default::default()
            },
            now_ms(),
        )
        .await
        .expect("disable");
    assert_eq!(
        repo.routed_domain(tenant, &domain).await.expect("routed"),
        None
    );
    assert!(!repo.tenant_has_routing(tenant).await.expect("has routing"));
    connections
        .update(
            tenant,
            conn.id,
            &ConnectionUpdate {
                enabled: Some(true),
                ..Default::default()
            },
            now_ms(),
        )
        .await
        .expect("enable");
    assert!(
        repo.routed_domain(tenant, &domain)
            .await
            .expect("routed")
            .is_some()
    );

    // Routing without a connection: no route.
    repo.update_domain(
        tenant,
        claim.id,
        &OrgDomainUpdate {
            connection_id: Some(None),
            ..Default::default()
        },
        now_ms(),
    )
    .await
    .expect("update");
    assert_eq!(
        repo.routed_domain(tenant, &domain).await.expect("routed"),
        None
    );
}

pub async fn domain_record_check_failure_streak(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let claim = new_org_domain(org.id, &unique_domain(), None);
    repo.create_domain(tenant, &claim).await.expect("create");
    let t0 = now_ms();
    repo.mark_verified(tenant, claim.id, t0)
        .await
        .expect("verify");

    let t1 = t0 + Duration::days(1);
    let failed = repo
        .record_check(tenant, claim.id, false, t1)
        .await
        .expect("check")
        .expect("claim exists");
    assert_eq!(failed.failing_since, Some(t1));
    assert_eq!(failed.last_checked_at, Some(t1));
    assert_eq!(failed.status, OrgDomainStatus::Verified);

    let t2 = t1 + Duration::days(1);
    let still = repo
        .record_check(tenant, claim.id, false, t2)
        .await
        .expect("check")
        .expect("claim exists");
    assert_eq!(still.failing_since, Some(t1), "the streak start is kept");
    assert_eq!(still.last_checked_at, Some(t2));

    let t3 = t2 + Duration::days(1);
    let ok = repo
        .record_check(tenant, claim.id, true, t3)
        .await
        .expect("check")
        .expect("claim exists");
    assert_eq!(ok.failing_since, None, "a success clears the streak");
    assert_eq!(ok.last_checked_at, Some(t3));
    assert_eq!(ok.verified_at, Some(t0));
    assert_eq!(
        repo.record_check(tenant, OrgDomainId::new_v7(), true, t3)
            .await
            .expect("check unknown"),
        None
    );
}

pub async fn domain_unverify_stops_routing(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let other_org = seed_org(s, tenant).await;
    let conn = seed_org_connection(s, tenant, org.id).await;
    let domain = unique_domain();
    let claim = new_org_domain(org.id, &domain, Some(conn.id));
    repo.create_domain(tenant, &claim).await.expect("create");
    assert!(
        !repo
            .unverify(tenant, claim.id, now_ms())
            .await
            .expect("unverify pending"),
        "only verified claims can be unverified"
    );
    repo.mark_verified(tenant, claim.id, now_ms())
        .await
        .expect("verify");
    repo.record_check(tenant, claim.id, false, now_ms())
        .await
        .expect("check");

    let t = now_ms();
    assert!(repo.unverify(tenant, claim.id, t).await.expect("unverify"));
    let d = repo
        .get_domain(tenant, claim.id)
        .await
        .expect("get")
        .expect("claim kept");
    assert_eq!(d.status, OrgDomainStatus::Pending);
    assert_eq!(d.verified_at, None);
    assert_eq!(d.failing_since, None);
    assert_eq!(d.last_checked_at, Some(t));
    assert_eq!(
        repo.routed_domain(tenant, &domain).await.expect("routed"),
        None
    );
    assert!(
        repo.verified_domains_of_org(tenant, org.id)
            .await
            .expect("verified")
            .is_empty()
    );
    // The domain is free for another org now.
    let claim_b = new_org_domain(other_org.id, &domain, None);
    repo.create_domain(tenant, &claim_b).await.expect("create");
    assert!(
        repo.mark_verified(tenant, claim_b.id, now_ms())
            .await
            .expect("verify b")
            .is_some()
    );
    assert!(
        !repo
            .unverify(tenant, OrgDomainId::new_v7(), now_ms())
            .await
            .expect("unverify unknown")
    );
}

pub async fn domain_due_for_recheck_across_tenants(s: &TestStorage) {
    let t1 = seed_tenant(s).await;
    let t2 = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let o1 = seed_org(s, t1).await;
    let o2 = seed_org(s, t2).await;
    let base = now_ms() - Duration::days(30);

    // Two verified claims checked at different times, in two tenants.
    let old = new_org_domain(o1.id, &unique_domain(), None);
    repo.create_domain(t1, &old).await.expect("create");
    repo.mark_verified(t1, old.id, base).await.expect("verify");
    let older = new_org_domain(o2.id, &unique_domain(), None);
    repo.create_domain(t2, &older).await.expect("create");
    repo.mark_verified(t2, older.id, base - Duration::days(1))
        .await
        .expect("verify");
    // A fresh verified claim and a pending claim are not due.
    let fresh = new_org_domain(o1.id, &unique_domain(), None);
    repo.create_domain(t1, &fresh).await.expect("create");
    repo.mark_verified(t1, fresh.id, now_ms())
        .await
        .expect("verify");
    let pending = new_org_domain(o1.id, &unique_domain(), None);
    repo.create_domain(t1, &pending).await.expect("create");

    let cutoff = now_ms() - Duration::days(1);
    let due: Vec<OrgDomainId> = repo
        .due_for_recheck(cutoff, 1000)
        .await
        .expect("due")
        .into_iter()
        .map(|d| d.id)
        .filter(|id| [old.id, older.id, fresh.id, pending.id].contains(id))
        .collect();
    assert_eq!(
        due,
        vec![older.id, old.id],
        "verified only, checked before the cutoff, oldest check first, every tenant"
    );

    // The limit applies; after a check the claim is no longer due.
    assert!(repo.due_for_recheck(cutoff, 1).await.expect("due").len() <= 1);
    repo.record_check(t2, older.id, true, now_ms())
        .await
        .expect("check");
    assert!(
        !repo
            .due_for_recheck(cutoff, 1000)
            .await
            .expect("due")
            .iter()
            .any(|d| d.id == older.id)
    );
}

pub async fn domain_verified_domains_of_org(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let other = seed_org(s, tenant).await;
    let d1 = new_org_domain(org.id, &unique_domain(), None);
    let d2 = new_org_domain(org.id, &unique_domain(), None);
    let pending = new_org_domain(org.id, &unique_domain(), None);
    let foreign = new_org_domain(other.id, &unique_domain(), None);
    for d in [&d1, &d2, &pending, &foreign] {
        repo.create_domain(tenant, d).await.expect("create");
    }
    for d in [&d1, &d2, &foreign] {
        repo.mark_verified(tenant, d.id, now_ms())
            .await
            .expect("verify");
    }
    let mut want = vec![d1.domain.clone(), d2.domain.clone()];
    want.sort();
    assert_eq!(
        repo.verified_domains_of_org(tenant, org.id)
            .await
            .expect("verified"),
        want
    );
}

pub async fn domains_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let conn = seed_org_connection(s, tenant, org.id).await;
    let domain = unique_domain();
    let claim = new_org_domain(org.id, &domain, Some(conn.id));
    repo.create_domain(tenant, &claim).await.expect("create");
    repo.mark_verified(tenant, claim.id, now_ms())
        .await
        .expect("verify");

    assert_eq!(repo.get_domain(other, claim.id).await.expect("get"), None);
    assert!(
        repo.list_domains(other, org.id)
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(
        repo.routed_domain(other, &domain).await.expect("routed"),
        None
    );
    assert!(!repo.tenant_has_routing(other).await.expect("has routing"));
    assert!(
        repo.verified_domains_of_org(other, org.id)
            .await
            .expect("verified")
            .is_empty()
    );
    assert_eq!(
        repo.update_domain(other, claim.id, &OrgDomainUpdate::default(), now_ms())
            .await
            .expect("update"),
        None
    );
    assert_eq!(
        repo.mark_verified(other, claim.id, now_ms())
            .await
            .expect("verify"),
        None
    );
    assert_eq!(
        repo.record_check(other, claim.id, false, now_ms())
            .await
            .expect("check"),
        None
    );
    assert!(
        !repo
            .unverify(other, claim.id, now_ms())
            .await
            .expect("unverify")
    );
    assert!(!repo.delete_domain(other, claim.id).await.expect("delete"));
    // An org of another tenant cannot claim into this tenant's org.
    assert!(matches!(
        repo.create_domain(other, &new_org_domain(org.id, &unique_domain(), None))
            .await,
        Err(StorageError::Conflict(_))
    ));
    assert!(
        repo.routed_domain(tenant, &domain)
            .await
            .expect("routed")
            .is_some()
    );
}
