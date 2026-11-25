//! JobRepo contract: installation-wide job leases.

use std::sync::Arc;

use anvil_core::model::JobName;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn job_lease_exclusive_renew_and_release(s: &TestStorage) {
    let jobs = s.storage.jobs();
    let name = JobName::KEY_ROTATION;
    let now = now_ms();
    let until = now + Duration::minutes(5);

    assert!(
        jobs.try_lease(name, "node-a", until, now)
            .await
            .expect("lease")
    );
    assert!(
        !jobs
            .try_lease(name, "node-b", until, now)
            .await
            .expect("lease"),
        "an unexpired lease of another owner blocks"
    );
    assert!(
        jobs.try_lease(name, "node-a", until + Duration::minutes(5), now)
            .await
            .expect("lease"),
        "the owner renews its lease"
    );
    assert!(
        jobs.try_lease(JobName::PURGE_EXPIRED, "node-b", until, now)
            .await
            .expect("lease"),
        "leases are per job"
    );

    assert!(
        !jobs.release(name, "node-b").await.expect("release"),
        "only the owner releases"
    );
    assert!(jobs.release(name, "node-a").await.expect("release"));
    assert!(
        !jobs.release(name, "node-a").await.expect("release"),
        "already released"
    );
    assert!(
        jobs.try_lease(name, "node-b", until, now)
            .await
            .expect("lease"),
        "a released job can be leased by anyone"
    );
}

pub async fn job_expired_lease_taken_over(s: &TestStorage) {
    let jobs = s.storage.jobs();
    let name = JobName::AUDIT_RETENTION;
    let now = now_ms();
    assert!(
        jobs.try_lease(name, "node-a", now + Duration::seconds(30), now)
            .await
            .expect("lease")
    );
    let later = now + Duration::seconds(30);
    assert!(
        jobs.try_lease(name, "node-b", later + Duration::minutes(1), later)
            .await
            .expect("lease"),
        "a lease with until <= now has expired"
    );
    assert!(
        !jobs
            .try_lease(name, "node-a", later + Duration::minutes(1), later)
            .await
            .expect("lease"),
        "the previous owner lost the lease"
    );
}

pub async fn job_lease_concurrent_single_holder(s: &TestStorage) {
    const N: usize = 16;
    const ROUNDS: usize = 5;
    for round in 0..ROUNDS {
        let name: Arc<str> = Arc::from(format!("contract-job-{round}"));
        let results = race(N, |i| {
            let storage = Arc::clone(&s.storage);
            let name = Arc::clone(&name);
            async move {
                let now = now_ms();
                storage
                    .jobs()
                    .try_lease(&name, &format!("node-{i}"), now + Duration::minutes(1), now)
                    .await
            }
        })
        .await;
        let won = results
            .iter()
            .map(|r| *r.as_ref().expect("no storage errors allowed"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(won, 1, "round {round}: exactly one concurrent lease holder");
    }
}
