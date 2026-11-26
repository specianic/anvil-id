//! Leased background jobs on SQLite: two runners sharing one storage never run the same job
//! concurrently, a held lease blocks other nodes, and the production jobs (rotation, purge,
//! audit retention, domain re-check) do their work when scheduled with short intervals.
//!
//! The domain re-check (ORG-04, plan 06-20) runs on real SQLite storage with a settable DNS TXT
//! fake defined here ([`FakeTxt`]): a passing check clears the failure streak, a failing check
//! starts it without unverifying, a streak older than the 7-day grace drops the domain to pending
//! (routing stops, audited, webhook queued), and the job runs once per period across nodes.

#[path = "../src/jobs.rs"]
#[allow(dead_code, reason = "the test uses only part of the module")]
mod jobs;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_core::clock::{Clock, SystemClock};
use anvil_core::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, AuditQuery, ConnectionConfig,
    ConnectionId, NewConnection, NewOrgDomain, NewOrganization, NewTenant, NewWebhookEndpoint,
    OidcConfig, OrgDomain, OrgDomainId, OrgDomainStatus, OrgId, OrgSettings, PageRequest,
    RequestContext, Tenant, TenantId, TenantSettings, WebhookEndpointId, WebhookEventType,
};
use anvil_core::policy::domain_verification::{record_name, record_value};
use anvil_core::ports::{DomainTxtLookup, Storage, TxtLookupError};
use anvil_core::service::audit::AuditService;
use anvil_core::service::domain_recheck::{DOMAIN_RECHECK_JOB, DomainRecheckService};
use anvil_core::service::key_rotation::RotationPolicy;
use anvil_jose::Kek;
use anvil_storage_sqlite::SqliteStorage;
use jobs::{DomainRecheckJob, JobIntervals, LeaseRunner, PeriodicJob};
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::task::JoinSet;

async fn storage(dir: &tempfile::TempDir) -> Arc<dyn Storage> {
    let url = format!("sqlite://{}", dir.path().join("jobs.db").display());
    let s = SqliteStorage::connect(&url).await.expect("connect");
    s.migrate().await.expect("migrate");
    Arc::new(s)
}

fn runner(storage: &Arc<dyn Storage>, node: &str) -> Arc<LeaseRunner> {
    Arc::new(LeaseRunner {
        storage: Arc::clone(storage),
        clock: Arc::new(SystemClock),
        node_id: node.to_owned(),
        lease: Duration::from_secs(60),
    })
}

/// Counts runs and records the highest number of runs in progress at once.
#[derive(Default)]
struct CountingJob {
    runs: AtomicUsize,
    running: AtomicUsize,
    max_running: AtomicUsize,
}

impl PeriodicJob for CountingJob {
    fn name(&self) -> &'static str {
        "counting_job"
    }

    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(30)).await;
            self.running.fetch_sub(1, Ordering::SeqCst);
            self.runs.fetch_add(1, Ordering::SeqCst);
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_runners_never_run_the_same_job_concurrently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let job = Arc::new(CountingJob::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut set = JoinSet::new();
    for node in ["node-a", "node-b"] {
        let r = runner(&storage, node);
        let job: Arc<dyn PeriodicJob> = Arc::clone(&job) as Arc<dyn PeriodicJob>;
        set.spawn(r.schedule(job, Duration::from_millis(5), stop_rx.clone()));
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    stop_tx.send(true).expect("stop");
    while set.join_next().await.is_some() {}

    let runs = job.runs.load(Ordering::SeqCst);
    assert!(runs >= 5, "the job ran only {runs} times");
    assert_eq!(
        job.max_running.load(Ordering::SeqCst),
        1,
        "two runners ran the job at the same time"
    );
}

#[tokio::test]
async fn a_held_lease_blocks_other_nodes_until_released() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    assert!(
        storage
            .jobs()
            .try_lease(
                "counting_job",
                "node-a",
                now + time::Duration::minutes(5),
                now
            )
            .await
            .expect("lease")
    );
    let job = CountingJob::default();
    let b = runner(&storage, "node-b");
    assert!(
        !b.run_once(&job).await,
        "node-b ran while node-a held the lease"
    );
    assert_eq!(job.runs.load(Ordering::SeqCst), 0);

    storage
        .jobs()
        .release("counting_job", "node-a")
        .await
        .expect("release");
    assert!(b.run_once(&job).await);
    assert_eq!(job.runs.load(Ordering::SeqCst), 1);
    // run_once releases its lease: node-a can take it again.
    let a = runner(&storage, "node-a");
    assert!(a.run_once(&job).await);
}

/// A clock fixed at one instant (records old audit events).
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

async fn audit_count(storage: &Arc<dyn Storage>, tenant: TenantId) -> usize {
    storage
        .audit()
        .query(
            tenant,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("query")
        .items
        .len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_jobs_rotate_purge_and_apply_audit_retention() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    let tenant = storage
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
            host: None,
            settings: TenantSettings::default(),
            created_at: now,
        })
        .await
        .expect("tenant");
    assert!(
        storage
            .keys()
            .active(tenant.id, "RS256")
            .await
            .expect("active")
            .is_none()
    );

    // One event older than the retention, one recent.
    for at in [now - time::Duration::days(400), now] {
        AuditService {
            storage: Arc::clone(&storage),
            clock: Arc::new(FixedClock(at)),
        }
        .record(
            tenant.id,
            AuditActor::system(),
            AuditAction::TenantUpdated,
            None,
            AuditOutcome::Success,
            &RequestContext::system(),
            AuditDetails::empty(),
        )
        .await
        .expect("record");
    }
    assert_eq!(audit_count(&storage, tenant.id).await, 2);
    // A verified domain last checked two days ago, whose record is published.
    let org = create_org(&storage, &tenant, now).await;
    let domain = verified_domain(&storage, &tenant, org, None, now - time::Duration::days(2)).await;
    let txt = FakeTxt::default();
    txt.publish(&domain);

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut set = JoinSet::new();
    let r = runner(&storage, "node-a");
    jobs::spawn_periodic(
        &mut set,
        &r,
        &Arc::new(Kek::generate()),
        RotationPolicy::default(),
        Some(time::Duration::days(365)),
        &(Arc::new(txt.clone()) as Arc<dyn DomainTxtLookup>),
        JobIntervals {
            rotation: Duration::from_millis(50),
            purge: Duration::from_millis(50),
            audit_retention: Duration::from_millis(50),
            domain_recheck: Duration::from_millis(50),
        },
        &stop_rx,
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rotated = storage
            .keys()
            .active(tenant.id, "RS256")
            .await
            .expect("active")
            .is_some();
        // The rotation job audits key_generated/key_activated; retention removed the old event.
        let events = storage
            .audit()
            .query(
                tenant.id,
                &AuditQuery {
                    limit: 200,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("query")
            .items;
        let old_gone = events
            .iter()
            .all(|e| e.at > now - time::Duration::days(365));
        let rechecked = get_domain(&storage, &domain)
            .await
            .last_checked_at
            .is_some_and(|at| at >= now);
        if rotated && old_gone && rechecked {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "jobs did not run: rotated={rotated} old_gone={old_gone} rechecked={rechecked}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop_tx.send(true).expect("stop");
    tokio::time::timeout(Duration::from_secs(10), async {
        while set.join_next().await.is_some() {}
    })
    .await
    .expect("jobs stop on shutdown");
    // Leases are released after each run.
    let later = SystemClock.now();
    for name in [
        "key_rotation",
        "purge_expired",
        "audit_retention",
        DOMAIN_RECHECK_JOB,
    ] {
        assert!(
            storage
                .jobs()
                .try_lease(name, "node-b", later + time::Duration::minutes(1), later)
                .await
                .expect("lease"),
            "{name} lease still held"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Domain re-check (ORG-04)
// ---------------------------------------------------------------------------------------------

/// Settable DNS TXT records keyed by FQDN (test double). Unknown names are NXDOMAIN.
#[derive(Clone, Default)]
struct FakeTxt(Arc<Mutex<HashMap<String, Vec<String>>>>);

impl FakeTxt {
    /// Publishes the domain's challenge record.
    fn publish(&self, domain: &OrgDomain) {
        self.0.lock().unwrap().insert(
            record_name(&domain.domain).trim_end_matches('.').to_owned(),
            vec![record_value(&domain.token)],
        );
    }
}

// The port is an `async_trait`; this crate has no `async-trait` dependency, so the impl is
// written in its expanded form.
impl DomainTxtLookup for FakeTxt {
    fn txt<'life0, 'life1, 'async_trait>(
        &'life0 self,
        fqdn: &'life1 str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<u8>>, TxtLookupError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let answer = self
            .0
            .lock()
            .unwrap()
            .get(fqdn.trim_end_matches('.'))
            .map(|v| v.iter().map(|r| r.as_bytes().to_vec()).collect())
            .ok_or(TxtLookupError::NotFound);
        Box::pin(async move { answer })
    }
}

async fn create_tenant(storage: &Arc<dyn Storage>, now: OffsetDateTime) -> Tenant {
    storage
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: format!("t{}", &uuid::Uuid::now_v7().simple().to_string()[24..]),
            display_name: "Acme".to_owned(),
            host: None,
            settings: TenantSettings::default(),
            created_at: now,
        })
        .await
        .expect("tenant")
}

async fn create_org(storage: &Arc<dyn Storage>, tenant: &Tenant, now: OffsetDateTime) -> OrgId {
    storage
        .organizations()
        .create(
            tenant.id,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: "globex".to_owned(),
                display_name: "Globex".to_owned(),
                mfa_policy: None,
                settings: OrgSettings::default(),
                metadata: serde_json::json!({}),
                created_at: now,
            },
        )
        .await
        .expect("org")
        .id
}

/// An enabled OIDC connection of the org.
async fn org_connection(
    storage: &Arc<dyn Storage>,
    tenant: &Tenant,
    org: OrgId,
    now: OffsetDateTime,
) -> ConnectionId {
    storage
        .connections()
        .create(
            tenant.id,
            &NewConnection {
                id: ConnectionId::new_v7(),
                org_id: Some(org),
                slug: "globex-sso".to_owned(),
                display_name: "Globex SSO".to_owned(),
                enabled: true,
                config: ConnectionConfig::Oidc(OidcConfig {
                    issuer: "https://idp.globex.example".to_owned(),
                    client_id: "anvil".to_owned(),
                    scopes: vec!["openid".to_owned(), "email".to_owned()],
                    use_pkce: true,
                    fetch_userinfo: false,
                }),
                secret_enc: Some(vec![7; 48]),
                trust_email_verified: false,
                created_at: now,
            },
        )
        .await
        .expect("connection")
        .id
}

/// A domain claim verified at `verified_at` (routing to `connection` when given).
async fn verified_domain(
    storage: &Arc<dyn Storage>,
    tenant: &Tenant,
    org: OrgId,
    connection: Option<ConnectionId>,
    verified_at: OffsetDateTime,
) -> OrgDomain {
    let orgs = storage.organizations();
    let claim = orgs
        .create_domain(
            tenant.id,
            &NewOrgDomain {
                id: OrgDomainId::new_v7(),
                org_id: org,
                domain: "globex.example".to_owned(),
                token: format!("tok{}", uuid::Uuid::now_v7().simple()),
                connection_id: connection,
                routing: connection.is_some(),
                allow_local_password: true,
                created_at: verified_at,
            },
        )
        .await
        .expect("claim");
    let d = orgs
        .mark_verified(tenant.id, claim.id, verified_at)
        .await
        .expect("verify")
        .expect("exists");
    assert_eq!(d.status, OrgDomainStatus::Verified);
    d
}

async fn get_domain(storage: &Arc<dyn Storage>, d: &OrgDomain) -> OrgDomain {
    storage
        .organizations()
        .get_domain(d.tenant_id, d.id)
        .await
        .expect("get")
        .expect("exists")
}

fn recheck(storage: &Arc<dyn Storage>, txt: &FakeTxt, now: OffsetDateTime) -> DomainRecheckService {
    DomainRecheckService {
        storage: Arc::clone(storage),
        clock: Arc::new(FixedClock(now)),
        lookup: Arc::new(txt.clone()),
    }
}

async fn unverified_events(storage: &Arc<dyn Storage>, tenant: TenantId) -> Vec<String> {
    storage
        .audit()
        .query(
            tenant,
            &AuditQuery {
                action: Some(AuditAction::OrgDomainUnverified),
                limit: 50,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("query")
        .items
        .into_iter()
        .filter_map(|e| e.target)
        .collect()
}

#[tokio::test]
async fn recheck_keeps_passing_domain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    let tenant = create_tenant(&storage, now).await;
    let org = create_org(&storage, &tenant, now).await;
    let d = verified_domain(&storage, &tenant, org, None, now - time::Duration::days(10)).await;
    // A failure streak from three days ago...
    storage
        .organizations()
        .record_check(tenant.id, d.id, false, now - time::Duration::days(3))
        .await
        .unwrap();
    let txt = FakeTxt::default();
    txt.publish(&d);

    // ...is cleared by a passing check.
    let report = recheck(&storage, &txt, now).recheck_due(10).await.unwrap();
    assert_eq!((report.checked, report.passed, report.failed), (1, 1, 0));
    let after = get_domain(&storage, &d).await;
    assert_eq!(after.status, OrgDomainStatus::Verified);
    assert_eq!(after.failing_since, None);
    assert_eq!(after.last_checked_at, Some(now));
    // Checked just now: not due again within the day.
    let again = recheck(&storage, &txt, now + time::Duration::hours(1))
        .recheck_due(10)
        .await
        .unwrap();
    assert_eq!(again.checked, 0);
}

#[tokio::test]
async fn recheck_failure_starts_streak_without_unverifying() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    let tenant = create_tenant(&storage, now).await;
    let org = create_org(&storage, &tenant, now).await;
    let conn = org_connection(&storage, &tenant, org, now).await;
    let d = verified_domain(
        &storage,
        &tenant,
        org,
        Some(conn),
        now - time::Duration::days(10),
    )
    .await;
    let txt = FakeTxt::default(); // record removed

    let report = recheck(&storage, &txt, now).recheck_due(10).await.unwrap();
    assert_eq!(
        (report.checked, report.failed, report.unverified),
        (1, 1, 0)
    );
    let after = get_domain(&storage, &d).await;
    assert_eq!(after.status, OrgDomainStatus::Verified);
    assert_eq!(after.failing_since, Some(now));
    // Still routing.
    assert!(
        storage
            .organizations()
            .routed_domain(tenant.id, "globex.example")
            .await
            .unwrap()
            .is_some()
    );

    // Six days of daily failures later the streak keeps its start and nothing changes.
    let mut at = now;
    for _ in 0..6 {
        at += time::Duration::days(1);
        recheck(&storage, &txt, at).recheck_due(10).await.unwrap();
    }
    let after = get_domain(&storage, &d).await;
    assert_eq!(after.status, OrgDomainStatus::Verified);
    assert_eq!(after.failing_since, Some(now));
    assert!(unverified_events(&storage, tenant.id).await.is_empty());
}

#[tokio::test]
async fn recheck_unverifies_after_grace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    let tenant = create_tenant(&storage, now).await;
    let org = create_org(&storage, &tenant, now).await;
    let conn = org_connection(&storage, &tenant, org, now).await;
    let d = verified_domain(
        &storage,
        &tenant,
        org,
        Some(conn),
        now - time::Duration::days(20),
    )
    .await;
    let endpoint = storage
        .webhooks()
        .create_endpoint(
            tenant.id,
            &NewWebhookEndpoint {
                id: WebhookEndpointId::new_v7(),
                name: "domains".to_owned(),
                url: "https://hooks.example.test/anvil".to_owned(),
                events: vec![WebhookEventType::OrganizationDomainUnverified],
                enabled: true,
                secret_enc: vec![1; 48],
                created_at: now,
            },
        )
        .await
        .expect("endpoint");
    // The record has been missing for eight days.
    storage
        .organizations()
        .record_check(tenant.id, d.id, false, now - time::Duration::days(8))
        .await
        .unwrap();
    assert!(
        storage
            .organizations()
            .routed_domain(tenant.id, "globex.example")
            .await
            .unwrap()
            .is_some()
    );

    let report = recheck(&storage, &FakeTxt::default(), now)
        .recheck_due(10)
        .await
        .unwrap();
    assert_eq!((report.failed, report.unverified), (1, 1), "{report:?}");
    let after = get_domain(&storage, &d).await;
    assert_eq!(after.status, OrgDomainStatus::Pending);
    assert_eq!(after.verified_at, None);
    assert_eq!(after.failing_since, None);
    // Routing stopped.
    assert!(
        storage
            .organizations()
            .routed_domain(tenant.id, "globex.example")
            .await
            .unwrap()
            .is_none()
    );
    // Audited once, with the domain as target, and queued as the webhook.
    assert_eq!(
        unverified_events(&storage, tenant.id).await,
        [d.id.to_string()]
    );
    let deliveries = storage
        .webhooks()
        .deliveries(
            tenant.id,
            endpoint.id,
            PageRequest {
                after: None,
                limit: 10,
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(deliveries.len(), 1);
    assert_eq!(
        deliveries[0].event_type,
        WebhookEventType::OrganizationDomainUnverified
    );
    assert!(deliveries[0].payload_json.contains(&d.id.to_string()));
    // A pending claim is no longer re-checked.
    let again = recheck(&storage, &FakeTxt::default(), now + time::Duration::days(2))
        .recheck_due(10)
        .await
        .unwrap();
    assert_eq!(again.checked, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recheck_job_is_leased() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    let tenant = create_tenant(&storage, now).await;
    let org = create_org(&storage, &tenant, now).await;
    let d = verified_domain(&storage, &tenant, org, None, now - time::Duration::days(3)).await;
    let txt = FakeTxt::default();
    txt.publish(&d);
    let job = || DomainRecheckJob(recheck(&storage, &txt, SystemClock.now()));
    assert_eq!(job().name(), "domain_recheck");

    // Another node holds the lease: nothing is checked.
    assert!(
        storage
            .jobs()
            .try_lease(
                DOMAIN_RECHECK_JOB,
                "node-a",
                now + time::Duration::minutes(5),
                now
            )
            .await
            .unwrap()
    );
    let b = runner(&storage, "node-b");
    assert!(!b.run_once(&job()).await);
    assert_eq!(
        get_domain(&storage, &d).await.last_checked_at,
        Some(now - time::Duration::days(3))
    );
    storage
        .jobs()
        .release(DOMAIN_RECHECK_JOB, "node-a")
        .await
        .unwrap();

    // Two nodes in the same period: one runs, the other finds nothing due.
    let a = runner(&storage, "node-a");
    let (job_a, job_b) = (job(), job());
    let (ran_a, ran_b) = tokio::join!(a.run_once(&job_a), b.run_once(&job_b));
    assert!(ran_a || ran_b);
    let checked = get_domain(&storage, &d).await.last_checked_at.unwrap();
    assert!(checked >= now, "the domain was re-checked");
    // Whoever ran second (if the lease was free again) found nothing due: one check per period.
    let report = recheck(&storage, &txt, SystemClock.now())
        .recheck_due(10)
        .await
        .unwrap();
    assert_eq!(report.checked, 0);
}
