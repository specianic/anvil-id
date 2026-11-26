//! The daily re-check of verified organization domains (ORG-04; draft-ietf-dnsop-domain-verification
//! asks verifiers to re-validate and to document how often).
//!
//! [`DomainRecheckService::recheck_due`] walks every **verified** claim of the installation whose
//! last check is older than [`RECHECK_MIN_AGE`] (`OrgRepo::due_for_recheck`), oldest first, and runs
//! the one domain check ([`check_domain`]) against it:
//!
//! - the record is found: `record_check(ok = true)` (`last_checked_at = now`, the failure streak
//!   `failing_since` is cleared);
//! - it is not (any lookup error or mismatch): `record_check(ok = false)`, which starts the streak
//!   (`failing_since = now`) or keeps its start. Once the streak is at least
//!   [`DOMAIN_RECHECK_GRACE`] (7 days) old, the claim drops back to pending (`OrgRepo::unverify`):
//!   home-realm routing stops at once (routing only considers verified claims). The change is
//!   audited `org_domain_unverified` (actor system, target the domain id, the org and the domain in
//!   the details), which the webhook classification turns into
//!   `organization.domain_unverified`.
//!
//! A single failed check never unverifies: a DNS outage shorter than the grace period changes
//! nothing visible. Each claim is handled on its own; a storage error on one is reported in
//! [`RecheckReport::failures`] and the walk continues.
//!
//! The binary runs this as the leased periodic job [`DOMAIN_RECHECK_JOB`] every
//! [`RECHECK_INTERVAL`] (one run per period across nodes), so each verified domain is re-checked
//! about once a day.

use std::sync::Arc;

use time::Duration;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, DOMAIN_RECHECK_GRACE, OrgDomain,
    OrgDomainId, RequestContext,
};
use crate::ports::{DomainTxtLookup, Storage};
use crate::service::audit::AuditService;
use crate::service::domain_check::{DomainCheck, check_domain};

/// Lease name of the re-check job.
pub const DOMAIN_RECHECK_JOB: &str = "domain_recheck";
/// How often the job runs.
pub const RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
/// A claim is due when its last check is older than this. Slightly under the interval, so the
/// start jitter of the daily run never pushes a domain to the following day.
pub const RECHECK_MIN_AGE: Duration = Duration::hours(23);
/// Claims fetched per batch.
pub const RECHECK_BATCH: u32 = 200;
/// Batches per run at most (a run covers up to `RECHECK_BATCH * MAX_BATCHES` claims; the rest
/// are due first on the next run).
pub const MAX_BATCHES: u32 = 50;

/// What one run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecheckReport {
    /// Claims checked.
    pub checked: u32,
    /// Claims whose record was found.
    pub passed: u32,
    /// Claims whose check failed (streak started or continued).
    pub failed: u32,
    /// Claims dropped back to pending after the grace period.
    pub unverified: u32,
    /// Claims that could not be handled (storage error), with the error.
    pub failures: Vec<(OrgDomainId, String)>,
}

/// Re-checks verified domains (module docs).
#[derive(Clone)]
pub struct DomainRecheckService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub lookup: Arc<dyn DomainTxtLookup>,
}

impl DomainRecheckService {
    /// Re-checks up to `limit` due claims per batch, for at most [`MAX_BATCHES`] batches. Only a
    /// failure to list the due claims is an error.
    pub async fn recheck_due(&self, limit: u32) -> Result<RecheckReport, CoreError> {
        let mut report = RecheckReport::default();
        let limit = limit.max(1);
        for _ in 0..MAX_BATCHES {
            let now = self.clock.now();
            let due = self
                .storage
                .organizations()
                .due_for_recheck(now - RECHECK_MIN_AGE, limit)
                .await?;
            let full = u32::try_from(due.len()).unwrap_or(u32::MAX) >= limit;
            let mut progressed = false;
            for domain in &due {
                report.checked += 1;
                match self.recheck_one(domain, &mut report).await {
                    Ok(()) => progressed = true,
                    Err(e) => report.failures.push((domain.id, e.to_string())),
                }
            }
            // A batch where nothing could be recorded would be fetched again unchanged.
            if !full || !progressed {
                break;
            }
        }
        Ok(report)
    }

    async fn recheck_one(
        &self,
        domain: &OrgDomain,
        report: &mut RecheckReport,
    ) -> Result<(), CoreError> {
        let orgs = self.storage.organizations();
        let ok = check_domain(self.lookup.as_ref(), &domain.domain, &domain.token).await
            == DomainCheck::Verified;
        let now = self.clock.now();
        let Some(updated) = orgs
            .record_check(domain.tenant_id, domain.id, ok, now)
            .await?
        else {
            // Deleted meanwhile.
            return Ok(());
        };
        if ok {
            report.passed += 1;
            return Ok(());
        }
        report.failed += 1;
        let expired = updated
            .failing_since
            .is_some_and(|since| now - since >= DOMAIN_RECHECK_GRACE);
        if !expired || !orgs.unverify(domain.tenant_id, domain.id, now).await? {
            return Ok(());
        }
        report.unverified += 1;
        let details = match orgs.get(domain.tenant_id, domain.org_id).await? {
            Some(org) => AuditDetails::org(org.id, &org.slug),
            None => AuditDetails::empty(),
        }
        .with(AuditDetails::domain(&domain.domain));
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            domain.tenant_id,
            AuditActor::system(),
            AuditAction::OrgDomainUnverified,
            Some(domain.id.to_string()),
            AuditOutcome::Success,
            &RequestContext::system(),
            details,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cutoff_is_under_the_interval_and_the_grace_is_a_week() {
        let interval = Duration::try_from(RECHECK_INTERVAL).expect("fits");
        assert!(RECHECK_MIN_AGE < interval);
        assert!(RECHECK_MIN_AGE > interval - Duration::hours(2));
        assert_eq!(DOMAIN_RECHECK_GRACE, Duration::days(7));
    }
}
