//! Scheduled signing-key rotation (SEC-02, OIDC-11).
//!
//! [`plan_rotation`] is a pure function from a tenant's key rows, its enabled algorithms, the
//! current time and a [`RotationPolicy`] to a list of [`KeyAction`]s. [`KeyRotationService`]
//! applies those actions through [`KeyRepo`](crate::ports::KeyRepo) and audits each one.
//!
//! # Lifecycle of a key
//!
//! 1. **Next**: generated `period − prepublish` after the active key was activated. It is already
//!    in the JWKS but does not sign.
//! 2. **Active**: promoted once it has been published for at least `prepublish` and the current
//!    active key is `period` old. Promotion is [`KeyRepo::promote`](crate::ports::KeyRepo::promote):
//!    two statements in one transaction (retire, then activate).
//! 3. **Retired**: stays in the JWKS until `expires_at = retired_at + retire_grace` (longest token
//!    lifetime plus clock skew), so tokens it signed keep verifying.
//! 4. Deleted once `expires_at <= now`.
//!
//! `prepublish ≥` [`JWKS_MAX_AGE`] guarantees that every relying party which caches the JWKS for
//! at most one `max-age` has seen a key before the first token signed with it arrives.
//!
//! # Concurrency
//!
//! `run_once` is safe to run on several instances at once: a second active key is refused by the
//! partial unique index (`Conflict`, treated as "another runner won"), a stale promotion returns
//! `false` and changes nothing, and `delete_expired` is idempotent. The worst outcome of a race is
//! an extra `Next` key, which is promoted in a later period. The job lease (03-24) removes even
//! that.

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::keys::Alg;
use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, KeyState, PageRequest, RequestContext,
    SigningKey, SigningKeyId, Tenant, TenantId,
};
use crate::ports::{Clock, Storage, StorageError};
use crate::service::audit::AuditService;
use crate::service::claims::{ACCESS_TOKEN_TTL, ID_TOKEN_TTL};
use crate::service::tenant::seal_new_key_for;

/// How long relying parties may cache the JWKS (`Cache-Control: max-age` of `/jwks`).
pub const JWKS_MAX_AGE: Duration = Duration::hours(1);

/// Clock skew tolerated when a relying party validates a token signed by a retired key.
pub const RETIRE_SKEW: Duration = Duration::minutes(5);

/// Default rotation period of an active key.
pub const DEFAULT_PERIOD: Duration = Duration::days(90);

/// Default time a next key is published before it may sign.
pub const DEFAULT_PREPUBLISH: Duration = Duration::days(7);

/// The longest lifetime of a JWT signed by an active key.
fn max_token_ttl() -> Duration {
    if ID_TOKEN_TTL > ACCESS_TOKEN_TTL {
        ID_TOKEN_TTL
    } else {
        ACCESS_TOKEN_TTL
    }
}

/// Rotation timings. Built with [`RotationPolicy::new`], which enforces the invariants, or
/// [`Default`] (90 days, 7 days, 1 h + 5 min).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    period: Duration,
    prepublish: Duration,
    retire_grace: Duration,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            period: DEFAULT_PERIOD,
            prepublish: DEFAULT_PREPUBLISH,
            retire_grace: max_token_ttl() + RETIRE_SKEW,
        }
    }
}

impl RotationPolicy {
    /// A policy with the given timings.
    ///
    /// Rejects `prepublish < JWKS_MAX_AGE` (a key could sign before caches have seen it),
    /// `period <= prepublish` (a next key would be due before the active one is activated) and
    /// `retire_grace <` the longest token lifetime plus [`RETIRE_SKEW`] (tokens would outlive
    /// their key).
    pub fn new(
        period: Duration,
        prepublish: Duration,
        retire_grace: Duration,
    ) -> Result<Self, CoreError> {
        let invalid = |field: &'static str, message: &str| CoreError::Validation {
            field,
            message: message.to_owned(),
        };
        if prepublish < JWKS_MAX_AGE {
            return Err(invalid(
                "prepublish",
                "must be at least the JWKS cache lifetime (1 hour)",
            ));
        }
        if period <= prepublish {
            return Err(invalid("period", "must be longer than prepublish"));
        }
        if retire_grace < max_token_ttl() + RETIRE_SKEW {
            return Err(invalid(
                "retire_grace",
                "must cover the longest token lifetime plus 5 minutes of clock skew",
            ));
        }
        Ok(Self {
            period,
            prepublish,
            retire_grace,
        })
    }

    pub fn period(&self) -> Duration {
        self.period
    }

    pub fn prepublish(&self) -> Duration {
        self.prepublish
    }

    pub fn retire_grace(&self) -> Duration {
        self.retire_grace
    }
}

/// One step of a rotation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAction {
    /// Generate a key for `alg` in `state` (`Active` when the algorithm has no active key,
    /// `Next` when the active key is due for rotation).
    Generate { alg: Alg, state: KeyState },
    /// Retire the active key (with `retire_expires_at`) and activate the next key.
    Promote {
        alg: String,
        retire: SigningKeyId,
        retire_kid: String,
        retire_expires_at: OffsetDateTime,
        activate: SigningKeyId,
        activate_kid: String,
    },
    /// Delete an expired retired key.
    Delete {
        id: SigningKeyId,
        kid: String,
        alg: String,
    },
}

fn activated(key: &SigningKey) -> OffsetDateTime {
    key.activated_at.unwrap_or(key.created_at)
}

/// The rotation plan for one tenant. Pure: no I/O, no clock.
///
/// Per enabled algorithm (in the order given):
/// - no active key → `Generate { alg, Active }`;
/// - active key at least `period − prepublish` old and no next key → `Generate { alg, Next }`;
/// - next key published for at least `prepublish` and active key at least `period` old →
///   `Promote` (the old key expires `retire_grace` from now). A key never signs before it has
///   been published for `prepublish`.
///
/// Keys of algorithms that are not enabled are neither generated nor rotated; an active key is
/// never deleted. Then, for every algorithm: retired keys with `expires_at <= now` → `Delete`.
pub fn plan_rotation(
    keys: &[SigningKey],
    algs: &[Alg],
    now: OffsetDateTime,
    policy: &RotationPolicy,
) -> Vec<KeyAction> {
    let mut actions = Vec::new();
    let mut seen: Vec<Alg> = Vec::new();
    for &alg in algs {
        if seen.contains(&alg) {
            continue;
        }
        seen.push(alg);
        let of_alg = |state: KeyState| {
            keys.iter()
                .filter(move |k| k.alg == alg.as_str() && k.state == state)
        };
        let Some(active) = of_alg(KeyState::Active).max_by_key(|k| activated(k)) else {
            actions.push(KeyAction::Generate {
                alg,
                state: KeyState::Active,
            });
            continue;
        };
        let active_age = now - activated(active);
        match of_alg(KeyState::Next).min_by_key(|k| (k.created_at, k.id)) {
            None => {
                if active_age >= policy.period - policy.prepublish {
                    actions.push(KeyAction::Generate {
                        alg,
                        state: KeyState::Next,
                    });
                }
            }
            Some(next) => {
                if now - next.created_at >= policy.prepublish && active_age >= policy.period {
                    actions.push(KeyAction::Promote {
                        alg: alg.as_str().to_owned(),
                        retire: active.id,
                        retire_kid: active.kid.clone(),
                        retire_expires_at: now + policy.retire_grace,
                        activate: next.id,
                        activate_kid: next.kid.clone(),
                    });
                }
            }
        }
    }
    for key in keys {
        if key.state == KeyState::Retired && key.expires_at.is_some_and(|e| e <= now) {
            actions.push(KeyAction::Delete {
                id: key.id,
                kid: key.kid.clone(),
                alg: key.alg.clone(),
            });
        }
    }
    actions
}

/// The tenant's enabled signing algorithms (RS256 always first). An unknown algorithm name in
/// the settings is an internal error, never silently skipped.
pub fn enabled_algs(tenant: &Tenant) -> Result<Vec<Alg>, CoreError> {
    tenant
        .settings
        .effective_signing_algs()
        .iter()
        .map(|a| {
            a.parse::<Alg>().map_err(|_| {
                CoreError::Internal(format!("tenant {} enables unknown alg {a}", tenant.slug))
            })
        })
        .collect()
}

/// What one rotation run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationReport {
    pub tenants: u32,
    pub generated: u32,
    pub promoted: u32,
    pub deleted: u64,
    /// Tenants whose rotation failed, with the error. Other tenants are still rotated; the
    /// caller logs these.
    pub failures: Vec<(TenantId, String)>,
}

/// Applies rotation plans with audit.
#[derive(Clone)]
pub struct KeyRotationService {
    pub storage: Arc<dyn Storage>,
    pub kek: Arc<Kek>,
    pub clock: Arc<dyn Clock>,
    pub policy: RotationPolicy,
}

const TENANT_PAGE: u32 = 100;

impl KeyRotationService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    async fn record(
        &self,
        tenant: TenantId,
        actor: &AuditActor,
        action: AuditAction,
        kid: &str,
        alg: &str,
    ) -> Result<(), CoreError> {
        self.audit()
            .record(
                tenant,
                actor.clone(),
                action,
                Some(kid.to_owned()),
                AuditOutcome::Success,
                &RequestContext::system(),
                AuditDetails::key(kid, alg),
            )
            .await
    }

    /// Rotates every tenant once. A failure for one tenant is collected in the report and does
    /// not stop the others; only failing to list tenants is an error.
    pub async fn run_once(&self) -> Result<RotationReport, CoreError> {
        let mut report = RotationReport::default();
        let mut after = None;
        loop {
            let page = self
                .storage
                .tenants()
                .list(PageRequest {
                    after,
                    limit: TENANT_PAGE,
                })
                .await?;
            for tenant in &page.items {
                report.tenants += 1;
                if let Err(e) = self.rotate_tenant(tenant, &mut report).await {
                    report.failures.push((tenant.id, e.to_string()));
                }
            }
            match page.next_cursor {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        Ok(report)
    }

    async fn rotate_tenant(
        &self,
        tenant: &Tenant,
        report: &mut RotationReport,
    ) -> Result<(), CoreError> {
        let algs = enabled_algs(tenant)?;
        let now = self.clock.now();
        let keys = self.storage.keys().list(tenant.id).await?;
        let actor = AuditActor::system();
        let mut delete = false;
        for action in plan_rotation(&keys, &algs, now, &self.policy) {
            match action {
                KeyAction::Generate { alg, state } => {
                    if self.generate(tenant.id, alg, state, now, &actor).await? {
                        report.generated += 1;
                    }
                }
                KeyAction::Promote {
                    alg,
                    retire,
                    retire_kid,
                    retire_expires_at,
                    activate,
                    activate_kid,
                } => {
                    let promoted = self
                        .storage
                        .keys()
                        .promote(tenant.id, Some((retire, retire_expires_at)), activate, now)
                        .await;
                    match promoted {
                        Ok(true) => {
                            report.promoted += 1;
                            self.record(
                                tenant.id,
                                &actor,
                                AuditAction::KeyRetired,
                                &retire_kid,
                                &alg,
                            )
                            .await?;
                            self.record(
                                tenant.id,
                                &actor,
                                AuditAction::KeyActivated,
                                &activate_kid,
                                &alg,
                            )
                            .await?;
                        }
                        // Another runner promoted first: nothing changed here.
                        Ok(false) | Err(StorageError::Conflict(_)) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                KeyAction::Delete { .. } => delete = true,
            }
        }
        if delete {
            report.deleted += self.storage.keys().delete_expired(tenant.id, now).await?;
        }
        Ok(())
    }

    /// Generates and stores a key. `false` if an `Active` key lost a race against another
    /// runner (several nodes starting together on one database): the index refused a second
    /// active key and the winner's key is now active. Only the winner audits. A conflict with no
    /// active key behind it is a real error and is returned, never treated as success.
    async fn generate(
        &self,
        tenant: TenantId,
        alg: Alg,
        state: KeyState,
        now: OffsetDateTime,
        actor: &AuditActor,
    ) -> Result<bool, CoreError> {
        let key = seal_new_key_for(&self.kek, tenant, alg, now, state)?;
        match self.storage.keys().insert(tenant, &key).await {
            Ok(()) => {}
            Err(StorageError::Conflict(msg)) if state == KeyState::Active => {
                return match self.storage.keys().active(tenant, alg.as_str()).await? {
                    Some(_) => Ok(false),
                    None => Err(StorageError::Conflict(msg).into()),
                };
            }
            Err(e) => return Err(e.into()),
        }
        self.record(
            tenant,
            actor,
            AuditAction::KeyGenerated,
            &key.kid,
            alg.as_str(),
        )
        .await?;
        if state == KeyState::Active {
            self.record(
                tenant,
                actor,
                AuditAction::KeyActivated,
                &key.kid,
                alg.as_str(),
            )
            .await?;
        }
        Ok(true)
    }

    /// Generates an active key for every enabled algorithm of `tenant` that has none (startup,
    /// and when a tenant enables an algorithm). Never rotates. Returns the number generated.
    pub async fn ensure_tenant(&self, tenant: &Tenant) -> Result<u32, CoreError> {
        let algs = enabled_algs(tenant)?;
        let now = self.clock.now();
        let actor = AuditActor::system();
        let mut generated = 0;
        for alg in algs {
            if self
                .storage
                .keys()
                .active(tenant.id, alg.as_str())
                .await?
                .is_none()
                && self
                    .generate(tenant.id, alg, KeyState::Active, now, &actor)
                    .await?
            {
                generated += 1;
            }
        }
        Ok(generated)
    }

    /// On-demand rotation of `alg` for `tenant`, audited as `key_rotation_requested` by `actor`.
    /// Returns the kid of the key that will sign next.
    ///
    /// - `immediate = false`: a next key is created now (or the existing next key is kept); the
    ///   scheduled job promotes it once it has been published for `prepublish`.
    /// - `immediate = true` (key compromise): a new key is generated and promoted at once; the old
    ///   active key is retired with `expires_at = now`, so it leaves the JWKS immediately and
    ///   tokens it signed stop verifying.
    ///
    /// The algorithm must be enabled for the tenant.
    pub async fn rotate_now(
        &self,
        tenant: &Tenant,
        alg: Alg,
        immediate: bool,
        actor: AuditActor,
    ) -> Result<String, CoreError> {
        if !enabled_algs(tenant)?.contains(&alg) {
            return Err(CoreError::Validation {
                field: "alg",
                message: format!("{} is not enabled for this tenant", alg.as_str()),
            });
        }
        let now = self.clock.now();
        let keys = self.storage.keys();
        let active = keys.active(tenant.id, alg.as_str()).await?;
        let target = active.as_ref().map_or_else(String::new, |k| k.kid.clone());
        self.record(
            tenant.id,
            &actor,
            AuditAction::KeyRotationRequested,
            &target,
            alg.as_str(),
        )
        .await?;

        if !immediate {
            let existing_next = keys
                .list(tenant.id)
                .await?
                .into_iter()
                .filter(|k| k.alg == alg.as_str() && k.state == KeyState::Next)
                .min_by_key(|k| (k.created_at, k.id));
            if let Some(next) = existing_next {
                return Ok(next.kid);
            }
            let state = if active.is_some() {
                KeyState::Next
            } else {
                KeyState::Active
            };
            let key = seal_new_key_for(&self.kek, tenant.id, alg, now, state)?;
            keys.insert(tenant.id, &key).await?;
            self.record(
                tenant.id,
                &actor,
                AuditAction::KeyGenerated,
                &key.kid,
                alg.as_str(),
            )
            .await?;
            if state == KeyState::Active {
                self.record(
                    tenant.id,
                    &actor,
                    AuditAction::KeyActivated,
                    &key.kid,
                    alg.as_str(),
                )
                .await?;
            }
            return Ok(key.kid);
        }

        let key = seal_new_key_for(&self.kek, tenant.id, alg, now, KeyState::Next)?;
        keys.insert(tenant.id, &key).await?;
        self.record(
            tenant.id,
            &actor,
            AuditAction::KeyGenerated,
            &key.kid,
            alg.as_str(),
        )
        .await?;
        let retire = active.as_ref().map(|a| (a.id, now));
        if !keys.promote(tenant.id, retire, key.id, now).await? {
            return Err(CoreError::Conflict(
                "the active key changed during rotation; retry".to_owned(),
            ));
        }
        if let Some(old) = &active {
            self.record(
                tenant.id,
                &actor,
                AuditAction::KeyRetired,
                &old.kid,
                alg.as_str(),
            )
            .await?;
        }
        self.record(
            tenant.id,
            &actor,
            AuditAction::KeyActivated,
            &key.kid,
            alg.as_str(),
        )
        .await?;
        Ok(key.kid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn key(alg: Alg, state: KeyState, created: OffsetDateTime) -> SigningKey {
        SigningKey {
            id: SigningKeyId::new_v7(),
            tenant_id: TenantId::new_v7(),
            kid: format!("kid-{}", SigningKeyId::new_v7()),
            alg: alg.as_str().to_owned(),
            state,
            private_key_enc: vec![],
            public_jwk: String::new(),
            created_at: created,
            activated_at: (state != KeyState::Next).then_some(created),
            retired_at: None,
            expires_at: None,
        }
    }

    fn p() -> RotationPolicy {
        RotationPolicy::default()
    }

    #[test]
    fn defaults_are_90_days_7_days_and_token_lifetime_plus_skew() {
        let policy = p();
        assert_eq!(policy.period(), Duration::days(90));
        assert_eq!(policy.prepublish(), Duration::days(7));
        assert_eq!(
            policy.retire_grace(),
            Duration::hours(1) + Duration::minutes(5)
        );
        assert_eq!(
            RotationPolicy::new(policy.period(), policy.prepublish(), policy.retire_grace())
                .unwrap(),
            policy
        );
    }

    #[test]
    fn policy_rejects_prepublish_shorter_than_jwks_max_age() {
        let grace = p().retire_grace();
        let err = RotationPolicy::new(
            Duration::days(1),
            JWKS_MAX_AGE - Duration::seconds(1),
            grace,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Validation {
                field: "prepublish",
                ..
            }
        ));
        assert!(RotationPolicy::new(Duration::days(1), JWKS_MAX_AGE, grace).is_ok());
    }

    #[test]
    fn policy_rejects_period_not_longer_than_prepublish_and_short_grace() {
        let grace = p().retire_grace();
        assert!(matches!(
            RotationPolicy::new(Duration::days(7), Duration::days(7), grace),
            Err(CoreError::Validation {
                field: "period",
                ..
            })
        ));
        assert!(matches!(
            RotationPolicy::new(Duration::days(90), Duration::days(7), Duration::hours(1)),
            Err(CoreError::Validation {
                field: "retire_grace",
                ..
            })
        ));
    }

    #[test]
    fn empty_key_set_generates_an_active_key_per_alg() {
        let actions = plan_rotation(&[], &[Alg::RS256, Alg::ES256], t0(), &p());
        assert_eq!(
            actions,
            vec![
                KeyAction::Generate {
                    alg: Alg::RS256,
                    state: KeyState::Active
                },
                KeyAction::Generate {
                    alg: Alg::ES256,
                    state: KeyState::Active
                },
            ]
        );
    }

    #[test]
    fn young_active_key_needs_nothing() {
        let policy = p();
        let now = t0();
        let active = key(
            Alg::RS256,
            KeyState::Active,
            now - (policy.period() - policy.prepublish()) + Duration::seconds(1),
        );
        assert!(plan_rotation(&[active], &[Alg::RS256], now, &policy).is_empty());
    }

    #[test]
    fn active_due_for_prepublish_generates_next() {
        let policy = p();
        let now = t0();
        let active = key(
            Alg::RS256,
            KeyState::Active,
            now - (policy.period() - policy.prepublish()),
        );
        assert_eq!(
            plan_rotation(&[active], &[Alg::RS256], now, &policy),
            vec![KeyAction::Generate {
                alg: Alg::RS256,
                state: KeyState::Next
            }]
        );
    }

    #[test]
    fn published_next_and_overdue_active_promote() {
        let policy = p();
        let now = t0();
        let active = key(Alg::ES256, KeyState::Active, now - policy.period());
        let next = key(Alg::ES256, KeyState::Next, now - policy.prepublish());
        let actions = plan_rotation(
            &[active.clone(), next.clone()],
            &[Alg::RS256, Alg::ES256],
            now,
            &policy,
        );
        assert_eq!(
            actions,
            vec![
                KeyAction::Generate {
                    alg: Alg::RS256,
                    state: KeyState::Active
                },
                KeyAction::Promote {
                    alg: "ES256".into(),
                    retire: active.id,
                    retire_kid: active.kid.clone(),
                    retire_expires_at: now + Duration::hours(1) + Duration::minutes(5),
                    activate: next.id,
                    activate_kid: next.kid.clone(),
                }
            ]
        );
    }

    #[test]
    fn next_not_published_long_enough_is_never_promoted() {
        let policy = p();
        let now = t0();
        // Active far overdue, but the next key has been in the JWKS for less than prepublish.
        let active = key(Alg::RS256, KeyState::Active, now - Duration::days(365));
        let next = key(
            Alg::RS256,
            KeyState::Next,
            now - policy.prepublish() + Duration::seconds(1),
        );
        assert!(plan_rotation(&[active, next], &[Alg::RS256], now, &policy).is_empty());
    }

    #[test]
    fn published_next_waits_for_active_period() {
        let policy = p();
        let now = t0();
        let active = key(
            Alg::RS256,
            KeyState::Active,
            now - policy.period() + Duration::seconds(1),
        );
        let next = key(Alg::RS256, KeyState::Next, now - Duration::days(30));
        assert!(plan_rotation(&[active, next], &[Alg::RS256], now, &policy).is_empty());
    }

    #[test]
    fn expired_retired_keys_are_deleted_unexpired_kept() {
        let policy = p();
        let now = t0();
        let active = key(Alg::RS256, KeyState::Active, now);
        let mut expired = key(Alg::RS256, KeyState::Retired, now - Duration::days(100));
        expired.expires_at = Some(now);
        let mut pending = key(Alg::RS256, KeyState::Retired, now - Duration::days(100));
        pending.expires_at = Some(now + Duration::seconds(1));
        let actions = plan_rotation(
            &[active, expired.clone(), pending],
            &[Alg::RS256],
            now,
            &policy,
        );
        assert_eq!(
            actions,
            vec![KeyAction::Delete {
                id: expired.id,
                kid: expired.kid.clone(),
                alg: "RS256".into()
            }]
        );
    }

    #[test]
    fn disabled_alg_is_not_rotated_and_its_active_key_never_deleted() {
        let policy = p();
        let now = t0();
        let rs = key(Alg::RS256, KeyState::Active, now);
        let es_old = key(Alg::ES256, KeyState::Active, now - Duration::days(400));
        let es_next = key(Alg::ES256, KeyState::Next, now - Duration::days(30));
        // ES256 removed from the enabled set: no generate, no promote, no delete.
        let actions = plan_rotation(&[rs, es_old, es_next], &[Alg::RS256], now, &policy);
        assert!(actions.is_empty(), "{actions:?}");
    }

    #[test]
    fn duplicate_algs_are_planned_once() {
        let actions = plan_rotation(&[], &[Alg::RS256, Alg::RS256], t0(), &p());
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn full_cycle_never_signs_with_a_key_younger_than_prepublish() {
        // Walk a simulated key set over 400 days in 1-hour steps, applying the plan like the
        // service does, and check the invariants on every promotion.
        let policy = p();
        let mut now = t0();
        let mut keys: Vec<SigningKey> = Vec::new();
        let mut promotions = 0;
        for _ in 0..(400 * 24) {
            for action in plan_rotation(&keys, &[Alg::RS256], now, &policy) {
                match action {
                    KeyAction::Generate { alg, state } => keys.push(key(alg, state, now)),
                    KeyAction::Promote {
                        retire,
                        retire_expires_at,
                        activate,
                        ..
                    } => {
                        let next = keys.iter().find(|k| k.id == activate).unwrap();
                        assert!(now - next.created_at >= policy.prepublish());
                        assert!(now - next.created_at >= JWKS_MAX_AGE);
                        for k in &mut keys {
                            if k.id == retire {
                                k.state = KeyState::Retired;
                                k.retired_at = Some(now);
                                k.expires_at = Some(retire_expires_at);
                            } else if k.id == activate {
                                k.state = KeyState::Active;
                                k.activated_at = Some(now);
                            }
                        }
                        promotions += 1;
                    }
                    KeyAction::Delete { id, .. } => keys.retain(|k| k.id != id),
                }
            }
            let active = keys.iter().filter(|k| k.state == KeyState::Active).count();
            assert_eq!(active, 1, "exactly one active key at all times");
            assert!(keys.len() <= 3);
            now += Duration::hours(1);
        }
        assert_eq!(promotions, 4, "400 days / 90-day period");
    }

    // --- concurrent first start (OPS-03) ---------------------------------------------------

    use crate::service::bootstrap::race_fake::RaceFake;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn race_rotation(fake: Arc<RaceFake>) -> KeyRotationService {
        KeyRotationService {
            storage: fake,
            kek: Arc::new(Kek::generate()),
            clock: Arc::new(crate::clock::SystemClock),
            policy: p(),
        }
    }

    fn tenant() -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: "default".to_owned(),
            display_name: "Default".to_owned(),
            host: None,
            settings: crate::model::TenantSettings::default(),
            created_at: t0(),
        }
    }

    #[tokio::test]
    async fn ensure_tenant_treats_a_concurrent_winners_active_key_as_success() {
        let tenant = tenant();
        let algs = enabled_algs(&tenant).unwrap();
        // Per alg: no active key at first; after the conflict the winner's key is active.
        let mut answers = VecDeque::new();
        for alg in &algs {
            answers.push_back(None);
            answers.push_back(Some(key(*alg, KeyState::Active, t0())));
        }
        let fake = Arc::new(RaceFake {
            active_keys: Mutex::new(answers),
            key_insert_conflict: true,
            ..RaceFake::default()
        });
        let generated = race_rotation(fake.clone())
            .ensure_tenant(&tenant)
            .await
            .expect("losing the one-active-key race is success");
        assert_eq!(generated, 0);
        assert_eq!(*fake.key_inserts.lock().unwrap() as usize, algs.len());
        assert_eq!(
            fake.audit_count(),
            0,
            "only the winner audits key_generated"
        );
    }

    #[tokio::test]
    async fn ensure_tenant_conflict_without_an_active_key_is_an_error() {
        let fake = Arc::new(RaceFake {
            // No active key before or after the conflict (e.g. a duplicate kid).
            key_insert_conflict: true,
            ..RaceFake::default()
        });
        let err = race_rotation(fake.clone())
            .ensure_tenant(&tenant())
            .await
            .expect_err("a conflict nobody won is not hidden");
        assert!(
            matches!(err, CoreError::Storage(StorageError::Conflict(_))),
            "{err:?}"
        );
        assert_eq!(fake.audit_count(), 0);
    }

    #[tokio::test]
    async fn ensure_tenant_winner_generates_and_audits() {
        let tenant = tenant();
        let algs = enabled_algs(&tenant).unwrap();
        let fake = Arc::new(RaceFake::default());
        let generated = race_rotation(fake.clone())
            .ensure_tenant(&tenant)
            .await
            .unwrap();
        assert_eq!(generated as usize, algs.len());
        // key_generated + key_activated per alg.
        assert_eq!(fake.audit_count(), 2 * algs.len());
    }
}
