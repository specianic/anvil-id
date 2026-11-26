//! Argon2id password hashing behind a bounded worker pool (AUTH-01).
//!
//! - OWASP parameters by default: m = 19 MiB, t = 2, p = 1 ([`Argon2Pool::owasp_params`]).
//! - Every hash or verification runs in `spawn_blocking` while holding a semaphore permit, so at
//!   most `permits` run at once (each needs `m` of memory). If no permit frees up within the
//!   acquire timeout the call fails with [`CoreError::Overloaded`]; there is never a bypass.
//! - `verify(None, _)` (unknown user, no password) verifies against a dummy hash generated at
//!   startup with the same parameters, so response time does not reveal whether an account exists.
//! - The Argon2 parameters of a stored PHC string are checked against the import caps
//!   (`anvil_core::policy::password_import::check_stored_caps`) before any hashing; an over-cap
//!   hash fails closed without allocating its memory.
//!
//! Production wires [`crate::adapters::password::PasswordDispatcher`], which wraps this pool and runs
//! every scheme (Argon2 and the imported legacy schemes) through `Argon2Pool::run_verification`.
//! The pool's own `PasswordHasher` impl verifies Argon2 only (anything else takes the dummy path).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ::argon2::password_hash::phc::PasswordHash;
use ::argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};
use anvil_core::error::CoreError;
use anvil_core::model::HashProfileMaterial;
use anvil_core::policy::password_import::{StoredHash, check_stored_caps, parse_stored};
use anvil_core::ports::{PasswordCheck, PasswordHasher};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::errors::WebError;

/// Default time to wait for a free hashing slot before shedding load.
pub const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded Argon2id hasher implementing [`PasswordHasher`].
pub struct Argon2Pool {
    sem: Arc<Semaphore>,
    permits: usize,
    params: Params,
    dummy_phc: String,
    acquire_timeout: Duration,
    verifications: AtomicU64,
}

impl std::fmt::Debug for Argon2Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Argon2Pool")
            .field("m_cost", &self.params.m_cost())
            .field("t_cost", &self.params.t_cost())
            .field("p_cost", &self.params.p_cost())
            .field("available_permits", &self.sem.available_permits())
            .finish_non_exhaustive()
    }
}

fn argon2(params: Params) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_with(params: &Params, password: &[u8]) -> Result<String, CoreError> {
    let salt = anvil_jose::encoding::random_bytes::<16>();
    argon2(params.clone())
        .hash_password_with_salt(password, &salt)
        .map(|h| h.to_string())
        .map_err(|e| CoreError::Internal(format!("argon2 hashing failed: {e}")))
}

impl Argon2Pool {
    /// OWASP Password Storage Cheat Sheet parameters for Argon2id: 19 MiB, 2 iterations, 1 lane.
    pub fn owasp_params() -> Params {
        Params::new(19 * 1024, 2, 1, None).expect("OWASP argon2 parameters are valid")
    }

    /// A pool with `permits` concurrent hashing slots and the default acquire timeout.
    pub fn new(params: Params, permits: usize) -> Result<Self, WebError> {
        Self::with_acquire_timeout(params, permits, DEFAULT_ACQUIRE_TIMEOUT)
    }

    /// A pool with an explicit acquire timeout (how long a request waits for a slot before
    /// `Overloaded`).
    pub fn with_acquire_timeout(
        params: Params,
        permits: usize,
        acquire_timeout: Duration,
    ) -> Result<Self, WebError> {
        if permits == 0 {
            return Err(WebError::Config(
                "argon2 pool needs at least one permit".into(),
            ));
        }
        let dummy_password = anvil_jose::encoding::random_token();
        let dummy_phc = hash_with(&params, dummy_password.as_bytes())
            .map_err(|e| WebError::Config(format!("argon2 parameters rejected: {e}")))?;
        Ok(Self {
            sem: Arc::new(Semaphore::new(permits)),
            permits,
            params,
            dummy_phc,
            acquire_timeout,
            verifications: AtomicU64::new(0),
        })
    }

    /// Number of password verifications computed so far through this pool: Argon2, dummy and
    /// (behind the dispatcher) legacy-scheme verifications. Exposed as an operational metric.
    pub fn verifications(&self) -> u64 {
        self.verifications.load(Ordering::Relaxed)
    }

    /// Total number of concurrent hashing slots.
    pub fn permits(&self) -> usize {
        self.permits
    }

    async fn permit(&self) -> Result<OwnedSemaphorePermit, CoreError> {
        tokio::time::timeout(self.acquire_timeout, Arc::clone(&self.sem).acquire_owned())
            .await
            .map_err(|_| CoreError::Overloaded)?
            .map_err(|_| CoreError::Overloaded)
    }

    /// Runs `f` on the blocking pool while holding the permit.
    async fn spawn_with<F, R>(permit: OwnedSemaphorePermit, f: F) -> Result<R, CoreError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await
        .map_err(|e| CoreError::Internal(format!("password hashing task failed: {e}")))
    }

    /// Runs `f` in `spawn_blocking` while holding one of the pool's permits. `Overloaded` if no
    /// permit frees up within the acquire timeout; there is no bypass.
    pub(crate) async fn run_bounded<F, R>(&self, f: F) -> Result<R, CoreError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let permit = self.permit().await?;
        Self::spawn_with(permit, f).await
    }

    /// [`Self::run_bounded`] for a password verification: counted in [`Self::verifications`] once
    /// the permit is held.
    pub(crate) async fn run_verification<F, R>(&self, f: F) -> Result<R, CoreError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let permit = self.permit().await?;
        self.verifications.fetch_add(1, Ordering::Relaxed);
        Self::spawn_with(permit, f).await
    }

    /// Verifies `password` against the startup dummy hash (same parameters as real hashes) and
    /// returns "invalid". Used for unknown users and unrecognised stored values so their timing
    /// matches a real verification.
    pub(crate) async fn verify_dummy(&self, password: &str) -> Result<PasswordCheck, CoreError> {
        let target = self.dummy_phc.clone();
        let password = Zeroizing::new(password.to_owned());
        // The result is discarded: the dummy's own password is random and never valid.
        let _ = self
            .run_verification(move || {
                PasswordHash::new(&target).is_ok_and(|hash| {
                    argon2(Params::default())
                        .verify_password(password.as_bytes(), &hash)
                        .is_ok()
                })
            })
            .await?;
        Ok(PasswordCheck {
            valid: false,
            needs_rehash: false,
        })
    }

    /// Verifies `password` against an Argon2 PHC string whose parameters already passed
    /// `check_stored_caps`. `needs_rehash` follows the current parameters.
    pub(crate) async fn verify_argon2(
        &self,
        phc: &str,
        password: &str,
    ) -> Result<PasswordCheck, CoreError> {
        let target = phc.to_owned();
        let password = Zeroizing::new(password.to_owned());
        let (ok, rehash) = self
            .run_verification({
                let params = self.params.clone();
                move || match PasswordHash::new(&target) {
                    Ok(hash) => {
                        let ok = argon2(Params::default())
                            .verify_password(password.as_bytes(), &hash)
                            .is_ok();
                        (Some(ok), ok && needs_rehash(&params, &hash))
                    }
                    Err(_) => (None, false),
                }
            })
            .await?;
        let Some(valid) = ok else {
            tracing::error!(
                scheme = "argon2",
                "stored password hash is not a valid PHC string"
            );
            return Ok(PasswordCheck {
                valid: false,
                needs_rehash: false,
            });
        };
        Ok(PasswordCheck {
            valid,
            needs_rehash: valid && rehash,
        })
    }
}

/// `true` if `phc` was produced with other parameters than `current` (or is not an Argon2id v1.3
/// hash at all).
fn needs_rehash(current: &Params, phc: &PasswordHash) -> bool {
    if phc.algorithm.as_str() != "argon2id" || phc.version != Some(Version::V0x13.into()) {
        return true;
    }
    match Params::try_from(phc) {
        Ok(p) => {
            p.m_cost() != current.m_cost()
                || p.t_cost() != current.t_cost()
                || p.p_cost() != current.p_cost()
                || phc.hash.as_ref().map(|h| h.len())
                    != Some(current.output_len().unwrap_or(Params::DEFAULT_OUTPUT_LEN))
        }
        Err(_) => true,
    }
}

/// Argon2-only verification (tests and tools that use the pool directly). Production goes through
/// [`crate::adapters::password::PasswordDispatcher`]. A hash profile is meaningless for Argon2 and
/// is ignored; any non-Argon2 or unparseable stored value takes the dummy path.
#[async_trait::async_trait]
impl PasswordHasher for Argon2Pool {
    async fn hash(&self, password: &str) -> Result<String, CoreError> {
        let params = self.params.clone();
        let password = Zeroizing::new(password.to_owned());
        self.run_bounded(move || hash_with(&params, password.as_bytes()))
            .await?
    }

    async fn verify(
        &self,
        phc: Option<&str>,
        password: &str,
        _profile: Option<&HashProfileMaterial>,
    ) -> Result<PasswordCheck, CoreError> {
        let Some(stored) = phc else {
            return self.verify_dummy(password).await;
        };
        match parse_stored(stored) {
            Ok(h @ StoredHash::Argon2 { phc, .. }) => {
                if let Err(e) = check_stored_caps(&h) {
                    tracing::warn!(
                        scheme = "argon2",
                        reason = e.reason(),
                        "stored password hash refused; verification failed closed"
                    );
                    return Ok(PasswordCheck {
                        valid: false,
                        needs_rehash: false,
                    });
                }
                self.verify_argon2(phc, password).await
            }
            _ => {
                tracing::error!("stored password hash is not an Argon2 PHC string");
                self.verify_dummy(password).await
            }
        }
    }
}

/// Test-only access to the pool's semaphore (the dispatcher tests observe the shared permit).
#[cfg(test)]
pub(crate) mod test_support {
    impl super::Argon2Pool {
        /// Slots free right now.
        pub(crate) fn available_permits(&self) -> usize {
            self.sem.available_permits()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn low() -> Params {
        Params::new(256, 1, 1, None).expect("params")
    }

    #[test]
    fn owasp_defaults() {
        let p = Argon2Pool::owasp_params();
        assert_eq!((p.m_cost(), p.t_cost(), p.p_cost()), (19 * 1024, 2, 1));
    }

    #[tokio::test]
    async fn hash_and_verify() {
        let pool = Argon2Pool::new(low(), 2).expect("pool");
        let phc = pool.hash("correct horse").await.expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=256,t=1,p=1$"), "{phc}");
        let ok = pool
            .verify(Some(&phc), "correct horse", None)
            .await
            .expect("verify");
        assert!(ok.valid);
        assert!(!ok.needs_rehash);
        let bad = pool
            .verify(Some(&phc), "wrong", None)
            .await
            .expect("verify");
        assert!(!bad.valid);
        assert!(!bad.needs_rehash);
    }

    #[tokio::test]
    async fn missing_user_runs_the_dummy_hash() {
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let before = pool.verifications();
        let check = pool.verify(None, "anything", None).await.expect("verify");
        assert!(!check.valid);
        assert_eq!(
            pool.verifications(),
            before + 1,
            "a real Argon2 verification ran"
        );
        // The dummy hash's own password is random, so even guessing cannot make it valid.
        assert!(!pool.verify(None, "", None).await.expect("verify").valid);
    }

    #[tokio::test]
    async fn missing_user_takes_as_long_as_a_real_verification() {
        let params = Params::new(8 * 1024, 2, 1, None).expect("params");
        let pool = Argon2Pool::new(params, 1).expect("pool");
        let phc = pool.hash("pw").await.expect("hash");
        let t = std::time::Instant::now();
        pool.verify(Some(&phc), "nope", None).await.expect("verify");
        let real = t.elapsed();
        let t = std::time::Instant::now();
        pool.verify(None, "nope", None).await.expect("verify");
        let dummy = t.elapsed();
        assert!(dummy * 3 >= real, "dummy {dummy:?} vs real {real:?}");
    }

    #[tokio::test]
    async fn other_params_need_rehash() {
        let old = Argon2Pool::new(Params::new(128, 1, 1, None).expect("params"), 1).expect("pool");
        let phc = old.hash("pw").await.expect("hash");
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let check = pool.verify(Some(&phc), "pw", None).await.expect("verify");
        assert!(check.valid);
        assert!(check.needs_rehash);
        // Wrong password: never asks for a rehash.
        assert!(
            !pool
                .verify(Some(&phc), "x", None)
                .await
                .expect("verify")
                .needs_rehash
        );
    }

    #[tokio::test]
    async fn argon2_pool_ignores_profile_material() {
        // A hash profile only means something for Firebase scrypt (the dispatcher's job); the
        // Argon2 path neither uses it nor lets it change the outcome.
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let phc = pool.hash("pw").await.expect("hash");
        let material = HashProfileMaterial {
            salt_separator: vec![0x01],
            signer_key: secrecy::SecretBox::from(vec![0x02_u8; 16].into_boxed_slice()),
            rounds: 8,
            mem_cost: 14,
        };
        let ok = pool
            .verify(Some(&phc), "pw", Some(&material))
            .await
            .expect("verify");
        assert!(ok.valid);
        let bad = pool
            .verify(Some(&phc), "x", Some(&material))
            .await
            .expect("verify");
        assert!(!bad.valid);
        assert!(
            !pool
                .verify(None, "pw", Some(&material))
                .await
                .expect("verify")
                .valid
        );
    }

    #[tokio::test]
    async fn argon2_pool_over_cap_phc_fails_closed_without_hashing() {
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let before = pool.verifications();
        let t = std::time::Instant::now();
        for phc in [
            "$argon2id$v=19$m=4194304,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$argon2id$v=19$m=256,t=11,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$argon2id$v=19$m=256,t=1,p=9$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        ] {
            let check = pool.verify(Some(phc), "pw", None).await.expect("verify");
            assert!(!check.valid && !check.needs_rehash, "{phc}");
        }
        assert_eq!(
            pool.verifications(),
            before,
            "no hashing ran for over-cap hashes"
        );
        assert!(t.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn non_argon2_stored_value_takes_the_dummy_path() {
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let before = pool.verifications();
        let check = pool
            .verify(
                Some("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
                "U*U",
                None,
            )
            .await
            .expect("verify");
        assert!(!check.valid);
        assert_eq!(
            pool.verifications(),
            before + 1,
            "the dummy verification ran"
        );
    }

    #[tokio::test]
    async fn garbage_phc_is_invalid() {
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let check = pool
            .verify(Some("not-a-phc"), "pw", None)
            .await
            .expect("verify");
        assert!(!check.valid);
    }

    #[tokio::test]
    async fn saturation_is_overloaded_never_a_bypass() {
        let pool =
            Argon2Pool::with_acquire_timeout(low(), 1, Duration::from_millis(50)).expect("pool");
        let phc = pool.hash("pw").await.expect("hash");
        let held = Arc::clone(&pool.sem).acquire_owned().await.expect("permit");
        let err = pool
            .verify(Some(&phc), "pw", None)
            .await
            .expect_err("saturated");
        assert!(matches!(err, CoreError::Overloaded));
        let err = pool.hash("pw").await.expect_err("saturated");
        assert!(matches!(err, CoreError::Overloaded));
        drop(held);
        assert!(
            pool.verify(Some(&phc), "pw", None)
                .await
                .expect("verify")
                .valid
        );
    }

    #[test]
    fn zero_permits_rejected() {
        assert!(Argon2Pool::new(low(), 0).is_err());
    }
}
