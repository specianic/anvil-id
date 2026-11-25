//! Argon2id password hashing behind a bounded worker pool (AUTH-01).
//!
//! - OWASP parameters by default: m = 19 MiB, t = 2, p = 1 ([`Argon2Pool::owasp_params`]).
//! - Every hash or verification runs in `spawn_blocking` while holding a semaphore permit, so at
//!   most `permits` run at once (each needs `m` of memory). If no permit frees up within the
//!   acquire timeout the call fails with [`CoreError::Overloaded`]; there is never a bypass.
//! - `verify(None, _)` (unknown user, no password) verifies against a dummy hash generated at
//!   startup with the same parameters, so response time does not reveal whether an account exists.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ::argon2::password_hash::phc::PasswordHash;
use ::argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};
use anvil_core::error::CoreError;
use anvil_core::ports::{PasswordCheck, PasswordHasher};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::errors::WebError;

/// Default time to wait for a free hashing slot before shedding load.
pub const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded Argon2id hasher implementing [`PasswordHasher`].
pub struct Argon2Pool {
    sem: Arc<Semaphore>,
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
            params,
            dummy_phc,
            acquire_timeout,
            verifications: AtomicU64::new(0),
        })
    }

    /// Number of Argon2 verifications computed so far (including dummy verifications). Exposed
    /// as an operational metric.
    pub fn verifications(&self) -> u64 {
        self.verifications.load(Ordering::Relaxed)
    }

    async fn permit(&self) -> Result<OwnedSemaphorePermit, CoreError> {
        tokio::time::timeout(self.acquire_timeout, Arc::clone(&self.sem).acquire_owned())
            .await
            .map_err(|_| CoreError::Overloaded)?
            .map_err(|_| CoreError::Overloaded)
    }

    /// `true` if `phc` was produced with other parameters than the current ones (or is not an
    /// Argon2id v1.3 hash at all).
    fn needs_rehash(&self, phc: &PasswordHash) -> bool {
        if phc.algorithm.as_str() != "argon2id" || phc.version != Some(Version::V0x13.into()) {
            return true;
        }
        match Params::try_from(phc) {
            Ok(p) => {
                p.m_cost() != self.params.m_cost()
                    || p.t_cost() != self.params.t_cost()
                    || p.p_cost() != self.params.p_cost()
                    || phc.hash.as_ref().map(|h| h.len())
                        != Some(self.params.output_len().unwrap_or(Params::DEFAULT_OUTPUT_LEN))
            }
            Err(_) => true,
        }
    }
}

#[async_trait::async_trait]
impl PasswordHasher for Argon2Pool {
    async fn hash(&self, password: &str) -> Result<String, CoreError> {
        let permit = self.permit().await?;
        let params = self.params.clone();
        let password = Zeroizing::new(password.to_owned());
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            hash_with(&params, password.as_bytes())
        })
        .await
        .map_err(|e| CoreError::Internal(format!("argon2 task failed: {e}")))?
    }

    async fn verify(&self, phc: Option<&str>, password: &str) -> Result<PasswordCheck, CoreError> {
        let permit = self.permit().await?;
        let known = phc.is_some();
        let target = phc.unwrap_or(&self.dummy_phc).to_owned();
        let password = Zeroizing::new(password.to_owned());
        self.verifications.fetch_add(1, Ordering::Relaxed);
        let (ok, parsed) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            match PasswordHash::new(&target) {
                Ok(hash) => {
                    let ok = argon2(Params::default())
                        .verify_password(password.as_bytes(), &hash)
                        .is_ok();
                    (ok, Some(hash))
                }
                Err(_) => (false, None),
            }
        })
        .await
        .map_err(|e| CoreError::Internal(format!("argon2 task failed: {e}")))?;
        if known && parsed.is_none() {
            tracing::error!("stored password hash is not a valid PHC string");
        }
        let valid = known && ok;
        let needs_rehash = valid && parsed.as_ref().is_some_and(|h| self.needs_rehash(h));
        Ok(PasswordCheck {
            valid,
            needs_rehash,
        })
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
        let ok = pool.verify(Some(&phc), "correct horse").await.expect("verify");
        assert!(ok.valid);
        assert!(!ok.needs_rehash);
        let bad = pool.verify(Some(&phc), "wrong").await.expect("verify");
        assert!(!bad.valid);
        assert!(!bad.needs_rehash);
    }

    #[tokio::test]
    async fn missing_user_runs_the_dummy_hash() {
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let before = pool.verifications();
        let check = pool.verify(None, "anything").await.expect("verify");
        assert!(!check.valid);
        assert_eq!(pool.verifications(), before + 1, "a real Argon2 verification ran");
        // The dummy hash's own password is random, so even guessing cannot make it valid.
        assert!(!pool.verify(None, "").await.expect("verify").valid);
    }

    #[tokio::test]
    async fn missing_user_takes_as_long_as_a_real_verification() {
        let params = Params::new(8 * 1024, 2, 1, None).expect("params");
        let pool = Argon2Pool::new(params, 1).expect("pool");
        let phc = pool.hash("pw").await.expect("hash");
        let t = std::time::Instant::now();
        pool.verify(Some(&phc), "nope").await.expect("verify");
        let real = t.elapsed();
        let t = std::time::Instant::now();
        pool.verify(None, "nope").await.expect("verify");
        let dummy = t.elapsed();
        assert!(dummy * 3 >= real, "dummy {dummy:?} vs real {real:?}");
    }

    #[tokio::test]
    async fn other_params_need_rehash() {
        let old = Argon2Pool::new(Params::new(128, 1, 1, None).expect("params"), 1).expect("pool");
        let phc = old.hash("pw").await.expect("hash");
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let check = pool.verify(Some(&phc), "pw").await.expect("verify");
        assert!(check.valid);
        assert!(check.needs_rehash);
        // Wrong password: never asks for a rehash.
        assert!(!pool.verify(Some(&phc), "x").await.expect("verify").needs_rehash);
    }

    #[tokio::test]
    async fn garbage_phc_is_invalid() {
        let pool = Argon2Pool::new(low(), 1).expect("pool");
        let check = pool.verify(Some("not-a-phc"), "pw").await.expect("verify");
        assert!(!check.valid);
    }

    #[tokio::test]
    async fn saturation_is_overloaded_never_a_bypass() {
        let pool =
            Argon2Pool::with_acquire_timeout(low(), 1, Duration::from_millis(50)).expect("pool");
        let phc = pool.hash("pw").await.expect("hash");
        let held = Arc::clone(&pool.sem).acquire_owned().await.expect("permit");
        let err = pool.verify(Some(&phc), "pw").await.expect_err("saturated");
        assert!(matches!(err, CoreError::Overloaded));
        let err = pool.hash("pw").await.expect_err("saturated");
        assert!(matches!(err, CoreError::Overloaded));
        drop(held);
        assert!(pool.verify(Some(&phc), "pw").await.expect("verify").valid);
    }

    #[test]
    fn zero_permits_rejected() {
        assert!(Argon2Pool::new(low(), 0).is_err());
    }
}
