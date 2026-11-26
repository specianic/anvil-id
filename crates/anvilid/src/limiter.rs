//! Rate-limiter backend selection: the one place the binary builds the limiter
//! (ARCHITECTURE §11). The result goes to `AppState::new_with_limiter`; no handler or layer
//! chooses a backend.
//!
//! - `redis_url` unset: the per-node [`InProcessLimiter`].
//! - `redis_url` set: the shared [`RedisLimiter`]. Key names in Redis are HMAC-SHA-256 under a
//!   key derived from the KEK ([`RATELIMIT_KEY_INFO`]), so they reveal no IPs, client ids or
//!   identifiers. `rate_limit_redis_failure` selects what the auth class does while Redis is
//!   unavailable (`closed`: 429 with `Retry-After`; `local`: per-node limits); every other class
//!   falls back to per-node limits, so an outage never stops token issuance. An unreachable
//!   server at startup is a startup error (the message never contains the URL).

use std::sync::Arc;

use anvil_cache::limiter::{
    BackendHealth, FailureMode, HealthObserver, InProcessLimiter, KeyHasher, RateLimiter,
    RedisLimiter,
};
use anvil_core::ports::Clock;
use anvil_jose::Kek;
use anyhow::anyhow;
use rustls::crypto::tls13::OkmBlock;
use rustls::{SupportedCipherSuite, Tls13CipherSuite};
use secrecy::ExposeSecret;

use crate::config::{Config, RedisFailure};

/// HKDF info for the secret keying limiter key names in Redis.
pub const RATELIMIT_KEY_INFO: &str = "anvilid/ratelimit-key/v1";

/// The limiter for this node (see the module docs). Async because the shared backend connects
/// and checks the server here.
pub async fn build_limiter(
    cfg: &Config,
    clock: Arc<dyn Clock>,
    kek: &Arc<Kek>,
) -> anyhow::Result<Arc<dyn RateLimiter>> {
    let Some(url) = &cfg.redis_url else {
        tracing::info!(backend = "in-process", "rate limiter");
        return Ok(Arc::new(InProcessLimiter::new(
            cfg.rate_limits.clone(),
            clock,
        )));
    };
    let failure = failure_mode(cfg.redis_failure);
    let limiter = RedisLimiter::connect(
        url.expose_secret(),
        cfg.rate_limits.clone(),
        clock,
        key_hasher(kek),
        failure,
    )
    .await
    // RedisInitError never contains the URL (it may carry a password).
    .map_err(|e| anyhow!("redis_url: {e}"))?
    .with_health_observer(health_logger());
    tracing::info!(
        backend = "redis",
        failure_mode = failure_name(failure),
        "rate limiter"
    );
    Ok(Arc::new(limiter))
}

fn failure_mode(mode: RedisFailure) -> FailureMode {
    match mode {
        RedisFailure::Closed => FailureMode::Closed,
        RedisFailure::Local => FailureMode::Local,
    }
}

fn failure_name(mode: FailureMode) -> &'static str {
    match mode {
        FailureMode::Closed => "closed",
        FailureMode::Local => "local",
    }
}

/// Logs each shared-backend state change once (the metric is emitted by `anvil-cache`).
fn health_logger() -> HealthObserver {
    Arc::new(|health| match health {
        BackendHealth::Degraded => tracing::warn!(
            "rate-limit backend (Redis) unavailable: auth requests follow \
             rate_limit_redis_failure, other classes use per-node limits"
        ),
        BackendHealth::Healthy => {
            tracing::info!("rate-limit backend (Redis) reachable again: limits are shared");
        }
    })
}

/// HMAC-SHA-256 keyed with `kek.derive_key(RATELIMIT_KEY_INFO)`.
///
/// The HMAC comes from the binary's TLS crypto provider (aws-lc-rs through rustls): the TLS 1.3
/// SHA-256 suite's HKDF provider exposes HMAC-SHA-256 over an arbitrary key, so the binary needs
/// no second crypto dependency.
fn key_hasher(kek: &Kek) -> KeyHasher {
    let secret = kek.derive_key(RATELIMIT_KEY_INFO);
    let key = OkmBlock::new(secret.as_ref());
    let suite = sha256_suite();
    Arc::new(move |bytes: &[u8]| {
        let tag = suite.hkdf_provider.hmac_sign(&key, bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    })
}

fn sha256_suite() -> &'static Tls13CipherSuite {
    match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls13(suite) => suite,
        SupportedCipherSuite::Tls12(_) => {
            unreachable!("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CliOverrides, Config, Layers};
    use anvil_cache::limiter::{LimitKey, canonical};
    use anvil_core::clock::SystemClock;
    use figment::value::{Dict, Value};

    fn config(env: &[(&str, &str)]) -> Config {
        let env: Dict = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Value::from((*v).to_owned())))
            .collect();
        let layers = Layers::new(&CliOverrides::default(), env, None).expect("layers");
        Config::resolve(layers.raw().expect("raw")).expect("config")
    }

    #[tokio::test]
    async fn in_process_limiter_without_redis_url() {
        let cfg = config(&[]);
        let limiter = build_limiter(&cfg, Arc::new(SystemClock), &Arc::new(Kek::generate())).await;
        assert!(limiter.is_ok());
    }

    #[tokio::test]
    async fn unreachable_redis_url_fails_startup_naming_the_key_without_echoing_it() {
        // Port 1 (tcpmux) is not a Redis server on any CI runner or dev host.
        let cfg = config(&[("redis_url", "redis://:hunter2@127.0.0.1:1/0")]);
        let err = build_limiter(&cfg, Arc::new(SystemClock), &Arc::new(Kek::generate()))
            .await
            .err()
            .expect("unreachable Redis must fail startup")
            .to_string();
        assert!(err.starts_with("redis_url: "), "{err}");
        assert!(err.contains("unreachable"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
        assert!(!err.contains("127.0.0.1"), "{err}");
    }

    #[test]
    fn failure_modes_map_one_to_one() {
        assert_eq!(failure_mode(RedisFailure::Closed), FailureMode::Closed);
        assert_eq!(failure_mode(RedisFailure::Local), FailureMode::Local);
        assert_eq!(
            failure_mode(config(&[]).redis_failure),
            FailureMode::Closed,
            "closed is the default"
        );
        assert_eq!(
            failure_mode(config(&[("rate_limit_redis_failure", "local")]).redis_failure),
            FailureMode::Local
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_test_case_2() {
        let key = OkmBlock::new(b"Jefe");
        let tag = sha256_suite()
            .hkdf_provider
            .hmac_sign(&key, b"what do ya want for nothing?");
        let hex: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn key_hasher_is_hmac_under_the_derived_ratelimit_key() {
        let kek = Kek::from_bytes(&[7u8; 32]).expect("kek");
        let canon = canonical(&LimitKey::Ip("192.0.2.1".parse().expect("ip")));
        let hashed = key_hasher(&kek)(&canon);
        let derived = kek.derive_key(RATELIMIT_KEY_INFO);
        let expected = sha256_suite()
            .hkdf_provider
            .hmac_sign(&OkmBlock::new(derived.as_ref()), &canon);
        assert_eq!(hashed.as_slice(), expected.as_ref());
        // Stable per KEK, different under another KEK, never the bare derived key.
        assert_eq!(hashed, key_hasher(&kek)(&canon));
        let other = Kek::from_bytes(&[8u8; 32]).expect("kek");
        assert_ne!(hashed, key_hasher(&other)(&canon));
        assert_ne!(hashed.as_slice(), derived.as_ref());
    }
}
