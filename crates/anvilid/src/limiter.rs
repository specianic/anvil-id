//! Rate-limiter backend selection: the one place the binary builds the limiter
//! (ARCHITECTURE §11). The result goes to `AppState::new_with_limiter`; no handler or layer
//! chooses a backend.

use std::sync::Arc;

use anvil_cache::limiter::{InProcessLimiter, RateLimiter};
use anvil_core::ports::Clock;
use anvil_jose::Kek;
use anyhow::bail;

use crate::config::Config;

/// The limiter for this node: the in-process limiter when `redis_url` is unset. Async because
/// the shared backend connects here (05-16).
///
/// `kek` is reserved for the shared backend (05-16 derives its key-hashing secret from it).
pub async fn build_limiter(
    cfg: &Config,
    clock: Arc<dyn Clock>,
    _kek: &Arc<Kek>,
) -> anyhow::Result<Arc<dyn RateLimiter>> {
    if cfg.redis_url.is_some() {
        // TRANSITIONAL(05-16): the Redis-backed limiter lands in 05-16. Refuse to start rather
        // than silently running per-node limits an operator asked to share.
        bail!(
            "redis_url is not supported yet: the shared Redis rate limiter is not available in \
             this build; unset redis_url to use the per-node limiter"
        );
    }
    Ok(Arc::new(InProcessLimiter::new(
        cfg.rate_limits.clone(),
        clock,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CliOverrides, Config, Layers};
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
    async fn redis_url_fails_explicitly_without_echoing_it() {
        let cfg = config(&[("redis_url", "redis://:hunter2@cache.example.test:6379/0")]);
        let err = build_limiter(&cfg, Arc::new(SystemClock), &Arc::new(Kek::generate()))
            .await
            .err()
            .expect("refused")
            .to_string();
        assert!(err.contains("redis_url is not supported yet"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
    }
}
