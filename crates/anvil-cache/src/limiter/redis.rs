//! Shared rate-limit backend on Redis: the second implementation of the one [`RateLimiter`]
//! trait (ARCHITECTURE §11), for several nodes behind a load balancer.
//!
//! - **Same decisions as [`InProcessLimiter`]**, proven by the limiter contract suite. Every
//!   operation is one atomic Lua script ([`GCRA_LUA`], [`BACKOFF_LUA`]) and `now` is passed in
//!   from the injected core clock (microseconds); Redis `TIME` is never read.
//! - **No raw keys in Redis.** Key names are `anvil:rl:{class}:{hex}` where `hex` is the
//!   [`KeyHasher`] output over a canonical binary encoding of the [`LimitKey`]. The binary keys
//!   this with a secret (HMAC-SHA-256 under a KEK-derived key), so IPs, client ids and identifier
//!   hashes never appear in key names.
//! - **Failure policy** when Redis errors or times out (50 ms response timeout): a circuit breaker
//!   ([`BREAKER_COOL_DOWN`]) skips Redis for a cool-down. Meanwhile the [`RouteClass::Auth`]
//!   class and [`RateLimiter::brute_force_gate`] fail closed with
//!   `Decision::Deny { retry_after: <rest of the cool-down> }` unless the failure mode is
//!   [`FailureMode::Local`]. Every other decision falls back to an embedded [`InProcessLimiter`]
//!   (the same implementation, same config and clock), so an outage never stops token issuance.
//!   Each fallback increments `anvil_ratelimit_backend_errors_total{operation, reason}`
//!   (`reason` = `error` | `breaker_open`), and each healthy/degraded state change is reported
//!   once to the optional [`HealthObserver`] (the binary logs it).

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::ports::Clock;
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::aio::ConnectionManagerConfig;
use redis::{AsyncConnectionConfig, Client, FromRedisValue, Script, ScriptInvocation};

use super::breaker::{BREAKER_COOL_DOWN, Breaker, Permit, Transition};
use super::config::{LimiterConfig, RateQuota};
use super::types::{Backoff, Decision, LimitKey, RouteClass};
use super::{InProcessLimiter, RateLimiter};

/// The GCRA check script (one key).
pub const GCRA_LUA: &str = include_str!("scripts/gcra.lua");
/// The backoff store and brute-force gate script (operation selected by its first argument).
pub const BACKOFF_LUA: &str = include_str!("scripts/backoff.lua");

/// Prefix of every limiter key in Redis.
pub const KEY_PREFIX: &str = "anvil:rl:";

/// Response timeout of every Redis call.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_millis(50);
/// Timeout of each connection attempt.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_millis(500);

/// Length of the loose-tier counting window (same as the in-process store).
const LOOSE_WINDOW: Duration = Duration::from_secs(3_600);

/// Maps the canonical encoding of a [`LimitKey`] to the 32 bytes used in its Redis key name.
///
/// The binary supplies a keyed hash (HMAC-SHA-256 with a key derived from the KEK), so key names
/// reveal nothing without the secret. `anvil-cache` deliberately has no crypto dependency.
pub type KeyHasher = Arc<dyn Fn(&[u8]) -> [u8; 32] + Send + Sync>;

/// Health of the shared backend, as reported to a [`HealthObserver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealth {
    /// Redis answers again; decisions are shared.
    Healthy,
    /// Redis failed; decisions follow the [`FailureMode`] until it recovers.
    Degraded,
}

/// Called once per backend state change (not per request).
pub type HealthObserver = Arc<dyn Fn(BackendHealth) + Send + Sync>;

/// What the auth class and the brute-force gate do while Redis is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureMode {
    /// Deny (fail closed) with `retry_after` = the rest of the breaker cool-down. Default.
    #[default]
    Closed,
    /// Use the node-local in-process limiter, like every other class.
    Local,
}

/// Why [`RedisLimiter::connect`] failed. The message never contains the URL (it may carry a
/// password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisInitError {
    /// The URL is not a valid Redis URL.
    InvalidUrl,
    /// The server could not be reached or did not answer `PING`.
    Unreachable(String),
}

impl fmt::Display for RedisInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedisInitError::InvalidUrl => {
                f.write_str("redis_url is not a valid redis:// or rediss:// URL")
            }
            RedisInitError::Unreachable(reason) => {
                write!(f, "the Redis rate-limit backend is unreachable: {reason}")
            }
        }
    }
}

impl std::error::Error for RedisInitError {}

/// A short, URL-free description of a Redis error.
fn describe(err: &redis::RedisError) -> String {
    if err.is_timeout() {
        "timed out".to_owned()
    } else if err.is_connection_refusal() {
        "connection refused".to_owned()
    } else if err.is_connection_dropped() || err.is_io_error() {
        "connection error".to_owned()
    } else {
        format!("{:?}", err.kind())
    }
}

/// The Redis-backed [`RateLimiter`].
pub struct RedisLimiter {
    config: LimiterConfig,
    clock: Arc<dyn Clock>,
    conn: ConnectionManager,
    hasher: KeyHasher,
    failure: FailureMode,
    breaker: Breaker,
    local: InProcessLimiter,
    gcra: Script,
    backoff: Script,
    observer: Option<HealthObserver>,
}

impl RedisLimiter {
    /// Connects to `url` and checks the server with `PING`, so a wrong URL or an unreachable
    /// server fails startup instead of degrading silently.
    pub async fn connect(
        url: &str,
        config: LimiterConfig,
        clock: Arc<dyn Clock>,
        hasher: KeyHasher,
        failure: FailureMode,
    ) -> Result<Self, RedisInitError> {
        let client = Client::open(url).map_err(|_| RedisInitError::InvalidUrl)?;
        // Probe once with a plain connection first: the connection manager would otherwise
        // retry with backoff before reporting an unreachable server.
        let probe_cfg = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(CONNECTION_TIMEOUT))
            .set_response_timeout(Some(CONNECTION_TIMEOUT));
        let mut probe = client
            .get_multiplexed_async_connection_with_config(&probe_cfg)
            .await
            .map_err(|e| RedisInitError::Unreachable(describe(&e)))?;
        redis::cmd("PING")
            .query_async::<String>(&mut probe)
            .await
            .map_err(|e| RedisInitError::Unreachable(describe(&e)))?;
        drop(probe);

        let manager_cfg = ConnectionManagerConfig::new()
            .set_response_timeout(Some(RESPONSE_TIMEOUT))
            .set_connection_timeout(Some(CONNECTION_TIMEOUT))
            .set_number_of_retries(1);
        let conn = ConnectionManager::new_with_config(client, manager_cfg)
            .await
            .map_err(|e| RedisInitError::Unreachable(describe(&e)))?;

        Ok(Self {
            local: InProcessLimiter::new(config.clone(), clock.clone()),
            config,
            clock,
            conn,
            hasher,
            failure,
            breaker: Breaker::new(BREAKER_COOL_DOWN),
            gcra: Script::new(GCRA_LUA),
            backoff: Script::new(BACKOFF_LUA),
            observer: None,
        })
    }

    /// Reports backend state changes (healthy/degraded) to `observer`, once per change.
    #[must_use]
    pub fn with_health_observer(mut self, observer: HealthObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// The configuration in effect.
    pub fn config(&self) -> &LimiterConfig {
        &self.config
    }

    /// The failure mode in effect.
    pub fn failure_mode(&self) -> FailureMode {
        self.failure
    }

    fn now_us(&self) -> i64 {
        micros_since_epoch(self.clock.now())
    }

    /// The Redis key of `key` under `class` (a GCRA bucket name or `bf` for the backoff store).
    fn redis_key(&self, class: &str, key: &LimitKey) -> String {
        let digest = (self.hasher)(&canonical(key));
        let mut name = String::with_capacity(KEY_PREFIX.len() + class.len() + 1 + 64);
        name.push_str(KEY_PREFIX);
        name.push_str(class);
        name.push(':');
        push_hex(&mut name, &digest);
        name
    }

    fn report(&self, transition: Option<Transition>) {
        let Some(transition) = transition else {
            return;
        };
        let health = match transition {
            Transition::Opened => BackendHealth::Degraded,
            Transition::Closed => BackendHealth::Healthy,
        };
        if let Some(observer) = &self.observer {
            observer(health);
        }
    }

    /// Runs one script invocation behind the breaker. `None` means "Redis unavailable": the
    /// caller applies the failure policy (the error counter has been incremented).
    async fn run<T: FromRedisValue>(
        &self,
        operation: &'static str,
        invocation: &ScriptInvocation<'_>,
    ) -> Option<T> {
        if self.breaker.permit(self.clock.now()) == Permit::Skip {
            backend_error(operation, "breaker_open");
            return None;
        }
        let mut conn = self.conn.clone();
        match invocation.invoke_async::<T>(&mut conn).await {
            Ok(value) => {
                self.report(self.breaker.success());
                Some(value)
            }
            Err(_) => {
                self.report(self.breaker.failure(self.clock.now()));
                backend_error(operation, "error");
                None
            }
        }
    }

    fn fail_closed(&self) -> Decision {
        Decision::Deny {
            retry_after: self
                .breaker
                .retry_after(self.clock.now())
                .max(Duration::from_millis(1)),
        }
    }

    fn backoff_invocation<'a>(&'a self, op: &str, now: i64) -> ScriptInvocation<'a> {
        let mut inv = self.backoff.prepare_invoke();
        inv.arg(op)
            .arg(now)
            .arg(micros(self.idle()))
            .arg(micros(LOOSE_WINDOW));
        inv
    }

    /// Idle expiry of a backoff entry: `2 * cap`, at least one second (as in-process).
    fn idle(&self) -> Duration {
        self.config
            .cap
            .saturating_mul(2)
            .max(Duration::from_secs(1))
    }
}

fn backend_error(operation: &'static str, reason: &'static str) {
    metrics::counter!(
        "anvil_ratelimit_backend_errors_total",
        "operation" => operation,
        "reason" => reason
    )
    .increment(1);
}

#[async_trait]
impl RateLimiter for RedisLimiter {
    async fn check(&self, class: RouteClass, key: &LimitKey) -> Decision {
        if !self.config.enabled {
            return Decision::Allow;
        }
        let (bucket, quota) = bucket(&self.config, class, key);
        let t = micros(quota.replenish_interval()).max(1);
        let tau = t.saturating_mul(i64::from(quota.burst.get() - 1));
        let mut inv = self.gcra.prepare_invoke();
        inv.key(self.redis_key(bucket, key))
            .arg(self.now_us())
            .arg(t)
            .arg(tau);
        match self.run::<(i64, i64)>("check", &inv).await {
            Some((1, _)) => Decision::Allow,
            Some((_, retry_us)) => Decision::Deny {
                retry_after: from_micros(retry_us).max(Duration::from_nanos(1)),
            },
            None if class == RouteClass::Auth && self.failure == FailureMode::Closed => {
                self.fail_closed()
            }
            None => self.local.check(class, key).await,
        }
    }

    async fn backoff(&self, key: &LimitKey) -> Option<Duration> {
        if !self.config.enabled {
            return None;
        }
        let mut inv = self.backoff_invocation("get", self.now_us());
        inv.key(self.redis_key("bf", key));
        match self.run::<i64>("backoff", &inv).await {
            Some(left) => (left > 0).then(|| from_micros(left)),
            None => self.local.backoff(key).await,
        }
    }

    async fn record_failure(&self, key: &LimitKey) -> Backoff {
        if !self.config.enabled {
            return Backoff {
                failures: 0,
                locked_for: None,
            };
        }
        let mut inv = self.backoff_invocation("fail", self.now_us());
        inv.key(self.redis_key("bf", key))
            .arg(if key.is_loose_tier() { "1" } else { "0" })
            .arg(self.config.free_attempts)
            .arg(micros(self.config.base))
            .arg(micros(self.config.cap));
        match self.run::<(i64, i64)>("record_failure", &inv).await {
            Some((failures, locked_us)) => Backoff {
                failures: u32::try_from(failures).unwrap_or(u32::MAX),
                locked_for: (locked_us > 0).then(|| from_micros(locked_us)),
            },
            None => self.local.record_failure(key).await,
        }
    }

    async fn record_success(&self, key: &LimitKey) {
        if !self.config.enabled {
            return;
        }
        // Failures recorded locally during an outage are forgotten as well.
        self.local.record_success(key).await;
        let mut inv = self.backoff_invocation("clear", self.now_us());
        inv.key(self.redis_key("bf", key));
        let _cleared: Option<i64> = self.run("record_success", &inv).await;
    }

    async fn brute_force_gate(
        &self,
        strict: &LimitKey,
        loose: &LimitKey,
        captcha_available: bool,
    ) -> Decision {
        if !self.config.enabled {
            return Decision::Allow;
        }
        let mut inv = self.backoff_invocation("gate", self.now_us());
        inv.key(self.redis_key("bf", strict))
            .key(self.redis_key("bf", loose))
            .arg(self.config.loose_threshold_per_hour.max(1));
        match self.run::<(i64, i64)>("brute_force_gate", &inv).await {
            Some((0, _)) => Decision::Allow,
            Some((1, retry_us)) => Decision::Deny {
                retry_after: from_micros(retry_us),
            },
            Some(_) if captcha_available => Decision::RequireCaptcha,
            Some(_) => Decision::Deny {
                retry_after: self
                    .config
                    .base
                    .saturating_mul(2)
                    .min(self.config.cap)
                    .max(Duration::from_millis(1)),
            },
            None if self.failure == FailureMode::Closed => self.fail_closed(),
            None => {
                self.local
                    .brute_force_gate(strict, loose, captcha_available)
                    .await
            }
        }
    }
}

/// The GCRA bucket (Redis class segment) and quota of `key` in `class`, as in-process.
fn bucket(config: &LimiterConfig, class: RouteClass, key: &LimitKey) -> (&'static str, RateQuota) {
    match class {
        RouteClass::Auth => ("auth", config.auth),
        RouteClass::Token if matches!(key, LimitKey::Client { .. }) => {
            ("token_client", config.token_client)
        }
        RouteClass::Token => ("token", config.token),
        RouteClass::Admin => ("admin", config.admin),
        RouteClass::Default => ("default", config.default),
    }
}

/// Canonical, unambiguous binary encoding of a [`LimitKey`] (the [`KeyHasher`] input):
/// a variant tag, then fixed-width fields; the only variable field (`client_id`) is
/// length-prefixed.
pub fn canonical(key: &LimitKey) -> Vec<u8> {
    fn ip(out: &mut Vec<u8>, ip: &IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    let mut out = Vec::with_capacity(72);
    match key {
        LimitKey::Ip(addr) => {
            out.push(1);
            ip(&mut out, addr);
        }
        LimitKey::Identifier { tenant, ident } => {
            out.push(2);
            out.extend_from_slice(tenant.0.as_bytes());
            out.extend_from_slice(ident);
        }
        LimitKey::IdentIp {
            tenant,
            ident,
            ip: addr,
        } => {
            out.push(3);
            out.extend_from_slice(tenant.0.as_bytes());
            out.extend_from_slice(ident);
            ip(&mut out, addr);
        }
        LimitKey::Client { tenant, client_id } => {
            out.push(4);
            out.extend_from_slice(tenant.0.as_bytes());
            let len = u32::try_from(client_id.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(client_id.as_bytes());
        }
        LimitKey::User { tenant, user } => {
            out.push(5);
            out.extend_from_slice(tenant.0.as_bytes());
            out.extend_from_slice(user.0.as_bytes());
        }
    }
    out
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
}

fn micros(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

fn from_micros(us: i64) -> Duration {
    Duration::from_micros(u64::try_from(us).unwrap_or(0))
}

fn micros_since_epoch(t: time::OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use anvil_core::model::{TenantId, UserId};

    use super::*;

    #[test]
    fn canonical_encoding_is_unambiguous() {
        let tenant = TenantId::new_v7();
        let keys = [
            LimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            LimitKey::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            LimitKey::Ip(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped())),
            LimitKey::Identifier {
                tenant,
                ident: [1; 32],
            },
            LimitKey::IdentIp {
                tenant,
                ident: [1; 32],
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            },
            LimitKey::Client {
                tenant,
                client_id: "a".into(),
            },
            LimitKey::Client {
                tenant,
                client_id: "ab".into(),
            },
            LimitKey::User {
                tenant,
                user: UserId::new_v7(),
            },
        ];
        let encoded: Vec<Vec<u8>> = keys.iter().map(canonical).collect();
        for (i, a) in encoded.iter().enumerate() {
            for b in &encoded[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // Deterministic.
        assert_eq!(canonical(&keys[0]), canonical(&keys[0].clone()));
    }

    #[test]
    fn hex_is_lowercase_and_complete() {
        let mut s = String::new();
        push_hex(&mut s, &[0x00, 0x0f, 0xa5, 0xff]);
        assert_eq!(s, "000fa5ff");
    }

    #[test]
    fn buckets_match_the_in_process_quota_selection() {
        let c = LimiterConfig::default();
        let tenant = TenantId::new_v7();
        let client = LimitKey::Client {
            tenant,
            client_id: "x".into(),
        };
        let ip = LimitKey::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            bucket(&c, RouteClass::Token, &client),
            ("token_client", c.token_client)
        );
        assert_eq!(bucket(&c, RouteClass::Token, &ip), ("token", c.token));
        assert_eq!(bucket(&c, RouteClass::Auth, &client), ("auth", c.auth));
        assert_eq!(bucket(&c, RouteClass::Admin, &ip), ("admin", c.admin));
        assert_eq!(bucket(&c, RouteClass::Default, &ip), ("default", c.default));
    }

    #[test]
    fn init_errors_never_echo_the_url() {
        let e = RedisInitError::Unreachable("connection refused".into());
        assert!(!e.to_string().contains("redis://"));
        assert!(!RedisInitError::InvalidUrl.to_string().contains("hunter2"));
    }
}
