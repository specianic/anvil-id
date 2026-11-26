//! Shared application state handed to every handler.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anvil_cache::limiter::{InProcessLimiter, RateLimiter};
use anvil_core::ports::{BreachChecker, Clock, DomainTxtLookup, PasswordHasher, Storage};
use anvil_jose::kek::Kek;
use tokio::sync::{Notify, Semaphore};

use crate::adapters::outbound::OutboundClient;
use crate::adapters::upstream::UpstreamHttp;
use crate::config::AppConfig;
use crate::cookies::CookiePolicy;
use crate::errors::WebError;
use crate::render::Renderer;

/// The ports and secrets the web layer runs on. The binary wires production implementations;
/// tests wire their own (test code only).
pub struct AppDeps {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub breach: Arc<dyn BreachChecker>,
    pub kek: Arc<Kek>,
    /// DNS TXT lookups for organization domain verification. The binary wires
    /// [`crate::adapters::dns_txt::HickoryTxtLookup`]; tests wire a fake (test code only).
    pub domain_txt: Arc<dyn DomainTxtLookup>,
}

struct Inner {
    config: AppConfig,
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    hasher: Arc<dyn PasswordHasher>,
    breach: Arc<dyn BreachChecker>,
    kek: Arc<Kek>,
    domain_txt: Arc<dyn DomainTxtLookup>,
    renderer: Renderer,
    cookies: CookiePolicy,
    limiter: Arc<dyn RateLimiter>,
    outbound: Arc<OutboundClient>,
    upstream: UpstreamHttp,
    logout_wake: Arc<Notify>,
    /// Readiness of this node: cleared on shutdown so `/health/ready` and `/readyz` answer 503
    /// while the node drains.
    ready: AtomicBool,
    /// Negative cache of `Host` headers that matched no tenant (05-18).
    unknown_hosts: moka::sync::Cache<String, ()>,
    /// Bounds concurrent Client ID Metadata Document fetches (05-15).
    cimd_fetch_permits: Arc<Semaphore>,
}

/// Upper bound of the unknown-host negative cache (entries).
pub const UNKNOWN_HOSTS_CAPACITY: u64 = 10_000;
/// Concurrent Client ID Metadata Document fetches per node.
pub const CIMD_FETCH_PERMITS: usize = 16;

/// Cheaply clonable handle to the application state.
///
/// Wave-3 plans add service constructors (`impl AppState { pub(crate) fn token_service(&self) … }`)
/// in their own modules.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("public_url", &self.0.config.public_url.as_str())
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Builds the state: compiles the templates (theme override first), derives the cookie
    /// policy from the public URL and builds the in-process rate limiter from
    /// [`AppConfig::rate_limits`], driven by the app clock, and the single SSRF-guarded outbound
    /// client from [`AppConfig::outbound`] (fails on an unusable extra CA bundle). Tests use it;
    /// the binary uses [`Self::new_with_limiter`].
    pub fn new(config: AppConfig, deps: AppDeps) -> Result<Self, WebError> {
        let limiter: Arc<dyn RateLimiter> = Arc::new(InProcessLimiter::new(
            config.rate_limits.clone(),
            Arc::clone(&deps.clock),
        ));
        Self::new_with_limiter(config, deps, limiter)
    }

    /// [`Self::new`] with the rate limiter chosen by the binary (the in-process limiter, or the
    /// shared backend once it exists). The binary builds it in exactly one place
    /// (`anvilid::limiter::build_limiter`).
    pub fn new_with_limiter(
        config: AppConfig,
        deps: AppDeps,
        limiter: Arc<dyn RateLimiter>,
    ) -> Result<Self, WebError> {
        let renderer = Renderer::new(config.theme_dir.as_deref())?;
        let cookies = CookiePolicy::new(config.is_https());
        if config.dev_mode() {
            tracing::warn!(
                public_url = %config.public_url,
                "development mode: cookies are not Secure and pages show a development banner"
            );
        }
        let unknown_hosts = moka::sync::Cache::builder()
            .max_capacity(UNKNOWN_HOSTS_CAPACITY)
            .time_to_live(config.unknown_host_ttl)
            .build();
        let outbound = Arc::new(OutboundClient::new(&config.outbound)?);
        let upstream = UpstreamHttp::new(Arc::clone(&outbound));
        Ok(Self(Arc::new(Inner {
            config,
            storage: deps.storage,
            clock: deps.clock,
            hasher: deps.hasher,
            breach: deps.breach,
            kek: deps.kek,
            domain_txt: deps.domain_txt,
            renderer,
            cookies,
            limiter,
            outbound,
            upstream,
            logout_wake: Arc::new(Notify::new()),
            ready: AtomicBool::new(true),
            unknown_hosts,
            cimd_fetch_permits: Arc::new(Semaphore::new(CIMD_FETCH_PERMITS)),
        })))
    }

    pub fn config(&self) -> &AppConfig {
        &self.0.config
    }

    pub fn storage(&self) -> &dyn Storage {
        self.0.storage.as_ref()
    }

    /// The storage handle as an `Arc`, for services that keep it.
    pub fn storage_arc(&self) -> Arc<dyn Storage> {
        Arc::clone(&self.0.storage)
    }

    pub fn clock(&self) -> &dyn Clock {
        self.0.clock.as_ref()
    }

    pub fn clock_arc(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.0.clock)
    }

    pub fn hasher(&self) -> &dyn PasswordHasher {
        self.0.hasher.as_ref()
    }

    pub fn hasher_arc(&self) -> Arc<dyn PasswordHasher> {
        Arc::clone(&self.0.hasher)
    }

    pub fn breach(&self) -> &dyn BreachChecker {
        self.0.breach.as_ref()
    }

    pub fn breach_arc(&self) -> Arc<dyn BreachChecker> {
        Arc::clone(&self.0.breach)
    }

    pub fn kek(&self) -> &Kek {
        self.0.kek.as_ref()
    }

    pub fn kek_arc(&self) -> Arc<Kek> {
        Arc::clone(&self.0.kek)
    }

    /// DNS TXT lookups for organization domain verification.
    pub fn domain_txt(&self) -> &dyn DomainTxtLookup {
        self.0.domain_txt.as_ref()
    }

    pub fn domain_txt_arc(&self) -> Arc<dyn DomainTxtLookup> {
        Arc::clone(&self.0.domain_txt)
    }

    pub fn renderer(&self) -> &Renderer {
        &self.0.renderer
    }

    pub fn cookies(&self) -> &CookiePolicy {
        &self.0.cookies
    }

    /// The single rate limiter (ARCHITECTURE §11). UI handlers use it only through
    /// [`crate::layers::ratelimit::guard_attempt`] and [`crate::layers::ratelimit::record_attempt`].
    pub fn limiter(&self) -> &dyn RateLimiter {
        self.0.limiter.as_ref()
    }

    /// The single SSRF-guarded outbound HTTP client (ARCHITECTURE §11).
    pub fn outbound(&self) -> &OutboundClient {
        &self.0.outbound
    }

    pub fn outbound_arc(&self) -> Arc<OutboundClient> {
        Arc::clone(&self.0.outbound)
    }

    /// The upstream identity-provider adapter (built on [`Self::outbound`]).
    pub fn upstream(&self) -> &UpstreamHttp {
        &self.0.upstream
    }

    /// Wakes the back-channel logout worker when a delivery job is enqueued. The binary hands
    /// the same `Notify` to the worker (it gets it from here).
    pub fn logout_wake(&self) -> Arc<Notify> {
        Arc::clone(&self.0.logout_wake)
    }

    /// Wakes the back-channel logout worker. Revocations enqueue back-channel deliveries in
    /// their own storage transaction; this wakes the worker so they go out now instead of at
    /// the next poll. Spurious wakes cost one claim query, so call it after every successful
    /// revoking request (never from read-only handlers). This is the only place that notifies.
    pub fn wake_logout_worker(&self) {
        self.0.logout_wake.notify_one();
    }

    /// Whether this node accepts new traffic (`/health/ready`, `/readyz`).
    pub fn is_ready(&self) -> bool {
        self.0.ready.load(Ordering::Acquire)
    }

    /// Sets readiness. The binary clears it on SIGTERM before the drain delay, so load balancers
    /// stop routing new requests here while in-flight and keep-alive requests are still served.
    pub fn set_ready(&self, ready: bool) {
        self.0.ready.store(ready, Ordering::Release);
    }

    /// Negative cache of `Host` headers that matched no tenant (bounded to
    /// [`UNKNOWN_HOSTS_CAPACITY`] entries, TTL [`AppConfig::unknown_host_ttl`]), used by tenant
    /// resolution by host (`crate::tenant`).
    pub(crate) fn unknown_hosts(&self) -> &moka::sync::Cache<String, ()> {
        &self.0.unknown_hosts
    }

    /// Permits bounding concurrent Client ID Metadata Document fetches
    /// ([`CIMD_FETCH_PERMITS`]), used by the CIMD fetcher (`adapters::cimd`).
    pub(crate) fn cimd_fetch_permits(&self) -> Arc<Semaphore> {
        Arc::clone(&self.0.cimd_fetch_permits)
    }
}
