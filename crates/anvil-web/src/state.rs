//! Shared application state handed to every handler.

use std::sync::Arc;

use anvil_core::ports::{BreachChecker, Clock, PasswordHasher, Storage};
use anvil_jose::kek::Kek;

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
}

struct Inner {
    config: AppConfig,
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    hasher: Arc<dyn PasswordHasher>,
    breach: Arc<dyn BreachChecker>,
    kek: Arc<Kek>,
    renderer: Renderer,
    cookies: CookiePolicy,
}

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
    /// Builds the state: compiles the templates (theme override first) and derives the cookie
    /// policy from the public URL.
    pub fn new(config: AppConfig, deps: AppDeps) -> Result<Self, WebError> {
        let renderer = Renderer::new(config.theme_dir.as_deref())?;
        let cookies = CookiePolicy::new(config.is_https());
        if config.dev_mode() {
            tracing::warn!(
                public_url = %config.public_url,
                "development mode: cookies are not Secure and pages show a development banner"
            );
        }
        Ok(Self(Arc::new(Inner {
            config,
            storage: deps.storage,
            clock: deps.clock,
            hasher: deps.hasher,
            breach: deps.breach,
            kek: deps.kek,
            renderer,
            cookies,
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

    pub fn renderer(&self) -> &Renderer {
        &self.0.renderer
    }

    pub fn cookies(&self) -> &CookiePolicy {
        &self.0.cookies
    }
}
