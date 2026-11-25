//! Configuration of the HTTP application built by [`crate::app`].

use std::path::PathBuf;

use anvil_cache::limiter::LimiterConfig;
use anvil_core::model::PublicUrl;
use anvil_core::policy::PasswordPolicy;

use crate::adapters::captcha::CaptchaEndpoints;
use crate::adapters::outbound::OutboundPolicy;
use crate::client_ip::TrustedProxies;

/// Settings the web layer needs. The binary builds it from its own configuration (02-18).
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// The installation's public base URL. Issuers, cookie policy and HSTS derive from it.
    pub public_url: PublicUrl,
    /// Operator theme directory (`templates/`, `emails/`, `static/`). Files found there win over the
    /// embedded default theme; missing files fall back to it.
    pub theme_dir: Option<PathBuf>,
    pub password_policy: PasswordPolicy,
    /// Operator opt-in to a plain-http public URL on a non-loopback host (`--insecure-http`).
    /// Treated as development mode (banner, dev cookie policy).
    pub insecure_http: bool,
    /// Reverse proxies whose forwarding header is believed for the client IP (OPS-06). Default:
    /// loopback in development mode (public URL on a loopback host), nobody otherwise.
    pub trusted_proxies: TrustedProxies,
    /// Rate limits (SEC-05): on by default with the documented quotas of
    /// [`LimiterConfig::default`]. `enabled = false` is the operator switch that turns limiting off.
    pub rate_limits: LimiterConfig,
    /// CAPTCHA siteverify endpoints (AUTH-09). Default: the providers' public endpoints. Only
    /// used for tenants that configure a CAPTCHA; tests point them at a local mock.
    pub captcha_endpoints: CaptchaEndpoints,
    /// Destination policy of the single outbound HTTP client (SSRF guard). Default, following
    /// the trusted-proxies precedent: loopback (`127.0.0.0/8`, `::1/128`) allowed, plain http to
    /// it allowed, in development mode (public URL on a loopback host); nothing beyond public
    /// https destinations otherwise. The binary replaces `allow_cidrs` with an explicit
    /// `outbound_allow_cidrs`.
    pub outbound: OutboundPolicy,
    /// Whether the installation SMTP transport (`smtp_url`) is configured. Tenants without SMTP
    /// settings of their own can enable email sign-in (codes, magic links) only when it is.
    pub installation_smtp: bool,
}

impl AppConfig {
    /// A configuration with the default password policy and no theme override.
    pub fn new(public_url: PublicUrl) -> Self {
        let (trusted_proxies, outbound) = if public_url.is_dev_mode() {
            (TrustedProxies::loopback(), OutboundPolicy::loopback_dev())
        } else {
            (TrustedProxies::default(), OutboundPolicy::default())
        };
        Self {
            trusted_proxies,
            public_url,
            theme_dir: None,
            password_policy: PasswordPolicy::default(),
            insecure_http: false,
            rate_limits: LimiterConfig::default(),
            captcha_endpoints: CaptchaEndpoints::default(),
            outbound,
            installation_smtp: false,
        }
    }

    /// Development mode: plain http on a loopback host, or `insecure_http`. Decided from the
    /// configuration only, never from request headers.
    pub fn dev_mode(&self) -> bool {
        self.public_url.is_dev_mode() || self.insecure_http
    }

    /// `true` when the public URL uses https (HSTS and `Secure` cookies).
    pub fn is_https(&self) -> bool {
        self.public_url.scheme() == "https"
    }

    /// The public origin (`scheme://host[:port]`), used by the Fetch-Metadata CSRF check.
    pub fn public_origin(&self) -> String {
        format!(
            "{}://{}",
            self.public_url.scheme(),
            self.public_url.host_port()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_and_modes() {
        let prod = AppConfig::new(PublicUrl::parse("https://op.test/base").expect("url"));
        assert_eq!(prod.public_origin(), "https://op.test");
        assert!(prod.is_https());
        assert!(!prod.dev_mode());
        let dev = AppConfig::new(PublicUrl::parse("http://localhost:8080").expect("url"));
        assert_eq!(dev.public_origin(), "http://localhost:8080");
        assert!(!dev.is_https());
        assert!(dev.dev_mode());
        let mut insecure = AppConfig::new(PublicUrl::parse("http://op.test").expect("url"));
        assert!(!insecure.dev_mode());
        insecure.insecure_http = true;
        assert!(insecure.dev_mode());
        assert!(!insecure.is_https());
    }

    #[test]
    fn trusted_proxies_default_by_mode() {
        let prod = AppConfig::new(PublicUrl::parse("https://op.test").expect("url"));
        assert!(prod.trusted_proxies.cidrs.is_empty());
        let dev = AppConfig::new(PublicUrl::parse("http://localhost:8080").expect("url"));
        assert_eq!(dev.trusted_proxies, TrustedProxies::loopback());
    }

    #[test]
    fn outbound_policy_default_by_mode() {
        let prod = AppConfig::new(PublicUrl::parse("https://op.test").expect("url"));
        assert_eq!(prod.outbound, OutboundPolicy::default());
        assert!(prod.outbound.allow_cidrs.is_empty() && !prod.outbound.allow_http);
        let dev = AppConfig::new(PublicUrl::parse("http://localhost:8080").expect("url"));
        assert_eq!(dev.outbound, OutboundPolicy::loopback_dev());
    }

    #[test]
    fn rate_limits_are_on_by_default() {
        let cfg = AppConfig::new(PublicUrl::parse("https://op.test").expect("url"));
        assert!(cfg.rate_limits.enabled);
        assert_eq!(cfg.rate_limits, LimiterConfig::default());
    }
}
