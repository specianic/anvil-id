//! CAPTCHA verification (AUTH-09): Cloudflare Turnstile or hCaptcha, enabled per tenant.
//!
//! The browser solves the widget rendered by `templates/captcha.html`; the server verifies the
//! response token with the provider's siteverify endpoint (form-encoded `secret`, `response`,
//! `remoteip`). Verification **fails closed**: an empty token, a network error, a timeout
//! (5 s by default), a non-success status, an oversized or malformed body and `success: false` are
//! all errors.
//!
//! The siteverify URLs are constructor arguments ([`CaptchaEndpoints`], defaulting to the
//! provider URLs); request data never selects the destination. An endpoint must be https (plain
//! http only to a loopback host), and requests go through the single SSRF-guarded
//! [`OutboundClient`] (no redirects, no proxies, destination policy).
//!
//! Enabling CAPTCHA loads the provider's script and frame on the pages that render the widget:
//! [`captcha_csp`] gives the CSP for those pages only; every other page keeps the strict default
//! CSP of [`crate::layers::security_headers::CSP`].

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::{CAPTCHA_SECRET_PURPOSE, CaptchaProvider, CaptchaSettings, TenantId};
use anvil_jose::kek::Kek;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::adapters::outbound::{self, OutboundClient, OutboundError};

/// Cloudflare Turnstile siteverify endpoint.
pub const TURNSTILE_SITEVERIFY: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
/// hCaptcha siteverify endpoint.
pub const HCAPTCHA_SITEVERIFY: &str = "https://api.hcaptcha.com/siteverify";
/// Default siteverify timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest siteverify response body read.
const MAX_BODY: usize = 16 * 1024;
/// Longest response token accepted (provider tokens are a few KiB at most).
const MAX_TOKEN: usize = 8 * 1024;

/// Why a CAPTCHA was not accepted. Every variant means "reject the attempt".
#[derive(Debug, thiserror::Error)]
pub enum CaptchaError {
    #[error("no CAPTCHA response was submitted")]
    MissingToken,
    #[error("the CAPTCHA response was rejected by the provider")]
    Rejected,
    #[error("CAPTCHA verification is unavailable: {0}")]
    Unavailable(String),
    #[error("CAPTCHA configuration error: {0}")]
    Config(String),
}

/// The siteverify URL of each provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaEndpoints {
    pub turnstile: String,
    pub hcaptcha: String,
}

impl Default for CaptchaEndpoints {
    fn default() -> Self {
        Self {
            turnstile: TURNSTILE_SITEVERIFY.to_owned(),
            hcaptcha: HCAPTCHA_SITEVERIFY.to_owned(),
        }
    }
}

impl CaptchaEndpoints {
    fn url(&self, provider: CaptchaProvider) -> &str {
        match provider {
            CaptchaProvider::Turnstile => &self.turnstile,
            CaptchaProvider::Hcaptcha => &self.hcaptcha,
        }
    }
}

/// An endpoint must be https, or plain http to a loopback host.
fn check_endpoint(raw: &str) -> Result<(), CaptchaError> {
    let url = url::Url::parse(raw)
        .map_err(|e| CaptchaError::Config(format!("invalid siteverify URL: {e}")))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(CaptchaError::Config(
            "siteverify URL must use https".to_owned(),
        )),
    }
}

/// The form field the widget submits its response token in.
pub fn response_field(provider: CaptchaProvider) -> &'static str {
    match provider {
        CaptchaProvider::Turnstile => "cf-turnstile-response",
        CaptchaProvider::Hcaptcha => "h-captcha-response",
    }
}

/// Opens the tenant's sealed CAPTCHA secret (`Kek::open(CAPTCHA_SECRET_PURPOSE, tenant id bytes,
/// ..)` of the base64url `secret_sealed`).
pub fn open_secret(
    kek: &Kek,
    tenant: TenantId,
    settings: &CaptchaSettings,
) -> Result<SecretString, CaptchaError> {
    let sealed = anvil_jose::encoding::b64url_decode(&settings.secret_sealed)
        .map_err(|_| CaptchaError::Config("sealed CAPTCHA secret is not base64url".to_owned()))?;
    let plain = kek
        .open(CAPTCHA_SECRET_PURPOSE, tenant.0.as_bytes(), &sealed)
        .map_err(|_| CaptchaError::Config("sealed CAPTCHA secret does not open".to_owned()))?;
    let secret = std::str::from_utf8(&plain)
        .map_err(|_| CaptchaError::Config("CAPTCHA secret is not UTF-8".to_owned()))?;
    Ok(SecretString::from(secret.to_owned()))
}

#[derive(Debug, Deserialize)]
struct SiteverifyResponse {
    success: bool,
    #[serde(rename = "error-codes", default)]
    error_codes: Vec<String>,
}

/// Server-side CAPTCHA verification against the provider's siteverify endpoint.
#[derive(Debug, Clone)]
pub struct CaptchaVerifier {
    outbound: Arc<OutboundClient>,
    endpoints: CaptchaEndpoints,
    timeout: Duration,
}

impl CaptchaVerifier {
    /// A verifier for `endpoints` with the given request timeout, sending through `outbound`.
    /// Fails if an endpoint is not https (plain http is allowed only to a loopback host).
    pub fn new(
        outbound: Arc<OutboundClient>,
        endpoints: CaptchaEndpoints,
        timeout: Duration,
    ) -> Result<Self, CaptchaError> {
        check_endpoint(&endpoints.turnstile)?;
        check_endpoint(&endpoints.hcaptcha)?;
        Ok(Self {
            outbound,
            endpoints,
            timeout,
        })
    }

    /// A verifier for the providers' public endpoints with [`DEFAULT_TIMEOUT`].
    pub fn with_defaults(outbound: Arc<OutboundClient>) -> Result<Self, CaptchaError> {
        Self::new(outbound, CaptchaEndpoints::default(), DEFAULT_TIMEOUT)
    }

    /// Verifies `token` for the tenant's provider. `Ok(())` only when the provider answered
    /// `success: true`; everything else is an error (fail closed).
    pub async fn verify(
        &self,
        settings: &CaptchaSettings,
        secret: &SecretString,
        token: &str,
        ip: Option<IpAddr>,
    ) -> Result<(), CaptchaError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(CaptchaError::MissingToken);
        }
        if token.len() > MAX_TOKEN {
            return Err(CaptchaError::Rejected);
        }
        // The serializer is not `Send`: finish it before the request is awaited, so the
        // verification future can run on a multi-threaded runtime (a handler future).
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("secret", secret.expose_secret())
                .append_pair("response", token);
            if let Some(ip) = ip {
                form.append_pair("remoteip", &ip.to_string());
            }
            form.finish()
        };
        let url = self.endpoints.url(settings.provider);
        let body = self
            .outbound
            .post(url)
            .map_err(siteverify_failed)?
            .form_body(body)
            .timeout(self.timeout)
            .fetch(MAX_BODY)
            .await
            .map_err(siteverify_failed)?;
        let parsed: SiteverifyResponse = serde_json::from_slice(&body)
            .map_err(|_| unavailable("malformed siteverify response".to_owned()))?;
        if parsed.success {
            Ok(())
        } else {
            tracing::info!(
                provider = settings.provider.as_str(),
                error_codes = ?parsed.error_codes,
                "CAPTCHA rejected"
            );
            Err(CaptchaError::Rejected)
        }
    }
}

fn siteverify_failed(e: OutboundError) -> CaptchaError {
    match e {
        OutboundError::Status(code) => unavailable(format!("siteverify status {code}")),
        OutboundError::TooLarge => unavailable("siteverify response too large".to_owned()),
        other => unavailable(format!("siteverify request failed: {other}")),
    }
}

// The siteverify body limit stays below the generic document limit.
const _: () = assert!(MAX_BODY <= outbound::LIMIT_DOCUMENT);

fn unavailable(msg: String) -> CaptchaError {
    tracing::warn!(error = %msg, "CAPTCHA verification unavailable; rejecting (fail closed)");
    CaptchaError::Unavailable(msg)
}

/// Extra CSP sources a page needs to render a provider's widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptchaCsp {
    pub script_src: &'static [&'static str],
    pub frame_src: &'static [&'static str],
    pub connect_src: &'static [&'static str],
    pub style_src: &'static [&'static str],
}

const TURNSTILE_ORIGINS: &[&str] = &["https://challenges.cloudflare.com"];
const HCAPTCHA_ORIGINS: &[&str] = &["https://hcaptcha.com", "https://*.hcaptcha.com"];

/// The extra CSP origins of `provider`'s widget. Only pages that render the widget use them.
pub fn captcha_csp(provider: CaptchaProvider) -> CaptchaCsp {
    match provider {
        CaptchaProvider::Turnstile => CaptchaCsp {
            script_src: TURNSTILE_ORIGINS,
            frame_src: TURNSTILE_ORIGINS,
            connect_src: TURNSTILE_ORIGINS,
            style_src: &[],
        },
        CaptchaProvider::Hcaptcha => CaptchaCsp {
            script_src: HCAPTCHA_ORIGINS,
            frame_src: HCAPTCHA_ORIGINS,
            connect_src: HCAPTCHA_ORIGINS,
            style_src: HCAPTCHA_ORIGINS,
        },
    }
}

impl CaptchaCsp {
    /// The full Content-Security-Policy of a page that renders the widget: the strict default
    /// plus these origins (and `'self'` for scripts and connections). Set it on the response;
    /// the security-headers layer keeps a CSP a handler already set.
    pub fn header_value(&self) -> String {
        let join = |base: &str, extra: &[&str]| {
            let mut v = vec![base];
            v.extend_from_slice(extra);
            v.join(" ")
        };
        format!(
            "default-src 'none'; script-src {}; style-src {}; img-src 'self'; frame-src {}; \
             connect-src {}; frame-ancestors 'none'; base-uri 'none'",
            join("'self'", self.script_src),
            join("'self'", self.style_src),
            self.frame_src.join(" "),
            join("'self'", self.connect_src),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::security_headers::CSP;

    #[test]
    fn endpoints_must_be_https_or_loopback_http() {
        assert!(check_endpoint(TURNSTILE_SITEVERIFY).is_ok());
        assert!(check_endpoint(HCAPTCHA_SITEVERIFY).is_ok());
        assert!(check_endpoint("http://127.0.0.1:4000/siteverify").is_ok());
        assert!(check_endpoint("http://[::1]:4000/siteverify").is_ok());
        assert!(check_endpoint("http://localhost:4000/siteverify").is_ok());
        assert!(check_endpoint("http://challenges.cloudflare.com/x").is_err());
        assert!(check_endpoint("http://10.0.0.1/x").is_err());
        assert!(check_endpoint("file:///etc/passwd").is_err());
        assert!(check_endpoint("not a url").is_err());
        let bad = CaptchaEndpoints {
            turnstile: "http://example.test/x".into(),
            hcaptcha: HCAPTCHA_SITEVERIFY.into(),
        };
        let outbound = Arc::new(
            OutboundClient::new(&crate::adapters::outbound::OutboundPolicy::default())
                .expect("client"),
        );
        assert!(CaptchaVerifier::new(Arc::clone(&outbound), bad, DEFAULT_TIMEOUT).is_err());
        assert!(CaptchaVerifier::with_defaults(outbound).is_ok());
    }

    #[test]
    fn csp_per_provider() {
        let t = captcha_csp(CaptchaProvider::Turnstile).header_value();
        assert!(
            t.contains("script-src 'self' https://challenges.cloudflare.com;"),
            "{t}"
        );
        assert!(
            t.contains("frame-src https://challenges.cloudflare.com;"),
            "{t}"
        );
        assert!(
            t.contains("connect-src 'self' https://challenges.cloudflare.com;"),
            "{t}"
        );
        assert!(!t.contains("hcaptcha"));
        let h = captcha_csp(CaptchaProvider::Hcaptcha).header_value();
        assert!(h.contains("script-src 'self' https://hcaptcha.com https://*.hcaptcha.com;"));
        assert!(h.contains("style-src 'self' https://hcaptcha.com https://*.hcaptcha.com;"));
        assert!(!h.contains("cloudflare"));
        for csp in [&t, &h] {
            assert!(csp.contains("frame-ancestors 'none'"));
            assert!(csp.contains("base-uri 'none'"));
            assert!(csp.starts_with("default-src 'none';"));
            assert!(!csp.contains("unsafe-inline"));
            assert!(!csp.contains("unsafe-eval"));
        }
        // The default CSP stays strict: no third-party origin.
        assert!(!CSP.contains("cloudflare") && !CSP.contains("hcaptcha"));
    }

    #[test]
    fn response_fields() {
        assert_eq!(
            response_field(CaptchaProvider::Turnstile),
            "cf-turnstile-response"
        );
        assert_eq!(
            response_field(CaptchaProvider::Hcaptcha),
            "h-captcha-response"
        );
    }

    #[test]
    fn sealed_secret_opens_only_for_its_tenant() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let sealed = kek
            .seal(CAPTCHA_SECRET_PURPOSE, tenant.0.as_bytes(), b"0x-secret")
            .expect("seal");
        let settings = CaptchaSettings {
            provider: CaptchaProvider::Turnstile,
            site_key: "site".into(),
            secret_sealed: anvil_jose::encoding::b64url(&sealed),
        };
        let secret = open_secret(&kek, tenant, &settings).expect("opens");
        assert_eq!(secret.expose_secret(), "0x-secret");
        assert!(open_secret(&kek, TenantId::new_v7(), &settings).is_err());
        let padded = CaptchaSettings {
            secret_sealed: format!("{}=", settings.secret_sealed),
            ..settings
        };
        assert!(
            matches!(
                open_secret(&kek, tenant, &padded),
                Err(CaptchaError::Config(_))
            ),
            "non-canonical base64url is rejected"
        );
    }
}
