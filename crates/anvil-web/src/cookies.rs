//! Cookie policy (SEC-04).
//!
//! | | prod (https public URL) | dev (http) |
//! |---|---|---|
//! | session | `__Host-anvil_session_{t}`, Secure, HttpOnly, SameSite=Lax, Path=/ | `anvil_session_{t}`, HttpOnly, SameSite=Lax, Path=/ |
//! | flow | `__Host-anvil_flow_{t}`, Secure, HttpOnly, SameSite=Strict, Path=/ | `anvil_flow_{t}`, HttpOnly, SameSite=Strict, Path=/ |
//! | upstream binding | `__Host-anvil_upstream_{t}`, Secure, HttpOnly, SameSite=Lax, Path=/, Max-Age=600 | `anvil_upstream_{t}`, HttpOnly, SameSite=Lax, Path=/, Max-Age=600 |
//!
//! The upstream binding cookie ties an upstream sign-in to the browser that started it. It is
//! SameSite=Lax because the provider returns with a cross-site top-level navigation, on which the
//! Strict flow cookie is not sent.
//!
//! `{t}` is the tenant short id (first 12 hex characters of the tenant UUID): path-based tenants
//! share one host, and `__Host-` cookies cannot be scoped by path, so the tenant is part of the
//! name. No cookie ever has a `Domain` attribute.

use anvil_core::model::Tenant;
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

/// Builds and names the session and flow cookies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookiePolicy {
    secure: bool,
}

/// First 12 hex characters of the tenant UUID (simple form).
fn short_id(t: &Tenant) -> String {
    let mut s = t.id.0.simple().to_string();
    s.truncate(12);
    s
}

impl CookiePolicy {
    /// `secure = true` for an https public URL: `__Host-` prefix and the `Secure` attribute.
    pub fn new(secure: bool) -> Self {
        Self { secure }
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    fn prefix(&self) -> &'static str {
        if self.secure { "__Host-" } else { "" }
    }

    pub fn session_name(&self, t: &Tenant) -> String {
        format!("{}anvil_session_{}", self.prefix(), short_id(t))
    }

    pub fn flow_name(&self, t: &Tenant) -> String {
        format!("{}anvil_flow_{}", self.prefix(), short_id(t))
    }

    /// Name of the upstream sign-in binding cookie.
    pub fn upstream_name(&self, t: &Tenant) -> String {
        format!("{}anvil_upstream_{}", self.prefix(), short_id(t))
    }

    fn build(&self, name: String, value: String, same_site: SameSite) -> Cookie<'static> {
        Cookie::build((name, value))
            .http_only(true)
            .secure(self.secure)
            .same_site(same_site)
            .path("/")
            .build()
    }

    /// Browser session cookie (SameSite=Lax so the authorize redirect from a relying party
    /// carries it). A session cookie in the browser sense: no `Max-Age`; the server enforces
    /// idle and absolute expiry.
    pub fn session_cookie(&self, t: &Tenant, value: &str) -> Cookie<'static> {
        self.build(self.session_name(t), value.to_owned(), SameSite::Lax)
    }

    /// Self-service flow cookie (SameSite=Strict).
    pub fn flow_cookie(&self, t: &Tenant, value: &str) -> Cookie<'static> {
        self.build(self.flow_name(t), value.to_owned(), SameSite::Strict)
    }

    /// Removes the flow cookie (empty value, `Max-Age=0`).
    pub fn clear_flow(&self, t: &Tenant) -> Cookie<'static> {
        let mut c = self.build(self.flow_name(t), String::new(), SameSite::Strict);
        c.set_max_age(Duration::ZERO);
        c
    }

    /// Upstream sign-in binding cookie (SameSite=Lax so the provider's return carries it; 10
    /// minutes, the lifetime of a started upstream sign-in).
    pub fn upstream_binding_cookie(&self, t: &Tenant, value: &str) -> Cookie<'static> {
        let mut c = self.build(self.upstream_name(t), value.to_owned(), SameSite::Lax);
        c.set_max_age(Duration::seconds(
            anvil_core::flow::upstream::UPSTREAM_TTL.whole_seconds(),
        ));
        c
    }

    /// Removes the upstream binding cookie (empty value, `Max-Age=0`).
    pub fn clear_upstream_binding(&self, t: &Tenant) -> Cookie<'static> {
        let mut c = self.build(self.upstream_name(t), String::new(), SameSite::Lax);
        c.set_max_age(Duration::ZERO);
        c
    }

    /// Removes the session cookie (empty value, `Max-Age=0`).
    pub fn clear_session(&self, t: &Tenant) -> Cookie<'static> {
        let mut c = self.build(self.session_name(t), String::new(), SameSite::Lax);
        c.set_max_age(Duration::ZERO);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::model::{TenantId, TenantSettings};
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn tenant() -> Tenant {
        Tenant {
            id: TenantId(Uuid::parse_str("0192f0c4-7a1b-7c3d-8e9f-0123456789ab").expect("uuid")),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn prod_cookies_are_host_prefixed_and_secure() {
        let p = CookiePolicy::new(true);
        let t = tenant();
        assert_eq!(p.session_name(&t), "__Host-anvil_session_0192f0c47a1b");
        assert_eq!(p.flow_name(&t), "__Host-anvil_flow_0192f0c47a1b");
        let s = p.session_cookie(&t, "v");
        assert!(s.name().starts_with("__Host-"));
        assert_eq!(s.secure(), Some(true));
        assert_eq!(s.http_only(), Some(true));
        assert_eq!(s.path(), Some("/"));
        assert_eq!(s.domain(), None);
        assert_eq!(s.same_site(), Some(SameSite::Lax));
        let f = p.flow_cookie(&t, "v");
        assert!(f.name().starts_with("__Host-"));
        assert_eq!(f.secure(), Some(true));
        assert_eq!(f.http_only(), Some(true));
        assert_eq!(f.path(), Some("/"));
        assert_eq!(f.same_site(), Some(SameSite::Strict));
        let header = f.to_string();
        assert!(
            header.contains("Secure") && header.contains("HttpOnly"),
            "{header}"
        );
    }

    #[test]
    fn dev_cookies_have_no_prefix_and_no_secure() {
        let p = CookiePolicy::new(false);
        let t = tenant();
        let s = p.session_cookie(&t, "v");
        assert_eq!(s.name(), "anvil_session_0192f0c47a1b");
        assert_ne!(s.secure(), Some(true));
        assert_eq!(s.http_only(), Some(true));
        assert_eq!(s.same_site(), Some(SameSite::Lax));
        let f = p.flow_cookie(&t, "v");
        assert_eq!(f.name(), "anvil_flow_0192f0c47a1b");
        assert_ne!(f.secure(), Some(true));
        assert_eq!(f.same_site(), Some(SameSite::Strict));
        assert!(!f.to_string().contains("Secure"));
    }

    #[test]
    fn upstream_binding_cookie_is_lax_short_lived_and_host_prefixed() {
        let p = CookiePolicy::new(true);
        let t = tenant();
        let c = p.upstream_binding_cookie(&t, "v");
        assert_eq!(c.name(), "__Host-anvil_upstream_0192f0c47a1b");
        assert_eq!(c.same_site(), Some(SameSite::Lax));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.path(), Some("/"));
        assert_eq!(c.domain(), None);
        assert_eq!(c.max_age(), Some(Duration::seconds(600)));
        let cleared = p.clear_upstream_binding(&t);
        assert_eq!(cleared.max_age(), Some(Duration::ZERO));
        assert_eq!(cleared.value(), "");
        let dev = CookiePolicy::new(false).upstream_binding_cookie(&t, "v");
        assert_eq!(dev.name(), "anvil_upstream_0192f0c47a1b");
        assert_ne!(dev.secure(), Some(true));
    }

    #[test]
    fn clear_flow_expires_the_cookie() {
        let p = CookiePolicy::new(true);
        let c = p.clear_flow(&tenant());
        assert_eq!(c.value(), "");
        assert_eq!(c.max_age(), Some(Duration::ZERO));
        assert_eq!(c.name(), p.flow_name(&tenant()));
    }
}
