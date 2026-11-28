//! Tenant resolution. Runs **before** routing (it wraps the inner router as a service), so it can
//! rewrite `/t/{slug}/…` to the tenant-relative path the routes are registered on.
//!
//! Order: a registered custom host → `/t/{slug}` (including the inserted well-known forms: RFC 8414
//! `/.well-known/oauth-authorization-server/t/{slug}` and OIDC path insertion
//! `/.well-known/openid-configuration/t/{slug}`, which MCP clients try) → the `default` tenant at
//! the root.
//! The issuer is computed once per request with [`anvil_core::model::issuer`].
//!
//! If the default tenant does not exist (not installed yet) root requests carry no
//! [`ResolvedTenant`]; handlers that need one answer with the `not_found` error page.
//!
//! ## Unknown-host negative cache (QUAL-05)
//!
//! A request whose `Host` is not the public host costs a tenant lookup by host. Hosts that are
//! **not** a tenant host are remembered in `AppState::unknown_hosts` for
//! [`AppConfig::unknown_host_ttl`](crate::config::AppConfig::unknown_host_ttl) (default 5 s,
//! bounded to [`UNKNOWN_HOSTS_CAPACITY`](crate::state::UNKNOWN_HOSTS_CAPACITY) entries). A miss
//! only means "not a host tenant", so serving it from the cache is safe; the one visible effect is
//! that a **newly configured tenant host starts resolving on each node within that TTL** (there
//! is deliberately no invalidation hook: the TTL bound is the contract). Positive results, tenant
//! rows and lookup errors are never cached, so a deleted tenant or a removed host stops resolving
//! on the very next request.

use anvil_core::model::{DEFAULT_TENANT_SLUG, Tenant, TenantBase, issuer};
use axum::extract::{FromRequestParts, OptionalFromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::errors::error_page_in;
use crate::i18n::locale_of;
use crate::state::AppState;

/// The tenant a request addresses, inserted as a request extension by the tenant layer.
#[derive(Debug, Clone)]
pub struct ResolvedTenant {
    pub tenant: Tenant,
    pub base: TenantBase,
    /// The tenant's issuer (no trailing `/`).
    pub issuer: String,
}

impl ResolvedTenant {
    /// The path prefix of the tenant below the public URL: `""` or `/t/{slug}`.
    pub fn base_path(&self) -> String {
        match &self.base {
            TenantBase::Path(slug) => format!("/t/{slug}"),
            TenantBase::Root | TenantBase::Host(_) => String::new(),
        }
    }

    /// Absolute URL of a tenant-relative path (`/ui/login` → `{issuer}/ui/login`).
    pub fn ui_url(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }
}

/// Origins allowed for unsafe browser requests (Fetch-Metadata CSRF check): the public origin and,
/// for host-based tenants, the tenant host's origin. Inserted by the tenant layer.
#[derive(Debug, Clone)]
pub(crate) struct AllowedOrigins(pub(crate) Vec<String>);

/// Which tenant a path addresses, before any lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Root,
    Path(String),
    Host(String),
    /// Malformed tenant path (`/t/`, invalid slug): 404 without a lookup.
    Invalid,
}

const RFC8414: &str = "/.well-known/oauth-authorization-server";
const OIDC_DISCOVERY: &str = "/.well-known/openid-configuration";

/// Well-known documents also served with the tenant path inserted after them
/// (`{well-known}/t/{slug}`), rewritten to the tenant-relative well-known path.
const INSERTED_WELL_KNOWN: [&str; 2] = [RFC8414, OIDC_DISCOVERY];

fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Pure classification of a request. `host_tenant` is the request host if it is a registered
/// tenant host. Returns the target and the tenant-relative path the routes see.
pub(crate) fn classify(path: &str, host_tenant: Option<&str>) -> (Target, String) {
    if let Some(host) = host_tenant {
        return (Target::Host(host.to_owned()), path.to_owned());
    }
    for well_known in INSERTED_WELL_KNOWN {
        if let Some(rest) = path
            .strip_prefix(well_known)
            .and_then(|r| r.strip_prefix("/t/"))
        {
            return if valid_slug(rest) {
                (Target::Path(rest.to_owned()), well_known.to_owned())
            } else {
                (Target::Invalid, path.to_owned())
            };
        }
    }
    if path == "/t" {
        return (Target::Invalid, path.to_owned());
    }
    if let Some(rest) = path.strip_prefix("/t/") {
        let (slug, tail) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if !valid_slug(slug) {
            return (Target::Invalid, path.to_owned());
        }
        let tail = if tail.is_empty() { "/" } else { tail };
        return (Target::Path(slug.to_owned()), tail.to_owned());
    }
    (Target::Root, path.to_owned())
}

/// Paths that never need a tenant (liveness/readiness must not depend on tenant lookups).
fn is_tenantless(path: &str) -> bool {
    matches!(path, "/health/live" | "/health/ready" | "/healthz")
}

/// The request host (Host header, else the URI authority), lowercased, without a trailing dot.
fn request_host(req: &Request) -> Option<String> {
    let raw = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()))?;
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn rewrite(uri: &Uri, new_path: &str) -> Option<Uri> {
    let pq = match uri.query() {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path.to_owned(),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(pq.parse().ok()?);
    Uri::from_parts(parts).ok()
}

fn internal(state: &AppState, headers: &HeaderMap, query: Option<&str>) -> Response {
    let locale = locale_of(state, None, headers, query);
    error_page_in(
        state,
        None,
        &locale,
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "",
    )
}

/// The installation-level 404 (no tenant resolved), in the request's language.
fn not_found(state: &AppState, headers: &HeaderMap, query: Option<&str>) -> Response {
    let locale = locale_of(state, None, headers, query);
    error_page_in(state, None, &locale, StatusCode::NOT_FOUND, "not_found", "")
}

/// The tenant layer (used with `axum::middleware::from_fn_with_state` around the inner router).
pub(crate) async fn resolve(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    req.extensions_mut().insert(state.clone());
    let public_origin = state.config().public_origin();
    if is_tenantless(req.uri().path()) {
        req.extensions_mut()
            .insert(AllowedOrigins(vec![public_origin]));
        return next.run(req).await;
    }

    let tenants = state.storage().tenants();
    let mut host_tenant: Option<Tenant> = None;
    if let Some(host) = request_host(&req)
        && host != state.config().public_url.host_port()
        && !state.unknown_hosts().contains_key(&host)
    {
        match tenants.get_by_host(&host).await {
            Ok(Some(t)) => host_tenant = Some(t),
            // Only misses are cached (see the module docs); a found tenant is looked up again on
            // every request.
            Ok(None) => state.unknown_hosts().insert(host, ()),
            Err(e) => {
                tracing::error!(error = %e, "tenant lookup by host failed");
                return internal(&state, req.headers(), req.uri().query());
            }
        }
    }

    let (target, path) = classify(
        req.uri().path(),
        host_tenant.as_ref().and_then(|t| t.host.as_deref()),
    );
    let (tenant, base) = match target {
        Target::Invalid => return not_found(&state, req.headers(), req.uri().query()),
        Target::Host(h) => (host_tenant, TenantBase::Host(h)),
        Target::Path(slug) => match tenants.get_by_slug(&slug).await {
            Ok(Some(t)) => (Some(t), TenantBase::Path(slug)),
            Ok(None) => return not_found(&state, req.headers(), req.uri().query()),
            Err(e) => {
                tracing::error!(error = %e, "tenant lookup by slug failed");
                return internal(&state, req.headers(), req.uri().query());
            }
        },
        Target::Root => match tenants.get_by_slug(DEFAULT_TENANT_SLUG).await {
            Ok(t) => (t, TenantBase::Root),
            Err(e) => {
                tracing::error!(error = %e, "default tenant lookup failed");
                return internal(&state, req.headers(), req.uri().query());
            }
        },
    };

    let mut origins = vec![public_origin];
    if let TenantBase::Host(h) = &base {
        origins.push(format!("{}://{}", state.config().public_url.scheme(), h));
    }
    req.extensions_mut().insert(AllowedOrigins(origins));

    if let Some(tenant) = tenant {
        let iss = issuer(&state.config().public_url, &base);
        req.extensions_mut().insert(ResolvedTenant {
            tenant,
            base,
            issuer: iss,
        });
    }
    if path != req.uri().path() {
        match rewrite(req.uri(), &path) {
            Some(uri) => *req.uri_mut() = uri,
            None => return not_found(&state, req.headers(), req.uri().query()),
        }
    }
    next.run(req).await
}

impl FromRequestParts<AppState> for ResolvedTenant {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        parts
            .extensions
            .get::<ResolvedTenant>()
            .cloned()
            .ok_or_else(|| not_found(state, &parts.headers, parts.uri.query()))
    }
}

impl OptionalFromRequestParts<AppState> for ResolvedTenant {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<ResolvedTenant>().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(slug: &str) -> Target {
        Target::Path(slug.to_owned())
    }

    #[test]
    fn path_tenants_are_rewritten() {
        assert_eq!(
            classify("/t/acme/token", None),
            (path("acme"), "/token".into())
        );
        assert_eq!(
            classify("/t/acme/.well-known/openid-configuration", None),
            (path("acme"), "/.well-known/openid-configuration".into())
        );
        assert_eq!(classify("/t/acme", None), (path("acme"), "/".into()));
        assert_eq!(classify("/t/acme/", None), (path("acme"), "/".into()));
    }

    #[test]
    fn rfc8414_inserted_path() {
        assert_eq!(
            classify("/.well-known/oauth-authorization-server/t/acme", None),
            (path("acme"), RFC8414.into())
        );
        assert_eq!(
            classify("/.well-known/oauth-authorization-server", None),
            (Target::Root, RFC8414.into())
        );
        assert_eq!(
            classify("/.well-known/oauth-authorization-server/t/", None).0,
            Target::Invalid
        );
        assert_eq!(
            classify("/.well-known/oauth-authorization-server/t/a/b", None).0,
            Target::Invalid
        );
    }

    #[test]
    fn oidc_inserted_path() {
        assert_eq!(
            classify("/.well-known/openid-configuration/t/acme", None),
            (path("acme"), OIDC_DISCOVERY.into())
        );
        assert_eq!(
            classify("/.well-known/openid-configuration", None),
            (Target::Root, OIDC_DISCOVERY.into())
        );
        for bad in [
            "/.well-known/openid-configuration/t/",
            "/.well-known/openid-configuration/t/a/b",
            "/.well-known/openid-configuration/t/a b",
        ] {
            assert_eq!(classify(bad, None).0, Target::Invalid, "{bad}");
        }
    }

    #[test]
    fn host_tenants_win_and_keep_the_path() {
        assert_eq!(
            classify("/t/acme/token", Some("login.acme.com")),
            (
                Target::Host("login.acme.com".into()),
                "/t/acme/token".into()
            )
        );
        assert_eq!(
            classify("/token", Some("login.acme.com")),
            (Target::Host("login.acme.com".into()), "/token".into())
        );
    }

    #[test]
    fn root_and_invalid() {
        assert_eq!(classify("/token", None), (Target::Root, "/token".into()));
        assert_eq!(classify("/", None), (Target::Root, "/".into()));
        assert_eq!(classify("/tenant", None), (Target::Root, "/tenant".into()));
        assert_eq!(classify("/t/", None).0, Target::Invalid);
        assert_eq!(classify("/t", None).0, Target::Invalid);
        assert_eq!(classify("/t//token", None).0, Target::Invalid);
        assert_eq!(classify("/t/a%2Fb/token", None).0, Target::Invalid);
    }

    #[test]
    fn rewrite_keeps_the_query() {
        let uri: Uri = "/t/acme/authorize?client_id=x&state=y"
            .parse()
            .expect("uri");
        let out = rewrite(&uri, "/authorize").expect("rewritten");
        assert_eq!(out.path(), "/authorize");
        assert_eq!(out.query(), Some("client_id=x&state=y"));
    }
}
