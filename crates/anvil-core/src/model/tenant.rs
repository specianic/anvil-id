//! Tenants, the public URL and the single issuer function.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{TenantId, str_enum};
use crate::error::CoreError;

/// Slug of the installation's system tenant (holds the administrators and the admin client).
pub const SYSTEM_TENANT_SLUG: &str = "system";
/// Slug of the tenant created on first start for applications.
pub const DEFAULT_TENANT_SLUG: &str = "default";

/// Who may self-register in a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    #[default]
    Open,
    InviteOnly,
    Disabled,
}

str_enum!(RegistrationMode {
    Open => "open",
    InviteOnly => "invite_only",
    Disabled => "disabled",
});

/// Per-tenant settings. Backends store them as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantSettings {
    pub registration: RegistrationMode,
    pub require_verified_email: bool,
}

/// A persisted tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: TenantId,
    pub slug: String,
    pub display_name: String,
    /// Custom host (`login.acme.com`) when the tenant is served host-based. Unique.
    pub host: Option<String>,
    pub settings: TenantSettings,
    pub created_at: OffsetDateTime,
}

/// A tenant to be created. The caller generates the id and timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewTenant {
    pub id: TenantId,
    pub slug: String,
    pub display_name: String,
    pub host: Option<String>,
    pub settings: TenantSettings,
    pub created_at: OffsetDateTime,
}

/// Partial tenant update; `None` leaves a field unchanged. `host: Some(None)` clears the host.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TenantUpdate {
    pub display_name: Option<String>,
    pub host: Option<Option<String>>,
    pub settings: Option<TenantSettings>,
}

/// The installation's public base URL (`ANVIL_PUBLIC_URL`).
///
/// Invariants: scheme `http` or `https`, a non-empty host, no userinfo, query or fragment, and
/// no trailing `/`. Scheme and host are lowercased.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicUrl {
    url: String,
    scheme: String,
    host_port: String,
    host: String,
}

fn invalid_url(message: &str) -> CoreError {
    CoreError::Validation {
        field: "public_url",
        message: message.to_owned(),
    }
}

impl PublicUrl {
    /// Parses and normalises a public URL. See the type docs for the accepted form.
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        if raw.is_empty() || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(invalid_url("must be a non-empty URL without whitespace"));
        }
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| invalid_url("must start with http:// or https://"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(invalid_url("scheme must be http or https"));
        }
        if rest.contains('?') {
            return Err(invalid_url("must not contain a query"));
        }
        if rest.contains('#') {
            return Err(invalid_url("must not contain a fragment"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(invalid_url("must not contain userinfo"));
        }
        let authority = authority.to_ascii_lowercase();
        let (host, port) = split_host_port(&authority)?;
        if let Some(port) = port {
            match port.parse::<u16>() {
                Ok(p) if p > 0 && !port.starts_with('+') => {}
                _ => return Err(invalid_url("invalid port")),
            }
        }
        let path = path.strip_suffix('/').unwrap_or(path);
        if path.contains("//") || path.ends_with('/') {
            return Err(invalid_url("path must not contain empty segments"));
        }
        let host = host.to_owned();
        Ok(Self {
            url: format!("{scheme}://{authority}{path}"),
            scheme,
            host_port: authority,
            host,
        })
    }

    /// The normalised URL (no trailing `/`).
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// `http` or `https`.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Host and optional port, e.g. `localhost:8080` or `[::1]:8080`.
    pub fn host_port(&self) -> &str {
        &self.host_port
    }

    /// Development mode: plain http on a loopback host (`localhost`, `127.0.0.1`, `[::1]`).
    pub fn is_dev_mode(&self) -> bool {
        self.scheme == "http" && matches!(self.host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
    }
}

impl std::fmt::Display for PublicUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.url)
    }
}

/// Splits `host[:port]` / `[v6][:port]` and validates the host characters.
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), CoreError> {
    if authority.is_empty() {
        return Err(invalid_url("missing host"));
    }
    if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| invalid_url("unterminated IPv6 literal"))?;
        let host = &authority[..=end];
        let inner = &host[1..host.len() - 1];
        if inner.is_empty()
            || !inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return Err(invalid_url("invalid IPv6 literal"));
        }
        let rest = &authority[end + 1..];
        return match rest.strip_prefix(':') {
            Some(port) => Ok((host, Some(port))),
            None if rest.is_empty() => Ok((host, None)),
            None => Err(invalid_url("invalid authority")),
        };
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.starts_with('-')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(invalid_url("invalid host"));
    }
    Ok((host, port))
}

/// How a tenant is addressed below the public URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TenantBase {
    /// The tenant served at the public URL itself.
    Root,
    /// Path-based tenant `/t/{slug}`.
    Path(String),
    /// Host-based tenant (custom domain), served with the public URL's scheme.
    Host(String),
}

/// THE issuer function (ARCHITECTURE §12). Every issuer string in the system comes from here.
///
/// - `Root` → the public URL
/// - `Path(slug)` → public URL + `/t/` + slug
/// - `Host(h)` → public URL scheme + `://` + h
///
/// Never ends with `/`.
pub fn issuer(public_url: &PublicUrl, base: &TenantBase) -> String {
    match base {
        TenantBase::Root => public_url.as_str().to_owned(),
        TenantBase::Path(slug) => format!("{}/t/{}", public_url.as_str(), slug.trim_matches('/')),
        TenantBase::Host(host) => {
            format!("{}://{}", public_url.scheme(), host.trim_end_matches('/'))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> PublicUrl {
        PublicUrl::parse(s).unwrap_or_else(|e| panic!("{s} must parse: {e:?}"))
    }

    #[test]
    fn issuer_root_path_host() {
        let u = url("https://id.example");
        assert_eq!(issuer(&u, &TenantBase::Root), "https://id.example");
        assert_eq!(
            issuer(&u, &TenantBase::Path("acme".into())),
            "https://id.example/t/acme"
        );
        assert_eq!(
            issuer(&u, &TenantBase::Host("login.acme.com".into())),
            "https://login.acme.com"
        );
    }

    #[test]
    fn issuer_never_ends_with_slash() {
        let u = url("https://id.example/");
        for base in [
            TenantBase::Root,
            TenantBase::Path("acme".into()),
            TenantBase::Host("login.acme.com/".into()),
        ] {
            let iss = issuer(&u, &base);
            assert!(!iss.ends_with('/'), "{iss} must not end with '/'");
        }
        let with_path = url("https://example.test/idp/");
        assert_eq!(
            issuer(&with_path, &TenantBase::Root),
            "https://example.test/idp"
        );
        assert_eq!(
            issuer(&with_path, &TenantBase::Path("a".into())),
            "https://example.test/idp/t/a"
        );
    }

    #[test]
    fn public_url_rejects_bad_input() {
        for bad in [
            "",
            "ftp://id.example",
            "id.example",
            "https://id.example?x=1",
            "https://id.example/#frag",
            "https://user@id.example",
            "https://user:pw@id.example",
            "https://",
            "https://:8080",
            "https://id.example:0",
            "https://id.example:99999",
            "https://id.example:abc",
            "https://id ex.example",
            "https://id.example//",
            "https://[::1",
            "https://[zz]",
        ] {
            assert!(PublicUrl::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn public_url_normalises() {
        let u = url("HTTPS://ID.Example:8443/");
        assert_eq!(u.as_str(), "https://id.example:8443");
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_port(), "id.example:8443");
        assert_eq!(url("http://[::1]:8080").host_port(), "[::1]:8080");
    }

    #[test]
    fn public_url_dev_mode() {
        for dev in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://localhost",
        ] {
            assert!(url(dev).is_dev_mode(), "{dev} must be dev mode");
        }
        for prod in [
            "https://localhost",
            "http://example.test",
            "https://id.example",
            "http://localhost.example.test",
        ] {
            assert!(!url(prod).is_dev_mode(), "{prod} must not be dev mode");
        }
    }

    #[test]
    fn registration_mode_names_round_trip() {
        for m in RegistrationMode::ALL {
            assert_eq!(RegistrationMode::parse(m.as_str()), Some(*m));
        }
        assert_eq!(RegistrationMode::parse("nope"), None);
        assert_eq!(
            TenantSettings::default().registration,
            RegistrationMode::Open
        );
        assert!(!TenantSettings::default().require_verified_email);
    }
}
