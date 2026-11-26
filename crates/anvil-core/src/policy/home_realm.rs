//! Email domains and home-realm discovery (ORG-04).
//!
//! Pure functions, no I/O:
//! - [`normalize_domain`] turns admin input into the one stored form of a domain (trimmed,
//!   lowercase IDNA A-label) and refuses everything that is not a registrable DNS name an
//!   organization could prove control of.
//! - [`email_domain`] extracts and normalises the domain of an email address.
//! - [`route`] decides where identifier-first login sends an address. It looks at the
//!   address's domain and the tenant's routed domains only, never at whether an account
//!   exists, so the decision reveals nothing about accounts (no enumeration).
//!
//! Routing is a convenience, not an authorization: decisions about trust use memberships and
//! verified domains stored in normalised form.

use std::net::IpAddr;

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

use crate::error::CoreError;
use crate::model::{ConnectionId, OrgDomain, OrgDomainStatus, OrgId};

/// Longest domain name in bytes (RFC 1035 §2.3.4, without the root dot).
pub const MAX_DOMAIN_LEN: usize = 253;

/// Longest DNS label in bytes (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Special-use names (RFC 6761, RFC 6762, ICANN `.internal`) refused as a whole name or as the
/// last label.
const RESERVED_NAMES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "invalid",
    "test",
    "example",
];

/// Why a domain was refused. One variant per rule, for precise API messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("the domain is empty")]
    Empty,
    #[error("enter a domain name, not a URL")]
    Scheme,
    #[error("the domain must not contain a port")]
    Port,
    #[error("the domain must not contain a path, query or fragment")]
    Path,
    #[error("wildcard domains are not accepted")]
    Wildcard,
    #[error("IP addresses are not accepted")]
    IpLiteral,
    #[error("the domain is not a valid internationalised domain name")]
    Idna,
    #[error("the domain needs at least two labels")]
    TooFewLabels,
    #[error("each label must be 1-63 bytes")]
    LabelLength,
    #[error("the domain must be at most 253 bytes")]
    TooLong,
    #[error("reserved and special-use names are not accepted")]
    Reserved,
    #[error("a public suffix cannot be claimed")]
    PublicSuffix,
    #[error("the domain has no known public suffix")]
    UnknownSuffix,
}

impl From<DomainError> for CoreError {
    fn from(e: DomainError) -> Self {
        CoreError::Validation {
            field: "domain",
            message: e.to_string(),
        }
    }
}

/// Normalises a domain to its stored form: trimmed, lowercase, IDNA A-label (UTS #46,
/// STD3 rules, hyphen checks), one trailing root dot removed.
///
/// Refused: a scheme, port, path/query/fragment, wildcard, IP literal, fewer than two labels, a
/// label outside 1..=63 bytes, more than 253 bytes, a reserved name (`localhost`, `*.local`,
/// `*.internal`, `*.localhost`, `*.invalid`, `*.test`, `*.example`), a public suffix (the
/// private section of the list counts as public: `github.io` is refused) and a name whose
/// suffix is not on the list at all.
pub fn normalize_domain(input: &str) -> Result<String, DomainError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(DomainError::Empty);
    }
    if raw.contains("://") {
        return Err(DomainError::Scheme);
    }
    if raw.starts_with('[') || raw.parse::<IpAddr>().is_ok() {
        return Err(DomainError::IpLiteral);
    }
    if raw.contains(['/', '?', '#', '\\']) {
        return Err(DomainError::Path);
    }
    if raw.contains(':') {
        return Err(DomainError::Port);
    }
    if raw.contains('*') {
        return Err(DomainError::Wildcard);
    }
    let raw = raw.strip_suffix('.').unwrap_or(raw);

    let ascii = Uts46::new()
        .to_ascii(
            raw.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::Check,
            DnsLength::Ignore,
        )
        .map_err(|_| DomainError::Idna)?
        .into_owned();

    if ascii.is_empty() {
        return Err(DomainError::Empty);
    }
    // WHATWG-style numeric hosts (`10.0.0.1`, `1.2.3`, `0x7f.1`) are IPv4 forms, not names.
    if ascii.parse::<IpAddr>().is_ok() || ascii.rsplit('.').next().is_some_and(is_numeric_label) {
        return Err(DomainError::IpLiteral);
    }
    if ascii.len() > MAX_DOMAIN_LEN {
        return Err(DomainError::TooLong);
    }
    if ascii
        .split('.')
        .any(|l| l.is_empty() || l.len() > MAX_LABEL_LEN)
    {
        return Err(DomainError::LabelLength);
    }
    let last = ascii.rsplit('.').next().unwrap_or(&ascii);
    if RESERVED_NAMES.contains(&last) {
        return Err(DomainError::Reserved);
    }
    if !ascii.contains('.') {
        return Err(DomainError::TooFewLabels);
    }
    match psl::suffix(ascii.as_bytes()) {
        Some(s) if !s.is_known() => Err(DomainError::UnknownSuffix),
        Some(s) if s.as_bytes() == ascii.as_bytes() => Err(DomainError::PublicSuffix),
        Some(_) => Ok(ascii),
        None => Err(DomainError::UnknownSuffix),
    }
}

/// All digits, or a `0x` hex number: the last label of an IPv4 address in WHATWG host parsing.
fn is_numeric_label(label: &str) -> bool {
    let hex = label
        .strip_prefix("0x")
        .map(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    hex.unwrap_or_else(|| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// The normalised domain of an email address: exactly one `@`, a non-empty local part and a
/// domain [`normalize_domain`] accepts. `None` otherwise.
pub fn email_domain(email: &str) -> Option<String> {
    let mut parts = email.trim().split('@');
    let (local, domain) = (parts.next()?, parts.next()?);
    if parts.next().is_some() || local.is_empty() {
        return None;
    }
    normalize_domain(domain).ok()
}

/// Where a routed domain sends its users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsoTarget {
    pub org_id: OrgId,
    pub connection_id: ConnectionId,
}

/// A domain that home-realm discovery routes. `domain` is the stored, normalised form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedDomain {
    pub domain: String,
    pub target: SsoTarget,
}

impl RoutedDomain {
    /// The routing entry of an org domain: only a verified domain with routing on and a target
    /// connection routes.
    pub fn from_org_domain(d: &OrgDomain) -> Option<Self> {
        if d.status != OrgDomainStatus::Verified || !d.routing {
            return None;
        }
        Some(Self {
            domain: d.domain.clone(),
            target: SsoTarget {
                org_id: d.org_id,
                connection_id: d.connection_id?,
            },
        })
    }
}

/// The identifier-first decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Send the user to the organization's identity provider.
    Sso(SsoTarget),
    /// Continue with the tenant's own sign-in (the password step), whether or not an account
    /// exists for the address.
    Local,
}

/// Routes `email` by its domain only: [`Route::Sso`] for an exact match of the normalised
/// domain (a subdomain does not match its parent), [`Route::Local`] otherwise, including for an
/// address that is not a valid email.
pub fn route(email: &str, routed: &[RoutedDomain]) -> Route {
    let Some(domain) = email_domain(email) else {
        return Route::Local;
    };
    routed
        .iter()
        .find(|r| r.domain == domain)
        .map_or(Route::Local, |r| Route::Sso(r.target))
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;
    use crate::model::OrgDomainId;

    fn refused(input: &str) -> DomainError {
        match normalize_domain(input) {
            Err(e) => e,
            Ok(d) => panic!("{input:?} must be refused, got {d:?}"),
        }
    }

    #[test]
    fn normalises_case_and_whitespace() {
        assert_eq!(normalize_domain(" Example.COM ").unwrap(), "example.com");
        assert_eq!(normalize_domain("example.com.").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("sub.example.co.uk").unwrap(),
            "sub.example.co.uk"
        );
    }

    #[test]
    fn normalises_to_a_label() {
        assert_eq!(
            normalize_domain("bücher.example.de").unwrap(),
            "xn--bcher-kva.example.de"
        );
        assert_eq!(
            normalize_domain("BÜCHER.de").unwrap(),
            normalize_domain("xn--bcher-kva.de").unwrap()
        );
    }

    #[test]
    fn refuses_empty() {
        assert_eq!(refused("   "), DomainError::Empty);
    }

    #[test]
    fn refuses_scheme() {
        assert_eq!(refused("https://example.com"), DomainError::Scheme);
    }

    #[test]
    fn refuses_port() {
        assert_eq!(refused("example.com:443"), DomainError::Port);
    }

    #[test]
    fn refuses_path() {
        assert_eq!(refused("example.com/x"), DomainError::Path);
        assert_eq!(refused("example.com?x"), DomainError::Path);
    }

    #[test]
    fn refuses_wildcard() {
        assert_eq!(refused("*.example.com"), DomainError::Wildcard);
    }

    #[test]
    fn refuses_single_label() {
        assert_eq!(refused("com"), DomainError::TooFewLabels);
    }

    #[test]
    fn refuses_localhost() {
        assert_eq!(refused("localhost"), DomainError::Reserved);
        assert_eq!(refused("a.localhost"), DomainError::Reserved);
    }

    #[test]
    fn refuses_local() {
        assert_eq!(refused("a.local"), DomainError::Reserved);
    }

    #[test]
    fn refuses_internal() {
        assert_eq!(refused("a.internal"), DomainError::Reserved);
    }

    #[test]
    fn refuses_test() {
        assert_eq!(refused("a.test"), DomainError::Reserved);
    }

    #[test]
    fn refuses_example() {
        assert_eq!(refused("a.example"), DomainError::Reserved);
    }

    #[test]
    fn refuses_invalid() {
        assert_eq!(refused("a.invalid"), DomainError::Reserved);
    }

    #[test]
    fn refuses_ipv4() {
        assert_eq!(refused("10.0.0.1"), DomainError::IpLiteral);
        assert_eq!(refused("1.2.3"), DomainError::IpLiteral);
    }

    #[test]
    fn refuses_ipv6() {
        assert_eq!(refused("[::1]"), DomainError::IpLiteral);
        assert_eq!(refused("::1"), DomainError::IpLiteral);
    }

    #[test]
    fn refuses_icann_public_suffix() {
        assert_eq!(refused("co.uk"), DomainError::PublicSuffix);
        assert_eq!(refused("COM."), DomainError::TooFewLabels);
    }

    #[test]
    fn refuses_private_public_suffix() {
        assert_eq!(refused("github.io"), DomainError::PublicSuffix);
        assert_eq!(
            normalize_domain("acme.github.io").unwrap(),
            "acme.github.io"
        );
    }

    #[test]
    fn refuses_long_label() {
        let d = format!("{}.com", "a".repeat(64));
        assert_eq!(refused(&d), DomainError::LabelLength);
        let ok = format!("{}.com", "a".repeat(63));
        assert_eq!(normalize_domain(&ok).unwrap(), ok);
    }

    #[test]
    fn refuses_empty_label() {
        assert_eq!(refused("a..com"), DomainError::LabelLength);
    }

    #[test]
    fn refuses_long_domain() {
        // 58 + 3 * 63 + ".com" and the dots: 254 bytes, all labels valid.
        let label = "a".repeat(63);
        let d = format!("{}.{label}.{label}.{label}.com", "b".repeat(58));
        assert_eq!(d.len(), 254);
        assert_eq!(refused(&d), DomainError::TooLong);
        let d253 = format!("{}.{label}.{label}.{label}.com", "b".repeat(57));
        assert_eq!(normalize_domain(&d253).unwrap(), d253);
    }

    #[test]
    fn refuses_unknown_suffix() {
        assert_eq!(refused("foo.notarealtld"), DomainError::UnknownSuffix);
    }

    #[test]
    fn refuses_bad_idna() {
        assert_eq!(refused("a_b.example.com"), DomainError::Idna);
        assert_eq!(refused("-a.example.com"), DomainError::Idna);
        assert_eq!(refused("a@b.com"), DomainError::Idna);
    }

    #[test]
    fn domain_errors_map_to_validation() {
        match CoreError::from(DomainError::PublicSuffix) {
            CoreError::Validation { field, .. } => assert_eq!(field, "domain"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn email_domains() {
        assert_eq!(
            email_domain("Alice@Example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            email_domain("alice@bücher.de").as_deref(),
            Some("xn--bcher-kva.de")
        );
        assert_eq!(email_domain("alice.example.com"), None);
        assert_eq!(email_domain("a@b@example.com"), None);
        assert_eq!(email_domain("@example.com"), None);
        assert_eq!(email_domain("alice@"), None);
        assert_eq!(email_domain("alice@localhost"), None);
    }

    fn target() -> SsoTarget {
        SsoTarget {
            org_id: OrgId::new_v7(),
            connection_id: ConnectionId::new_v7(),
        }
    }

    #[test]
    fn routes_exact_domain_only() {
        let t = target();
        let routed = vec![RoutedDomain {
            domain: "example.com".into(),
            target: t,
        }];
        assert_eq!(route("alice@example.com", &routed), Route::Sso(t));
        assert_eq!(route(" Alice@EXAMPLE.com ", &routed), Route::Sso(t));
        assert_eq!(route("alice@sub.example.com", &routed), Route::Local);
        assert_eq!(route("alice@example.co", &routed), Route::Local);
        assert_eq!(route("alice@notexample.com", &routed), Route::Local);
        assert_eq!(route("not-an-email", &routed), Route::Local);
        assert_eq!(route("alice@example.com", &[]), Route::Local);
    }

    #[test]
    fn routes_to_the_matching_domain() {
        let (a, b) = (target(), target());
        let routed = vec![
            RoutedDomain {
                domain: "a.com".into(),
                target: a,
            },
            RoutedDomain {
                domain: "b.com".into(),
                target: b,
            },
        ];
        assert_eq!(route("x@b.com", &routed), Route::Sso(b));
        assert_eq!(route("x@a.com", &routed), Route::Sso(a));
    }

    fn org_domain() -> OrgDomain {
        OrgDomain {
            id: OrgDomainId::new_v7(),
            tenant_id: crate::model::TenantId::new_v7(),
            org_id: OrgId::new_v7(),
            domain: "example.com".into(),
            token: "T".into(),
            status: OrgDomainStatus::Verified,
            connection_id: Some(ConnectionId::new_v7()),
            routing: true,
            allow_local_password: true,
            verified_at: Some(OffsetDateTime::UNIX_EPOCH),
            last_checked_at: None,
            failing_since: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn only_verified_routed_domains_with_a_connection_route() {
        let d = org_domain();
        let r = RoutedDomain::from_org_domain(&d).unwrap();
        assert_eq!(r.domain, "example.com");
        assert_eq!(r.target.org_id, d.org_id);
        assert_eq!(Some(r.target.connection_id), d.connection_id);

        let pending = OrgDomain {
            status: OrgDomainStatus::Pending,
            ..org_domain()
        };
        assert_eq!(RoutedDomain::from_org_domain(&pending), None);
        let off = OrgDomain {
            routing: false,
            ..org_domain()
        };
        assert_eq!(RoutedDomain::from_org_domain(&off), None);
        let no_conn = OrgDomain {
            connection_id: None,
            ..org_domain()
        };
        assert_eq!(RoutedDomain::from_org_domain(&no_conn), None);
    }
}
