//! DNS TXT lookups for organization domain verification (`ports::DomainTxtLookup`, ORG-04).
//!
//! A dedicated hickory resolver, separate from anything else in the process:
//!
//! - Name servers: the operator's `domain_verification_resolvers` (UDP and TCP on each
//!   address), or the system resolver configuration when that list is empty. Nothing else is
//!   ever contacted: the queried name only selects what the resolver is asked about.
//! - Queries are absolute names (`Name::set_fqdn(true)`, `ndots` 0, no search domains, no hosts
//!   file), so resolv.conf search domains never turn a challenge name into an internal one.
//! - No cache (`cache_size` 0, TTL bounds 0): a record published after a negative answer is seen
//!   by the next lookup.
//! - Bounded: 2 s per attempt, 2 attempts, and a 5 s overall tokio timeout around the lookup.
//! - Uniform errors: NXDOMAIN and NODATA are `NotFound`; everything else (timeout, SERVFAIL,
//!   refused, malformed, unparsable name, unreadable system configuration) is `Failed`. Callers
//!   (`service::domain_check`) fold both into one "not verified" outcome.
//!
//! Queried names are logged at debug level at most.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use anvil_core::ports::{DomainTxtLookup, TxtLookupError};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RData};

/// Per-attempt timeout.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
/// Attempts per lookup.
const ATTEMPTS: usize = 2;
/// Upper bound for one whole lookup, whatever the resolver does internally.
const OVERALL_TIMEOUT: Duration = Duration::from_secs(5);

/// The resolver setup failed (invalid resolver configuration). Fixed text; never echoes the
/// configured addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("domain verification resolver setup failed")]
pub struct DnsTxtSetupError;

/// The production [`DomainTxtLookup`] (module docs).
#[derive(Clone)]
pub struct HickoryTxtLookup {
    /// Explicit resolvers (`domain_verification_resolvers`); empty means the system
    /// configuration.
    resolvers: Vec<SocketAddr>,
    /// `None` only when the resolvers list is empty and the system configuration could not be
    /// read at startup: every lookup then fails explicitly.
    resolver: Option<TokioResolver>,
}

impl fmt::Debug for HickoryTxtLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HickoryTxtLookup")
            .field("resolvers", &self.resolvers)
            .field("available", &self.resolver.is_some())
            .finish()
    }
}

/// The resolver options for verification lookups (module docs).
fn options() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.ndots = 0;
    opts.timeout = ATTEMPT_TIMEOUT;
    opts.attempts = ATTEMPTS;
    opts.cache_size = 0;
    opts.positive_max_ttl = Some(Duration::ZERO);
    opts.negative_max_ttl = Some(Duration::ZERO);
    opts.use_hosts_file = ResolveHosts::Never;
    opts
}

/// A name server entry for `addr`, UDP and TCP on its port.
fn name_server(addr: SocketAddr) -> NameServerConfig {
    let mut udp = ConnectionConfig::udp();
    udp.port = addr.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = addr.port();
    NameServerConfig::new(addr.ip(), true, vec![udp, tcp])
}

impl HickoryTxtLookup {
    /// A lookup querying `resolvers` (empty: the system resolver configuration).
    ///
    /// Fails only when an explicit resolver configuration can't be turned into a resolver. An
    /// unreadable system configuration is logged and leaves a lookup that always fails, so a host
    /// without resolv.conf still starts (domain verification is then unavailable, never
    /// successful).
    pub fn new(resolvers: &[SocketAddr]) -> Result<Self, DnsTxtSetupError> {
        let provider = TokioRuntimeProvider::default();
        let resolver = if resolvers.is_empty() {
            match TokioResolver::builder(provider) {
                Ok(builder) => match builder.with_options(options()).build() {
                    Ok(resolver) => Some(resolver),
                    Err(_) => {
                        tracing::warn!(
                            "domain verification: system resolver configuration unusable; \
                             domain verification lookups will fail"
                        );
                        None
                    }
                },
                Err(_) => {
                    tracing::warn!(
                        "domain verification: system resolver configuration unreadable; \
                         set domain_verification_resolvers to enable domain verification"
                    );
                    None
                }
            }
        } else {
            let config = ResolverConfig::from_parts(
                None,
                vec![],
                resolvers.iter().copied().map(name_server).collect(),
            );
            let resolver = TokioResolver::builder_with_config(config, provider)
                .with_options(options())
                .build()
                .map_err(|_| DnsTxtSetupError)?;
            Some(resolver)
        };
        Ok(Self {
            resolvers: resolvers.to_vec(),
            resolver,
        })
    }

    /// The configured resolvers (empty: system configuration).
    pub fn resolvers(&self) -> &[SocketAddr] {
        &self.resolvers
    }
}

#[async_trait::async_trait]
impl DomainTxtLookup for HickoryTxtLookup {
    async fn txt(&self, fqdn: &str) -> Result<Vec<Vec<u8>>, TxtLookupError> {
        let Some(resolver) = &self.resolver else {
            return Err(TxtLookupError::Failed);
        };
        let mut name = Name::from_ascii(fqdn).map_err(|_| TxtLookupError::Failed)?;
        // Absolute, whether or not the caller wrote the trailing dot: never a search domain.
        name.set_fqdn(true);
        let lookup = match tokio::time::timeout(OVERALL_TIMEOUT, resolver.txt_lookup(name)).await {
            Ok(Ok(lookup)) => lookup,
            Ok(Err(e)) if e.is_no_records_found() => {
                tracing::debug!(name = fqdn, "domain verification: no txt record");
                return Err(TxtLookupError::NotFound);
            }
            Ok(Err(e)) => {
                tracing::debug!(name = fqdn, error = %e, "domain verification: lookup failed");
                return Err(TxtLookupError::Failed);
            }
            Err(_) => {
                tracing::debug!(name = fqdn, "domain verification: lookup timed out");
                return Err(TxtLookupError::Failed);
            }
        };
        // One entry per TXT RR, its character-strings joined in order. Other RRs in the answer
        // (a CNAME chain) are skipped.
        let records: Vec<Vec<u8>> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt.txt_data.iter().flatten().copied().collect()),
                _ => None,
            })
            .collect();
        if records.is_empty() {
            return Err(TxtLookupError::NotFound);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_bounded_uncached_and_fqdn_only() {
        let opts = options();
        assert_eq!(opts.ndots, 0);
        assert_eq!(opts.timeout, Duration::from_secs(2));
        assert_eq!(opts.attempts, 2);
        assert_eq!(opts.cache_size, 0);
        assert_eq!(opts.negative_max_ttl, Some(Duration::ZERO));
        assert_eq!(opts.positive_max_ttl, Some(Duration::ZERO));
        assert!(matches!(opts.use_hosts_file, ResolveHosts::Never));
        assert!(OVERALL_TIMEOUT >= ATTEMPT_TIMEOUT * ATTEMPTS as u32);
    }

    #[test]
    fn explicit_resolvers_use_udp_and_tcp_on_the_configured_port() {
        let ns = name_server("192.0.2.1:5353".parse().expect("addr"));
        assert_eq!(ns.ip.to_string(), "192.0.2.1");
        assert_eq!(ns.connections.len(), 2);
        assert!(ns.connections.iter().all(|c| c.port == 5353));
    }

    #[tokio::test]
    async fn unparsable_names_fail() {
        let lookup =
            HickoryTxtLookup::new(&["127.0.0.1:9".parse().expect("addr")]).expect("resolver");
        assert_eq!(lookup.txt("a..b").await, Err(TxtLookupError::Failed));
    }
}
