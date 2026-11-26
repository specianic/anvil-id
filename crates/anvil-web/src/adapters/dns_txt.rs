//! DNS TXT lookups for organization domain verification (`ports::DomainTxtLookup`, ORG-04).
//!
//! Owned by plan 06-10, which builds the hickory resolver here (dedicated resolver, no search
//! domains, no cache, bounded timeouts, FQDN queries, uniform errors). Until then the type exists
//! so the binary can wire it into `AppDeps`, and every lookup fails with an explicit error:
//! no domain can be verified before 06-10.

use std::net::SocketAddr;

use anvil_core::ports::{DomainTxtLookup, TxtLookupError};

/// The resolver setup failed (invalid resolver configuration). Fixed text; never echoes the
/// configured addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("domain verification resolver setup failed")]
pub struct DnsTxtSetupError;

/// The production [`DomainTxtLookup`] (module docs).
#[derive(Debug, Clone)]
pub struct HickoryTxtLookup {
    /// Explicit resolvers (`domain_verification_resolvers`); empty means the system
    /// configuration.
    resolvers: Vec<SocketAddr>,
}

impl HickoryTxtLookup {
    /// A lookup querying `resolvers` (empty: the system resolver configuration).
    pub fn new(resolvers: &[SocketAddr]) -> Result<Self, DnsTxtSetupError> {
        Ok(Self {
            resolvers: resolvers.to_vec(),
        })
    }

    /// The configured resolvers (empty: system configuration).
    pub fn resolvers(&self) -> &[SocketAddr] {
        &self.resolvers
    }
}

#[async_trait::async_trait]
impl DomainTxtLookup for HickoryTxtLookup {
    async fn txt(&self, _fqdn: &str) -> Result<Vec<Vec<u8>>, TxtLookupError> {
        // TRANSITIONAL(06-10): the hickory resolver arrives in 06-10. Until then every lookup is
        // an explicit failure, so domain verification can never succeed.
        Err(TxtLookupError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lookup_fails_explicitly_until_the_resolver_exists() {
        let lookup = HickoryTxtLookup::new(&[]).expect("system configuration");
        assert!(lookup.resolvers().is_empty());
        assert_eq!(
            lookup.txt("_anvilid-challenge.example.com.").await,
            Err(TxtLookupError::Failed)
        );
    }
}
