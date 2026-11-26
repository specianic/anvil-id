//! One DNS TXT verification check of an organization domain over the `DomainTxtLookup` port
//! (ORG-04).
//!
//! [`check_domain`] is the only domain check: verification (06-17) and re-check (06-20) both call
//! it. The record format and the comparison are the pure rules in
//! [`crate::policy::domain_verification`]; this module only performs the lookup.
//!
//! The outcome is deliberately binary. A missing name, a missing record, SERVFAIL, a timeout, a
//! refused query and a record with the wrong value all give [`DomainCheck::NotVerified`], so an
//! org admin can't use verification to learn anything about DNS beyond "your record is not
//! there yet".

use crate::policy::domain_verification;
use crate::ports::DomainTxtLookup;

/// The result of one domain check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainCheck {
    /// A TXT record of `_anvilid-challenge.{domain}.` equals the expected value.
    Verified,
    /// Anything else: every lookup error and every non-match, indistinguishable by design.
    NotVerified,
}

/// Checks whether `domain` (normalised) publishes the challenge record for `token`.
///
/// Queries `domain_verification::record_name(domain)` (fully qualified) and compares with
/// `domain_verification::matches` against `record_value(token)`. Errors and non-matches are
/// indistinguishable by design (module docs). The lookup adapter bounds the time spent.
pub async fn check_domain(lookup: &dyn DomainTxtLookup, domain: &str, token: &str) -> DomainCheck {
    let name = domain_verification::record_name(domain);
    let expected = domain_verification::record_value(token);
    match lookup.txt(&name).await {
        Ok(records) => {
            // Each entry is one RR with its character-strings already joined; `matches` takes
            // the per-RR list of strings, so every RR is passed as a single string.
            let rrs: Vec<Vec<Vec<u8>>> = records.into_iter().map(|rr| vec![rr]).collect();
            if domain_verification::matches(&rrs, &expected) {
                DomainCheck::Verified
            } else {
                DomainCheck::NotVerified
            }
        }
        Err(_) => DomainCheck::NotVerified,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::ports::TxtLookupError;

    const TOKEN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    struct FakeLookup {
        answer: Result<Vec<Vec<u8>>, TxtLookupError>,
        asked: Mutex<Vec<String>>,
    }

    impl FakeLookup {
        fn new(answer: Result<Vec<Vec<u8>>, TxtLookupError>) -> Self {
            Self {
                answer,
                asked: Mutex::new(Vec::new()),
            }
        }

        fn records(values: &[&str]) -> Self {
            Self::new(Ok(values.iter().map(|v| v.as_bytes().to_vec()).collect()))
        }
    }

    #[async_trait::async_trait]
    impl DomainTxtLookup for FakeLookup {
        async fn txt(&self, fqdn: &str) -> Result<Vec<Vec<u8>>, TxtLookupError> {
            self.asked.lock().expect("lock").push(fqdn.to_owned());
            self.answer.clone()
        }
    }

    fn expected() -> String {
        domain_verification::record_value(TOKEN)
    }

    #[tokio::test]
    async fn one_matching_record_verifies() {
        let value = expected();
        let lookup = FakeLookup::records(&["v=spf1 -all", &value, "other"]);
        assert_eq!(
            check_domain(&lookup, "example.com", TOKEN).await,
            DomainCheck::Verified
        );
    }

    #[tokio::test]
    async fn queries_the_record_name() {
        let lookup = FakeLookup::records(&[]);
        check_domain(&lookup, "example.com", TOKEN).await;
        assert_eq!(
            *lookup.asked.lock().expect("lock"),
            vec![domain_verification::record_name("example.com")]
        );
        assert_eq!(
            lookup.asked.lock().expect("lock")[0],
            "_anvilid-challenge.example.com."
        );
    }

    #[tokio::test]
    async fn not_found_is_not_verified() {
        let lookup = FakeLookup::new(Err(TxtLookupError::NotFound));
        assert_eq!(
            check_domain(&lookup, "example.com", TOKEN).await,
            DomainCheck::NotVerified
        );
    }

    #[tokio::test]
    async fn failure_is_not_verified() {
        let lookup = FakeLookup::new(Err(TxtLookupError::Failed));
        assert_eq!(
            check_domain(&lookup, "example.com", TOKEN).await,
            DomainCheck::NotVerified
        );
    }

    #[tokio::test]
    async fn no_match_is_not_verified() {
        let wrong = domain_verification::record_value("ZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        for records in [
            vec![],
            vec![wrong.as_str()],
            vec![" anvilid-domain-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ"],
            vec!["anvilid-domain-verification=abcdefghijklmnopqrstuvwxyz"],
        ] {
            let lookup = FakeLookup::records(&records);
            assert_eq!(
                check_domain(&lookup, "example.com", TOKEN).await,
                DomainCheck::NotVerified,
                "{records:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_value_split_across_two_records_is_not_verified() {
        let value = expected();
        let (a, b) = value.split_at(10);
        let lookup = FakeLookup::records(&[a, b]);
        assert_eq!(
            check_domain(&lookup, "example.com", TOKEN).await,
            DomainCheck::NotVerified
        );
    }

    #[tokio::test]
    async fn errors_and_non_matches_are_one_outcome() {
        let outcomes = [
            check_domain(
                &FakeLookup::new(Err(TxtLookupError::NotFound)),
                "example.com",
                TOKEN,
            )
            .await,
            check_domain(
                &FakeLookup::new(Err(TxtLookupError::Failed)),
                "example.com",
                TOKEN,
            )
            .await,
            check_domain(&FakeLookup::records(&["x"]), "example.com", TOKEN).await,
        ];
        assert!(outcomes.iter().all(|o| *o == DomainCheck::NotVerified));
    }
}
