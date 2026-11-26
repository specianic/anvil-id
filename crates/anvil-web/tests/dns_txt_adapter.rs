//! `HickoryTxtLookup` (ORG-04 domain verification) against a local UDP DNS stub on 127.0.0.1:
//! matching records, multi-string records joined per RR, the exact (absolute) query name,
//! NXDOMAIN and SERVFAIL mapping, the overall timeout bound and the absence of a cache.
//! No network access beyond loopback.

mod dns_support;

use std::time::{Duration, Instant};

use anvil_core::policy::domain_verification::{record_name, record_value};
use anvil_core::ports::{DomainTxtLookup, TxtLookupError};
use anvil_core::service::domain_check::{DomainCheck, check_domain};
use anvil_web::adapters::dns_txt::HickoryTxtLookup;
use dns_support::DnsStub;

const TOKEN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn lookup_for(stub: &DnsStub) -> HickoryTxtLookup {
    HickoryTxtLookup::new(&[stub.addr()]).expect("resolver over the stub")
}

#[tokio::test]
async fn dns_txt_adapter_reads_matching_record() {
    let stub = DnsStub::start().await;
    let name = record_name("example.com");
    let value = record_value(TOKEN);
    stub.set_txt(&name, &[&[b"v=spf1 -all"], &[value.as_bytes()]]);
    let lookup = lookup_for(&stub);

    let mut records = lookup.txt(&name).await.expect("records");
    records.sort();
    let mut expected = vec![b"v=spf1 -all".to_vec(), value.clone().into_bytes()];
    expected.sort();
    assert_eq!(records, expected);
    assert_eq!(
        check_domain(&lookup, "example.com", TOKEN).await,
        DomainCheck::Verified
    );

    // A 300-byte value can't be one character-string (255 max): it is split in two and comes
    // back joined.
    let long = "x".repeat(300);
    let (a, b) = long.as_bytes().split_at(255);
    stub.set_txt(&name, &[&[a, b]]);
    assert_eq!(lookup.txt(&name).await, Ok(vec![long.into_bytes()]));
}

#[tokio::test]
async fn dns_txt_adapter_verifies_a_record_split_into_strings_but_not_across_records() {
    let stub = DnsStub::start().await;
    let name = record_name("example.com");
    let value = record_value(TOKEN);
    let (a, b) = value.as_bytes().split_at(12);
    let lookup = lookup_for(&stub);

    stub.set_txt(&name, &[&[a, b]]);
    assert_eq!(
        check_domain(&lookup, "example.com", TOKEN).await,
        DomainCheck::Verified
    );

    stub.set_txt(&name, &[&[a], &[b]]);
    assert_eq!(
        check_domain(&lookup, "example.com", TOKEN).await,
        DomainCheck::NotVerified
    );
}

#[tokio::test]
async fn dns_txt_adapter_queries_fqdn_without_search_suffix() {
    let stub = DnsStub::start().await;
    let lookup = lookup_for(&stub);
    let name = record_name("example.com");

    // Not configured: NXDOMAIN. Whatever the outcome, every query must be the challenge name
    // itself, never one with a search domain appended.
    let _ = lookup.txt(&name).await;
    // Also without the trailing dot: still absolute.
    let _ = lookup.txt(name.trim_end_matches('.')).await;

    let queries = stub.queries();
    assert!(!queries.is_empty());
    for q in &queries {
        assert_eq!(
            q.to_ascii_lowercase(),
            "_anvilid-challenge.example.com.",
            "{q}"
        );
    }
}

#[tokio::test]
async fn dns_txt_adapter_nxdomain_is_not_found() {
    let stub = DnsStub::start().await;
    let lookup = lookup_for(&stub);
    assert_eq!(
        lookup.txt(&record_name("missing.example")).await,
        Err(TxtLookupError::NotFound)
    );
    assert_eq!(
        check_domain(&lookup, "missing.example", TOKEN).await,
        DomainCheck::NotVerified
    );
}

#[tokio::test]
async fn dns_txt_adapter_nodata_is_not_found() {
    let stub = DnsStub::start().await;
    let lookup = lookup_for(&stub);
    let name = record_name("example.com");
    stub.set_txt(&name, &[]);
    assert_eq!(lookup.txt(&name).await, Err(TxtLookupError::NotFound));
}

#[tokio::test]
async fn dns_txt_adapter_servfail_is_failed() {
    let stub = DnsStub::start().await;
    let lookup = lookup_for(&stub);
    let name = record_name("example.com");
    stub.set_txt(&name, &[&[record_value(TOKEN).as_bytes()]]);
    stub.servfail();
    assert_eq!(lookup.txt(&name).await, Err(TxtLookupError::Failed));
    assert_eq!(
        check_domain(&lookup, "example.com", TOKEN).await,
        DomainCheck::NotVerified
    );
}

#[tokio::test]
async fn dns_txt_adapter_timeout_is_bounded() {
    let stub = DnsStub::start().await;
    stub.silent();
    let lookup = lookup_for(&stub);
    let started = Instant::now();
    let result = lookup.txt(&record_name("example.com")).await;
    let elapsed = started.elapsed();
    assert_eq!(result, Err(TxtLookupError::Failed));
    assert!(elapsed < Duration::from_secs(6), "took {elapsed:?}");
}

#[tokio::test]
async fn dns_txt_adapter_has_no_cache() {
    let stub = DnsStub::start().await;
    let lookup = lookup_for(&stub);
    let name = record_name("example.com");

    assert_eq!(lookup.txt(&name).await, Err(TxtLookupError::NotFound));
    assert_eq!(
        check_domain(&lookup, "example.com", TOKEN).await,
        DomainCheck::NotVerified
    );

    let value = record_value(TOKEN);
    stub.set_txt(&name, &[&[value.as_bytes()]]);
    assert_eq!(lookup.txt(&name).await, Ok(vec![value.into_bytes()]));
    assert_eq!(
        check_domain(&lookup, "example.com", TOKEN).await,
        DomainCheck::Verified
    );
}
