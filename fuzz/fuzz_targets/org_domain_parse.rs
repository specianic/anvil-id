//! Organization domain normalisation (ORG-04): `policy::home_realm::normalize_domain`.
//!
//! Input: an arbitrary string.
//!
//! Invariants (besides never panicking):
//! - idempotent: an accepted domain normalises to itself;
//! - an accepted domain is lowercase ASCII (A-labels), at most 253 bytes, has at least two
//!   labels, each 1..=63 bytes of `a-z 0-9 -` not starting or ending with `-`, and no trailing dot.
#![no_main]

use anvil_core::policy::home_realm::normalize_domain;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(domain) = normalize_domain(input) else {
        return;
    };
    assert_eq!(
        normalize_domain(&domain).as_deref(),
        Ok(domain.as_str()),
        "not idempotent"
    );
    assert!(domain.len() <= 253, "too long: {domain:?}");
    assert!(!domain.ends_with('.'));
    let labels: Vec<&str> = domain.split('.').collect();
    assert!(labels.len() >= 2, "single label: {domain:?}");
    for label in labels {
        assert!((1..=63).contains(&label.len()), "label length: {domain:?}");
        assert!(
            label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "label characters: {domain:?}"
        );
        assert!(
            !label.starts_with('-') && !label.ends_with('-'),
            "hyphen: {domain:?}"
        );
    }
});
