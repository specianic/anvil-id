//! Redirect URI matching (SEC-07).
//!
//! Invariants:
//! - web clients: exact string match only, `redirect_matches(.., Web) == registered.contains(requested)`;
//! - native clients: an exact match always matches, and any extra match is an RFC 8252 §7.3
//!   loopback IP literal (`http://127.0.0.1` or `http://[::1]`), never `localhost` or https.
#![no_main]

use anvil_core::model::ApplicationType;
use anvil_core::oauth::redirect::redirect_matches;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    registered: Vec<String>,
    requested: String,
}

fuzz_target!(|input: Input| {
    let Input {
        registered,
        requested,
    } = input;
    let exact = registered.contains(&requested);

    assert_eq!(
        redirect_matches(&registered, &requested, ApplicationType::Web),
        exact,
        "web client matched {requested:?} against {registered:?}"
    );

    let matched = redirect_matches(&registered, &requested, ApplicationType::Native);
    if exact {
        assert!(matched, "native client rejected an exact match");
    } else if matched {
        assert!(
            requested.starts_with("http://127.0.0.1") || requested.starts_with("http://[::1]"),
            "native client matched non-loopback {requested:?} against {registered:?}"
        );
    }
});
