//! Imported password hashes (ADM-08): `policy::password_import::{parse_stored, convert_import}`.
//!
//! Input: arbitrary bytes, used twice: as a (lossy UTF-8) stored hash string for the login-path
//! parser, and as JSON for the import parser and conversion.
//!
//! Invariants (besides never panicking):
//! - an accepted stored string is canonical: `format_stored(parse_stored(s)) == s`;
//! - `check_stored_caps` is total on every parsed hash;
//! - a successful import conversion yields a stored string that parses and is within the caps.
#![no_main]

use anvil_core::policy::password_import::{
    ImportPassword, check_stored_caps, convert_import, format_stored, parse_import_value,
    parse_stored,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(h) = parse_stored(&s) {
        let _ = check_stored_caps(&h);
        assert_eq!(format_stored(&h), s, "stored encoding not canonical");
    }

    let mut converted = Vec::new();
    if let Ok(input) = serde_json::from_slice::<ImportPassword>(data) {
        converted.push(convert_import(&input));
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data)
        && let Ok(input) = parse_import_value(value)
    {
        converted.push(convert_import(&input));
    }
    for c in converted.into_iter().flatten() {
        let h = parse_stored(&c.stored).expect("converted output parses");
        assert_eq!(
            check_stored_caps(&h),
            Ok(()),
            "converted output over the caps"
        );
        assert_eq!(format_stored(&h), c.stored);
    }
});
