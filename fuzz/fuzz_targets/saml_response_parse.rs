//! SAML response parsing, pre-check and verification (ORG-03, decision D4).
//!
//! Input: arbitrary bytes as a decoded `SAMLResponse`, verified against `CERT`.
//!
//! Invariants (besides never panicking):
//! - the adapter never returns `Ok`. `CERT` is a self-signed P-256 certificate generated for
//!   this target with its private key written to /dev/null, so no input can carry a valid
//!   signature by it: an `Ok` means a signature check was skipped or mis-mapped.
#![no_main]

use anvil_core::ports::SamlXml;
use anvil_web::adapters::saml_xml::SamlXmlAdapter;
use libfuzzer_sys::fuzz_target;

/// Public material only (the matching private key was never stored).
const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBwjCCAWmgAwIBAgIUQMLxNGezoSDLzGV2M1DIQ6Gfn8IwCgYIKoZIzj0EAwIw
NjE0MDIGA1UEAwwrQW52aWxJRCBmdXp6IHRhcmdldCAocHJpdmF0ZSBrZXkgZGlz
Y2FyZGVkKTAgFw0yNjExMjYxMDE3MzVaGA8yMTI2MTEwMjEwMTczNVowNjE0MDIG
A1UEAwwrQW52aWxJRCBmdXp6IHRhcmdldCAocHJpdmF0ZSBrZXkgZGlzY2FyZGVk
KTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOJdBVNlVq3E92yP2+FS4NzIXAUo
lMYHts8mIKaosTfbYDMI/xC6Umh6TpUfLRkgbXhc3RGLTDlDZ9imVfLt2KmjUzBR
MB0GA1UdDgQWBBRPL3m1tAhMHgyeD1pCxMJKTzRDIzAfBgNVHSMEGDAWgBRPL3m1
tAhMHgyeD1pCxMJKTzRDIzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cA
MEQCIDlDo4/eO4IOWhRSy9tzTkSMTB5bAePDJ0hgFA3t+/3UAiA56LXWWNA20blC
tEdyiA2aZ1HDgrywyU2fQ3l2ABECsg==
-----END CERTIFICATE-----
";

fuzz_target!(|data: &[u8]| {
    let result = SamlXmlAdapter.verify_response(data, &[CERT.to_owned()]);
    assert!(
        result.is_err(),
        "accepted a response that cannot carry a valid signature"
    );
});
