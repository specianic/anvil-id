//! Production implementations of the non-storage core ports: password hashing (Argon2id behind the
//! scheme dispatcher [`PasswordDispatcher`]), the breached-password check (HIBP k-anonymity range
//! API) and WebAuthn passkey ceremonies (webauthn-rs), plus the server-side SVG QR renderer for TOTP enrolment and the CAPTCHA
//! siteverify client (Turnstile / hCaptcha). Every server-side HTTP fetch goes through the single
//! SSRF-guarded client in [`outbound`].

pub mod argon2;
pub mod backchannel;
pub mod captcha;
pub mod hibp;
pub mod outbound;
pub mod passkey;
// The production PasswordHasher (scheme dispatcher, 07-09) and the legacy verifiers (07-01, ADM-08).
pub mod password;
pub mod qr;
pub mod upstream;

// Phase 5 (pre-declared by plan 05-02; the owning plans fill them in)
pub mod attribute_schema;
pub mod cimd;
pub mod webhook;

// Phase 6 (pre-declared by plan 06-04; the owning plans fill them in)
pub mod dns_txt;
pub mod saml_xml;

pub use self::argon2::Argon2Pool;
pub use self::captcha::{CaptchaEndpoints, CaptchaError, CaptchaVerifier, captcha_csp};
pub use self::hibp::{BreachCheckMode, HibpChecker, breach_checker, breach_checker_with};
pub use self::outbound::{OutboundClient, OutboundError, OutboundPolicy};
pub use self::passkey::{WebauthnPasskeys, relying_party};
pub use self::password::PasswordDispatcher;
pub use self::qr::qr_svg;
