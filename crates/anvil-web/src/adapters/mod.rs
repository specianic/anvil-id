//! Production implementations of the non-storage core ports: password hashing (Argon2id), the
//! breached-password check (HIBP k-anonymity range API) and WebAuthn passkey ceremonies
//! (webauthn-rs), plus the server-side SVG QR renderer for TOTP enrolment and the CAPTCHA
//! siteverify client (Turnstile / hCaptcha). Every server-side HTTP fetch goes through the single
//! SSRF-guarded client in [`outbound`].

pub mod argon2;
pub mod captcha;
pub mod hibp;
pub mod outbound;
pub mod passkey;
pub mod qr;

pub use self::argon2::Argon2Pool;
pub use self::captcha::{CaptchaEndpoints, CaptchaError, CaptchaVerifier, captcha_csp};
pub use self::hibp::{BreachCheckMode, HibpChecker, breach_checker};
pub use self::outbound::{OutboundClient, OutboundError, OutboundPolicy};
pub use self::passkey::{WebauthnPasskeys, relying_party};
pub use self::qr::qr_svg;
