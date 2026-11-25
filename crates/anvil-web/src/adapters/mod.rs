//! Production implementations of the non-storage core ports: password hashing (Argon2id) and the
//! breached-password check (HIBP k-anonymity range API).

pub mod argon2;
pub mod hibp;

pub use self::argon2::Argon2Pool;
pub use self::hibp::{BreachCheckMode, HibpChecker, breach_checker};
