//! Password policy (NIST SP 800-63B style: length only, no composition rules).

use crate::error::CoreError;

// Phase 4 (pre-declared by plan 04-01; the owning plans fill them in)
pub mod branding;
pub mod mfa;

// Phase 5 (pre-declared by plan 05-02; the owning plans fill them in)
pub mod claims_mapping;
pub mod webhook_event;

// Phase 6 (plan 06-05)
pub mod domain_verification;
pub mod home_realm;
pub mod org_claims;

/// Length limits in characters (not bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_len: usize,
    pub max_len: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_len: 8,
            max_len: 1024,
        }
    }
}

/// Checks a password against the policy. Breach checking is a separate port
/// (`ports::BreachChecker`).
pub fn check_password(policy: &PasswordPolicy, password: &str) -> Result<(), CoreError> {
    let len = password.chars().count();
    if len < policy.min_len {
        return Err(CoreError::Validation {
            field: "password",
            message: format!("must be at least {} characters", policy.min_len),
        });
    }
    if len > policy.max_len {
        return Err(CoreError::Validation {
            field: "password",
            message: format!("must be at most {} characters", policy.max_len),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_limits() {
        let p = PasswordPolicy::default();
        assert!(matches!(
            check_password(&p, "1234567"),
            Err(CoreError::Validation {
                field: "password",
                ..
            })
        ));
        assert!(check_password(&p, "12345678").is_ok());
        assert!(check_password(&p, &"a".repeat(1024)).is_ok());
        assert!(check_password(&p, &"a".repeat(1025)).is_err());
    }

    #[test]
    fn counts_chars_not_bytes() {
        let p = PasswordPolicy::default();
        let eight = "äöüßéèêë";
        assert_eq!(eight.chars().count(), 8);
        assert!(eight.len() > 8);
        assert!(check_password(&p, eight).is_ok());
        assert!(check_password(&p, "äöüßéèê").is_err());
    }
}
