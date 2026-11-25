//! Per-tenant email templates and SMTP settings (UI-07).
//!
//! The SMTP password is stored sealed with the KEK ([`SMTP_PASSWORD_PURPOSE`], AAD = tenant id
//! bytes). [`seal_smtp_password`] and [`smtp_connection`] are the only places that seal and open
//! it; the outbox worker and the test send both go through [`smtp_connection`].

use anvil_jose::Kek;
use secrecy::{ExposeSecret as _, SecretString};

use crate::error::CoreError;
use crate::model::{SMTP_PASSWORD_PURPOSE, SmtpSettings, TenantId};
use crate::ports::SmtpConnection;

/// Seals an SMTP password for `tenant`.
pub fn seal_smtp_password(
    kek: &Kek,
    tenant: TenantId,
    password: &SecretString,
) -> Result<Vec<u8>, CoreError> {
    kek.seal(
        SMTP_PASSWORD_PURPOSE,
        tenant.0.as_bytes(),
        password.expose_secret().as_bytes(),
    )
    .map_err(|_| CoreError::Internal("SMTP password could not be sealed".into()))
}

/// The connection parameters of stored settings, with the password opened. The error is
/// generic: it never contains the sealed or opened value.
pub fn smtp_connection(
    kek: &Kek,
    tenant: TenantId,
    settings: &SmtpSettings,
) -> Result<SmtpConnection, CoreError> {
    let password = match &settings.password_enc {
        None => None,
        Some(sealed) => {
            let undecryptable =
                || CoreError::Internal("SMTP password could not be decrypted".into());
            let raw = kek
                .open(SMTP_PASSWORD_PURPOSE, tenant.0.as_bytes(), sealed)
                .map_err(|_| undecryptable())?;
            let text = std::str::from_utf8(&raw).map_err(|_| undecryptable())?;
            Some(SecretString::from(text.to_owned()))
        }
    };
    Ok(SmtpConnection {
        host: settings.host.clone(),
        port: settings.port,
        username: settings.username.clone(),
        password,
        from: settings.from.clone(),
        tls: settings.tls,
    })
}
