//! WebAuthn passkey ceremonies over webauthn-rs (AUTH-04), implementing the core
//! [`PasskeyCeremonies`] port so webauthn-rs never reaches anvil-core.
//!
//! - The relying party is derived per tenant from the tenant issuer ([`relying_party`]):
//!   `rp_id` = issuer host, `origin` = issuer origin, `name` = tenant display name.
//! - Registration requests a discoverable credential (`residentKey: "required"`,
//!   `requireResidentKey: true`) with user verification required, excludes the user's existing
//!   credentials and uses the user's UUID bytes as the WebAuthn user handle.
//! - Sign-in is discoverable (usernameless): `start_discoverable_authentication` forces
//!   `mediation: "conditional"` (autofill UI); we clear it so a button can trigger the ceremony.
//!   Verification uses `finish_discoverable_authentication_v2` with the single stored passkey.
//! - Ceremony state is serialised to JSON (`danger-allow-state-serialisation`) for server-side
//!   storage only (the flow state); it never goes to the browser.
//! - Every library error maps to [`PasskeyError::Invalid`] except `CredentialPossibleCompromise`
//!   (signature counter did not advance), which maps to [`PasskeyError::PossibleClone`]. Library
//!   errors are logged at debug level by variant only, never with credential material.

use anvil_core::error::CoreError;
use anvil_core::model::{Tenant, UserId};
use anvil_core::ports::{
    AssertionIdentity, Challenge, PasskeyCeremonies, PasskeyError, PasskeyUser, RegisteredPasskey,
    RelyingParty, VerifiedAssertion,
};
use url::Url;
use webauthn_rs::prelude::{
    CredentialID, DiscoverableAuthentication, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};

/// The relying party of `tenant` served at `issuer` (e.g. `https://op.test/t/acme` →
/// `rp_id = "op.test"`, `origin = "https://op.test"`). Fails for issuers without a domain host
/// (IP literals cannot be WebAuthn relying party ids).
pub fn relying_party(tenant: &Tenant, issuer: &str) -> Result<RelyingParty, CoreError> {
    let url = Url::parse(issuer)
        .map_err(|_| CoreError::Internal("issuer is not a valid URL".to_owned()))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(CoreError::Internal(
            "issuer must use http or https".to_owned(),
        ));
    }
    let Some(host) = url.domain() else {
        return Err(CoreError::Internal(
            "issuer host must be a domain name for WebAuthn".to_owned(),
        ));
    };
    Ok(RelyingParty {
        rp_id: host.to_owned(),
        origin: url.origin().ascii_serialization(),
        name: tenant.display_name.clone(),
    })
}

/// [`PasskeyCeremonies`] over webauthn-rs. Stateless: a `Webauthn` instance is built per call
/// from the [`RelyingParty`] (cheap: a few string copies).
#[derive(Debug, Clone, Copy, Default)]
pub struct WebauthnPasskeys;

impl WebauthnPasskeys {
    pub fn new() -> Self {
        Self
    }
}

fn webauthn(rp: &RelyingParty) -> Result<Webauthn, WebauthnError> {
    let origin = Url::parse(&rp.origin).map_err(|_| WebauthnError::Configuration)?;
    WebauthnBuilder::new(&rp.rp_id, &origin)?
        .rp_name(&rp.name)
        .build()
}

fn config_error(err: &WebauthnError) -> CoreError {
    CoreError::Internal(format!("webauthn relying party configuration: {err:?}"))
}

fn reject(stage: &'static str, err: &WebauthnError) -> PasskeyError {
    tracing::debug!(stage, error = ?err, "passkey response rejected");
    match err {
        WebauthnError::CredentialPossibleCompromise => PasskeyError::PossibleClone,
        _ => PasskeyError::Invalid,
    }
}

fn malformed(stage: &'static str, what: &'static str) -> PasskeyError {
    tracing::debug!(stage, what, "passkey input malformed");
    PasskeyError::Invalid
}

/// Counter and backup eligibility of a freshly registered passkey. The credential fields are
/// crate-private in webauthn-rs (unless `danger-credential-internals`), so read them from the
/// passkey's own serialisation (`{"cred": {"counter": .., "backup_eligible": ..}}`).
fn passkey_facts(passkey: &Passkey) -> Result<(u32, bool), PasskeyError> {
    let value = serde_json::to_value(passkey).map_err(|_| malformed("register", "passkey"))?;
    let cred = value
        .get("cred")
        .ok_or_else(|| malformed("register", "passkey cred"))?;
    let counter = cred
        .get("counter")
        .and_then(serde_json::Value::as_u64)
        .and_then(|c| u32::try_from(c).ok())
        .ok_or_else(|| malformed("register", "passkey counter"))?;
    let backup_eligible = cred
        .get("backup_eligible")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| malformed("register", "passkey backup_eligible"))?;
    Ok((counter, backup_eligible))
}

impl PasskeyCeremonies for WebauthnPasskeys {
    fn start_registration(
        &self,
        rp: &RelyingParty,
        user: &PasskeyUser,
        exclude: &[Vec<u8>],
    ) -> Result<Challenge, CoreError> {
        let wa = webauthn(rp).map_err(|e| config_error(&e))?;
        let exclude: Vec<CredentialID> = exclude.to_vec();
        let exclude = (!exclude.is_empty()).then_some(exclude);
        let (mut ccr, state) = wa
            .start_passkey_registration(user.id.0, &user.name, &user.display_name, exclude)
            .map_err(|e| CoreError::Internal(format!("webauthn registration options: {e:?}")))?;
        // Passkeys must be discoverable for usernameless sign-in.
        if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
            // `ResidentKeyRequirement` is not re-exported by webauthn-rs; name it through serde.
            sel.resident_key = Some(serde_json::from_str("\"required\"").map_err(|e| {
                CoreError::Internal(format!("webauthn resident key requirement: {e}"))
            })?);
            sel.require_resident_key = true;
        } else {
            return Err(CoreError::Internal(
                "webauthn registration options lack authenticator selection".to_owned(),
            ));
        }
        Ok(Challenge {
            options_json: to_json(&ccr)?,
            state_json: to_json(&state)?,
        })
    }

    fn finish_registration(
        &self,
        rp: &RelyingParty,
        response_json: &str,
        state_json: &str,
    ) -> Result<RegisteredPasskey, PasskeyError> {
        let wa = webauthn(rp).map_err(|e| reject("register", &e))?;
        let state: PasskeyRegistration =
            serde_json::from_str(state_json).map_err(|_| malformed("register", "state"))?;
        let response: RegisterPublicKeyCredential =
            serde_json::from_str(response_json).map_err(|_| malformed("register", "response"))?;
        let passkey = wa
            .finish_passkey_registration(&response, &state)
            .map_err(|e| reject("register", &e))?;
        let (counter, backup_eligible) = passkey_facts(&passkey)?;
        let credential_id: Vec<u8> = passkey.cred_id().clone();
        let passkey_json =
            serde_json::to_string(&passkey).map_err(|_| malformed("register", "passkey"))?;
        Ok(RegisteredPasskey {
            credential_id,
            passkey_json,
            counter,
            backup_eligible,
        })
    }

    fn start_discoverable(&self, rp: &RelyingParty) -> Result<Challenge, CoreError> {
        let wa = webauthn(rp).map_err(|e| config_error(&e))?;
        let (mut rcr, state) = wa
            .start_discoverable_authentication()
            .map_err(|e| CoreError::Internal(format!("webauthn request options: {e:?}")))?;
        // The library forces conditional (autofill) mediation; sign-in here is button-triggered.
        rcr.mediation = None;
        Ok(Challenge {
            options_json: to_json(&rcr)?,
            state_json: to_json(&state)?,
        })
    }

    fn identify(&self, response_json: &str) -> Result<AssertionIdentity, PasskeyError> {
        let response: PublicKeyCredential =
            serde_json::from_str(response_json).map_err(|_| malformed("identify", "response"))?;
        let handle = response
            .get_user_unique_id()
            .ok_or_else(|| malformed("identify", "user handle missing"))?;
        let uuid = Uuid::from_slice(handle)
            .map_err(|_| malformed("identify", "user handle not a uuid"))?;
        let credential_id = response.get_credential_id().to_vec();
        if credential_id.is_empty() {
            return Err(malformed("identify", "credential id empty"));
        }
        Ok(AssertionIdentity {
            user_id: UserId(uuid),
            credential_id,
        })
    }

    fn finish_discoverable(
        &self,
        rp: &RelyingParty,
        response_json: &str,
        state_json: &str,
        stored_passkey_json: &str,
    ) -> Result<VerifiedAssertion, PasskeyError> {
        let wa = webauthn(rp).map_err(|e| reject("authenticate", &e))?;
        let state: DiscoverableAuthentication =
            serde_json::from_str(state_json).map_err(|_| malformed("authenticate", "state"))?;
        let response: PublicKeyCredential = serde_json::from_str(response_json)
            .map_err(|_| malformed("authenticate", "response"))?;
        let mut passkey: Passkey = serde_json::from_str(stored_passkey_json)
            .map_err(|_| malformed("authenticate", "stored passkey"))?;
        if response.get_credential_id() != passkey.cred_id().as_slice() {
            return Err(malformed("authenticate", "credential id mismatch"));
        }
        let result = wa
            .finish_discoverable_authentication_v2(&response, state, &passkey)
            .map_err(|e| reject("authenticate", &e))?;
        let changed = passkey.update_credential(&result).unwrap_or(false);
        let updated_passkey_json = if changed {
            Some(
                serde_json::to_string(&passkey)
                    .map_err(|_| malformed("authenticate", "passkey"))?,
            )
        } else {
            None
        };
        Ok(VerifiedAssertion {
            counter: result.counter(),
            user_verified: result.user_verified(),
            backup_eligible: result.backup_eligible(),
            updated_passkey_json,
        })
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, CoreError> {
    serde_json::to_string(value)
        .map_err(|e| CoreError::Internal(format!("webauthn serialisation: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn possible_compromise_maps_to_possible_clone() {
        assert_eq!(
            reject("authenticate", &WebauthnError::CredentialPossibleCompromise),
            PasskeyError::PossibleClone
        );
    }

    #[test]
    fn other_library_errors_map_to_invalid() {
        for err in [
            WebauthnError::MismatchedChallenge,
            WebauthnError::InvalidRPOrigin,
            WebauthnError::UserNotVerified,
            WebauthnError::AuthenticationFailure,
            WebauthnError::Configuration,
        ] {
            assert_eq!(reject("authenticate", &err), PasskeyError::Invalid, "{err:?}");
        }
    }

    #[test]
    fn webauthn_rejects_rp_id_outside_origin() {
        let rp = RelyingParty {
            rp_id: "evil.test".to_owned(),
            origin: "https://op.test".to_owned(),
            name: "x".to_owned(),
        };
        assert!(webauthn(&rp).is_err());
        assert!(matches!(
            WebauthnPasskeys.start_discoverable(&rp),
            Err(CoreError::Internal(_))
        ));
    }
}
