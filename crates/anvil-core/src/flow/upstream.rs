//! Upstream (social / OIDC / OAuth2) sign-in and account-linking flow states (AUTH-07, AUTH-11).
//!
//! # Pending authorization
//!
//! Starting an upstream sign-in stores a [`PendingUpstream`] in the flow that started it: the
//! login flow ([`super::login::LoginState::upstream`], purpose [`UpstreamPurpose::Login`]) or the
//! account page's settings flow ([`super::settings::SettingsState::upstream`], purpose
//! [`UpstreamPurpose::Link`]). It holds only hashes and sealed values:
//!
//! - `state_hash`: SHA-256 of the `state` sent to the provider. `state` is `{flow_id}.{random}`
//!   ([`split_state`]): the flow cookie (SameSite=Strict) is not sent on the cross-site return
//!   from the provider, so the flow is found through `state`.
//! - `binding_hash`: SHA-256 of the browser-binding cookie (SameSite=Lax, 10 minutes) set when the
//!   sign-in started. A callback from another browser (login CSRF) does not carry it.
//! - `nonce` (OIDC): compared with the ID token's `nonce`.
//! - `pkce_sealed`: the PKCE verifier sealed with the KEK ([`UPSTREAM_PKCE_PURPOSE`], AAD
//!   [`upstream_aad`]).
//!
//! The callback takes the pending authorization out of the flow with a compare-and-swap before
//! anything else is done with it, so a replayed callback finds nothing ([`check_callback`]).
//!
//! # Pending link
//!
//! An upstream identity whose email matches an account that may not be linked automatically
//! continues in a fresh login flow holding a [`PendingLink`]: the upstream identity sealed with
//! the KEK ([`UPSTREAM_IDENTITY_PURPOSE`], AAD [`upstream_aad`] of that flow). Signing in to an
//! existing account in that flow (password or passkey, plus any required second factor) links
//! the identity to the account just proved. When the candidate account may be revealed, the flow
//! also records how it can confirm ([`LinkConfirmMethods`]): an upstream connection it is
//! already linked to (started from the same flow, which keeps the pending link; the callback
//! confirms only an identity linked to exactly that candidate) or an emailed sign-in code. A
//! candidate with none of them gets a page saying how to go on instead of a dead end.
//!
//! When the matching account may not be revealed (an unverified or untrusted upstream email, e.g.
//! every Microsoft address), its id is still kept, sealed like the identity
//! ([`UPSTREAM_MATCH_PURPOSE`], [`PendingLink::matched_sealed`]) and never rendered. The page then
//! offers what does not depend on the account: the tenant's other connections and, with
//! `email_otp`, an emailed code to the matching account's verified address without showing it.
//! Signing in through one of those connections confirms only an identity already linked to
//! exactly the sealed account; the code reaches only that account's verified address. When the
//! second factor continues in a fresh flow, both sealed values are resealed under that flow.
//!
//! Pure: no I/O.

use anvil_jose::encoding::{b64url, ct_eq, secret_hash};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use crate::model::{ConnectionId, FlowId, TenantId, UserId};
use crate::upstream::claims::UpstreamIdentity;

/// KEK purpose of a PKCE verifier pending in a flow.
pub const UPSTREAM_PKCE_PURPOSE: &str = "anvilid/upstream-pkce/v1";

/// KEK purpose of an upstream identity awaiting link confirmation.
pub const UPSTREAM_IDENTITY_PURPOSE: &str = "anvilid/upstream-identity/v1";

/// KEK purpose of the id of the account matching a pending link that may not be revealed
/// ([`PendingLink::matched_sealed`]).
pub const UPSTREAM_MATCH_PURPOSE: &str = "anvilid/upstream-match/v1";

/// KEK purpose of an authorization response posted by the provider (`form_post`) and kept until
/// the browser comes back with the binding cookie.
pub const UPSTREAM_RESPONSE_PURPOSE: &str = "anvilid/upstream-response/v1";

/// How long a started upstream sign-in may take (also the binding cookie's `Max-Age`).
pub const UPSTREAM_TTL: Duration = Duration::minutes(10);

/// AAD of values sealed into a flow: tenant id bytes followed by flow id bytes.
pub fn upstream_aad(tenant: TenantId, flow: FlowId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(flow.0.as_bytes());
    aad
}

/// Why an upstream sign-in was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpstreamPurpose {
    /// Sign in (or register) through the provider.
    Login,
    /// Link the provider identity to this signed-in user (account page).
    Link { user_id: UserId },
}

/// A started upstream authorization (module docs). Holds no plaintext secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUpstream {
    pub connection_id: ConnectionId,
    /// base64url SHA-256 of the `state` parameter.
    pub state_hash: String,
    /// OIDC only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// base64url KEK-sealed PKCE verifier, when the provider uses PKCE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkce_sealed: Option<String>,
    /// base64url SHA-256 of the binding cookie value.
    pub binding_hash: String,
    pub purpose: UpstreamPurpose,
    /// Unix seconds.
    pub started_at: i64,
    /// RFC 9207: the provider advertises `authorization_response_iss_parameter_supported`, so the
    /// callback must carry `iss` equal to this issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_iss: Option<String>,
    /// base64url KEK-sealed [`PostedResponse`] (`form_post` providers such as Apple).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_sealed: Option<String>,
}

/// The authorization response a provider posted (`response_mode=form_post`), kept sealed in the
/// flow until the browser returns to the callback with its binding cookie.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PostedResponse {
    #[serde(default)]
    pub code: Option<String>,
    /// Apple's first-authorization `user` JSON (unsigned; only names are taken from it).
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// RFC 9207 `iss`, when the provider sent one.
    #[serde(default)]
    pub iss: Option<String>,
}

/// An upstream identity waiting for the user to prove an existing account (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLink {
    pub connection_id: ConnectionId,
    /// base64url KEK-sealed [`SealedIdentity`] JSON.
    pub identity_sealed: String,
    /// The matching account, set only when the upstream email is verified and trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_user: Option<UserId>,
    /// The connection's display name (shown on the confirmation page).
    pub provider_name: String,
    /// The matching account's email, set only together with `candidate_user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_email: Option<String>,
    /// How the revealed candidate can prove the account, set only together with
    /// `candidate_user` (an unrevealed candidate reveals nothing, not even its methods).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<LinkConfirmMethods>,
    /// The matching account when it may not be revealed (no `candidate_user`): its id sealed
    /// with the KEK ([`UPSTREAM_MATCH_PURPOSE`], AAD [`upstream_aad`] of the flow). Only the
    /// service opens it, to confirm through an identity already linked to that account or to
    /// send a code to its verified address; it is never rendered and never decides what the page
    /// shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_sealed: Option<String>,
}

impl PendingLink {
    /// The matching account may be revealed (verified and trusted upstream email).
    pub fn revealed(&self) -> bool {
        self.candidate_user.is_some()
    }
}

/// The ways a revealed candidate account can confirm a [`PendingLink`], decided when the link
/// confirmation starts (`service::upstream`). Proving the account links it; the password and
/// passkey forms are always the flow's own sign-in, the others are:
///
/// - `connections`: enabled OAuth/OIDC connections the candidate is already linked to. Signing in
///   through one of them from the confirmation page confirms only when the returned identity is
///   linked to exactly the candidate (checked again by the callback);
/// - `email_code`: an emailed sign-in code to the candidate's verified address (tenant
///   `email_otp`; never the magic link, which may open in another browser).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LinkConfirmMethods {
    #[serde(default)]
    pub password: bool,
    #[serde(default)]
    pub passkey: bool,
    #[serde(default)]
    pub email_code: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<ConnectionId>,
}

impl LinkConfirmMethods {
    /// The candidate has no way at all to confirm on the page (the page then says how to go on).
    pub fn none_available(&self) -> bool {
        !self.password && !self.passkey && !self.email_code && self.connections.is_empty()
    }
}

/// Serialisable form of an [`UpstreamIdentity`] (sealed into a [`PendingLink`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedIdentity {
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
}

impl From<&UpstreamIdentity> for SealedIdentity {
    fn from(i: &UpstreamIdentity) -> Self {
        Self {
            subject: i.subject.clone(),
            email: i.email.clone(),
            email_verified: i.email_verified,
            given_name: i.given_name.clone(),
            family_name: i.family_name.clone(),
            name: i.name.clone(),
            metadata: i.metadata.clone(),
        }
    }
}

impl From<SealedIdentity> for UpstreamIdentity {
    fn from(s: SealedIdentity) -> Self {
        Self {
            subject: s.subject,
            email: s.email,
            email_verified: s.email_verified,
            given_name: s.given_name,
            family_name: s.family_name,
            name: s.name,
            metadata: s.metadata,
        }
    }
}

/// base64url SHA-256 of a `state` or binding value (what the flow stores).
pub fn value_hash(value: &str) -> String {
    b64url(&secret_hash(value))
}

/// The flow id of a `state` parameter (`{flow_id}.{random}`). `None` if malformed.
pub fn split_state(state: &str) -> Option<FlowId> {
    let (flow, random) = state.split_once('.')?;
    if random.is_empty() || random.len() > 128 || flow.len() != 36 {
        return None;
    }
    uuid::Uuid::parse_str(flow).ok().map(FlowId)
}

/// Why a callback does not belong to the pending authorization. The `reason` strings are the
/// audit reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackReject {
    /// The `state` is not the one sent for this flow.
    State,
    /// The callback is for another connection than the one started.
    Connection,
    /// The binding cookie is missing or wrong (another browser).
    Binding,
    /// The sign-in was started more than [`UPSTREAM_TTL`] ago.
    Expired,
}

impl CallbackReject {
    pub fn reason(self) -> &'static str {
        match self {
            Self::State => "state_invalid",
            Self::Connection => "connection_mismatch",
            Self::Binding => "binding_invalid",
            Self::Expired => "expired",
        }
    }
}

/// Checks that a callback belongs to `pending`: same `state` and binding cookie (constant-time
/// hash comparisons, both always compared), the connection that was started, within
/// [`UPSTREAM_TTL`].
pub fn check_callback(
    pending: &PendingUpstream,
    state: &str,
    binding_cookie: Option<&str>,
    connection: Option<ConnectionId>,
    now: OffsetDateTime,
) -> Result<(), CallbackReject> {
    let state_ok = ct_eq(value_hash(state).as_bytes(), pending.state_hash.as_bytes());
    let binding_ok = binding_cookie
        .is_some_and(|b| ct_eq(value_hash(b).as_bytes(), pending.binding_hash.as_bytes()));
    if !state_ok {
        return Err(CallbackReject::State);
    }
    if connection != Some(pending.connection_id) {
        return Err(CallbackReject::Connection);
    }
    if !binding_ok {
        return Err(CallbackReject::Binding);
    }
    if !is_fresh(pending, now) {
        return Err(CallbackReject::Expired);
    }
    Ok(())
}

/// `true` while the pending authorization is younger than [`UPSTREAM_TTL`].
pub fn is_fresh(pending: &PendingUpstream, now: OffsetDateTime) -> bool {
    let age = now.unix_timestamp() - pending.started_at;
    (0..=UPSTREAM_TTL.whole_seconds()).contains(&age)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-25 12:00 UTC);

    fn pending(conn: ConnectionId) -> PendingUpstream {
        PendingUpstream {
            connection_id: conn,
            state_hash: value_hash("state-1"),
            nonce: Some("n".into()),
            pkce_sealed: None,
            binding_hash: value_hash("bind-1"),
            purpose: UpstreamPurpose::Login,
            started_at: NOW.unix_timestamp(),
            expected_iss: None,
            response_sealed: None,
        }
    }

    #[test]
    fn matching_callback_passes() {
        let c = ConnectionId::new_v7();
        assert_eq!(
            check_callback(&pending(c), "state-1", Some("bind-1"), Some(c), NOW),
            Ok(())
        );
    }

    #[test]
    fn wrong_state_binding_connection_or_age_is_rejected() {
        let c = ConnectionId::new_v7();
        let p = pending(c);
        assert_eq!(
            check_callback(&p, "state-2", Some("bind-1"), Some(c), NOW),
            Err(CallbackReject::State)
        );
        assert_eq!(
            check_callback(&p, "state-1", None, Some(c), NOW),
            Err(CallbackReject::Binding)
        );
        assert_eq!(
            check_callback(&p, "state-1", Some("bind-2"), Some(c), NOW),
            Err(CallbackReject::Binding)
        );
        assert_eq!(
            check_callback(
                &p,
                "state-1",
                Some("bind-1"),
                Some(ConnectionId::new_v7()),
                NOW
            ),
            Err(CallbackReject::Connection)
        );
        assert_eq!(
            check_callback(&p, "state-1", Some("bind-1"), None, NOW),
            Err(CallbackReject::Connection)
        );
        assert_eq!(
            check_callback(
                &p,
                "state-1",
                Some("bind-1"),
                Some(c),
                NOW + UPSTREAM_TTL + Duration::seconds(1)
            ),
            Err(CallbackReject::Expired)
        );
        assert!(is_fresh(&p, NOW + UPSTREAM_TTL));
    }

    #[test]
    fn state_carries_the_flow_id() {
        let f = FlowId::new_v7();
        assert_eq!(split_state(&format!("{f}.abc")), Some(f));
        for bad in ["", "abc", &format!("{f}."), &format!("{f}"), "x.y"] {
            assert_eq!(split_state(bad), None, "{bad}");
        }
        assert_eq!(split_state(&format!("{f}.{}", "a".repeat(129))), None);
    }

    #[test]
    fn aad_binds_tenant_and_flow() {
        let t = TenantId::new_v7();
        let f = FlowId::new_v7();
        assert_ne!(upstream_aad(t, f), upstream_aad(t, FlowId::new_v7()));
        assert_ne!(upstream_aad(t, f), upstream_aad(TenantId::new_v7(), f));
        assert_eq!(upstream_aad(t, f).len(), 32);
    }

    #[test]
    fn identity_round_trips_through_its_sealed_form() {
        let mut metadata = Map::new();
        metadata.insert("login".into(), Value::from("octo"));
        let id = UpstreamIdentity {
            subject: "s".into(),
            email: Some("a@b.example".into()),
            email_verified: true,
            given_name: Some("A".into()),
            family_name: None,
            name: Some("A B".into()),
            metadata,
        };
        let json = serde_json::to_string(&SealedIdentity::from(&id)).unwrap();
        let back: SealedIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(UpstreamIdentity::from(back), id);
    }

    #[test]
    fn pending_json_omits_absent_values() {
        let p = pending(ConnectionId::new_v7());
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("pkce_sealed"), "{json}");
        assert!(!json.contains("response_sealed"), "{json}");
        let back: PendingUpstream = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
        let link = UpstreamPurpose::Link {
            user_id: UserId::new_v7(),
        };
        let j = serde_json::to_string(&link).unwrap();
        assert_eq!(serde_json::from_str::<UpstreamPurpose>(&j).unwrap(), link);
    }
}
