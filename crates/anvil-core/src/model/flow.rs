//! Self-service flows (login, registration, verification, recovery, setup).

use time::OffsetDateTime;

use super::ids::{AuthRequestId, FlowId, SecretHash, TenantId, str_enum};

/// Kind of a self-service flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowKind {
    Login,
    Registration,
    Verification,
    Recovery,
    Setup,
    /// Account settings (passkeys, TOTP, recovery codes, password change).
    Settings,
    /// OAuth consent screen.
    Consent,
}

str_enum!(FlowKind {
    Login => "login",
    Registration => "registration",
    Verification => "verification",
    Recovery => "recovery",
    Setup => "setup",
    Settings => "settings",
    Consent => "consent",
});

/// A persisted flow. `state` is opaque to storage (JSON produced by the flow engine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub id: FlowId,
    pub tenant_id: TenantId,
    pub kind: FlowKind,
    pub state: String,
    pub csrf_hash: SecretHash,
    pub cookie_hash: SecretHash,
    pub auth_request_id: Option<AuthRequestId>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// A flow to be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFlow {
    pub id: FlowId,
    pub kind: FlowKind,
    pub state: String,
    pub csrf_hash: SecretHash,
    pub cookie_hash: SecretHash,
    pub auth_request_id: Option<AuthRequestId>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_kind_names_round_trip() {
        for v in FlowKind::ALL {
            assert_eq!(FlowKind::parse(v.as_str()), Some(*v));
        }
    }
}
