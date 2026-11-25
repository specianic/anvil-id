//! Authorization requests, codes, token families, refresh tokens, replay guards and
//! self-service tokens.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{
    AuthRequestId, CodeHash, SecretHash, SessionId, TenantId, TokenFamilyId, UserId, str_enum,
};
use crate::error::CoreError;
use crate::oauth::response_mode::ResponseMode;

/// A parsed OAuth scope (RFC 6749 §3.3): a set of scope tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope(BTreeSet<String>);

fn is_nqchar(c: char) -> bool {
    matches!(c, '\x21' | '\x23'..='\x5B' | '\x5D'..='\x7E')
}

impl Scope {
    /// Parses a space-delimited scope string. Rejects empty tokens (leading, trailing or double
    /// spaces, or an empty string) and tokens with characters outside NQCHAR.
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        let mut set = BTreeSet::new();
        for token in raw.split(' ') {
            if token.is_empty() {
                return Err(CoreError::InvalidScope(
                    "scope contains an empty token".to_owned(),
                ));
            }
            if !token.chars().all(is_nqchar) {
                return Err(CoreError::InvalidScope(
                    "scope contains an invalid character".to_owned(),
                ));
            }
            set.insert(token.to_owned());
        }
        Ok(Self(set))
    }

    /// Whether the scope contains `token`.
    pub fn contains(&self, token: &str) -> bool {
        self.0.contains(token)
    }

    /// Whether every token of `self` is in `other`.
    pub fn is_subset(&self, other: &Scope) -> bool {
        self.0.is_subset(&other.0)
    }

    /// The tokens in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<String> for Scope {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl std::fmt::Display for Scope {
    /// Sorted, space-joined.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for token in &self.0 {
            if !first {
                f.write_str(" ")?;
            }
            f.write_str(token)?;
            first = false;
        }
        Ok(())
    }
}

/// OIDC Core §5.5 `claims` request parameter, reduced to the parts 0.1 honours.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaimsRequest {
    pub userinfo: Vec<RequestedClaim>,
    pub id_token: Vec<RequestedClaim>,
}

/// One requested claim (`essential`, `value`/`values` merged into `values`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedClaim {
    pub name: String,
    #[serde(default)]
    pub essential: bool,
    #[serde(default)]
    pub values: Vec<String>,
}

/// Validated authorization request parameters, kept while the user signs in. Backends store
/// this struct as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationParams {
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub prompt: Vec<String>,
    pub max_age: Option<i64>,
    pub login_hint: Option<String>,
    #[serde(default)]
    pub acr_values: Vec<String>,
    pub ui_locales: Option<String>,
    pub claims: Option<ClaimsRequest>,
    /// How the authorization response is delivered; absent in requests stored by 0.1.
    #[serde(default)]
    pub response_mode: ResponseMode,
    /// RFC 8707 resource indicators (absolute URIs); absent in requests stored by 0.2.
    #[serde(default)]
    pub resource: Vec<String>,
}

/// A stored authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub id: AuthRequestId,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub params: AuthorizationParams,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// An authorization request to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuthorizationRequest {
    pub id: AuthRequestId,
    pub client_id: String,
    pub params: AuthorizationParams,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// An authorization code to be stored together with its token family
/// (`token_family_id == family.id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuthorizationCode {
    pub code_hash: CodeHash,
    pub client_id: String,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub redirect_uri: String,
    pub scope: String,
    /// RFC 8707 resources the tokens are audience-bound to (empty = the client).
    pub resource: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub auth_time: OffsetDateTime,
    pub acr: String,
    pub amr: Vec<String>,
    pub token_family_id: TokenFamilyId,
    /// The issuer of the authorization response and of the ID tokens issued from this code.
    /// Recorded on the RP session for back-channel logout.
    pub issuer: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// A stored authorization code, as returned when it is consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    pub tenant_id: TenantId,
    pub code_hash: CodeHash,
    pub client_id: String,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub redirect_uri: String,
    pub scope: String,
    /// RFC 8707 resources the tokens are audience-bound to (empty = the client).
    pub resource: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub auth_time: OffsetDateTime,
    pub acr: String,
    pub amr: Vec<String>,
    pub token_family_id: TokenFamilyId,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// Why a token family was revoked. The first reason is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevokeReason {
    CodeReuse,
    RefreshReuse,
    UserRecovery,
    ClientDeleted,
    UserDeleted,
    Admin,
    ConsentRevoked,
    SessionRevoked,
    TokenRevoked,
}

str_enum!(RevokeReason {
    CodeReuse => "code_reuse",
    RefreshReuse => "refresh_reuse",
    UserRecovery => "user_recovery",
    ClientDeleted => "client_deleted",
    UserDeleted => "user_deleted",
    Admin => "admin",
    ConsentRevoked => "consent_revoked",
    SessionRevoked => "session_revoked",
    TokenRevoked => "token_revoked",
});

/// A token family: every token issued from one authorization (code or client credentials). It
/// carries the authentication context so refreshed ID tokens repeat `auth_time`, `acr` and `amr`
/// and UserInfo can apply `claims.userinfo`. Access tokens carry the family id; revoking the
/// family invalidates all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFamily {
    pub id: TokenFamilyId,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub user_id: Option<UserId>,
    pub scope: String,
    /// RFC 8707 resources the tokens are audience-bound to (empty = the client).
    pub resource: Vec<String>,
    pub auth_time: Option<OffsetDateTime>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub session_id: Option<SessionId>,
    pub claims: Option<ClaimsRequest>,
    pub created_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoked_reason: Option<RevokeReason>,
}

/// A token family to be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTokenFamily {
    pub id: TokenFamilyId,
    pub client_id: String,
    pub user_id: Option<UserId>,
    pub scope: String,
    /// RFC 8707 resources the tokens are audience-bound to (empty = the client).
    pub resource: Vec<String>,
    pub auth_time: Option<OffsetDateTime>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub session_id: Option<SessionId>,
    pub claims: Option<ClaimsRequest>,
    pub created_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
}

/// A stored refresh token (looked up by hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub token_hash: SecretHash,
    pub tenant_id: TenantId,
    pub family_id: TokenFamilyId,
    pub parent_hash: Option<SecretHash>,
    pub scope: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

/// A refresh token to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRefreshToken {
    pub token_hash: SecretHash,
    pub family_id: TokenFamilyId,
    pub parent_hash: Option<SecretHash>,
    pub scope: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// A stored opaque access token (looked up by hash). Client-credentials tokens may have no
/// family; tokens of an authorization have one, and revoking the family invalidates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRecord {
    pub token_hash: SecretHash,
    pub tenant_id: TenantId,
    pub family_id: Option<TokenFamilyId>,
    pub client_id: String,
    pub user_id: Option<UserId>,
    pub scope: String,
    /// RFC 8707 resources the tokens are audience-bound to (empty = the client).
    pub resource: Vec<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// An opaque access token to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccessToken {
    pub token_hash: SecretHash,
    pub family_id: Option<TokenFamilyId>,
    pub client_id: String,
    pub user_id: Option<UserId>,
    pub scope: String,
    /// RFC 8707 resources the tokens are audience-bound to (empty = the client).
    pub resource: Vec<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// What a replay guard protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayKind {
    /// `jti` of a `private_key_jwt` client assertion.
    ClientAssertionJti,
}

str_enum!(ReplayKind {
    ClientAssertionJti => "client_assertion_jti",
});

/// Purpose of a self-service token (sent by email).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfServiceKind {
    Verification,
    Recovery,
    Invitation,
    /// Confirms a new email address (`email` = the new address).
    EmailChange,
}

str_enum!(SelfServiceKind {
    Verification => "verification",
    Recovery => "recovery",
    Invitation => "invitation",
    EmailChange => "email_change",
});

/// A stored self-service token. `email` is the address the token was sent to; verification only
/// succeeds while the user's email still equals it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfServiceToken {
    pub token_hash: SecretHash,
    pub tenant_id: TenantId,
    pub kind: SelfServiceKind,
    pub user_id: UserId,
    pub email: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

/// A self-service token to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSelfServiceToken {
    pub token_hash: SecretHash,
    pub kind: SelfServiceKind,
    pub user_id: UserId,
    pub email: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parse_and_display_sorted() {
        let s = Scope::parse("profile openid email openid").unwrap();
        assert_eq!(s.len(), 3);
        assert!(s.contains("openid"));
        assert!(!s.contains("phone"));
        assert_eq!(s.to_string(), "email openid profile");
    }

    #[test]
    fn scope_rejects_empty_tokens_and_bad_chars() {
        for bad in [
            "",
            " openid",
            "openid ",
            "openid  profile",
            "a\"b",
            "a\\b",
            "é",
            "a\tb",
        ] {
            assert!(
                matches!(Scope::parse(bad), Err(CoreError::InvalidScope(_))),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn scope_subset() {
        let small = Scope::parse("openid").unwrap();
        let big = Scope::parse("openid profile").unwrap();
        assert!(small.is_subset(&big));
        assert!(!big.is_subset(&small));
    }

    #[test]
    fn params_stored_by_0_2_parse_without_resource() {
        let json = r#"{"redirect_uri":"https://rp/cb","scope":"openid","state":null,"nonce":null,"code_challenge":null,"max_age":null,"login_hint":null,"ui_locales":null,"claims":null}"#;
        let p: AuthorizationParams = serde_json::from_str(json).unwrap();
        assert!(p.resource.is_empty());
    }

    #[test]
    fn enum_names_round_trip() {
        for v in RevokeReason::ALL {
            assert_eq!(RevokeReason::parse(v.as_str()), Some(*v));
        }
        for v in SelfServiceKind::ALL {
            assert_eq!(SelfServiceKind::parse(v.as_str()), Some(*v));
        }
        for v in ReplayKind::ALL {
            assert_eq!(ReplayKind::parse(v.as_str()), Some(*v));
        }
    }
}
