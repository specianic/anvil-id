//! The core error type and its single mapping to OAuth error codes and HTTP statuses.
//!
//! [`CoreError::oauth_error`], [`CoreError::http_status`] and [`CoreError::description`] are the
//! only place where a domain failure becomes a wire error. Handlers never pick codes themselves.

use crate::ports::StorageError;

/// Every failure the core reports to the web layer.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    /// Client authentication failed. `basic_auth_used` tells the web layer to answer with a
    /// `WWW-Authenticate: Basic` challenge (RFC 6749 §5.2).
    #[error("invalid_client: {reason}")]
    InvalidClient {
        reason: String,
        basic_auth_used: bool,
    },
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("unsupported_response_type")]
    UnsupportedResponseType,
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("access_denied: {0}")]
    AccessDenied(String),
    #[error("login_required")]
    LoginRequired,
    #[error("interaction_required")]
    InteractionRequired,
    /// `prompt=none` but the user has not consented to the requested scopes (OIDC Core §3.1.2.6).
    #[error("consent_required")]
    ConsentRequired,
    /// RFC 7009 §2.2.1: the server does not support revoking this token type.
    #[error("unsupported_token_type")]
    UnsupportedTokenType,
    #[error("request_not_supported")]
    RequestNotSupported,
    #[error("request_uri_not_supported")]
    RequestUriNotSupported,
    /// RFC 8707 §2: a `resource` is invalid, not allowed for the client or not combinable.
    #[error("invalid_target: {0}")]
    InvalidTarget(String),
    /// OpenID Connect Unmet Authentication Requirements 1.0: an essential `acr` cannot be met.
    /// Delivered to the RP like `login_required`.
    #[error("unmet_authentication_requirements")]
    UnmetAuthenticationRequirements,
    /// RFC 6750 bearer token error.
    #[error("invalid_token: {0}")]
    InvalidToken(String),
    #[error("insufficient_scope: {0}")]
    InsufficientScope(String),
    /// Input validation failure on a named field (forms, management API).
    #[error("validation failed on {field}: {message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("forbidden")]
    Forbidden,
    /// Load shedding (e.g. the password hashing queue is full).
    #[error("overloaded")]
    Overloaded,
    /// Internal failure. The message is for logs only.
    #[error("internal error: {0}")]
    Internal(String),
    /// Storage failure. The inner error is for logs only.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

impl CoreError {
    /// The OAuth / OIDC / RFC 6750 `error` code. Management-API-only variants use `not_found`,
    /// `conflict` and `forbidden`; `Validation` uses `invalid_request`.
    pub fn oauth_error(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient { .. } => "invalid_client",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::UnauthorizedClient(_) => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope(_) => "invalid_scope",
            Self::AccessDenied(_) => "access_denied",
            Self::LoginRequired => "login_required",
            Self::InteractionRequired => "interaction_required",
            Self::ConsentRequired => "consent_required",
            Self::UnsupportedTokenType => "unsupported_token_type",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::InvalidTarget(_) => "invalid_target",
            Self::UnmetAuthenticationRequirements => "unmet_authentication_requirements",
            Self::InvalidToken(_) => "invalid_token",
            Self::InsufficientScope(_) => "insufficient_scope",
            Self::Validation { .. } => "invalid_request",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Forbidden => "forbidden",
            Self::Overloaded => "temporarily_unavailable",
            Self::Internal(_) | Self::Storage(_) => "server_error",
        }
    }

    /// The HTTP status for a direct (non-redirect) error response.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidClient { .. } | Self::InvalidToken(_) => 401,
            Self::InsufficientScope(_) | Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict(_) => 409,
            Self::Validation { .. } => 422,
            Self::Overloaded => 503,
            Self::Internal(_) | Self::Storage(_) => 500,
            Self::InvalidRequest(_)
            | Self::InvalidGrant(_)
            | Self::UnauthorizedClient(_)
            | Self::UnsupportedGrantType
            | Self::UnsupportedResponseType
            | Self::InvalidScope(_)
            | Self::AccessDenied(_)
            | Self::LoginRequired
            | Self::InteractionRequired
            | Self::ConsentRequired
            | Self::UnsupportedTokenType
            | Self::RequestNotSupported
            | Self::RequestUriNotSupported
            | Self::InvalidTarget(_)
            | Self::UnmetAuthenticationRequirements => 400,
        }
    }

    /// The `error_description` safe to send to a client. Internal and storage failures get a
    /// generic text; their details never leave the server.
    pub fn description(&self) -> String {
        match self {
            Self::InvalidRequest(m)
            | Self::InvalidGrant(m)
            | Self::UnauthorizedClient(m)
            | Self::InvalidScope(m)
            | Self::AccessDenied(m)
            | Self::InvalidToken(m)
            | Self::InsufficientScope(m)
            | Self::InvalidTarget(m)
            | Self::Conflict(m) => m.clone(),
            Self::InvalidClient { reason, .. } => reason.clone(),
            Self::Validation { field, message } => format!("{field}: {message}"),
            Self::UnsupportedGrantType => "the grant type is not supported".to_owned(),
            Self::UnsupportedResponseType => "the response type is not supported".to_owned(),
            Self::LoginRequired => "the user must sign in".to_owned(),
            Self::InteractionRequired => "user interaction is required".to_owned(),
            Self::ConsentRequired => "the user must consent to the requested scopes".to_owned(),
            Self::UnsupportedTokenType => "the token type is not supported".to_owned(),
            Self::RequestNotSupported => "the request parameter is not supported".to_owned(),
            Self::RequestUriNotSupported => "the request_uri parameter is not supported".to_owned(),
            Self::UnmetAuthenticationRequirements => {
                "the requested authentication requirements cannot be met".to_owned()
            }
            Self::NotFound => "not found".to_owned(),
            Self::Forbidden => "forbidden".to_owned(),
            Self::Overloaded => "the server is temporarily overloaded, retry later".to_owned(),
            Self::Internal(_) | Self::Storage(_) => "internal server error".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_owned()
    }

    #[test]
    fn every_variant_maps_to_one_code_and_status() {
        let cases: Vec<(CoreError, &str, u16)> = vec![
            (CoreError::InvalidRequest(s("x")), "invalid_request", 400),
            (
                CoreError::InvalidClient {
                    reason: s("x"),
                    basic_auth_used: true,
                },
                "invalid_client",
                401,
            ),
            (CoreError::InvalidGrant(s("x")), "invalid_grant", 400),
            (
                CoreError::UnauthorizedClient(s("x")),
                "unauthorized_client",
                400,
            ),
            (
                CoreError::UnsupportedGrantType,
                "unsupported_grant_type",
                400,
            ),
            (
                CoreError::UnsupportedResponseType,
                "unsupported_response_type",
                400,
            ),
            (CoreError::InvalidScope(s("x")), "invalid_scope", 400),
            (CoreError::AccessDenied(s("x")), "access_denied", 400),
            (CoreError::LoginRequired, "login_required", 400),
            (CoreError::InteractionRequired, "interaction_required", 400),
            (CoreError::ConsentRequired, "consent_required", 400),
            (
                CoreError::UnsupportedTokenType,
                "unsupported_token_type",
                400,
            ),
            (CoreError::RequestNotSupported, "request_not_supported", 400),
            (
                CoreError::RequestUriNotSupported,
                "request_uri_not_supported",
                400,
            ),
            (CoreError::InvalidTarget(s("x")), "invalid_target", 400),
            (
                CoreError::UnmetAuthenticationRequirements,
                "unmet_authentication_requirements",
                400,
            ),
            (CoreError::InvalidToken(s("x")), "invalid_token", 401),
            (
                CoreError::InsufficientScope(s("x")),
                "insufficient_scope",
                403,
            ),
            (
                CoreError::Validation {
                    field: "email",
                    message: s("x"),
                },
                "invalid_request",
                422,
            ),
            (CoreError::NotFound, "not_found", 404),
            (CoreError::Conflict(s("x")), "conflict", 409),
            (CoreError::Forbidden, "forbidden", 403),
            (CoreError::Overloaded, "temporarily_unavailable", 503),
            (CoreError::Internal(s("x")), "server_error", 500),
            (
                CoreError::Storage(StorageError::Conflict(s("x"))),
                "server_error",
                500,
            ),
        ];
        for (err, code, status) in cases {
            assert_eq!(err.oauth_error(), code, "{err:?}");
            assert_eq!(err.http_status(), status, "{err:?}");
            assert!(!err.description().is_empty(), "{err:?}");
        }
    }

    #[test]
    fn internal_and_storage_descriptions_do_not_leak() {
        let secret = "db at 10.0.0.1 password hunter2";
        for err in [
            CoreError::Internal(secret.to_owned()),
            CoreError::Storage(StorageError::Backend(secret.into())),
            CoreError::Storage(StorageError::Corrupt(secret.to_owned())),
        ] {
            assert!(!err.description().contains("hunter2"), "{err:?}");
            assert_eq!(err.description(), "internal server error");
        }
    }

    #[test]
    fn from_storage_error() {
        let e: CoreError = StorageError::Unsupported("x").into();
        assert_eq!(e.http_status(), 500);
    }
}
