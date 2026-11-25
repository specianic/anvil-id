//! The request context recorded with audit events: client IP ([`crate::client_ip`]), user agent
//! and request id.

use anvil_core::model::RequestContext;
use axum::extract::FromRequestParts;
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;

use crate::client_ip::{ClientIp, MissingPeerAddress};
use crate::state::AppState;

/// Longest request id kept (the id normally is a UUID set by the request-id layer).
pub const MAX_REQUEST_ID_CHARS: usize = 128;

/// Extractor for the audit [`RequestContext`] of a request.
///
/// Rejects like [`ClientIp`] (500 when the peer address is missing).
#[derive(Debug, Clone)]
pub struct AuditContext(pub RequestContext);

impl AuditContext {
    pub fn into_inner(self) -> RequestContext {
        self.0
    }
}

/// Builds the context from request parts and the already resolved client IP.
pub fn request_context(parts: &Parts, ip: ClientIp) -> RequestContext {
    let user_agent = parts
        .headers
        .get(USER_AGENT)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    let request_id = parts
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(|v| v.chars().take(MAX_REQUEST_ID_CHARS).collect::<String>());
    RequestContext::new(Some(ip.0), user_agent.as_deref(), request_id)
}

impl FromRequestParts<AppState> for AuditContext {
    type Rejection = MissingPeerAddress;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, MissingPeerAddress> {
        let ip = ClientIp::from_parts(parts, &state.config().trusted_proxies)?;
        Ok(Self(request_context(parts, ip)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::model::MAX_USER_AGENT_CHARS;
    use axum::http::Request;

    #[test]
    fn request_context_collects_ip_agent_and_request_id() {
        let long_ua = "a".repeat(MAX_USER_AGENT_CHARS + 50);
        let long_id = "r".repeat(MAX_REQUEST_ID_CHARS + 10);
        let (parts, ()) = Request::get("/")
            .header(USER_AGENT, long_ua.as_str())
            .header("x-request-id", long_id.as_str())
            .body(())
            .expect("req")
            .into_parts();
        let ctx = request_context(&parts, ClientIp("198.51.100.7".parse().expect("ip")));
        assert_eq!(ctx.ip, Some("198.51.100.7".parse().expect("ip")));
        assert_eq!(
            ctx.user_agent.as_deref().map(|u| u.chars().count()),
            Some(MAX_USER_AGENT_CHARS)
        );
        assert_eq!(
            ctx.trace_id.as_deref().map(str::len),
            Some(MAX_REQUEST_ID_CHARS)
        );

        let (parts, ()) = Request::get("/").body(()).expect("req").into_parts();
        let ctx = request_context(&parts, ClientIp("::1".parse().expect("ip")));
        assert_eq!(ctx.user_agent, None);
        assert_eq!(ctx.trace_id, None);
    }
}
