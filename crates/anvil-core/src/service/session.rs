//! Browser sessions.
//!
//! The session cookie holds a 256-bit random token; only its SHA-256 is stored. A session lasts
//! at most [`SESSION_ABSOLUTE_LIFETIME`] (14 days) from sign-in and ends after
//! [`SESSION_IDLE_TIMEOUT`] (12 hours) without use. Every use pushes the idle deadline forward,
//! but never past the absolute expiry. Signing in rotates the session: the previous session is
//! revoked and a new token is issued (session fixation defence).

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::SecretString;
use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::{
    BrowserSession, NewBrowserSession, RequestContext, SecretHash, SessionId, TenantId, UserId,
};
use crate::ports::{Clock, Storage};

/// Absolute session lifetime from sign-in.
pub const SESSION_ABSOLUTE_LIFETIME: Duration = Duration::days(14);
/// Idle timeout: a session unused for this long expires.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::hours(12);

/// `(expires_at, idle_expires_at)` of a session created at `now`.
pub fn session_expiry(now: OffsetDateTime) -> (OffsetDateTime, OffsetDateTime) {
    let expires_at = now + SESSION_ABSOLUTE_LIFETIME;
    (expires_at, next_idle_expiry(now, expires_at))
}

/// The idle deadline after a use at `now`, capped at the absolute expiry.
pub fn next_idle_expiry(now: OffsetDateTime, expires_at: OffsetDateTime) -> OffsetDateTime {
    (now + SESSION_IDLE_TIMEOUT).min(expires_at)
}

/// A new session together with the plaintext cookie token (shown to the browser once).
pub struct NewSessionCookie {
    pub token: SecretString,
    pub session: BrowserSession,
}

impl std::fmt::Debug for NewSessionCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSessionCookie")
            .field("token", &"<redacted>")
            .field("session", &self.session.id)
            .finish()
    }
}

/// Creates, resolves and revokes browser sessions.
#[derive(Clone)]
pub struct SessionService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl SessionService {
    /// Creates a session for `user`. If `replaces` is given, that session is revoked first. The
    /// client IP and user agent of `ctx` are stored with the session (shown on the sessions
    /// page).
    pub async fn create(
        &self,
        tenant: TenantId,
        user: UserId,
        acr: &str,
        amr: &[String],
        replaces: Option<SessionId>,
        ctx: &RequestContext,
    ) -> Result<NewSessionCookie, CoreError> {
        let now = self.clock.now();
        let (ip, user_agent) = session_client(ctx);
        if let Some(old) = replaces {
            self.storage.sessions().revoke(tenant, old, now).await?;
        }
        let token = random_token();
        let (expires_at, idle_expires_at) = session_expiry(now);
        let new = NewBrowserSession {
            id: SessionId::new_v7(),
            user_id: user,
            token_hash: SecretHash(secret_hash(&token)),
            auth_time: now,
            acr: acr.to_owned(),
            amr: amr.to_vec(),
            created_at: now,
            expires_at,
            idle_expires_at,
            ip,
            user_agent,
        };
        self.storage.sessions().create(tenant, &new).await?;
        let session = BrowserSession {
            id: new.id,
            tenant_id: tenant,
            user_id: new.user_id,
            token_hash: new.token_hash,
            auth_time: new.auth_time,
            acr: new.acr,
            amr: new.amr,
            created_at: now,
            last_seen_at: now,
            expires_at,
            idle_expires_at,
            revoked_at: None,
            ip: new.ip,
            user_agent: new.user_agent,
        };
        Ok(NewSessionCookie {
            token: SecretString::from(token),
            session,
        })
    }

    /// The active session for a cookie token, if any. Extends the idle deadline.
    pub async fn current(
        &self,
        tenant: TenantId,
        cookie_token: Option<&str>,
    ) -> Result<Option<BrowserSession>, CoreError> {
        let Some(token) = cookie_token.filter(|t| !t.is_empty()) else {
            return Ok(None);
        };
        let now = self.clock.now();
        let hash = SecretHash(secret_hash(token));
        let Some(mut session) = self
            .storage
            .sessions()
            .get_active(tenant, &hash, now)
            .await?
        else {
            return Ok(None);
        };
        let idle = next_idle_expiry(now, session.expires_at);
        if !self
            .storage
            .sessions()
            .touch(tenant, session.id, now, idle)
            .await?
        {
            // Revoked or expired between lookup and touch.
            return Ok(None);
        }
        session.last_seen_at = now;
        session.idle_expires_at = idle;
        Ok(Some(session))
    }

    /// Revokes a session. Unknown or already revoked sessions are not an error.
    pub async fn revoke(&self, tenant: TenantId, id: SessionId) -> Result<(), CoreError> {
        self.storage
            .sessions()
            .revoke(tenant, id, self.clock.now())
            .await?;
        Ok(())
    }
}

/// `(ip, user_agent)` stored on a session created in `ctx` (the user agent is already
/// truncated by [`RequestContext::new`]).
pub fn session_client(ctx: &RequestContext) -> (Option<String>, Option<String>) {
    (ctx.ip.map(|ip| ip.to_string()), ctx.user_agent.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn session_client_takes_ip_and_user_agent_from_the_request() {
        let ctx = RequestContext::new(
            Some("2001:db8::7".parse().unwrap()),
            Some("Mozilla/5.0"),
            Some("req-1".into()),
        );
        assert_eq!(
            session_client(&ctx),
            (Some("2001:db8::7".into()), Some("Mozilla/5.0".into()))
        );
        assert_eq!(session_client(&RequestContext::default()), (None, None));
    }

    #[test]
    fn expiry_is_14d_absolute_and_12h_idle() {
        let now = datetime!(2026-11-25 12:00 UTC);
        let (abs, idle) = session_expiry(now);
        assert_eq!(abs, datetime!(2026-12-09 12:00 UTC));
        assert_eq!(idle, datetime!(2026-11-26 00:00 UTC));
    }

    #[test]
    fn idle_never_exceeds_absolute() {
        let start = datetime!(2026-11-25 12:00 UTC);
        let (abs, _) = session_expiry(start);
        let late = abs - Duration::hours(1);
        assert_eq!(next_idle_expiry(late, abs), abs);
        let early = start + Duration::hours(1);
        assert_eq!(next_idle_expiry(early, abs), early + SESSION_IDLE_TIMEOUT);
    }

    #[test]
    fn cookie_debug_redacts_token() {
        let now = datetime!(2026-11-25 12:00 UTC);
        let c = NewSessionCookie {
            token: SecretString::from("cookie-secret".to_owned()),
            session: BrowserSession {
                id: SessionId::new_v7(),
                tenant_id: TenantId::new_v7(),
                user_id: UserId::new_v7(),
                token_hash: SecretHash([0; 32]),
                auth_time: now,
                acr: String::new(),
                amr: Vec::new(),
                created_at: now,
                last_seen_at: now,
                expires_at: now,
                idle_expires_at: now,
                revoked_at: None,
                ip: None,
                user_agent: None,
            },
        };
        assert!(!format!("{c:?}").contains("cookie-secret"));
    }
}
