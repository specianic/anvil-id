//! Browser sessions.
//!
//! The session cookie holds a 256-bit random token; only its SHA-256 is stored. A session lasts
//! at most [`SESSION_ABSOLUTE_LIFETIME`] (14 days) from sign-in and ends after
//! [`SESSION_IDLE_TIMEOUT`] (12 hours) without use. Every use pushes the idle deadline forward,
//! but never past the absolute expiry. Signing in rotates the session: the previous session is
//! revoked and a new token is issued (session fixation defence).
//!
//! # Activity tracking
//!
//! [`SessionService::current`] slides `idle_expires_at` and `last_seen_at` at most once per
//! [`TOUCH_INTERVAL`] (one minute) per session, so a burst of requests causes one write. The
//! stored idle deadline therefore lags real activity by under a minute; expiry itself is always
//! checked by `SessionRepo::get_active` against both deadlines.
//!
//! # Listing and revocation
//!
//! Users list their active sessions ([`SessionService::list_for_user`]) and revoke one
//! ([`SessionService::revoke_mine`]) or all others ([`SessionService::revoke_others`]).
//! Administrators use the `admin_*` functions (management API). Every revocation also revokes
//! the token families issued under the session (`SessionRepo::revoke_with_families` /
//! `revoke_all_for_user`) and is audited.

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::SecretString;
use time::{Duration, OffsetDateTime};

use super::account::{AccountError, AccountFailure, SettingsBinding};
use super::audit::AuditService;
use super::flow::{BindingError, check_binding};
use super::tenant::admin_page;
use crate::error::CoreError;
use crate::flow::settings::SettingsState;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, BrowserSession, FlowKind,
    NewBrowserSession, Page, PageRequest, RequestContext, SecretHash, SessionId, TenantId, UserId,
};
use crate::ports::{Clock, Storage};

/// Absolute session lifetime from sign-in.
pub const SESSION_ABSOLUTE_LIFETIME: Duration = Duration::days(14);
/// Idle timeout: a session unused for this long expires.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::hours(12);
/// Minimum time between two activity writes (`touch`) of one session.
pub const TOUCH_INTERVAL: Duration = Duration::seconds(60);

/// Whether a use at `now` writes the session's activity (`last_seen_at` at least
/// [`TOUCH_INTERVAL`] ago).
pub fn needs_touch(now: OffsetDateTime, last_seen_at: OffsetDateTime) -> bool {
    now - last_seen_at >= TOUCH_INTERVAL
}

/// A session as shown on the sessions page and in the management API (never the token hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub user_id: UserId,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub auth_time: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
    pub acr: String,
    pub amr: Vec<String>,
    /// Client IP at sign-in, as stored.
    pub ip: Option<String>,
    /// User agent at sign-in, as stored (truncated at sign-in).
    pub user_agent: Option<String>,
    /// The session of the request that lists it.
    pub current: bool,
}

impl SessionInfo {
    fn from_session(s: BrowserSession, current: Option<SessionId>) -> Self {
        Self {
            current: current == Some(s.id),
            id: s.id,
            user_id: s.user_id,
            created_at: s.created_at,
            last_seen_at: s.last_seen_at,
            auth_time: s.auth_time,
            expires_at: s.expires_at,
            idle_expires_at: s.idle_expires_at,
            acr: s.acr,
            amr: s.amr,
            ip: s.ip,
            user_agent: s.user_agent,
        }
    }
}

/// Whether `s` is usable at `now` (not revoked, both deadlines in the future).
pub fn is_active(s: &BrowserSession, now: OffsetDateTime) -> bool {
    s.revoked_at.is_none() && s.expires_at > now && s.idle_expires_at > now
}

/// Message keys of the sessions page.
pub const MSG_SESSION_REVOKED: &str = "sessions.revoked";
pub const MSG_OTHERS_REVOKED: &str = "sessions.revoked_others";
pub const MSG_SESSION_NOT_FOUND: &str = "sessions.not_found";

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

    /// The active session for a cookie token, if any. Extends the idle deadline and records the
    /// activity when the last write is at least [`TOUCH_INTERVAL`] old.
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
        if !needs_touch(now, session.last_seen_at) {
            return Ok(Some(session));
        }
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

    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Checks a sessions-page submission against its settings flow: the flow exists and is
    /// unexpired (else [`AccountFailure::FlowExpired`]), is a settings flow, carries the flow
    /// cookie and CSRF token, and belongs to the session's user (else `Forbidden`). Unlike
    /// credential changes, signing out sessions needs no recent sign-in.
    pub async fn check_settings_binding(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
    ) -> Result<(), AccountError> {
        let now = self.clock.now();
        let Some(flow) = self
            .storage
            .flows()
            .get(tenant, binding.flow_id, now)
            .await?
        else {
            return Err(AccountFailure::FlowExpired.into());
        };
        if flow.kind != FlowKind::Settings {
            return Err(CoreError::Forbidden.into());
        }
        match check_binding(&flow, binding.cookie_token, binding.csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => return Err(AccountFailure::FlowExpired.into()),
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden.into()),
        }
        let state = SettingsState::from_json(&flow.state)
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        if state.user != session.user_id || session.tenant_id != tenant {
            return Err(CoreError::Forbidden.into());
        }
        Ok(())
    }

    /// The user's active sessions, newest first; `current` is marked.
    pub async fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
        current: Option<SessionId>,
    ) -> Result<Vec<SessionInfo>, CoreError> {
        let now = self.clock.now();
        Ok(self
            .storage
            .sessions()
            .list_for_user(tenant, user, now)
            .await?
            .into_iter()
            .map(|s| SessionInfo::from_session(s, current))
            .collect())
    }

    /// The user's active session `id`, else `NotFound` (unknown, another user's, revoked or
    /// expired).
    async fn active_of(
        &self,
        tenant: TenantId,
        user: Option<UserId>,
        id: SessionId,
    ) -> Result<BrowserSession, CoreError> {
        let now = self.clock.now();
        match self.storage.sessions().get(tenant, id).await? {
            Some(s) if is_active(&s, now) && user.is_none_or(|u| u == s.user_id) => Ok(s),
            _ => Err(CoreError::NotFound),
        }
    }

    /// Revokes session `id` with its token families and audits `session_revoked`.
    async fn revoke_audited(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let now = self.clock.now();
        if !self
            .storage
            .sessions()
            .revoke_with_families(tenant, session.id, now)
            .await?
        {
            // Revoked concurrently.
            return Err(CoreError::NotFound);
        }
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::SessionRevoked,
                Some(session.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::empty(),
            )
            .await
    }

    /// The user signs out one of their own active sessions (the current one included). Also
    /// revokes the token families issued under it. `NotFound` for an unknown, inactive or
    /// another user's session.
    pub async fn revoke_mine(
        &self,
        tenant: TenantId,
        user: UserId,
        id: SessionId,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let session = self.active_of(tenant, Some(user), id).await?;
        self.revoke_audited(tenant, &session, AuditActor::user(user), ctx)
            .await
    }

    /// The user signs out every other session (and their token families), keeping `current`.
    /// Returns the number revoked; audited as `sessions_revoked_all` with that count.
    pub async fn revoke_others(
        &self,
        tenant: TenantId,
        user: UserId,
        current: SessionId,
        ctx: &RequestContext,
    ) -> Result<u64, CoreError> {
        let n = self
            .storage
            .sessions()
            .revoke_all_for_user(tenant, user, Some(current), self.clock.now())
            .await?;
        self.audit()
            .record(
                tenant,
                AuditActor::user(user),
                AuditAction::SessionsRevokedAll,
                Some(user.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::count("sessions", n),
            )
            .await?;
        Ok(n)
    }

    /// Admin: the active sessions of `user`, newest first. `NotFound` for an unknown user.
    pub async fn admin_list_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<SessionInfo>, CoreError> {
        if self.storage.users().get(tenant, user).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        self.list_for_user(tenant, user, None).await
    }

    /// Admin: the tenant's active sessions in id order, paged by the management-API rules
    /// (limit `0` → 50, otherwise clamped to `1..=200`).
    pub async fn admin_list_tenant(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<SessionInfo>, CoreError> {
        let page = self
            .storage
            .sessions()
            .list(tenant, self.clock.now(), admin_page(page))
            .await?;
        Ok(Page {
            items: page
                .items
                .into_iter()
                .map(|s| SessionInfo::from_session(s, None))
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    /// Admin: revokes one active session and its token families, audited with the
    /// administrator as actor. `NotFound` for an unknown or inactive session.
    pub async fn admin_revoke(
        &self,
        tenant: TenantId,
        id: SessionId,
        admin: &str,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let session = self.active_of(tenant, None, id).await?;
        self.revoke_audited(tenant, &session, AuditActor::admin(admin), ctx)
            .await
    }

    /// Admin: revokes every session of `user` and their token families, audited as
    /// `sessions_revoked_all` with the administrator as actor. Returns the number revoked;
    /// `NotFound` for an unknown user.
    pub async fn admin_revoke_all(
        &self,
        tenant: TenantId,
        user: UserId,
        admin: &str,
        ctx: &RequestContext,
    ) -> Result<u64, CoreError> {
        if self.storage.users().get(tenant, user).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        let n = self
            .storage
            .sessions()
            .revoke_all_for_user(tenant, user, None, self.clock.now())
            .await?;
        self.audit()
            .record(
                tenant,
                AuditActor::admin(admin),
                AuditAction::SessionsRevokedAll,
                Some(user.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::count("sessions", n),
            )
            .await?;
        Ok(n)
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
    fn touch_is_throttled_to_once_a_minute() {
        let seen = datetime!(2026-11-25 12:00 UTC);
        assert!(!needs_touch(seen, seen));
        assert!(!needs_touch(seen + Duration::seconds(30), seen));
        assert!(!needs_touch(seen + Duration::seconds(59), seen));
        assert!(needs_touch(seen + Duration::seconds(60), seen));
        assert!(needs_touch(seen + Duration::seconds(61), seen));
    }

    #[test]
    fn message_keys_are_namespaced() {
        for k in [
            MSG_SESSION_REVOKED,
            MSG_OTHERS_REVOKED,
            MSG_SESSION_NOT_FOUND,
        ] {
            assert!(k.starts_with("sessions."));
        }
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

/// Service tests against in-memory fakes of the session and audit repositories (the storage
/// contract suite covers the real backends; the web tests cover them end to end).
#[cfg(test)]
mod service_tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    use time::macros::datetime;

    use super::*;
    use crate::model::{AuditEvent, AuditQuery, NewAuditEvent};
    use crate::ports::{
        AttributeRepo, AuditRepo, BrandingRepo, ClientRepo, ConnectionRepo, FlowRepo, GrantRepo,
        JobRepo, KeyRepo, LogoutRepo, MailSettingsRepo, OutboxRepo, RegistrationRepo, RoleRepo,
        SessionRepo, SetupRepo, StorageError, TenantRepo, UserRepo, WebhookRepo,
    };

    /// Runs a future whose fakes never wait (std mutexes only).
    fn run<F: Future>(f: F) -> F::Output {
        let mut f = pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    struct FixedClock(Mutex<OffsetDateTime>);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    #[derive(Default)]
    struct Fake {
        sessions: Mutex<Vec<BrowserSession>>,
        /// Families as (session id, revoked).
        families: Mutex<Vec<(SessionId, bool)>>,
        touches: Mutex<Vec<(SessionId, OffsetDateTime, OffsetDateTime)>>,
        events: Mutex<Vec<NewAuditEvent>>,
    }

    fn active(s: &BrowserSession, now: OffsetDateTime) -> bool {
        is_active(s, now)
    }

    #[async_trait::async_trait]
    impl SessionRepo for Fake {
        async fn create(
            &self,
            _tenant: TenantId,
            _session: &NewBrowserSession,
        ) -> Result<(), StorageError> {
            Err(StorageError::Unsupported("fake: create"))
        }
        async fn get_active(
            &self,
            tenant: TenantId,
            token_hash: &SecretHash,
            now: OffsetDateTime,
        ) -> Result<Option<BrowserSession>, StorageError> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.tenant_id == tenant && s.token_hash == *token_hash && active(s, now))
                .cloned())
        }
        async fn touch(
            &self,
            tenant: TenantId,
            id: SessionId,
            now: OffsetDateTime,
            idle_expires_at: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut all = self.sessions.lock().unwrap();
            let Some(s) = all
                .iter_mut()
                .find(|s| s.tenant_id == tenant && s.id == id && active(s, now))
            else {
                return Ok(false);
            };
            s.last_seen_at = now;
            s.idle_expires_at = idle_expires_at;
            self.touches
                .lock()
                .unwrap()
                .push((id, now, idle_expires_at));
            Ok(true)
        }
        async fn revoke(
            &self,
            tenant: TenantId,
            id: SessionId,
            now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            let mut all = self.sessions.lock().unwrap();
            match all
                .iter_mut()
                .find(|s| s.tenant_id == tenant && s.id == id && s.revoked_at.is_none())
            {
                Some(s) => {
                    s.revoked_at = Some(now);
                    Ok(true)
                }
                None => Ok(false),
            }
        }
        async fn get(
            &self,
            tenant: TenantId,
            id: SessionId,
        ) -> Result<Option<BrowserSession>, StorageError> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.tenant_id == tenant && s.id == id)
                .cloned())
        }
        async fn list_for_user(
            &self,
            tenant: TenantId,
            user: UserId,
            now: OffsetDateTime,
        ) -> Result<Vec<BrowserSession>, StorageError> {
            let mut v: Vec<_> = self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.tenant_id == tenant && s.user_id == user && active(s, now))
                .cloned()
                .collect();
            v.sort_by_key(|s| std::cmp::Reverse(s.id));
            Ok(v)
        }
        async fn list(
            &self,
            tenant: TenantId,
            now: OffsetDateTime,
            page: PageRequest,
        ) -> Result<Page<BrowserSession>, StorageError> {
            let mut v: Vec<_> = self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .filter(|s| {
                    s.tenant_id == tenant && active(s, now) && page.after.is_none_or(|a| s.id.0 > a)
                })
                .cloned()
                .collect();
            v.sort_by_key(|s| s.id);
            let more = v.len() > page.limit as usize;
            v.truncate(page.limit as usize);
            let next_cursor = more.then(|| v.last().map(|s| s.id.0)).flatten();
            Ok(Page {
                items: v,
                next_cursor,
            })
        }
        async fn revoke_with_families(
            &self,
            tenant: TenantId,
            id: SessionId,
            now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            if !self.revoke(tenant, id, now).await? {
                return Ok(false);
            }
            for f in self.families.lock().unwrap().iter_mut() {
                if f.0 == id {
                    f.1 = true;
                }
            }
            Ok(true)
        }
        async fn revoke_all_for_user(
            &self,
            tenant: TenantId,
            user: UserId,
            except: Option<SessionId>,
            now: OffsetDateTime,
        ) -> Result<u64, StorageError> {
            let ids: Vec<SessionId> = self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .filter(|s| {
                    s.tenant_id == tenant
                        && s.user_id == user
                        && s.revoked_at.is_none()
                        && Some(s.id) != except
                })
                .map(|s| s.id)
                .collect();
            for id in &ids {
                self.revoke_with_families(tenant, *id, now).await?;
            }
            Ok(ids.len() as u64)
        }
        async fn upgrade_auth(
            &self,
            _tenant: TenantId,
            _id: SessionId,
            _acr: &str,
            _amr: &[String],
            _auth_time: OffsetDateTime,
            _now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            Err(StorageError::Unsupported("fake: upgrade_auth"))
        }
    }

    #[async_trait::async_trait]
    impl AuditRepo for Fake {
        async fn append(
            &self,
            _tenant: TenantId,
            event: &NewAuditEvent,
        ) -> Result<(), StorageError> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
        async fn query(
            &self,
            _tenant: TenantId,
            _query: &AuditQuery,
        ) -> Result<Page<AuditEvent>, StorageError> {
            Err(StorageError::Unsupported("fake: audit query"))
        }
        async fn purge_before(&self, _cutoff: OffsetDateTime) -> Result<u64, StorageError> {
            Err(StorageError::Unsupported("fake: audit purge"))
        }
    }

    /// The Phase 5 repositories are not used by the session service: every call is refused with
    /// `Unsupported` (never a success), like the unbacked session and audit methods above.
    mod phase5_fakes {
        use serde_json::{Map, Value};
        use time::OffsetDateTime;

        use super::Fake;
        use crate::model::{
            AttributeDefinition, ClientSource, InitialAccessToken, InitialAccessTokenId,
            NewInitialAccessToken, NewRole, NewWebhookEndpoint, Page, PageRequest, Role, RoleId,
            RoleUpdate, SecretHash, TenantId, User, UserId, WebhookDelivery, WebhookDeliveryId,
            WebhookEndpoint, WebhookEndpointId, WebhookEndpointUpdate, WebhookEvent, WebhookResult,
        };
        use crate::ports::{
            AttributeRepo, ClaimedWebhookDelivery, RegistrationRepo, RoleRepo, StorageError,
            WebhookRepo,
        };

        fn unsupported<T>(what: &'static str) -> Result<T, StorageError> {
            Err(StorageError::Unsupported(what))
        }

        #[async_trait::async_trait]
        impl RoleRepo for Fake {
            async fn create(&self, _t: TenantId, _role: &NewRole) -> Result<Role, StorageError> {
                unsupported("fake: roles")
            }
            async fn get(&self, _t: TenantId, _id: RoleId) -> Result<Option<Role>, StorageError> {
                unsupported("fake: roles")
            }
            async fn get_by_name(
                &self,
                _t: TenantId,
                _name: &str,
            ) -> Result<Option<Role>, StorageError> {
                unsupported("fake: roles")
            }
            async fn list(&self, _t: TenantId) -> Result<Vec<Role>, StorageError> {
                unsupported("fake: roles")
            }
            async fn update(
                &self,
                _t: TenantId,
                _id: RoleId,
                _update: &RoleUpdate,
                _now: OffsetDateTime,
            ) -> Result<Option<Role>, StorageError> {
                unsupported("fake: roles")
            }
            async fn delete(&self, _t: TenantId, _id: RoleId) -> Result<bool, StorageError> {
                unsupported("fake: roles")
            }
            async fn assign(
                &self,
                _t: TenantId,
                _role: RoleId,
                _user: UserId,
                _now: OffsetDateTime,
            ) -> Result<bool, StorageError> {
                unsupported("fake: roles")
            }
            async fn unassign(
                &self,
                _t: TenantId,
                _role: RoleId,
                _user: UserId,
            ) -> Result<bool, StorageError> {
                unsupported("fake: roles")
            }
            async fn roles_for_user(
                &self,
                _t: TenantId,
                _user: UserId,
            ) -> Result<Vec<Role>, StorageError> {
                unsupported("fake: roles")
            }
            async fn users_with_role(
                &self,
                _t: TenantId,
                _role: RoleId,
                _page: PageRequest,
            ) -> Result<Page<User>, StorageError> {
                unsupported("fake: roles")
            }
            async fn holders_of_permission(
                &self,
                _t: TenantId,
                _permission: &str,
            ) -> Result<u64, StorageError> {
                unsupported("fake: roles")
            }
        }

        #[async_trait::async_trait]
        impl AttributeRepo for Fake {
            async fn list(&self, _t: TenantId) -> Result<Vec<AttributeDefinition>, StorageError> {
                unsupported("fake: attributes")
            }
            async fn get(
                &self,
                _t: TenantId,
                _name: &str,
            ) -> Result<Option<AttributeDefinition>, StorageError> {
                unsupported("fake: attributes")
            }
            async fn upsert(
                &self,
                _t: TenantId,
                _definition: &AttributeDefinition,
                _now: OffsetDateTime,
            ) -> Result<AttributeDefinition, StorageError> {
                unsupported("fake: attributes")
            }
            async fn delete(&self, _t: TenantId, _name: &str) -> Result<bool, StorageError> {
                unsupported("fake: attributes")
            }
            async fn user_values(
                &self,
                _t: TenantId,
                _user: UserId,
            ) -> Result<Option<Map<String, Value>>, StorageError> {
                unsupported("fake: attributes")
            }
            async fn set_user_values(
                &self,
                _t: TenantId,
                _user: UserId,
                _values: &Map<String, Value>,
                _now: OffsetDateTime,
            ) -> Result<bool, StorageError> {
                unsupported("fake: attributes")
            }
        }

        #[async_trait::async_trait]
        impl WebhookRepo for Fake {
            async fn create_endpoint(
                &self,
                _t: TenantId,
                _endpoint: &NewWebhookEndpoint,
            ) -> Result<WebhookEndpoint, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn get_endpoint(
                &self,
                _t: TenantId,
                _id: WebhookEndpointId,
            ) -> Result<Option<WebhookEndpoint>, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn list_endpoints(
                &self,
                _t: TenantId,
            ) -> Result<Vec<WebhookEndpoint>, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn update_endpoint(
                &self,
                _t: TenantId,
                _id: WebhookEndpointId,
                _update: &WebhookEndpointUpdate,
                _now: OffsetDateTime,
            ) -> Result<Option<WebhookEndpoint>, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn rotate_secret(
                &self,
                _t: TenantId,
                _id: WebhookEndpointId,
                _new_secret_enc: &[u8],
                _previous_expires_at: OffsetDateTime,
                _now: OffsetDateTime,
            ) -> Result<bool, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn disable_endpoint(
                &self,
                _t: TenantId,
                _id: WebhookEndpointId,
                _reason: &str,
                _now: OffsetDateTime,
            ) -> Result<bool, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn delete_endpoint(
                &self,
                _t: TenantId,
                _id: WebhookEndpointId,
            ) -> Result<bool, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn claim_due(
                &self,
                _owner_lease_until: OffsetDateTime,
                _now: OffsetDateTime,
                _limit: u32,
            ) -> Result<Vec<ClaimedWebhookDelivery>, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn complete(
                &self,
                _id: WebhookDeliveryId,
                _result: &WebhookResult,
                _now: OffsetDateTime,
            ) -> Result<bool, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn deliveries(
                &self,
                _t: TenantId,
                _endpoint: WebhookEndpointId,
                _page: PageRequest,
            ) -> Result<Page<WebhookDelivery>, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn redeliver(
                &self,
                _t: TenantId,
                _id: WebhookDeliveryId,
                _now: OffsetDateTime,
            ) -> Result<Option<WebhookDelivery>, StorageError> {
                unsupported("fake: webhooks")
            }
            async fn enqueue_test(
                &self,
                _t: TenantId,
                _endpoint: WebhookEndpointId,
                _event: &WebhookEvent,
                _now: OffsetDateTime,
            ) -> Result<Option<WebhookDelivery>, StorageError> {
                unsupported("fake: webhooks")
            }
        }

        #[async_trait::async_trait]
        impl RegistrationRepo for Fake {
            async fn create_iat(
                &self,
                _t: TenantId,
                _token: &NewInitialAccessToken,
            ) -> Result<InitialAccessToken, StorageError> {
                unsupported("fake: registration")
            }
            async fn list_iats(
                &self,
                _t: TenantId,
            ) -> Result<Vec<InitialAccessToken>, StorageError> {
                unsupported("fake: registration")
            }
            async fn revoke_iat(
                &self,
                _t: TenantId,
                _id: InitialAccessTokenId,
                _now: OffsetDateTime,
            ) -> Result<bool, StorageError> {
                unsupported("fake: registration")
            }
            async fn consume_iat(
                &self,
                _t: TenantId,
                _token_hash: &SecretHash,
                _now: OffsetDateTime,
            ) -> Result<Option<InitialAccessToken>, StorageError> {
                unsupported("fake: registration")
            }
            async fn count_clients_by_source(
                &self,
                _t: TenantId,
                _source: ClientSource,
            ) -> Result<u64, StorageError> {
                unsupported("fake: registration")
            }
        }
    }

    /// Only sessions and audit are backed; the functions under test use nothing else.
    #[async_trait::async_trait]
    impl Storage for Fake {
        fn tenants(&self) -> &dyn TenantRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn users(&self) -> &dyn UserRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn clients(&self) -> &dyn ClientRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn keys(&self) -> &dyn KeyRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn sessions(&self) -> &dyn SessionRepo {
            self
        }
        fn flows(&self) -> &dyn FlowRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn grants(&self) -> &dyn GrantRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn setup(&self) -> &dyn SetupRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn outbox(&self) -> &dyn OutboxRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn audit(&self) -> &dyn AuditRepo {
            self
        }
        fn mail_settings(&self) -> &dyn MailSettingsRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn jobs(&self) -> &dyn JobRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn connections(&self) -> &dyn ConnectionRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn branding(&self) -> &dyn BrandingRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn logout(&self) -> &dyn LogoutRepo {
            unreachable!("session service tests use only sessions and audit")
        }
        fn roles(&self) -> &dyn RoleRepo {
            self
        }
        fn attributes(&self) -> &dyn AttributeRepo {
            self
        }
        fn webhooks(&self) -> &dyn WebhookRepo {
            self
        }
        fn registration(&self) -> &dyn RegistrationRepo {
            self
        }
        async fn purge_expired(&self, _now: OffsetDateTime) -> Result<u64, StorageError> {
            Err(StorageError::Unsupported("fake: purge"))
        }
    }

    const T0: OffsetDateTime = datetime!(2026-11-25 12:00 UTC);

    struct Harness {
        fake: Arc<Fake>,
        clock: Arc<FixedClock>,
        svc: SessionService,
        tenant: TenantId,
    }

    impl Harness {
        fn new() -> Self {
            let fake = Arc::new(Fake::default());
            let clock = Arc::new(FixedClock(Mutex::new(T0)));
            let svc = SessionService {
                storage: fake.clone(),
                clock: clock.clone(),
            };
            Self {
                fake,
                clock,
                svc,
                tenant: TenantId::new_v7(),
            }
        }

        fn advance(&self, d: Duration) {
            *self.clock.0.lock().unwrap() += d;
        }

        /// Adds an active session of `user` signed in at the current time; returns its id and
        /// cookie token.
        fn add(&self, user: UserId) -> (SessionId, String) {
            let now = self.clock.now();
            let token = random_token();
            let (expires_at, idle_expires_at) = session_expiry(now);
            let id = SessionId::new_v7();
            self.fake.sessions.lock().unwrap().push(BrowserSession {
                id,
                tenant_id: self.tenant,
                user_id: user,
                token_hash: SecretHash(secret_hash(&token)),
                auth_time: now,
                acr: String::new(),
                amr: vec!["pwd".into()],
                created_at: now,
                last_seen_at: now,
                expires_at,
                idle_expires_at,
                revoked_at: None,
                ip: Some("192.0.2.1".into()),
                user_agent: Some("UA".into()),
            });
            self.fake.families.lock().unwrap().push((id, false));
            (id, token)
        }

        fn revoked(&self, id: SessionId) -> bool {
            let s = self.fake.sessions.lock().unwrap();
            s.iter().find(|s| s.id == id).unwrap().revoked_at.is_some()
        }

        fn family_revoked(&self, id: SessionId) -> bool {
            let f = self.fake.families.lock().unwrap();
            f.iter().find(|f| f.0 == id).unwrap().1
        }

        fn events(&self) -> Vec<NewAuditEvent> {
            self.fake.events.lock().unwrap().clone()
        }
    }

    #[test]
    fn current_touches_at_most_once_a_minute() {
        let h = Harness::new();
        let (id, token) = h.add(UserId::new_v7());
        h.advance(Duration::seconds(30));
        let s = run(h.svc.current(h.tenant, Some(&token))).unwrap().unwrap();
        assert_eq!(s.id, id);
        assert!(h.fake.touches.lock().unwrap().is_empty(), "30 s: no write");
        assert_eq!(s.last_seen_at, T0);

        h.advance(Duration::seconds(31));
        let now = h.clock.now();
        let s = run(h.svc.current(h.tenant, Some(&token))).unwrap().unwrap();
        let touches = h.fake.touches.lock().unwrap().clone();
        assert_eq!(touches.len(), 1, "61 s: one write");
        assert_eq!(touches[0], (id, now, next_idle_expiry(now, s.expires_at)));
        assert_eq!(s.last_seen_at, now);
        assert_eq!(s.idle_expires_at, now + SESSION_IDLE_TIMEOUT);

        // Again within a minute of that write: nothing.
        h.advance(Duration::seconds(10));
        run(h.svc.current(h.tenant, Some(&token))).unwrap().unwrap();
        assert_eq!(h.fake.touches.lock().unwrap().len(), 1);
    }

    #[test]
    fn current_rejects_idle_absolute_revoked_and_missing() {
        let h = Harness::new();
        assert!(run(h.svc.current(h.tenant, None)).unwrap().is_none());
        assert!(run(h.svc.current(h.tenant, Some(""))).unwrap().is_none());
        let (_, token) = h.add(UserId::new_v7());
        h.advance(SESSION_IDLE_TIMEOUT + Duration::seconds(1));
        assert!(
            run(h.svc.current(h.tenant, Some(&token)))
                .unwrap()
                .is_none()
        );

        let (id, token) = h.add(UserId::new_v7());
        run(h.svc.revoke(h.tenant, id)).unwrap();
        assert!(
            run(h.svc.current(h.tenant, Some(&token)))
                .unwrap()
                .is_none()
        );

        // Used every hour: alive until the absolute limit, then gone.
        let (_, token) = h.add(UserId::new_v7());
        for _ in 0..(14 * 24 - 1) {
            h.advance(Duration::hours(1));
            assert!(
                run(h.svc.current(h.tenant, Some(&token)))
                    .unwrap()
                    .is_some()
            );
        }
        h.advance(Duration::hours(1));
        assert!(
            run(h.svc.current(h.tenant, Some(&token)))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn list_for_user_is_active_only_newest_first_with_current_marked() {
        let h = Harness::new();
        let user = UserId::new_v7();
        let (a, _) = h.add(user);
        let (b, _) = h.add(user);
        let (c, _) = h.add(user);
        h.add(UserId::new_v7());
        run(h.svc.revoke(h.tenant, c)).unwrap();
        let list = run(h.svc.list_for_user(h.tenant, user, Some(a))).unwrap();
        let ids: Vec<SessionId> = list.iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![b, a]);
        assert!(!list[0].current);
        assert!(list[1].current);
        assert_eq!(list[1].ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(list[1].user_agent.as_deref(), Some("UA"));
    }

    #[test]
    fn revoke_mine_refuses_other_users_and_inactive_sessions() {
        let h = Harness::new();
        let alice = UserId::new_v7();
        let bob = UserId::new_v7();
        let (bobs, _) = h.add(bob);
        let ctx = RequestContext::default();
        let err = run(h.svc.revoke_mine(h.tenant, alice, bobs, &ctx)).unwrap_err();
        assert!(matches!(err, CoreError::NotFound), "{err:?}");
        assert!(!h.revoked(bobs));
        assert!(!h.family_revoked(bobs));
        let unknown = run(h
            .svc
            .revoke_mine(h.tenant, alice, SessionId::new_v7(), &ctx));
        assert!(matches!(unknown, Err(CoreError::NotFound)));
        assert!(h.events().is_empty());

        // Own session: revoked with its families, audited; a second revoke is NotFound.
        let (mine, _) = h.add(alice);
        run(h.svc.revoke_mine(h.tenant, alice, mine, &ctx)).unwrap();
        assert!(h.revoked(mine));
        assert!(h.family_revoked(mine));
        let again = run(h.svc.revoke_mine(h.tenant, alice, mine, &ctx));
        assert!(matches!(again, Err(CoreError::NotFound)));
        let ev = h.events();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].action, AuditAction::SessionRevoked);
        assert_eq!(ev[0].actor, AuditActor::user(alice));
        assert_eq!(ev[0].target, Some(mine.to_string()));

        // Expired sessions cannot be revoked either.
        let (old, _) = h.add(alice);
        h.advance(SESSION_IDLE_TIMEOUT + Duration::seconds(1));
        let expired = run(h.svc.revoke_mine(h.tenant, alice, old, &ctx));
        assert!(matches!(expired, Err(CoreError::NotFound)));
    }

    #[test]
    fn revoke_others_keeps_the_current_session() {
        let h = Harness::new();
        let user = UserId::new_v7();
        let (current, _) = h.add(user);
        let (o1, _) = h.add(user);
        let (o2, _) = h.add(user);
        let (other_user, _) = h.add(UserId::new_v7());
        let n = run(h
            .svc
            .revoke_others(h.tenant, user, current, &RequestContext::default()))
        .unwrap();
        assert_eq!(n, 2);
        assert!(!h.revoked(current) && !h.family_revoked(current));
        assert!(h.revoked(o1) && h.family_revoked(o1));
        assert!(h.revoked(o2) && h.family_revoked(o2));
        assert!(!h.revoked(other_user));
        let ev = h.events();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].action, AuditAction::SessionsRevokedAll);
        assert_eq!(ev[0].actor, AuditActor::user(user));
        assert_eq!(ev[0].details, AuditDetails::count("sessions", 2));
    }

    #[test]
    fn admin_revoke_audits_with_the_admin_actor() {
        let h = Harness::new();
        let (id, _) = h.add(UserId::new_v7());
        let ctx = RequestContext::default();
        run(h.svc.admin_revoke(h.tenant, id, "admin-1", &ctx)).unwrap();
        assert!(h.revoked(id) && h.family_revoked(id));
        let ev = h.events();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].action, AuditAction::SessionRevoked);
        assert_eq!(ev[0].actor, AuditActor::admin("admin-1"));
        let again = run(h.svc.admin_revoke(h.tenant, id, "admin-1", &ctx));
        assert!(matches!(again, Err(CoreError::NotFound)));
        let unknown = run(h
            .svc
            .admin_revoke(h.tenant, SessionId::new_v7(), "admin-1", &ctx));
        assert!(matches!(unknown, Err(CoreError::NotFound)));
        assert_eq!(h.events().len(), 1);
    }

    #[test]
    fn admin_list_tenant_pages_with_admin_page_rules() {
        let h = Harness::new();
        let mut ids: Vec<SessionId> = (0..3).map(|_| h.add(UserId::new_v7()).0).collect();
        ids.sort();
        let first = run(h.svc.admin_list_tenant(
            h.tenant,
            PageRequest {
                after: None,
                limit: 2,
            },
        ))
        .unwrap();
        assert_eq!(
            first.items.iter().map(|s| s.id).collect::<Vec<_>>(),
            ids[..2]
        );
        assert!(first.items.iter().all(|s| !s.current));
        let rest = run(h.svc.admin_list_tenant(
            h.tenant,
            PageRequest {
                after: first.next_cursor,
                limit: 2,
            },
        ))
        .unwrap();
        assert_eq!(
            rest.items.iter().map(|s| s.id).collect::<Vec<_>>(),
            ids[2..]
        );
        assert!(rest.next_cursor.is_none());
        // limit 0 means the default page (50), not an empty page.
        let all = run(h.svc.admin_list_tenant(
            h.tenant,
            PageRequest {
                after: None,
                limit: 0,
            },
        ))
        .unwrap();
        assert_eq!(all.items.len(), 3);
    }
}
