//! Flow service: starts self-service flows and executes the effects planned by the pure flow
//! engine (`flow::engine`) through the ports.
//!
//! # Binding
//!
//! Every flow is bound to two independent random tokens: the flow cookie and the CSRF token
//! (hidden form field). The flow row stores only their SHA-256 hashes. Every submission must
//! present both; they are compared in constant time ([`check_binding`]). A mismatch is
//! [`CoreError::Forbidden`]. Flows expire after [`FLOW_LIFETIME`] (15 minutes); submitting to an
//! expired or unknown flow starts a fresh flow of the same kind that shows `flow.expired`
//! ([`FlowOutcome::Restarted`]).
//!
//! # Enumeration safety
//!
//! - Login: unknown users, blocked users and users without a password run
//!   `PasswordHasher::verify(None, …)` (the dummy hash) and produce the same failure as a wrong
//!   password ([`password_login_result`]).
//! - Recovery request: the response is `recovery.sent` whether or not an account exists; the
//!   request does the same lookup either way and issues a token only for an active user.
//!
//! `CoreError::Overloaded` from the hasher or breach checker renders the form with
//! `service.overloaded`; it is never a bypass.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{ct_eq, random_token, secret_hash};
use secrecy::{ExposeSecret as _, SecretString};
use time::{Duration, OffsetDateTime};

use super::session::{NewSessionCookie, SessionService};
use crate::error::CoreError;
use crate::flow::engine::{
    Effect, EmailKind, Failure, FlowEnv, FlowInput, FlowState, message_text, on_failure, transition,
};
use crate::flow::form::{FormDescription, FormMessage, MessageLevel};
use crate::model::{
    AuthRequestId, Flow, FlowId, FlowKind, NewEmail, NewFlow, NewPasswordCredential,
    NewSelfServiceToken, NewUser, OutboxId, SecretHash, SelfServiceKind, SessionId, StandardClaims,
    Tenant, User, UserId, UserStatus, seal_payload,
};
use crate::policy::PasswordPolicy;
use crate::ports::{BreachChecker, Clock, PasswordCheck, PasswordHasher, Storage, StorageError};

/// Lifetime of a self-service flow.
pub const FLOW_LIFETIME: Duration = Duration::minutes(15);
/// Lifetime of an email verification token.
pub const VERIFICATION_TOKEN_TTL: Duration = Duration::hours(24);
/// Lifetime of a recovery token.
pub const RECOVERY_TOKEN_TTL: Duration = Duration::hours(1);
/// How long an informational email (password changed) stays deliverable in the outbox.
pub const NOTICE_EMAIL_TTL: Duration = Duration::hours(24);

/// Per-request context: the resolved tenant and its URLs.
#[derive(Debug, Clone, Copy)]
pub struct FlowContext<'a> {
    pub tenant: &'a Tenant,
    pub issuer: &'a str,
    /// `issuer + "/ui"`: base of the self-service pages and of the emailed links.
    pub ui_base: &'a str,
}

/// A newly created flow. `cookie_token` goes into the flow cookie; the form carries the CSRF
/// token.
#[derive(Debug)]
pub struct StartedFlow {
    pub flow_id: FlowId,
    pub cookie_token: SecretString,
    pub form: FormDescription,
}

/// Result of a submission.
#[derive(Debug)]
pub enum FlowOutcome {
    /// Render the form again. HTTP 400 if it carries an error message, 200 otherwise.
    Render(FormDescription),
    /// The user signed in: set the session cookie and continue the authorization request (or go
    /// to the default page).
    SignedIn {
        cookie: NewSessionCookie,
        continue_to: Option<AuthRequestId>,
    },
    /// Show a message page. The flow is finished.
    Message { key: &'static str },
    /// Validated setup input. The caller completes setup with `BootstrapService`.
    SetupSubmitted {
        email: String,
        password: SecretString,
    },
    /// The flow had expired or did not exist: a fresh flow of the same kind was started (set its
    /// cookie) and its form shows `flow.expired`.
    Restarted(StartedFlow),
}

/// Why a submission does not match its flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// Missing or wrong flow cookie, or wrong CSRF token.
    Forbidden,
    /// The flow has expired.
    Expired,
}

/// Checks that a submission belongs to `flow`: unexpired, with the flow cookie and the CSRF
/// token whose hashes the flow stores. Both hashes are compared in constant time and both are
/// always compared.
pub fn check_binding(
    flow: &Flow,
    cookie_token: Option<&str>,
    csrf_token: &str,
    now: OffsetDateTime,
) -> Result<(), BindingError> {
    if flow.expires_at <= now {
        return Err(BindingError::Expired);
    }
    let Some(cookie) = cookie_token else {
        return Err(BindingError::Forbidden);
    };
    let cookie_ok = ct_eq(&secret_hash(cookie), flow.cookie_hash.as_bytes());
    let csrf_ok = ct_eq(&secret_hash(csrf_token), flow.csrf_hash.as_bytes());
    if cookie_ok & csrf_ok {
        Ok(())
    } else {
        Err(BindingError::Forbidden)
    }
}

/// Maps a password check to the login result. Every credential failure (no such user, blocked,
/// no password, wrong password) is the same [`Failure::InvalidCredentials`]. A `valid` check
/// without a stored password is never accepted.
pub fn password_login_result(
    user: Option<User>,
    had_password: bool,
    check: PasswordCheck,
    require_verified_email: bool,
) -> Result<User, Failure> {
    match user {
        Some(u) if had_password && check.valid && u.status == UserStatus::Active => {
            if require_verified_email && !u.email_verified {
                Err(Failure::EmailNotVerified)
            } else {
                Ok(u)
            }
        }
        _ => Err(Failure::InvalidCredentials),
    }
}

/// Binds an engine form to a flow: absolute action URL and the real CSRF token.
pub fn bind_form(
    mut form: FormDescription,
    cx: &FlowContext<'_>,
    flow_id: FlowId,
    csrf_token: &str,
) -> FormDescription {
    form.action = format!("{}/{}?flow={}", cx.ui_base, form.action, flow_id);
    form.csrf_token = csrf_token.to_owned();
    form
}

/// Executes self-service flows.
pub struct FlowService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub breach: Arc<dyn BreachChecker>,
    pub policy: PasswordPolicy,
    /// Seals outbox email payloads (verification and recovery links carry single-use tokens).
    pub kek: Arc<Kek>,
}

enum Step {
    Continue,
    Fail(Failure),
    Done(Box<FlowOutcome>),
}

impl FlowService {
    fn env(&self, cx: &FlowContext<'_>) -> FlowEnv {
        FlowEnv {
            registration: cx.tenant.settings.registration,
            require_verified_email: cx.tenant.settings.require_verified_email,
            policy: self.policy,
        }
    }

    fn sessions(&self) -> SessionService {
        SessionService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Starts a flow. For verification and recovery, `token` (from the emailed link) is placed
    /// in a hidden field unvalidated; it is only consumed when the form is submitted.
    pub async fn start(
        &self,
        cx: &FlowContext<'_>,
        kind: FlowKind,
        auth_request: Option<AuthRequestId>,
        token: Option<String>,
    ) -> Result<StartedFlow, CoreError> {
        let (state, form) = FlowState::initial(kind, token, &self.env(cx))?;
        self.create_flow(cx, &state, form, auth_request).await
    }

    async fn create_flow(
        &self,
        cx: &FlowContext<'_>,
        state: &FlowState,
        form: FormDescription,
        auth_request: Option<AuthRequestId>,
    ) -> Result<StartedFlow, CoreError> {
        let now = self.clock.now();
        let cookie = random_token();
        let csrf = random_token();
        let new = NewFlow {
            id: FlowId::new_v7(),
            kind: state.kind(),
            state: encode_state(state)?,
            csrf_hash: SecretHash(secret_hash(&csrf)),
            cookie_hash: SecretHash(secret_hash(&cookie)),
            auth_request_id: auth_request,
            created_at: now,
            expires_at: now + FLOW_LIFETIME,
        };
        self.storage.flows().create(cx.tenant.id, &new).await?;
        Ok(StartedFlow {
            flow_id: new.id,
            cookie_token: SecretString::from(cookie),
            form: bind_form(form, cx, new.id, &csrf),
        })
    }

    async fn restart(
        &self,
        cx: &FlowContext<'_>,
        kind: FlowKind,
        auth_request: Option<AuthRequestId>,
    ) -> Result<FlowOutcome, CoreError> {
        let (state, mut form) = FlowState::initial(kind, None, &self.env(cx))?;
        form.messages.insert(
            0,
            FormMessage {
                level: MessageLevel::Error,
                key: "flow.expired".to_owned(),
                text: message_text("flow.expired").to_owned(),
            },
        );
        let started = self.create_flow(cx, &state, form, auth_request).await?;
        Ok(FlowOutcome::Restarted(started))
    }

    /// Submits user input to a flow. `current_session` (the caller's existing session, if any)
    /// is revoked when the user signs in.
    pub async fn submit(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
        input: FlowInput,
        current_session: Option<SessionId>,
    ) -> Result<FlowOutcome, CoreError> {
        let now = self.clock.now();
        let tenant = cx.tenant.id;
        let Some(flow) = self.storage.flows().get(tenant, flow_id, now).await? else {
            return self.restart(cx, input.kind(), None).await;
        };
        match check_binding(&flow, cookie_token, csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => {
                return self.restart(cx, flow.kind, flow.auth_request_id).await;
            }
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden),
        }
        let state: FlowState = serde_json::from_str(&flow.state)
            .map_err(|e| CoreError::Internal(format!("corrupt flow state: {e}")))?;
        if state.kind() != flow.kind {
            return Err(CoreError::Internal("flow state kind mismatch".into()));
        }

        let env = self.env(cx);
        let (state, effects) = transition(state, input, &env);
        let mut queue: VecDeque<Effect> = effects.into();
        let mut subject: Option<User> = None;

        while let Some(effect) = queue.pop_front() {
            match effect {
                Effect::Render(form) => {
                    return self.render(cx, &flow, csrf_token, &state, form).await;
                }
                Effect::Message(key) => {
                    self.storage.flows().delete(tenant, flow.id).await?;
                    return Ok(FlowOutcome::Message { key });
                }
                effect => {
                    let step = self
                        .run(
                            cx,
                            &flow,
                            &effect,
                            &mut queue,
                            &mut subject,
                            current_session,
                            &env,
                        )
                        .await?;
                    match step {
                        Step::Continue => {}
                        Step::Done(outcome) => return Ok(*outcome),
                        Step::Fail(failure) => {
                            let mut pending = Vec::with_capacity(queue.len() + 1);
                            pending.push(effect);
                            pending.extend(queue.drain(..));
                            let (state, form) = on_failure(state, &pending, failure, &env);
                            return self.render(cx, &flow, csrf_token, &state, form).await;
                        }
                    }
                }
            }
        }
        Err(CoreError::Internal(
            "flow effects ended without a terminal effect".into(),
        ))
    }

    async fn render(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        csrf_token: &str,
        state: &FlowState,
        form: FormDescription,
    ) -> Result<FlowOutcome, CoreError> {
        let json = encode_state(state)?;
        if json != flow.state {
            self.storage
                .flows()
                .update_state(cx.tenant.id, flow.id, &json, self.clock.now())
                .await?;
        }
        Ok(FlowOutcome::Render(bind_form(
            form, cx, flow.id, csrf_token,
        )))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "effect runner threads the per-submission context"
    )]
    async fn run(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        effect: &Effect,
        queue: &mut VecDeque<Effect>,
        subject: &mut Option<User>,
        current_session: Option<SessionId>,
        env: &FlowEnv,
    ) -> Result<Step, CoreError> {
        let tenant = cx.tenant.id;
        let users = self.storage.users();
        match effect {
            Effect::VerifyPassword { email, password } => {
                let user = users.get_by_email(tenant, email).await?;
                // Blocked users and users without a password take the dummy-hash path.
                let phc = match &user {
                    Some(u) if u.status == UserStatus::Active => {
                        users.password(tenant, u.id).await?.map(|c| c.phc)
                    }
                    _ => None,
                };
                let check = match self
                    .hasher
                    .verify(phc.as_deref(), password.expose_secret())
                    .await
                {
                    Ok(c) => c,
                    Err(CoreError::Overloaded) => return Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => return Err(e),
                };
                match password_login_result(user, phc.is_some(), check, env.require_verified_email)
                {
                    Ok(u) => {
                        if check.needs_rehash {
                            self.rehash(tenant, u.id, password).await?;
                        }
                        *subject = Some(u);
                        Ok(Step::Continue)
                    }
                    Err(f) => Ok(Step::Fail(f)),
                }
            }
            Effect::CheckBreach { password } => {
                match self.breach.is_breached(password.expose_secret()).await {
                    Ok(true) => Ok(Step::Fail(Failure::Breached)),
                    Ok(false) => Ok(Step::Continue),
                    Err(CoreError::Overloaded) => Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => Err(e),
                }
            }
            Effect::CreateUser {
                email,
                name,
                password,
            } => {
                let phc = match self.hasher.hash(password.expose_secret()).await {
                    Ok(p) => p,
                    Err(CoreError::Overloaded) => return Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => return Err(e),
                };
                let now = self.clock.now();
                let new_user = NewUser {
                    id: UserId::new_v7(),
                    email: email.clone(),
                    email_verified: false,
                    username: None,
                    claims: StandardClaims {
                        name: name.clone(),
                        ..StandardClaims::default()
                    },
                    status: UserStatus::Active,
                    created_at: now,
                };
                let credential = NewPasswordCredential {
                    phc,
                    created_at: now,
                };
                // A verification email directly after CreateUser is stored in the same
                // transaction as the user.
                let verification = if matches!(
                    queue.front(),
                    Some(Effect::EnqueueEmail(EmailKind::Verification))
                ) {
                    queue.pop_front();
                    Some(self_service_email(
                        &self.kek,
                        cx,
                        SelfServiceKind::Verification,
                        new_user.id,
                        email,
                        now,
                    )?)
                } else {
                    None
                };
                let result = users
                    .create(
                        tenant,
                        &new_user,
                        Some(&credential),
                        verification.as_ref().map(|(t, _)| t),
                        verification.as_ref().map(|(_, e)| e),
                    )
                    .await;
                match result {
                    Ok(u) => {
                        *subject = Some(u);
                        Ok(Step::Continue)
                    }
                    Err(StorageError::Conflict(_)) => Ok(Step::Fail(Failure::EmailTaken)),
                    Err(e) => Err(e.into()),
                }
            }
            Effect::EnqueueEmail(kind) => Err(CoreError::Internal(format!(
                "EnqueueEmail({kind:?}) is only valid directly after CreateUser"
            ))),
            Effect::CheckSecondFactor => {
                // Fails closed until the second-factor step is executed (next commit).
                let Some(user) = subject.as_ref() else {
                    return Err(CoreError::Internal(
                        "CheckSecondFactor without an established user".into(),
                    ));
                };
                if users.totp(tenant, user.id).await?.is_some() {
                    return Err(CoreError::Internal(
                        "second-factor login is not executed yet".into(),
                    ));
                }
                Ok(Step::Continue)
            }
            Effect::StartPasskey
            | Effect::FinishPasskey { .. }
            | Effect::VerifyTotp { .. }
            | Effect::ConsumeRecoveryCode { .. } => Err(CoreError::Internal(
                "passkey and second-factor effects are not executed yet".into(),
            )),
            Effect::CreateSession(auth) => {
                let (acr, amr) = crate::flow::engine::session_acr_amr(*auth, false);
                let Some(user) = subject.take() else {
                    return Err(CoreError::Internal(
                        "CreateSession without an established user".into(),
                    ));
                };
                let cookie = self
                    .sessions()
                    .create(tenant, user.id, acr, &amr, current_session)
                    .await?;
                users
                    .record_login(tenant, user.id, self.clock.now())
                    .await?;
                self.storage.flows().delete(tenant, flow.id).await?;
                Ok(Step::Done(Box::new(FlowOutcome::SignedIn {
                    cookie,
                    continue_to: flow.auth_request_id,
                })))
            }
            Effect::IssueRecovery { email } => {
                // Same lookup whether or not the account exists; the caller always shows
                // `recovery.sent`.
                if let Some(user) = users.get_by_email(tenant, email).await?
                    && user.status == UserStatus::Active
                {
                    let (token, mail) = self_service_email(
                        &self.kek,
                        cx,
                        SelfServiceKind::Recovery,
                        user.id,
                        &user.email,
                        self.clock.now(),
                    )?;
                    users
                        .issue_self_service_token(tenant, &token, Some(&mail))
                        .await?;
                }
                Ok(Step::Continue)
            }
            Effect::CompleteVerification { token } => {
                let hash = SecretHash(secret_hash(token.expose_secret()));
                match users
                    .complete_verification(tenant, &hash, self.clock.now())
                    .await?
                {
                    Some(_) => Ok(Step::Continue),
                    None => Ok(Step::Fail(Failure::InvalidToken)),
                }
            }
            Effect::CompleteRecovery { token, password } => {
                let phc = match self.hasher.hash(password.expose_secret()).await {
                    Ok(p) => p,
                    Err(CoreError::Overloaded) => return Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => return Err(e),
                };
                let hash = SecretHash(secret_hash(token.expose_secret()));
                let now = self.clock.now();
                let Some(user) = users
                    .complete_recovery(tenant, &hash, &phc, now, None)
                    .await?
                else {
                    return Ok(Step::Fail(Failure::InvalidToken));
                };
                // The recipient is only known once the token is consumed, so the notice is
                // enqueued right after the recovery transaction.
                let notice = password_changed_email(&self.kek, cx, &user.email, now)?;
                self.storage.outbox().enqueue(tenant, &notice).await?;
                Ok(Step::Continue)
            }
            Effect::SubmitSetup { email, password } => {
                Ok(Step::Done(Box::new(FlowOutcome::SetupSubmitted {
                    email: email.clone(),
                    password: SecretString::from(password.expose_secret().to_owned()),
                })))
            }
            Effect::Render(_) | Effect::Message(_) => Err(CoreError::Internal(
                "terminal effect reached the effect runner".into(),
            )),
        }
    }

    /// Re-hashes a password with the current parameters after a successful login. Skipped
    /// (retried at the next login) when the hasher is overloaded.
    async fn rehash(
        &self,
        tenant: crate::model::TenantId,
        user: UserId,
        password: &SecretString,
    ) -> Result<(), CoreError> {
        match self.hasher.hash(password.expose_secret()).await {
            Ok(phc) => {
                self.storage
                    .users()
                    .set_password(tenant, user, &phc, self.clock.now())
                    .await?;
                Ok(())
            }
            Err(CoreError::Overloaded) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// A new self-service token for `user` and the email carrying its link. The payload is sealed
/// with the KEK because the link carries the token.
fn self_service_email(
    kek: &Kek,
    cx: &FlowContext<'_>,
    kind: SelfServiceKind,
    user: UserId,
    email: &str,
    now: OffsetDateTime,
) -> Result<(NewSelfServiceToken, NewEmail), CoreError> {
    let token = random_token();
    let (ttl, page, template, expires_in) = match kind {
        SelfServiceKind::Verification => (
            VERIFICATION_TOKEN_TTL,
            "verification",
            "verification",
            "24 hours",
        ),
        SelfServiceKind::Recovery => (RECOVERY_TOKEN_TTL, "recovery", "recovery", "1 hour"),
        SelfServiceKind::Invitation => (Duration::days(7), "recovery", "invitation", "7 days"),
    };
    let expires_at = now + ttl;
    let record = NewSelfServiceToken {
        token_hash: SecretHash(secret_hash(&token)),
        kind,
        user_id: user,
        email: email.to_owned(),
        created_at: now,
        expires_at,
    };
    let mut payload = BTreeMap::new();
    payload.insert("tenant_name".to_owned(), cx.tenant.display_name.clone());
    payload.insert("email".to_owned(), email.to_owned());
    payload.insert(
        "link".to_owned(),
        format!("{}/{}?token={}", cx.ui_base, page, token),
    );
    payload.insert("expires_in".to_owned(), expires_in.to_owned());
    let mail = NewEmail {
        id: OutboxId::new_v7(),
        to: email.to_owned(),
        template: template.to_owned(),
        payload: seal_payload(kek, cx.tenant.id, &payload)?,
        created_at: now,
        expires_at,
    };
    Ok((record, mail))
}

fn password_changed_email(
    kek: &Kek,
    cx: &FlowContext<'_>,
    to: &str,
    now: OffsetDateTime,
) -> Result<NewEmail, CoreError> {
    let mut payload = BTreeMap::new();
    payload.insert("tenant_name".to_owned(), cx.tenant.display_name.clone());
    payload.insert("email".to_owned(), to.to_owned());
    Ok(NewEmail {
        id: OutboxId::new_v7(),
        to: to.to_owned(),
        template: "password_changed".to_owned(),
        payload: seal_payload(kek, cx.tenant.id, &payload)?,
        created_at: now,
        expires_at: now + NOTICE_EMAIL_TTL,
    })
}

fn encode_state(state: &FlowState) -> Result<String, CoreError> {
    serde_json::to_string(state)
        .map_err(|e| CoreError::Internal(format!("flow state serialisation: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::engine::LoginState;
    use crate::model::{SEALED_PAYLOAD_KEY, TenantId, TenantSettings, open_payload};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-25 12:00 UTC);

    fn flow(cookie: &str, csrf: &str, expires_at: OffsetDateTime) -> Flow {
        Flow {
            id: FlowId::new_v7(),
            tenant_id: TenantId::new_v7(),
            kind: FlowKind::Login,
            state: "{}".into(),
            csrf_hash: SecretHash(secret_hash(csrf)),
            cookie_hash: SecretHash(secret_hash(cookie)),
            auth_request_id: None,
            created_at: NOW,
            expires_at,
        }
    }

    fn user(status: UserStatus, verified: bool) -> User {
        User {
            id: UserId::new_v7(),
            tenant_id: TenantId::new_v7(),
            email: "alice@example.com".into(),
            email_verified: verified,
            username: None,
            claims: StandardClaims::default(),
            status,
            created_at: NOW,
            updated_at: NOW,
            last_login_at: None,
        }
    }

    const INVALID: PasswordCheck = PasswordCheck {
        valid: false,
        needs_rehash: false,
    };
    const VALID: PasswordCheck = PasswordCheck {
        valid: true,
        needs_rehash: false,
    };

    #[test]
    fn binding_accepts_matching_tokens() {
        let f = flow("cookie", "csrf", NOW + FLOW_LIFETIME);
        assert_eq!(check_binding(&f, Some("cookie"), "csrf", NOW), Ok(()));
    }

    #[test]
    fn binding_rejects_missing_or_wrong_tokens() {
        let f = flow("cookie", "csrf", NOW + FLOW_LIFETIME);
        for (cookie, csrf) in [
            (None, "csrf"),
            (Some("other"), "csrf"),
            (Some("cookie"), "other"),
            (Some("cookie"), ""),
            (Some(""), "csrf"),
            // The tokens are not interchangeable.
            (Some("csrf"), "cookie"),
        ] {
            assert_eq!(
                check_binding(&f, cookie, csrf, NOW),
                Err(BindingError::Forbidden),
                "{cookie:?} {csrf:?}"
            );
        }
    }

    #[test]
    fn binding_rejects_expired_flow() {
        let f = flow("cookie", "csrf", NOW);
        assert_eq!(
            check_binding(&f, Some("cookie"), "csrf", NOW),
            Err(BindingError::Expired)
        );
        let f = flow("cookie", "csrf", NOW - Duration::seconds(1));
        assert_eq!(
            check_binding(&f, None, "x", NOW),
            Err(BindingError::Expired)
        );
    }

    #[test]
    fn login_failures_are_indistinguishable() {
        let env = FlowEnv::default();
        let cases = [
            password_login_result(None, false, INVALID, false),
            password_login_result(Some(user(UserStatus::Active, true)), true, INVALID, false),
            password_login_result(Some(user(UserStatus::Active, true)), false, INVALID, false),
            // A valid check never rescues a blocked user or a user without a password.
            password_login_result(Some(user(UserStatus::Blocked, true)), true, VALID, false),
            password_login_result(Some(user(UserStatus::Active, true)), false, VALID, false),
        ];
        let state = FlowState::Login(LoginState {
            identifier: Some("alice@example.com".into()),
            ..LoginState::default()
        });
        let mut forms = Vec::new();
        for r in cases {
            let failure = r.expect_err("must fail");
            assert_eq!(failure, Failure::InvalidCredentials);
            let (_, form) = on_failure(
                state.clone(),
                &[Effect::CreateSession(
                    crate::flow::engine::SessionAuth::Password,
                )],
                failure,
                &env,
            );
            forms.push(form);
        }
        assert!(forms.windows(2).all(|w| w[0] == w[1]));
        let keys: Vec<_> = forms[0].messages.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["login.invalid_credentials"]);
    }

    #[test]
    fn login_success_and_verified_email_requirement() {
        let u = user(UserStatus::Active, false);
        assert_eq!(
            password_login_result(Some(u.clone()), true, VALID, false).map(|x| x.id),
            Ok(u.id)
        );
        assert_eq!(
            password_login_result(Some(u), true, VALID, true).map(|x| x.id),
            Err(Failure::EmailNotVerified)
        );
    }

    #[test]
    fn bind_form_sets_action_and_csrf() {
        let tenant = Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: NOW,
        };
        let cx = FlowContext {
            tenant: &tenant,
            issuer: "https://id.example.test/t/acme",
            ui_base: "https://id.example.test/t/acme/ui",
        };
        let (_, form) = FlowState::initial(FlowKind::Login, None, &FlowEnv::default()).unwrap();
        let id = FlowId::new_v7();
        let bound = bind_form(form, &cx, id, "csrf-tok");
        assert_eq!(
            bound.action,
            format!("https://id.example.test/t/acme/ui/login?flow={id}")
        );
        assert_eq!(bound.csrf_token, "csrf-tok");
    }

    fn acme() -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: NOW,
        }
    }

    fn cx(tenant: &Tenant) -> FlowContext<'_> {
        FlowContext {
            tenant,
            issuer: "https://id.example.test/t/acme",
            ui_base: "https://id.example.test/t/acme/ui",
        }
    }

    #[test]
    fn self_service_emails_are_sealed() {
        let kek = Kek::generate();
        let tenant = acme();
        let cx = cx(&tenant);
        for (kind, page, template, expires_in) in [
            (
                SelfServiceKind::Verification,
                "verification",
                "verification",
                "24 hours",
            ),
            (SelfServiceKind::Recovery, "recovery", "recovery", "1 hour"),
        ] {
            let user = UserId::new_v7();
            let (record, mail) =
                self_service_email(&kek, &cx, kind, user, "alice@example.com", NOW).unwrap();
            assert_eq!(mail.template, template);
            assert_eq!(mail.payload.len(), 1, "{template}: one sealed entry");
            assert!(mail.payload.contains_key(SEALED_PAYLOAD_KEY));
            assert!(!mail.payload[SEALED_PAYLOAD_KEY].contains("token="));
            assert!(open_payload(&kek, TenantId::new_v7(), &mail.payload).is_err());
            let payload = open_payload(&kek, tenant.id, &mail.payload).unwrap();
            let token = payload["link"]
                .strip_prefix(&format!("https://id.example.test/t/acme/ui/{page}?token="))
                .expect("link format");
            assert_eq!(record.token_hash, SecretHash(secret_hash(token)));
            assert!(!mail.payload[SEALED_PAYLOAD_KEY].contains(token));
            assert_eq!(payload["email"], "alice@example.com");
            assert_eq!(payload["tenant_name"], "Acme");
            assert_eq!(payload["expires_in"], expires_in);
        }
    }

    #[test]
    fn password_changed_email_is_sealed() {
        let kek = Kek::generate();
        let tenant = acme();
        let mail = password_changed_email(&kek, &cx(&tenant), "alice@example.com", NOW).unwrap();
        assert_eq!(mail.template, "password_changed");
        assert_eq!(mail.payload.len(), 1);
        assert!(mail.payload.contains_key(SEALED_PAYLOAD_KEY));
        let payload = open_payload(&kek, tenant.id, &mail.payload).unwrap();
        assert_eq!(payload["email"], "alice@example.com");
        assert_eq!(payload["tenant_name"], "Acme");
    }
}
