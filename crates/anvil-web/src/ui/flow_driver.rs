//! The web-side orchestration of a self-service flow step, shared by every renderer.
//!
//! The flow engine (`anvil_core::service::flow::FlowService`) decides what a step means; this
//! module owns everything the web layer adds around it, once:
//!
//! - the flow binding ([`FlowBinding`]: the flow cookie plus the posted CSRF token for a
//!   browser, the flow token for a native app of the headless API) and the caller's current
//!   browser session (the session-switch and step-up input of a submission; a native app has
//!   none);
//! - the brute-force gate ([`guard_attempt`]) before an attempt, the server-side CAPTCHA check
//!   when the gate asks for one, and [`record_attempt`] after it ([`Throttle`] names the limiter
//!   keys of each kind of step);
//! - the lock decision after a failed attempt;
//! - the sign-in methods a form offers ([`login_methods`]).
//!
//! Every function returns typed values ([`DriveOutcome`], [`DriveRejection`], core results) and
//! never HTML: the page handlers in `ui::login`, `ui::registration`, `ui::recovery`,
//! `ui::verification`, `ui::email_code` and `ui::mfa` only encode them (templates, cookies, CSP,
//! `no-store`). A second renderer (the headless JSON API) calls the same functions, so
//! throttling, CAPTCHA and session handling exist once (CLAUDE.md: one implementation per
//! concern). In `ui`, this module is the only caller of [`guard_attempt`], [`record_attempt`],
//! the CAPTCHA verifier and the flow service's start and submission entry points.
//!
//! The order of a gated submission is fixed: binding fields present (checked by the caller) →
//! brute-force gate (a lock answers before the flow runs; a CAPTCHA demand is verified here,
//! before the password is looked at) → current session → flow service → record the attempt →
//! lock check. Unknown identifiers go through exactly the same steps as known ones, and nothing
//! sleeps.

use std::net::IpAddr;
use std::time::Duration;

use anvil_cache::limiter::{Decision, LimitKey};
use anvil_core::error::CoreError;
use anvil_core::flow::engine::FlowInput;
use anvil_core::flow::form::{FormDescription, FormMessage};
use anvil_core::flow::login::FlowBindingKind;
use anvil_core::flow::login::{
    IDENTIFY_FORM_ID, IdentifyInput, SSO_CHOICE_FORM_ID, UPSTREAM_LINK_FORM_ID,
};
use anvil_core::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditOutcome, AuthRequestId, BrowserSession,
    CaptchaProvider, CaptchaSettings, FlowId, FlowKind, RequestContext, TenantId, UserId,
};
use anvil_core::policy::return_to::ReturnTarget;
use anvil_core::ports::RelyingParty;
use anvil_core::service::audit::AuditService;
use anvil_core::service::flow::{
    AuthAttempt, EmailLinkOutcome, FlowContext, FlowOutcome, FlowProof, IdentifyOutcome, IdpStart,
    LoginStart, StartedFlow, SubmitResult, bind_form,
};
use axum_extra::extract::cookie::CookieJar;

use super::login::{current_browser_session, tenant_relying_party, ui_base};
use super::upstream::SignInChoices;
use crate::adapters::captcha::{CaptchaError, CaptchaVerifier, DEFAULT_TIMEOUT, open_secret};
use crate::layers::ratelimit::{attempt_keys, guard_attempt, record_attempt};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

// ---------------------------------------------------------------------------------------------
// Binding and outcome types
// ---------------------------------------------------------------------------------------------

/// How a submission proves it belongs to its flow. The flow service checks the proof against
/// the binding the flow was created with (`FlowProof`): a cookie-bound flow refuses a token
/// and a token-bound flow refuses a cookie, whatever the values.
pub(crate) enum FlowBinding<'a> {
    /// A browser: the flow cookie in `jar` (checked against the flow's stored hash by the flow
    /// service) plus the posted CSRF token. The session cookie in the same jar names the
    /// caller's current session.
    Cookie { jar: &'a CookieJar, csrf: &'a str },
    /// A native first-party app of the headless API: the flow token from the
    /// `Authorization: AnvilFlow` header. There is no browser, so no CSRF token and no current
    /// session (no session switch, no step-up). Passkey ceremonies and the emailed link are
    /// browser-only and refuse it.
    Token { token: &'a str },
}

impl FlowBinding<'_> {
    /// The CSRF token the flow service checks and forms are bound to (empty for a token).
    pub(crate) fn csrf(&self) -> &str {
        match self {
            Self::Cookie { csrf, .. } => csrf,
            Self::Token { .. } => "",
        }
    }

    /// The flow's binding secret as presented by the caller (the flow cookie's value or the flow
    /// token), if any.
    pub(crate) fn flow_token(&self, state: &AppState, tenant: &ResolvedTenant) -> Option<String> {
        match self {
            Self::Cookie { jar, .. } => jar
                .get(&state.cookies().flow_name(&tenant.tenant))
                .map(|c| c.value().to_owned()),
            Self::Token { token } => Some((*token).to_owned()),
        }
    }

    /// Whether this is the native token binding.
    pub(crate) fn is_token(&self) -> bool {
        matches!(self, Self::Token { .. })
    }

    /// The proof the flow service checks; `presented` is [`Self::flow_token`].
    fn proof<'p>(&'p self, presented: Option<&'p str>) -> FlowProof<'p> {
        match self {
            Self::Cookie { csrf, .. } => FlowProof::Cookie {
                cookie: presented,
                csrf,
            },
            Self::Token { token } => FlowProof::Token(token),
        }
    }

    /// The caller's active browser session, if any (step-up input, and the session a new
    /// sign-in switches away from). Always `None` for a native app.
    pub(crate) async fn current_session(
        &self,
        state: &AppState,
        tenant: &ResolvedTenant,
    ) -> Result<Option<BrowserSession>, CoreError> {
        match self {
            Self::Cookie { jar, .. } => current_browser_session(state, tenant, jar).await,
            Self::Token { .. } => Ok(None),
        }
    }
}

/// Why a step was refused without an outcome.
#[derive(Debug)]
pub(crate) enum DriveRejection {
    /// The submission is not bound to the flow (wrong or missing CSRF token or flow binding):
    /// the flow service answered `CoreError::Forbidden`.
    Binding,
    /// Any other error (expired or unknown flow as `InvalidRequest`, storage, internal).
    Failed(CoreError),
}

impl DriveRejection {
    /// The rejection of a flow service result: `Forbidden` is a binding failure.
    fn from_flow(e: CoreError) -> Self {
        match e {
            CoreError::Forbidden => Self::Binding,
            e => Self::Failed(e),
        }
    }
}

/// The typed result of a submission ([`submit`]). Renderers encode it; it carries no HTML.
#[derive(Debug)]
pub(crate) enum DriveOutcome {
    /// The flow ran. `attempt` is the authentication attempt it represented (already recorded
    /// with the limiter). `captcha` is set when the brute-force gate now asks for a CAPTCHA, so
    /// the next sign-in form must carry the widget.
    Flow {
        outcome: FlowOutcome,
        attempt: Option<AuthAttempt>,
        captcha: bool,
    },
    /// Locked by the brute-force gate, with a form to show again (with the lock message,
    /// `Retry-After`): before the flow ran (the tenant's initial sign-in form bound to the posted
    /// flow, the same whether or not the account exists) or after a failed attempt (the form
    /// the flow answered, with the attempt that was recorded).
    Locked {
        form: FormDescription,
        retry_after: Duration,
        attempt: Option<AuthAttempt>,
    },
    /// Locked before the flow ran on a step that has no form to show again (second factor,
    /// email code): a plain 429.
    Throttled { retry_after: Duration },
    /// The gate asked for a CAPTCHA and the submission had none, or the provider refused it
    /// (fail closed). The password was not looked at. `form` is the initial sign-in form bound to
    /// the posted flow, with the identifier echoed and the error message
    /// ([`CAPTCHA_REQUIRED`] or [`CAPTCHA_FAILED`]) as its only message.
    CaptchaRejected { form: FormDescription },
    /// Refused without an outcome.
    Rejected(DriveRejection),
}

/// The CAPTCHA widget responses a submission carried (one per provider field name).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CaptchaAnswer<'a> {
    /// `cf-turnstile-response`.
    pub(crate) turnstile: Option<&'a str>,
    /// `h-captcha-response`.
    pub(crate) hcaptcha: Option<&'a str>,
}

impl<'a> CaptchaAnswer<'a> {
    /// The response for `provider`, empty if absent.
    fn for_provider(self, provider: CaptchaProvider) -> &'a str {
        match provider {
            CaptchaProvider::Turnstile => self.turnstile,
            CaptchaProvider::Hcaptcha => self.hcaptcha,
        }
        .unwrap_or_default()
    }
}

/// The brute-force class of a submission: which limiter keys gate it and count its attempts.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Throttle<'a> {
    /// Not an authentication attempt (registration, recovery, verification).
    None,
    /// A password: keyed by (identifier, client IP) and by identifier, with the CAPTCHA tier
    /// when the tenant has a CAPTCHA. A lock shows the sign-in form again.
    Password {
        identifier: &'a str,
        ip: IpAddr,
        captcha: CaptchaAnswer<'a>,
    },
    /// A passkey assertion at sign-in: keyed by client IP (a passkey names no identifier before
    /// it is verified). A lock shows the sign-in form again.
    Passkey { ip: IpAddr },
    /// A TOTP or recovery code: keyed by the step's user (from the second-factor token). The
    /// attempt is counted for the user the flow reports.
    SecondFactor { user: UserId },
    /// A sign-in email request: keyed by (address, client IP) and by address when the address
    /// is known to the caller (`ident`, see `ui::email_code`). Every send counts as a failure.
    EmailCodeSend { ident: Option<[u8; 32]>, ip: IpAddr },
    /// An emailed code: keyed by the code's rate-limit subject.
    EmailCode { subject: UserId },
}

/// What answers a lock found before the flow runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenyAnswer {
    /// The tenant's initial sign-in form, bound to the posted flow, with this identifier echoed.
    SignInForm,
    /// A plain 429.
    Throttled,
}

/// The pre-attempt gate of a [`Throttle`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gate {
    strict: LimitKey,
    loose: LimitKey,
    /// The tenant has a CAPTCHA and the class uses the CAPTCHA tier (passwords only).
    captcha: bool,
    on_deny: DenyAnswer,
}

/// How an attempt is recorded with the limiter, and the keys to check for a lock afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Count {
    keys: Vec<LimitKey>,
    success: bool,
    /// Check the gate again after a failure (lock or CAPTCHA demand on the next form).
    regate: Option<Gate>,
}

/// The gate of a throttle class in `tenant` (`captcha_available`: the tenant has a CAPTCHA).
/// `None` when nothing gates the submission.
fn gate(throttle: &Throttle<'_>, tenant: TenantId, captcha_available: bool) -> Option<Gate> {
    let gate = |strict: LimitKey, loose: LimitKey, captcha: bool, on_deny| Gate {
        strict,
        loose,
        captcha,
        on_deny,
    };
    match *throttle {
        Throttle::None => None,
        Throttle::Password { identifier, ip, .. } => {
            let (strict, loose) = attempt_keys(tenant, identifier, ip);
            Some(gate(
                strict,
                loose,
                captcha_available,
                DenyAnswer::SignInForm,
            ))
        }
        Throttle::Passkey { ip } => {
            let key = LimitKey::Ip(ip);
            Some(gate(key.clone(), key, false, DenyAnswer::SignInForm))
        }
        Throttle::SecondFactor { user } => {
            let key = LimitKey::User { tenant, user };
            Some(gate(key.clone(), key, false, DenyAnswer::Throttled))
        }
        Throttle::EmailCodeSend { ident, ip } => ident.map(|ident| {
            gate(
                LimitKey::IdentIp { tenant, ident, ip },
                LimitKey::Identifier { tenant, ident },
                false,
                DenyAnswer::Throttled,
            )
        }),
        Throttle::EmailCode { subject } => {
            let key = LimitKey::User {
                tenant,
                user: subject,
            };
            Some(gate(key.clone(), key, false, DenyAnswer::Throttled))
        }
    }
}

/// How `attempt` counts for a submission of class `throttle` gated by `gate`. `None` when the
/// attempt does not belong to the class (nothing is recorded).
fn count(
    throttle: &Throttle<'_>,
    tenant: TenantId,
    gate: &Gate,
    attempt: &AuthAttempt,
) -> Option<Count> {
    let pair = || vec![gate.strict.clone(), gate.loose.clone()];
    let single = || vec![gate.strict.clone()];
    let failed = |keys: Vec<LimitKey>| Count {
        keys,
        success: false,
        regate: Some(gate.clone()),
    };
    let succeeded = |keys: Vec<LimitKey>| Count {
        keys,
        success: true,
        regate: None,
    };
    match (throttle, attempt) {
        (Throttle::Password { .. }, AuthAttempt::PasswordFailed { .. }) => Some(failed(pair())),
        (Throttle::Password { .. }, AuthAttempt::PasswordSucceeded { .. }) => {
            Some(succeeded(pair()))
        }
        (Throttle::Passkey { .. }, AuthAttempt::PasskeyFailed) => Some(failed(single())),
        (Throttle::Passkey { .. }, AuthAttempt::PasskeySucceeded { .. }) => {
            Some(succeeded(single()))
        }
        // Counted for the user the flow reports (the flow state, not the token, is the truth).
        (Throttle::SecondFactor { .. }, AuthAttempt::SecondFactorFailed { user }) => {
            let key = LimitKey::User {
                tenant,
                user: *user,
            };
            Some(Count {
                keys: vec![key.clone()],
                success: false,
                regate: Some(Gate {
                    strict: key.clone(),
                    loose: key,
                    ..gate.clone()
                }),
            })
        }
        (Throttle::SecondFactor { .. }, AuthAttempt::SecondFactorSucceeded { user }) => {
            Some(succeeded(vec![LimitKey::User {
                tenant,
                user: *user,
            }]))
        }
        // A send never "succeeds" for the limiter, and the form after it is never locked.
        (Throttle::EmailCodeSend { .. }, AuthAttempt::EmailCodeSent { .. }) => Some(Count {
            keys: pair(),
            success: false,
            regate: None,
        }),
        (Throttle::EmailCode { .. }, AuthAttempt::EmailCodeFailed { .. }) => Some(failed(single())),
        (Throttle::EmailCode { .. }, AuthAttempt::EmailCodeSucceeded { .. }) => {
            Some(succeeded(single()))
        }
        _ => None,
    }
}

/// The outcome after an attempt was recorded and the gate checked again: a lock with a form to
/// show turns into [`DriveOutcome::Locked`]; a CAPTCHA demand marks the next form.
fn after_regate(
    decision: Option<Decision>,
    outcome: FlowOutcome,
    attempt: Option<AuthAttempt>,
    captcha_available: bool,
) -> DriveOutcome {
    match (decision, outcome) {
        (Some(Decision::Deny { retry_after }), FlowOutcome::Render(form)) => DriveOutcome::Locked {
            form,
            retry_after,
            attempt,
        },
        (decision, outcome) => DriveOutcome::Flow {
            outcome,
            attempt,
            captcha: captcha_available && matches!(decision, Some(Decision::RequireCaptcha)),
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Flow context
// ---------------------------------------------------------------------------------------------

/// The owned parts of a [`FlowContext`] for a tenant.
struct Cx {
    base: String,
    rp: Result<RelyingParty, CoreError>,
}

impl Cx {
    fn new(tenant: &ResolvedTenant) -> Self {
        Self {
            base: ui_base(tenant),
            rp: tenant_relying_party(tenant),
        }
    }

    /// Without a WebAuthn relying party: for forms built without running a passkey step.
    fn without_rp(tenant: &ResolvedTenant) -> Self {
        Self {
            base: ui_base(tenant),
            rp: Err(CoreError::Internal("not used".into())),
        }
    }

    fn flow<'a>(&'a self, tenant: &'a ResolvedTenant, ctx: &'a RequestContext) -> FlowContext<'a> {
        FlowContext {
            tenant: &tenant.tenant,
            issuer: &tenant.issuer,
            ui_base: &self.base,
            rp: &self.rp,
            ctx,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------------------------

/// Starts a flow of `kind` (`request`: the authorization request it continues; `token`: an
/// emailed self-service token). Starting records nothing (no session, no audit event), so no
/// request context.
pub(crate) async fn start(
    state: &AppState,
    tenant: &ResolvedTenant,
    kind: FlowKind,
    request: Option<AuthRequestId>,
    token: Option<String>,
) -> Result<StartedFlow, CoreError> {
    let cx = Cx::new(tenant);
    let ctx = RequestContext::default();
    state
        .ui_flow_service()
        .start(&cx.flow(tenant, &ctx), kind, request, token)
        .await
}

/// Starts a sign-in (`FlowService::start_login`): the step-up of `current` when the request
/// asks for it, the email-first or combined form, or a direct start at an org IdP.
pub(crate) async fn start_login(
    state: &AppState,
    tenant: &ResolvedTenant,
    request: Option<AuthRequestId>,
    current: Option<&BrowserSession>,
    return_target: Option<ReturnTarget>,
) -> Result<LoginStart, CoreError> {
    let cx = Cx::new(tenant);
    let ctx = RequestContext::default();
    state
        .ui_flow_service()
        .start_login(&cx.flow(tenant, &ctx), request, current, return_target)
        .await
}

/// Starts a token-bound sign-in for a native first-party app (`FlowService::start_login_bound`
/// with [`FlowBindingKind::Token`]): the same decisions as [`start_login`] without a browser
/// session or return target. The started flow's `cookie_token` is its flow token.
pub(crate) async fn start_native_login(
    state: &AppState,
    tenant: &ResolvedTenant,
    request: AuthRequestId,
) -> Result<LoginStart, CoreError> {
    let cx = Cx::new(tenant);
    let ctx = RequestContext::default();
    state
        .ui_flow_service()
        .start_login_bound(
            &cx.flow(tenant, &ctx),
            Some(request),
            None,
            None,
            FlowBindingKind::Token,
        )
        .await
}

/// The form a new sign-in of this tenant starts with (`FlowService::initial_login_form`: the
/// email-first form in a tenant with a routable domain, the combined form otherwise), bound to
/// `flow` and the submitted CSRF token, with `identifier` echoed. Used when the gate answers
/// before the flow runs, so the response is the same whether or not the account exists; the
/// web layer never decides email-first itself.
async fn posted_login_form(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    csrf: &str,
    identifier: &str,
) -> Result<FormDescription, CoreError> {
    let cx = Cx::without_rp(tenant);
    let ctx = RequestContext::default();
    let cx = cx.flow(tenant, &ctx);
    let form = state.ui_flow_service().initial_login_form(&cx).await?;
    let mut form = bind_form(form, &cx, flow, csrf);
    let echoed = identifier.trim();
    if let Some(field) = form.fields.iter_mut().find(|f| f.name == "identifier")
        && !echoed.is_empty()
    {
        field.value = Some(echoed.to_owned());
    }
    Ok(form)
}

// ---------------------------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------------------------

/// Runs a bound submission of `input` to `flow` behind the gate of `throttle` (module docs for
/// the order of checks), records the attempt and decides a lock.
pub(crate) async fn submit(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    flow: FlowId,
    binding: FlowBinding<'_>,
    throttle: Throttle<'_>,
    input: FlowInput,
) -> DriveOutcome {
    let tenant_id = tenant.tenant.id;
    let captcha = tenant.tenant.settings.captcha.as_ref();
    let gate = gate(&throttle, tenant_id, captcha.is_some());

    if let Some(gate) = &gate {
        match guard_attempt(state, &gate.strict, &gate.loose, gate.captcha).await {
            Decision::Deny { retry_after } => {
                return match gate.on_deny {
                    DenyAnswer::Throttled => DriveOutcome::Throttled { retry_after },
                    DenyAnswer::SignInForm => {
                        let identifier = match throttle {
                            Throttle::Password { identifier, .. } => identifier,
                            _ => "",
                        };
                        match posted_login_form(state, tenant, flow, binding.csrf(), identifier)
                            .await
                        {
                            Ok(form) => DriveOutcome::Locked {
                                form,
                                retry_after,
                                attempt: None,
                            },
                            Err(e) => DriveOutcome::Rejected(DriveRejection::Failed(e)),
                        }
                    }
                };
            }
            Decision::RequireCaptcha => {
                if let (
                    Some(settings),
                    Throttle::Password {
                        identifier,
                        ip,
                        captcha: answer,
                    },
                ) = (captcha, throttle)
                    && gate.captcha
                    && let Err(key) = verify_captcha(state, tenant, ctx, settings, answer, ip).await
                {
                    return match posted_login_form(state, tenant, flow, binding.csrf(), identifier)
                        .await
                    {
                        Ok(mut form) => {
                            form.messages = vec![FormMessage::error(key)];
                            DriveOutcome::CaptchaRejected { form }
                        }
                        Err(e) => DriveOutcome::Rejected(DriveRejection::Failed(e)),
                    };
                }
            }
            Decision::Allow => {}
        }
    }

    let result = match run_submission(state, tenant, ctx, flow, &binding, input).await {
        Ok(r) => r,
        Err(rejection) => return DriveOutcome::Rejected(rejection),
    };
    let SubmitResult { outcome, attempt } = result;
    let counted = match (&gate, &attempt) {
        (Some(gate), Some(attempt)) => count(&throttle, tenant_id, gate, attempt),
        _ => None,
    };
    let Some(counted) = counted else {
        return DriveOutcome::Flow {
            outcome,
            attempt,
            captcha: false,
        };
    };
    record_attempt(state, tenant_id, ctx, &counted.keys, counted.success).await;
    let (decision, captcha_available) = match &counted.regate {
        Some(g) => (
            Some(guard_attempt(state, &g.strict, &g.loose, g.captcha).await),
            g.captcha,
        ),
        None => (None, false),
    };
    after_regate(decision, outcome, attempt, captcha_available)
}

/// The flow service's submission with the binding and the current session.
async fn run_submission(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    flow: FlowId,
    binding: &FlowBinding<'_>,
    input: FlowInput,
) -> Result<SubmitResult, DriveRejection> {
    let token = binding.flow_token(state, tenant);
    let session = binding
        .current_session(state, tenant)
        .await
        .map_err(DriveRejection::Failed)?
        .map(|s| s.id);
    let cx = Cx::new(tenant);
    state
        .ui_flow_service()
        .submit_bound(
            &cx.flow(tenant, ctx),
            flow,
            binding.proof(token.as_deref()),
            input,
            session,
        )
        .await
        .map_err(DriveRejection::from_flow)
}

/// CAPTCHA message keys.
pub(crate) const CAPTCHA_REQUIRED: &str = "login.captcha_required";
pub(crate) const CAPTCHA_FAILED: &str = "login.captcha_failed";

/// Verifies the CAPTCHA response of a password submission server-side (fail closed). `Err`
/// carries the message key: no response submitted, or a response the provider did not accept
/// (or could not be checked). A submitted response that fails is audited as `captcha_failed`.
async fn verify_captcha(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    settings: &CaptchaSettings,
    answer: CaptchaAnswer<'_>,
    ip: IpAddr,
) -> Result<(), &'static str> {
    let token = answer.for_provider(settings.provider);
    if token.trim().is_empty() {
        return Err(CAPTCHA_REQUIRED);
    }
    let result = match (
        open_secret(state.kek(), tenant.tenant.id, settings),
        CaptchaVerifier::new(
            state.outbound_arc(),
            state.config().captcha_endpoints.clone(),
            DEFAULT_TIMEOUT,
        ),
    ) {
        (Ok(secret), Ok(verifier)) => verifier.verify(settings, &secret, token, Some(ip)).await,
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    let Err(e) = result else {
        return Ok(());
    };
    if let CaptchaError::Config(msg) = &e {
        tracing::error!(error = %msg, "CAPTCHA configuration error; rejecting");
    }
    let audit = AuditService {
        storage: state.storage_arc(),
        clock: state.clock_arc(),
    };
    if let Err(e) = audit
        .record(
            tenant.tenant.id,
            AuditActor::anonymous(ActorKind::User),
            AuditAction::CaptchaFailed,
            None,
            AuditOutcome::Failure,
            ctx,
            AuditDetails::reason(captcha_failure_reason(&e)),
        )
        .await
    {
        tracing::error!(error = %e, "recording the captcha_failed audit event failed");
    }
    Err(CAPTCHA_FAILED)
}

/// The audit reason of a refused CAPTCHA.
fn captcha_failure_reason(e: &CaptchaError) -> &'static str {
    match e {
        CaptchaError::MissingToken | CaptchaError::Rejected => "rejected",
        CaptchaError::Unavailable(_) => "unavailable",
        CaptchaError::Config(_) => "configuration",
    }
}

// ---------------------------------------------------------------------------------------------
// Identifier-first sign-in
// ---------------------------------------------------------------------------------------------

/// Result of [`identify`].
#[derive(Debug)]
pub(crate) enum Identified {
    /// Render (or restart) as for a submission. `captcha`: the outcome is the password step and
    /// the email's brute-force tier asks for a CAPTCHA, so the form carries the widget.
    Done {
        outcome: Box<FlowOutcome>,
        captcha: bool,
    },
    /// Start the sign-in at the org's IdP with the same flow binding.
    StartIdp(IdpStart),
}

/// The email-first page or the single-sign-on choice (`FlowService::identify`). No account is
/// looked up, so there is no brute-force gate: the answer depends on the email's domain only.
pub(crate) async fn identify(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    flow: FlowId,
    binding: &FlowBinding<'_>,
    input: IdentifyInput,
    ip: IpAddr,
) -> Result<Identified, DriveRejection> {
    let token = binding.flow_token(state, tenant);
    let cx = Cx::new(tenant);
    let result = state
        .ui_flow_service()
        .identify_bound(
            &cx.flow(tenant, ctx),
            flow,
            binding.proof(token.as_deref()),
            input,
        )
        .await
        .map_err(DriveRejection::from_flow)?;
    Ok(match result {
        IdentifyOutcome::Done(outcome) => {
            let captcha = match outcome.as_ref() {
                FlowOutcome::Render(form) => password_step_captcha(state, tenant, form, ip).await,
                _ => false,
            };
            Identified::Done { outcome, captcha }
        }
        IdentifyOutcome::StartIdp(idp) => Identified::StartIdp(idp),
    })
}

/// Whether `form` is the password step and the brute-force gate of its email asks for a CAPTCHA
/// (the same keys and decision as the password submission, read only: nothing is recorded).
/// The decision depends on the attempts made with the address, never on whether an account
/// exists.
async fn password_step_captcha(
    state: &AppState,
    tenant: &ResolvedTenant,
    form: &FormDescription,
    ip: IpAddr,
) -> bool {
    if tenant.tenant.settings.captcha.is_none() || form.id != "login" {
        return false;
    }
    let Some(identifier) = form
        .fields
        .iter()
        .find(|f| f.name == "identifier")
        .and_then(|f| f.value.as_deref())
    else {
        return false;
    };
    let (strict, loose) = attempt_keys(tenant.tenant.id, identifier, ip);
    matches!(
        guard_attempt(state, &strict, &loose, true).await,
        Decision::RequireCaptcha
    )
}

// ---------------------------------------------------------------------------------------------
// Passkeys and the email link
// ---------------------------------------------------------------------------------------------

/// Which passkey ceremony a step runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyStep {
    /// Discoverable sign-in (the assertion is submitted with [`submit`] and
    /// [`Throttle::Passkey`]).
    SignIn,
    /// Registration at the enrolment step (MFA policy `required`, no second factor yet).
    Enrolment,
    /// Assertion of one of the step user's passkeys at the second-factor step.
    SecondFactor,
}

/// WebAuthn options (JSON) for a passkey ceremony of the flow. Creating a challenge records
/// nothing, so no request context.
pub(crate) async fn passkey_options(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    binding: &FlowBinding<'_>,
    step: PasskeyStep,
) -> Result<String, DriveRejection> {
    if binding.is_token() {
        // Browser-only (WebAuthn needs the AnvilID origin); the flow service would refuse the
        // token as a cookie anyway.
        return Err(DriveRejection::Binding);
    }
    let token = binding.flow_token(state, tenant);
    let cx = Cx::new(tenant);
    let ctx = RequestContext::default();
    let cx = cx.flow(tenant, &ctx);
    let service = state.ui_flow_service();
    let (token, csrf) = (token.as_deref(), binding.csrf());
    match step {
        PasskeyStep::SignIn => service.passkey_options(&cx, flow, token, csrf).await,
        PasskeyStep::Enrolment => {
            service
                .passkey_enrolment_options(&cx, flow, token, csrf)
                .await
        }
        PasskeyStep::SecondFactor => {
            service
                .passkey_second_factor_options(&cx, flow, token, csrf)
                .await
        }
    }
    .map_err(DriveRejection::from_flow)
}

/// The in-flow passkey ceremonies that finish outside [`submit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InFlowPasskey {
    Enrolment,
    SecondFactor,
}

/// Finishes an in-flow passkey ceremony with the authenticator's `response` (JSON). Success
/// signs in or upgrades the step-up session like a passkey sign-in.
pub(crate) async fn passkey_finish(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    flow: FlowId,
    binding: &FlowBinding<'_>,
    step: InFlowPasskey,
    response: &str,
) -> Result<SubmitResult, DriveRejection> {
    if binding.is_token() {
        return Err(DriveRejection::Binding);
    }
    let token = binding.flow_token(state, tenant);
    let session = binding
        .current_session(state, tenant)
        .await
        .map_err(DriveRejection::Failed)?
        .map(|s| s.id);
    let cx = Cx::new(tenant);
    let cx = cx.flow(tenant, ctx);
    let service = state.ui_flow_service();
    let (token, csrf) = (token.as_deref(), binding.csrf());
    match step {
        InFlowPasskey::Enrolment => {
            service
                .passkey_enrolment_finish(&cx, flow, token, csrf, response, session)
                .await
        }
        InFlowPasskey::SecondFactor => {
            service
                .passkey_second_factor_finish(&cx, flow, token, csrf, response, session)
                .await
        }
    }
    .map_err(DriveRejection::from_flow)
}

/// Consumes a magic link (`token`) in the browser that started the sign-in.
pub(crate) async fn email_link(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    flow: FlowId,
    binding: &FlowBinding<'_>,
    link_token: &str,
) -> Result<EmailLinkOutcome, DriveRejection> {
    if binding.is_token() {
        return Err(DriveRejection::Binding);
    }
    let token = binding.flow_token(state, tenant);
    let session = binding
        .current_session(state, tenant)
        .await
        .map_err(DriveRejection::Failed)?
        .map(|s| s.id);
    let cx = Cx::new(tenant);
    state
        .ui_flow_service()
        .email_link(
            &cx.flow(tenant, ctx),
            flow,
            token.as_deref(),
            binding.csrf(),
            link_token,
            session,
        )
        .await
        .map_err(DriveRejection::from_flow)
}

// ---------------------------------------------------------------------------------------------
// Sign-in methods
// ---------------------------------------------------------------------------------------------

/// A way to sign in that a form offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoginMethod {
    /// The form has a password field.
    Password,
    /// Discoverable passkey sign-in (the issuer can be a WebAuthn relying party).
    Passkey,
    /// "Email me a sign-in code" (`email_otp`).
    EmailCode,
    /// The emailed sign-in link (`magic_link`); shares the request form with [`Self::EmailCode`].
    MagicLink,
    /// An enabled tenant-level upstream connection.
    Upstream { slug: String, name: String },
    /// "Continue with single sign-on" (the choice step of identifier-first sign-in).
    Sso,
}

/// The sign-in methods `form` offers in `tenant`, in display order. Pure: the upstream
/// connections are passed in (`ui::upstream::upstream_buttons` lists them for a bound sign-in
/// form). Only a form bound to a flow offers passkeys and email sign-in.
pub(super) fn login_methods(
    form: &FormDescription,
    tenant: &ResolvedTenant,
    upstream: &SignInChoices,
) -> Vec<LoginMethod> {
    let id = form.id.as_str();
    let bound = super::login::flow_of(form).is_some();
    let settings = &tenant.tenant.settings;
    let mut methods = Vec::new();
    if form.fields.iter().any(|f| f.name == "password") {
        methods.push(LoginMethod::Password);
    }
    // A link confirmation without any method has no fields: no passkey form either.
    let link_without_method = id == UPSTREAM_LINK_FORM_ID && form.fields.is_empty();
    if bound
        && matches!(id, "login" | UPSTREAM_LINK_FORM_ID | IDENTIFY_FORM_ID)
        && !link_without_method
        && tenant_relying_party(tenant).is_ok()
    {
        methods.push(LoginMethod::Passkey);
    }
    if bound && id == "login" {
        if settings.email_otp {
            methods.push(LoginMethod::EmailCode);
        }
        if settings.magic_link {
            methods.push(LoginMethod::MagicLink);
        }
    }
    // Link confirmation: the code only (the magic link may open in another browser).
    if bound && id == UPSTREAM_LINK_FORM_ID && settings.email_otp && upstream.link_email_code {
        methods.push(LoginMethod::EmailCode);
    }
    // The link confirmation lists only the candidate's own linked connections
    // (`ui::upstream::upstream_buttons`).
    if matches!(id, "login" | IDENTIFY_FORM_ID | UPSTREAM_LINK_FORM_ID) {
        methods.extend(upstream.buttons.iter().map(|b| LoginMethod::Upstream {
            slug: b.slug.clone(),
            name: b.name.clone(),
        }));
    }
    if id == SSO_CHOICE_FORM_ID {
        methods.push(LoginMethod::Sso);
    }
    methods
}

// ---------------------------------------------------------------------------------------------
// Second renderer support (the headless flow API, `crate::api_flows`)
// ---------------------------------------------------------------------------------------------
//
// The JSON handlers encode the same outcomes as the pages. These helpers expose what the page
// handlers read from sibling `ui` modules (binding tokens, the lock message, the sign-in
// methods with upstream connections), so the JSON handlers never re-implement them.

/// What a renderer shows about a flow besides its form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlowMeta {
    pub(crate) kind: FlowKind,
    pub(crate) expires_at: time::OffsetDateTime,
    /// The authorization request the flow continues.
    pub(crate) request: Option<AuthRequestId>,
}

/// The kind, expiry and authorization request of an unexpired `flow` (through the storage
/// port; `None` when unknown or expired). Reads only: no binding is checked, nothing is
/// returned that the caller did not already hold.
pub(crate) async fn flow_meta(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
) -> Result<Option<FlowMeta>, CoreError> {
    let found = state
        .storage()
        .flows()
        .get(tenant.tenant.id, flow, state.clock().now())
        .await?;
    Ok(found.map(|f| FlowMeta {
        kind: f.kind,
        expires_at: f.expires_at,
        request: f.auth_request_id,
    }))
}

/// The current form of a bound, unexpired engine flow (login, registration, recovery,
/// verification) without messages, for a renderer that shows a step again (`GET` of the
/// headless API). Read only: the flow state is not changed and nothing is recorded. One-time
/// display data (an enrolment secret, recovery codes) is only part of the answer that produced
/// it. `Ok(None)`: unknown, expired or not an engine flow. A wrong binding is
/// [`DriveRejection::Binding`].
pub(crate) async fn current_step(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    binding: &FlowBinding<'_>,
) -> Result<Option<(FormDescription, FlowMeta)>, DriveRejection> {
    use anvil_core::flow::engine::{FlowEnv, FlowState, current_form};
    use anvil_core::service::flow::{BindingError, email_code_enabled};

    let now = state.clock().now();
    let Some(stored) = state
        .storage()
        .flows()
        .get(tenant.tenant.id, flow, now)
        .await
        .map_err(|e| DriveRejection::Failed(e.into()))?
    else {
        return Ok(None);
    };
    if !matches!(
        stored.kind,
        FlowKind::Login | FlowKind::Registration | FlowKind::Recovery | FlowKind::Verification
    ) {
        return Ok(None);
    }
    let token = binding.flow_token(state, tenant);
    match binding.proof(token.as_deref()).check(&stored, now) {
        Ok(()) => {}
        Err(BindingError::Expired) => return Ok(None),
        Err(BindingError::Forbidden) => return Err(DriveRejection::Binding),
    }
    let flow_state: FlowState = serde_json::from_str(&stored.state).map_err(|e| {
        DriveRejection::Failed(CoreError::Internal(format!("corrupt flow state: {e}")))
    })?;
    if flow_state.kind() != stored.kind {
        return Err(DriveRejection::Failed(CoreError::Internal(
            "flow state kind mismatch".into(),
        )));
    }
    let settings = &tenant.tenant.settings;
    let env = FlowEnv {
        registration: settings.registration,
        require_verified_email: settings.require_verified_email,
        policy: state.config().password_policy,
        email_code: email_code_enabled(&tenant.tenant),
    };
    let form = current_form(&flow_state, Vec::new(), &env);
    let cx = Cx::without_rp(tenant);
    let ctx = RequestContext::default();
    let form = bind_form(form, &cx.flow(tenant, &ctx), stored.id, binding.csrf());
    Ok(Some((
        form,
        FlowMeta {
            kind: stored.kind,
            expires_at: stored.expires_at,
            request: stored.auth_request_id,
        },
    )))
}

/// The sign-in methods `form` offers, with the tenant's upstream connections (the same list the
/// sign-in page renders its choices from).
pub(crate) async fn offered_methods(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &crate::i18n::Locale,
    form: &FormDescription,
) -> Vec<LoginMethod> {
    let upstream = super::upstream::upstream_buttons(state, tenant, loc, form).await;
    login_methods(form, tenant, &upstream)
}

/// The caller's active browser session from the session cookie in `jar`.
pub(crate) async fn session_of(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
) -> Result<Option<BrowserSession>, CoreError> {
    current_browser_session(state, tenant, jar).await
}

/// The second-factor binding token for `user` in `flow` (`ui::mfa`); `None` (logged) when
/// sealing fails.
pub(crate) fn seal_factor_token(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    user: UserId,
) -> Option<String> {
    super::login::factor_token(state, tenant, flow, user)
}

/// The user a second-factor token names, if it opens for this tenant and flow (`ui::mfa`).
pub(crate) fn open_factor_token(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    token: &str,
) -> Option<UserId> {
    super::mfa::open_factor_token(state.kek(), tenant.tenant.id, flow, token)
}

/// The email step's limiter token (`ui::email_code`): the rate-limit subject and address hash.
pub(crate) fn seal_email_token(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    subject: UserId,
    ident: &[u8; 32],
) -> Option<String> {
    super::email_code::seal_email_token(state.kek(), tenant.tenant.id, flow, subject, ident)
}

/// The subject and address hash an email step token names (`ui::email_code`).
pub(crate) fn open_email_token(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    token: &str,
) -> Option<(UserId, [u8; 32])> {
    super::email_code::open_email_token(state.kek(), tenant.tenant.id, flow, token)
}

/// The limiter hash of a normalised address for sign-in email sends (`ui::email_code`).
pub(crate) fn email_send_ident(email: &str) -> [u8; 32] {
    super::email_code::send_ident(email)
}

/// The lock message ("try again in N seconds") of a locked form.
pub(crate) fn lock_message(retry_after: Duration) -> FormMessage {
    super::login::too_many_attempts(retry_after)
}

/// `Retry-After` in whole seconds (rounded up, at least 1).
pub(crate) fn retry_after_secs(retry_after: Duration) -> u64 {
    super::login::whole_seconds(retry_after)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use anvil_core::flow::form::{FieldKind, FormField};
    use anvil_core::model::{Tenant, TenantBase, TenantSettings};
    use time::OffsetDateTime;

    use super::super::upstream::UpstreamButton;
    use super::*;

    const FLOW: &str = "0190a6d4-0000-7000-8000-000000000001";

    fn tenant(issuer: &str, settings: TenantSettings) -> ResolvedTenant {
        ResolvedTenant {
            tenant: Tenant {
                id: TenantId::new_v7(),
                slug: "acme".into(),
                display_name: "Acme".into(),
                host: None,
                settings,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
            base: TenantBase::Path("acme".into()),
            issuer: issuer.into(),
        }
    }

    fn field(name: &str, kind: FieldKind) -> FormField {
        FormField {
            name: name.into(),
            kind,
            label_key: format!("field.{name}"),
            label: String::new(),
            value: None,
            required: true,
            autocomplete: None,
            messages: Vec::new(),
        }
    }

    fn form(id: &str, fields: Vec<FormField>) -> FormDescription {
        FormDescription {
            id: id.into(),
            action: format!("https://id.example.com/t/acme/ui/login?flow={FLOW}"),
            method: "post",
            fields,
            messages: Vec::new(),
            csrf_token: "csrf".into(),
        }
    }

    fn password_form() -> FormDescription {
        form(
            "login",
            vec![
                field("identifier", FieldKind::Email),
                field("password", FieldKind::Password),
            ],
        )
    }

    fn choices(buttons: Vec<UpstreamButton>) -> SignInChoices {
        SignInChoices {
            buttons,
            ..SignInChoices::default()
        }
    }

    fn button(slug: &str, name: &str) -> UpstreamButton {
        UpstreamButton {
            slug: slug.into(),
            name: name.into(),
            action: format!("https://id.example.com/t/acme/ui/login/upstream/{slug}?flow={FLOW}"),
        }
    }

    const ISSUER: &str = "https://id.example.com/t/acme";

    #[test]
    fn password_only_tenant_offers_password_and_passkey() {
        let t = tenant(ISSUER, TenantSettings::default());
        assert_eq!(
            login_methods(&password_form(), &t, &SignInChoices::default()),
            vec![LoginMethod::Password, LoginMethod::Passkey]
        );
    }

    #[test]
    fn an_issuer_that_cannot_be_a_relying_party_offers_no_passkey() {
        let t = tenant("http://127.0.0.1:8080", TenantSettings::default());
        assert_eq!(
            login_methods(&password_form(), &t, &SignInChoices::default()),
            vec![LoginMethod::Password]
        );
    }

    #[test]
    fn email_sign_in_is_offered_on_the_bound_sign_in_form_only() {
        let settings = TenantSettings {
            email_otp: true,
            magic_link: true,
            ..TenantSettings::default()
        };
        let t = tenant(ISSUER, settings);
        assert_eq!(
            login_methods(&password_form(), &t, &SignInChoices::default()),
            vec![
                LoginMethod::Password,
                LoginMethod::Passkey,
                LoginMethod::EmailCode,
                LoginMethod::MagicLink
            ]
        );
        let mut unbound = password_form();
        unbound.action = "https://id.example.com/t/acme/ui/login".into();
        assert_eq!(
            login_methods(&unbound, &t, &SignInChoices::default()),
            vec![LoginMethod::Password],
            "no flow, no passkey or email form"
        );
        let registration = form("registration", vec![field("email", FieldKind::Email)]);
        assert!(login_methods(&registration, &t, &SignInChoices::default()).is_empty());
    }

    #[test]
    fn upstream_buttons_become_methods_on_sign_in_forms() {
        let t = tenant(ISSUER, TenantSettings::default());
        let buttons = choices(vec![button("github", "GitHub"), button("google", "Google")]);
        assert_eq!(
            login_methods(&password_form(), &t, &buttons),
            vec![
                LoginMethod::Password,
                LoginMethod::Passkey,
                LoginMethod::Upstream {
                    slug: "github".into(),
                    name: "GitHub".into()
                },
                LoginMethod::Upstream {
                    slug: "google".into(),
                    name: "Google".into()
                },
            ]
        );
        let link = form(
            UPSTREAM_LINK_FORM_ID,
            vec![field("password", FieldKind::Password)],
        );
        assert_eq!(
            login_methods(&link, &t, &SignInChoices::default()),
            vec![LoginMethod::Password, LoginMethod::Passkey],
            "an unrevealed candidate: no upstream buttons"
        );
        let mine = choices(vec![button("github", "GitHub")]);
        assert_eq!(
            login_methods(&link, &t, &mine),
            vec![
                LoginMethod::Password,
                LoginMethod::Passkey,
                LoginMethod::Upstream {
                    slug: "github".into(),
                    name: "GitHub".into()
                },
            ],
            "the candidate's linked connections confirm the link"
        );
    }

    #[test]
    fn link_confirmation_offers_the_code_only_when_the_candidate_may_get_one() {
        let settings = TenantSettings {
            email_otp: true,
            magic_link: true,
            ..TenantSettings::default()
        };
        let t = tenant(ISSUER, settings);
        let link = form(
            UPSTREAM_LINK_FORM_ID,
            vec![field("password", FieldKind::Password)],
        );
        assert_eq!(
            login_methods(&link, &t, &SignInChoices::default()),
            vec![LoginMethod::Password, LoginMethod::Passkey]
        );
        let offered = SignInChoices {
            link_email_code: true,
            ..SignInChoices::default()
        };
        assert_eq!(
            login_methods(&link, &t, &offered),
            vec![
                LoginMethod::Password,
                LoginMethod::Passkey,
                LoginMethod::EmailCode
            ],
            "the code, never the magic link"
        );
        // No method at all: no fields, no passkey form.
        let empty = form(UPSTREAM_LINK_FORM_ID, Vec::new());
        assert!(login_methods(&empty, &t, &SignInChoices::default()).is_empty());
    }

    #[test]
    fn routed_domain_tenant_offers_email_first_then_sso_choice() {
        let settings = TenantSettings {
            email_otp: true,
            ..TenantSettings::default()
        };
        let t = tenant(ISSUER, settings);
        let identify = form(
            IDENTIFY_FORM_ID,
            vec![field("identifier", FieldKind::Email)],
        );
        let buttons = choices(vec![button("github", "GitHub")]);
        assert_eq!(
            login_methods(&identify, &t, &buttons),
            vec![
                LoginMethod::Passkey,
                LoginMethod::Upstream {
                    slug: "github".into(),
                    name: "GitHub".into()
                },
            ],
            "email-first page: no password field, no email code form"
        );
        let mut identifier = field("identifier", FieldKind::Hidden);
        identifier.value = Some("a@corp.example".into());
        let choice = form(SSO_CHOICE_FORM_ID, vec![identifier]);
        assert_eq!(login_methods(&choice, &t, &buttons), vec![LoginMethod::Sso]);
    }

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
    }

    #[test]
    fn gates_name_the_limiter_keys_of_each_class() {
        let t = TenantId::new_v7();
        let user = UserId::new_v7();
        assert_eq!(gate(&Throttle::None, t, true), None);

        let password = Throttle::Password {
            identifier: "a@example.com",
            ip: ip(),
            captcha: CaptchaAnswer::default(),
        };
        let g = gate(&password, t, true).expect("gated");
        let (strict, loose) = attempt_keys(t, "a@example.com", ip());
        assert_eq!((&g.strict, &g.loose), (&strict, &loose));
        assert!(
            g.captcha,
            "passwords use the CAPTCHA tier when the tenant has one"
        );
        assert_eq!(g.on_deny, DenyAnswer::SignInForm);
        assert!(!gate(&password, t, false).expect("gated").captcha);

        let g = gate(&Throttle::Passkey { ip: ip() }, t, true).expect("gated");
        assert_eq!(g.strict, LimitKey::Ip(ip()));
        assert!(!g.captcha, "only passwords use the CAPTCHA tier");
        assert_eq!(g.on_deny, DenyAnswer::SignInForm);

        let g = gate(&Throttle::SecondFactor { user }, t, true).expect("gated");
        assert_eq!(g.strict, LimitKey::User { tenant: t, user });
        assert_eq!(g.on_deny, DenyAnswer::Throttled);

        let g = gate(&Throttle::EmailCode { subject: user }, t, true).expect("gated");
        assert_eq!(g.loose, LimitKey::User { tenant: t, user });
        assert_eq!(g.on_deny, DenyAnswer::Throttled);

        let unknown = Throttle::EmailCodeSend {
            ident: None,
            ip: ip(),
        };
        assert_eq!(gate(&unknown, t, true), None, "no address, no gate");
        let send = Throttle::EmailCodeSend {
            ident: Some([7; 32]),
            ip: ip(),
        };
        let g = gate(&send, t, true).expect("gated");
        assert_eq!(
            (g.strict, g.loose),
            (
                LimitKey::IdentIp {
                    tenant: t,
                    ident: [7; 32],
                    ip: ip()
                },
                LimitKey::Identifier {
                    tenant: t,
                    ident: [7; 32]
                }
            )
        );
    }

    #[test]
    fn attempts_count_only_for_their_own_class() {
        let t = TenantId::new_v7();
        let user = UserId::new_v7();
        let password = Throttle::Password {
            identifier: "a@example.com",
            ip: ip(),
            captcha: CaptchaAnswer::default(),
        };
        let g = gate(&password, t, true).expect("gated");

        let failed = count(
            &password,
            t,
            &g,
            &AuthAttempt::PasswordFailed {
                ident_hash: [0; 32],
            },
        )
        .expect("counted");
        assert_eq!(failed.keys, vec![g.strict.clone(), g.loose.clone()]);
        assert!(!failed.success);
        assert_eq!(
            failed.regate.as_ref(),
            Some(&g),
            "a failure checks for a lock"
        );

        let ok = count(
            &password,
            t,
            &g,
            &AuthAttempt::PasswordSucceeded {
                ident_hash: [0; 32],
                user,
            },
        )
        .expect("counted");
        assert!(ok.success);
        assert_eq!(ok.regate, None);

        assert_eq!(
            count(&password, t, &g, &AuthAttempt::PasskeyFailed),
            None,
            "a passkey attempt does not count against a password class"
        );

        let throttle = Throttle::SecondFactor {
            user: UserId::new_v7(),
        };
        let g = gate(&throttle, t, false).expect("gated");
        let c =
            count(&throttle, t, &g, &AuthAttempt::SecondFactorFailed { user }).expect("counted");
        assert_eq!(
            c.keys,
            vec![LimitKey::User { tenant: t, user }],
            "counted for the user the flow reports"
        );
        assert_eq!(
            c.regate.map(|r| r.strict),
            Some(LimitKey::User { tenant: t, user })
        );

        let send = Throttle::EmailCodeSend {
            ident: Some([1; 32]),
            ip: ip(),
        };
        let g = gate(&send, t, false).expect("gated");
        let c =
            count(&send, t, &g, &AuthAttempt::EmailCodeSent { subject: user }).expect("counted");
        assert!(!c.success, "every send counts as a failure");
        assert_eq!(c.regate, None, "a send is never locked after the fact");
        assert_eq!(c.keys.len(), 2);

        let code = Throttle::EmailCode { subject: user };
        let g = gate(&code, t, false).expect("gated");
        assert!(
            count(
                &code,
                t,
                &g,
                &AuthAttempt::EmailCodeFailed { subject: user }
            )
            .expect("counted")
            .regate
            .is_some()
        );
        assert!(
            count(
                &code,
                t,
                &g,
                &AuthAttempt::EmailCodeSucceeded { subject: user }
            )
            .expect("counted")
            .success
        );
    }

    #[test]
    fn a_lock_after_a_failure_locks_only_a_rendered_form() {
        let retry_after = Duration::from_secs(30);
        let deny = Some(Decision::Deny { retry_after });
        match after_regate(deny, FlowOutcome::Render(password_form()), None, true) {
            DriveOutcome::Locked {
                form,
                retry_after: r,
                ..
            } => {
                assert_eq!(form.id, "login");
                assert_eq!(r, retry_after);
            }
            other => panic!("expected a lock, got {other:?}"),
        }
        let message = FlowOutcome::Message {
            key: "recovery.sent",
        };
        assert!(matches!(
            after_regate(deny, message, None, true),
            DriveOutcome::Flow { captcha: false, .. }
        ));
        assert!(matches!(
            after_regate(
                Some(Decision::RequireCaptcha),
                FlowOutcome::Render(password_form()),
                None,
                true
            ),
            DriveOutcome::Flow { captcha: true, .. }
        ));
        assert!(matches!(
            after_regate(
                Some(Decision::RequireCaptcha),
                FlowOutcome::Render(password_form()),
                None,
                false
            ),
            DriveOutcome::Flow { captcha: false, .. }
        ));
        assert!(matches!(
            after_regate(None, FlowOutcome::Render(password_form()), None, true),
            DriveOutcome::Flow { captcha: false, .. }
        ));
    }

    #[test]
    fn the_captcha_answer_is_read_for_the_configured_provider() {
        let answer = CaptchaAnswer {
            turnstile: Some("t"),
            hcaptcha: Some("h"),
        };
        assert_eq!(answer.for_provider(CaptchaProvider::Turnstile), "t");
        assert_eq!(answer.for_provider(CaptchaProvider::Hcaptcha), "h");
        assert_eq!(
            CaptchaAnswer::default().for_provider(CaptchaProvider::Turnstile),
            ""
        );
        assert_eq!(
            captcha_failure_reason(&CaptchaError::Unavailable("down".into())),
            "unavailable"
        );
    }

    #[test]
    fn a_forbidden_flow_answer_is_a_binding_rejection() {
        assert!(matches!(
            DriveRejection::from_flow(CoreError::Forbidden),
            DriveRejection::Binding
        ));
        assert!(matches!(
            DriveRejection::from_flow(CoreError::NotFound),
            DriveRejection::Failed(CoreError::NotFound)
        ));
    }

    #[test]
    fn token_binding_presents_only_the_token() {
        let native = FlowBinding::Token { token: "tok" };
        assert!(native.is_token());
        assert_eq!(native.csrf(), "");
        assert!(matches!(native.proof(Some("tok")), FlowProof::Token("tok")));
        let jar = CookieJar::new();
        let browser = FlowBinding::Cookie {
            jar: &jar,
            csrf: "csrf",
        };
        assert!(!browser.is_token());
        assert!(matches!(
            browser.proof(Some("cookie")),
            FlowProof::Cookie {
                cookie: Some("cookie"),
                csrf: "csrf"
            }
        ));
    }
}
