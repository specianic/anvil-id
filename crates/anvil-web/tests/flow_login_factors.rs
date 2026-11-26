//! FlowService second factors and passkey sign-in against real storage on the selected backend
//! (`ANVILID_TEST_DB`): TOTP replay protection, single-use recovery codes with their sealed
//! notice, single-use WebAuthn challenges, user-handle binding and clone detection. The WebAuthn
//! cryptography itself is covered by `passkey_adapter.rs`; here a scripted test double stands in
//! for the ceremonies so the service's checks can be driven directly.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anvil_core::error::CoreError;
use anvil_core::flow::engine::FlowInput;
use anvil_core::model::{
    ACR_MFA, AMR_HWK, AMR_MFA, AMR_OTP, AMR_PWD, AMR_SWK, AMR_USER, AuditAction, AuditQuery,
    CredentialId, NewPasskey, NewPasswordCredential, NewTotp, NewUser, RecoveryCodeHash,
    RequestContext, StandardClaims, TOTP_SEED_PURPOSE, Tenant, UserId, UserStatus, credential_aad,
    open_payload,
};
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::{
    AssertionIdentity, Challenge, PasskeyCeremonies, PasskeyError, PasskeyUser,
    PasswordHasher as _, RegisteredPasskey, RelyingParty, Storage, VerifiedAssertion,
};
use anvil_core::service::flow::{AuthAttempt, FlowContext, FlowOutcome, FlowService, SubmitResult};
use anvil_jose::Kek;
use anvil_jose::recovery_code::{normalize_recovery_code, recovery_code_hash};
use anvil_web::adapters::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use secrecy::ExposeSecret as _;
use time::OffsetDateTime;

use support::{TestApp, TestClock};

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
/// RFC 6238 Appendix B seed; at T=1111111109 the 6-digit code is 081804.
const SEED: &[u8] = b"12345678901234567890";
const T: i64 = 1_111_111_109;
const CODE: &str = "081804";
const RECOVERY: [&str; 2] = ["AAAA-BBBB-CCCC-DDDD", "EEEE-FFFF-GGGG-HHHH"];

/// Scripted WebAuthn ceremonies (test double). The "response JSON" is
/// `{"user": <uuid>, "cred": [bytes]}`; finishing succeeds iff the presented challenge state is
/// one this double issued, and returns the configured result.
#[derive(Default)]
struct ScriptedPasskeys {
    issued: Mutex<Vec<String>>,
    result: Mutex<Option<Result<VerifiedAssertion, PasskeyError>>>,
}

impl PasskeyCeremonies for ScriptedPasskeys {
    fn start_registration(
        &self,
        _: &RelyingParty,
        _: &PasskeyUser,
        _: &[Vec<u8>],
    ) -> Result<Challenge, CoreError> {
        Err(CoreError::Internal("not used".into()))
    }
    fn finish_registration(
        &self,
        _: &RelyingParty,
        _: &str,
        _: &str,
    ) -> Result<RegisteredPasskey, PasskeyError> {
        Err(PasskeyError::Invalid)
    }
    fn start_discoverable(&self, _: &RelyingParty) -> Result<Challenge, CoreError> {
        let state = format!("state-{}", uuid::Uuid::new_v4());
        self.issued.lock().unwrap().push(state.clone());
        Ok(Challenge {
            options_json: format!("{{\"publicKey\":{{\"challenge\":\"{state}\"}}}}"),
            state_json: state,
        })
    }
    fn identify(&self, response_json: &str) -> Result<AssertionIdentity, PasskeyError> {
        let v: serde_json::Value =
            serde_json::from_str(response_json).map_err(|_| PasskeyError::Invalid)?;
        let user = v["user"].as_str().ok_or(PasskeyError::Invalid)?;
        let cred: Vec<u8> =
            serde_json::from_value(v["cred"].clone()).map_err(|_| PasskeyError::Invalid)?;
        Ok(AssertionIdentity {
            user_id: UserId(uuid::Uuid::parse_str(user).map_err(|_| PasskeyError::Invalid)?),
            credential_id: cred,
        })
    }
    fn finish_discoverable(
        &self,
        _: &RelyingParty,
        _: &str,
        state_json: &str,
        _: &str,
    ) -> Result<VerifiedAssertion, PasskeyError> {
        if !self.issued.lock().unwrap().iter().any(|s| s == state_json) {
            return Err(PasskeyError::Invalid);
        }
        self.result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(Err(PasskeyError::Invalid))
    }
}

fn assertion(counter: u32, backup_eligible: bool) -> Result<VerifiedAssertion, PasskeyError> {
    Ok(VerifiedAssertion {
        counter,
        user_verified: true,
        backup_eligible,
        updated_passkey_json: Some(format!("{{\"counter\":{counter}}}")),
    })
}

struct Fixture {
    app: TestApp,
    storage: Arc<dyn Storage>,
    kek: Arc<Kek>,
    tenant: Tenant,
    service: FlowService,
    passkeys: Arc<ScriptedPasskeys>,
    rp: Result<RelyingParty, CoreError>,
    ctx: RequestContext,
    user: UserId,
}

impl Fixture {
    async fn new() -> Self {
        let app = TestApp::new().await;
        let storage = app.storage_arc();
        let kek = app.kek_arc();
        let tenant = app.default.as_ref().expect("installed").tenant.clone();
        let clock = Arc::new(TestClock::new(
            OffsetDateTime::from_unix_timestamp(T).expect("time"),
        ));
        let hasher = Arc::new(
            Argon2Pool::new(argon2::Params::new(256, 1, 1, None).expect("params"), 2)
                .expect("pool"),
        );
        let passkeys = Arc::new(ScriptedPasskeys::default());
        let service = FlowService {
            storage: Arc::clone(&storage),
            clock: clock.clone(),
            hasher: hasher.clone(),
            breach: breach_checker(BreachCheckMode::Off),
            policy: PasswordPolicy::default(),
            kek: Arc::clone(&kek),
            passkeys: passkeys.clone(),
            saml_enabled: false,
        };
        let now = OffsetDateTime::from_unix_timestamp(T).expect("time");
        let phc = hasher.hash(PASSWORD).await.expect("hash");
        let user = storage
            .users()
            .create(
                tenant.id,
                &NewUser {
                    id: UserId::new_v7(),
                    email: EMAIL.into(),
                    email_verified: true,
                    username: None,
                    claims: StandardClaims::default(),
                    status: UserStatus::Active,
                    created_at: now,
                },
                Some(&NewPasswordCredential {
                    phc,
                    created_at: now,
                }),
                None,
                None,
            )
            .await
            .expect("user")
            .id;
        let rp = Ok(RelyingParty {
            rp_id: "op.test".into(),
            origin: "https://op.test".into(),
            name: tenant.display_name.clone(),
        });
        let ctx = RequestContext::new(
            Some("198.51.100.23".parse().expect("ip")),
            Some("TestAgent/1.0"),
            None,
        );
        Self {
            app,
            storage,
            kek,
            tenant,
            service,
            passkeys,
            rp,
            ctx,
            user,
        }
    }

    fn cx(&self) -> FlowContext<'_> {
        FlowContext {
            tenant: &self.tenant,
            issuer: "https://op.test",
            ui_base: "https://op.test/ui",
            rp: &self.rp,
            ctx: &self.ctx,
        }
    }

    async fn enrol_totp(&self) {
        let id = CredentialId::new_v7();
        let secret_enc = self
            .kek
            .seal(TOTP_SEED_PURPOSE, &credential_aad(id), SEED)
            .expect("seal");
        let codes: Vec<RecoveryCodeHash> = RECOVERY
            .iter()
            .map(|c| {
                RecoveryCodeHash(recovery_code_hash(
                    &self.kek,
                    &normalize_recovery_code(c).expect("code"),
                ))
            })
            .collect();
        let now = OffsetDateTime::from_unix_timestamp(T).expect("time");
        self.storage
            .users()
            .create_totp(
                self.tenant.id,
                self.user,
                &NewTotp {
                    id,
                    secret_enc,
                    created_at: now,
                },
                &codes,
                now,
            )
            .await
            .expect("totp");
    }

    async fn start(&self) -> (anvil_core::model::FlowId, String, String) {
        let started = self
            .service
            .start(&self.cx(), anvil_core::model::FlowKind::Login, None, None)
            .await
            .expect("start");
        (
            started.flow_id,
            started.cookie_token.expose_secret().to_owned(),
            started.form.csrf_token,
        )
    }

    async fn submit(
        &self,
        flow: &(anvil_core::model::FlowId, String, String),
        input: FlowInput,
    ) -> SubmitResult {
        self.service
            .submit(&self.cx(), flow.0, Some(&flow.1), &flow.2, input, None)
            .await
            .expect("submit")
    }

    async fn password_step(&self) -> (anvil_core::model::FlowId, String, String) {
        let flow = self.start().await;
        let r = self
            .submit(
                &flow,
                FlowInput::Login {
                    identifier: EMAIL.into(),
                    password: PASSWORD.into(),
                },
            )
            .await;
        match &r.outcome {
            FlowOutcome::Render(f) => assert_eq!(f.id, "second-factor"),
            other => panic!("expected the second-factor form, got {other:?}"),
        }
        assert!(matches!(
            r.attempt,
            Some(AuthAttempt::PasswordSucceeded { user, .. }) if user == self.user
        ));
        flow
    }

    async fn audit_actions(&self) -> Vec<AuditAction> {
        self.storage
            .audit()
            .query(
                self.tenant.id,
                &AuditQuery {
                    limit: 100,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("audit")
            .items
            .into_iter()
            .map(|e| e.action)
            .collect()
    }

    async fn passkey(&self, credential_id: &[u8], counter: u32) {
        self.storage
            .users()
            .create_passkey(
                self.tenant.id,
                self.user,
                &NewPasskey {
                    id: CredentialId::new_v7(),
                    credential_id: credential_id.to_vec(),
                    passkey_json: "{}".into(),
                    counter,
                    backup_eligible: false,
                    label: "Key".into(),
                    created_at: OffsetDateTime::from_unix_timestamp(T).expect("time"),
                },
            )
            .await
            .expect("passkey");
    }
}

fn amr(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_owned()).collect()
}

fn signed_in(r: &SubmitResult) -> &anvil_core::model::BrowserSession {
    match &r.outcome {
        FlowOutcome::SignedIn { cookie, .. } => &cookie.session,
        other => panic!("expected sign-in, got {other:?}"),
    }
}

fn error_keys(r: &SubmitResult) -> Vec<String> {
    match &r.outcome {
        FlowOutcome::Render(f) => f.messages.iter().map(|m| m.key.clone()).collect(),
        other => panic!("expected a form, got {other:?}"),
    }
}

fn response(user: UserId, cred: &[u8]) -> String {
    serde_json::json!({"user": user.0.to_string(), "cred": cred}).to_string()
}

#[tokio::test]
async fn password_only_user_signs_in_with_pwd_amr_and_request_context() {
    let fx = Fixture::new().await;
    let flow = fx.start().await;
    let r = fx
        .submit(
            &flow,
            FlowInput::Login {
                identifier: EMAIL.into(),
                password: PASSWORD.into(),
            },
        )
        .await;
    let s = signed_in(&r);
    assert_eq!(s.amr, amr(&[AMR_PWD]));
    assert_eq!(s.ip.as_deref(), Some("198.51.100.23"));
    assert_eq!(s.user_agent.as_deref(), Some("TestAgent/1.0"));
    assert!(matches!(
        r.attempt,
        Some(AuthAttempt::PasswordSucceeded { .. })
    ));
    assert!(
        fx.audit_actions()
            .await
            .contains(&AuditAction::LoginSucceeded)
    );

    let flow = fx.start().await;
    let r = fx
        .submit(
            &flow,
            FlowInput::Login {
                identifier: EMAIL.into(),
                password: "wrong password!".into(),
            },
        )
        .await;
    assert_eq!(error_keys(&r), vec!["login.invalid_credentials"]);
    assert!(matches!(
        r.attempt,
        Some(AuthAttempt::PasswordFailed { .. })
    ));
    assert!(fx.audit_actions().await.contains(&AuditAction::LoginFailed));
}

#[tokio::test]
async fn totp_code_signs_in_once_and_a_replay_is_rejected() {
    let fx = Fixture::new().await;
    fx.enrol_totp().await;

    let flow = fx.password_step().await;
    let r = fx
        .submit(&flow, FlowInput::Totp { code: CODE.into() })
        .await;
    let s = signed_in(&r);
    assert_eq!(s.amr, amr(&[AMR_PWD, AMR_OTP, AMR_MFA]));
    assert_eq!(s.acr, ACR_MFA);
    assert!(matches!(
        r.attempt,
        Some(AuthAttempt::SecondFactorSucceeded { user }) if user == fx.user
    ));

    // The same code (same time step) again: rejected, the step stays.
    let flow = fx.password_step().await;
    let r = fx
        .submit(&flow, FlowInput::Totp { code: CODE.into() })
        .await;
    assert_eq!(error_keys(&r), vec!["login.second_factor_invalid"]);
    assert!(matches!(
        r.attempt,
        Some(AuthAttempt::SecondFactorFailed { user }) if user == fx.user
    ));
    // A wrong code as well.
    let r = fx
        .submit(
            &flow,
            FlowInput::Totp {
                code: "000000".into(),
            },
        )
        .await;
    assert_eq!(error_keys(&r), vec!["login.second_factor_invalid"]);
    assert!(
        fx.audit_actions()
            .await
            .contains(&AuditAction::SecondFactorFailed)
    );
}

#[tokio::test]
async fn second_factor_inputs_without_a_verified_password_are_refused() {
    let fx = Fixture::new().await;
    fx.enrol_totp().await;
    let flow = fx.start().await;
    let r = fx
        .submit(&flow, FlowInput::Totp { code: CODE.into() })
        .await;
    assert_eq!(error_keys(&r), vec!["flow.invalid_input"]);
    assert_eq!(r.attempt, None);
    let r = fx
        .submit(
            &flow,
            FlowInput::RecoveryCode {
                code: RECOVERY[0].into(),
            },
        )
        .await;
    assert_eq!(error_keys(&r), vec!["flow.invalid_input"]);
}

#[tokio::test]
async fn recovery_code_is_single_use_and_enqueues_a_sealed_notice() {
    let fx = Fixture::new().await;
    fx.enrol_totp().await;
    let flow = fx.password_step().await;
    let r = fx
        .submit(
            &flow,
            FlowInput::RecoveryCode {
                code: "aaaa bbbb cccc dddd".into(),
            },
        )
        .await;
    assert_eq!(signed_in(&r).amr, amr(&[AMR_PWD, AMR_OTP, AMR_MFA]));
    assert!(
        fx.audit_actions()
            .await
            .contains(&AuditAction::RecoveryCodeUsed)
    );

    let claimed = fx
        .storage
        .outbox()
        .claim_due(
            OffsetDateTime::from_unix_timestamp(T + 1).expect("time"),
            10,
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("claim");
    let notices: Vec<_> = claimed
        .iter()
        .filter(|e| e.template == "recovery_code_used")
        .collect();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].to, EMAIL);
    let payload: BTreeMap<String, String> =
        open_payload(fx.app.kek(), fx.tenant.id, &notices[0].payload).expect("sealed");
    assert_eq!(
        payload.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["remaining", "tenant_name"]
    );
    assert_eq!(payload["remaining"], "1");

    // The same code again fails and enqueues nothing.
    let flow = fx.password_step().await;
    let r = fx
        .submit(
            &flow,
            FlowInput::RecoveryCode {
                code: RECOVERY[0].into(),
            },
        )
        .await;
    assert_eq!(error_keys(&r), vec!["login.second_factor_invalid"]);
    let claimed = fx
        .storage
        .outbox()
        .claim_due(
            OffsetDateTime::from_unix_timestamp(T + 2).expect("time"),
            10,
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("claim");
    assert!(claimed.is_empty());
}

#[tokio::test]
async fn passkey_sign_in_is_mfa_and_skips_the_second_factor() {
    let fx = Fixture::new().await;
    fx.enrol_totp().await;
    fx.passkey(&[7, 7, 7], 0).await;
    *fx.passkeys.result.lock().unwrap() = Some(assertion(1, false));

    let flow = fx.start().await;
    let options = fx
        .service
        .passkey_options(&fx.cx(), flow.0, Some(&flow.1), &flow.2)
        .await
        .expect("options");
    assert!(options.contains("publicKey"));
    let r = fx
        .submit(
            &flow,
            FlowInput::PasskeyAssertion {
                response_json: response(fx.user, &[7, 7, 7]),
            },
        )
        .await;
    let s = signed_in(&r);
    assert_eq!(s.amr, amr(&[AMR_HWK, AMR_USER, AMR_MFA]));
    assert_eq!(s.acr, ACR_MFA);
    assert!(matches!(r.attempt, Some(AuthAttempt::PasskeySucceeded { user }) if user == fx.user));

    // A synced (backup-eligible) passkey is `swk`.
    *fx.passkeys.result.lock().unwrap() = Some(assertion(2, true));
    let flow = fx.start().await;
    fx.service
        .passkey_options(&fx.cx(), flow.0, Some(&flow.1), &flow.2)
        .await
        .expect("options");
    let r = fx
        .submit(
            &flow,
            FlowInput::PasskeyAssertion {
                response_json: response(fx.user, &[7, 7, 7]),
            },
        )
        .await;
    assert_eq!(signed_in(&r).amr, amr(&[AMR_SWK, AMR_USER, AMR_MFA]));
}

#[tokio::test]
async fn passkey_challenge_is_single_use() {
    let fx = Fixture::new().await;
    fx.passkey(&[1], 0).await;
    *fx.passkeys.result.lock().unwrap() = Some(assertion(0, false));

    // Without a challenge: the generic passkey failure.
    let flow = fx.start().await;
    let input = || FlowInput::PasskeyAssertion {
        response_json: response(fx.user, &[1]),
    };
    let r = fx.submit(&flow, input()).await;
    assert_eq!(error_keys(&r), vec!["login.passkey_failed"]);

    // A failed finish consumes the challenge: a retry with a valid response fails too.
    fx.service
        .passkey_options(&fx.cx(), flow.0, Some(&flow.1), &flow.2)
        .await
        .expect("options");
    let r = fx
        .submit(
            &flow,
            FlowInput::PasskeyAssertion {
                response_json: "garbage".into(),
            },
        )
        .await;
    assert_eq!(error_keys(&r), vec!["login.passkey_failed"]);
    assert_eq!(r.attempt, Some(AuthAttempt::PasskeyFailed));
    let r = fx.submit(&flow, input()).await;
    assert_eq!(error_keys(&r), vec!["login.passkey_failed"]);

    // Concurrent finishes with one challenge: exactly one signs in.
    fx.service
        .passkey_options(&fx.cx(), flow.0, Some(&flow.1), &flow.2)
        .await
        .expect("options");
    let (a, b) = tokio::join!(fx.submit(&flow, input()), fx.submit(&flow, input()));
    let wins = [&a, &b]
        .iter()
        .filter(|r| matches!(r.outcome, FlowOutcome::SignedIn { .. }))
        .count();
    assert_eq!(wins, 1);
}

#[tokio::test]
async fn passkey_of_another_user_or_tenant_is_rejected() {
    let fx = Fixture::new().await;
    fx.passkey(&[5, 5], 0).await;
    *fx.passkeys.result.lock().unwrap() = Some(assertion(1, false));
    for resp in [
        // Alice's credential with another user handle.
        response(UserId::new_v7(), &[5, 5]),
        // An unknown credential id.
        response(fx.user, &[6]),
    ] {
        let flow = fx.start().await;
        fx.service
            .passkey_options(&fx.cx(), flow.0, Some(&flow.1), &flow.2)
            .await
            .expect("options");
        let r = fx
            .submit(
                &flow,
                FlowInput::PasskeyAssertion {
                    response_json: resp,
                },
            )
            .await;
        assert_eq!(error_keys(&r), vec!["login.passkey_failed"]);
    }
}

#[tokio::test]
async fn possible_clone_or_stale_counter_fails_and_is_audited() {
    let fx = Fixture::new().await;
    fx.passkey(&[9], 10).await;
    for result in [Err(PasskeyError::PossibleClone), assertion(10, false)] {
        *fx.passkeys.result.lock().unwrap() = Some(result);
        let flow = fx.start().await;
        fx.service
            .passkey_options(&fx.cx(), flow.0, Some(&flow.1), &flow.2)
            .await
            .expect("options");
        let r = fx
            .submit(
                &flow,
                FlowInput::PasskeyAssertion {
                    response_json: response(fx.user, &[9]),
                },
            )
            .await;
        assert_eq!(error_keys(&r), vec!["login.passkey_failed"]);
    }
    let clones = fx
        .audit_actions()
        .await
        .into_iter()
        .filter(|a| *a == AuditAction::PasskeyCloneSuspected)
        .count();
    assert_eq!(clones, 2);
}

#[tokio::test]
async fn a_flow_of_another_service_posted_to_login_restarts_instead_of_failing() {
    use anvil_core::model::{FlowId, FlowKind, NewFlow, SecretHash};
    use anvil_jose::encoding::secret_hash;
    let fx = Fixture::new().await;
    let now = OffsetDateTime::from_unix_timestamp(T).expect("time");
    let id = FlowId::new_v7();
    fx.storage
        .flows()
        .create(
            fx.tenant.id,
            &NewFlow {
                id,
                kind: FlowKind::Settings,
                state: "{\"not\":\"an engine state\"}".into(),
                csrf_hash: SecretHash(secret_hash("csrf")),
                cookie_hash: SecretHash(secret_hash("cookie")),
                auth_request_id: None,
                created_at: now,
                expires_at: now + time::Duration::minutes(15),
            },
        )
        .await
        .expect("flow");
    let flow = (id, "cookie".to_owned(), "csrf".to_owned());
    let r = fx
        .submit(
            &flow,
            FlowInput::Login {
                identifier: EMAIL.into(),
                password: PASSWORD.into(),
            },
        )
        .await;
    match r.outcome {
        FlowOutcome::Restarted(started) => {
            assert_eq!(started.form.id, "login");
            assert_ne!(started.flow_id, id);
        }
        other => panic!("expected a restart, got {other:?}"),
    }
    assert_eq!(r.attempt, None);
    let err = fx
        .service
        .passkey_options(&fx.cx(), id, Some("cookie"), "csrf")
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidRequest(_)));
}
