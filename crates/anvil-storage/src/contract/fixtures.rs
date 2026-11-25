//! Record builders and seed helpers for the contract suite.
//!
//! Every builder populates all optional fields so round-trips exercise the nullable columns.
//! Timestamps come from [`now_ms`]; secret hashes are fake (UUID bytes) because this crate has no
//! crypto dependency and storage never interprets them.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anvil_core::model::{
    AccessTokenRecord, ActorKind, Address, ApplicationType, AuditAction, AuditActor, AuditDetails,
    AuditEvent, AuditEventId, AuditOutcome, AuthRequestId, AuthorizationCode, AuthorizationParams,
    ClaimsRequest, Client, ClientAuthMethod, ClientId, ClientType, ConsentId, ConsentMode,
    CredentialId, EmailKind, EmailTemplate, FlowId, FlowKind, GrantType, KeyState, NewAccessToken,
    NewAuditEvent, NewAuthorizationCode, NewAuthorizationRequest, NewBrowserSession, NewClient,
    NewConsent, NewEmail, NewFlow, NewPasskey, NewPasswordCredential, NewRefreshToken,
    NewSelfServiceToken, NewSetupToken, NewSigningKey, NewTenant, NewTokenFamily, NewTotp, NewUser,
    OutboxId, PasskeyCredential, RecoveryCodeHash, RecoveryNotice, RefreshToken, RegistrationMode,
    RequestContext, RequestedClaim, SecretHash, SelfServiceKind, SessionId, SigningKeyId,
    SmtpSettings, SmtpTls, StandardClaims, TenantId, TenantSettings, TokenFamily, TokenFamilyId,
    TokenFormat, User, UserId, UserStatus, truncate_to_ms,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::TestStorage;

/// The current time, truncated to milliseconds.
pub fn now_ms() -> OffsetDateTime {
    truncate_to_ms(OffsetDateTime::now_utc())
}

/// Outbox claim lease used by the tests.
pub const LEASE: StdDuration = StdDuration::from_secs(60);

/// A unique fake secret hash built from two UUIDv7 values.
pub fn unique_hash() -> SecretHash {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::now_v7().as_bytes());
    bytes[16..].copy_from_slice(Uuid::now_v7().as_bytes());
    SecretHash(bytes)
}

/// Alias kept from the Phase 1 suite.
pub fn unique_code_hash() -> SecretHash {
    unique_hash()
}

fn short() -> String {
    Uuid::now_v7().simple().to_string()
}

// ---------------------------------------------------------------------------------------------
// Tenants

/// A tenant with a unique slug and host and non-default settings.
pub fn new_tenant() -> NewTenant {
    let id = TenantId::new_v7();
    let tag = short();
    NewTenant {
        id,
        slug: format!("t-{tag}"),
        display_name: format!("Tenant {}", id.0),
        host: Some(format!("login-{tag}.example.test")),
        settings: TenantSettings {
            registration: RegistrationMode::InviteOnly,
            require_verified_email: true,
            ..TenantSettings::default()
        },
        created_at: now_ms(),
    }
}

/// Creates a tenant.
pub async fn seed_tenant(s: &TestStorage) -> TenantId {
    let t = new_tenant();
    s.storage
        .tenants()
        .create(&t)
        .await
        .expect("creating a seed tenant must succeed");
    t.id
}

// ---------------------------------------------------------------------------------------------
// Users

/// Every standard claim populated.
pub fn full_claims() -> StandardClaims {
    StandardClaims {
        name: Some("Ada Lovelace".into()),
        given_name: Some("Ada".into()),
        family_name: Some("Lovelace".into()),
        middle_name: Some("Augusta".into()),
        nickname: Some("ada".into()),
        preferred_username: Some("ada.l".into()),
        profile: Some("https://profile.example.test/ada".into()),
        picture: Some("https://profile.example.test/ada.png".into()),
        website: Some("https://ada.example.test".into()),
        gender: Some("female".into()),
        birthdate: Some("1815-12-10".into()),
        zoneinfo: Some("Europe/London".into()),
        locale: Some("en-GB".into()),
        phone_number: Some("+44 20 7946 0000".into()),
        phone_number_verified: true,
        address: Some(Address {
            formatted: Some("1 Example Street\nLondon".into()),
            street_address: Some("1 Example Street".into()),
            locality: Some("London".into()),
            region: Some("Greater London".into()),
            postal_code: Some("EC1A 1AA".into()),
            country: Some("GB".into()),
        }),
    }
}

/// An unverified active user with a unique email and username and every claim populated.
pub fn new_user() -> NewUser {
    let tag = short();
    NewUser {
        id: UserId::new_v7(),
        email: format!("u-{tag}@example.test"),
        email_verified: false,
        username: Some(format!("user-{tag}")),
        claims: full_claims(),
        status: UserStatus::Active,
        created_at: now_ms(),
    }
}

/// A password credential (fake PHC string).
pub fn new_password() -> NewPasswordCredential {
    NewPasswordCredential {
        phc: format!("$argon2id$v=19$m=19456,t=2,p=1$fake${}", short()),
        created_at: now_ms(),
    }
}

/// The user record `UserRepo::create` must return.
pub fn expected_user(tenant: TenantId, u: &NewUser) -> User {
    User {
        id: u.id,
        tenant_id: tenant,
        email: u.email.clone(),
        email_verified: u.email_verified,
        username: u.username.clone(),
        claims: u.claims.clone(),
        status: u.status,
        created_at: u.created_at,
        updated_at: u.created_at,
        last_login_at: None,
    }
}

/// Creates a user with a password.
pub async fn seed_user(s: &TestStorage, tenant: TenantId) -> User {
    s.storage
        .users()
        .create(tenant, &new_user(), Some(&new_password()), None, None)
        .await
        .expect("creating a seed user must succeed")
}

/// A self-service token for `user` sent to `email`.
pub fn new_self_service_token(
    kind: SelfServiceKind,
    user: UserId,
    email: &str,
    expires_in: Duration,
) -> NewSelfServiceToken {
    let now = now_ms();
    NewSelfServiceToken {
        token_hash: unique_hash(),
        kind,
        user_id: user,
        email: email.to_owned(),
        created_at: now,
        expires_at: now + expires_in,
    }
}

/// An outbox email to `to`, valid for a day.
/// A password-changed notice for `complete_recovery` (recipient filled in by storage).
pub fn new_recovery_notice() -> RecoveryNotice {
    let now = now_ms();
    RecoveryNotice {
        id: OutboxId::new_v7(),
        template: "password_changed".to_owned(),
        payload: BTreeMap::from([("sealed".to_owned(), format!("sealed-{}", short()))]),
        created_at: now,
        expires_at: now + Duration::days(1),
    }
}

pub fn new_email(to: &str) -> NewEmail {
    let now = now_ms();
    let mut payload = BTreeMap::new();
    payload.insert(
        "link".to_owned(),
        format!("https://id.example.test/x/{}", short()),
    );
    payload.insert("name".to_owned(), "Ada".to_owned());
    NewEmail {
        id: OutboxId::new_v7(),
        to: to.to_owned(),
        template: "verification".to_owned(),
        payload,
        created_at: now,
        expires_at: now + Duration::days(1),
    }
}

// ---------------------------------------------------------------------------------------------
// Clients

/// A confidential client with every optional field populated.
pub fn new_client() -> NewClient {
    NewClient {
        id: ClientId::new_v7(),
        client_id: format!("client-{}", short()),
        name: "Example App".to_owned(),
        client_type: ClientType::Confidential,
        application_type: ApplicationType::Web,
        auth_method: ClientAuthMethod::PrivateKeyJwt,
        secret_hash: Some(unique_hash()),
        jwks: Some(r#"{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]}"#.to_owned()),
        redirect_uris: vec![
            "https://app.example.test/callback".to_owned(),
            "https://app.example.test/callback2".to_owned(),
        ],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        require_pkce: true,
        // Defaults until both backends store the Phase 3 client columns (03-05/03-06); the
        // dedicated client_phase3_fields_round_trip test covers non-default values.
        token_format: TokenFormat::Jwt,
        consent_mode: ConsentMode::Required,
        id_token_signed_response_alg: None,
        can_introspect: false,
        created_at: now_ms(),
    }
}

/// The client record `ClientRepo::create` must return.
pub fn expected_client(tenant: TenantId, c: &NewClient) -> Client {
    Client {
        id: c.id,
        tenant_id: tenant,
        client_id: c.client_id.clone(),
        name: c.name.clone(),
        client_type: c.client_type,
        application_type: c.application_type,
        auth_method: c.auth_method,
        secret_hash: c.secret_hash,
        jwks: c.jwks.clone(),
        redirect_uris: c.redirect_uris.clone(),
        grant_types: c.grant_types.clone(),
        scopes: c.scopes.clone(),
        require_pkce: c.require_pkce,
        token_format: c.token_format,
        consent_mode: c.consent_mode,
        id_token_signed_response_alg: c.id_token_signed_response_alg.clone(),
        can_introspect: c.can_introspect,
        created_at: c.created_at,
        updated_at: c.created_at,
    }
}

/// Creates a client.
pub async fn seed_client(s: &TestStorage, tenant: TenantId) -> Client {
    s.storage
        .clients()
        .create(tenant, &new_client())
        .await
        .expect("creating a seed client must succeed")
}

// ---------------------------------------------------------------------------------------------
// Keys

/// An RS256 key in `state`, with fake sealed private key bytes.
pub fn new_signing_key(alg: &str, state: KeyState, expires_in: Option<Duration>) -> NewSigningKey {
    let now = now_ms();
    let id = SigningKeyId::new_v7();
    NewSigningKey {
        id,
        kid: format!("kid-{}", short()),
        alg: alg.to_owned(),
        state,
        private_key_enc: id.0.as_bytes().repeat(4),
        public_jwk: format!(r#"{{"kty":"RSA","kid":"{}","n":"n","e":"AQAB"}}"#, id.0),
        created_at: now,
        activated_at: Some(now),
        retired_at: Some(now),
        expires_at: expires_in.map(|d| now + d),
    }
}

// ---------------------------------------------------------------------------------------------
// Sessions and flows

/// A session for `user` with absolute expiry `expires_in` and idle expiry `idle_in`.
pub fn new_session(user: UserId, expires_in: Duration, idle_in: Duration) -> NewBrowserSession {
    let now = now_ms();
    NewBrowserSession {
        id: SessionId::new_v7(),
        user_id: user,
        token_hash: unique_hash(),
        auth_time: now - Duration::seconds(5),
        acr: anvil_core::model::ACR_PWD.to_owned(),
        amr: vec![anvil_core::model::AMR_PWD.to_owned()],
        created_at: now,
        expires_at: now + expires_in,
        idle_expires_at: now + idle_in,
        ip: None,
        user_agent: None,
    }
}

/// Creates a session (8 h absolute, 30 min idle) for `user`.
pub async fn seed_session(s: &TestStorage, tenant: TenantId, user: UserId) -> NewBrowserSession {
    let session = new_session(user, Duration::hours(8), Duration::minutes(30));
    s.storage
        .sessions()
        .create(tenant, &session)
        .await
        .expect("creating a seed session must succeed");
    session
}

/// A flow linked to `auth_request`.
pub fn new_flow(auth_request: Option<AuthRequestId>, expires_in: Duration) -> NewFlow {
    let now = now_ms();
    NewFlow {
        id: FlowId::new_v7(),
        kind: FlowKind::Login,
        state: r#"{"step":"identify","attempts":0}"#.to_owned(),
        csrf_hash: unique_hash(),
        cookie_hash: unique_hash(),
        auth_request_id: auth_request,
        created_at: now,
        expires_at: now + expires_in,
    }
}

// ---------------------------------------------------------------------------------------------
// Grants

/// Authorization parameters with every optional field populated, including a claims request.
pub fn full_params() -> AuthorizationParams {
    AuthorizationParams {
        redirect_uri: "https://app.example.test/callback".to_owned(),
        scope: "openid profile email".to_owned(),
        state: Some(format!("s-{}", short())),
        nonce: Some(format!("n-{}", short())),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
        prompt: vec!["login".into(), "consent".into()],
        max_age: Some(3600),
        login_hint: Some("ada@example.test".into()),
        acr_values: vec![anvil_core::model::ACR_PWD.to_owned()],
        ui_locales: Some("de en".into()),
        claims: Some(full_claims_request()),
    }
}

/// A claims request touching both targets.
pub fn full_claims_request() -> ClaimsRequest {
    ClaimsRequest {
        userinfo: vec![
            RequestedClaim {
                name: "email".into(),
                essential: true,
                values: vec![],
            },
            RequestedClaim {
                name: "locale".into(),
                essential: false,
                values: vec!["de".into(), "en".into()],
            },
        ],
        id_token: vec![RequestedClaim {
            name: "auth_time".into(),
            essential: true,
            values: vec![],
        }],
    }
}

/// An authorization request for `client_id`.
pub fn new_auth_request(client_id: &str, expires_in: Duration) -> NewAuthorizationRequest {
    let now = now_ms();
    NewAuthorizationRequest {
        id: AuthRequestId::new_v7(),
        client_id: client_id.to_owned(),
        params: full_params(),
        created_at: now,
        expires_at: now + expires_in,
    }
}

/// A tenant with a user, a client and a session: what a real code issuance has.
pub struct GrantCtx {
    pub tenant: TenantId,
    pub user: User,
    pub client: Client,
    pub session: NewBrowserSession,
}

/// Creates a tenant, user, client and session.
pub async fn seed_grant_ctx(s: &TestStorage) -> GrantCtx {
    let tenant = seed_tenant(s).await;
    seed_grant_ctx_in(s, tenant).await
}

/// Creates a user, client and session in an existing tenant.
pub async fn seed_grant_ctx_in(s: &TestStorage, tenant: TenantId) -> GrantCtx {
    let user = seed_user(s, tenant).await;
    let client = seed_client(s, tenant).await;
    let session = seed_session(s, tenant, user.id).await;
    GrantCtx {
        tenant,
        user,
        client,
        session,
    }
}

/// A token family for the context with the full authentication context.
pub fn new_family(ctx: &GrantCtx, absolute_in: Duration) -> NewTokenFamily {
    let now = now_ms();
    NewTokenFamily {
        id: TokenFamilyId::new_v7(),
        client_id: ctx.client.client_id.clone(),
        user_id: Some(ctx.user.id),
        scope: "openid profile offline_access".to_owned(),
        auth_time: Some(ctx.session.auth_time),
        acr: Some(ctx.session.acr.clone()),
        amr: ctx.session.amr.clone(),
        session_id: Some(ctx.session.id),
        claims: Some(full_claims_request()),
        created_at: now,
        absolute_expires_at: now + absolute_in,
    }
}

/// A code bound to `family`, expiring `expires_in` from now.
pub fn new_code(
    ctx: &GrantCtx,
    family: &NewTokenFamily,
    expires_in: Duration,
) -> NewAuthorizationCode {
    let now = now_ms();
    NewAuthorizationCode {
        code_hash: unique_hash(),
        client_id: ctx.client.client_id.clone(),
        user_id: ctx.user.id,
        session_id: ctx.session.id,
        redirect_uri: "https://app.example.test/callback".to_owned(),
        scope: family.scope.clone(),
        nonce: Some(format!("n-{}", short())),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
        auth_time: ctx.session.auth_time,
        acr: ctx.session.acr.clone(),
        amr: ctx.session.amr.clone(),
        token_family_id: family.id,
        expires_at: now + expires_in,
        created_at: now,
    }
}

/// The record `consume_code` must return for `code` stored under `tenant`.
pub fn expected_code(tenant: TenantId, code: &NewAuthorizationCode) -> AuthorizationCode {
    AuthorizationCode {
        tenant_id: tenant,
        code_hash: code.code_hash,
        client_id: code.client_id.clone(),
        user_id: code.user_id,
        session_id: code.session_id,
        redirect_uri: code.redirect_uri.clone(),
        scope: code.scope.clone(),
        nonce: code.nonce.clone(),
        code_challenge: code.code_challenge.clone(),
        auth_time: code.auth_time,
        acr: code.acr.clone(),
        amr: code.amr.clone(),
        token_family_id: code.token_family_id,
        expires_at: code.expires_at,
        created_at: code.created_at,
    }
}

/// The (unrevoked) family record `get_family` must return.
pub fn expected_family(tenant: TenantId, f: &NewTokenFamily) -> TokenFamily {
    TokenFamily {
        id: f.id,
        tenant_id: tenant,
        client_id: f.client_id.clone(),
        user_id: f.user_id,
        scope: f.scope.clone(),
        auth_time: f.auth_time,
        acr: f.acr.clone(),
        amr: f.amr.clone(),
        session_id: f.session_id,
        claims: f.claims.clone(),
        created_at: f.created_at,
        absolute_expires_at: f.absolute_expires_at,
        revoked_at: None,
        revoked_reason: None,
    }
}

/// Creates a family (30 days) and a code (`expires_in`) in one `create_code` call.
pub async fn seed_code(
    s: &TestStorage,
    ctx: &GrantCtx,
    expires_in: Duration,
) -> (NewAuthorizationCode, NewTokenFamily) {
    let family = new_family(ctx, Duration::days(30));
    let code = new_code(ctx, &family, expires_in);
    s.storage
        .grants()
        .create_code(ctx.tenant, &code, &family)
        .await
        .expect("creating a seed code must succeed");
    (code, family)
}

/// Creates a full context and a code valid for five minutes (Phase 1 helper shape).
pub async fn seed_tenant_and_code(s: &TestStorage) -> (TenantId, NewAuthorizationCode) {
    let ctx = seed_grant_ctx(s).await;
    let (code, _) = seed_code(s, &ctx, Duration::minutes(5)).await;
    (ctx.tenant, code)
}

/// A refresh token in `family`.
pub fn new_refresh(
    family: TokenFamilyId,
    parent: Option<SecretHash>,
    expires_in: Duration,
) -> NewRefreshToken {
    let now = now_ms();
    NewRefreshToken {
        token_hash: unique_hash(),
        family_id: family,
        parent_hash: parent,
        scope: "openid profile offline_access".to_owned(),
        created_at: now,
        expires_at: now + expires_in,
    }
}

/// The unconsumed refresh-token record for `t` stored under `tenant`.
pub fn expected_refresh(tenant: TenantId, t: &NewRefreshToken) -> RefreshToken {
    RefreshToken {
        token_hash: t.token_hash,
        tenant_id: tenant,
        family_id: t.family_id,
        parent_hash: t.parent_hash,
        scope: t.scope.clone(),
        created_at: t.created_at,
        expires_at: t.expires_at,
        consumed_at: None,
    }
}

/// Creates a family (via a code) and a first refresh token in it (valid 1 day).
pub async fn seed_refresh(s: &TestStorage, ctx: &GrantCtx) -> (NewTokenFamily, NewRefreshToken) {
    let (_, family) = seed_code(s, ctx, Duration::minutes(5)).await;
    let token = new_refresh(family.id, None, Duration::days(1));
    s.storage
        .grants()
        .create_refresh_token(ctx.tenant, &token)
        .await
        .expect("creating a seed refresh token must succeed");
    (family, token)
}

// ---------------------------------------------------------------------------------------------
// Setup

/// A setup token valid for `expires_in`.
pub fn new_setup_token(expires_in: Duration) -> NewSetupToken {
    let now = now_ms();
    NewSetupToken {
        token_hash: unique_hash(),
        created_at: now,
        expires_at: now + expires_in,
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 3: credentials, consent, access tokens, audit, mail settings

/// A passkey with a unique WebAuthn credential id.
pub fn new_passkey() -> NewPasskey {
    NewPasskey {
        id: CredentialId::new_v7(),
        credential_id: Uuid::now_v7().as_bytes().to_vec(),
        passkey_json: format!(r#"{{"cred":{{"id":"{}","counter":0}}}}"#, short()),
        counter: 0,
        backup_eligible: true,
        label: "Laptop".to_owned(),
        created_at: now_ms(),
    }
}

/// The record `UserRepo::passkeys` / `find_passkey` must return for `p` of `user`.
pub fn expected_passkey(user: UserId, p: &NewPasskey) -> PasskeyCredential {
    PasskeyCredential {
        id: p.id,
        user_id: user,
        credential_id: p.credential_id.clone(),
        passkey_json: p.passkey_json.clone(),
        counter: p.counter,
        backup_eligible: p.backup_eligible,
        label: p.label.clone(),
        created_at: p.created_at,
        last_used_at: None,
    }
}

/// A TOTP credential with a fake sealed seed.
pub fn new_totp() -> NewTotp {
    let id = CredentialId::new_v7();
    NewTotp {
        id,
        secret_enc: id.0.as_bytes().repeat(3),
        created_at: now_ms(),
    }
}

/// `n` distinct fake recovery-code hashes.
pub fn recovery_codes(n: usize) -> Vec<RecoveryCodeHash> {
    (0..n).map(|_| RecoveryCodeHash(unique_hash().0)).collect()
}

/// A consent of `user` for `client_id`.
pub fn new_consent(user: UserId, client_id: &str, scopes: &[&str]) -> NewConsent {
    NewConsent {
        id: ConsentId::new_v7(),
        user_id: user,
        client_id: client_id.to_owned(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        created_at: now_ms(),
    }
}

/// A client-credentials family (no user, no session, no authentication context).
pub fn new_service_family(client_id: &str, absolute_in: Duration) -> NewTokenFamily {
    let now = now_ms();
    NewTokenFamily {
        id: TokenFamilyId::new_v7(),
        client_id: client_id.to_owned(),
        user_id: None,
        scope: "api".to_owned(),
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        session_id: None,
        claims: None,
        created_at: now,
        absolute_expires_at: now + absolute_in,
    }
}

/// An opaque access token.
pub fn new_access_token(
    family: Option<TokenFamilyId>,
    client_id: &str,
    user: Option<UserId>,
    expires_in: Duration,
) -> NewAccessToken {
    let now = now_ms();
    NewAccessToken {
        token_hash: unique_hash(),
        family_id: family,
        client_id: client_id.to_owned(),
        user_id: user,
        scope: "openid profile".to_owned(),
        created_at: now,
        expires_at: now + expires_in,
    }
}

/// The unrevoked record `find_access_token` must return for `t` stored under `tenant`.
pub fn expected_access_token(tenant: TenantId, t: &NewAccessToken) -> AccessTokenRecord {
    AccessTokenRecord {
        token_hash: t.token_hash,
        tenant_id: tenant,
        family_id: t.family_id,
        client_id: t.client_id.clone(),
        user_id: t.user_id,
        scope: t.scope.clone(),
        created_at: t.created_at,
        expires_at: t.expires_at,
        revoked_at: None,
    }
}

/// An audit event with every optional field populated.
pub fn new_audit_event(
    action: AuditAction,
    outcome: AuditOutcome,
    actor_id: &str,
    target: &str,
    at: OffsetDateTime,
) -> NewAuditEvent {
    NewAuditEvent {
        id: AuditEventId::new_v7(),
        at,
        actor: AuditActor {
            kind: ActorKind::User,
            id: Some(actor_id.to_owned()),
        },
        action,
        target: Some(target.to_owned()),
        outcome,
        ctx: RequestContext::new(
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            Some("Mozilla/5.0 (contract)"),
            Some(format!("trace-{}", short())),
        ),
        details: AuditDetails::login("password").with(AuditDetails::reason("contract")),
    }
}

/// The stored record for `e` under `tenant`.
pub fn expected_audit_event(tenant: TenantId, e: &NewAuditEvent) -> AuditEvent {
    AuditEvent {
        id: e.id,
        tenant_id: tenant,
        at: e.at,
        actor: e.actor.clone(),
        action: e.action,
        target: e.target.clone(),
        outcome: e.outcome,
        ctx: e.ctx.clone(),
        details: e.details.clone(),
    }
}

/// SMTP settings with every optional field populated.
pub fn new_smtp_settings() -> SmtpSettings {
    SmtpSettings {
        host: format!("smtp-{}.example.test", short()),
        port: 587,
        username: Some("mailer".to_owned()),
        password_enc: Some(Uuid::now_v7().as_bytes().repeat(2)),
        from: "noreply@example.test".to_owned(),
        tls: SmtpTls::Starttls,
        updated_at: now_ms(),
    }
}

/// An email template override for `kind`.
pub fn new_email_template(kind: EmailKind) -> EmailTemplate {
    EmailTemplate {
        kind,
        subject: format!("Subject {}", short()),
        body_html: "<p>Hello {{ tenant_name }}</p>".to_owned(),
        body_text: "Hello {{ tenant_name }}".to_owned(),
        updated_at: now_ms(),
    }
}

/// Runs `n` copies of `f` released together by a barrier and collects the results.
pub async fn race<T, F, Fut>(n: usize, f: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = T> + Send + 'static,
{
    let barrier = Arc::new(tokio::sync::Barrier::new(n));
    let mut set = tokio::task::JoinSet::new();
    for i in 0..n {
        let barrier = Arc::clone(&barrier);
        let fut = f(i);
        set.spawn(async move {
            barrier.wait().await;
            fut.await
        });
    }
    let mut out = Vec::with_capacity(n);
    while let Some(joined) = set.join_next().await {
        out.push(joined.expect("race task panicked"));
    }
    out
}
