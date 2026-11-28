//! 0.1 → 0.2 upgrade path (OPS-04).
//!
//! A database is migrated to the last 0.1 schema (`run_to(2)`), populated with 0.1 rows
//! (`fixtures/v0_1.sql`, plus a signing key and an outbox row sealed here with a fixed test KEK),
//! then upgraded with `migrate_with(Default)` exactly like a 0.2 binary does on start. Everything
//! is then checked through the storage traits. Finally the whole contract suite runs against
//! databases built through this upgrade path. Needs Docker (one shared testcontainers Postgres per
//! test binary, a fresh database per test), like the contract suite.
//!
//! Later releases add their own upgrade tests below (0.2 → 0.3, the 0.3 logout issuer,
//! 0.3 → 0.4 from `fixtures/release_0_3.sql`, which also checks the administrator backfill, and
//! 0.4 → 1.0 from `fixtures/release_0_4.sql`, which counts the rows of every table 0007 changes,
//! and 1.0.0-beta.1 → final from `fixtures/release_1_0_beta1.sql`, which compares the row count and
//! every beta.1 column value of every table before and after 0008, and 1.0.0-rc.3 → rc.4 from
//! `fixtures/release_1_0_rc3.sql`, one client per registration source, which checks that 0009's
//! client_uri and initiate_login_uri columns read NULL on every rc.3 row).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::{
    ClientAuthMethod, ConsentMode, CredentialKind, NewRefreshToken, RegistrationMode,
    SIGNING_KEY_PURPOSE, SecretHash, SessionId, SigningKeyId, TenantId, TenantSettings,
    TokenFamilyId, TokenFormat, UserId, open_payload, seal_payload, signing_key_aad,
};
use anvil_core::ports::{ConsumeOutcome, RotateOutcome, Storage};
use anvil_core::service::key::open_key;
use anvil_jose::{Kek, generate_rs256};
use anvil_storage::contract::TestStorage;
use anvil_storage_postgres::{MigrateOptions, PostgresStorage};
use sqlx::{Connection, PgConnection};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use time::OffsetDateTime;
use uuid::Uuid;

/// Last schema version shipped in 0.1.
const LAST_V0_1_VERSION: i64 = 2;

/// Fixed test KEK (never a production key).
const TEST_KEK: [u8; 32] = [0x42; 32];

const SYSTEM: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0001);
const DEFAULT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0002);
const USER: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0010);
const SESSION: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0030);
const FAMILY: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0040);
const KEY: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0050);
const OUTBOX: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0060);

const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$\
                   9vYp7ZrIx8DT2eTnNdD0yzKd0Zl0b3gxYk5y0RqFqm8";
const CODE_HASH: [u8; 32] = [0x01; 32];
const REFRESH_HASH: [u8; 32] = [0x02; 32];
const SESSION_HASH: [u8; 32] = [0x31; 32];
const CLIENT_SECRET_HASH: [u8; 32] = [0xaa; 32];

/// Pool size per test database; the contract's concurrency tests run 32 parallel consumers.
const MAX_CONNECTIONS: u32 = 40;

static PG: tokio::sync::OnceCell<(ContainerAsync<Postgres>, String)> =
    tokio::sync::OnceCell::const_new();

/// Server URL of the shared container (never dropped; see `anvil_storage::postgres_container` for cleanup).
async fn server_url() -> &'static str {
    let (_, url) = PG
        .get_or_init(|| anvil_storage::postgres_container::start(500))
        .await;
    url
}

async fn connect(url: &str) -> PgConnection {
    let mut last = None;
    for _ in 0..50 {
        match PgConnection::connect(url).await {
            Ok(c) => return c,
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    panic!("connecting to the test Postgres failed: {last:?}");
}

/// A fresh, empty database on the shared container; returns its URL.
async fn fresh_database() -> String {
    let server = server_url().await;
    let db = format!("upgrade_{}", Uuid::now_v7().simple());
    let mut admin = connect(&format!("{server}/postgres")).await;
    // `db` is built only from a UUID's hex digits, so interpolating it is safe.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
        .execute(&mut admin)
        .await
        .expect("create database");
    admin.close().await.expect("close admin connection");
    format!("{server}/{db}")
}

struct Upgraded {
    storage: PostgresStorage,
    kid: String,
    payload: BTreeMap<String, String>,
    url: String,
}

/// Builds a database through the 0.1 → latest upgrade path.
async fn upgraded() -> Upgraded {
    let url = fresh_database().await;
    let kek = Kek::from_bytes(&TEST_KEK).expect("test KEK");

    // A 0.1 installation: schema version 2 and 0.1 rows.
    let mut conn = connect(&url).await;
    let migrator = sqlx::migrate!();
    migrator
        .run_to(LAST_V0_1_VERSION, &mut conn)
        .await
        .expect("0.1 migrations apply");
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("version");
    assert_eq!(version, LAST_V0_1_VERSION);
    sqlx::raw_sql(include_str!("fixtures/v0_1.sql"))
        .execute(&mut conn)
        .await
        .expect("0.1 fixtures load");

    // Signing key sealed exactly like 0.1 seals it (purpose + row-id AAD), stored in the 0.1 shape.
    let key = generate_rs256().expect("generate key");
    let enc = kek
        .seal(
            SIGNING_KEY_PURPOSE,
            &signing_key_aad(SigningKeyId(KEY)),
            &key.pkcs8,
        )
        .expect("seal key");
    sqlx::query(
        "INSERT INTO signing_key (id, tenant_id, kid, alg, state, private_key_enc, public_jwk,
                                  created_at, activated_at, retired_at, expires_at)
         VALUES ($1, $2, $3, 'RS256', 'active', $4, $5, '2025-01-01T00:00:00Z',
                 '2025-01-01T00:00:00Z', NULL, NULL)",
    )
    .bind(KEY)
    .bind(DEFAULT)
    .bind(&key.kid)
    .bind(&enc)
    .bind(serde_json::to_string(&key.public_jwk).expect("jwk json"))
    .execute(&mut conn)
    .await
    .expect("insert signing key");

    // Outbox row with a payload sealed like 0.1 seals it.
    let payload = BTreeMap::from([
        (
            "link".to_owned(),
            "https://id.example.test/verify?t=x".to_owned(),
        ),
        ("email".to_owned(), "ada@example.test".to_owned()),
    ]);
    let sealed = seal_payload(&kek, TenantId(DEFAULT), &payload).expect("seal payload");
    sqlx::query(
        "INSERT INTO email_outbox (id, tenant_id, recipient, template, payload, attempts,
                                   next_attempt_at, created_at, expires_at, sent_at, last_error)
         VALUES ($1, $2, 'ada@example.test', 'verification', $3::jsonb, 0,
                 '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2100-01-01T00:00:00Z',
                 NULL, NULL)",
    )
    .bind(OUTBOX)
    .bind(DEFAULT)
    .bind(serde_json::to_string(&sealed).expect("payload json"))
    .execute(&mut conn)
    .await
    .expect("insert outbox row");
    conn.close().await.expect("close");

    // The 0.2 binary starts: connect and migrate with the defaults (destructive refused).
    let storage = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connect");
    storage
        .migrate_with(MigrateOptions::default())
        .await
        .expect("0.1 → latest upgrade applies without the destructive flag");
    Upgraded {
        storage,
        kid: key.kid,
        payload,
        url,
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

#[tokio::test]
async fn upgrade_from_0_1_keeps_every_row_and_defaults_new_columns() {
    let up = upgraded().await;
    let s = &up.storage;
    let kek = Kek::from_bytes(&TEST_KEK).expect("test KEK");
    let tenant = TenantId(DEFAULT);
    let user = UserId(USER);

    // Tenants: 0.1 settings parse; new settings take their defaults.
    let default = s
        .tenants()
        .get_by_slug("default")
        .await
        .expect("get tenant")
        .expect("default tenant survives");
    assert_eq!(default.id, tenant);
    assert_eq!(
        default.settings,
        TenantSettings {
            registration: RegistrationMode::InviteOnly,
            require_verified_email: true,
            ..TenantSettings::default()
        }
    );
    assert_eq!(default.settings.signing_algs, ["RS256"]);
    assert_eq!(default.settings.captcha, None);
    let system = s
        .tenants()
        .get(TenantId(SYSTEM))
        .await
        .expect("get system")
        .expect("system tenant survives");
    assert_eq!(system.slug, "system");
    assert_eq!(system.settings.registration, RegistrationMode::Disabled);
    assert!(s.setup().is_installed().await.expect("is_installed"));

    // Users and passwords.
    let u = s
        .users()
        .get(tenant, user)
        .await
        .expect("get user")
        .expect("user survives");
    assert_eq!(u.email, "ada@example.test");
    assert_eq!(u.username.as_deref(), Some("ada"));
    let pw = s
        .users()
        .password(tenant, user)
        .await
        .expect("password")
        .expect("password survives");
    assert_eq!(pw.phc, PHC);
    assert_eq!(pw.user_id, user);

    // Clients: 0.2 columns have their secure defaults.
    let web = s
        .clients()
        .get(tenant, "web-app")
        .await
        .expect("get client")
        .expect("confidential client survives");
    assert_eq!(web.secret_hash, Some(SecretHash(CLIENT_SECRET_HASH)));
    assert_eq!(web.auth_method, ClientAuthMethod::ClientSecretBasic);
    assert_eq!(web.redirect_uris, ["https://rp.example.test/cb"]);
    let spa = s
        .clients()
        .get(tenant, "spa")
        .await
        .expect("get client")
        .expect("public client survives");
    assert_eq!(spa.auth_method, ClientAuthMethod::None);
    assert!(spa.require_pkce);
    for c in [&web, &spa] {
        assert_eq!(c.token_format, TokenFormat::Jwt, "{}", c.client_id);
        assert_eq!(c.consent_mode, ConsentMode::Required, "{}", c.client_id);
        assert!(!c.can_introspect, "{}", c.client_id);
        assert_eq!(c.id_token_signed_response_alg, None, "{}", c.client_id);
    }

    // Browser session: still active, new request-context columns empty.
    let session = s
        .sessions()
        .get_active(tenant, &SecretHash(SESSION_HASH), now())
        .await
        .expect("get session")
        .expect("session still active");
    assert_eq!(session.id, SessionId(SESSION));
    assert_eq!(session.user_id, user);
    assert_eq!(session.ip, None);
    assert_eq!(session.user_agent, None);

    // The unconsumed code can be redeemed exactly once.
    match s
        .grants()
        .consume_code(tenant, &SecretHash(CODE_HASH), now())
        .await
        .expect("consume code")
    {
        ConsumeOutcome::Consumed(code) => {
            assert_eq!(code.token_family_id, TokenFamilyId(FAMILY));
            assert_eq!(code.session_id, SessionId(SESSION));
            assert_eq!(code.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
            assert_eq!(code.amr, ["pwd"]);
        }
        other => panic!("fixture code not consumable: {other:?}"),
    }
    assert!(matches!(
        s.grants()
            .consume_code(tenant, &SecretHash(CODE_HASH), now())
            .await
            .expect("second consume"),
        ConsumeOutcome::AlreadyConsumed { .. }
    ));

    // The live refresh token rotates.
    let child = NewRefreshToken {
        token_hash: SecretHash([0x03; 32]),
        family_id: TokenFamilyId(FAMILY),
        parent_hash: Some(SecretHash(REFRESH_HASH)),
        scope: "openid email offline_access".into(),
        created_at: now(),
        expires_at: now() + time::Duration::days(1),
    };
    match s
        .grants()
        .rotate_refresh(tenant, &SecretHash(REFRESH_HASH), &child, now())
        .await
        .expect("rotate")
    {
        RotateOutcome::Rotated(family) => {
            assert_eq!(family.id, TokenFamilyId(FAMILY));
            assert_eq!(family.session_id, Some(SessionId(SESSION)));
        }
        other => panic!("fixture refresh token did not rotate: {other:?}"),
    }

    // The 0.1 signing key opens with the KEK and signs.
    let row = s
        .keys()
        .active(tenant, "RS256")
        .await
        .expect("active key")
        .expect("active RS256 key survives");
    assert_eq!(row.kid, up.kid);
    let signer = open_key(&kek, &row).expect("key opens with the test KEK");
    let jwt = signer
        .sign_jwt(None, &serde_json::json!({ "sub": "upgrade" }))
        .expect("sign");
    assert_eq!(jwt.split('.').count(), 3);

    // The outbox row is claimable and its payload still opens.
    let claimed = s
        .outbox()
        .claim_due(now(), 10, Duration::from_secs(120))
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id.0, OUTBOX);
    assert_eq!(claimed[0].to, "ada@example.test");
    assert_eq!(
        open_payload(&kek, tenant, &claimed[0].payload).expect("payload opens"),
        up.payload
    );

    // The migrated password shows up as the user's only credential; 0.2 tables are empty.
    let creds = s
        .users()
        .list_credentials(tenant, user)
        .await
        .expect("credentials");
    assert_eq!(creds.len(), 1, "{creds:?}");
    assert_eq!(creds[0].kind, CredentialKind::Password);
    assert!(
        s.users()
            .passkeys(tenant, user)
            .await
            .expect("passkeys")
            .is_empty()
    );
}

#[tokio::test]
async fn upgrade_from_0_1_is_idempotent_on_restart() {
    let up = upgraded().await;
    up.storage
        .migrate()
        .await
        .expect("a second start finds nothing pending");
}

// ---------------------------------------------------------------------------------------------
// 0.2 → 0.3

/// Last schema version shipped in 0.2.
const LAST_V0_2_VERSION: i64 = 3;

const V2_TENANT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0001);
const V2_USER: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0010);
const V2_SESSION: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0030);
const V2_FAMILY: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0040);
const V2_FLOW: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0070);
const V2_CODE_HASH: [u8; 32] = [0x21; 32];
const V2_AT_HASH: [u8; 32] = [0x22; 32];
const V2_SESSION_HASH: [u8; 32] = [0x23; 32];
const V2_TOKEN_HASH: [u8; 32] = [0x24; 32];

/// 0.2 rows in every table migration 0004 touches (flow, self_service_token, email_template,
/// client, authorization_code, token_family, access_token, browser_session).
const V0_2_FIXTURE: &str = "
INSERT INTO tenant (id, slug, display_name, created_at, settings)
     VALUES ('00000000-0000-7000-8000-000000020001', 'acme', 'Acme', '2026-01-01T00:00:00Z',
             '{\"registration\":\"open\",\"require_verified_email\":false}');
INSERT INTO \"user\" (id, tenant_id, email, email_verified, username, status, created_at,
                      updated_at)
     VALUES ('00000000-0000-7000-8000-000000020010', '00000000-0000-7000-8000-000000020001',
             'grace@example.test', true, 'grace', 'active', '2026-01-01T00:00:00Z',
             '2026-01-01T00:00:00Z');
INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    redirect_uris, grant_types, scopes, require_pkce, created_at, updated_at,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect)
     VALUES ('00000000-0000-7000-8000-000000020020', '00000000-0000-7000-8000-000000020001',
             'rp', 'RP', 'public', 'web', 'none', ARRAY['https://rp.example.test/cb'],
             ARRAY['authorization_code', 'refresh_token'], ARRAY['openid'], true,
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'opaque', 'skip_first_party',
             'ES256', true);
INSERT INTO browser_session (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                             last_seen_at, expires_at, idle_expires_at, ip, user_agent)
     VALUES ('00000000-0000-7000-8000-000000020030', '00000000-0000-7000-8000-000000020001',
             '00000000-0000-7000-8000-000000020010', decode(repeat('23', 32), 'hex'),
             '2026-01-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'], '2026-01-01T00:00:00Z',
             '2026-01-01T00:00:00Z', '2100-01-01T00:00:00Z', '2100-01-01T00:00:00Z',
             '192.0.2.7', 'fixture-agent');
INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, created_at, absolute_expires_at)
     VALUES ('00000000-0000-7000-8000-000000020040', '00000000-0000-7000-8000-000000020001',
             'rp', '00000000-0000-7000-8000-000000020010', 'openid', '2026-01-01T00:00:00Z',
             'urn:anvilid:acr:pwd', ARRAY['pwd'], '00000000-0000-7000-8000-000000020030',
             '2026-01-01T00:00:00Z', '2100-01-01T00:00:00Z');
INSERT INTO authorization_code (code_hash, tenant_id, client_id, redirect_uri, scope, nonce,
                                code_challenge, token_family_id, user_id, session_id, auth_time,
                                acr, amr, expires_at, created_at)
     VALUES (decode(repeat('21', 32), 'hex'), '00000000-0000-7000-8000-000000020001', 'rp',
             'https://rp.example.test/cb', 'openid', 'n-0.2', 'challenge-0.2',
             '00000000-0000-7000-8000-000000020040', '00000000-0000-7000-8000-000000020010',
             '00000000-0000-7000-8000-000000020030', '2026-01-01T00:00:00Z',
             'urn:anvilid:acr:pwd', ARRAY['pwd'], '2100-01-01T00:00:00Z',
             '2026-01-01T00:00:00Z');
INSERT INTO access_token (token_hash, tenant_id, family_id, client_id, user_id, scope,
                          created_at, expires_at)
     VALUES (decode(repeat('22', 32), 'hex'), '00000000-0000-7000-8000-000000020001',
             '00000000-0000-7000-8000-000000020040', 'rp', '00000000-0000-7000-8000-000000020010',
             'openid', '2026-01-01T00:00:00Z', '2100-01-01T00:00:00Z');
INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash, created_at, expires_at)
     VALUES ('00000000-0000-7000-8000-000000020070', '00000000-0000-7000-8000-000000020001',
             'consent', '{\"step\":\"0.2\"}', decode(repeat('25', 32), 'hex'),
             decode(repeat('26', 32), 'hex'), '2026-01-01T00:00:00Z', '2100-01-01T00:00:00Z');
INSERT INTO self_service_token (token_hash, tenant_id, kind, user_id, email, created_at,
                                expires_at)
     VALUES (decode(repeat('24', 32), 'hex'), '00000000-0000-7000-8000-000000020001', 'recovery',
             '00000000-0000-7000-8000-000000020010', 'grace@example.test',
             '2026-01-01T00:00:00Z', '2100-01-01T00:00:00Z');
INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text, updated_at)
     VALUES ('00000000-0000-7000-8000-000000020001', 'password_changed', 'Changed',
             '<p>changed</p>', 'changed', '2026-01-01T00:00:00Z');
";

/// Runs one statement on a raw connection.
async fn exec(conn: &mut PgConnection, sql: &str) -> Result<u64, sqlx::Error> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
}

#[tokio::test]
async fn upgrade_from_0_2_keeps_every_row_and_widens_kinds() {
    use anvil_core::model::{FlowId, FlowKind, NewFlow, NewSelfServiceToken, SelfServiceKind};

    let url = fresh_database().await;
    let mut conn = connect(&url).await;
    sqlx::migrate!()
        .run_to(LAST_V0_2_VERSION, &mut conn)
        .await
        .expect("0.2 migrations apply");
    sqlx::raw_sql(V0_2_FIXTURE)
        .execute(&mut conn)
        .await
        .expect("0.2 fixtures load");

    // The 0.3 binary starts: migrate with the defaults (destructive refused).
    let s = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connect");
    s.migrate_with(MigrateOptions::default())
        .await
        .expect("0.2 → 0.3 upgrade applies without the destructive flag");
    let tenant = TenantId(V2_TENANT);

    // Client: 0.2 values kept, 0.3 columns default to "nothing configured".
    let rp = s
        .clients()
        .get(tenant, "rp")
        .await
        .expect("get client")
        .expect("client survives");
    assert_eq!(rp.token_format, TokenFormat::Opaque);
    assert_eq!(rp.consent_mode, ConsentMode::SkipFirstParty);
    assert_eq!(rp.id_token_signed_response_alg.as_deref(), Some("ES256"));
    assert!(rp.can_introspect);
    assert_eq!(rp.redirect_uris, ["https://rp.example.test/cb"]);
    assert!(rp.post_logout_redirect_uris.is_empty());
    assert_eq!(rp.backchannel_logout_uri, None);
    assert!(!rp.backchannel_logout_session_required);
    assert!(rp.allowed_resources.is_empty());
    assert_eq!(rp.mfa_policy, None);

    // Session: still active with its request context.
    let session = s
        .sessions()
        .get_active(tenant, &SecretHash(V2_SESSION_HASH), now())
        .await
        .expect("get session")
        .expect("session survives");
    assert_eq!(session.id, SessionId(V2_SESSION));
    assert_eq!(session.ip.as_deref(), Some("192.0.2.7"));
    assert_eq!(session.user_agent.as_deref(), Some("fixture-agent"));

    // Family, code and access token: preserved, resource defaults to empty.
    let family = s
        .grants()
        .get_family(tenant, TokenFamilyId(V2_FAMILY))
        .await
        .expect("get family")
        .expect("family survives");
    assert_eq!(family.session_id, Some(SessionId(V2_SESSION)));
    assert!(family.resource.is_empty());
    match s
        .grants()
        .consume_code(tenant, &SecretHash(V2_CODE_HASH), now())
        .await
        .expect("consume code")
    {
        ConsumeOutcome::Consumed(code) => {
            assert_eq!(code.nonce.as_deref(), Some("n-0.2"));
            assert_eq!(code.code_challenge.as_deref(), Some("challenge-0.2"));
            assert_eq!(code.token_family_id, TokenFamilyId(V2_FAMILY));
            assert!(code.resource.is_empty());
        }
        other => panic!("0.2 code not consumable: {other:?}"),
    }
    let (at, at_family) = s
        .grants()
        .find_access_token(tenant, &SecretHash(V2_AT_HASH))
        .await
        .expect("find access token")
        .expect("access token survives");
    assert_eq!(at.scope, "openid");
    assert!(at.resource.is_empty());
    assert_eq!(at_family.map(|f| f.id), Some(TokenFamilyId(V2_FAMILY)));

    // Flow, self-service token and template rows are intact.
    let flow = s
        .flows()
        .get(tenant, FlowId(V2_FLOW), now())
        .await
        .expect("get flow")
        .expect("flow survives");
    assert_eq!(flow.kind, FlowKind::Consent);
    assert_eq!(flow.state, "{\"step\":\"0.2\"}");
    let (kind, email): (String, String) =
        sqlx::query_as("SELECT kind, email FROM self_service_token WHERE token_hash = $1")
            .bind(&V2_TOKEN_HASH[..])
            .fetch_one(&mut conn)
            .await
            .expect("self-service token survives");
    assert_eq!(
        (kind.as_str(), email.as_str()),
        ("recovery", "grace@example.test")
    );
    let (subject, text): (String, String) = sqlx::query_as(
        "SELECT subject, body_text FROM email_template
          WHERE tenant_id = $1 AND kind = 'password_changed'",
    )
    .bind(V2_TENANT)
    .fetch_one(&mut conn)
    .await
    .expect("custom template survives");
    assert_eq!((subject.as_str(), text.as_str()), ("Changed", "changed"));

    // The widened CHECKs accept the 0.3 kinds through the storage traits...
    s.flows()
        .create(
            tenant,
            &NewFlow {
                id: FlowId::new_v7(),
                kind: FlowKind::Logout,
                state: "{}".into(),
                csrf_hash: SecretHash([0x27; 32]),
                cookie_hash: SecretHash([0x28; 32]),
                auth_request_id: None,
                created_at: now(),
                expires_at: now() + time::Duration::minutes(10),
            },
        )
        .await
        .expect("a logout flow is accepted");
    s.users()
        .issue_self_service_token(
            tenant,
            &NewSelfServiceToken {
                token_hash: SecretHash([0x29; 32]),
                kind: SelfServiceKind::EmailChange,
                user_id: UserId(V2_USER),
                email: "grace.new@example.test".into(),
                created_at: now(),
                expires_at: now() + time::Duration::hours(1),
            },
            None,
        )
        .await
        .expect("an email change token is accepted");
    // ...and raw SQL, while unknown values are still rejected.
    for kind in ["login_code", "email_change", "email_changed"] {
        exec(
            &mut conn,
            &format!(
                "INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text,
                                             updated_at)
                      VALUES ('{V2_TENANT}', '{kind}', 's', 'h', 't', now())"
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("template kind {kind} must be accepted: {e}"));
    }
    for (table, sql) in [
        (
            "email_template",
            format!(
                "INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text,
                                             updated_at)
                      VALUES ('{V2_TENANT}', 'bogus', 's', 'h', 't', now())"
            ),
        ),
        (
            "flow",
            format!(
                "INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash,
                                   created_at, expires_at)
                      VALUES ('{}', '{V2_TENANT}', 'bogus', '{{}}',
                              decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'),
                              now(), now())",
                Uuid::now_v7()
            ),
        ),
        (
            "self_service_token",
            format!(
                "INSERT INTO self_service_token (token_hash, tenant_id, kind, user_id, email,
                                                 created_at, expires_at)
                      VALUES (decode(repeat('0a', 32), 'hex'), '{V2_TENANT}', 'bogus',
                              '{V2_USER}', 'x@example.test', now(), now())"
            ),
        ),
        (
            "client.mfa_policy",
            format!("UPDATE client SET mfa_policy = 'bogus' WHERE tenant_id = '{V2_TENANT}'"),
        ),
    ] {
        let err = exec(&mut conn, &sql)
            .await
            .expect_err(&format!("{table}: an unknown kind must still be rejected"));
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.into_owned());
        assert_eq!(
            code.as_deref(),
            Some("23514"),
            "{table}: CHECK violation, got {err}"
        );
    }

    // A second start finds nothing pending.
    s.migrate().await.expect("restart after the upgrade");
    conn.close().await.expect("close");
}

/// Last 0.3 schema version before the RP-session issuer (migration 0005).
const LAST_PRE_ISSUER_VERSION: i64 = 4;

/// 0.3 rows written before migration 0005: an RP session of the 0.2 fixture session and a
/// queued back-channel logout delivery, in the 0004 shape (no issuer column).
const V0_3_PRE_ISSUER_FIXTURE: &str = "
UPDATE client SET backchannel_logout_uri = 'https://rp.example.test/bc' WHERE client_id = 'rp';
INSERT INTO rp_session (tenant_id, session_id, client_id, created_at)
     VALUES ('00000000-0000-7000-8000-000000020001', '00000000-0000-7000-8000-000000020030',
             'rp', '2026-01-01T00:00:00Z');
INSERT INTO logout_delivery (id, tenant_id, client_id, uri, sub, sid, attempts, next_attempt_at,
                             give_up_at, created_at)
     VALUES ('00000000-0000-7000-8000-000000020080', '00000000-0000-7000-8000-000000020001',
             'rp', 'https://rp.example.test/bc', 'grace', 'session', 0, '2026-01-01T00:00:00Z',
             '2100-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
";

/// 0.2 → 0.3 before 0005 → latest: RP sessions and deliveries written before the issuer column
/// survive with `issuer` NULL (the delivery worker then uses the canonical issuer).
#[tokio::test]
async fn upgrade_keeps_pre_issuer_rp_sessions_and_deliveries_with_null_issuer() {
    let url = fresh_database().await;
    let mut conn = connect(&url).await;
    sqlx::migrate!()
        .run_to(LAST_V0_2_VERSION, &mut conn)
        .await
        .expect("0.2 migrations apply");
    sqlx::raw_sql(V0_2_FIXTURE)
        .execute(&mut conn)
        .await
        .expect("0.2 fixtures load");
    sqlx::migrate!()
        .run_to(LAST_PRE_ISSUER_VERSION, &mut conn)
        .await
        .expect("0.3 migrations up to 0004 apply");
    sqlx::raw_sql(V0_3_PRE_ISSUER_FIXTURE)
        .execute(&mut conn)
        .await
        .expect("pre-issuer 0.3 fixtures load");
    conn.close().await.expect("close");

    let s = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connect");
    s.migrate_with(MigrateOptions::default())
        .await
        .expect("0005 applies without the destructive flag");
    let tenant = TenantId(V2_TENANT);
    let rps = s
        .logout()
        .rp_sessions(tenant, SessionId(V2_SESSION))
        .await
        .expect("rp_sessions");
    assert_eq!(rps.len(), 1, "the RP session survives");
    assert_eq!(rps[0].client_id, "rp");
    assert_eq!(rps[0].issuer, None, "pre-0005 RP sessions have no issuer");
    let deliveries = s
        .logout()
        .deliveries_for_client(tenant, "rp")
        .await
        .expect("deliveries");
    assert_eq!(deliveries.len(), 1, "the queued delivery survives");
    assert_eq!(deliveries[0].sid, "session");
    assert_eq!(
        deliveries[0].issuer, None,
        "pre-0005 deliveries have no issuer"
    );
}

/// Last schema version shipped in 0.3 (0005, the logout issuer).
const LAST_V0_3_VERSION: i64 = 5;

const V3_SYSTEM: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0001);
const V3_ACME: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0002);
const V3_ADMIN_ONE: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0010);
const V3_ADMIN_TWO: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0011);
const V3_USER: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0012);
const V3_CONSENT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0030);

/// 0.3 → 0.4 (0006): every 0.3 row stays readable with the 0.4 defaults, and the system tenant's
/// users keep administering the installation through the backfilled `administrator` role.
#[tokio::test]
async fn upgrade_from_0_3_backfills_administrators_and_keeps_rows() {
    use anvil_core::model::{ClientSource, MfaPolicy, SYSTEM_ADMIN_ROLE};

    let url = fresh_database().await;
    let mut conn = connect(&url).await;
    sqlx::migrate!()
        .run_to(LAST_V0_3_VERSION, &mut conn)
        .await
        .expect("0.3 migrations apply");
    sqlx::raw_sql(include_str!("fixtures/release_0_3.sql"))
        .execute(&mut conn)
        .await
        .expect("0.3 fixtures load");
    conn.close().await.expect("close");

    // The 0.4 binary starts: migrate with the defaults (destructive refused).
    let s = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connect");
    s.migrate_with(MigrateOptions::default())
        .await
        .expect("0006 applies without the destructive flag");

    // Administrators: the role exists once, with [admin:write], and both system users hold it.
    let system = TenantId(V3_SYSTEM);
    let role = s
        .roles()
        .get_by_name(system, SYSTEM_ADMIN_ROLE)
        .await
        .expect("get_by_name")
        .expect("0006 creates the administrator role");
    assert_eq!(role.tenant_id, system);
    assert_eq!(role.org_id, None);
    assert_eq!(role.permissions, vec!["admin:write".to_owned()]);
    assert_eq!(s.roles().list(system).await.expect("list").len(), 1);
    for admin in [V3_ADMIN_ONE, V3_ADMIN_TWO] {
        assert_eq!(
            s.roles()
                .roles_for_user(system, UserId(admin))
                .await
                .expect("roles_for_user"),
            vec![role.clone()],
            "system user {admin} keeps administering"
        );
    }
    assert_eq!(
        s.roles()
            .holders_of_permission(system, "admin:write")
            .await
            .expect("holders"),
        2
    );
    // Other tenants get no role and no assignment.
    let acme = TenantId(V3_ACME);
    assert!(s.roles().list(acme).await.expect("list").is_empty());
    assert!(
        s.roles()
            .roles_for_user(acme, UserId(V3_USER))
            .await
            .expect("roles_for_user")
            .is_empty()
    );

    // 0.3 rows read back with the 0.4 defaults.
    let client = s
        .clients()
        .get(acme, "rp")
        .await
        .expect("get client")
        .expect("client survives");
    assert_eq!(client.registration_source, ClientSource::Static);
    assert_eq!(client.metadata_expires_at, None);
    assert_eq!(client.registration_access_token_hash, None);
    assert_eq!(client.mfa_policy, Some(MfaPolicy::Optional));
    assert_eq!(
        client.allowed_resources,
        vec!["https://api.example.test".to_owned()]
    );
    let consent = s
        .grants()
        .consent(acme, UserId(V3_USER), "rp")
        .await
        .expect("consent")
        .expect("consent survives");
    assert_eq!(consent.id.0, V3_CONSENT);
    assert_eq!(
        consent.scopes,
        vec!["openid".to_owned(), "profile".to_owned()]
    );
    assert!(
        consent.resources.is_empty(),
        "0.3 grants cover no resources"
    );
    let user = s
        .users()
        .get(acme, UserId(V3_USER))
        .await
        .expect("get user")
        .expect("user survives");
    assert_eq!(user.email, "ada@example.test");
    assert_eq!(
        s.attributes()
            .user_values(acme, UserId(V3_USER))
            .await
            .expect("user_values"),
        Some(serde_json::Map::new()),
        "0.3 users start without attribute values"
    );
    assert!(s.attributes().list(acme).await.expect("list").is_empty());
    assert!(
        s.webhooks()
            .list_endpoints(system)
            .await
            .expect("endpoints")
            .is_empty()
    );
    assert!(
        s.registration()
            .list_iats(acme)
            .await
            .expect("iats")
            .is_empty()
    );

    // A new 0.4 administrator still gets the role through setup (the backfilled role is the one
    // `complete_setup` assigns).
    let token = SecretHash::from_slice(&[0x77; 32]).expect("hash");
    let now = now();
    s.setup()
        .create_setup_token(&anvil_core::model::NewSetupToken {
            token_hash: token,
            created_at: now,
            expires_at: now + time::Duration::hours(1),
        })
        .await
        .expect("setup token");
    let admin = anvil_storage::contract::new_user();
    let outcome = s
        .setup()
        .complete_setup(
            &token,
            now,
            system,
            &admin,
            &anvil_storage::contract::new_password(),
            acme,
            &anvil_storage::contract::new_client(),
        )
        .await
        .expect("complete_setup");
    assert!(matches!(
        outcome,
        anvil_core::ports::SetupOutcome::Completed { .. }
    ));
    assert_eq!(
        s.roles()
            .holders_of_permission(system, "admin:write")
            .await
            .expect("holders"),
        3
    );
}

// ---------------------------------------------------------------------------------------------
// 0.4 → 1.0

/// Last schema version shipped in 0.4 (0006).
const LAST_V0_4_VERSION: i64 = 6;

const V4_SYSTEM: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0004_0001);
const V4_ACME: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0004_0002);
const V4_ADMIN: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0004_0010);
const V4_ADA: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0004_0011);
const V4_BOB: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0004_0012);
const V4_CORP: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0004_0031);
const V4_FAMILY: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0004_0070);

/// Every table migration 0007 changes in place, plus the tables that reference them.
const V4_COUNTED_TABLES: &[&str] = &[
    "tenant",
    "\"user\"",
    "connection",
    "identity_link",
    "role",
    "role_assignment",
    "replay_guard",
    "email_template",
    "client",
    "token_family",
    "authorization_code",
];

/// Row count per table in [`V4_COUNTED_TABLES`].
async fn row_counts(conn: &mut PgConnection) -> BTreeMap<&'static str, i64> {
    let mut counts = BTreeMap::new();
    for table in V4_COUNTED_TABLES {
        // `table` comes from the constant list above, never from input.
        let n: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(&mut *conn)
                .await
                .expect("count");
        counts.insert(*table, n);
    }
    counts
}

/// A database at the last 0.4 schema version, populated from `fixtures/release_0_4.sql`, with its
/// per-table row counts before the upgrade.
async fn populated_v0_4() -> (String, BTreeMap<&'static str, i64>) {
    let url = fresh_database().await;
    let mut conn = connect(&url).await;
    sqlx::migrate!()
        .run_to(LAST_V0_4_VERSION, &mut conn)
        .await
        .expect("0.4 migrations apply");
    sqlx::raw_sql(include_str!("fixtures/release_0_4.sql"))
        .execute(&mut conn)
        .await
        .expect("0.4 fixtures load");
    let before = row_counts(&mut conn).await;
    conn.close().await.expect("close");
    (url, before)
}

/// 0.4 → 1.0 (0007): every row survives the in-place schema change, every foreign key still
/// holds, the 0.4 semantics are unchanged and the widened kinds are accepted.
#[tokio::test]
async fn upgrade_from_0_4_keeps_every_row() {
    use anvil_core::model::{
        ConnectionKind, EmailKind, EmailTemplate, OrgClientPolicy, ReplayKind, SYSTEM_ADMIN_ROLE,
    };
    use anvil_core::ports::JtiOutcome;

    let (url, before) = populated_v0_4().await;
    assert_eq!(before["identity_link"], 4, "fixture sanity");
    assert_eq!(before["role_assignment"], 4, "fixture sanity");
    assert_eq!(before["connection"], 3, "fixture sanity");
    assert_eq!(before["replay_guard"], 3, "fixture sanity");
    assert_eq!(before["email_template"], 2, "fixture sanity");

    // The 1.0 binary starts: migrate with the defaults (destructive refused).
    let s = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connect");
    s.migrate_with(MigrateOptions::default())
        .await
        .expect("0007 applies without the destructive flag");

    let mut conn = connect(&url).await;
    assert_eq!(
        row_counts(&mut conn).await,
        before,
        "no row is lost or added"
    );

    // Every reference still resolves, and every pre-existing row is tenant-level (org_id NULL).
    let orphans: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM identity_link l
                  WHERE NOT EXISTS (SELECT 1 FROM connection c
                                     WHERE c.tenant_id = l.tenant_id AND c.id = l.connection_id)
                     OR NOT EXISTS (SELECT 1 FROM \"user\" u
                                     WHERE u.tenant_id = l.tenant_id AND u.id = l.user_id))
              + (SELECT count(*) FROM role_assignment a
                  WHERE NOT EXISTS (SELECT 1 FROM role r
                                     WHERE r.tenant_id = a.tenant_id AND r.id = a.role_id)
                     OR NOT EXISTS (SELECT 1 FROM \"user\" u
                                     WHERE u.tenant_id = a.tenant_id AND u.id = a.user_id))",
    )
    .fetch_one(&mut conn)
    .await
    .expect("orphan check");
    assert_eq!(orphans, 0, "every link and assignment keeps its targets");
    let with_org: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM connection WHERE org_id IS NOT NULL)
              + (SELECT count(*) FROM role WHERE org_id IS NOT NULL)
              + (SELECT count(*) FROM role_assignment WHERE org_id IS NOT NULL)
              + (SELECT count(*) FROM token_family WHERE org_id IS NOT NULL)
              + (SELECT count(*) FROM authorization_code WHERE org_id IS NOT NULL)
              + (SELECT count(*) FROM client WHERE organization <> 'off')",
    )
    .fetch_one(&mut conn)
    .await
    .expect("org columns");
    assert_eq!(
        with_org, 0,
        "0.4 rows are tenant-level with the 1.0 defaults"
    );
    // The swapped CHECKs still reject unknown kinds.
    for bad in [
        format!("UPDATE connection SET kind = 'bogus' WHERE id = '{V4_CORP}'"),
        format!(
            "INSERT INTO replay_guard (tenant_id, kind, value_hash, expires_at)
                  VALUES ('{V4_ACME}', 'bogus', decode(repeat('99', 32), 'hex'), now())"
        ),
        format!(
            "INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text,
                                         updated_at)
                  VALUES ('{V4_ACME}', 'bogus', 's', 'h', 't', now())"
        ),
    ] {
        assert!(
            exec(&mut conn, &bad).await.is_err(),
            "an unknown kind is still rejected: {bad}"
        );
    }
    conn.close().await.expect("close");

    // Through the storage traits: administrators keep administering, 0.4 role semantics hold.
    let system = TenantId(V4_SYSTEM);
    let acme = TenantId(V4_ACME);
    let admin_role = s
        .roles()
        .get_by_name(system, SYSTEM_ADMIN_ROLE)
        .await
        .expect("get_by_name")
        .expect("the administrator role survives");
    assert_eq!(
        s.roles()
            .roles_for_user(system, UserId(V4_ADMIN))
            .await
            .expect("roles_for_user"),
        vec![admin_role.clone()]
    );
    assert_eq!(
        s.roles()
            .holders_of_permission(system, "admin:write")
            .await
            .expect("holders"),
        1
    );
    let ada_roles: Vec<String> = s
        .roles()
        .roles_for_user(acme, UserId(V4_ADA))
        .await
        .expect("roles_for_user")
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(ada_roles, vec!["editor".to_owned(), "viewer".to_owned()]);
    assert_eq!(
        s.roles()
            .holders_of_permission(acme, "docs:read")
            .await
            .expect("holders"),
        2
    );
    // Re-assigning an existing tenant-wide role is still idempotent (the partial unique index
    // replaced the primary key as the conflict target).
    let viewer = s
        .roles()
        .get_by_name(acme, "viewer")
        .await
        .expect("get_by_name")
        .expect("viewer");
    assert!(
        s.roles()
            .assign(acme, viewer.id, UserId(V4_BOB), now())
            .await
            .expect("assign again")
    );
    let mut conn = connect(&url).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM role_assignment")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(n, before["role_assignment"], "no duplicate assignment");
    conn.close().await.expect("close");

    // Connections and links read back unchanged, as tenant connections.
    let conns = s.connections().list(acme).await.expect("list");
    assert_eq!(
        conns
            .iter()
            .map(|c| (c.slug.as_str(), c.config.kind(), c.org_id))
            .collect::<Vec<_>>(),
        vec![
            ("corp", ConnectionKind::Oidc, None),
            ("google", ConnectionKind::Google, None),
        ]
    );
    assert_eq!(
        s.connections()
            .links_for_user(acme, UserId(V4_ADA))
            .await
            .expect("links")
            .len(),
        2
    );
    assert!(
        s.connections()
            .has_links(acme, anvil_core::model::ConnectionId(V4_CORP))
            .await
            .expect("has_links")
    );

    // Grants and clients carry the 1.0 defaults.
    let family = s
        .grants()
        .get_family(acme, TokenFamilyId(V4_FAMILY))
        .await
        .expect("get_family")
        .expect("family survives");
    assert_eq!(family.org_id, None);
    assert_eq!(family.user_id, Some(UserId(V4_ADA)));
    let client = s
        .clients()
        .get(acme, "rp")
        .await
        .expect("get client")
        .expect("client survives");
    assert_eq!(client.organization, OrgClientPolicy::Off);
    assert_client_phase7_defaults(&client);
    let mut conn = connect(&url).await;
    assert_new_1_0_tables_empty(&mut conn).await;
    conn.close().await.expect("close");

    // Replay guards: the 0.4 entries still block replays; the new kind is accepted.
    let jti = SecretHash::from_slice(&[0x41; 32]).expect("hash");
    let far = now() + time::Duration::days(1);
    assert_eq!(
        s.grants()
            .record_jti(acme, ReplayKind::ClientAssertionJti, &jti, far, now())
            .await
            .expect("record_jti"),
        JtiOutcome::Replayed,
        "a 0.4 replay guard entry survives"
    );
    assert_eq!(
        s.grants()
            .record_jti(acme, ReplayKind::SamlAssertionId, &jti, far, now())
            .await
            .expect("record_jti"),
        JtiOutcome::Recorded
    );

    // Email templates: the 0.4 overrides survive; the org invitation kind is accepted.
    let templates = s
        .mail_settings()
        .list_templates(acme)
        .await
        .expect("templates");
    assert_eq!(
        templates.iter().map(|t| t.kind).collect::<Vec<_>>(),
        vec![EmailKind::LoginCode, EmailKind::PasswordChanged]
    );
    s.mail_settings()
        .put_template(
            acme,
            &EmailTemplate {
                kind: EmailKind::OrgInvitation,
                subject: "Join".into(),
                body_html: "<p>join</p>".into(),
                body_text: "join".into(),
                updated_at: now(),
            },
        )
        .await
        .expect("org_invitation template");

    // Deleting a 0.4 user still cascades through the replaced keys.
    assert!(
        s.users()
            .delete(acme, UserId(V4_BOB))
            .await
            .expect("delete user")
    );
    let mut conn = connect(&url).await;
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM role_assignment WHERE user_id = $1)
              + (SELECT count(*) FROM identity_link WHERE user_id = $1)",
    )
    .bind(V4_BOB)
    .fetch_one(&mut conn)
    .await
    .expect("count");
    assert_eq!(left, 0);
    conn.close().await.expect("close");

    // Organizations work on the upgraded schema: a 0.4 user joins an org with a 0.4 role, and an
    // org connection routed to by a domain can still be deleted (the claim stays, without a
    // routing target), and so can the tenant holding all of it.
    use anvil_storage::contract::{new_membership, new_org, new_org_connection, new_org_domain};
    let org = s
        .organizations()
        .create(acme, &new_org())
        .await
        .expect("create org");
    assert_eq!(
        s.organizations()
            .add_member(acme, &new_membership(org.id, UserId(V4_ADA), &[viewer.id]))
            .await
            .expect("add member"),
        anvil_core::ports::AddMemberOutcome::Added
    );
    assert_eq!(
        s.roles()
            .roles_for_user_in_org(acme, UserId(V4_ADA), org.id)
            .await
            .expect("roles in org"),
        vec![viewer.clone()]
    );
    let org_conn = s
        .connections()
        .create(acme, &new_org_connection(org.id))
        .await
        .expect("org connection");
    let claim = new_org_domain(org.id, "upgrade.example.test", Some(org_conn.id));
    s.organizations()
        .create_domain(acme, &claim)
        .await
        .expect("domain");
    assert!(
        s.connections()
            .delete(acme, org_conn.id)
            .await
            .expect("delete a routed connection")
    );
    let kept = s
        .organizations()
        .get_domain(acme, claim.id)
        .await
        .expect("get domain")
        .expect("the claim stays");
    assert_eq!(kept.connection_id, None);
    let again = s
        .connections()
        .create(acme, &new_org_connection(org.id))
        .await
        .expect("org connection");
    s.organizations()
        .update_domain(
            acme,
            claim.id,
            &anvil_core::model::OrgDomainUpdate {
                connection_id: Some(Some(again.id)),
                ..Default::default()
            },
            now(),
        )
        .await
        .expect("update domain")
        .expect("routed again");
    assert!(s.tenants().delete(acme).await.expect("delete tenant"));
}

#[tokio::test]
async fn upgrade_from_0_4_is_idempotent_on_restart() {
    let (url, before) = populated_v0_4().await;
    for start in ["first", "second"] {
        let s = PostgresStorage::connect(&url, MAX_CONNECTIONS)
            .await
            .expect("connect");
        s.migrate_with(MigrateOptions::default())
            .await
            .unwrap_or_else(|e| panic!("{start} start migrates: {e}"));
    }
    let mut conn = connect(&url).await;
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("version");
    assert!(version > LAST_V0_4_VERSION);
    assert_eq!(row_counts(&mut conn).await, before);
    conn.close().await.expect("close");
}

/// Contract-suite factory: a database built through the upgrade path. The 0.1 fixture tenants
/// are deleted through the storage traits afterwards (cascading every fixture row through the
/// upgraded foreign keys), because the contract tests start from an uninstalled database.
pub async fn upgraded_postgres() -> TestStorage {
    let up = upgraded().await;
    for id in [DEFAULT, SYSTEM] {
        assert!(
            up.storage
                .tenants()
                .delete(TenantId(id))
                .await
                .expect("delete fixture tenant"),
            "fixture tenant {id} missing"
        );
    }
    TestStorage {
        storage: Arc::new(up.storage),
        _guard: Box::new(up.url),
    }
}

mod upgraded_contract {
    anvil_storage::storage_contract_tests!(crate::upgraded_postgres);
}

// ---------------------------------------------------------------------------------------------
// 1.0.0-beta.1 → final (migration 0008: pushed_authorization_request and password_hash_profile
// tables, client columns require_pushed_authorization_requests, client_kind and
// headless_native). Additive only: every beta.1 row must survive unchanged.

/// Schema version shipped in 1.0.0-beta.1 (0007_release_1_0).
const BETA1_VERSION: i64 = 7;

const B1_SYSTEM: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0001);
const B1_DEFAULT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0002);
const B1_ALICE: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0011);
const B1_BOB: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0012);
const B1_ORG: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0020);
const B1_ORG_ROLE: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0031);
const B1_SAML: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0050);
const B1_FAMILY: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0010_0080);

/// Tables the beta.1 fixture must populate (at least one row each).
const B1_POPULATED: [&str; 17] = [
    "tenant",
    "user",
    "credential",
    "client",
    "organization",
    "org_membership",
    "org_invitation",
    "connection",
    "identity_link",
    "org_domain",
    "role",
    "role_assignment",
    "browser_session",
    "token_family",
    "authorization_code",
    "replay_guard",
    "audit_event",
];

/// Highest migration version this binary embeds.
fn latest_version() -> i64 {
    sqlx::migrate!()
        .iter()
        .map(|m| m.version)
        .max()
        .expect("at least one migration")
}

/// The tables 0008 adds; they must exist and be empty right after the upgrade.
async fn assert_new_1_0_tables_empty(conn: &mut PgConnection) {
    for table in ["pushed_authorization_request", "password_hash_profile"] {
        // Table names are compile-time constants of this test.
        let n: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(&mut *conn)
                .await
                .unwrap_or_else(|e| panic!("{table} must exist after the upgrade: {e}"));
        assert_eq!(n, 0, "{table} starts empty");
    }
}

/// The 0008 client columns read as their defaults on pre-0008 rows.
fn assert_client_phase7_defaults(client: &anvil_core::model::Client) {
    assert!(!client.require_pushed_authorization_requests);
    assert_eq!(
        client.client_kind,
        anvil_core::model::ClientKind::Application
    );
    assert!(!client.headless_native);
}

/// Every table of the `public` schema (except sqlx's bookkeeping) with its columns in ordinal
/// order, as they are at the time of the call.
async fn table_columns(conn: &mut PgConnection) -> BTreeMap<String, Vec<String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.table_name::text, c.column_name::text
           FROM information_schema.columns c
           JOIN information_schema.tables t
             ON t.table_schema = c.table_schema AND t.table_name = c.table_name
          WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
            AND c.table_name <> '_sqlx_migrations'
          ORDER BY c.table_name, c.ordinal_position",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("columns");
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (table, column) in rows {
        out.entry(table).or_default().push(column);
    }
    out
}

/// Double-quoted identifier (names come from the test database's own catalog).
fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// `count(*)` of every table in `columns`.
async fn table_counts(
    conn: &mut PgConnection,
    columns: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    for table in columns.keys() {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {}",
            ident(table)
        )))
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("count {table}: {e}"));
        out.insert(table.clone(), n);
    }
    out
}

/// Every value of the given columns of every table, one sorted text line per row. Only the
/// columns passed in are read, so columns a later migration adds do not change the snapshot.
async fn snapshot(
    conn: &mut PgConnection,
    columns: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (table, cols) in columns {
        let list = cols.iter().map(|c| ident(c)).collect::<Vec<_>>().join(", ");
        let text: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT coalesce(string_agg(r, E'\\n' ORDER BY r), '')
               FROM (SELECT ROW({list})::text AS r FROM {}) s",
            ident(table)
        )))
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("snapshot {table}: {e}"));
        out.insert(table.clone(), text);
    }
    out
}

/// Rows whose composite references no longer resolve (checked on the beta.1 relations that
/// 0008 could have touched: clients and everything hanging off users, orgs and connections).
async fn dangling_references(conn: &mut PgConnection) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM token_family f
                  WHERE NOT EXISTS (SELECT 1 FROM client c
                                     WHERE c.tenant_id = f.tenant_id
                                       AND c.client_id = f.client_id))
              + (SELECT count(*) FROM authorization_code a
                  WHERE NOT EXISTS (SELECT 1 FROM token_family f
                                     WHERE f.id = a.token_family_id))
              + (SELECT count(*) FROM org_membership m
                  WHERE NOT EXISTS (SELECT 1 FROM organization o
                                     WHERE o.tenant_id = m.tenant_id AND o.id = m.org_id)
                     OR NOT EXISTS (SELECT 1 FROM \"user\" u
                                     WHERE u.tenant_id = m.tenant_id AND u.id = m.user_id))
              + (SELECT count(*) FROM identity_link l
                  WHERE NOT EXISTS (SELECT 1 FROM connection c
                                     WHERE c.tenant_id = l.tenant_id AND c.id = l.connection_id))
              + (SELECT count(*) FROM org_domain d
                  WHERE d.connection_id IS NOT NULL
                    AND NOT EXISTS (SELECT 1 FROM connection c
                                     WHERE c.tenant_id = d.tenant_id AND c.org_id = d.org_id
                                       AND c.id = d.connection_id))",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("reference check")
}

struct UpgradedBeta1 {
    storage: PostgresStorage,
    url: String,
    before: BTreeMap<String, String>,
    columns: BTreeMap<String, Vec<String>>,
    counts_before: BTreeMap<String, i64>,
}

/// A database at the beta.1 schema, populated from `fixtures/release_1_0_beta1.sql`, then
/// upgraded exactly like the final 1.0 binary does on start.
async fn upgraded_from_beta1() -> UpgradedBeta1 {
    let url = fresh_database().await;
    let mut conn = connect(&url).await;
    sqlx::migrate!()
        .run_to(BETA1_VERSION, &mut conn)
        .await
        .expect("beta.1 migrations apply");
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("version");
    assert_eq!(version, BETA1_VERSION);
    sqlx::raw_sql(include_str!("fixtures/release_1_0_beta1.sql"))
        .execute(&mut conn)
        .await
        .expect("beta.1 fixtures load (every foreign key holds)");
    let columns = table_columns(&mut conn).await;
    let before = snapshot(&mut conn, &columns).await;
    let counts_before = table_counts(&mut conn, &columns).await;
    for table in B1_POPULATED {
        assert!(
            counts_before.get(table).copied().unwrap_or(0) >= 1,
            "the beta.1 fixture must populate {table}"
        );
    }
    conn.close().await.expect("close");

    // The final 1.0 binary starts: connect and migrate with the defaults (destructive refused).
    let storage = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connect");
    storage
        .migrate_with(MigrateOptions::default())
        .await
        .expect("beta.1 → latest upgrade applies without the destructive flag");
    UpgradedBeta1 {
        storage,
        url,
        before,
        columns,
        counts_before,
    }
}

#[tokio::test]
async fn upgrade_from_1_0_beta1_keeps_every_row_and_defaults_new_columns() {
    use anvil_core::model::{
        ConnectionConfig, ConnectionId, ConnectionKind, NameIdFormat, NewPushedRequest,
        OrgClientPolicy, OrgId, PageRequest, ReplayKind, RoleId,
    };
    use anvil_core::ports::JtiOutcome;

    let up = upgraded_from_beta1().await;
    let s = &up.storage;
    let default = TenantId(B1_DEFAULT);
    let mut conn = connect(&up.url).await;

    // Row counts per table and every value of every beta.1 column are unchanged.
    assert_eq!(
        table_counts(&mut conn, &up.columns).await,
        up.counts_before,
        "0008 must not add or lose a row in any beta.1 table"
    );
    assert_eq!(
        snapshot(&mut conn, &up.columns).await,
        up.before,
        "the upgrade must not lose or change any row"
    );
    assert_eq!(dangling_references(&mut conn).await, 0);
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("version");
    assert_eq!(version, latest_version());
    assert_new_1_0_tables_empty(&mut conn).await;
    // The new columns carry their defaults in the rows themselves, not only through the reader.
    let defaults: (bool, String, bool) = sqlx::query_as(
        "SELECT require_pushed_authorization_requests, client_kind, headless_native
           FROM client WHERE client_id = 'beta1-web'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("client defaults");
    assert_eq!(defaults, (false, "application".to_owned(), false));
    conn.close().await.expect("close");

    // The client keeps its beta.1 policy and defaults the new columns.
    let web = s
        .clients()
        .get(default, "beta1-web")
        .await
        .expect("get client")
        .expect("client survives");
    assert_eq!(web.organization, OrgClientPolicy::Optional);
    assert_client_phase7_defaults(&web);

    // The beta.1 organization data reads back through the traits.
    let org = s
        .organizations()
        .get(default, OrgId(B1_ORG))
        .await
        .expect("get org")
        .expect("org survives");
    assert_eq!(org.slug, "acme");
    assert!(
        s.organizations()
            .is_member(default, OrgId(B1_ORG), UserId(B1_ALICE))
            .await
            .expect("is_member")
    );
    assert_eq!(
        s.organizations()
            .list_members(
                default,
                OrgId(B1_ORG),
                PageRequest {
                    after: None,
                    limit: 10
                }
            )
            .await
            .expect("members")
            .items
            .len(),
        1
    );
    let invitations = s
        .organizations()
        .list_invitations(default, OrgId(B1_ORG), false)
        .await
        .expect("invitations");
    assert_eq!(invitations.len(), 1);
    assert_eq!(invitations[0].role_ids, vec![RoleId(B1_ORG_ROLE)]);
    let saml = s
        .connections()
        .get(default, ConnectionId(B1_SAML))
        .await
        .expect("get connection")
        .expect("SAML connection survives");
    assert_eq!(saml.kind(), ConnectionKind::Saml);
    assert_eq!(saml.org_id, Some(OrgId(B1_ORG)));
    match &saml.config {
        ConnectionConfig::Saml(c) => assert_eq!(c.name_id_format, NameIdFormat::EmailAddress),
        other => panic!("SAML config expected, got {other:?}"),
    }
    let domains = s
        .organizations()
        .list_domains(default, OrgId(B1_ORG))
        .await
        .expect("domains");
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].connection_id, Some(ConnectionId(B1_SAML)));
    assert!(
        s.organizations()
            .routed_domain(default, "acme.example.test")
            .await
            .expect("routed_domain")
            .is_some(),
        "the verified routing domain still routes"
    );
    let org_roles: Vec<RoleId> = s
        .roles()
        .roles_for_user_in_org(default, UserId(B1_ALICE), OrgId(B1_ORG))
        .await
        .expect("org roles")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(org_roles.contains(&RoleId(B1_ORG_ROLE)));
    assert_eq!(
        s.connections()
            .links_for_user(default, UserId(B1_BOB))
            .await
            .expect("links")
            .len(),
        1
    );
    assert_eq!(
        s.grants()
            .record_jti(
                default,
                ReplayKind::SamlAssertionId,
                &SecretHash([0x53; 32]),
                now() + time::Duration::hours(1),
                now(),
            )
            .await
            .expect("record_jti"),
        JtiOutcome::Replayed,
        "the beta.1 SAML replay guard still blocks"
    );
    match s
        .grants()
        .consume_code(default, &SecretHash([0x52; 32]), now())
        .await
        .expect("consume")
    {
        ConsumeOutcome::Consumed(code) => assert_eq!(code.org_id, Some(OrgId(B1_ORG))),
        other => panic!("the beta.1 code must survive: {other:?}"),
    }

    // The Phase 7 methods work on the upgraded beta.1 rows.
    let families = s
        .grants()
        .families_for_user(default, UserId(B1_ALICE))
        .await
        .expect("families_for_user");
    assert_eq!(families.len(), 1);
    assert_eq!(families[0].id, TokenFamilyId(B1_FAMILY));
    assert_eq!(families[0].org_id, Some(OrgId(B1_ORG)));
    assert!(
        s.users()
            .replace_password_if(
                default,
                UserId(B1_ALICE),
                "$argon2id$v=19$beta1-alice",
                "$argon2id$v=19$rehashed",
                now(),
            )
            .await
            .expect("replace_password_if"),
        "the beta.1 password can be swapped"
    );
    let at = anvil_core::model::truncate_to_ms(now());
    let pushed = NewPushedRequest {
        request_uri_hash: SecretHash([0x54; 32]),
        client_id: "beta1-web".to_owned(),
        params: serde_json::json!({"redirect_uri": "https://rp.acme.example.test/cb"}),
        created_at: at,
        expires_at: at + time::Duration::seconds(60),
    };
    s.grants()
        .create_pushed_request(default, &pushed)
        .await
        .expect("PAR on the upgraded client");
    assert!(
        s.grants()
            .consume_pushed_request(default, &pushed.request_uri_hash, at)
            .await
            .expect("consume")
            .is_some()
    );
    assert!(
        s.password_profiles()
            .list(default)
            .await
            .expect("profiles")
            .is_empty()
    );
}

#[tokio::test]
async fn upgrade_from_1_0_beta1_is_idempotent_on_restart() {
    let up = upgraded_from_beta1().await;
    up.storage
        .migrate()
        .await
        .expect("a second start finds nothing pending");
    let again = PostgresStorage::connect(&up.url, MAX_CONNECTIONS)
        .await
        .expect("reconnect");
    again.migrate().await.expect("third start");
    let mut conn = connect(&up.url).await;
    assert_eq!(table_counts(&mut conn, &up.columns).await, up.counts_before);
    assert_eq!(snapshot(&mut conn, &up.columns).await, up.before);
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(applied, latest_version(), "every migration recorded once");
    assert_new_1_0_tables_empty(&mut conn).await;
    conn.close().await.expect("close");
}

/// Contract-suite factory: a database built through the beta.1 upgrade path, with the fixture
/// tenants deleted through the storage traits (the contract tests start uninstalled).
pub async fn upgraded_beta1_postgres() -> TestStorage {
    let up = upgraded_from_beta1().await;
    for id in [B1_DEFAULT, B1_SYSTEM] {
        assert!(
            up.storage
                .tenants()
                .delete(TenantId(id))
                .await
                .expect("delete fixture tenant"),
            "fixture tenant {id} missing"
        );
    }
    TestStorage {
        storage: Arc::new(up.storage),
        _guard: Box::new(up.url),
    }
}

mod upgraded_beta1_contract {
    anvil_storage::storage_contract_tests!(crate::upgraded_beta1_postgres);
}

// ---------------------------------------------------------------------------------------------
// 1.0.0-rc.3 → rc.4 (migration 0009: client columns client_uri and initiate_login_uri, nullable,
// no default). Additive only: every rc.3 row must survive unchanged and read NULL home URLs.

/// Schema version shipped in 1.0.0-rc.3 (0008_release_1_0_par_import).
const RC3_VERSION: i64 = 8;

const RC3_SYSTEM: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0011_0001);
const RC3_DEFAULT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0011_0002);
const RC3_CAROL: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0011_0011);
const RC3_FAMILY: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0011_0080);

/// The rc.3 fixture's clients: (client_id, registration source).
const RC3_CLIENTS: [(&str, anvil_core::model::ClientSource); 4] = [
    ("rc3-web", anvil_core::model::ClientSource::Static),
    ("rc3-spa", anvil_core::model::ClientSource::Static),
    ("rc3-dcr", anvil_core::model::ClientSource::Dynamic),
    (
        "https://mcp.example.test/client.json",
        anvil_core::model::ClientSource::Cimd,
    ),
];

struct UpgradedRc3 {
    storage: PostgresStorage,
    url: String,
    before: BTreeMap<String, String>,
    columns: BTreeMap<String, Vec<String>>,
    counts_before: BTreeMap<String, i64>,
}

/// A database at the rc.3 schema, populated from `fixtures/release_1_0_rc3.sql`, then upgraded
/// exactly like the rc.4 binary does on start.
async fn upgraded_from_rc3() -> UpgradedRc3 {
    let url = fresh_database().await;
    let mut conn = connect(&url).await;
    sqlx::migrate!()
        .run_to(RC3_VERSION, &mut conn)
        .await
        .expect("rc.3 migrations apply");
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("version");
    assert_eq!(version, RC3_VERSION);
    sqlx::raw_sql(include_str!("fixtures/release_1_0_rc3.sql"))
        .execute(&mut conn)
        .await
        .expect("rc.3 fixtures load (every foreign key holds)");
    let columns = table_columns(&mut conn).await;
    let before = snapshot(&mut conn, &columns).await;
    let counts_before = table_counts(&mut conn, &columns).await;
    assert_eq!(counts_before.get("client").copied(), Some(4));
    conn.close().await.expect("close");

    // The rc.4 binary starts: connect and migrate with the defaults (destructive refused).
    let storage = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connect");
    storage
        .migrate_with(MigrateOptions::default())
        .await
        .expect("rc.3 → latest upgrade applies without the destructive flag");
    UpgradedRc3 {
        storage,
        url,
        before,
        columns,
        counts_before,
    }
}

#[tokio::test]
async fn upgrade_from_1_0_rc3_keeps_clients_and_nulls_home_urls() {
    use anvil_core::model::{ClientKind, ClientType, ClientUpdate, PageRequest};

    let up = upgraded_from_rc3().await;
    let s = &up.storage;
    let default = TenantId(RC3_DEFAULT);
    let mut conn = connect(&up.url).await;

    // Row counts per table and every value of every rc.3 column are unchanged.
    assert_eq!(
        table_counts(&mut conn, &up.columns).await,
        up.counts_before,
        "0009 must not add or lose a row in any rc.3 table"
    );
    assert_eq!(
        snapshot(&mut conn, &up.columns).await,
        up.before,
        "the upgrade must not lose or change any row"
    );
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("version");
    assert_eq!(version, latest_version());
    let non_null: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM client WHERE client_uri IS NOT NULL OR initiate_login_uri IS NOT NULL",
    )
    .fetch_one(&mut conn)
    .await
    .expect("count");
    assert_eq!(non_null, 0, "the new columns are NULL on every rc.3 row");
    conn.close().await.expect("close");

    // Every client reads back through the traits with its source and NULL home URLs.
    for (client_id, source) in RC3_CLIENTS {
        let client = s
            .clients()
            .get(default, client_id)
            .await
            .expect("get client")
            .unwrap_or_else(|| panic!("{client_id} survives"));
        assert_eq!(client.registration_source, source, "{client_id}");
        assert_eq!(client.client_uri, None, "{client_id}");
        assert_eq!(client.initiate_login_uri, None, "{client_id}");
    }
    let listed = s
        .clients()
        .list(
            default,
            PageRequest {
                after: None,
                limit: 10,
            },
        )
        .await
        .expect("list");
    assert_eq!(listed.items.len(), 4);

    // The rc.3 column values survive on the confidential client.
    let web = s
        .clients()
        .get(default, "rc3-web")
        .await
        .expect("get")
        .expect("rc3-web");
    assert_eq!(web.client_type, ClientType::Confidential);
    assert_eq!(web.id_token_signed_response_alg.as_deref(), Some("ES256"));
    assert!(web.require_pushed_authorization_requests);
    assert_eq!(web.client_kind, ClientKind::Agent);
    assert_eq!(web.secret_hash, Some(SecretHash([0xee; 32])));
    let spa = s
        .clients()
        .get(default, "rc3-spa")
        .await
        .expect("get")
        .expect("rc3-spa");
    assert_eq!(spa.client_type, ClientType::Public);
    assert_eq!(spa.auth_method, ClientAuthMethod::None);
    assert!(
        s.clients()
            .get_by_registration_token(default, "rc3-dcr", &SecretHash([0x72; 32]))
            .await
            .expect("get_by_registration_token")
            .is_some(),
        "the DCR registration token still authenticates"
    );
    let cimd = s
        .clients()
        .get(default, "https://mcp.example.test/client.json")
        .await
        .expect("get")
        .expect("cimd");
    assert!(cimd.metadata_expires_at.is_some());

    // The upgraded rows accept the new fields.
    let updated = s
        .clients()
        .update(
            default,
            "rc3-spa",
            &ClientUpdate {
                client_uri: Some(Some("https://spa.example.test/".to_owned())),
                initiate_login_uri: Some(Some("https://spa.example.test/login".to_owned())),
                ..ClientUpdate::default()
            },
            now(),
        )
        .await
        .expect("update")
        .expect("rc3-spa");
    assert_eq!(
        updated.client_uri.as_deref(),
        Some("https://spa.example.test/")
    );
    assert_eq!(
        updated.initiate_login_uri.as_deref(),
        Some("https://spa.example.test/login")
    );

    // The rc.3 token family and user are intact.
    let families = s
        .grants()
        .families_for_user(default, UserId(RC3_CAROL))
        .await
        .expect("families_for_user");
    assert_eq!(families.len(), 1);
    assert_eq!(families[0].id, TokenFamilyId(RC3_FAMILY));
}

#[tokio::test]
async fn upgrade_from_1_0_rc3_is_idempotent_on_restart() {
    let up = upgraded_from_rc3().await;
    up.storage
        .migrate()
        .await
        .expect("a second start finds nothing pending");
    let again = PostgresStorage::connect(&up.url, MAX_CONNECTIONS)
        .await
        .expect("reconnect");
    again.migrate().await.expect("third start");
    let mut conn = connect(&up.url).await;
    assert_eq!(table_counts(&mut conn, &up.columns).await, up.counts_before);
    assert_eq!(snapshot(&mut conn, &up.columns).await, up.before);
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(applied, latest_version(), "every migration recorded once");
    conn.close().await.expect("close");
}

/// Contract-suite factory: a database built through the rc.3 upgrade path, with the fixture
/// tenants deleted through the storage traits (the contract tests start uninstalled).
pub async fn upgraded_rc3_postgres() -> TestStorage {
    let up = upgraded_from_rc3().await;
    for id in [RC3_DEFAULT, RC3_SYSTEM] {
        assert!(
            up.storage
                .tenants()
                .delete(TenantId(id))
                .await
                .expect("delete fixture tenant"),
            "fixture tenant {id} missing"
        );
    }
    TestStorage {
        storage: Arc::new(up.storage),
        _guard: Box::new(up.url),
    }
}

mod upgraded_rc3_contract {
    anvil_storage::storage_contract_tests!(crate::upgraded_rc3_postgres);
}
