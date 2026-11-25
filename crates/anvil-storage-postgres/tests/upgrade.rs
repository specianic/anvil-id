//! 0.1 → 0.2 upgrade path (OPS-04).
//!
//! A database is migrated to the last 0.1 schema (`run_to(2)`), populated with 0.1 rows
//! (`fixtures/v0_1.sql`, plus a signing key and an outbox row sealed here with a fixed test KEK),
//! then upgraded with `migrate_with(Default)` exactly like a 0.2 binary does on start. Everything
//! is then checked through the storage traits. Finally the whole contract suite runs against
//! databases built through this upgrade path. Needs Docker (one shared testcontainers Postgres per
//! test binary, a fresh database per test), like the contract suite.

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
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
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

/// Server URL of the shared container (never dropped, like the contract suite's container).
async fn server_url() -> &'static str {
    let (_, url) = PG
        .get_or_init(|| async {
            let container = Postgres::default()
                .with_tag("18-alpine")
                .with_cmd(["postgres", "-c", "max_connections=500"])
                .start()
                .await
                .expect("docker must be running for Postgres upgrade tests");
            let host = container.get_host().await.expect("host");
            let port = container.get_host_port_ipv4(5432).await.expect("port");
            // Default credentials of the throwaway testcontainers image, not a secret.
            (
                container,
                format!("postgres://postgres:postgres@{host}:{port}"),
            )
        })
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
