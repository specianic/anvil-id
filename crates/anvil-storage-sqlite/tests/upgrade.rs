//! 0.1 → 0.2 upgrade path (OPS-04).
//!
//! A database is migrated to the last 0.1 schema (`run_to(2)`), populated with 0.1 rows
//! (`fixtures/v0_1.sql`, plus a signing key and an outbox row sealed here with a fixed test KEK),
//! then upgraded with `migrate_with(Default)` exactly like a 0.2 binary does on start. Everything
//! is then checked through the storage traits. Finally the whole contract suite runs against
//! databases built through this upgrade path.
//!
//! The same shape covers 0.2 → 0.3 (row-preserving CHECK rebuilds) and 0.3 → 0.4 (migration 0007:
//! additive schema plus the system tenant's administrator role backfill), each with its own
//! fixtures and its own contract-suite run.

use std::collections::BTreeMap;
use std::str::FromStr;
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
use anvil_storage_sqlite::{MigrateOptions, SqliteStorage};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
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
const FAR_FUTURE_MS: i64 = 4_102_444_800_000;

struct Upgraded {
    storage: SqliteStorage,
    kid: String,
    payload: BTreeMap<String, String>,
    _dir: tempfile::TempDir,
}

/// Builds a file database through the 0.1 → latest upgrade path.
async fn upgraded() -> Upgraded {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("anvil.db").display());
    let kek = Kek::from_bytes(&TEST_KEK).expect("test KEK");

    // A 0.1 installation: schema version 2 and 0.1 rows.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&url)
                .expect("url")
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .expect("open raw pool");
    let migrator = sqlx::migrate!();
    migrator
        .run_to(LAST_V0_1_VERSION, &pool)
        .await
        .expect("0.1 migrations apply");
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("version");
    assert_eq!(version, LAST_V0_1_VERSION);
    sqlx::raw_sql(include_str!("fixtures/v0_1.sql"))
        .execute(&pool)
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
         VALUES (?1, ?2, ?3, 'RS256', 'active', ?4, ?5, 1735689600000, 1735689600000, NULL, NULL)",
    )
    .bind(KEY)
    .bind(DEFAULT)
    .bind(&key.kid)
    .bind(&enc)
    .bind(serde_json::to_string(&key.public_jwk).expect("jwk json"))
    .execute(&pool)
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
         VALUES (?1, ?2, 'ada@example.test', 'verification', ?3, 0, 1735689600000,
                 1735689600000, ?4, NULL, NULL)",
    )
    .bind(OUTBOX)
    .bind(DEFAULT)
    .bind(serde_json::to_string(&sealed).expect("payload json"))
    .bind(FAR_FUTURE_MS)
    .execute(&pool)
    .await
    .expect("insert outbox row");
    pool.close().await;

    // The 0.2 binary starts: connect and migrate with the defaults (destructive refused).
    let storage = SqliteStorage::connect(&url).await.expect("connect");
    storage
        .migrate_with(MigrateOptions::default())
        .await
        .expect("0.1 → latest upgrade applies without the destructive flag");
    Upgraded {
        storage,
        kid: key.kid,
        payload,
        _dir: dir,
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

/// Contract-suite factory: a database built through the upgrade path. The 0.1 fixture tenants
/// are deleted through the storage traits afterwards (cascading every fixture row through the
/// upgraded foreign keys), because the contract tests start from an uninstalled database.
pub async fn upgraded_sqlite() -> TestStorage {
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
        _guard: Box::new(up._dir),
    }
}

mod upgraded_contract {
    anvil_storage::storage_contract_tests!(crate::upgraded_sqlite);
}

// ---------------------------------------------------------------------------------------------
// 0.2 → 0.3 (migration 0005: CHECK-widening rebuilds of flow, self_service_token and
// email_template, new tables, new client/code/family/access-token columns).

/// Last schema version shipped in 0.2.
const LAST_V0_2_VERSION: i64 = 4;

const V02_TENANT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0001);
const V02_USER: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0010);
const V02_SESSION: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0030);
const V02_FAMILY: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0002_0040);
const V02_CODE_HASH: [u8; 32] = [0x21; 32];
const V02_AT_HASH: [u8; 32] = [0x23; 32];

/// A populated 0.2 database (schema version 4), hand-written in the 0.2 shape: rows in every
/// table that 0005 rebuilds (a flow of every 0.2 kind, a self-service token of every 0.2 kind,
/// custom email templates) plus clients, a session, a family, a code, a refresh token and an
/// opaque access token. Timestamps: 2025-01-01 created, 2100-01-01 "far future".
const V0_2_FIXTURES: &str = r#"
INSERT INTO tenant (id, slug, display_name, created_at, host, settings) VALUES
  (x'00000000000070008000000000020001', 'v02', 'Release 0.2', 1735689600000, 'id.v02.example.test',
   '{"registration":"open","require_verified_email":true,"signing_algs":["RS256","ES256"]}');

INSERT INTO user (id, tenant_id, email, email_verified, username, claims, status, created_at,
                  updated_at, last_login_at) VALUES
  (x'00000000000070008000000000020010', x'00000000000070008000000000020001',
   'grace@example.test', 1, 'grace', '{"name":"Grace"}', 'active', 1735689600000, 1735689600000,
   NULL);

INSERT INTO credential (id, tenant_id, user_id, kind, secret, external_id, counter,
                        backup_eligible, label, created_at, updated_at, last_used_at) VALUES
  (x'00000000000070008000000000020011', x'00000000000070008000000000020001',
   x'00000000000070008000000000020010', 'password', '$argon2id$v=19$v02', NULL, NULL, 0, '',
   1735689600000, 1735689600000, NULL),
  (x'00000000000070008000000000020012', x'00000000000070008000000000020001',
   x'00000000000070008000000000020010', 'totp', 'c2VhbGVkLXNlZWQ', NULL, 42, 0, 'phone',
   1735689600000, 1735689600000, 1735689600001);

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at, token_format, consent_mode,
                    id_token_signed_response_alg, can_introspect) VALUES
  (x'00000000000070008000000000020020', x'00000000000070008000000000020001', 'v02-web',
   'Web', 'confidential', 'web', 'client_secret_basic',
   x'abababababababababababababababababababababababababababababababab', NULL,
   '["https://rp.example.test/cb"]', '["authorization_code","refresh_token"]',
   '["openid","offline_access"]', 1, 1735689600000, 1735689600000, 'opaque',
   'skip_first_party', 'ES256', 1);

INSERT INTO browser_session (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                             last_seen_at, expires_at, idle_expires_at, revoked_at, ip,
                             user_agent) VALUES
  (x'00000000000070008000000000020030', x'00000000000070008000000000020001',
   x'00000000000070008000000000020010',
   x'3232323232323232323232323232323232323232323232323232323232323232', 1735689600000,
   'urn:anvilid:acr:mfa', '["pwd","otp","mfa"]', 1735689600000, 1735689600000, 4102444800000,
   4102444800000, NULL, '192.0.2.1', 'Test agent');

INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash, auth_request_id,
                  created_at, expires_at) VALUES
  (x'00000000000070008000000000021001', x'00000000000070008000000000020001', 'login',
   '{"k":"login"}', zeroblob(32), x'0101010101010101010101010101010101010101010101010101010101010101',
   x'00000000000070008000000000021101', 1735689600000, 4102444800000),
  (x'00000000000070008000000000021002', x'00000000000070008000000000020001', 'registration',
   '{"k":"registration"}', zeroblob(32), zeroblob(32), NULL, 1735689600000, 4102444800000),
  (x'00000000000070008000000000021003', x'00000000000070008000000000020001', 'verification',
   '{"k":"verification"}', zeroblob(32), zeroblob(32), NULL, 1735689600000, 4102444800000),
  (x'00000000000070008000000000021004', x'00000000000070008000000000020001', 'recovery',
   '{"k":"recovery"}', zeroblob(32), zeroblob(32), NULL, 1735689600000, 4102444800000),
  (x'00000000000070008000000000021005', x'00000000000070008000000000020001', 'setup',
   '{"k":"setup"}', zeroblob(32), zeroblob(32), NULL, 1735689600000, 4102444800000),
  (x'00000000000070008000000000021006', x'00000000000070008000000000020001', 'settings',
   '{"k":"settings"}', zeroblob(32), zeroblob(32), NULL, 1735689600000, 4102444800000),
  (x'00000000000070008000000000021007', x'00000000000070008000000000020001', 'consent',
   '{"k":"consent"}', zeroblob(32), zeroblob(32), NULL, 1735689600000, 1735689600001);

INSERT INTO self_service_token (token_hash, tenant_id, kind, user_id, email, created_at,
                                expires_at, consumed_at) VALUES
  (x'4141414141414141414141414141414141414141414141414141414141414141',
   x'00000000000070008000000000020001', 'verification', x'00000000000070008000000000020010',
   'grace@example.test', 1735689600000, 4102444800000, NULL),
  (x'4242424242424242424242424242424242424242424242424242424242424242',
   x'00000000000070008000000000020001', 'recovery', x'00000000000070008000000000020010',
   'grace@example.test', 1735689600000, 4102444800000, 1735689600500),
  (x'4343434343434343434343434343434343434343434343434343434343434343',
   x'00000000000070008000000000020001', 'invitation', x'00000000000070008000000000020010',
   'grace@example.test', 1735689600000, 4102444800000, NULL);

INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text, updated_at) VALUES
  (x'00000000000070008000000000020001', 'verification', 'Verify {{ tenant_name }}',
   '<p>{{ link }}</p>', '{{ link }}', 1735689600000),
  (x'00000000000070008000000000020001', 'recovery_code_used', 'Code used',
   '<p>{{ remaining }}</p>', '{{ remaining }}', 1735689600001);

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason) VALUES
  (x'00000000000070008000000000020040', x'00000000000070008000000000020001', 'v02-web',
   x'00000000000070008000000000020010', 'openid offline_access', 1735689600000,
   'urn:anvilid:acr:mfa', '["pwd","otp","mfa"]', x'00000000000070008000000000020030', NULL,
   1735689600000, 4102444800000, NULL, NULL),
  (x'00000000000070008000000000020041', x'00000000000070008000000000020001', 'v02-web',
   x'00000000000070008000000000020010', 'openid', NULL, NULL, '[]', NULL, NULL,
   1735689600000, 4102444800000, 1735689600002, 'consent_revoked');

INSERT INTO authorization_code (code_hash, tenant_id, client_id, user_id, session_id,
                                redirect_uri, scope, nonce, code_challenge, auth_time, acr, amr,
                                token_family_id, expires_at, consumed_at, created_at) VALUES
  (x'2121212121212121212121212121212121212121212121212121212121212121',
   x'00000000000070008000000000020001', 'v02-web', x'00000000000070008000000000020010',
   x'00000000000070008000000000020030', 'https://rp.example.test/cb', 'openid offline_access',
   'n-v02', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 1735689600000,
   'urn:anvilid:acr:mfa', '["pwd","otp","mfa"]', x'00000000000070008000000000020040',
   4102444800000, NULL, 1735689600000);

INSERT INTO refresh_token (token_hash, tenant_id, family_id, parent_hash, scope, created_at,
                           expires_at, consumed_at) VALUES
  (x'2222222222222222222222222222222222222222222222222222222222222222',
   x'00000000000070008000000000020001', x'00000000000070008000000000020040', NULL,
   'openid offline_access', 1735689600000, 4102444800000, NULL);

INSERT INTO access_token (token_hash, tenant_id, family_id, client_id, user_id, scope,
                          created_at, expires_at, revoked_at) VALUES
  (x'2323232323232323232323232323232323232323232323232323232323232323',
   x'00000000000070008000000000020001', x'00000000000070008000000000020040', 'v02-web',
   x'00000000000070008000000000020010', 'openid offline_access', 1735689600000, 4102444800000,
   NULL);

INSERT INTO consent_grant (id, tenant_id, user_id, client_id, scopes, created_at, updated_at,
                           revoked_at) VALUES
  (x'00000000000070008000000000020050', x'00000000000070008000000000020001',
   x'00000000000070008000000000020010', 'v02-web', '["openid","offline_access"]',
   1735689600000, 1735689600000, NULL);

INSERT INTO audit_event (id, tenant_id, at, actor_kind, actor_id, action, target, outcome, ip,
                         user_agent, trace_id, details) VALUES
  (x'00000000000070008000000000020060', x'00000000000070008000000000020001', 1735689600000,
   'user', 'grace', 'login', NULL, 'success', '192.0.2.1', NULL, NULL, '{}');
"#;

/// Every row of every application table, each value rendered with SQLite's `quote()` over the
/// columns the table had before the upgrade, sorted. Equal snapshots = no row or value lost.
async fn snapshot(
    pool: &sqlx::SqlitePool,
    columns: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (table, cols) in columns {
        let expr = cols
            .iter()
            .map(|c| format!("quote(\"{c}\")"))
            .collect::<Vec<_>>()
            .join(" || '|' || ");
        // Table and column names come from sqlite_master of the test database itself.
        let sql = sqlx::AssertSqlSafe(format!("SELECT {expr} FROM \"{table}\""));
        let mut rows: Vec<String> = sqlx::query_scalar(sql)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|e| panic!("snapshot {table}: {e}"));
        rows.sort();
        out.insert(table.clone(), rows);
    }
    out
}

/// Application tables and their columns (sqlx bookkeeping excluded).
async fn table_columns(pool: &sqlx::SqlitePool) -> BTreeMap<String, Vec<String>> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master
          WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations'",
    )
    .fetch_all(pool)
    .await
    .expect("tables");
    let mut out = BTreeMap::new();
    for t in tables {
        let cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?1)")
            .bind(&t)
            .fetch_all(pool)
            .await
            .expect("columns");
        out.insert(t, cols);
    }
    out
}

struct UpgradedV02 {
    storage: SqliteStorage,
    url: String,
    before: BTreeMap<String, Vec<String>>,
    columns: BTreeMap<String, Vec<String>>,
    _dir: tempfile::TempDir,
}

/// Builds a file database through the 0.2 → latest upgrade path.
async fn upgraded_from_v0_2() -> UpgradedV02 {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("anvil.db").display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&url)
                .expect("url")
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .expect("open raw pool");
    sqlx::migrate!()
        .run_to(LAST_V0_2_VERSION, &pool)
        .await
        .expect("0.2 migrations apply");
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("version");
    assert_eq!(version, LAST_V0_2_VERSION);
    sqlx::raw_sql(V0_2_FIXTURES)
        .execute(&pool)
        .await
        .expect("0.2 fixtures load");
    let columns = table_columns(&pool).await;
    let before = snapshot(&pool, &columns).await;
    for table in [
        "flow",
        "self_service_token",
        "email_template",
        "client",
        "authorization_code",
        "token_family",
        "access_token",
    ] {
        assert!(!before[table].is_empty(), "fixture rows in {table}");
    }
    pool.close().await;

    // The 0.3 binary starts: connect and migrate with the defaults (destructive refused).
    let storage = SqliteStorage::connect(&url).await.expect("connect");
    storage
        .migrate_with(MigrateOptions::default())
        .await
        .expect("0.2 → latest upgrade applies without the destructive flag");
    UpgradedV02 {
        storage,
        url,
        before,
        columns,
        _dir: dir,
    }
}

#[tokio::test]
async fn upgrade_from_0_2_keeps_every_row_and_widens_checks() {
    let up = upgraded_from_v0_2().await;
    let s = &up.storage;
    let tenant = TenantId(V02_TENANT);

    // Every row and every value of every 0.2 table survives (rebuilt tables included).
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&up.url)
                .expect("url")
                .foreign_keys(true),
        )
        .await
        .expect("open raw pool");
    let after = snapshot(&pool, &up.columns).await;
    assert_eq!(
        after, up.before,
        "the upgrade must not lose or change any row"
    );
    let fk_violations: i64 = sqlx::query_scalar("SELECT count(*) FROM pragma_foreign_key_check")
        .fetch_one(&pool)
        .await
        .expect("fk check");
    assert_eq!(fk_violations, 0);

    // New columns take their defaults on existing rows.
    let web = s
        .clients()
        .get(tenant, "v02-web")
        .await
        .expect("get client")
        .expect("client survives");
    assert_eq!(web.token_format, TokenFormat::Opaque);
    assert_eq!(web.consent_mode, ConsentMode::SkipFirstParty);
    assert!(web.post_logout_redirect_uris.is_empty());
    assert_eq!(web.backchannel_logout_uri, None);
    assert!(!web.backchannel_logout_session_required);
    assert!(web.allowed_resources.is_empty());
    assert_eq!(web.mfa_policy, None);
    let family = s
        .grants()
        .get_family(tenant, TokenFamilyId(V02_FAMILY))
        .await
        .expect("get family")
        .expect("family survives");
    assert!(family.resource.is_empty());
    assert_eq!(family.session_id, Some(SessionId(V02_SESSION)));
    let (at, at_family) = s
        .grants()
        .find_access_token(tenant, &SecretHash(V02_AT_HASH))
        .await
        .expect("find access token")
        .expect("access token survives");
    assert!(at.resource.is_empty());
    assert_eq!(at.user_id, Some(UserId(V02_USER)));
    assert_eq!(at_family.map(|f| f.id), Some(TokenFamilyId(V02_FAMILY)));
    match s
        .grants()
        .consume_code(tenant, &SecretHash(V02_CODE_HASH), now())
        .await
        .expect("consume code")
    {
        ConsumeOutcome::Consumed(code) => {
            assert!(code.resource.is_empty());
            assert_eq!(code.nonce.as_deref(), Some("n-v02"));
        }
        other => panic!("fixture code not consumable: {other:?}"),
    }

    // The widened CHECK constraints accept the 0.3 kinds.
    sqlx::query(
        "INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash, auth_request_id,
                           created_at, expires_at)
         VALUES (x'00000000000070008000000000021008', ?1, 'logout', '{}', zeroblob(32),
                 zeroblob(32), NULL, 1735689600000, 4102444800000)",
    )
    .bind(V02_TENANT)
    .execute(&pool)
    .await
    .expect("a logout flow is accepted");
    sqlx::query(
        "INSERT INTO self_service_token (token_hash, tenant_id, kind, user_id, email, created_at,
                                         expires_at, consumed_at)
         VALUES (x'4444444444444444444444444444444444444444444444444444444444444444', ?1,
                 'email_change', ?2, 'new@example.test', 1735689600000, 4102444800000, NULL)",
    )
    .bind(V02_TENANT)
    .bind(V02_USER)
    .execute(&pool)
    .await
    .expect("an email_change token is accepted");
    for kind in ["login_code", "email_change", "email_changed"] {
        sqlx::query(
            "INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text,
                                         updated_at)
             VALUES (?1, ?2, 's', 'h', 't', 1735689600000)",
        )
        .bind(V02_TENANT)
        .bind(kind)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("a {kind} template is accepted: {e}"));
    }
    // ... and still reject unknown kinds.
    assert!(
        sqlx::query(
            "INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash, created_at,
                               expires_at)
             VALUES (x'00000000000070008000000000021009', ?1, 'bogus', '{}', zeroblob(32),
                     zeroblob(32), 0, 1)",
        )
        .bind(V02_TENANT)
        .execute(&pool)
        .await
        .is_err(),
        "the flow kind CHECK still rejects unknown kinds"
    );

    // The rebuilt self-service token table still cascades from the user.
    sqlx::query("DELETE FROM user WHERE id = ?1")
        .bind(V02_USER)
        .execute(&pool)
        .await
        .expect("delete user");
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM self_service_token")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(tokens, 0, "self-service tokens cascade from the user");
    pool.close().await;
}

/// Last 0.3 schema version before the RP-session issuer (migration 0006).
const LAST_PRE_ISSUER_VERSION: i64 = 5;

/// 0.3 rows written before migration 0006: an RP session of the 0.2 fixture session and a
/// queued back-channel logout delivery, in the 0005 shape (no issuer column).
const V0_3_PRE_ISSUER_FIXTURES: &str = r#"
UPDATE client SET backchannel_logout_uri = 'https://rp.example.test/bc'
 WHERE client_id = 'v02-web';
INSERT INTO rp_session (tenant_id, session_id, client_id, created_at) VALUES
  (x'00000000000070008000000000020001', x'00000000000070008000000000020030', 'v02-web',
   1735689600000);
INSERT INTO logout_delivery (id, tenant_id, client_id, uri, sub, sid, attempts, next_attempt_at,
                             give_up_at, created_at, delivered_at, last_error) VALUES
  (x'00000000000070008000000000020070', x'00000000000070008000000000020001', 'v02-web',
   'https://rp.example.test/bc', 'grace', 'session', 0, 1735689600000, 4102444800000,
   1735689600000, NULL, NULL);
"#;

/// 0.2 → 0.3 before 0006 → latest: RP sessions and deliveries written before the issuer column
/// survive with `issuer` NULL (the delivery worker then uses the canonical issuer).
#[tokio::test]
async fn upgrade_keeps_pre_issuer_rp_sessions_and_deliveries_with_null_issuer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("anvil.db").display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&url)
                .expect("url")
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .expect("open raw pool");
    sqlx::migrate!()
        .run_to(LAST_V0_2_VERSION, &pool)
        .await
        .expect("0.2 migrations apply");
    sqlx::raw_sql(V0_2_FIXTURES)
        .execute(&pool)
        .await
        .expect("0.2 fixtures load");
    sqlx::migrate!()
        .run_to(LAST_PRE_ISSUER_VERSION, &pool)
        .await
        .expect("0.3 migrations up to 0005 apply");
    sqlx::raw_sql(V0_3_PRE_ISSUER_FIXTURES)
        .execute(&pool)
        .await
        .expect("pre-issuer 0.3 fixtures load");
    pool.close().await;

    let storage = SqliteStorage::connect(&url).await.expect("connect");
    storage
        .migrate_with(MigrateOptions::default())
        .await
        .expect("0006 applies without the destructive flag");
    let tenant = TenantId(V02_TENANT);
    let rps = storage
        .logout()
        .rp_sessions(tenant, SessionId(V02_SESSION))
        .await
        .expect("rp_sessions");
    assert_eq!(rps.len(), 1, "the RP session survives");
    assert_eq!(rps[0].client_id, "v02-web");
    assert_eq!(rps[0].issuer, None, "pre-0006 RP sessions have no issuer");
    let deliveries = storage
        .logout()
        .deliveries_for_client(tenant, "v02-web")
        .await
        .expect("deliveries");
    assert_eq!(deliveries.len(), 1, "the queued delivery survives");
    assert_eq!(deliveries[0].sid, "session");
    assert_eq!(
        deliveries[0].issuer, None,
        "pre-0006 deliveries have no issuer"
    );
}

#[tokio::test]
async fn upgrade_from_0_2_is_idempotent_on_restart() {
    let up = upgraded_from_v0_2().await;
    up.storage
        .migrate()
        .await
        .expect("a second start finds nothing pending");
}

/// Contract-suite factory: a database built through the 0.2 upgrade path, with the fixture
/// tenant deleted through the storage traits (the contract tests start uninstalled).
pub async fn upgraded_v0_2_sqlite() -> TestStorage {
    let up = upgraded_from_v0_2().await;
    assert!(
        up.storage
            .tenants()
            .delete(TenantId(V02_TENANT))
            .await
            .expect("delete fixture tenant"),
        "fixture tenant missing"
    );
    TestStorage {
        storage: Arc::new(up.storage),
        _guard: Box::new(up._dir),
    }
}

mod upgraded_v0_2_contract {
    anvil_storage::storage_contract_tests!(crate::upgraded_v0_2_sqlite);
}

// ---------------------------------------------------------------------------------------------
// 0.3 → 0.4 (migration 0007: roles, attributes, webhooks, DCR/CIMD, consent resources, and the
// administrator role backfill for upgraded installations).

/// Last schema version shipped in 0.3.
const LAST_V0_3_VERSION: i64 = 6;

const V03_SYSTEM: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0001);
const V03_DEFAULT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0002);
const V03_ROOT: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0010);
const V03_OPS: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0011);
const V03_END_USER: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0003_0012);

struct UpgradedV03 {
    storage: SqliteStorage,
    url: String,
    before: BTreeMap<String, Vec<String>>,
    columns: BTreeMap<String, Vec<String>>,
    _dir: tempfile::TempDir,
}

/// Builds a file database through the 0.3 → latest upgrade path.
async fn upgraded_from_v0_3() -> UpgradedV03 {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("anvil.db").display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&url)
                .expect("url")
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .expect("open raw pool");
    sqlx::migrate!()
        .run_to(LAST_V0_3_VERSION, &pool)
        .await
        .expect("0.3 migrations apply");
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("version");
    assert_eq!(version, LAST_V0_3_VERSION);
    sqlx::raw_sql(include_str!("fixtures/release_0_3.sql"))
        .execute(&pool)
        .await
        .expect("0.3 fixtures load");
    let columns = table_columns(&pool).await;
    let before = snapshot(&pool, &columns).await;
    for table in ["tenant", "user", "client", "consent_grant"] {
        assert!(!before[table].is_empty(), "fixture rows in {table}");
    }
    pool.close().await;

    // The 0.4 binary starts: connect and migrate with the defaults (destructive refused).
    let storage = SqliteStorage::connect(&url).await.expect("connect");
    storage
        .migrate_with(MigrateOptions::default())
        .await
        .expect("0.3 → latest upgrade applies without the destructive flag");
    UpgradedV03 {
        storage,
        url,
        before,
        columns,
        _dir: dir,
    }
}

#[tokio::test]
async fn upgrade_from_0_3_keeps_every_row_and_backfills_administrators() {
    use anvil_core::model::{ClientSource, MfaPolicy, SYSTEM_ADMIN_ROLE, UserStatus};

    let up = upgraded_from_v0_3().await;
    let s = &up.storage;
    let system = TenantId(V03_SYSTEM);
    let default = TenantId(V03_DEFAULT);

    // Every row and every value of every 0.3 table survives.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&up.url)
                .expect("url")
                .foreign_keys(true),
        )
        .await
        .expect("open raw pool");
    let after = snapshot(&pool, &up.columns).await;
    assert_eq!(
        after, up.before,
        "the upgrade must not lose or change any row"
    );
    let fk_violations: i64 = sqlx::query_scalar("SELECT count(*) FROM pragma_foreign_key_check")
        .fetch_one(&pool)
        .await
        .expect("fk check");
    assert_eq!(fk_violations, 0);

    // Old rows stay readable through the traits; new columns take their defaults.
    let root = s
        .users()
        .get(system, UserId(V03_ROOT))
        .await
        .expect("get user")
        .expect("root survives");
    assert_eq!(root.email, "root@example.test");
    let ops = s
        .users()
        .get(system, UserId(V03_OPS))
        .await
        .expect("get user")
        .expect("ops survives");
    assert_eq!(ops.status, UserStatus::Blocked);
    assert_eq!(
        s.attributes()
            .user_values(default, UserId(V03_END_USER))
            .await
            .expect("user_values"),
        Some(serde_json::Map::new()),
        "existing users start with no attribute values"
    );
    let web = s
        .clients()
        .get(default, "v03-web")
        .await
        .expect("get client")
        .expect("client survives");
    assert_eq!(web.token_format, TokenFormat::Jwt);
    assert_eq!(web.mfa_policy, Some(MfaPolicy::Required));
    assert_eq!(
        web.post_logout_redirect_uris,
        vec!["https://rp.example.test/bye".to_owned()]
    );
    assert_eq!(
        web.allowed_resources,
        vec!["https://api.example.test".to_owned()]
    );
    assert_eq!(
        web.registration_source,
        ClientSource::Static,
        "0.3 clients are static registrations"
    );
    assert_eq!(web.metadata_expires_at, None);
    assert_eq!(web.registration_access_token_hash, None);
    assert_eq!(
        s.registration()
            .count_clients_by_source(default, ClientSource::Static)
            .await
            .expect("count"),
        1
    );
    let consent = s
        .grants()
        .consent(default, UserId(V03_END_USER), "v03-web")
        .await
        .expect("consent")
        .expect("consent survives");
    assert_eq!(
        consent.scopes,
        vec!["openid".to_owned(), "profile".to_owned()]
    );
    assert!(
        consent.resources.is_empty(),
        "0.3 consents cover no resources"
    );

    // The backfill: the system tenant has its administrator role and both 0.3 administrators
    // (blocked ones included) hold it; nobody outside the system tenant gets anything.
    let admin = s
        .roles()
        .get_by_name(system, SYSTEM_ADMIN_ROLE)
        .await
        .expect("get_by_name")
        .expect("the backfill creates the administrator role");
    assert_eq!(admin.tenant_id, system);
    assert_eq!(admin.org_id, None);
    assert_eq!(admin.permissions, vec!["admin:write".to_owned()]);
    assert_eq!(admin.id.0.get_version_num(), 7, "UUID-shaped role id");
    assert_eq!(
        admin.id.0.get_variant(),
        uuid::Variant::RFC4122,
        "UUID-shaped role id"
    );
    for user in [V03_ROOT, V03_OPS] {
        assert_eq!(
            s.roles()
                .roles_for_user(system, UserId(user))
                .await
                .expect("roles"),
            vec![admin.clone()],
            "system user {user} keeps administrator access"
        );
    }
    assert_eq!(
        s.roles()
            .holders_of_permission(system, "admin:write")
            .await
            .expect("holders"),
        1,
        "the blocked administrator is not an active holder"
    );
    assert!(
        s.roles()
            .roles_for_user(default, UserId(V03_END_USER))
            .await
            .expect("roles")
            .is_empty()
    );
    assert!(s.roles().list(default).await.expect("list").is_empty());

    // The upgraded schema works for 0.4 writes: consent resources merge, roles can be assigned
    // and deleting the system tenant cascades the backfilled rows.
    let mut more =
        anvil_storage::contract::new_consent(UserId(V03_END_USER), "v03-web", &["openid"]);
    more.resources = vec!["https://api.example.test".to_owned()];
    let merged = s
        .grants()
        .upsert_consent(default, &more, now())
        .await
        .expect("upsert consent");
    assert_eq!(merged.id, consent.id);
    assert_eq!(
        merged.resources,
        vec!["https://api.example.test".to_owned()]
    );
    assert!(s.tenants().delete(system).await.expect("delete system"));
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM role) + (SELECT count(*) FROM role_assignment)",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        leftovers, 0,
        "roles and assignments cascade from the tenant"
    );
    pool.close().await;
}

/// A 0.3 database without a system tenant (never installed) gets no role at all.
#[tokio::test]
async fn upgrade_from_0_3_without_system_tenant_creates_no_role() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("anvil.db").display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&url)
                .expect("url")
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .expect("open raw pool");
    sqlx::migrate!()
        .run_to(LAST_V0_3_VERSION, &pool)
        .await
        .expect("0.3 migrations apply");
    pool.close().await;
    let storage = SqliteStorage::connect(&url).await.expect("connect");
    storage
        .migrate()
        .await
        .expect("0007 applies on an empty 0.3 database");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::from_str(&url).expect("url"))
        .await
        .expect("open raw pool");
    let roles: i64 = sqlx::query_scalar("SELECT count(*) FROM role")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(roles, 0);
}

#[tokio::test]
async fn upgrade_from_0_3_is_idempotent_on_restart() {
    let up = upgraded_from_v0_3().await;
    up.storage
        .migrate()
        .await
        .expect("a second start finds nothing pending");
    assert_eq!(
        up.storage
            .roles()
            .list(TenantId(V03_SYSTEM))
            .await
            .expect("list")
            .len(),
        1,
        "the backfill runs once"
    );
}

/// Contract-suite factory: a database built through the 0.3 upgrade path, with the fixture
/// tenants deleted through the storage traits (the contract tests start uninstalled).
pub async fn upgraded_v0_3_sqlite() -> TestStorage {
    let up = upgraded_from_v0_3().await;
    for id in [V03_DEFAULT, V03_SYSTEM] {
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
        _guard: Box::new(up._dir),
    }
}

mod upgraded_v0_3_contract {
    anvil_storage::storage_contract_tests!(crate::upgraded_v0_3_sqlite);
}
