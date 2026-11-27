//! Secrets at rest (ARCHITECTURE §6.2, QUAL-01): row inspection of a real SQLite file.
//!
//! Seeds, through the storage ports, an authorization code, a refresh token (and its rotated
//! child), a browser session, a client secret digest, a setup token, a self-service token, a flow
//! CSRF/cookie pair and a replay-guarded jti, each derived from a known plaintext marker, plus a
//! verification email whose link carries a marker token (sealed with the KEK, as the core services
//! store it). Then it opens the database file with a plain connection and checks that no TEXT or
//! BLOB column of any table contains any marker, and that every hash column holds exactly 32 bytes
//! (the expected digest for the seeded rows).
//!
//! Release 0.2 secrets are covered too: a TOTP credential whose seed is sealed with the KEK
//! (`TOTP_SEED_PURPOSE`, `credential_aad`), recovery codes stored as peppered digests, an opaque
//! access token stored by hash, per-tenant SMTP settings with a sealed password and a sealed
//! CAPTCHA secret in the tenant settings. Besides the column scan, the raw bytes of the database
//! file and its WAL are searched for every Phase 3 plaintext (seed bytes, its base32 and base64url
//! forms, each recovery code, the SMTP password and the CAPTCHA secret).
//!
//! Release 0.3: upstream connection secrets are stored only KEK-sealed (purpose
//! `CONNECTION_SECRET_PURPOSE`, AAD `connection_aad(tenant, id)`); the raw file is scanned before
//! and after a WAL checkpoint, and the AAD binding is checked.
//!
//! Release 0.4: an RFC 7591 initial access token and two RFC 7592 registration access tokens
//! (one stored at registration, one by `set_registration_token`, the rotation path) are stored
//! only as digests, and a webhook endpoint's signing secrets (current and, after a rotation,
//! previous) only KEK-sealed under `WEBHOOK_SECRET_PURPOSE` with `webhook_aad(tenant, id)`. The
//! column scan and the raw file scan cover the `whsec_` secrets and their decoded key bytes.
//!
//! Release 1.0: an organization invitation token (digest only; its email sealed), an org-owned
//! connection's client secret (KEK-sealed) and a login flow holding a sealed SAML identity and a
//! sealed invitation return target (`return_to_sealed`), see
//! `release_1_0_secrets_never_stored_plaintext`. Domain challenge tokens and SAML certificates
//! are public by design and serve as positive controls.
//!
//! Release 1.0 final (Phase 7): a Firebase scrypt hash profile's signer key (KEK-sealed under
//! `PROFILE_SIGNER_KEY_PURPOSE`), a pushed authorization request's `request_uri` (hash only) and
//! a native headless flow token (hash only), see
//! `release_1_0_final_secrets_never_stored_plaintext`.

use std::collections::BTreeMap;

use anvil_core::model::{
    CAPTCHA_SECRET_PURPOSE, CaptchaProvider, CaptchaSettings, ClientSource, CredentialId,
    InitialAccessTokenId, NewAccessToken, NewEmail, NewInitialAccessToken, NewTotp,
    NewWebhookEndpoint, OutboxId, RecoveryCodeHash, ReplayKind, SMTP_PASSWORD_PURPOSE, SecretHash,
    SelfServiceKind, SmtpSettings, SmtpTls, TOTP_SEED_PURPOSE, TenantId, TenantSettings,
    TenantUpdate, UserId, WEBHOOK_SECRET_PURPOSE, WebhookEndpointId, WebhookEventType,
    credential_aad, seal_payload, webhook_aad,
};
use anvil_core::ports::{RotateOutcome, Storage};
use anvil_jose::encoding::{b64url, secret_hash};
use anvil_jose::webhook::{generate_webhook_secret, parse_webhook_secret};
use anvil_jose::{
    Kek, TotpSecret, generate_recovery_codes, normalize_recovery_code, recovery_code_hash,
};
use anvil_storage::contract::{
    GrantCtx, new_client, new_code, new_family, new_flow, new_password, new_refresh,
    new_self_service_token, new_session, new_setup_token, new_tenant, new_user, now_ms,
};
use anvil_storage_sqlite::SqliteStorage;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{AssertSqlSafe, Row, SqlitePool};
use time::Duration;

/// Every column that stores a secret hash: (table, column).
const HASH_COLUMNS: &[(&str, &str)] = &[
    ("authorization_code", "code_hash"),
    ("refresh_token", "token_hash"),
    ("refresh_token", "parent_hash"),
    ("browser_session", "token_hash"),
    ("client", "secret_hash"),
    ("admin_setup_token", "token_hash"),
    ("self_service_token", "token_hash"),
    ("flow", "csrf_hash"),
    ("flow", "cookie_hash"),
    ("replay_guard", "value_hash"),
    ("recovery_code", "code_hash"),
    ("access_token", "token_hash"),
    ("initial_access_token", "token_hash"),
    ("client", "registration_access_token_hash"),
];

fn marker(kind: &str) -> String {
    format!("PLAINTEXT-MARKER-{kind}-{}", uuid::Uuid::now_v7().simple())
}

fn hash_of(plaintext: &str) -> SecretHash {
    SecretHash(secret_hash(plaintext))
}

/// The seeded markers, with the table/column their digest must appear in.
struct Seeded {
    markers: Vec<(String, &'static str, &'static str)>,
    /// Markers stored only inside sealed values (no digest to look for).
    sealed_markers: Vec<String>,
    /// Release 0.2 plaintext secrets that must not appear anywhere, not even in the raw file.
    phase3_secrets: Vec<(&'static str, Vec<u8>)>,
}

async fn seed(storage: &SqliteStorage) -> Seeded {
    let mut markers = Vec::new();
    let mut track = |kind: &str, table: &'static str, column: &'static str| {
        let m = marker(kind);
        markers.push((m.clone(), table, column));
        m
    };

    let tenant = new_tenant();
    storage.tenants().create(&tenant).await.expect("tenant");
    let tenant = tenant.id;

    // User with a password and a verification token (self-service token).
    let user = new_user();
    let sst_marker = track("self-service", "self_service_token", "token_hash");
    let mut sst = new_self_service_token(
        SelfServiceKind::Verification,
        user.id,
        &user.email,
        Duration::hours(1),
    );
    sst.token_hash = hash_of(&sst_marker);
    // The verification email carrying the token link, sealed as the flow service stores it.
    let link_marker = marker("outbox-link");
    let vars = BTreeMap::from([
        ("tenant_name".to_owned(), "Acme".to_owned()),
        ("email".to_owned(), user.email.clone()),
        (
            "link".to_owned(),
            format!("https://id.example.test/ui/verification?token={link_marker}"),
        ),
        ("expires_in".to_owned(), "24 hours".to_owned()),
    ]);
    let email = NewEmail {
        id: OutboxId::new_v7(),
        to: user.email.clone(),
        template: "verification".to_owned(),
        payload: seal_payload(&Kek::generate(), tenant, &vars).expect("seal payload"),
        created_at: now_ms(),
        expires_at: now_ms() + Duration::days(1),
    };
    let user = storage
        .users()
        .create(
            tenant,
            &user,
            Some(&new_password()),
            Some(&sst),
            Some(&email),
        )
        .await
        .expect("user");

    // Client with a secret digest.
    let client_marker = track("client-secret", "client", "secret_hash");
    let mut client = new_client();
    client.secret_hash = Some(hash_of(&client_marker));
    let client = storage
        .clients()
        .create(tenant, &client)
        .await
        .expect("client");

    // Browser session.
    let session_marker = track("session", "browser_session", "token_hash");
    let mut session = new_session(user.id, Duration::hours(8), Duration::minutes(30));
    session.token_hash = hash_of(&session_marker);
    storage
        .sessions()
        .create(tenant, &session)
        .await
        .expect("session");

    // Authorization code with its family.
    let ctx = GrantCtx {
        tenant,
        user,
        client,
        session,
    };
    let code_marker = track("code", "authorization_code", "code_hash");
    let family = new_family(&ctx, Duration::days(30));
    let mut code = new_code(&ctx, &family, Duration::minutes(5));
    code.code_hash = hash_of(&code_marker);
    storage
        .grants()
        .create_code(tenant, &code, &family)
        .await
        .expect("code");

    // Refresh token and its rotated child (parent_hash populated).
    let refresh_marker = track("refresh", "refresh_token", "token_hash");
    let mut refresh = new_refresh(family.id, None, Duration::days(1));
    refresh.token_hash = hash_of(&refresh_marker);
    storage
        .grants()
        .create_refresh_token(tenant, &refresh)
        .await
        .expect("refresh");
    let child_marker = track("refresh-child", "refresh_token", "token_hash");
    let mut child = new_refresh(family.id, Some(refresh.token_hash), Duration::days(1));
    child.token_hash = hash_of(&child_marker);
    assert!(matches!(
        storage
            .grants()
            .rotate_refresh(tenant, &refresh.token_hash, &child, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::Rotated(_)
    ));

    // Setup token.
    let setup_marker = track("setup", "admin_setup_token", "token_hash");
    let mut setup = new_setup_token(Duration::hours(1));
    setup.token_hash = hash_of(&setup_marker);
    storage
        .setup()
        .create_setup_token(&setup)
        .await
        .expect("setup token");

    // Flow CSRF and cookie secrets.
    let csrf_marker = track("flow-csrf", "flow", "csrf_hash");
    let cookie_marker = track("flow-cookie", "flow", "cookie_hash");
    let mut flow = new_flow(None, Duration::minutes(10));
    flow.csrf_hash = hash_of(&csrf_marker);
    flow.cookie_hash = hash_of(&cookie_marker);
    storage.flows().create(tenant, &flow).await.expect("flow");

    // Client assertion jti.
    let jti_marker = track("jti", "replay_guard", "value_hash");
    storage
        .grants()
        .record_jti(
            tenant,
            ReplayKind::ClientAssertionJti,
            &hash_of(&jti_marker),
            now_ms() + Duration::minutes(5),
            now_ms(),
        )
        .await
        .expect("record_jti");

    let opaque_marker = track("opaque-access-token", "access_token", "token_hash");
    storage
        .grants()
        .create_access_token(
            tenant,
            &NewAccessToken {
                token_hash: hash_of(&opaque_marker),
                family_id: Some(family.id),
                client_id: ctx.client.client_id.clone(),
                user_id: Some(ctx.user.id),
                scope: "openid".to_owned(),
                created_at: now_ms(),
                expires_at: now_ms() + Duration::minutes(10),
                resource: vec![],
            },
        )
        .await
        .expect("opaque access token");

    // Release 0.4: RFC 7591 initial access token, stored as a digest.
    let iat_marker = track("initial-access-token", "initial_access_token", "token_hash");
    storage
        .registration()
        .create_iat(
            tenant,
            &NewInitialAccessToken {
                id: InitialAccessTokenId::new_v7(),
                description: "plaintext scan".to_owned(),
                token_hash: hash_of(&iat_marker),
                expires_at: Some(now_ms() + Duration::hours(24)),
                uses_remaining: Some(1),
                created_at: now_ms(),
            },
        )
        .await
        .expect("create_iat");

    // RFC 7592 registration access tokens: one stored with the dynamic client, one set later
    // (the path a rotation takes).
    let rat_marker = track(
        "registration-access-token",
        "client",
        "registration_access_token_hash",
    );
    let mut dynamic = new_client();
    dynamic.client_id = format!("dyn-{}", uuid::Uuid::now_v7().simple());
    dynamic.registration_source = ClientSource::Dynamic;
    dynamic.registration_access_token_hash = Some(hash_of(&rat_marker));
    storage
        .clients()
        .create(tenant, &dynamic)
        .await
        .expect("dynamic client");
    let rotated_rat_marker = track(
        "registration-access-token-rotated",
        "client",
        "registration_access_token_hash",
    );
    let mut rotated = new_client();
    rotated.client_id = format!("dyn-{}", uuid::Uuid::now_v7().simple());
    rotated.registration_source = ClientSource::Dynamic;
    storage
        .clients()
        .create(tenant, &rotated)
        .await
        .expect("second dynamic client");
    assert!(
        storage
            .clients()
            .set_registration_token(
                tenant,
                &rotated.client_id,
                Some(&hash_of(&rotated_rat_marker)),
                now_ms(),
            )
            .await
            .expect("set_registration_token"),
        "the second dynamic client exists"
    );

    let mut phase3_secrets = seed_phase3(storage, tenant, ctx.user.id).await;
    phase3_secrets.extend(seed_webhook_secrets(storage, tenant).await);

    Seeded {
        markers,
        sealed_markers: vec![link_marker],
        phase3_secrets,
    }
}

/// Seeds the Release 0.2 secrets exactly as the core services store them and returns every
/// plaintext form that must never reach the database.
async fn seed_phase3(
    storage: &SqliteStorage,
    tenant: TenantId,
    user: UserId,
) -> Vec<(&'static str, Vec<u8>)> {
    let kek = Kek::generate();
    let mut secrets = Vec::new();

    // TOTP seed sealed with the KEK, bound to the credential id; recovery codes as digests.
    let seed = TotpSecret::generate();
    let id = CredentialId::new_v7();
    let secret_enc = kek
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal TOTP seed");
    secrets.push(("totp seed bytes", seed.as_bytes().to_vec()));
    secrets.push(("totp seed base32", seed.to_base32().as_bytes().to_vec()));
    secrets.push(("totp seed base64url", b64url(seed.as_bytes()).into_bytes()));
    let codes = generate_recovery_codes(10).expect("recovery codes");
    let hashes: Vec<RecoveryCodeHash> = codes
        .iter()
        .map(|c| {
            let normalized = normalize_recovery_code(c).expect("normalize");
            secrets.push(("recovery code", c.as_bytes().to_vec()));
            secrets.push(("normalised recovery code", normalized.as_bytes().to_vec()));
            RecoveryCodeHash(recovery_code_hash(&kek, &normalized))
        })
        .collect();
    storage
        .users()
        .create_totp(
            tenant,
            user,
            &NewTotp {
                id,
                secret_enc,
                created_at: now_ms(),
            },
            &hashes,
            now_ms(),
        )
        .await
        .expect("create_totp");

    // SMTP settings with the password sealed under the tenant id.
    let smtp_password = marker("smtp-password");
    let password_enc = kek
        .seal(
            SMTP_PASSWORD_PURPOSE,
            tenant.0.as_bytes(),
            smtp_password.as_bytes(),
        )
        .expect("seal SMTP password");
    secrets.push(("smtp password", smtp_password.into_bytes()));
    storage
        .mail_settings()
        .put_smtp(
            tenant,
            &SmtpSettings {
                host: "smtp.example.test".to_owned(),
                port: 587,
                username: Some("mailer".to_owned()),
                password_enc: Some(password_enc),
                from: "noreply@example.test".to_owned(),
                tls: SmtpTls::Starttls,
                updated_at: now_ms(),
            },
        )
        .await
        .expect("put_smtp");

    // CAPTCHA secret sealed into the tenant settings JSON.
    let captcha_secret = marker("captcha-secret");
    let secret_sealed = b64url(
        &kek.seal(
            CAPTCHA_SECRET_PURPOSE,
            tenant.0.as_bytes(),
            captcha_secret.as_bytes(),
        )
        .expect("seal CAPTCHA secret"),
    );
    secrets.push(("captcha secret", captcha_secret.into_bytes()));
    storage
        .tenants()
        .update(
            tenant,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    captcha: Some(CaptchaSettings {
                        provider: CaptchaProvider::Turnstile,
                        site_key: "site-key-public".to_owned(),
                        secret_sealed,
                    }),
                    ..TenantSettings::default()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");

    secrets
}

/// Release 0.4: a webhook endpoint whose signing secret is sealed exactly as
/// `service::webhook::seal_webhook_secret` does, then rotated so that `previous_secret_enc` is
/// populated too. Returns the plaintext forms (the `whsec_` strings and their HMAC key bytes).
async fn seed_webhook_secrets(
    storage: &SqliteStorage,
    tenant: TenantId,
) -> Vec<(&'static str, Vec<u8>)> {
    let kek = Kek::generate();
    let id = WebhookEndpointId::new_v7();
    let seal = |secret: &str| {
        kek.seal(
            WEBHOOK_SECRET_PURPOSE,
            &webhook_aad(tenant, id),
            secret.as_bytes(),
        )
        .expect("seal webhook secret")
    };
    let first = generate_webhook_secret();
    let second = generate_webhook_secret();
    storage
        .webhooks()
        .create_endpoint(
            tenant,
            &NewWebhookEndpoint {
                id,
                name: "plaintext-scan".to_owned(),
                url: "https://hooks.example.test/anvil".to_owned(),
                events: vec![WebhookEventType::UserCreated],
                enabled: true,
                secret_enc: seal(&first),
                created_at: now_ms(),
            },
        )
        .await
        .expect("create_endpoint");
    assert!(
        storage
            .webhooks()
            .rotate_secret(
                tenant,
                id,
                &seal(&second),
                now_ms() + Duration::hours(24),
                now_ms(),
            )
            .await
            .expect("rotate_secret"),
        "the endpoint exists"
    );
    let stored = storage
        .webhooks()
        .get_endpoint(tenant, id)
        .await
        .expect("get_endpoint")
        .expect("endpoint exists");
    assert!(
        stored.previous_secret_enc.is_some(),
        "the rotation keeps the previous sealed secret"
    );
    vec![
        ("webhook secret", first.as_bytes().to_vec()),
        (
            "webhook key bytes",
            parse_webhook_secret(&first).expect("key").to_vec(),
        ),
        ("rotated webhook secret", second.as_bytes().to_vec()),
        (
            "rotated webhook key bytes",
            parse_webhook_secret(&second).expect("key").to_vec(),
        ),
    ]
}

/// Raw bytes of the database file and its WAL (whichever exist).
fn raw_database_bytes(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for suffix in ["", "-wal"] {
        let p = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if let Ok(bytes) = std::fs::read(&p) {
            files.push((p.display().to_string(), bytes));
        }
    }
    files
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

async fn inspect(path: &std::path::Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(path).read_only(true))
        .await
        .expect("plain read-only connection")
}

/// Every (table, column) of the schema, excluding sqlx's own bookkeeping table.
async fn all_columns(pool: &SqlitePool) -> Vec<(String, String)> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master
          WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations'
          ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .expect("list tables");
    let mut columns = Vec::new();
    for table in tables {
        let rows = sqlx::query("SELECT name FROM pragma_table_info(?1)")
            .bind(&table)
            .fetch_all(pool)
            .await
            .expect("table_info");
        for row in rows {
            columns.push((table.clone(), row.get::<String, _>("name")));
        }
    }
    columns
}

/// Number of (row, column) cells of TEXT or BLOB type whose bytes contain `needle`.
async fn hits_anywhere(pool: &SqlitePool, columns: &[(String, String)], needle: &[u8]) -> i64 {
    let mut total = 0;
    for (table, column) in columns {
        // Identifiers come from sqlite_master of the schema under test, not from input.
        let sql = format!(
            "SELECT COUNT(*) FROM \"{table}\"
              WHERE typeof(\"{column}\") IN ('text', 'blob')
                AND instr(CAST(\"{column}\" AS BLOB), ?1) > 0"
        );
        let hits: i64 = sqlx::query_scalar(AssertSqlSafe(sql))
            .bind(needle)
            .fetch_one(pool)
            .await
            .expect("scan column");
        total += hits;
    }
    total
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secrets_never_stored_plaintext() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("anvil.db");
    let storage = SqliteStorage::connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");
    let seeded = seed(&storage).await;

    // Raw file scan while the storage is open, so pages still in the WAL are covered too.
    let raw = raw_database_bytes(&path);
    assert!(!raw.is_empty(), "the database file must exist");
    assert!(
        raw.iter()
            .any(|(_, bytes)| contains(bytes, b"smtp.example.test")),
        "positive control: the raw scan must find the stored SMTP host"
    );
    assert!(
        raw.iter()
            .any(|(_, bytes)| contains(bytes, b"site-key-public")),
        "positive control: the raw scan must find the stored CAPTCHA site key"
    );
    for (what, secret) in &seeded.phase3_secrets {
        for (file, bytes) in &raw {
            assert!(
                !contains(bytes, secret),
                "{what} found in plaintext in {file}"
            );
        }
    }
    drop(storage);

    let pool = inspect(&path).await;
    let columns = all_columns(&pool).await;
    assert!(
        columns.len() > 50,
        "the inspection must see the whole schema"
    );

    // Positive control: the scanner finds values that are stored in plaintext (TEXT and BLOB),
    // so the negative assertions below cannot pass vacuously.
    assert!(
        hits_anywhere(&pool, &columns, b"Example App").await > 0,
        "the scanner must find the stored client name"
    );
    assert!(
        hits_anywhere(&pool, &columns, &secret_hash(&seeded.markers[0].0)).await > 0,
        "the scanner must find a stored digest inside a BLOB"
    );

    // The outbox row is stored (sealed): the scanner sees its template and the sealed envelope.
    assert!(
        hits_anywhere(&pool, &columns, b"verification").await > 0,
        "the scanner must find the stored outbox template"
    );
    assert!(
        hits_anywhere(&pool, &columns, b"sealed").await > 0,
        "the outbox payload must be stored as a sealed envelope"
    );

    // No column of any table may contain a plaintext marker, as TEXT or inside a BLOB. This
    // includes the single-use token inside the email link.
    for m in &seeded.sealed_markers {
        assert_eq!(
            hits_anywhere(&pool, &columns, m.as_bytes()).await,
            0,
            "the email link marker {m} is stored in plaintext"
        );
        assert_eq!(
            hits_anywhere(&pool, &columns, b"token=").await,
            0,
            "no email link is stored in plaintext"
        );
    }
    for (m, _, _) in &seeded.markers {
        assert_eq!(
            hits_anywhere(&pool, &columns, m.as_bytes()).await,
            0,
            "the plaintext marker {m} is stored somewhere"
        );
    }
    for (what, secret) in &seeded.phase3_secrets {
        assert_eq!(
            hits_anywhere(&pool, &columns, secret).await,
            0,
            "{what} is stored in plaintext in some column"
        );
    }
    let recovery_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_code")
        .fetch_one(&pool)
        .await
        .expect("count recovery codes");
    assert_eq!(
        recovery_rows, 10,
        "every recovery code is stored, as a digest"
    );

    // Every hash column holds exactly 32 bytes.
    for (table, column) in HASH_COLUMNS {
        assert!(
            columns.iter().any(|(t, c)| t == table && c == column),
            "{table}.{column} must exist"
        );
        let bad: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM \"{table}\"
              WHERE \"{column}\" IS NOT NULL
                AND (typeof(\"{column}\") != 'blob' OR length(\"{column}\") != 32)"
        )))
        .fetch_one(&pool)
        .await
        .expect("check hash column");
        assert_eq!(bad, 0, "{table}.{column} must only hold 32-byte hashes");
    }

    // ... and the seeded rows store exactly the digest of their marker.
    for (m, table, column) in &seeded.markers {
        let found: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM \"{table}\" WHERE \"{column}\" = ?1"
        )))
        .bind(secret_hash(m).as_slice())
        .fetch_one(&pool)
        .await
        .expect("find digest");
        assert_eq!(found, 1, "{table}.{column} must store the digest of {m}");
    }
}

/// Release 0.3 (SEC-03): an upstream connection secret is stored only KEK-sealed under
/// `CONNECTION_SECRET_PURPOSE` with `connection_aad(tenant, id)`. The raw database file and WAL
/// never contain the plaintext (before and after a WAL checkpoint), the sealed value opens only
/// with its own tenant and connection id, and published branding CSS (not a secret) is found by
/// the same scan as a positive control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_secret_sealed_at_rest() {
    use anvil_core::model::{
        BrandingScope, CONNECTION_SECRET_PURPOSE, ConnectionId, LogoChange, NewConnection,
        connection_aad,
    };
    use anvil_storage::contract::{new_branding_update, new_connection};

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("anvil.db");
    let storage = SqliteStorage::connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");
    let kek = Kek::generate();

    let tenant = new_tenant();
    let t = storage
        .tenants()
        .create(&tenant)
        .await
        .expect("create tenant")
        .id;
    let other_tenant = TenantId::new_v7();

    let secret = marker("connection-secret");
    let template = new_connection();
    let id = template.id;
    let sealed = kek
        .seal(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(t, id),
            secret.as_bytes(),
        )
        .expect("seal connection secret");
    let connection = NewConnection {
        secret_enc: Some(sealed.clone()),
        ..template
    };
    storage
        .connections()
        .create(t, &connection)
        .await
        .expect("create connection");

    let mut branding = new_branding_update("#123456", LogoChange::Keep);
    let css = format!(
        ".css-control-{} {{ color: red; }}",
        uuid::Uuid::now_v7().simple()
    );
    branding.custom_css = Some(css.clone());
    storage
        .branding()
        .put(t, &BrandingScope::Tenant.scope_key(), &branding, now_ms())
        .await
        .expect("put branding");

    // The stored value round-trips exactly and opens only with its own AAD.
    let stored = storage
        .connections()
        .get(t, id)
        .await
        .expect("get connection")
        .expect("connection exists")
        .secret_enc
        .expect("secret stored");
    assert_eq!(
        stored, sealed,
        "the sealed secret is stored exactly as given"
    );
    let opened = kek
        .open(CONNECTION_SECRET_PURPOSE, &connection_aad(t, id), &stored)
        .expect("opens with its own tenant and connection id");
    assert_eq!(opened.as_slice(), secret.as_bytes());
    assert!(
        kek.open(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(other_tenant, id),
            &stored
        )
        .is_err(),
        "a sealed secret must not open under another tenant"
    );
    assert!(
        kek.open(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(t, ConnectionId::new_v7()),
            &stored
        )
        .is_err(),
        "a sealed secret must not open under another connection id"
    );
    assert!(
        kek.open(TOTP_SEED_PURPOSE, &connection_aad(t, id), &stored)
            .is_err(),
        "a sealed secret must not open under another purpose"
    );

    // Raw scan while open (database file + WAL).
    let raw = raw_database_bytes(&path);
    assert!(
        raw.iter().any(|(_, bytes)| contains(bytes, css.as_bytes())),
        "positive control: the raw scan must find the stored branding CSS"
    );
    for (file, bytes) in &raw {
        assert!(
            !contains(bytes, secret.as_bytes()),
            "the connection secret is in plaintext in {file}"
        );
    }
    drop(storage);

    // Checkpoint the WAL into the main file and scan the main file again.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .expect("plain connection");
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .expect("checkpoint");
    pool.close().await;
    let main = std::fs::read(&path).expect("read database file");
    assert!(
        contains(&main, css.as_bytes()),
        "positive control: the checkpointed file holds the branding CSS"
    );
    assert!(
        !contains(&main, secret.as_bytes()),
        "the connection secret is in plaintext in the checkpointed database file"
    );

    // Column scan: no TEXT or BLOB cell holds the plaintext; the sealed bytes are in secret_enc.
    let pool = inspect(&path).await;
    let columns = all_columns(&pool).await;
    assert_eq!(hits_anywhere(&pool, &columns, secret.as_bytes()).await, 0);
    assert_eq!(hits_anywhere(&pool, &columns, &sealed).await, 1);
}

/// Release 1.0 (Phase 6) secrets, seeded through the storage ports exactly as the core services
/// store them:
///
/// - an organization invitation: only `SecretHash(secret_hash(token))` in `org_invitation`, and
///   its email (whose link carries the token) sealed into the outbox with `seal_payload`;
/// - an org-owned OIDC connection whose client secret is KEK-sealed under
///   `CONNECTION_SECRET_PURPOSE` with `connection_aad`, like a tenant connection;
/// - a login flow whose JSON state holds a verified SAML identity sealed under
///   `SAML_IDENTITY_PURPOSE` and the invitation return target sealed under `RETURN_TO_PURPOSE`
///   (06-31, `return_to_sealed`), both with `upstream_aad(tenant, flow)`.
///
/// Neither the invitation token (alone or as `token=` in a link or return target), the
/// connection secret nor the SAML subject and email may appear in any column or in the raw
/// database file and WAL (before and after a checkpoint). The invitation hash is stored exactly
/// once, in `org_invitation.token_hash`.
///
/// Public by design and therefore positive controls of the scan, not secrets: the DNS TXT
/// challenge token of an org domain (it is published in DNS) and the IdP signing certificates of
/// a SAML connection (published in the IdP metadata).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_1_0_secrets_never_stored_plaintext() {
    use anvil_core::flow::engine::FlowState;
    use anvil_core::flow::login::{LoginState, SamlPending};
    use anvil_core::flow::upstream::{SealedIdentity, upstream_aad};
    use anvil_core::model::{CONNECTION_SECRET_PURPOSE, EmailKind, connection_aad};
    use anvil_core::policy::return_to::parse_return_target;
    use anvil_core::service::flow::RETURN_TO_PURPOSE;
    use anvil_core::service::saml::SAML_IDENTITY_PURPOSE;
    use anvil_jose::encoding::random_token;
    use anvil_storage::contract::{
        new_invitation, new_org, new_org_connection, new_org_domain, new_saml_connection,
        unique_domain,
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("anvil.db");
    let storage = SqliteStorage::connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");
    let kek = Kek::generate();
    let t = storage
        .tenants()
        .create(&new_tenant())
        .await
        .expect("tenant")
        .id;
    let org = storage
        .organizations()
        .create(t, &new_org())
        .await
        .expect("organization");

    // Invitation: the token is stored only as its digest; the email with the link is sealed.
    let token = random_token();
    let token_hash = hash_of(&token);
    let invitation = anvil_core::model::NewOrgInvitation {
        token_hash,
        ..new_invitation(org.id, "invitee@example.test", &[], Duration::days(7))
    };
    storage
        .organizations()
        .create_invitation(t, &invitation)
        .await
        .expect("create_invitation");
    let vars = BTreeMap::from([
        ("tenant_name".to_owned(), "Acme".to_owned()),
        ("org_name".to_owned(), org.display_name.clone()),
        ("email".to_owned(), invitation.email.clone()),
        ("inviter".to_owned(), "Acme".to_owned()),
        (
            "link".to_owned(),
            format!("https://id.example.test/ui/invitation?token={token}"),
        ),
        ("expires_in".to_owned(), "7 days".to_owned()),
    ]);
    storage
        .outbox()
        .enqueue(
            t,
            &NewEmail {
                id: OutboxId::new_v7(),
                to: invitation.email.clone(),
                template: EmailKind::OrgInvitation.as_str().to_owned(),
                payload: seal_payload(&kek, t, &vars).expect("seal payload"),
                created_at: now_ms(),
                expires_at: now_ms() + Duration::days(7),
            },
        )
        .await
        .expect("enqueue invitation email");

    // Org-owned OIDC connection with a sealed client secret.
    let connection_secret = marker("org-connection-secret");
    let template = new_org_connection(org.id);
    let connection_sealed = kek
        .seal(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(t, template.id),
            connection_secret.as_bytes(),
        )
        .expect("seal org connection secret");
    storage
        .connections()
        .create(
            t,
            &anvil_core::model::NewConnection {
                secret_enc: Some(connection_sealed.clone()),
                ..template
            },
        )
        .await
        .expect("create org connection");

    // Public by design: a SAML connection's IdP certificate and a domain's TXT challenge token.
    let saml = new_saml_connection(org.id);
    storage
        .connections()
        .create(t, &saml)
        .await
        .expect("create SAML connection");
    let domain = new_org_domain(org.id, &unique_domain(), None);
    storage
        .organizations()
        .create_domain(t, &domain)
        .await
        .expect("create domain");

    // Login flow holding a sealed SAML identity and the sealed invitation return target.
    let mut flow = new_flow(None, Duration::minutes(10));
    let subject = marker("saml-subject");
    let saml_email = format!("{}@example.test", marker("saml-email"));
    let identity = SealedIdentity {
        subject: subject.clone(),
        email: Some(saml_email.clone()),
        email_verified: true,
        given_name: None,
        family_name: None,
        name: None,
        metadata: serde_json::Map::new(),
    };
    let identity_sealed = b64url(
        &kek.seal(
            SAML_IDENTITY_PURPOSE,
            &upstream_aad(t, flow.id),
            &serde_json::to_vec(&identity).expect("encode identity"),
        )
        .expect("seal SAML identity"),
    );
    let target = parse_return_target(&format!("/ui/invitation?token={token}"))
        .expect("an allowlisted return target");
    let return_to_sealed = b64url(
        &kek.seal(
            RETURN_TO_PURPOSE,
            &upstream_aad(t, flow.id),
            target.as_path().as_bytes(),
        )
        .expect("seal return target"),
    );
    flow.state = serde_json::to_string(&FlowState::Login(LoginState {
        saml: Some(Box::new(SamlPending {
            connection_id: saml.id,
            request_id: format!("_{}", uuid::Uuid::now_v7().simple()),
            relay_state_hash: b64url(&secret_hash("relay-state")),
            binding_hash: b64url(&secret_hash("binding-cookie")),
            created_at: now_ms().unix_timestamp(),
            identity_sealed: Some(identity_sealed.clone()),
        })),
        return_to_sealed: Some(return_to_sealed.clone()),
        ..LoginState::default()
    }))
    .expect("encode flow state");
    storage.flows().create(t, &flow).await.expect("create flow");

    // The sealed values open only under their own flow (AAD binding).
    let other_flow = anvil_core::model::FlowId::new_v7();
    for (purpose, sealed) in [
        (SAML_IDENTITY_PURPOSE, &identity_sealed),
        (RETURN_TO_PURPOSE, &return_to_sealed),
    ] {
        let raw = anvil_jose::encoding::b64url_decode(sealed).expect("base64url");
        assert!(kek.open(purpose, &upstream_aad(t, flow.id), &raw).is_ok());
        assert!(
            kek.open(purpose, &upstream_aad(t, other_flow), &raw)
                .is_err(),
            "a value sealed into one flow must not open under another"
        );
    }

    let token_link = format!("token={token}");
    let plaintexts: Vec<(&str, &[u8])> = vec![
        ("invitation token", token.as_bytes()),
        ("invitation token in a link", token_link.as_bytes()),
        ("org connection secret", connection_secret.as_bytes()),
        ("sealed SAML subject", subject.as_bytes()),
        ("sealed SAML email", saml_email.as_bytes()),
    ];
    let cert_body = b"TUlJQ29udHJhY3Q=";

    // Raw scan while the storage is open (database file + WAL).
    let raw = raw_database_bytes(&path);
    assert!(
        raw.iter().any(|(_, bytes)| contains(bytes, cert_body)),
        "positive control: the raw scan must find the public SAML certificate"
    );
    for (what, secret) in &plaintexts {
        for (file, bytes) in &raw {
            assert!(!contains(bytes, secret), "{what} in plaintext in {file}");
        }
    }
    drop(storage);

    // Checkpoint the WAL and scan the main file again.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .expect("plain connection");
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .expect("checkpoint");
    pool.close().await;
    let main = std::fs::read(&path).expect("read database file");
    assert!(
        contains(&main, domain.token.as_bytes()),
        "positive control: the checkpointed file holds the public domain challenge token"
    );
    for (what, secret) in &plaintexts {
        assert!(
            !contains(&main, secret),
            "{what} in plaintext in the checkpointed database file"
        );
    }

    // Column scan.
    let pool = inspect(&path).await;
    let columns = all_columns(&pool).await;
    for (what, secret) in &plaintexts {
        assert_eq!(
            hits_anywhere(&pool, &columns, secret).await,
            0,
            "{what} is stored in plaintext in some column"
        );
    }
    // Positive controls: public values, the sealed state keys and the sealed bytes are found.
    assert!(hits_anywhere(&pool, &columns, cert_body).await > 0);
    assert!(hits_anywhere(&pool, &columns, domain.token.as_bytes()).await > 0);
    assert_eq!(
        hits_anywhere(&pool, &columns, return_to_sealed.as_bytes()).await,
        1,
        "the flow state holds the sealed return target"
    );
    assert_eq!(
        hits_anywhere(&pool, &columns, identity_sealed.as_bytes()).await,
        1,
        "the flow state holds the sealed SAML identity"
    );
    assert_eq!(
        hits_anywhere(&pool, &columns, &connection_sealed).await,
        1,
        "the org connection secret is stored sealed"
    );
    // The invitation digest is stored once, as exactly 32 bytes in org_invitation.token_hash.
    assert_eq!(
        hits_anywhere(&pool, &columns, &token_hash.0).await,
        1,
        "the invitation digest is stored once"
    );
    let found: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM org_invitation WHERE token_hash = ?1 AND length(token_hash) = 32",
    )
    .bind(token_hash.0.as_slice())
    .fetch_one(&pool)
    .await
    .expect("find invitation digest");
    assert_eq!(found, 1, "org_invitation.token_hash holds the token digest");
}

/// Release 1.0 final (Phase 7) secrets, seeded through the storage ports the way the core
/// services store them: a Firebase scrypt hash profile whose signer key is sealed with
/// `hash_profile::seal_signer_key` (purpose `PROFILE_SIGNER_KEY_PURPOSE`, AAD bound to tenant and
/// profile), a pushed authorization request stored under the hash of its `request_uri`
/// (`oauth::par::new_request_uri`), and a token-bound login flow (headless native mode) whose flow
/// token is stored only as the flow's cookie hash. Neither the signer key (raw, base64 or base64url), the
/// `request_uri` (or its random part) nor the flow token may appear in the database file, its WAL
/// (before and after a checkpoint) or any column; the stored hashes and the sealed key are
/// positive controls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_1_0_final_secrets_never_stored_plaintext() {
    use anvil_core::flow::engine::FlowState;
    use anvil_core::flow::login::{FlowBindingKind, LoginState};
    use anvil_core::model::{
        NewPasswordHashProfile, NewPushedRequest, PROFILE_SIGNER_KEY_PURPOSE, ProfileKind,
        profile_signer_key_aad,
    };
    use anvil_core::oauth::par::{REQUEST_URI_PREFIX, new_request_uri};
    use anvil_core::service::flow::check_token_binding;
    use anvil_core::service::hash_profile::{open_signer_key, seal_signer_key};
    use anvil_jose::encoding::{b64std, random_bytes, random_token};

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("anvil.db");
    let storage = SqliteStorage::connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");
    let kek = Kek::generate();
    let t = storage
        .tenants()
        .create(&new_tenant())
        .await
        .expect("tenant")
        .id;

    // Firebase scrypt hash profile: the signer key is stored only KEK-sealed.
    let signer_key = marker("firebase-signer-key");
    let profile_id = uuid::Uuid::now_v7();
    let signer_sealed =
        seal_signer_key(&kek, t, profile_id, signer_key.as_bytes()).expect("seal signer key");
    storage
        .password_profiles()
        .create(
            t,
            &NewPasswordHashProfile {
                id: profile_id,
                name: format!("firebase-{}", profile_id.simple()),
                kind: ProfileKind::FirebaseScrypt,
                salt_separator: vec![0x42, 0x00, 0xff],
                rounds: 8,
                mem_cost: 14,
                signer_key_sealed: signer_sealed.clone(),
                created_at: now_ms(),
            },
        )
        .await
        .expect("create hash profile");
    let stored = storage
        .password_profiles()
        .get(t, profile_id)
        .await
        .expect("get hash profile")
        .expect("the profile exists");
    let opened = kek
        .open(
            PROFILE_SIGNER_KEY_PURPOSE,
            &profile_signer_key_aad(t, profile_id),
            &stored.signer_key_sealed,
        )
        .expect("open signer key");
    assert_eq!(opened.to_vec(), signer_key.as_bytes());
    assert!(
        open_signer_key(&kek, t, uuid::Uuid::now_v7(), &stored.signer_key_sealed).is_err(),
        "the sealed signer key must not open under another profile"
    );

    // Pushed authorization request: stored under the hash of its request_uri only.
    let client = storage
        .clients()
        .create(t, &new_client())
        .await
        .expect("client");
    let (request_uri, uri_hash) = new_request_uri(random_bytes());
    let uri_random = request_uri
        .strip_prefix(REQUEST_URI_PREFIX)
        .expect("PAR prefix")
        .to_owned();
    let now = now_ms();
    storage
        .grants()
        .create_pushed_request(
            t,
            &NewPushedRequest {
                request_uri_hash: uri_hash,
                client_id: client.client_id.clone(),
                params: serde_json::json!({
                    "response_type": "code",
                    "client_id": client.client_id,
                    "redirect_uri": "https://app.example.test/cb",
                    "scope": "openid",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "code_challenge_method": "S256",
                }),
                created_at: now,
                expires_at: now + Duration::seconds(60),
            },
        )
        .await
        .expect("create pushed request");

    // Token-bound native login flow: the flow token is stored only as the cookie hash.
    let flow_token = random_token();
    let mut flow = new_flow(None, Duration::minutes(10));
    flow.cookie_hash = hash_of(&flow_token);
    flow.state = serde_json::to_string(&FlowState::Login(LoginState {
        binding: FlowBindingKind::Token,
        ..LoginState::default()
    }))
    .expect("encode flow state");
    storage.flows().create(t, &flow).await.expect("create flow");
    let stored_flow = storage
        .flows()
        .get(t, flow.id, now_ms())
        .await
        .expect("get flow")
        .expect("the flow exists");
    assert!(
        check_token_binding(&stored_flow, &flow_token, now_ms()).is_ok(),
        "the seeded flow is token-bound to the flow token"
    );

    let signer_b64url = b64url(signer_key.as_bytes());
    let signer_b64std = b64std(signer_key.as_bytes());
    let plaintexts: Vec<(&str, &[u8])> = vec![
        ("hash profile signer key", signer_key.as_bytes()),
        (
            "hash profile signer key (base64url)",
            signer_b64url.as_bytes(),
        ),
        ("hash profile signer key (base64)", signer_b64std.as_bytes()),
        ("PAR request_uri", request_uri.as_bytes()),
        ("PAR request_uri random part", uri_random.as_bytes()),
        ("native flow token", flow_token.as_bytes()),
    ];

    // Raw scan while the storage is open (database file + WAL).
    let raw = raw_database_bytes(&path);
    assert!(
        raw.iter().any(|(_, bytes)| contains(bytes, &signer_sealed)),
        "positive control: the raw scan must find the sealed signer key"
    );
    for (what, secret) in &plaintexts {
        for (file, bytes) in &raw {
            assert!(!contains(bytes, secret), "{what} in plaintext in {file}");
        }
    }
    drop(storage);

    // Checkpoint the WAL and scan the main file again.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .expect("plain connection");
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .expect("checkpoint");
    pool.close().await;
    let main = std::fs::read(&path).expect("read database file");
    assert!(
        contains(&main, &uri_hash.0),
        "positive control: the checkpointed file holds the request_uri hash"
    );
    for (what, secret) in &plaintexts {
        assert!(
            !contains(&main, secret),
            "{what} in plaintext in the checkpointed database file"
        );
    }

    // Column scan.
    let pool = inspect(&path).await;
    let columns = all_columns(&pool).await;
    for (table, column) in [
        ("password_hash_profile", "signer_key_enc"),
        ("pushed_authorization_request", "uri_hash"),
        ("pushed_authorization_request", "params"),
        ("flow", "cookie_hash"),
        ("flow", "state"),
    ] {
        assert!(
            columns.iter().any(|(t, c)| t == table && c == column),
            "the scan must cover {table}.{column}"
        );
    }
    for (what, secret) in &plaintexts {
        assert_eq!(
            hits_anywhere(&pool, &columns, secret).await,
            0,
            "{what} is stored in plaintext in some column"
        );
    }
    assert_eq!(
        hits_anywhere(&pool, &columns, &signer_sealed).await,
        1,
        "the signer key is stored sealed, once"
    );
    let found: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pushed_authorization_request
          WHERE uri_hash = ?1 AND length(uri_hash) = 32",
    )
    .bind(uri_hash.0.as_slice())
    .fetch_one(&pool)
    .await
    .expect("find request_uri hash");
    assert_eq!(
        found, 1,
        "pushed_authorization_request.uri_hash holds the hash"
    );
    let flow_hash = hash_of(&flow_token);
    let found: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM flow WHERE cookie_hash = ?1 AND length(cookie_hash) = 32",
    )
    .bind(flow_hash.0.as_slice())
    .fetch_one(&pool)
    .await
    .expect("find flow token hash");
    assert_eq!(found, 1, "flow.cookie_hash holds the flow token hash");
}
