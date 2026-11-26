//! Secrets at rest (ARCHITECTURE §6.2): `secrets_never_stored_plaintext` row inspection.
//!
//! Seeds an authorization code, a refresh token, a browser session, a flow, a client secret, a
//! setup token, a self-service token and a replay guard through the ports, each derived from a
//! known plaintext marker hashed with `anvil_jose::encoding::secret_hash`, plus the recovery email
//! whose link carries a marker token (payload sealed with the KEK, as the core services store
//! it). Then it scans every
//! text, text[], jsonb and bytea column of every table with a plain sqlx connection and asserts
//! that no marker appears anywhere, and that every hash column holds exactly the 32-byte hash.
//!
//! Phase 3 secrets are seeded the way the core services store them: a TOTP seed sealed with
//! `Kek::seal(TOTP_SEED_PURPOSE, credential_aad(id), seed)`, recovery codes hashed with
//! `recovery_code_hash`, an SMTP password sealed with `SMTP_PASSWORD_PURPOSE` and a captcha
//! secret sealed with `CAPTCHA_SECRET_PURPOSE` in the tenant settings. None of the plaintexts
//! (seed bytes, hex and base32; each recovery code; the SMTP password; the captcha secret) may
//! appear in any column.
//!
//! Release 0.4 secrets: an initial access token and two registration access tokens (one stored
//! with the dynamic client, one set by `set_registration_token`) are stored only as hashes, and a
//! webhook endpoint's signing secrets (current and, after a rotation, previous) only sealed with
//! `Kek::seal(WEBHOOK_SECRET_PURPOSE, webhook_aad(tenant, id), secret)`. Neither the `whsec_`
//! strings nor their decoded key bytes may appear in any column.
//!
//! Release 1.0 (`release_1_0_secrets_never_stored_plaintext`): an organization invitation token
//! (digest only; its email sealed), an org-owned connection's client secret (KEK-sealed) and a
//! login flow holding a sealed SAML identity and a sealed invitation return target
//! (`return_to_sealed`). Domain challenge tokens and SAML certificates are public by design and
//! serve as positive controls.
//!
//! Run with `cargo test`, not nextest: the container is shared per test binary.

mod support;

use std::collections::BTreeMap;

use anvil_core::model::{
    CAPTCHA_SECRET_PURPOSE, CaptchaProvider, CaptchaSettings, ClientSource, CredentialId, FlowKind,
    InitialAccessTokenId, NewBrowserSession, NewEmail, NewFlow, NewInitialAccessToken,
    NewRefreshToken, NewSelfServiceToken, NewSetupToken, NewTotp, NewWebhookEndpoint, OutboxId,
    RecoveryCodeHash, ReplayKind, SMTP_PASSWORD_PURPOSE, SecretHash, SelfServiceKind, SmtpSettings,
    SmtpTls, TOTP_SEED_PURPOSE, TenantSettings, TenantUpdate, WEBHOOK_SECRET_PURPOSE,
    WebhookEndpointId, WebhookEventType, credential_aad, seal_payload, webhook_aad,
};
use anvil_jose::encoding::{b64url, secret_hash};
use anvil_jose::webhook::{generate_webhook_secret, parse_webhook_secret};
use anvil_jose::{Kek, TotpSecret, generate_recovery_codes, recovery_code_hash};
use anvil_storage::contract::*;
use sqlx::{Connection, PgConnection, Row};
use time::Duration;
use uuid::Uuid;

/// A plaintext secret marker and its stored hash.
struct Marker {
    plain: String,
    hash: SecretHash,
}

fn marker(kind: &str) -> Marker {
    let plain = format!("plaintext-marker-{kind}-{}", Uuid::now_v7().simple());
    let hash = SecretHash(secret_hash(&plain));
    Marker { plain, hash }
}

/// Identifiers read from information_schema are only interpolated if they are plain names.
fn ident(name: &str) -> String {
    assert!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "unexpected identifier {name:?}"
    );
    format!("\"{name}\"")
}

async fn count(conn: &mut PgConnection, sql: String, bind_text: &str, bind_bytes: &[u8]) -> i64 {
    sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
        .bind(bind_text)
        .bind(bind_bytes)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .get::<i64, _>(0)
}

/// Every `table.column` (text, text[], jsonb or bytea) that contains `plain`.
async fn locations(
    conn: &mut PgConnection,
    columns: &[(String, String, String, String)],
    plain: &str,
) -> Vec<String> {
    let mut found = Vec::new();
    for (table, column, data_type, udt) in columns {
        let (t, c) = (ident(table), ident(column));
        // $1 = the value as text, $2 = the value as bytes.
        let predicate = match data_type.as_str() {
            "text" => format!("strpos({c}, $1) > 0 AND $2 IS NOT NULL"),
            "jsonb" => format!("strpos({c}::text, $1) > 0 AND $2 IS NOT NULL"),
            "bytea" => format!("position($2 in {c}) > 0 AND $1 IS NOT NULL"),
            "ARRAY" if udt == "_text" => {
                format!("strpos(array_to_string({c}, ' '), $1) > 0 AND $2 IS NOT NULL")
            }
            other => panic!("unexpected column type {other} ({udt}) for {table}.{column}"),
        };
        let hits = count(
            conn,
            format!("SELECT count(*) FROM {t} WHERE {predicate}"),
            plain,
            plain.as_bytes(),
        )
        .await;
        if hits > 0 {
            found.push(format!("{table}.{column}"));
        }
    }
    found
}

/// Every bytea column that contains the raw `bytes` (for secrets that are not valid text).
async fn raw_bytes_locations(
    conn: &mut PgConnection,
    columns: &[(String, String, String, String)],
    bytes: &[u8],
) -> Vec<String> {
    let mut found = Vec::new();
    for (table, column, data_type, _) in columns {
        if data_type != "bytea" {
            continue;
        }
        let (t, c) = (ident(table), ident(column));
        let hits = count(
            conn,
            format!("SELECT count(*) FROM {t} WHERE position($2 in {c}) > 0 AND $1 IS NOT NULL"),
            "",
            bytes,
        )
        .await;
        if hits > 0 {
            found.push(format!("{table}.{column}"));
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secrets_never_stored_plaintext() {
    let s = support::postgres().await;
    let url = s
        ._guard
        .downcast_ref::<String>()
        .expect("the Postgres test guard holds the database URL")
        .clone();

    // --- seed through the ports ----------------------------------------------------------
    let ctx = seed_grant_ctx(&s).await;
    let now = now_ms();

    let code = marker("code");
    let family = new_family(&ctx, Duration::days(30));
    let mut new_code_row = new_code(&ctx, &family, Duration::minutes(5));
    new_code_row.code_hash = code.hash;
    s.storage
        .grants()
        .create_code(ctx.tenant, &new_code_row, &family)
        .await
        .expect("create_code");

    let refresh = marker("refresh");
    s.storage
        .grants()
        .create_refresh_token(
            ctx.tenant,
            &NewRefreshToken {
                token_hash: refresh.hash,
                ..new_refresh(family.id, None, Duration::days(1))
            },
        )
        .await
        .expect("create_refresh_token");

    let session = marker("session");
    s.storage
        .sessions()
        .create(
            ctx.tenant,
            &NewBrowserSession {
                token_hash: session.hash,
                ..new_session(ctx.user.id, Duration::hours(8), Duration::minutes(30))
            },
        )
        .await
        .expect("create session");

    let csrf = marker("csrf");
    let cookie = marker("flowcookie");
    s.storage
        .flows()
        .create(
            ctx.tenant,
            &NewFlow {
                kind: FlowKind::Login,
                csrf_hash: csrf.hash,
                cookie_hash: cookie.hash,
                ..new_flow(None, Duration::minutes(15))
            },
        )
        .await
        .expect("create flow");

    let client_secret = marker("clientsecret");
    assert!(
        s.storage
            .clients()
            .set_secret_hash(
                ctx.tenant,
                &ctx.client.client_id,
                Some(client_secret.hash),
                now
            )
            .await
            .expect("set_secret_hash")
    );

    let setup = marker("setup");
    s.storage
        .setup()
        .create_setup_token(&NewSetupToken {
            token_hash: setup.hash,
            created_at: now,
            expires_at: now + Duration::hours(1),
        })
        .await
        .expect("create_setup_token");

    let self_service = marker("selfservice");
    // The recovery email carrying the token link, sealed as the flow service stores it.
    let link = marker("outboxlink");
    let vars = BTreeMap::from([
        ("tenant_name".to_owned(), "Acme".to_owned()),
        ("email".to_owned(), ctx.user.email.clone()),
        (
            "link".to_owned(),
            format!("https://id.example.test/ui/recovery?token={}", link.plain),
        ),
        ("expires_in".to_owned(), "1 hour".to_owned()),
    ]);
    let recovery_email = NewEmail {
        id: OutboxId::new_v7(),
        to: ctx.user.email.clone(),
        template: "recovery".to_owned(),
        payload: seal_payload(&Kek::generate(), ctx.tenant, &vars).expect("seal payload"),
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    s.storage
        .users()
        .issue_self_service_token(
            ctx.tenant,
            &NewSelfServiceToken {
                token_hash: self_service.hash,
                ..new_self_service_token(
                    SelfServiceKind::Recovery,
                    ctx.user.id,
                    &ctx.user.email,
                    Duration::hours(1),
                )
            },
            Some(&recovery_email),
        )
        .await
        .expect("issue_self_service_token");

    let jti = marker("jti");
    s.storage
        .grants()
        .record_jti(
            ctx.tenant,
            ReplayKind::ClientAssertionJti,
            &jti.hash,
            now + Duration::minutes(5),
            now,
        )
        .await
        .expect("record_jti");

    // --- Phase 3 secrets, sealed or hashed as the core services store them ---------------
    let kek = Kek::generate();

    let seed = TotpSecret::generate();
    let totp_id = CredentialId::new_v7();
    let recovery_plain = generate_recovery_codes(10).expect("generate recovery codes");
    let recovery_hashes: Vec<RecoveryCodeHash> = recovery_plain
        .iter()
        .map(|c| RecoveryCodeHash(recovery_code_hash(&kek, c)))
        .collect();
    s.storage
        .users()
        .create_totp(
            ctx.tenant,
            ctx.user.id,
            &NewTotp {
                id: totp_id,
                secret_enc: kek
                    .seal(TOTP_SEED_PURPOSE, &credential_aad(totp_id), seed.as_bytes())
                    .expect("seal TOTP seed"),
                created_at: now,
            },
            &recovery_hashes,
            now,
        )
        .await
        .expect("create_totp");

    let smtp_password = format!("plaintext-marker-smtp-{}", Uuid::now_v7().simple());
    s.storage
        .mail_settings()
        .put_smtp(
            ctx.tenant,
            &SmtpSettings {
                host: "smtp.example.test".to_owned(),
                port: 587,
                username: Some("mailer".to_owned()),
                password_enc: Some(
                    kek.seal(
                        SMTP_PASSWORD_PURPOSE,
                        ctx.tenant.0.as_bytes(),
                        smtp_password.as_bytes(),
                    )
                    .expect("seal SMTP password"),
                ),
                from: "noreply@example.test".to_owned(),
                tls: SmtpTls::Starttls,
                updated_at: now,
            },
        )
        .await
        .expect("put_smtp");

    let captcha_secret = format!("plaintext-marker-captcha-{}", Uuid::now_v7().simple());
    s.storage
        .tenants()
        .update(
            ctx.tenant,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    captcha: Some(CaptchaSettings {
                        provider: CaptchaProvider::Turnstile,
                        site_key: "site-key".to_owned(),
                        secret_sealed: b64url(
                            &kek.seal(
                                CAPTCHA_SECRET_PURPOSE,
                                ctx.tenant.0.as_bytes(),
                                captcha_secret.as_bytes(),
                            )
                            .expect("seal captcha secret"),
                        ),
                    }),
                    ..TenantSettings::default()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");

    // --- Release 0.4 secrets ----------------------------------------------------------------
    let iat = marker("iat");
    s.storage
        .registration()
        .create_iat(
            ctx.tenant,
            &NewInitialAccessToken {
                id: InitialAccessTokenId::new_v7(),
                description: "plaintext scan".to_owned(),
                token_hash: iat.hash,
                expires_at: Some(now + Duration::hours(24)),
                uses_remaining: Some(1),
                created_at: now,
            },
        )
        .await
        .expect("create_iat");

    let rat = marker("rat");
    let mut dynamic = new_client();
    dynamic.client_id = format!("dyn-{}", Uuid::now_v7().simple());
    dynamic.registration_source = ClientSource::Dynamic;
    dynamic.registration_access_token_hash = Some(rat.hash);
    s.storage
        .clients()
        .create(ctx.tenant, &dynamic)
        .await
        .expect("dynamic client");
    let rotated_rat = marker("ratrotated");
    let mut rotated = new_client();
    rotated.client_id = format!("dyn-{}", Uuid::now_v7().simple());
    rotated.registration_source = ClientSource::Dynamic;
    s.storage
        .clients()
        .create(ctx.tenant, &rotated)
        .await
        .expect("second dynamic client");
    assert!(
        s.storage
            .clients()
            .set_registration_token(ctx.tenant, &rotated.client_id, Some(&rotated_rat.hash), now)
            .await
            .expect("set_registration_token"),
        "the second dynamic client exists"
    );

    let endpoint_id = WebhookEndpointId::new_v7();
    let seal_webhook = |secret: &str| {
        kek.seal(
            WEBHOOK_SECRET_PURPOSE,
            &webhook_aad(ctx.tenant, endpoint_id),
            secret.as_bytes(),
        )
        .expect("seal webhook secret")
    };
    let webhook_secret = generate_webhook_secret();
    let rotated_webhook_secret = generate_webhook_secret();
    s.storage
        .webhooks()
        .create_endpoint(
            ctx.tenant,
            &NewWebhookEndpoint {
                id: endpoint_id,
                name: "plaintext-scan".to_owned(),
                url: "https://hooks.example.test/anvil".to_owned(),
                events: vec![WebhookEventType::UserCreated],
                enabled: true,
                secret_enc: seal_webhook(&webhook_secret),
                created_at: now,
            },
        )
        .await
        .expect("create_endpoint");
    assert!(
        s.storage
            .webhooks()
            .rotate_secret(
                ctx.tenant,
                endpoint_id,
                &seal_webhook(&rotated_webhook_secret),
                now + Duration::hours(24),
                now,
            )
            .await
            .expect("rotate_secret"),
        "the endpoint exists"
    );
    let webhook_keys = [
        parse_webhook_secret(&webhook_secret).expect("key"),
        parse_webhook_secret(&rotated_webhook_secret).expect("key"),
    ];

    let seed_hex: String = seed.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let mut phase3_plain: Vec<(String, String)> = vec![
        (
            "TOTP seed (base32)".to_owned(),
            seed.to_base32().to_string(),
        ),
        ("TOTP seed (hex)".to_owned(), seed_hex),
        ("SMTP password".to_owned(), smtp_password),
        ("captcha secret".to_owned(), captcha_secret),
        ("webhook secret".to_owned(), webhook_secret.to_string()),
        (
            "rotated webhook secret".to_owned(),
            rotated_webhook_secret.to_string(),
        ),
    ];
    for (i, code) in recovery_plain.iter().enumerate() {
        phase3_plain.push((format!("recovery code {i}"), code.to_string()));
    }

    let markers = [
        &code,
        &refresh,
        &session,
        &csrf,
        &cookie,
        &client_secret,
        &setup,
        &self_service,
        &jti,
        // The single-use token inside the email link.
        &link,
        &iat,
        &rat,
        &rotated_rat,
    ];

    // --- inspect the raw rows -------------------------------------------------------------
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("plain connection to the test database");

    let columns = sqlx::query(
        "SELECT table_name::text, column_name::text, data_type::text, udt_name::text
           FROM information_schema.columns
          WHERE table_schema = 'public'
            AND data_type IN ('text', 'bytea', 'jsonb', 'ARRAY')
          ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&mut conn)
    .await
    .expect("listing columns");
    let columns: Vec<(String, String, String, String)> = columns
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    assert!(
        columns.len() > 20,
        "the scan must cover the 0.1 schema, found {} columns",
        columns.len()
    );
    for (table, column) in [
        ("credential", "data"),
        ("initial_access_token", "token_hash"),
        ("client", "registration_access_token_hash"),
        ("webhook_endpoint", "secret_enc"),
        ("webhook_endpoint", "previous_secret_enc"),
        ("recovery_code", "code_hash"),
        ("smtp_settings", "password_enc"),
        ("tenant", "settings"),
    ] {
        assert!(
            columns.iter().any(|(t, c, _, _)| t == table && c == column),
            "the scan must cover {table}.{column}"
        );
    }

    for m in markers {
        let found = locations(&mut conn, &columns, &m.plain).await;
        assert!(
            found.is_empty(),
            "plaintext secret {:?} found in {found:?}",
            m.plain
        );
    }
    for (what, plain) in &phase3_plain {
        let found = locations(&mut conn, &columns, plain).await;
        assert!(found.is_empty(), "{what} found in plaintext in {found:?}");
    }
    // The raw seed bytes must not appear in any bytea column either.
    let raw_seed_hits = raw_bytes_locations(&mut conn, &columns, seed.as_bytes()).await;
    assert!(
        raw_seed_hits.is_empty(),
        "the raw TOTP seed bytes were found in {raw_seed_hits:?}"
    );
    // Nor the decoded webhook HMAC keys.
    for key in &webhook_keys {
        let hits = raw_bytes_locations(&mut conn, &columns, key).await;
        assert!(hits.is_empty(), "a raw webhook key was found in {hits:?}");
    }
    let webhook_rows = count(
        &mut conn,
        "SELECT count(*) FROM webhook_endpoint WHERE secret_enc IS NOT NULL
            AND previous_secret_enc IS NOT NULL AND $1 IS NOT NULL AND $2 IS NOT NULL"
            .to_owned(),
        "",
        &[],
    )
    .await;
    assert_eq!(
        webhook_rows, 1,
        "the endpoint stores its current and previous secrets (sealed)"
    );
    // Positive controls for the Phase 3 rows: they exist and hold the sealed/hashed forms.
    let stored_codes = count(
        &mut conn,
        "SELECT count(*) FROM recovery_code WHERE octet_length(code_hash) = 32
            AND $1 IS NOT NULL AND $2 IS NOT NULL"
            .to_owned(),
        "",
        &[],
    )
    .await;
    assert_eq!(
        stored_codes, 10,
        "every recovery code is stored as a 32-byte hash"
    );
    let stored_first = count(
        &mut conn,
        "SELECT count(*) FROM recovery_code WHERE code_hash = $2 AND $1 IS NOT NULL".to_owned(),
        "",
        &recovery_hashes[0].0,
    )
    .await;
    assert_eq!(
        stored_first, 1,
        "the recovery-code hash is stored as passed in"
    );
    let totp_rows = count(
        &mut conn,
        "SELECT count(*) FROM credential WHERE kind = 'totp' AND $1 IS NOT NULL
            AND $2 IS NOT NULL"
            .to_owned(),
        "",
        &[],
    )
    .await;
    assert_eq!(totp_rows, 1, "the TOTP credential row exists");
    let smtp_rows = count(
        &mut conn,
        "SELECT count(*) FROM smtp_settings WHERE password_enc IS NOT NULL AND $1 IS NOT NULL
            AND $2 IS NOT NULL"
            .to_owned(),
        "",
        &[],
    )
    .await;
    assert_eq!(smtp_rows, 1, "the sealed SMTP password is stored");
    let captcha_rows = locations(&mut conn, &columns, "secret_sealed").await;
    assert!(
        captcha_rows.contains(&"tenant.settings".to_owned()),
        "the captcha settings are stored (sealed) in tenant.settings, found {captcha_rows:?}"
    );

    // Positive control: the same scan finds a value that is stored in clear (the email).
    let email_found = locations(&mut conn, &columns, &ctx.user.email).await;
    assert!(
        email_found.contains(&"user.email".to_owned()),
        "the scan must find the user's email, found {email_found:?}"
    );

    // The outbox row exists and its payload is the sealed envelope, not the template variables.
    let sealed_found = locations(&mut conn, &columns, "sealed").await;
    assert!(
        sealed_found.iter().any(|l| l.starts_with("email_outbox.")),
        "the outbox payload must be stored as a sealed envelope, found {sealed_found:?}"
    );
    let link_found = locations(&mut conn, &columns, "token=").await;
    assert!(
        link_found.is_empty(),
        "no email link may be stored in plaintext, found in {link_found:?}"
    );

    // Every hash column holds exactly the 32-byte hash that was passed in.
    let hash_columns = [
        ("authorization_code", "code_hash", &code),
        ("refresh_token", "token_hash", &refresh),
        ("browser_session", "token_hash", &session),
        ("flow", "csrf_hash", &csrf),
        ("flow", "cookie_hash", &cookie),
        ("client", "secret_hash", &client_secret),
        ("admin_setup_token", "token_hash", &setup),
        ("self_service_token", "token_hash", &self_service),
        ("replay_guard", "value_hash", &jti),
        ("initial_access_token", "token_hash", &iat),
        ("client", "registration_access_token_hash", &rat),
        ("client", "registration_access_token_hash", &rotated_rat),
    ];
    for (table, column, m) in hash_columns {
        let (t, c) = (ident(table), ident(column));
        let wrong_length = count(
            &mut conn,
            format!(
                "SELECT count(*) FROM {t}
                  WHERE {c} IS NOT NULL AND octet_length({c}) <> 32
                    AND $1 IS NOT NULL AND $2 IS NOT NULL"
            ),
            "",
            &[],
        )
        .await;
        assert_eq!(
            wrong_length, 0,
            "{table}.{column} must only hold 32-byte hashes"
        );
        let stored = count(
            &mut conn,
            format!("SELECT count(*) FROM {t} WHERE {c} = $2 AND $1 IS NOT NULL"),
            "",
            m.hash.as_bytes(),
        )
        .await;
        assert_eq!(
            stored, 1,
            "{table}.{column} must hold the SHA-256 of the marker (positive control for the scan)"
        );
    }

    conn.close()
        .await
        .expect("closing the inspection connection");
}

/// SEC-03: an upstream connection's client secret is stored only KEK-sealed (purpose
/// `CONNECTION_SECRET_PURPOSE`, AAD = tenant id || connection id), in `connection.secret_enc`
/// exactly as sealed, and never appears in plaintext in any column of any table. The sealed
/// value opens only with this tenant's and this connection's AAD.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_secret_sealed_and_bound_to_tenant_and_connection() {
    use anvil_core::model::{
        BrandingScope, BrandingUpdate, CONNECTION_SECRET_PURPOSE, ConnectionId, LogoChange,
        NewConnection, TenantId, connection_aad,
    };

    let s = support::postgres().await;
    let url = s
        ._guard
        .downcast_ref::<String>()
        .expect("the Postgres test guard holds the database URL")
        .clone();
    let tenant = seed_tenant(&s).await;
    let kek = Kek::generate();

    // Seal exactly like the connection service does, then store through the port.
    let plain = format!(
        "plaintext-marker-connection-secret-{}",
        Uuid::now_v7().simple()
    );
    let id = ConnectionId::new_v7();
    let sealed = kek
        .seal(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(tenant, id),
            plain.as_bytes(),
        )
        .expect("seal connection secret");
    let connection = NewConnection {
        id,
        secret_enc: Some(sealed.clone()),
        ..new_connection()
    };
    s.storage
        .connections()
        .create(tenant, &connection)
        .await
        .expect("create connection");
    // A rotated secret goes through set_secret, sealed the same way.
    let rotated_plain = format!(
        "plaintext-marker-rotated-secret-{}",
        Uuid::now_v7().simple()
    );
    let rotated = kek
        .seal(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(tenant, id),
            rotated_plain.as_bytes(),
        )
        .expect("seal rotated secret");
    let second = seed_connection(&s, tenant).await;
    assert!(
        s.storage
            .connections()
            .set_secret(tenant, second.id, Some(&rotated), now_ms())
            .await
            .expect("set_secret")
    );
    // Branding custom CSS is stored too (not a secret; it must not disturb the scan).
    s.storage
        .branding()
        .put(
            tenant,
            &BrandingScope::Tenant.scope_key(),
            &BrandingUpdate {
                tokens: theme_tokens("#123456"),
                custom_css: Some(".brand { color: red; }".into()),
                logo: LogoChange::Keep,
            },
            now_ms(),
        )
        .await
        .expect("put branding");

    // --- inspect every column with a plain connection ---------------------------------------
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("inspection connection");
    let columns = sqlx::query(
        "SELECT table_name::text, column_name::text, data_type::text, udt_name::text
           FROM information_schema.columns
          WHERE table_schema = 'public'
            AND data_type IN ('text', 'bytea', 'jsonb', 'ARRAY')
          ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&mut conn)
    .await
    .expect("listing columns");
    let columns: Vec<(String, String, String, String)> = columns
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    assert!(
        columns
            .iter()
            .any(|(t, c, _, _)| t == "connection" && c == "secret_enc"),
        "the scan must cover connection.secret_enc"
    );
    for p in [&plain, &rotated_plain] {
        let found = locations(&mut conn, &columns, p).await;
        assert!(
            found.is_empty(),
            "the connection secret must never be stored in plaintext, found in {found:?}"
        );
        let raw = raw_bytes_locations(&mut conn, &columns, p.as_bytes()).await;
        assert!(raw.is_empty(), "plaintext secret bytes found in {raw:?}");
    }
    // Positive controls: the scan finds the sealed bytes and the clear slug.
    assert_eq!(
        raw_bytes_locations(&mut conn, &columns, &sealed).await,
        ["connection.secret_enc"],
        "the sealed secret is stored exactly as given"
    );
    assert!(
        locations(&mut conn, &columns, &connection.slug)
            .await
            .contains(&"connection.slug".to_owned()),
        "the scan must find a value stored in clear"
    );
    conn.close().await.expect("close inspection connection");

    // The stored value opens only with this tenant's and this connection's AAD.
    let stored = s
        .storage
        .connections()
        .get(tenant, id)
        .await
        .expect("get")
        .expect("connection")
        .secret_enc
        .expect("secret stored");
    assert_eq!(stored, sealed);
    let opened = kek
        .open(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(tenant, id),
            &stored,
        )
        .expect("opens with the right AAD");
    assert_eq!(opened.as_slice(), plain.as_bytes());
    for (why, aad) in [
        ("another tenant", connection_aad(TenantId::new_v7(), id)),
        ("another connection", connection_aad(tenant, second.id)),
        (
            "swapped ids",
            connection_aad(TenantId(id.0), ConnectionId(tenant.0)),
        ),
    ] {
        assert!(
            kek.open(CONNECTION_SECRET_PURPOSE, &aad, &stored).is_err(),
            "the sealed secret must not open with {why}'s AAD"
        );
    }
    assert!(
        kek.open(
            anvil_core::model::SMTP_PASSWORD_PURPOSE,
            &connection_aad(tenant, id),
            &stored
        )
        .is_err(),
        "the sealed secret must not open under another purpose"
    );
    assert!(
        Kek::generate()
            .open(
                CONNECTION_SECRET_PURPOSE,
                &connection_aad(tenant, id),
                &stored
            )
            .is_err(),
        "the sealed secret must not open with another KEK"
    );
}

/// Release 1.0 (Phase 6) secrets, seeded through the storage ports exactly as the core services
/// store them: an organization invitation (only `SecretHash(secret_hash(token))` in
/// `org_invitation`, its email with the token link sealed into the outbox), an org-owned OIDC
/// connection whose client secret is KEK-sealed like a tenant connection's, and a login flow
/// whose state holds a verified SAML identity sealed under `SAML_IDENTITY_PURPOSE` and the
/// invitation return target sealed under `RETURN_TO_PURPOSE` (06-31, `return_to_sealed`). No
/// column may contain the invitation token (alone or as `token=` in a link or return target),
/// the connection secret or the SAML subject and email; the invitation digest is stored once, in
/// `org_invitation.token_hash`.
///
/// Public by design and therefore positive controls, not secrets: an org domain's DNS TXT
/// challenge token (published in DNS) and a SAML connection's IdP signing certificates
/// (published in the IdP metadata).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn release_1_0_secrets_never_stored_plaintext() {
    use anvil_core::flow::engine::FlowState;
    use anvil_core::flow::login::{LoginState, SamlPending};
    use anvil_core::flow::upstream::{SealedIdentity, upstream_aad};
    use anvil_core::model::{
        CONNECTION_SECRET_PURPOSE, EmailKind, FlowId, NewConnection, NewOrgInvitation,
        connection_aad,
    };
    use anvil_core::policy::return_to::parse_return_target;
    use anvil_core::service::flow::RETURN_TO_PURPOSE;
    use anvil_core::service::saml::SAML_IDENTITY_PURPOSE;
    use anvil_jose::encoding::{b64url_decode, random_token};

    let s = support::postgres().await;
    let url = s
        ._guard
        .downcast_ref::<String>()
        .expect("the Postgres test guard holds the database URL")
        .clone();
    let t = seed_tenant(&s).await;
    let kek = Kek::generate();
    let org = seed_org(&s, t).await;

    // Invitation: the token is stored only as its digest; the email with the link is sealed.
    let token = random_token();
    let token_hash = SecretHash(secret_hash(&token));
    let invitation = NewOrgInvitation {
        token_hash,
        ..new_invitation(org.id, "invitee@example.test", &[], Duration::days(7))
    };
    s.storage
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
    s.storage
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
    let connection_secret = format!(
        "plaintext-marker-org-connection-secret-{}",
        Uuid::now_v7().simple()
    );
    let template = new_org_connection(org.id);
    let connection_sealed = kek
        .seal(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(t, template.id),
            connection_secret.as_bytes(),
        )
        .expect("seal org connection secret");
    s.storage
        .connections()
        .create(
            t,
            &NewConnection {
                secret_enc: Some(connection_sealed.clone()),
                ..template
            },
        )
        .await
        .expect("create org connection");

    // Public by design: a SAML connection's IdP certificate and a domain's TXT challenge token.
    let saml = new_saml_connection(org.id);
    s.storage
        .connections()
        .create(t, &saml)
        .await
        .expect("create SAML connection");
    let domain = new_org_domain(org.id, &unique_domain(), None);
    s.storage
        .organizations()
        .create_domain(t, &domain)
        .await
        .expect("create domain");

    // Login flow holding a sealed SAML identity and the sealed invitation return target.
    let mut flow = new_flow(None, Duration::minutes(10));
    let subject = format!("plaintext-marker-saml-subject-{}", Uuid::now_v7().simple());
    let saml_email = format!("saml-{}@example.test", Uuid::now_v7().simple());
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
            request_id: format!("_{}", Uuid::now_v7().simple()),
            relay_state_hash: b64url(&secret_hash("relay-state")),
            binding_hash: b64url(&secret_hash("binding-cookie")),
            created_at: now_ms().unix_timestamp(),
            identity_sealed: Some(identity_sealed.clone()),
        })),
        return_to_sealed: Some(return_to_sealed.clone()),
        ..LoginState::default()
    }))
    .expect("encode flow state");
    s.storage
        .flows()
        .create(t, &flow)
        .await
        .expect("create flow");

    // The sealed values open only under their own flow (AAD binding).
    for (purpose, sealed) in [
        (SAML_IDENTITY_PURPOSE, &identity_sealed),
        (RETURN_TO_PURPOSE, &return_to_sealed),
    ] {
        let raw = b64url_decode(sealed).expect("base64url");
        assert!(kek.open(purpose, &upstream_aad(t, flow.id), &raw).is_ok());
        assert!(
            kek.open(purpose, &upstream_aad(t, FlowId::new_v7()), &raw)
                .is_err(),
            "a value sealed into one flow must not open under another"
        );
    }

    // --- inspect every column with a plain connection ---------------------------------------
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("inspection connection");
    let columns = sqlx::query(
        "SELECT table_name::text, column_name::text, data_type::text, udt_name::text
           FROM information_schema.columns
          WHERE table_schema = 'public'
            AND data_type IN ('text', 'bytea', 'jsonb', 'ARRAY')
          ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&mut conn)
    .await
    .expect("listing columns");
    let columns: Vec<(String, String, String, String)> = columns
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    for (table, column) in [
        ("org_invitation", "token_hash"),
        ("connection", "secret_enc"),
        ("flow", "state"),
        ("email_outbox", "payload"),
    ] {
        assert!(
            columns.iter().any(|(t, c, _, _)| t == table && c == column),
            "the scan must cover {table}.{column}"
        );
    }

    let token_link = format!("token={token}");
    for (what, plain) in [
        ("invitation token", token.as_str()),
        ("invitation token in a link", token_link.as_str()),
        ("org connection secret", connection_secret.as_str()),
        ("sealed SAML subject", subject.as_str()),
        ("sealed SAML email", saml_email.as_str()),
    ] {
        let found = locations(&mut conn, &columns, plain).await;
        assert!(found.is_empty(), "{what} stored in plaintext in {found:?}");
        let raw = raw_bytes_locations(&mut conn, &columns, plain.as_bytes()).await;
        assert!(
            raw.is_empty(),
            "{what} bytes stored in plaintext in {raw:?}"
        );
    }

    // Positive controls: public values, the sealed state values and the sealed bytes are found.
    assert!(
        !locations(&mut conn, &columns, "TUlJQ29udHJhY3Q=")
            .await
            .is_empty(),
        "the scan must find the public SAML certificate"
    );
    assert!(
        !locations(&mut conn, &columns, &domain.token)
            .await
            .is_empty(),
        "the scan must find the public domain challenge token"
    );
    assert_eq!(
        locations(&mut conn, &columns, &return_to_sealed).await,
        ["flow.state"],
        "the flow state holds the sealed return target"
    );
    assert_eq!(
        locations(&mut conn, &columns, &identity_sealed).await,
        ["flow.state"],
        "the flow state holds the sealed SAML identity"
    );
    assert_eq!(
        raw_bytes_locations(&mut conn, &columns, &connection_sealed).await,
        ["connection.secret_enc"],
        "the org connection secret is stored sealed"
    );
    assert_eq!(
        raw_bytes_locations(&mut conn, &columns, &token_hash.0).await,
        ["org_invitation.token_hash"],
        "the invitation digest is stored only in org_invitation.token_hash"
    );
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM org_invitation WHERE token_hash = $1 AND length(token_hash) = 32",
    )
    .bind(token_hash.0.as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("find invitation digest");
    assert_eq!(
        stored, 1,
        "org_invitation.token_hash holds the token digest"
    );
    conn.close().await.expect("close inspection connection");
}
