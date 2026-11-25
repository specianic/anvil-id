//! Secrets at rest (ARCHITECTURE §6.2, QUAL-01): row inspection of a real SQLite file.
//!
//! Seeds, through the storage ports, an authorization code, a refresh token (and its rotated
//! child), a browser session, a client secret digest, a setup token, a self-service token, a flow
//! CSRF/cookie pair and a replay-guarded jti, each derived from a known plaintext marker. Then it
//! opens the database file with a plain connection and checks that no TEXT or BLOB column of any
//! table contains any marker, and that every hash column holds exactly 32 bytes (the expected
//! digest for the seeded rows).

use anvil_core::model::{ReplayKind, SecretHash, SelfServiceKind};
use anvil_core::ports::{RotateOutcome, Storage};
use anvil_jose::encoding::secret_hash;
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
    let user = storage
        .users()
        .create(tenant, &user, Some(&new_password()), Some(&sst), None)
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

    Seeded { markers }
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

    // No column of any table may contain a plaintext marker, as TEXT or inside a BLOB.
    for (m, _, _) in &seeded.markers {
        assert_eq!(
            hits_anywhere(&pool, &columns, m.as_bytes()).await,
            0,
            "the plaintext marker {m} is stored somewhere"
        );
    }

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
