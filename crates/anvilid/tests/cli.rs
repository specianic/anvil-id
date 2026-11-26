//! CLI behaviour of the spawned binary: `config validate|show`, `migrate`, and the storage and KEK
//! checks `serve` runs before it connects to anything.

use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");

/// A known, valid KEK (32 bytes of 0x2a) used to prove `config show` never prints it.
const KNOWN_KEK: &str = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=";

/// Runs the binary in `cwd` with a clean environment (only PATH kept) plus `envs`.
fn run(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run anvilid")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn config_validate_rejects_non_http_public_url() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "validate"],
        &[("ANVILID_PUBLIC_URL", "ftp://x")],
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("public_url"), "{}", text(&out));
}

#[test]
fn config_validate_accepts_the_zero_config_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["config", "validate"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        !dir.path().join("anvilid-data").exists(),
        "validate must not create the data directory"
    );
}

#[test]
fn config_show_prints_sources_and_hides_secrets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "show", "--listen", "127.0.0.1:9999"],
        &[
            ("ANVILID_KEK", KNOWN_KEK),
            ("ANVILID_PUBLIC_URL", "https://id.example.test"),
            (
                "ANVILID_DATABASE_URL",
                "postgres://anvil:pg-secret-pw@db.example.test/anvil",
            ),
            (
                "ANVILID_SMTP_URL",
                "smtps://u:smtp-secret-pw@mail.example.test",
            ),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let all = text(&out);
    assert!(!all.contains(KNOWN_KEK), "KEK leaked: {all}");
    assert!(
        !all.contains("pg-secret-pw"),
        "database password leaked: {all}"
    );
    assert!(
        !all.contains("smtp-secret-pw"),
        "SMTP password leaked: {all}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("kek = *** (env ANVILID_KEK)"), "{stdout}");
    assert!(
        stdout.contains("public_url = https://id.example.test (env ANVILID_PUBLIC_URL)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("listen = 127.0.0.1:9999 (cli --listen)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("data_dir = ./anvilid-data (default)"),
        "{stdout}"
    );
}

#[test]
fn config_file_is_read_and_env_wins_over_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("anvilid.toml"),
        "public_url = \"https://file.example.test\"\nlisten = \"127.0.0.1:7777\"\n",
    )
    .expect("write toml");
    let out = run(
        dir.path(),
        &["config", "show"],
        &[("ANVILID_LISTEN", "127.0.0.1:6666")],
    );
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("public_url = https://file.example.test (file anvilid.toml)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("listen = 127.0.0.1:6666 (env ANVILID_LISTEN)"),
        "{stdout}"
    );
}

#[test]
fn explicit_missing_config_file_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "validate", "--config", "missing.toml"],
        &[],
    );
    assert!(!out.status.success());
    assert!(text(&out).contains("missing.toml"), "{}", text(&out));
}

#[test]
fn migrate_creates_the_sqlite_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("x.db");
    let url = format!("sqlite://{}", db.display());
    let out = run(dir.path(), &["migrate", "--database-url", &url], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(db.exists(), "database file was not created");
    assert!(std::fs::metadata(&db).expect("meta").len() > 0);
    // Migrations only: no KEK, no lock.
    assert!(!dir.path().join("anvilid-data").exists());
}

#[test]
fn migrate_accepts_allow_destructive_migrations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("x.db");
    let url = format!("sqlite://{}", db.display());
    let out = run(
        dir.path(),
        &[
            "migrate",
            "--allow-destructive-migrations",
            "--database-url",
            &url,
        ],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(db.exists(), "database file was not created");
}

#[test]
fn allow_destructive_migrations_defaults_off_in_config_show() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["config", "show"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("allow_destructive_migrations = false (default)"),
        "{stdout}"
    );
}

#[test]
fn allow_destructive_migrations_from_env_and_cli_in_config_show() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "show"],
        &[("ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS", "true")],
    );
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(
            "allow_destructive_migrations = true (env ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS)"
        ),
        "{stdout}"
    );
    let out = run(
        dir.path(),
        &["config", "show", "--allow-destructive-migrations"],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("allow_destructive_migrations = true (cli --allow-destructive-migrations)"),
        "{stdout}"
    );
}

#[test]
fn serve_parses_allow_destructive_migrations_from_env() {
    // The flag parses and the configuration resolves: serve then stops at the next check (plain
    // http on a public host), before touching any database.
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["serve", "--public-url", "http://id.example.test"],
        &[("ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS", "true")],
    );
    assert!(!out.status.success());
    let all = text(&out);
    assert!(all.contains("--insecure-http"), "{all}");
    assert!(!all.contains("allow_destructive_migrations"), "{all}");
}

#[test]
fn serve_rejects_a_non_boolean_allow_destructive_migrations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["serve"],
        &[("ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS", "maybe")],
    );
    assert!(!out.status.success());
    let all = text(&out);
    assert!(all.contains("allow_destructive_migrations"), "{all}");
    assert!(!dir.path().join("anvilid-data").exists(), "{all}");
}

#[test]
fn serve_rejects_unsupported_scheme_without_echoing_the_url() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["serve", "--database-url", "mysql://u:secretpw@h/db"],
        &[],
    );
    assert!(!out.status.success());
    let all = text(&out);
    assert!(all.contains("unsupported database URL scheme"), "{all}");
    assert!(!all.contains("secretpw"), "URL leaked: {all}");
}

#[test]
fn serve_with_postgres_and_no_kek_refuses_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Port 9 (discard) on loopback: the KEK check must fail before any connection attempt.
    let out = run(
        dir.path(),
        &[
            "serve",
            "--database-url",
            "postgres://anvil:pg-secret-pw@127.0.0.1:9/anvil",
        ],
        &[],
    );
    assert!(!out.status.success());
    let all = text(&out);
    assert!(all.contains("KEK"), "{all}");
    assert!(!all.contains("pg-secret-pw"), "URL leaked: {all}");
    assert!(
        !dir.path().join("anvilid-data").join("kek").exists(),
        "a KEK must never be generated for Postgres"
    );
}

#[test]
fn serve_refuses_plain_http_on_a_public_host() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["serve", "--public-url", "http://id.example.test"],
        &[],
    );
    assert!(!out.status.success());
    assert!(text(&out).contains("--insecure-http"), "{}", text(&out));
}

#[test]
fn admin_setup_url_needs_an_installation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["admin", "setup-url"], &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("anvilid serve"), "{}", text(&out));
    assert!(
        !dir.path().join("anvilid-data").join("anvilid.db").exists(),
        "setup-url must not create a database"
    );
}

#[test]
fn backup_on_postgres_fails_and_points_to_the_docs() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Port 9 on loopback: the refusal happens before any connection attempt.
    let url = "postgres://anvil:pg-secret-pw@127.0.0.1:9/anvil";
    for args in [
        vec![
            "backup",
            "create",
            "--output",
            "b.db",
            "--database-url",
            url,
        ],
        vec![
            "backup",
            "restore",
            "--input",
            "b.db",
            "--yes",
            "--database-url",
            url,
        ],
    ] {
        let out = run(dir.path(), &args, &[("ANVILID_KEK", KNOWN_KEK)]);
        assert!(!out.status.success(), "{args:?} must fail");
        let all = text(&out);
        assert!(all.contains("docs/OPERATIONS.md#postgres"), "{all}");
        assert!(all.contains("pg_dump"), "{all}");
        assert!(!all.contains("pg-secret-pw"), "URL leaked: {all}");
    }
    assert!(!dir.path().join("b.db").exists(), "nothing was written");
}

#[test]
fn backup_create_needs_an_installation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["backup", "create", "--output", "b.db"], &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("anvilid serve"), "{}", text(&out));
    assert!(!dir.path().join("b.db").exists());
    assert!(
        !dir.path().join("anvilid-data").join("anvilid.db").exists(),
        "backup must not create a database"
    );
}

#[test]
fn help_lists_backup_admin_recover_and_healthcheck() {
    let dir = tempfile::tempdir().expect("tempdir");
    let top = text(&run(dir.path(), &["--help"], &[]));
    assert!(top.contains("backup"), "{top}");
    let backup = text(&run(dir.path(), &["backup", "--help"], &[]));
    assert!(
        backup.contains("create") && backup.contains("restore"),
        "{backup}"
    );
    assert!(top.contains("healthcheck"), "{top}");
    let admin = text(&run(dir.path(), &["admin", "--help"], &[]));
    assert!(admin.contains("recover"), "{admin}");
    let recover = text(&run(dir.path(), &["admin", "recover", "--help"], &[]));
    assert!(
        recover.contains("--email") && recover.contains("--reset-mfa"),
        "{recover}"
    );
}
