//! Phase 5 configuration of the spawned binary: `redis_url`, `rate_limit_redis_failure`,
//! `metrics_listen`, `metrics_on_main_port`, `otel_endpoint`, `otel_service_name`,
//! `shutdown_drain` and `database_max_connections` — defaults, flag/env/file sources in
//! `config show`, rejection of invalid values naming the key, redaction of credentials, and the
//! explicit refusal of `redis_url` at startup until the shared limiter exists.

use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");

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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn show(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut all = vec!["config", "show"];
    all.extend_from_slice(args);
    let out = run(cwd, &all, envs);
    assert!(out.status.success(), "{}", text(&out));
    stdout(&out)
}

fn assert_line(show: &str, line: &str) {
    assert!(
        show.lines().any(|l| l == line),
        "missing `{line}` in:\n{show}"
    );
}

#[test]
fn defaults_are_shown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = show(dir.path(), &[], &[]);
    for line in [
        "redis_url = <unset> (default)",
        "rate_limit_redis_failure = closed (default)",
        "metrics_listen = <unset> (default)",
        "metrics_on_main_port = false (default)",
        "otel_endpoint = <unset> (default)",
        "otel_service_name = anvilid (default)",
        "shutdown_drain = 0s (default)",
        "database_max_connections = 10 (default)",
    ] {
        assert_line(&s, line);
    }
}

#[test]
fn every_key_reads_from_the_environment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let envs = [
        ("ANVILID_REDIS_URL", "rediss://cache.example.test:6380/0"),
        ("ANVILID_RATE_LIMIT_REDIS_FAILURE", "local"),
        ("ANVILID_METRICS_LISTEN", "127.0.0.1:9464"),
        ("ANVILID_METRICS_ON_MAIN_PORT", "true"),
        ("ANVILID_OTEL_ENDPOINT", "http://127.0.0.1:4318"),
        ("ANVILID_OTEL_SERVICE_NAME", "idp-blue"),
        ("ANVILID_SHUTDOWN_DRAIN", "10s"),
        ("ANVILID_DATABASE_MAX_CONNECTIONS", "40"),
    ];
    let s = show(dir.path(), &[], &envs);
    for line in [
        "redis_url = rediss://cache.example.test:6380/0 (env ANVILID_REDIS_URL)",
        "rate_limit_redis_failure = local (env ANVILID_RATE_LIMIT_REDIS_FAILURE)",
        "metrics_listen = 127.0.0.1:9464 (env ANVILID_METRICS_LISTEN)",
        "metrics_on_main_port = true (env ANVILID_METRICS_ON_MAIN_PORT)",
        "otel_endpoint = http://127.0.0.1:4318/ (env ANVILID_OTEL_ENDPOINT)",
        "otel_service_name = idp-blue (env ANVILID_OTEL_SERVICE_NAME)",
        "shutdown_drain = 10s (env ANVILID_SHUTDOWN_DRAIN)",
        "database_max_connections = 40 (env ANVILID_DATABASE_MAX_CONNECTIONS)",
    ] {
        assert_line(&s, line);
    }
    let validate = run(dir.path(), &["config", "validate"], &envs);
    assert!(validate.status.success(), "{}", text(&validate));
    // A plain number of seconds is a duration too.
    let s = show(dir.path(), &[], &[("ANVILID_SHUTDOWN_DRAIN", "15")]);
    assert_line(&s, "shutdown_drain = 15s (env ANVILID_SHUTDOWN_DRAIN)");
}

#[test]
fn every_key_reads_from_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("anvilid.toml"),
        "redis_url = \"redis://cache.example.test:6379\"\n\
         rate_limit_redis_failure = \"local\"\n\
         metrics_listen = \"127.0.0.1:9100\"\n\
         metrics_on_main_port = true\n\
         otel_endpoint = \"https://otel.example.test\"\n\
         otel_service_name = \"from-file\"\n\
         shutdown_drain = 7\n\
         database_max_connections = 25\n",
    )
    .expect("config file");
    let s = show(dir.path(), &[], &[]);
    for line in [
        "redis_url = redis://cache.example.test:6379 (file anvilid.toml)",
        "rate_limit_redis_failure = local (file anvilid.toml)",
        "metrics_listen = 127.0.0.1:9100 (file anvilid.toml)",
        "metrics_on_main_port = true (file anvilid.toml)",
        "otel_endpoint = https://otel.example.test/ (file anvilid.toml)",
        "otel_service_name = from-file (file anvilid.toml)",
        "shutdown_drain = 7s (file anvilid.toml)",
        "database_max_connections = 25 (file anvilid.toml)",
    ] {
        assert_line(&s, line);
    }
    let validate = run(dir.path(), &["config", "validate"], &[]);
    assert!(validate.status.success(), "{}", text(&validate));
}

#[test]
fn non_secret_keys_read_from_flags_and_win_over_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let envs = [
        ("ANVILID_RATE_LIMIT_REDIS_FAILURE", "closed"),
        ("ANVILID_METRICS_LISTEN", "127.0.0.1:9000"),
        ("ANVILID_OTEL_SERVICE_NAME", "env-name"),
        ("ANVILID_SHUTDOWN_DRAIN", "1s"),
        ("ANVILID_DATABASE_MAX_CONNECTIONS", "5"),
    ];
    let s = show(
        dir.path(),
        &[
            "--rate-limit-redis-failure",
            "local",
            "--metrics-listen",
            "127.0.0.1:9464",
            "--metrics-on-main-port",
            "--otel-endpoint",
            "http://127.0.0.1:4318",
            "--otel-service-name",
            "cli-name",
            "--shutdown-drain",
            "500ms",
            "--database-max-connections",
            "50",
        ],
        &envs,
    );
    for line in [
        "rate_limit_redis_failure = local (cli --rate-limit-redis-failure)",
        "metrics_listen = 127.0.0.1:9464 (cli --metrics-listen)",
        "metrics_on_main_port = true (cli --metrics-on-main-port)",
        "otel_endpoint = http://127.0.0.1:4318/ (cli --otel-endpoint)",
        "otel_service_name = cli-name (cli --otel-service-name)",
        "shutdown_drain = 500ms (cli --shutdown-drain)",
        "database_max_connections = 50 (cli --database-max-connections)",
    ] {
        assert_line(&s, line);
    }
}

#[test]
fn redis_url_is_not_a_cli_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &[
            "config",
            "show",
            "--redis-url",
            "redis://:pw@cache.example.test",
        ],
        &[],
    );
    assert!(!out.status.success(), "{}", text(&out));
}

#[test]
fn credentials_in_redis_and_otel_urls_are_redacted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let envs = [
        (
            "ANVILID_REDIS_URL",
            "redis://anvil:redis-pass-1@cache.example.test:6379/0",
        ),
        (
            "ANVILID_OTEL_ENDPOINT",
            "https://otel-user-token:otel-pass-2@otel.example.test/",
        ),
    ];
    let s = show(dir.path(), &[], &envs);
    assert_line(
        &s,
        "redis_url = redis://***:***@cache.example.test:6379/0 (env ANVILID_REDIS_URL)",
    );
    assert_line(
        &s,
        "otel_endpoint = https://***:***@otel.example.test/ (env ANVILID_OTEL_ENDPOINT)",
    );
    for secret in ["redis-pass-1", "otel-pass-2", "otel-user-token"] {
        assert!(!s.contains(secret), "{secret} leaked:\n{s}");
    }
    // A password-only Redis URL keeps its (empty) user name.
    let s = show(
        dir.path(),
        &[],
        &[(
            "ANVILID_REDIS_URL",
            "redis://:only-pass-3@cache.example.test",
        )],
    );
    assert_line(
        &s,
        "redis_url = redis://:***@cache.example.test (env ANVILID_REDIS_URL)",
    );
}

#[test]
fn invalid_values_fail_validation_naming_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases: &[(&str, &str, &str)] = &[
        ("ANVILID_SHUTDOWN_DRAIN", "abc", "shutdown_drain"),
        ("ANVILID_SHUTDOWN_DRAIN", "2h", "shutdown_drain"),
        ("ANVILID_SHUTDOWN_DRAIN", "10 parsecs", "shutdown_drain"),
        (
            "ANVILID_DATABASE_MAX_CONNECTIONS",
            "0",
            "database_max_connections",
        ),
        (
            "ANVILID_DATABASE_MAX_CONNECTIONS",
            "1001",
            "database_max_connections",
        ),
        ("ANVILID_METRICS_LISTEN", "nope", "metrics_listen"),
        // The metrics listener must not take over the main listener.
        ("ANVILID_METRICS_LISTEN", "127.0.0.1:8080", "metrics_listen"),
        ("ANVILID_OTEL_ENDPOINT", "collector:4318", "otel_endpoint"),
        ("ANVILID_OTEL_ENDPOINT", "ftp://collector", "otel_endpoint"),
        ("ANVILID_OTEL_SERVICE_NAME", " ", "otel_service_name"),
        (
            "ANVILID_RATE_LIMIT_REDIS_FAILURE",
            "maybe",
            "rate_limit_redis_failure",
        ),
        (
            "ANVILID_REDIS_URL",
            "http://user:leaky-pass@cache.example.test",
            "redis_url",
        ),
    ];
    for (key, value, name) in cases {
        let out = run(dir.path(), &["config", "validate"], &[(key, value)]);
        let all = text(&out);
        assert!(!out.status.success(), "{key}={value} accepted: {all}");
        assert!(all.contains(name), "{key}={value}: {all}");
        assert!(!all.contains("leaky-pass"), "{key}: secret echoed: {all}");
    }
}

#[test]
fn redis_url_fails_startup_explicitly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &[
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--breach-check",
            "off",
            "--data-dir",
            dir.path().to_str().expect("utf-8 path"),
        ],
        &[(
            "ANVILID_REDIS_URL",
            "redis://:startup-pass@cache.example.test:6379",
        )],
    );
    let all = text(&out);
    assert!(!out.status.success(), "{all}");
    assert!(all.contains("redis_url is not supported yet"), "{all}");
    assert!(!all.contains("startup-pass"), "{all}");
    // It failed before the database was opened.
    assert!(!dir.path().join("anvilid.db").exists(), "{all}");
}
