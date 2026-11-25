//! Phase 4 configuration of the spawned binary: the outbound (SSRF guard) keys
//! `outbound_allow_cidrs` and `outbound_ca_file` — parsing, precedence (CLI > env > file),
//! `config show`, and rejection of invalid values without echoing them.

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

#[test]
fn defaults_follow_the_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dev = run(dir.path(), &["config", "show"], &[]);
    assert!(dev.status.success(), "{}", text(&dev));
    let s = stdout(&dev);
    assert!(
        s.contains("outbound_allow_cidrs = 127.0.0.0/8, ::1/128 (default)"),
        "{s}"
    );
    assert!(s.contains("outbound_ca_file = <unset> (default)"), "{s}");
    let prod = run(
        dir.path(),
        &["config", "show"],
        &[("ANVILID_PUBLIC_URL", "https://id.example.test")],
    );
    assert!(prod.status.success(), "{}", text(&prod));
    assert!(
        stdout(&prod).contains("outbound_allow_cidrs = <none> (default)"),
        "{}",
        stdout(&prod)
    );
}

#[test]
fn allow_list_parses_from_env_and_validates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let envs = [(
        "ANVILID_OUTBOUND_ALLOW_CIDRS",
        "10.0.0.0/8, 192.168.1.5, fd00::/8",
    )];
    let show = run(dir.path(), &["config", "show"], &envs);
    assert!(show.status.success(), "{}", text(&show));
    assert!(
        stdout(&show).contains(
            "outbound_allow_cidrs = 10.0.0.0/8, 192.168.1.5, fd00::/8 \
             (env ANVILID_OUTBOUND_ALLOW_CIDRS)"
        ),
        "{}",
        stdout(&show)
    );
    let validate = run(dir.path(), &["config", "validate"], &envs);
    assert!(validate.status.success(), "{}", text(&validate));
}

#[test]
fn precedence_is_cli_then_env_then_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("anvilid.toml"),
        "outbound_allow_cidrs = [\"172.16.0.0/12\"]\n",
    )
    .expect("config file");
    let file_only = run(dir.path(), &["config", "show"], &[]);
    assert!(
        stdout(&file_only).contains("outbound_allow_cidrs = 172.16.0.0/12 (file anvilid.toml)"),
        "{}",
        text(&file_only)
    );
    let env = [("ANVILID_OUTBOUND_ALLOW_CIDRS", "10.0.0.0/8")];
    let env_wins = run(dir.path(), &["config", "show"], &env);
    assert!(
        stdout(&env_wins)
            .contains("outbound_allow_cidrs = 10.0.0.0/8 (env ANVILID_OUTBOUND_ALLOW_CIDRS)"),
        "{}",
        text(&env_wins)
    );
    let cli_wins = run(
        dir.path(),
        &["config", "show", "--outbound-allow-cidrs", "192.168.0.0/16"],
        &env,
    );
    assert!(
        stdout(&cli_wins)
            .contains("outbound_allow_cidrs = 192.168.0.0/16 (cli --outbound-allow-cidrs)"),
        "{}",
        text(&cli_wins)
    );
    // An explicit empty list is allowed (nothing allow-listed, even in development mode).
    let empty = run(
        dir.path(),
        &["config", "validate"],
        &[("ANVILID_OUTBOUND_ALLOW_CIDRS", "")],
    );
    assert!(empty.status.success(), "{}", text(&empty));
}

#[test]
fn invalid_cidr_is_rejected_naming_the_key_not_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    for bad in [
        "10.0.0.0/33",
        "10.0.0.0/8, not-a-cidr-secretish",
        "300.1.2.3",
    ] {
        let out = run(
            dir.path(),
            &["config", "validate"],
            &[("ANVILID_OUTBOUND_ALLOW_CIDRS", bad)],
        );
        assert!(!out.status.success(), "{bad}: {}", text(&out));
        let all = text(&out);
        assert!(all.contains("outbound_allow_cidrs"), "{all}");
        assert!(
            !all.contains("secretish") && !all.contains("300.1.2.3"),
            "{all}"
        );
    }
}

#[test]
fn missing_or_non_pem_ca_file_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = run(
        dir.path(),
        &["config", "validate"],
        &[("ANVILID_OUTBOUND_CA_FILE", "/nonexistent/anvilid-ca.pem")],
    );
    assert!(!missing.status.success(), "{}", text(&missing));
    assert!(
        text(&missing).contains("outbound_ca_file"),
        "{}",
        text(&missing)
    );

    let junk = dir.path().join("junk.pem");
    std::fs::write(&junk, "this is not a certificate SECRET-CONTENT\n").expect("write");
    let out = run(
        dir.path(),
        &[
            "config",
            "validate",
            "--outbound-ca-file",
            junk.to_str().expect("utf-8 path"),
        ],
        &[],
    );
    assert!(!out.status.success(), "{}", text(&out));
    let all = text(&out);
    assert!(all.contains("outbound_ca_file"), "{all}");
    assert!(
        !all.contains("SECRET-CONTENT"),
        "file content leaked: {all}"
    );
}

/// A throwaway CA certificate generated with openssl, or `None` (and says why) when openssl is
/// not available. No key material is committed.
fn test_ca(dir: &Path) -> Option<std::path::PathBuf> {
    let ca = dir.join("ca.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=anvilid-test-ca",
        ])
        .arg("-keyout")
        .arg(dir.join("ca.key"))
        .arg("-out")
        .arg(&ca)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Some(ca),
        Ok(s) => panic!("openssl failed to create a test CA: {s}"),
        Err(e) => {
            eprintln!("SKIPPED: openssl is not on PATH ({e}); valid CA file test not run");
            None
        }
    }
}

#[test]
fn valid_ca_file_validates_and_is_shown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(ca) = test_ca(dir.path()) else {
        return;
    };
    let path = ca.to_str().expect("utf-8 path");
    let envs = [("ANVILID_OUTBOUND_CA_FILE", path)];
    let out = run(dir.path(), &["config", "validate"], &envs);
    assert!(out.status.success(), "{}", text(&out));
    let show = run(dir.path(), &["config", "show"], &envs);
    assert!(
        stdout(&show).contains(&format!(
            "outbound_ca_file = {path} (env ANVILID_OUTBOUND_CA_FILE)"
        )),
        "{}",
        text(&show)
    );
    assert!(!stdout(&show).contains("BEGIN CERTIFICATE"));
}
