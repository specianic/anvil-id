//! `anvilid users export` skeleton (plan 07-04): the final argument set is documented in --help
//! and the command fails with the explicit TRANSITIONAL marker. Plan 07-15 deletes this file when
//! the command is real.

use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");

/// Runs the binary in `cwd` with a clean environment (only PATH kept).
fn run(cwd: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.output().expect("run anvilid")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn users_help_lists_both_subcommands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["users", "--help"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let help = stdout(&out);
    assert!(help.contains("import"), "{help}");
    assert!(help.contains("export"), "{help}");
}

#[test]
fn users_export_help_lists_every_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["users", "export", "--help"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let help = stdout(&out);
    for flag in [
        "--tenant",
        "--user",
        "--gdpr",
        "--include-password-hashes",
        "--out",
    ] {
        assert!(help.contains(flag), "{flag} missing from:\n{help}");
    }
    assert!(
        help.contains("never part of the GDPR export (decision Q4)"),
        "{help}"
    );
}

#[test]
fn users_export_fails_with_the_transitional_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["users", "export"]);
    assert!(!out.status.success(), "must exit non-zero");
    assert!(
        stderr(&out).contains("not available yet (TRANSITIONAL(07-15))"),
        "{}",
        stderr(&out)
    );
    assert!(
        !dir.path().join("anvilid-data").exists(),
        "the skeleton must not create the data directory"
    );
}
