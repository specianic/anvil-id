//! Phase 6 configuration of the spawned binary: `saml_experimental` and
//! `domain_verification_resolvers` — defaults, flag/env/file sources in `config show`, the
//! experimental warning, and rejection of invalid resolver entries naming the key without echoing
//! other configuration.

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

fn show(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut all = vec!["config", "show"];
    all.extend_from_slice(args);
    let out = run(cwd, &all, envs);
    assert!(out.status.success(), "{}", text(&out));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn assert_line(show: &str, line: &str) {
    assert!(
        show.lines().any(|l| l == line),
        "missing `{line}` in:\n{show}"
    );
}

const SAML_WARNING: &str = "SAML 2.0 is experimental";

#[test]
fn defaults_are_shown_and_saml_is_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = show(dir.path(), &[], &[]);
    assert_line(&s, "saml_experimental = false (default)");
    assert_line(&s, "domain_verification_resolvers = <system> (default)");
    let validate = run(dir.path(), &["config", "validate"], &[]);
    assert!(validate.status.success(), "{}", text(&validate));
    assert!(
        !text(&validate).contains(SAML_WARNING),
        "no SAML warning by default: {}",
        text(&validate)
    );
}

#[test]
fn keys_read_from_the_environment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let envs = [
        ("ANVILID_SAML_EXPERIMENTAL", "true"),
        (
            "ANVILID_DOMAIN_VERIFICATION_RESOLVERS",
            "192.0.2.53, 198.51.100.7:5353,[2001:db8::53]:53",
        ),
    ];
    let s = show(dir.path(), &[], &envs);
    assert_line(
        &s,
        "saml_experimental = true (env ANVILID_SAML_EXPERIMENTAL)",
    );
    assert_line(
        &s,
        "domain_verification_resolvers = 192.0.2.53, 198.51.100.7:5353, [2001:db8::53]:53 \
         (env ANVILID_DOMAIN_VERIFICATION_RESOLVERS)",
    );
    let validate = run(dir.path(), &["config", "validate"], &envs);
    assert!(validate.status.success(), "{}", text(&validate));
    assert!(
        text(&validate).contains(SAML_WARNING),
        "the experimental flag is warned about: {}",
        text(&validate)
    );
}

#[test]
fn keys_read_from_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("anvilid.toml"),
        "saml_experimental = true\n\
         domain_verification_resolvers = [\"192.0.2.1\", \"2001:db8::1\"]\n",
    )
    .expect("config file");
    let s = show(dir.path(), &[], &[]);
    assert_line(&s, "saml_experimental = true (file anvilid.toml)");
    assert_line(
        &s,
        "domain_verification_resolvers = 192.0.2.1, 2001:db8::1 (file anvilid.toml)",
    );
    let validate = run(dir.path(), &["config", "validate"], &[]);
    assert!(validate.status.success(), "{}", text(&validate));
}

#[test]
fn keys_read_from_flags_and_win_over_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let envs = [("ANVILID_DOMAIN_VERIFICATION_RESOLVERS", "192.0.2.1")];
    let flags = [
        "--saml-experimental",
        "--domain-verification-resolvers",
        "198.51.100.1:53",
    ];
    let s = show(dir.path(), &flags, &envs);
    assert_line(&s, "saml_experimental = true (cli --saml-experimental)");
    assert_line(
        &s,
        "domain_verification_resolvers = 198.51.100.1:53 (cli --domain-verification-resolvers)",
    );
    let mut args = vec!["config", "validate"];
    args.extend_from_slice(&flags);
    let validate = run(dir.path(), &args, &envs);
    assert!(validate.status.success(), "{}", text(&validate));
}

#[test]
fn an_empty_resolver_list_means_the_system_configuration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let envs = [("ANVILID_DOMAIN_VERIFICATION_RESOLVERS", "")];
    let s = show(dir.path(), &[], &envs);
    assert_line(
        &s,
        "domain_verification_resolvers = <system> (env ANVILID_DOMAIN_VERIFICATION_RESOLVERS)",
    );
    let validate = run(dir.path(), &["config", "validate"], &envs);
    assert!(validate.status.success(), "{}", text(&validate));
}

#[test]
fn invalid_resolvers_fail_validation_naming_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A secret elsewhere in the configuration must never be echoed by the resolver error.
    let secret_marker = "leaky-smtp-pass";
    for value in [
        "dns.example.test",
        "192.0.2.1:notaport",
        "192.0.2.1:0",
        "192.0.2.1/24",
        "192.0.2.1, nope",
        "udp://192.0.2.1",
    ] {
        let out = run(
            dir.path(),
            &["config", "validate"],
            &[
                ("ANVILID_DOMAIN_VERIFICATION_RESOLVERS", value),
                (
                    "ANVILID_SMTP_URL",
                    "smtp://mailer:leaky-smtp-pass@mail.example.test:587",
                ),
            ],
        );
        let all = text(&out);
        assert!(!out.status.success(), "{value} accepted: {all}");
        assert!(
            all.contains("domain_verification_resolvers"),
            "{value}: {all}"
        );
        assert!(
            !all.contains(secret_marker),
            "{value}: other config echoed: {all}"
        );
    }
}

#[test]
fn saml_experimental_rejects_a_non_boolean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "validate"],
        &[("ANVILID_SAML_EXPERIMENTAL", "maybe")],
    );
    let all = text(&out);
    assert!(!out.status.success(), "accepted: {all}");
    assert!(all.contains("saml_experimental"), "{all}");
}
