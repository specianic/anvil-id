//! Page translations (UI-04): catalog loading and overrides, locale negotiation order, English
//! fallback, text direction, plurals, and the `t()` template function.

use std::path::Path;

use anvil_web::i18n::{Catalogs, Locale, LocaleInputs, direction, negotiate};
use anvil_web::render::Renderer;
use fluent_bundle::FluentValue;
use minijinja::context;

/// A theme directory with `locales/{lang}/{file}` = `body` for every entry.
fn theme(files: &[(&str, &str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (lang, file, body) in files {
        let d = dir.path().join("locales").join(lang);
        std::fs::create_dir_all(&d).expect("mkdir");
        std::fs::write(d.join(file), body).expect("write");
    }
    dir
}

/// Embedded catalogs plus a small German one.
fn with_german() -> (tempfile::TempDir, Catalogs) {
    let dir = theme(&[(
        "de",
        "main.ftl",
        "title-login = Anmelden\nlogin-invalid_credentials = E-Mail-Adresse oder Passwort ist falsch.\n",
    )]);
    let c = Catalogs::load(Some(dir.path())).expect("catalogs load");
    (dir, c)
}

fn inputs<'a>(
    ui: Option<&'a str>,
    user: Option<&'a str>,
    accept: Option<&'a str>,
    tenant: &'a str,
) -> LocaleInputs<'a> {
    LocaleInputs {
        ui_locales: ui,
        user_locale: user,
        accept_language: accept,
        tenant_default: tenant,
    }
}

#[test]
fn ui_locales_wins_when_available() {
    let (_d, c) = with_german();
    let l = negotiate(&c, &inputs(Some("de en"), None, Some("en"), "en"));
    assert_eq!(l.tag, "de");
    assert_eq!(l.ui_locales.as_deref(), Some("de en"));
}

#[test]
fn unknown_ui_locales_fall_through_to_accept_language() {
    let (_d, c) = with_german();
    let l = negotiate(&c, &inputs(Some("xx"), None, Some("de"), "en"));
    assert_eq!(l.tag, "de");
    assert_eq!(l.ui_locales, None, "an unmatched ui_locales is not carried");
    // Malformed values are skipped too.
    let l = negotiate(&c, &inputs(Some("!!! ***"), None, None, "en"));
    assert_eq!(l.tag, "en");
}

#[test]
fn accept_language_picks_the_best_available() {
    let (_d, c) = with_german();
    let l = negotiate(&c, &inputs(None, None, Some("fr;q=0.9, de;q=0.8"), "en"));
    assert_eq!(l.tag, "de");
    // Region subtags match the language catalog.
    let l = negotiate(&c, &inputs(None, None, Some("de-CH"), "en"));
    assert_eq!(l.tag, "de");
    // q-values order the preferences, not the position.
    let l = negotiate(&c, &inputs(None, None, Some("en;q=0.1, de"), "en"));
    assert_eq!(l.tag, "de");
}

#[test]
fn nothing_requested_uses_the_tenant_default_then_english() {
    let (_d, c) = with_german();
    assert_eq!(negotiate(&c, &inputs(None, None, None, "de")).tag, "de");
    assert_eq!(
        negotiate(&c, &inputs(None, None, Some("fr"), "de")).tag,
        "de"
    );
    assert_eq!(negotiate(&c, &inputs(None, None, None, "fr")).tag, "en");
    assert_eq!(negotiate(&c, &inputs(None, None, None, "")).tag, "en");
}

#[test]
fn user_locale_sits_between_ui_locales_and_accept_language() {
    let (_d, c) = with_german();
    assert_eq!(
        negotiate(&c, &inputs(None, Some("de"), Some("en"), "en")).tag,
        "de"
    );
    assert_eq!(
        negotiate(&c, &inputs(Some("en"), Some("de"), None, "en")).tag,
        "en"
    );
    // An unavailable claim falls through to Accept-Language.
    assert_eq!(
        negotiate(&c, &inputs(None, Some("fr"), Some("de"), "en")).tag,
        "de"
    );
    // OIDC claims sometimes use an underscore.
    assert_eq!(
        negotiate(&c, &inputs(None, Some("de_AT"), None, "en")).tag,
        "de"
    );
}

#[test]
fn missing_messages_fall_back_to_english_then_to_the_key() {
    let (_d, c) = with_german();
    let de = Locale::new("de");
    assert_eq!(c.text(&de, "title.login", &[]), "Anmelden");
    assert_eq!(
        c.text(&de, "title.registration", &[]),
        "Create an account",
        "missing in de -> English"
    );
    assert_eq!(
        c.text(&de, "no.such_key", &[]),
        "no.such_key",
        "missing everywhere -> the key"
    );
    assert_eq!(
        c.text(&Locale::new("zz"), "title.login", &[]),
        "Sign in",
        "an unknown locale reads English"
    );
}

#[test]
fn rtl_languages_get_rtl() {
    for tag in ["ar", "he", "fa", "ur", "ps", "yi", "ar-EG", "he_IL", "AR"] {
        assert_eq!(direction(tag), "rtl", "{tag}");
        assert_eq!(Locale::new(tag).dir, "rtl", "{tag}");
    }
    for tag in ["en", "de", "arn", "pt-BR", ""] {
        assert_eq!(direction(tag), "ltr", "{tag}");
    }
}

#[test]
fn plurals_render_in_english() {
    let c = Catalogs::load(None).expect("catalogs");
    let en = Locale::fallback();
    assert_eq!(
        c.text(
            &en,
            "login.too_many_attempts",
            &[("seconds", FluentValue::from(1))]
        ),
        "Too many attempts. Try again in 1 second."
    );
    assert_eq!(
        c.text(
            &en,
            "login.too_many_attempts",
            &[("seconds", FluentValue::from(5))]
        ),
        "Too many attempts. Try again in 5 seconds."
    );
    // String arguments holding numbers select plurals too (FormMessage.args).
    let args = [("seconds".to_owned(), "1".to_owned())]
        .into_iter()
        .collect();
    assert_eq!(
        c.text_with(&en, "login.too_many_attempts", &args),
        "Too many attempts. Try again in 1 second."
    );
}

#[test]
fn theme_override_replaces_an_embedded_message() {
    let dir = theme(&[("en", "main.ftl", "title-login = Log in to Acme\n")]);
    let c = Catalogs::load(Some(dir.path())).expect("catalogs");
    let en = Locale::fallback();
    assert_eq!(c.text(&en, "title.login", &[]), "Log in to Acme");
    assert_eq!(
        c.text(&en, "title.registration", &[]),
        "Create an account",
        "other messages keep the embedded text"
    );
}

#[test]
fn malformed_override_fails_with_the_file_name() {
    let dir = theme(&[("en", "broken.ftl", "title-login = Sign in\n= no id here\n")]);
    let err = Catalogs::load(Some(dir.path())).expect_err("malformed");
    let msg = err.to_string();
    assert!(msg.contains("broken.ftl"), "{msg}");
    assert!(msg.contains("line 2"), "{msg}");
}

#[test]
fn duplicate_ids_across_files_of_one_locale_fail_naming_both() {
    let dir = theme(&[
        ("de", "a.ftl", "title-login = Anmelden\n"),
        ("de", "b.ftl", "title-login = Einloggen\n"),
    ]);
    let msg = Catalogs::load(Some(dir.path()))
        .expect_err("duplicate")
        .to_string();
    assert!(msg.contains("a.ftl") && msg.contains("b.ftl"), "{msg}");
}

#[test]
fn every_ftl_file_of_a_locale_is_loaded() {
    let dir = theme(&[
        ("de", "main.ftl", "title-login = Anmelden\n"),
        ("de", "feature.ftl", "feature-hello = Hallo\n"),
    ]);
    let c = Catalogs::load(Some(dir.path())).expect("catalogs");
    let de = Locale::new("de");
    assert_eq!(c.text(&de, "title.login", &[]), "Anmelden");
    assert_eq!(c.text(&de, "feature.hello", &[]), "Hallo");
    assert_eq!(c.available(), vec!["de".to_owned(), "en".to_owned()]);
}

#[test]
fn invalid_locale_directory_fails() {
    let dir = theme(&[("not a tag!", "main.ftl", "x = y\n")]);
    assert!(Catalogs::load(Some(dir.path())).is_err());
}

#[test]
fn t_function_uses_page_lang_and_kwargs_and_escapes() {
    let dir = theme(&[(
        "de",
        "main.ftl",
        "title-login = Anmelden\nsessions-sign_out_device = { $device } abmelden\n",
    )]);
    std::fs::create_dir_all(dir.path().join("templates")).expect("mkdir");
    std::fs::write(
        dir.path().join("templates").join("i18n_probe.html"),
        r#"{{ t("title.login") }}|{{ t("sessions.sign_out_device", device=name) }}|{{ t("login.too_many_attempts", seconds=n) }}"#,
    )
    .expect("write");
    let r = Renderer::new(Some(dir.path())).expect("renderer");
    let html = |lang: Option<&str>| {
        r.page(
            "i18n_probe.html",
            context! { page => context! { lang => lang }, name => "<b>x</b>", n => 1 },
        )
        .expect("renders")
        .0
    };
    assert_eq!(
        html(Some("de")),
        "Anmelden|&lt;b&gt;x&lt;&#x2f;b&gt; abmelden|Too many attempts. Try again in 1 second."
    );
    assert!(
        html(None).starts_with("Sign in|Sign out &lt;b&gt;"),
        "{}",
        html(None)
    );
}

#[test]
fn renderer_rejects_a_broken_catalog_override() {
    let dir = theme(&[("en", "main.ftl", "{{{\n")]);
    assert!(Renderer::new(Some(dir.path())).is_err());
}

#[test]
fn embedded_english_has_every_message_key_in_use() {
    let c = Catalogs::load(None).expect("catalogs");
    let en = Locale::fallback();
    let keys = [
        // flow engine
        "login.invalid_credentials",
        "login.email_not_verified",
        "login.second_factor_invalid",
        "login.passkey_failed",
        "login.recovery_code_used",
        "registration.disabled",
        "registration.email_taken",
        "registration.check_email",
        "email.invalid",
        "password.too_short",
        "password.too_long",
        "password.breached",
        "recovery.sent",
        "recovery.invalid_token",
        "recovery.done",
        "verification.invalid_token",
        "verification.done",
        "flow.expired",
        "flow.invalid_input",
        "service.overloaded",
        // web sign-in
        "login.signed_in",
        "login.captcha_required",
        "login.captcha_failed",
        // sessions
        "sessions.revoked",
        "sessions.revoked_others",
        "sessions.not_found",
        // account
        "account.reauth_required",
        "account.flow_expired",
        "account.invalid_label",
        "account.passkey_failed",
        "account.passkey_exists",
        "account.totp_exists",
        "account.totp_not_pending",
        "account.totp_invalid_code",
        "account.totp_required",
        "account.credential_not_found",
        "account.try_again",
        "account.passkey_registered",
        "account.passkey_removed",
        "account.totp_removed",
        "account.totp_enrolled",
        "account.recovery_codes_regenerated",
        // consent and apps
        "consent.expired",
        "apps.revoked",
        "apps.not_found",
        "apps.expired",
        // field labels
        "field.email",
        "field.admin_email",
        "field.password",
        "field.name",
        "field.token",
        "field.code",
        "field.recovery_code",
    ];
    for key in keys {
        assert_ne!(c.text(&en, key, &[]), key, "{key} has no English text");
    }
}

#[test]
fn shipped_catalog_dir_is_where_the_embed_reads_it() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default/locales/en/main.ftl");
    assert!(path.is_file(), "{}", path.display());
}
