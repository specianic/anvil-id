//! Page translations (UI-04): Fluent message catalogs, locale negotiation and the `t()` template
//! function.
//!
//! # Catalogs
//!
//! The default theme embeds `themes/default/locales/{lang}/*.ftl`. Every `.ftl` file of a locale
//! directory is loaded in file name order, so each feature ships its own file
//! (`locales/en/main.ftl`, `locales/en/<feature>.ftl`) and parallel work never edits the same
//! catalog. Two files of one locale defining the same message id is a startup error naming both
//! files. An operator theme directory may add `{theme_dir}/locales/{lang}/*.ftl`: those files are
//! applied on top of the embedded ones and win per message id; they may also add new locales. A
//! malformed file fails [`Catalogs::load`] with its name and line.
//!
//! Message ids are the dotted keys used by code and templates with `.` replaced by `-`
//! ([`fluent_id`]): Fluent identifiers cannot contain dots. Isolation marks are off (they would
//! break exact-text matching of the English sentences).
//!
//! # Lookup
//!
//! [`Catalogs::text`] formats a message of the negotiated locale, falls back to English when the
//! locale lacks it, and returns the dotted key itself (with a debug log) when no catalog has it.
//! It never panics.
//!
//! # Negotiation
//!
//! [`negotiate`] picks the first source that matches an available locale, in this order:
//! `ui_locales` (authorization request or query parameter) > the user's `locale` claim (account
//! pages only) > `Accept-Language` > the tenant's `default_locale` > `en`. Unknown or malformed
//! tags are skipped, never an error.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anvil_core::flow::form::FormDescription;
use anvil_core::model::AuthorizationParams;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentError, FluentResource, FluentValue};
use fluent_langneg::{NegotiationStrategy, negotiate_languages};

use crate::errors::WebError;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

#[derive(rust_embed::Embed)]
#[folder = "../../themes/default/locales/"]
struct EmbeddedLocales;

/// The fallback locale: every message exists in English.
pub const FALLBACK: &str = "en";

/// Primary language subtags written right to left.
const RTL_LANGUAGES: &[&str] = &["ar", "he", "fa", "ur", "ps", "yi"];

/// The Fluent message id of a dotted key: `login.invalid_credentials` -> `login-invalid_credentials`.
pub fn fluent_id(key: &str) -> String {
    key.replace('.', "-")
}

/// A negotiated page language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locale {
    /// BCP 47 tag of an available catalog (`en`, `de`, `pt-BR`); goes into `<html lang>`.
    pub tag: String,
    /// `ltr` or `rtl`; goes into `<html dir>`.
    pub dir: &'static str,
    /// The explicit `ui_locales` value this page honours, if any. Pages carry it on their form
    /// actions (`&ui_locales=`) so the following POSTs keep the language the client asked for.
    pub ui_locales: Option<String>,
}

impl Locale {
    /// The locale for an available tag, with its text direction.
    pub fn new(tag: &str) -> Self {
        Self {
            tag: tag.to_owned(),
            dir: direction(tag),
            ui_locales: None,
        }
    }

    /// English (the fallback locale).
    pub fn fallback() -> Self {
        Self::new(FALLBACK)
    }
}

/// `rtl` when the primary language subtag is written right to left, else `ltr`.
pub fn direction(tag: &str) -> &'static str {
    let primary = tag
        .split(['-', '_'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if RTL_LANGUAGES.contains(&primary.as_str()) {
        "rtl"
    } else {
        "ltr"
    }
}

/// The sources of a negotiation, strongest first (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct LocaleInputs<'a> {
    /// Space-separated tags (OIDC `ui_locales`).
    pub ui_locales: Option<&'a str>,
    /// The user's `locale` claim (account pages).
    pub user_locale: Option<&'a str>,
    /// The raw `Accept-Language` header.
    pub accept_language: Option<&'a str>,
    /// The tenant's `default_locale` (installation pages: `en`).
    pub tenant_default: &'a str,
}

/// A source file of a catalog layer.
struct Source {
    /// Display name for errors (`embedded:en/main.ftl` or the file path).
    name: String,
    resource: Arc<FluentResource>,
}

type Bundle = FluentBundle<Arc<FluentResource>>;

/// The loaded catalogs, one Fluent bundle per locale.
pub struct Catalogs {
    bundles: BTreeMap<String, Bundle>,
}

impl std::fmt::Debug for Catalogs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Catalogs")
            .field("locales", &self.available())
            .finish()
    }
}

/// A locale directory name must be a valid language tag.
fn langid(tag: &str) -> Option<unic_langid::LanguageIdentifier> {
    tag.parse().ok()
}

fn parse(name: String, source: String) -> Result<Source, WebError> {
    match FluentResource::try_new(source) {
        Ok(resource) => Ok(Source {
            name,
            resource: Arc::new(resource),
        }),
        Err((resource, errors)) => {
            let detail = errors
                .first()
                .map(|e| {
                    let line = resource.source()[..e.pos.start.min(resource.source().len())]
                        .matches('\n')
                        .count()
                        + 1;
                    format!("line {line}: {e}")
                })
                .unwrap_or_default();
            Err(WebError::Config(format!(
                "malformed message catalog {name}: {detail}"
            )))
        }
    }
}

/// The first id a resource would redefine when added to `bundle`.
fn redefined(bundle: &mut Bundle, resource: &Arc<FluentResource>) -> Option<String> {
    match bundle.add_resource(Arc::clone(resource)) {
        Ok(()) => None,
        Err(errors) => errors.into_iter().find_map(|e| match e {
            FluentError::Overriding { id, .. } => Some(id),
            _ => None,
        }),
    }
}

/// Checks that no two files of one layer define the same id (the error names both files).
fn check_layer(tag: &str, files: &[Source]) -> Result<(), WebError> {
    let lang = langid(tag).unwrap_or_default();
    for (i, file) in files.iter().enumerate() {
        let mut own = Bundle::new_concurrent(vec![lang.clone()]);
        if let Some(id) = redefined(&mut own, &file.resource) {
            return Err(WebError::Config(format!(
                "message catalog {} defines {id} twice",
                file.name
            )));
        }
        for earlier in &files[..i] {
            let mut pair = Bundle::new_concurrent(vec![lang.clone()]);
            let _ = redefined(&mut pair, &earlier.resource);
            if let Some(id) = redefined(&mut pair, &file.resource) {
                return Err(WebError::Config(format!(
                    "message id {id} is defined in both {} and {}",
                    earlier.name, file.name
                )));
            }
        }
    }
    Ok(())
}

/// The embedded files, by locale, in file name order.
fn embedded_layer() -> Result<BTreeMap<String, Vec<Source>>, WebError> {
    let mut paths: Vec<String> = EmbeddedLocales::iter().map(|p| p.into_owned()).collect();
    paths.sort();
    let mut layer: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    for path in paths {
        let Some((tag, file)) = path.split_once('/') else {
            continue;
        };
        if file.contains('/') || !file.ends_with(".ftl") {
            continue;
        }
        let Some(file) = EmbeddedLocales::get(&path) else {
            continue;
        };
        let source = String::from_utf8(file.data.into_owned()).map_err(|_| {
            WebError::Config(format!("message catalog embedded:{path} is not UTF-8"))
        })?;
        layer
            .entry(tag.to_owned())
            .or_default()
            .push(parse(format!("embedded:{path}"), source)?);
    }
    Ok(layer)
}

/// `{theme_dir}/locales/{lang}/*.ftl`, by locale, in file name order. A missing `locales`
/// directory is no override.
fn theme_layer(theme_dir: &Path) -> Result<BTreeMap<String, Vec<Source>>, WebError> {
    let root = theme_dir.join("locales");
    let mut layer: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(layer),
        Err(e) => {
            return Err(WebError::Config(format!(
                "cannot read {}: {e}",
                root.display()
            )));
        }
    };
    let read_err = |p: &Path, e: std::io::Error| {
        WebError::Config(format!("cannot read message catalog {}: {e}", p.display()))
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| read_err(&root, e))?;
        if entry.path().is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    for dir in dirs {
        let Some(tag) = dir.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        if langid(&tag).is_none() {
            return Err(WebError::Config(format!(
                "locale directory {} is not a language tag",
                dir.display()
            )));
        }
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| read_err(&dir, e))? {
            let path = entry.map_err(|e| read_err(&dir, e))?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("ftl") && path.is_file() {
                files.push(path);
            }
        }
        files.sort();
        for path in files {
            let source = std::fs::read_to_string(&path).map_err(|e| read_err(&path, e))?;
            layer
                .entry(tag.clone())
                .or_default()
                .push(parse(path.display().to_string(), source)?);
        }
    }
    Ok(layer)
}

impl Catalogs {
    /// Loads the embedded catalogs and applies `{theme_dir}/locales` on top (module docs).
    pub fn load(theme_dir: Option<&Path>) -> Result<Self, WebError> {
        let embedded = embedded_layer()?;
        let theme = match theme_dir {
            Some(dir) => theme_layer(dir)?,
            None => BTreeMap::new(),
        };
        let tags: BTreeSet<&String> = embedded.keys().chain(theme.keys()).collect();
        let mut bundles = BTreeMap::new();
        for tag in tags {
            let lang = langid(tag).ok_or_else(|| {
                WebError::Config(format!("locale directory {tag} is not a language tag"))
            })?;
            let mut bundle = Bundle::new_concurrent(vec![lang]);
            bundle.set_use_isolating(false);
            if let Some(files) = embedded.get(tag) {
                check_layer(tag, files)?;
                for f in files {
                    // Duplicates were rejected by check_layer.
                    let _ = bundle.add_resource(Arc::clone(&f.resource));
                }
            }
            if let Some(files) = theme.get(tag) {
                check_layer(tag, files)?;
                for f in files {
                    bundle.add_resource_overriding(Arc::clone(&f.resource));
                }
            }
            bundles.insert(tag.clone(), bundle);
        }
        if !bundles.contains_key(FALLBACK) {
            return Err(WebError::Config("no English message catalog".into()));
        }
        Ok(Self { bundles })
    }

    /// The available locale tags, sorted.
    pub fn available(&self) -> Vec<String> {
        self.bundles.keys().cloned().collect()
    }

    /// Whether `locale` (or English) has a message for `key`.
    pub fn has(&self, locale: &Locale, key: &str) -> bool {
        let id = fluent_id(key);
        [locale.tag.as_str(), FALLBACK]
            .iter()
            .any(|tag| self.bundles.get(*tag).is_some_and(|b| b.has_message(&id)))
    }

    /// The text of `key` in `locale`, else in English, else the key itself (logged at debug).
    /// String arguments that are numbers become Fluent numbers (plural selection).
    pub fn text(&self, locale: &Locale, key: &str, args: &[(&str, FluentValue<'_>)]) -> String {
        let id = fluent_id(key);
        for tag in [locale.tag.as_str(), FALLBACK] {
            let Some(bundle) = self.bundles.get(tag) else {
                continue;
            };
            let Some(pattern) = bundle.get_message(&id).and_then(|m| m.value()) else {
                continue;
            };
            let mut fluent_args = FluentArgs::new();
            for (name, value) in args {
                fluent_args.set(*name, value.clone());
            }
            let mut errors = Vec::new();
            let text = bundle.format_pattern(pattern, Some(&fluent_args), &mut errors);
            if !errors.is_empty() {
                tracing::debug!(
                    key,
                    locale = tag,
                    ?errors,
                    "formatting a message reported errors"
                );
            }
            return text.into_owned();
        }
        tracing::debug!(key, locale = %locale.tag, "no catalog has this message");
        key.to_owned()
    }

    /// [`Catalogs::text`] with string arguments (numbers are detected).
    pub fn text_with(&self, locale: &Locale, key: &str, args: &BTreeMap<String, String>) -> String {
        let args: Vec<(&str, FluentValue<'_>)> = args
            .iter()
            .map(|(k, v)| (k.as_str(), FluentValue::try_number(v.as_str())))
            .collect();
        self.text(locale, key, &args)
    }
}

/// The best available locale for a list of requested tags, if any matches.
fn best_match(catalogs: &Catalogs, requested: &[&str]) -> Option<String> {
    let requested: Vec<fluent_langneg::LanguageIdentifier> = requested
        .iter()
        .filter_map(|t| t.replace('_', "-").parse().ok())
        .collect();
    if requested.is_empty() {
        return None;
    }
    let tags = catalogs.available();
    let available: Vec<fluent_langneg::LanguageIdentifier> =
        tags.iter().filter_map(|t| t.parse().ok()).collect();
    let chosen = negotiate_languages(&requested, &available, None, NegotiationStrategy::Filtering);
    chosen.first().map(|l| l.to_string())
}

/// `Accept-Language` tags in preference order (q-values, stable); `q=0` and `*` are dropped.
pub fn accept_language_tags(header: &str) -> Vec<String> {
    let mut weighted: Vec<(u16, String)> = header
        .split(',')
        .filter_map(|part| {
            let mut pieces = part.split(';');
            let tag = pieces.next()?.trim();
            if tag.is_empty() || tag == "*" {
                return None;
            }
            let mut q = 1000u16;
            for p in pieces {
                if let Some(v) = p.trim().strip_prefix("q=") {
                    let v: f32 = v.trim().parse().ok()?;
                    if !(0.0..=1.0).contains(&v) {
                        return None;
                    }
                    // Bounded to 0..=1000 by the check above.
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "q is checked to lie in 0..=1"
                    )]
                    {
                        q = (v * 1000.0).round() as u16;
                    }
                }
            }
            (q > 0).then(|| (q, tag.to_owned()))
        })
        .collect();
    weighted.sort_by_key(|w| std::cmp::Reverse(w.0));
    weighted.into_iter().map(|(_, t)| t).collect()
}

/// Picks the page language (module docs). Always returns an available locale.
pub fn negotiate(catalogs: &Catalogs, inputs: &LocaleInputs<'_>) -> Locale {
    if let Some(ui) = inputs.ui_locales {
        let requested: Vec<&str> = ui.split_whitespace().collect();
        if let Some(tag) = best_match(catalogs, &requested) {
            let mut locale = Locale::new(&tag);
            locale.ui_locales = Some(requested.join(" "));
            return locale;
        }
    }
    if let Some(user) = inputs.user_locale
        && let Some(tag) = best_match(catalogs, &[user.trim()])
    {
        return Locale::new(&tag);
    }
    if let Some(accept) = inputs.accept_language {
        let tags = accept_language_tags(accept);
        let requested: Vec<&str> = tags.iter().map(String::as_str).collect();
        if let Some(tag) = best_match(catalogs, &requested) {
            return Locale::new(&tag);
        }
    }
    if let Some(tag) = best_match(catalogs, &[inputs.tenant_default]) {
        return Locale::new(&tag);
    }
    Locale::fallback()
}

/// The tenant's default locale (installation pages: `en`).
fn tenant_default(tenant: Option<&ResolvedTenant>) -> &str {
    tenant.map_or(FALLBACK, |t| t.tenant.settings.default_locale.as_str())
}

/// The locale of a page without request input: the tenant default, else English. Used where no
/// request headers are at hand (error pages raised by layers).
pub fn default_locale(catalogs: &Catalogs, tenant: Option<&ResolvedTenant>) -> Locale {
    negotiate(
        catalogs,
        &LocaleInputs {
            tenant_default: tenant_default(tenant),
            ..LocaleInputs::default()
        },
    )
}

fn accept_language(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
}

/// The locale of a page that continues an authorization request: its stored `ui_locales` first,
/// then `Accept-Language` and the tenant default.
pub fn locale_for_request(
    state: &AppState,
    tenant: &ResolvedTenant,
    headers: &HeaderMap,
    params: Option<&AuthorizationParams>,
) -> Locale {
    negotiate(
        state.renderer().catalogs(),
        &LocaleInputs {
            ui_locales: params.and_then(|p| p.ui_locales.as_deref()),
            user_locale: None,
            accept_language: accept_language(headers),
            tenant_default: tenant_default(Some(tenant)),
        },
    )
}

/// The locale of an account page: the request's explicit `ui_locales`, then the user's `locale`
/// claim, then `Accept-Language` and the tenant default.
pub fn locale_for_user(
    state: &AppState,
    tenant: &ResolvedTenant,
    request: &RequestLocale,
    user_locale: Option<&str>,
) -> Locale {
    negotiate(
        state.renderer().catalogs(),
        &LocaleInputs {
            ui_locales: request.0.ui_locales.as_deref(),
            user_locale,
            accept_language: request.1.as_deref(),
            tenant_default: tenant_default(Some(tenant)),
        },
    )
}

/// The negotiated locale of a request: an optional `ui_locales` query parameter, then
/// `Accept-Language`, then the resolved tenant's default (installation pages: `en`). Never
/// rejects. The second field keeps the raw `Accept-Language` for a later re-negotiation with
/// the user's claim ([`locale_for_user`]).
#[derive(Debug, Clone)]
pub struct RequestLocale(pub Locale, pub Option<String>);

impl FromRequestParts<AppState> for RequestLocale {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Infallible> {
        let tenant = parts.extensions.get::<ResolvedTenant>();
        let ui_locales = parts.uri.query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "ui_locales")
                .map(|(_, v)| v.into_owned())
        });
        let accept = accept_language(&parts.headers).map(str::to_owned);
        let locale = negotiate(
            state.renderer().catalogs(),
            &LocaleInputs {
                ui_locales: ui_locales.as_deref(),
                user_locale: None,
                accept_language: accept.as_deref(),
                tenant_default: tenant_default(tenant),
            },
        );
        Ok(Self(locale, accept))
    }
}

/// Appends `&ui_locales=` (or `?ui_locales=`) to `url` when the locale honours an explicit
/// `ui_locales` request.
pub fn carry_ui_locales(url: &str, locale: &Locale) -> String {
    match &locale.ui_locales {
        Some(ui) if !url.contains("ui_locales=") => {
            let sep = if url.contains('?') { '&' } else { '?' };
            let encoded: String = url::form_urlencoded::byte_serialize(ui.as_bytes()).collect();
            format!("{url}{sep}ui_locales={encoded}")
        }
        _ => url.to_owned(),
    }
}

/// Fills every field `label` (from `label_key`) and every message `text` (from `key` and
/// `args`) of `form` in `locale`.
pub fn localize_form(catalogs: &Catalogs, locale: &Locale, form: &mut FormDescription) {
    for m in &mut form.messages {
        m.text = catalogs.text_with(locale, &m.key, &m.args);
    }
    for f in &mut form.fields {
        if !f.label_key.is_empty() {
            f.label = catalogs.text(locale, &f.label_key, &[]);
        }
        for m in &mut f.messages {
            m.text = catalogs.text_with(locale, &m.key, &m.args);
        }
    }
}

/// The minijinja `t(key, **kwargs)` function. The locale is the rendered page's `page.lang`
/// (English when absent), so imported macros and included partials translate the same way.
/// Keyword arguments become Fluent arguments (numbers stay numbers). The result is a plain
/// string: auto-escaping applies, it is never marked safe.
pub(crate) fn template_function(
    catalogs: Arc<Catalogs>,
) -> impl Fn(
    &minijinja::State<'_, '_>,
    &str,
    minijinja::value::Kwargs,
) -> Result<String, minijinja::Error>
+ Send
+ Sync
+ 'static {
    move |state, key, kwargs| {
        let tag = state
            .lookup("page")
            .and_then(|p| p.get_attr("lang").ok())
            .filter(|v| !v.is_undefined() && !v.is_none())
            .map(|v| v.to_string())
            .unwrap_or_else(|| FALLBACK.to_owned());
        let locale = Locale::new(&tag);
        let mut args: Vec<(String, FluentValue<'static>)> = Vec::new();
        for name in kwargs.args() {
            let value: minijinja::Value = kwargs.get(name)?;
            let fluent = match value.as_i64() {
                Some(n) if value.kind() == minijinja::value::ValueKind::Number => {
                    FluentValue::from(n)
                }
                _ if value.kind() == minijinja::value::ValueKind::Number => value
                    .to_string()
                    .parse::<f64>()
                    .map_or_else(|_| FluentValue::from(value.to_string()), FluentValue::from),
                _ => FluentValue::from(value.to_string()),
            };
            args.push((name.to_owned(), fluent));
        }
        kwargs.assert_all_used()?;
        let borrowed: Vec<(&str, FluentValue<'_>)> =
            args.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        Ok(catalogs.text(&locale, key, &borrowed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fluent_ids_replace_dots() {
        assert_eq!(
            fluent_id("login.invalid_credentials"),
            "login-invalid_credentials"
        );
        assert_eq!(fluent_id("a.b_c"), "a-b_c");
    }

    #[test]
    fn accept_language_respects_q_values() {
        assert_eq!(
            accept_language_tags("fr;q=0.5, de, en;q=0.8, *;q=0.1, it;q=0"),
            vec!["de", "en", "fr"]
        );
        assert!(accept_language_tags("").is_empty());
        assert!(accept_language_tags("de;q=abc").is_empty());
    }

    #[test]
    fn embedded_catalog_loads_with_english() {
        let c = Catalogs::load(None).expect("embedded catalogs load");
        assert!(c.available().contains(&"en".to_owned()));
        assert_eq!(c.text(&Locale::fallback(), "title.login", &[]), "Sign in");
    }

    #[test]
    fn carry_appends_only_explicit_ui_locales() {
        let mut l = Locale::fallback();
        assert_eq!(carry_ui_locales("/ui/login?flow=x", &l), "/ui/login?flow=x");
        l.ui_locales = Some("de en".into());
        assert_eq!(
            carry_ui_locales("/ui/login?flow=x", &l),
            "/ui/login?flow=x&ui_locales=de+en"
        );
        assert_eq!(
            carry_ui_locales("/ui/login", &l),
            "/ui/login?ui_locales=de+en"
        );
    }
}
