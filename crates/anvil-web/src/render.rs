//! Template rendering: a minijinja environment that loads the operator's theme directory first and
//! falls back to the embedded default theme (`themes/default/templates/`). `.html` templates are
//! auto-escaped.
//!
//! Every template can call `t(key, **kwargs)` ([`crate::i18n`]): it translates in the page's
//! `page.lang` (set by [`PageContext`] from the negotiated [`Locale`]), English when absent.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anvil_core::flow::form::FormDescription;

use axum::response::Html;
use minijinja::{Environment, ErrorKind, Value};
use serde::Serialize;

use crate::errors::WebError;
use crate::i18n::{self, Catalogs, Locale};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

#[derive(rust_embed::Embed)]
#[folder = "../../themes/default/templates/"]
struct EmbeddedTemplates;

/// Renders page templates and owns the message catalogs.
pub struct Renderer {
    env: Environment<'static>,
    catalogs: Arc<Catalogs>,
}

impl std::fmt::Debug for Renderer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Renderer").finish_non_exhaustive()
    }
}

/// Template names are plain file names or relative paths of plain segments.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && name
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn load(override_dir: Option<&Path>, name: &str) -> Result<Option<String>, minijinja::Error> {
    if !is_safe_name(name) {
        return Ok(None);
    }
    if let Some(dir) = override_dir {
        match std::fs::read_to_string(dir.join(name)) {
            Ok(source) => return Ok(Some(source)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(minijinja::Error::new(
                    ErrorKind::InvalidOperation,
                    format!("cannot read theme template {name}"),
                )
                .with_source(e));
            }
        }
    }
    Ok(EmbeddedTemplates::get(name).map(|f| String::from_utf8_lossy(&f.data).into_owned()))
}

impl Renderer {
    /// Builds the environment. `theme_dir` is the operator theme root (its `templates/`
    /// subdirectory overrides individual templates, its `locales/` subdirectory individual
    /// messages). Every page template and catalog is loaded once here, so a broken override fails
    /// at startup rather than on the first request.
    pub fn new(theme_dir: Option<&Path>) -> Result<Self, WebError> {
        let override_dir: Option<PathBuf> = match theme_dir {
            Some(dir) if !dir.is_dir() => {
                return Err(WebError::Config(format!(
                    "theme directory {} does not exist",
                    dir.display()
                )));
            }
            Some(dir) => Some(dir.join("templates")),
            None => None,
        };
        let catalogs = Arc::new(Catalogs::load(theme_dir)?);
        let mut env = Environment::new();
        env.set_loader(move |name| load(override_dir.as_deref(), name));
        env.add_function("t", i18n::template_function(Arc::clone(&catalogs)));
        for name in EmbeddedTemplates::iter() {
            env.get_template(&name)?;
        }
        Ok(Self { env, catalogs })
    }

    /// Renders a page template with the given context. `t()` translates in `page.lang`.
    ///
    /// When the page links the tenant theme (`page.theme_css`) and carries a flow-bound action
    /// (`form.action` or `action` with `?flow={id}`), the theme link gets `?flow={id}` so the theme
    /// route can resolve the flow's client server-side (UI-03); page handlers stay unchanged.
    pub fn page(&self, template: &str, ctx: Value) -> Result<Html<String>, WebError> {
        let ctx = with_flow_theme(ctx);
        Ok(Html(self.env.get_template(template)?.render(ctx)?))
    }

    /// The message catalogs.
    pub fn catalogs(&self) -> &Catalogs {
        &self.catalogs
    }

    /// The text of `key` in `locale` (English fallback, else the key).
    pub fn text(&self, locale: &Locale, key: &str) -> String {
        self.catalogs.text(locale, key, &[])
    }

    /// Fills the labels and message texts of `form` in `locale` ([`i18n::localize_form`]).
    pub fn localize_form(&self, locale: &Locale, form: &mut FormDescription) {
        i18n::localize_form(&self.catalogs, locale, form);
    }
}

/// The flow id of a flow-bound action (`…?flow={id}`, possibly followed by more parameters).
/// Only a UUID is accepted, so the value is safe to put back into a URL.
fn flow_of_action(action: &str) -> Option<uuid::Uuid> {
    let (_, rest) = action.rsplit_once("?flow=")?;
    uuid::Uuid::parse_str(rest.split('&').next().unwrap_or_default()).ok()
}

/// Adds `?flow={id}` to `page.theme_css` when the context has a flow-bound action.
fn with_flow_theme(ctx: Value) -> Value {
    let Ok(page) = ctx.get_attr("page") else {
        return ctx;
    };
    let Some(theme) = page
        .get_attr("theme_css")
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|s| !s.is_empty() && !s.contains('?'))
    else {
        return ctx;
    };
    let action = ctx
        .get_attr("form")
        .and_then(|f| f.get_attr("action"))
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .or_else(|| {
            ctx.get_attr("action")
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
        });
    let Some(flow) = action.as_deref().and_then(flow_of_action) else {
        return ctx;
    };
    let page = minijinja::context! { theme_css => format!("{theme}?flow={flow}"), ..page };
    minijinja::context! { page => page, ..ctx }
}

/// Links between self-service pages; `None` hides the link. Built by `ui::nav::NavContext`
/// (themes/default/README.md lists the element ids).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PageLinks {
    pub login: Option<String>,
    pub registration: Option<String>,
    pub recovery: Option<String>,
    /// The account page (`#link-account`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The action of the sign-out form (`#form-sign-out`, `method="post"`). The end-session
    /// endpoint, which only asks for confirmation without an `id_token_hint`; never a `GET`
    /// that signs out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_out: Option<String>,
    /// "Continue to &lt;app&gt;" of a live authorization request (`#link-continue`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_to: Option<ContinueLink>,
    /// The admin console (`#link-console`, system tenant only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console: Option<String>,
}

/// The "Continue to &lt;app&gt;" link of a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinueLink {
    pub href: String,
    pub app_name: String,
}

/// The `page` object every template receives (themes/default/README.md).
#[derive(Debug, Clone, Serialize)]
pub struct PageContext {
    /// Negotiated language tag (`<html lang>`, and the language of `t()`).
    pub lang: String,
    /// `ltr` or `rtl` (`<html dir>`).
    pub dir: &'static str,
    pub title: String,
    pub tenant_name: Option<String>,
    pub dev_mode: bool,
    pub asset_base: String,
    /// The tenant theme stylesheet (`{tenant_base}/theme/theme.css`, UI-03); `None` on
    /// installation pages. [`Renderer::page`] appends `?flow={id}` on flow pages.
    pub theme_css: Option<String>,
    pub links: PageLinks,
}

impl PageContext {
    /// Page context for a tenant page in `locale`; `title_key` is the message key of the title.
    /// Asset URLs live below the tenant base path.
    pub fn for_tenant(
        state: &AppState,
        tenant: &ResolvedTenant,
        locale: &Locale,
        title_key: &str,
    ) -> Self {
        Self {
            lang: locale.tag.clone(),
            dir: locale.dir,
            title: state.renderer().text(locale, title_key),
            tenant_name: Some(tenant.tenant.display_name.clone()),
            dev_mode: state.config().dev_mode(),
            asset_base: format!("{}/assets", tenant.base_path()),
            theme_css: Some(format!("{}/theme/theme.css", tenant.base_path())),
            links: PageLinks::default(),
        }
    }

    /// Page context for installation-level pages (setup, errors before a tenant is known).
    pub fn installation(state: &AppState, locale: &Locale, title_key: &str) -> Self {
        Self {
            lang: locale.tag.clone(),
            dir: locale.dir,
            title: state.renderer().text(locale, title_key),
            tenant_name: None,
            dev_mode: state.config().dev_mode(),
            asset_base: "/assets".to_owned(),
            theme_css: None,
            links: PageLinks::default(),
        }
    }

    pub fn into_value(self) -> Value {
        Value::from(minijinja::value::Serde(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_template_names() {
        for n in ["", "..", "../x.html", "a/../b", "/etc/passwd", "a\\b"] {
            assert!(!is_safe_name(n), "{n}");
            assert!(load(None, n).expect("no error").is_none(), "{n}");
        }
        assert!(is_safe_name("login.html"));
    }

    #[test]
    fn embedded_templates_compile() {
        let r = Renderer::new(None).expect("renderer");
        assert!(r.env.get_template("login.html").is_ok());
    }

    #[test]
    fn flow_pages_link_the_flow_theme() {
        let r = Renderer::new(None).expect("renderer");
        let flow = "0190f5b8-6b5e-7cc0-8b1a-1c2d3e4f5a6b";
        let page = minijinja::context! {
            title => "T", tenant_name => "Acme", asset_base => "/t/acme/assets",
            theme_css => "/t/acme/theme/theme.css",
        };
        let html = r
            .page(
                "consent.html",
                minijinja::context! {
                    page => page.clone(),
                    action => format!("/t/acme/ui/consent?flow={flow}&request=x"),
                    scopes => Vec::<Value>::new(),
                },
            )
            .expect("renders")
            .0
            .replace("&#x2f;", "/");
        assert!(
            html.contains(&format!(r#"href="/t/acme/theme/theme.css?flow={flow}""#)),
            "{html}"
        );
        // A non-UUID flow value is not carried.
        let html = r
            .page(
                "consent.html",
                minijinja::context! { page => page, action => "/x?flow=\"><b>", scopes => Vec::<Value>::new() },
            )
            .expect("renders")
            .0
            .replace("&#x2f;", "/");
        assert!(html.contains(r#"href="/t/acme/theme/theme.css""#), "{html}");
    }

    #[test]
    fn missing_theme_dir_is_a_config_error() {
        let err = Renderer::new(Some(Path::new("/nonexistent/anvil-theme"))).expect_err("missing");
        assert!(matches!(err, WebError::Config(_)));
    }
}
