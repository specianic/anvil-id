//! Template rendering: a minijinja environment that loads the operator's theme directory first and
//! falls back to the embedded default theme (`themes/default/templates/`). `.html` templates are
//! auto-escaped.

use std::path::{Path, PathBuf};

use axum::response::Html;
use minijinja::{Environment, ErrorKind, Value};
use serde::Serialize;

use crate::errors::WebError;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

#[derive(rust_embed::Embed)]
#[folder = "../../themes/default/templates/"]
struct EmbeddedTemplates;

/// Renders page templates.
pub struct Renderer {
    env: Environment<'static>,
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
    /// subdirectory overrides individual templates). Every page template is compiled once here, so
    /// a broken override fails at startup rather than on the first request.
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
        let mut env = Environment::new();
        env.set_loader(move |name| load(override_dir.as_deref(), name));
        for name in EmbeddedTemplates::iter() {
            env.get_template(&name)?;
        }
        Ok(Self { env })
    }

    /// Renders a page template with the given context.
    pub fn page(&self, template: &str, ctx: Value) -> Result<Html<String>, WebError> {
        Ok(Html(self.env.get_template(template)?.render(ctx)?))
    }
}

/// Links between self-service pages; `None` hides the link.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PageLinks {
    pub login: Option<String>,
    pub registration: Option<String>,
    pub recovery: Option<String>,
}

/// The `page` object every template receives (themes/default/README.md).
#[derive(Debug, Clone, Serialize)]
pub struct PageContext {
    pub title: String,
    pub tenant_name: Option<String>,
    pub dev_mode: bool,
    pub asset_base: String,
    pub links: PageLinks,
}

impl PageContext {
    /// Page context for a tenant page. Asset URLs live below the tenant base path.
    pub fn for_tenant(state: &AppState, tenant: &ResolvedTenant, title: &str) -> Self {
        Self {
            title: title.to_owned(),
            tenant_name: Some(tenant.tenant.display_name.clone()),
            dev_mode: state.config().dev_mode(),
            asset_base: format!("{}/assets", tenant.base_path()),
            links: PageLinks::default(),
        }
    }

    /// Page context for installation-level pages (setup, errors before a tenant is known).
    pub fn installation(state: &AppState, title: &str) -> Self {
        Self {
            title: title.to_owned(),
            tenant_name: None,
            dev_mode: state.config().dev_mode(),
            asset_base: "/assets".to_owned(),
            links: PageLinks::default(),
        }
    }

    pub fn into_value(self) -> Value {
        Value::from(minijinja::value::Serde(self))
    }
}

/// The `page` object for a tenant page, without links.
pub fn page_context(state: &AppState, tenant: &ResolvedTenant, title: &str) -> Value {
    PageContext::for_tenant(state, tenant, title).into_value()
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
    fn missing_theme_dir_is_a_config_error() {
        let err = Renderer::new(Some(Path::new("/nonexistent/anvil-theme"))).expect_err("missing");
        assert!(matches!(err, WebError::Config(_)));
    }
}
