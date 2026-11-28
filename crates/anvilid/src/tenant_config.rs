//! `anvilid tenant export|plan|apply`: declarative tenant configuration as YAML (ADM-06, ADM-07).
//!
//! The commands open the database with the server's configuration (next to a running server, no
//! migrations, like `keys rotate`) and call the same `ConfigService` as the admin API; there is
//! no HTTP involved. YAML is converted to and from the JSON document with serde-saphyr.
//!
//! Secret fields accept, besides `{configured: true|false}` and `{value: "…"}`, references that
//! are resolved here, on the operator's machine, before the document reaches the service:
//!
//! - `{env: NAME}`: the value of the environment variable `NAME` (must be set and non-empty);
//! - `{file: path}`: the contents of the file, without one trailing newline; a relative path is
//!   relative to the document's directory.
//!
//! `apply` prints the plan first and applies only with `--yes` or after an interactive
//! confirmation (refused when stdin is not a terminal). Deletions need `--prune`. Secrets the
//! server generates (new clients and webhooks without a secret) are printed once.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::{AuditActor, RequestContext, Scope, TenantConfigDocument};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::service::admin_scope::ADMIN_WRITE;
use anvil_core::service::attribute::AttributeService;
use anvil_core::service::branding::BrandingService;
use anvil_core::service::client::ClientService;
use anvil_core::service::config::{ApplyOutcome, ApplyRequest, ConfigError, ConfigService, render};
use anvil_core::service::connection::ConnectionService;
use anvil_core::service::mail_settings::MailSettingsService;
use anvil_core::service::role::RoleService;
use anvil_core::service::tenant::TenantService;
use anvil_core::service::webhook::WebhookService;
use anvil_web::adapters::attribute_schema::JsonSchemaCheck;
use anvil_web::adapters::upstream::UpstreamHttp;
use anvil_web::config::AppConfig;
use anyhow::{Context, bail};
use secrecy::ExposeSecret as _;
use serde_json::Value;

use crate::config::{CliOverrides, Config};
use crate::startup;

/// `tenant export` arguments.
#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// Slug of the tenant to export.
    #[arg(value_name = "SLUG")]
    pub slug: String,

    /// Write the YAML document to this file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// `tenant plan` arguments.
#[derive(Debug, clap::Args)]
pub struct PlanArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// The YAML document (`-` for stdin).
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: PathBuf,
}

/// `tenant apply` arguments.
#[derive(Debug, clap::Args)]
pub struct ApplyArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// The YAML document (`-` for stdin; then --yes is required).
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: PathBuf,

    /// Also delete what the document no longer lists (clients, connections, roles, ...).
    #[arg(long)]
    pub prune: bool,

    /// Apply without asking for confirmation.
    #[arg(long)]
    pub yes: bool,
}

/// The services the admin API uses, on the CLI's storage and KEK.
async fn service(cfg: &Config) -> anyhow::Result<ConfigService> {
    let (storage, kek) = startup::open_for_cli(cfg).await?;
    let kek = Arc::new(kek);
    let clock: Arc<dyn anvil_core::ports::Clock> = Arc::new(SystemClock);
    // The webhook URL policy of the server: the same outbound settings as `serve`.
    let mut app_config = AppConfig::new(cfg.public_url.clone());
    // `insecure_http` first: `outbound_client` reads development mode from it.
    app_config.insecure_http = cfg.insecure_http;
    let outbound = startup::outbound_client(cfg, &mut app_config)?;
    Ok(ConfigService {
        tenants: TenantService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock),
            kek: Arc::clone(&kek),
        },
        clients: ClientService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock),
            redirect_validator: validate_redirect_uri,
        },
        connections: ConnectionService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock),
            kek: Arc::clone(&kek),
            // SAML connections are never part of tenant YAML.
            saml_enabled: false,
            saml_xml: None,
            // Enabling a generic OIDC connection checks its issuer like the admin API does.
            upstream: Some(Arc::new(UpstreamHttp::new(Arc::clone(&outbound)))),
        },
        branding: BrandingService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock),
        },
        roles: RoleService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock),
        },
        attributes: AttributeService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock),
            check: Arc::new(JsonSchemaCheck::new()),
        },
        webhooks: WebhookService {
            storage: Arc::clone(&storage),
            kek: Arc::clone(&kek),
            clock: Arc::clone(&clock),
            url_check: outbound,
        },
        mail: MailSettingsService {
            storage,
            clock,
            kek,
            checker: Arc::new(anvil_mail::TemplateChecker),
            tester: Arc::new(anvil_mail::LettreSmtpTester::default()),
        },
        installation_smtp: cfg.smtp_url.is_some(),
        dev_mode: app_config.dev_mode(),
    })
}

/// The header of an exported file.
fn header(slug: &str) -> String {
    format!(
        "# AnvilID tenant configuration (kind TenantConfig, version 1) of tenant `{slug}`.\n\
         # Generated by anvilid {}. Secrets are not exported: `{{configured: true}}` keeps the\n\
         # stored value. To set a secret write `{{value: ...}}`, `{{env: NAME}}` or\n\
         # `{{file: path}}` (references are resolved by the CLI). See docs/CONFIG-YAML.md.\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// `anvilid tenant export`.
pub async fn export(cfg: &Config, args: &ExportArgs) -> anyhow::Result<()> {
    let service = service(cfg).await?;
    let doc = match service.export(&args.slug).await {
        Ok(doc) => doc,
        Err(anvil_core::error::CoreError::NotFound) => {
            bail!("tenant `{}` does not exist", args.slug)
        }
        Err(e) => return Err(e).context("export failed"),
    };
    let yaml = serde_saphyr::to_string(&doc).context("failed to write the YAML document")?;
    let text = format!("{}{yaml}", header(&args.slug));
    match &args.output {
        Some(path) => {
            std::fs::write(path, text)
                .with_context(|| format!("failed to write {}", path.display()))?;
            eprintln!("wrote tenant `{}` to {}", args.slug, path.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// A secret position of the document (the only places references are allowed).
fn secret_slots(doc: &mut Value) -> Vec<(String, &mut Value)> {
    let mut out = Vec::new();
    let Value::Object(map) = doc else {
        return out;
    };
    for (section, items) in map.iter_mut() {
        match (section.as_str(), items) {
            ("clients" | "connections" | "webhooks", Value::Array(items)) => {
                for (i, item) in items.iter_mut().enumerate() {
                    if let Some(slot) = item.get_mut("secret") {
                        out.push((format!("{section}[{i}].secret"), slot));
                    }
                }
            }
            ("smtp", smtp) => {
                if let Some(slot) = smtp.get_mut("password") {
                    out.push(("smtp.password".to_owned(), slot));
                }
            }
            _ => {}
        }
    }
    out
}

/// Strips one trailing newline (`\n` or `\r\n`) from file contents.
fn strip_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Replaces `{env: NAME}` and `{file: path}` secret references by `{value: …}`.
fn resolve_references(doc: &mut Value, base: &Path) -> anyhow::Result<()> {
    for (path, slot) in secret_slots(doc) {
        let Some(obj) = slot.as_object() else {
            continue;
        };
        let value = match (obj.get("env"), obj.get("file")) {
            (Some(_), Some(_)) => bail!("{path}: use either env or file, not both"),
            (Some(name), None) => {
                if obj.len() != 1 {
                    bail!("{path}: an env reference has no other keys");
                }
                let name = name
                    .as_str()
                    .with_context(|| format!("{path}: env must name a variable"))?;
                match std::env::var(name) {
                    Ok(v) if !v.is_empty() => v,
                    _ => bail!("{path}: environment variable {name} is not set or empty"),
                }
            }
            (None, Some(file)) => {
                if obj.len() != 1 {
                    bail!("{path}: a file reference has no other keys");
                }
                let file = file
                    .as_str()
                    .with_context(|| format!("{path}: file must be a path"))?;
                let full = base.join(file);
                let text = std::fs::read_to_string(&full)
                    .with_context(|| format!("{path}: failed to read {}", full.display()))?;
                let text = strip_newline(text);
                if text.is_empty() {
                    bail!("{path}: {} is empty", full.display());
                }
                text
            }
            (None, None) => continue,
        };
        *slot = serde_json::json!({ "value": value });
    }
    Ok(())
}

/// Reads a YAML document (or stdin for `-`) and resolves its secret references.
fn read_document(file: &Path) -> anyhow::Result<TenantConfigDocument> {
    let (text, base) = if file == Path::new("-") {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .context("failed to read the document from stdin")?;
        (s, PathBuf::from("."))
    } else {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let base = file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        (text, base)
    };
    let mut value: Value = serde_saphyr::from_str(&text).context("the file is not valid YAML")?;
    resolve_references(&mut value, &base)?;
    serde_json::from_value(value).context("the document does not match the TenantConfig schema")
}

fn report(e: ConfigError) -> anyhow::Error {
    match e {
        ConfigError::Invalid(issues) => {
            let mut msg = format!("the document is invalid ({} issue(s)):", issues.len());
            for i in issues {
                msg.push_str(&format!("\n  {}: {}", i.path, i.message));
            }
            anyhow::anyhow!(msg)
        }
        ConfigError::Core(e) => anyhow::Error::new(e).context("apply failed"),
    }
}

async fn run(
    service: &ConfigService,
    doc: &TenantConfigDocument,
    prune: bool,
    dry_run: bool,
) -> anyhow::Result<ApplyOutcome> {
    let caller = Scope::parse(ADMIN_WRITE).context("admin scope")?;
    service
        .apply(ApplyRequest {
            actor: &AuditActor::system(),
            caller: &caller,
            document: doc,
            prune,
            dry_run,
            ctx: &RequestContext::system(),
        })
        .await
        .map_err(report)
}

/// `anvilid tenant plan`.
pub async fn plan(cfg: &Config, args: &PlanArgs) -> anyhow::Result<()> {
    let doc = read_document(&args.file)?;
    let service = service(cfg).await?;
    let outcome = run(&service, &doc, false, true).await?;
    print!("{}", render(&outcome.plan));
    Ok(())
}

fn confirm() -> anyhow::Result<bool> {
    print!("Apply these changes? [y/N] ");
    std::io::stdout().flush().context("stdout")?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read the answer")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

/// `anvilid tenant apply`.
pub async fn apply(cfg: &Config, args: &ApplyArgs) -> anyhow::Result<()> {
    let doc = read_document(&args.file)?;
    let service = service(cfg).await?;
    let preview = run(&service, &doc, args.prune, true).await?;
    let p = &preview.plan;
    print!("{}", render(p));
    let pending = !p.creates.is_empty() || !p.updates.is_empty();
    if !pending && (p.deletes.is_empty() || !args.prune) {
        if !p.deletes.is_empty() {
            println!("Nothing to apply without --prune.");
        }
        return Ok(());
    }
    if !args.yes {
        if args.file == Path::new("-") || !std::io::stdin().is_terminal() {
            bail!("refusing to apply without --yes (stdin is not an interactive terminal)");
        }
        if !confirm()? {
            println!("Not applied.");
            return Ok(());
        }
    }
    let outcome = run(&service, &doc, args.prune, false).await?;
    let deletes = if outcome.pruned {
        outcome.plan.deletes.len()
    } else {
        0
    };
    if outcome.applied {
        println!(
            "Applied: {} created, {} updated, {deletes} deleted.",
            outcome.plan.creates.len(),
            outcome.plan.updates.len()
        );
    } else {
        println!("No changes.");
    }
    for g in &outcome.generated {
        let kind = serde_json::to_value(g.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        println!(
            "Generated {} of {kind} {} (shown once, store it now): {}",
            g.field,
            g.key,
            g.value.expose_secret()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_resolve_at_secret_positions_only() {
        let dir = tempfile_dir();
        std::fs::write(dir.join("smtp.txt"), "from-file\n").expect("write");
        // PATH is set for every test process (the environment is never modified here).
        let var = "PATH";
        let path = std::env::var(var).expect("PATH is set");
        let mut doc = serde_json::json!({
            "clients": [{"secret": {"env": var}}, {"secret": {"configured": true}}],
            "connections": [{"secret": {"value": "inline"}}],
            "smtp": {"password": {"file": "smtp.txt"}},
            "attributes": [{"name": "x", "schema": {"env": "HOME"}}],
        });
        resolve_references(&mut doc, &dir).expect("resolve");
        assert_eq!(
            doc["clients"][0]["secret"],
            serde_json::json!({"value": path})
        );
        assert_eq!(
            doc["clients"][1]["secret"],
            serde_json::json!({"configured": true})
        );
        assert_eq!(
            doc["connections"][0]["secret"],
            serde_json::json!({"value": "inline"})
        );
        assert_eq!(
            doc["smtp"]["password"],
            serde_json::json!({"value": "from-file"})
        );
        // Not a secret position: left alone.
        assert_eq!(
            doc["attributes"][0]["schema"],
            serde_json::json!({"env": "HOME"})
        );

        let mut missing =
            serde_json::json!({"webhooks": [{"secret": {"env": "ANVILID_TEST_UNSET_VAR"}}]});
        let err = resolve_references(&mut missing, &dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("webhooks[0].secret"), "{err}");
        let mut both = serde_json::json!({"webhooks": [{"secret": {"env": var, "file": "x"}}]});
        assert!(resolve_references(&mut both, &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn documented_example_is_a_valid_document() {
        let md = include_str!("../../../docs/CONFIG-YAML.md");
        let start = md.find("```yaml\n").expect("example") + "```yaml\n".len();
        let end = start + md[start..].find("```").expect("end of example");
        let mut value: Value = serde_saphyr::from_str(&md[start..end]).expect("example is YAML");
        for (_, slot) in secret_slots(&mut value) {
            if slot.get("env").is_some() || slot.get("file").is_some() {
                *slot = serde_json::json!({"value": "x"});
            }
        }
        let doc: TenantConfigDocument = serde_json::from_value(value).expect("example parses");
        assert_eq!(doc.tenant.slug, "acme");
        assert_eq!(doc.clients.len(), 1);
    }

    #[test]
    fn one_trailing_newline_is_stripped() {
        assert_eq!(strip_newline("a\n".into()), "a");
        assert_eq!(strip_newline("a\r\n".into()), "a");
        assert_eq!(strip_newline("a\n\n".into()), "a\n");
        assert_eq!(strip_newline("a".into()), "a");
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anvilid-tenant-config-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }
}
