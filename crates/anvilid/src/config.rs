//! Configuration (ARCHITECTURE.md §13).
//!
//! Precedence: CLI flags > `ANVILID_*` environment > `anvilid.toml` > defaults. Each layer is kept
//! as its own figment dictionary so `config show` can report where every value came from.
//!
//! Secrets (`kek`, `smtp_url`, credentials inside `database_url`) are accepted from the environment
//! and the config file only (never as CLI flags, which other users can read from the process
//! list), are held as [`SecretString`] once resolved, and are redacted by [`show`].

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anvil_core::model::PublicUrl;
use anvil_web::adapters::BreachCheckMode;
use anvil_web::adapters::hibp::HIBP_BASE_URL;
use anyhow::{Context, bail};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::value::{Dict, Value};
use figment::{Figment, Profile, Provider};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::storage::Backend;

/// Environment variable prefix.
pub const ENV_PREFIX: &str = "ANVILID_";
/// Config file looked up in the working directory when none is given.
pub const DEFAULT_CONFIG_FILE: &str = "anvilid.toml";

pub const DEFAULT_PUBLIC_URL: &str = "http://localhost:8080";
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
pub const DEFAULT_DATA_DIR: &str = "./anvilid-data";

/// Every configuration key, in `config show` order.
pub const KEYS: &[&str] = &[
    "public_url",
    "listen",
    "data_dir",
    "database_url",
    "kek",
    "kek_file",
    "smtp_url",
    "smtp_from",
    "theme_dir",
    "tls_cert",
    "tls_key",
    "breach_check",
    "breach_check_url",
    "no_migrate",
    "insecure_http",
    "log_format",
];

/// Keys whose value is a secret as a whole.
const SECRET_KEYS: &[&str] = &["kek", "smtp_url"];

/// Configuration flags shared by every subcommand. Every field is optional so that figment, not
/// clap, applies defaults and precedence.
#[derive(Debug, Default, Clone, clap::Args, Serialize)]
pub struct CliOverrides {
    /// Path to the config file (default: ./anvilid.toml if it exists). Env: ANVILID_CONFIG.
    #[arg(long, value_name = "PATH")]
    #[serde(skip)]
    pub config: Option<PathBuf>,

    /// Public base URL; every issuer and endpoint URL derives from it [default: http://localhost:8080].
    #[arg(long, value_name = "URL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,

    /// Socket address to listen on [default: 127.0.0.1:8080].
    #[arg(long, value_name = "ADDR")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    /// Data directory for the SQLite database, the KEK file and the lock [default: ./anvilid-data].
    #[arg(long, value_name = "DIR")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<PathBuf>,

    /// Database URL: `sqlite://<path>`, `sqlite::memory:` or `postgres://…`
    /// [default: sqlite://{data_dir}/anvilid.db].
    #[arg(long, value_name = "URL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_url: Option<String>,

    /// File holding the base64 key-encryption key [default: {data_dir}/kek].
    #[arg(long, value_name = "PATH")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kek_file: Option<PathBuf>,

    /// Sender address of outgoing email [default: AnvilID <no-reply@{public host}>].
    #[arg(long, value_name = "MAILBOX")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_from: Option<String>,

    /// Operator theme directory (templates/, emails/, static/).
    #[arg(long, value_name = "DIR")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme_dir: Option<PathBuf>,

    /// PEM certificate chain for the built-in TLS listener (requires --tls-key).
    #[arg(long, value_name = "PATH")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key for the built-in TLS listener (requires --tls-cert).
    #[arg(long, value_name = "PATH")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,

    /// Breached-password check: `hibp` or `off` [default: hibp].
    #[arg(long, value_name = "MODE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breach_check: Option<String>,

    /// Base URL of the HIBP range API [default: https://api.pwnedpasswords.com].
    #[arg(long, value_name = "URL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breach_check_url: Option<String>,

    /// Do not run database migrations on start.
    #[arg(long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub no_migrate: bool,

    /// Allow a plain-http public URL on a non-loopback host (development and test setups only).
    #[arg(long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub insecure_http: bool,

    /// Log format: `json` or `pretty` [default: pretty in dev mode, json otherwise].
    #[arg(long, value_name = "FORMAT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
}

/// The merged, not yet validated configuration. Missing keys take the defaults below; derived
/// defaults (`database_url`, `kek_file`, `smtp_from`, `log_format`) stay `None` here.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct RawConfig {
    pub public_url: String,
    pub listen: String,
    pub data_dir: PathBuf,
    pub database_url: Option<String>,
    pub kek: Option<String>,
    pub kek_file: Option<PathBuf>,
    pub smtp_url: Option<String>,
    pub smtp_from: Option<String>,
    pub theme_dir: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub breach_check: String,
    pub breach_check_url: String,
    pub no_migrate: bool,
    pub insecure_http: bool,
    pub log_format: Option<String>,
}

impl fmt::Debug for RawConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawConfig")
            .field("public_url", &self.public_url)
            .finish_non_exhaustive()
    }
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            public_url: DEFAULT_PUBLIC_URL.to_owned(),
            listen: DEFAULT_LISTEN.to_owned(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            database_url: None,
            kek: None,
            kek_file: None,
            smtp_url: None,
            smtp_from: None,
            theme_dir: None,
            tls_cert: None,
            tls_key: None,
            breach_check: "hibp".to_owned(),
            breach_check_url: HIBP_BASE_URL.to_owned(),
            no_migrate: false,
            insecure_http: false,
            log_format: None,
        }
    }
}

/// `sqlite://{data_dir}/anvilid.db` (the SQLite backend creates the file if missing).
pub fn default_database_url(data_dir: &Path) -> String {
    format!("sqlite://{}", data_dir.join("anvilid.db").display())
}

/// `{data_dir}/kek`.
pub fn default_kek_file(data_dir: &Path) -> PathBuf {
    data_dir.join("kek")
}

/// `AnvilID <no-reply@{host}>`, the host of the public URL without its port.
pub fn default_smtp_from(public_url: &PublicUrl) -> String {
    let host_port = public_url.host_port();
    let host = if host_port.starts_with('[') {
        host_port
            .find(']')
            .map_or(host_port, |end| &host_port[..=end])
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    format!("AnvilID <no-reply@{host}>")
}

/// Where a configuration value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Default,
    File(PathBuf),
    Env(String),
    Cli(String),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::File(p) => write!(f, "file {}", p.display()),
            Self::Env(v) => write!(f, "env {v}"),
            Self::Cli(flag) => write!(f, "cli {flag}"),
        }
    }
}

/// The configuration layers, each as a flat figment dictionary.
pub struct Layers {
    cli: Dict,
    env: Dict,
    file: Option<(PathBuf, Dict)>,
}

fn default_profile(data: figment::value::Map<Profile, Dict>) -> Dict {
    data.into_iter()
        .filter(|(p, _)| *p == Profile::Default)
        .flat_map(|(_, d)| d)
        .collect()
}

impl Layers {
    /// Reads the process environment (`ANVILID_*`, known keys only) and the config file: the
    /// `--config` path, else `ANVILID_CONFIG`, else `./anvilid.toml` if it exists. An explicitly
    /// named file must exist.
    pub fn from_process(cli: &CliOverrides) -> anyhow::Result<Self> {
        let env = Env::prefixed(ENV_PREFIX).only(KEYS);
        let env = default_profile(env.data().context("failed to read the environment")?);
        let explicit = cli.config.clone().or_else(|| {
            std::env::var_os(format!("{ENV_PREFIX}CONFIG"))
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        });
        let path = match explicit {
            Some(p) => {
                if !p.is_file() {
                    bail!("config file {} does not exist", p.display());
                }
                Some(p)
            }
            None => {
                let p = PathBuf::from(DEFAULT_CONFIG_FILE);
                p.is_file().then_some(p)
            }
        };
        let file = match path {
            Some(p) => Some((p.clone(), read_toml(&p)?)),
            None => None,
        };
        Self::new(cli, env, file)
    }

    /// Builds the layers from explicit dictionaries (tests pass their own environment).
    pub fn new(
        cli: &CliOverrides,
        env: Dict,
        file: Option<(PathBuf, Dict)>,
    ) -> anyhow::Result<Self> {
        let cli = match Value::serialize(cli).context("failed to read the command line")? {
            Value::Dict(_, d) => d,
            _ => Dict::new(),
        };
        Ok(Self { cli, env, file })
    }

    fn figment(&self) -> Figment {
        let mut fig = Figment::new();
        if let Some((_, file)) = &self.file {
            fig = fig.merge(Serialized::defaults(file));
        }
        fig.merge(Serialized::defaults(&self.env))
            .merge(Serialized::defaults(&self.cli))
    }

    /// The source of `key`: the highest-precedence layer that sets it.
    pub fn source(&self, key: &str) -> Source {
        if self.cli.contains_key(key) {
            Source::Cli(format!("--{}", key.replace('_', "-")))
        } else if self.env.contains_key(key) {
            Source::Env(format!("{ENV_PREFIX}{}", key.to_ascii_uppercase()))
        } else if let Some((path, _)) = self.file.as_ref().filter(|(_, d)| d.contains_key(key)) {
            Source::File(path.clone())
        } else {
            Source::Default
        }
    }

    /// The config file in use, if any.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_ref().map(|(p, _)| p.as_path())
    }

    /// Merges the layers. Errors name the key but never echo a secret value.
    pub fn raw(&self) -> anyhow::Result<RawConfig> {
        self.figment().extract_lossy::<RawConfig>().map_err(|e| {
            let key = e.path.join(".");
            if SECRET_KEYS.contains(&key.as_str()) {
                anyhow::anyhow!("invalid configuration: {key} has an invalid type")
            } else {
                anyhow::anyhow!("invalid configuration: {e}")
            }
        })
    }
}

fn read_toml(path: &Path) -> anyhow::Result<Dict> {
    let data = Toml::file_exact(path).data().map_err(|e| {
        // Only the first line: TOML errors quote the offending source line, which may hold a secret.
        let first = e.to_string().lines().next().unwrap_or_default().to_owned();
        anyhow::anyhow!("config file {} is invalid: {first}", path.display())
    })?;
    Ok(default_profile(data))
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

/// TLS certificate and key files of the built-in listener.
#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// The validated configuration.
#[derive(Debug)]
pub struct Config {
    pub public_url: PublicUrl,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub database_url: SecretString,
    pub kek: Option<SecretString>,
    pub kek_file: PathBuf,
    pub smtp_url: Option<SecretString>,
    pub smtp_from: String,
    pub theme_dir: Option<PathBuf>,
    pub tls: Option<TlsFiles>,
    pub breach_check: BreachCheckMode,
    pub migrate: bool,
    pub insecure_http: bool,
    pub log_format: LogFormat,
    /// Non-fatal findings, logged as warnings on start.
    pub warnings: Vec<String>,
}

fn field_error(key: &str, message: impl fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("invalid configuration: {key}: {message}")
}

impl Config {
    /// Validates the merged configuration and derives the dependent defaults.
    pub fn resolve(raw: RawConfig) -> anyhow::Result<Self> {
        let public_url = PublicUrl::parse(raw.public_url.trim()).map_err(|e| match e {
            anvil_core::error::CoreError::Validation { message, .. } => {
                field_error("public_url", message)
            }
            other => field_error("public_url", other),
        })?;
        let mut warnings = Vec::new();
        if public_url.scheme() == "http" && !public_url.is_dev_mode() {
            if !raw.insecure_http {
                return Err(field_error(
                    "public_url",
                    "plain http is only allowed on a loopback host; use https, or pass \
                     --insecure-http for a development or test setup",
                ));
            }
            warnings.push(
                "insecure_http is set: serving a plain-http public URL on a non-loopback host; \
                 cookies are not Secure. Never use this in production"
                    .to_owned(),
            );
        } else if raw.insecure_http {
            warnings.push("insecure_http is set (it has no effect on this public URL)".to_owned());
        }

        let listen: SocketAddr = raw.listen.trim().parse().map_err(|_| {
            field_error("listen", "must be a socket address such as 127.0.0.1:8080")
        })?;

        let database_url = raw
            .database_url
            .clone()
            .unwrap_or_else(|| default_database_url(&raw.data_dir));
        Backend::from_url(&database_url).map_err(|e| field_error("database_url", e))?;

        let tls = match (raw.tls_cert, raw.tls_key) {
            (Some(cert), Some(key)) => Some(TlsFiles { cert, key }),
            (None, None) => None,
            (Some(_), None) => return Err(field_error("tls_key", "tls_cert requires tls_key")),
            (None, Some(_)) => return Err(field_error("tls_cert", "tls_key requires tls_cert")),
        };

        let breach_check = match raw.breach_check.trim().to_ascii_lowercase().as_str() {
            "hibp" => {
                let url = url::Url::parse(raw.breach_check_url.trim())
                    .map_err(|_| field_error("breach_check_url", "must be an absolute URL"))?;
                if !matches!(url.scheme(), "http" | "https") {
                    return Err(field_error("breach_check_url", "must use http or https"));
                }
                BreachCheckMode::Hibp {
                    base_url: raw.breach_check_url.trim().trim_end_matches('/').to_owned(),
                }
            }
            "off" => {
                warnings.push(
                    "breach_check is off: passwords are not checked against known breaches"
                        .to_owned(),
                );
                BreachCheckMode::Off
            }
            _ => return Err(field_error("breach_check", "must be `hibp` or `off`")),
        };

        let log_format = match raw.log_format.as_deref().map(str::trim) {
            None | Some("") => {
                if public_url.is_dev_mode() {
                    LogFormat::Pretty
                } else {
                    LogFormat::Json
                }
            }
            Some(f) if f.eq_ignore_ascii_case("pretty") => LogFormat::Pretty,
            Some(f) if f.eq_ignore_ascii_case("json") => LogFormat::Json,
            Some(_) => return Err(field_error("log_format", "must be `json` or `pretty`")),
        };

        let kek = raw
            .kek
            .filter(|k| !k.trim().is_empty())
            .map(SecretString::from);
        let smtp_url = raw
            .smtp_url
            .filter(|u| !u.trim().is_empty())
            .map(SecretString::from);
        if let Some(url) = &smtp_url {
            let scheme = url
                .expose_secret()
                .split_once("://")
                .map(|(s, _)| s.to_ascii_lowercase());
            if !matches!(scheme.as_deref(), Some("smtp" | "smtps")) {
                return Err(field_error("smtp_url", "must use smtp:// or smtps://"));
            }
        }
        let smtp_from = raw
            .smtp_from
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| default_smtp_from(&public_url));

        Ok(Self {
            kek_file: raw
                .kek_file
                .unwrap_or_else(|| default_kek_file(&raw.data_dir)),
            public_url,
            listen,
            data_dir: raw.data_dir,
            database_url: SecretString::from(database_url),
            kek,
            smtp_url,
            smtp_from,
            theme_dir: raw.theme_dir,
            tls,
            breach_check,
            migrate: !raw.no_migrate,
            insecure_http: raw.insecure_http,
            log_format,
            warnings,
        })
    }
}

/// Redacts the password (userinfo and `password`-like query parameters) of a URL. Unparsable
/// URLs other than `sqlite:` ones are redacted as a whole.
pub fn redact_url(raw: &str) -> String {
    if raw.starts_with("sqlite:") {
        return raw.to_owned();
    }
    let Ok(mut url) = url::Url::parse(raw) else {
        return "***".to_owned();
    };
    if url.password().is_some() && url.set_password(Some("***")).is_err() {
        return "***".to_owned();
    }
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| {
                let secret = k.to_ascii_lowercase().contains("password");
                (
                    k.into_owned(),
                    if secret {
                        "***".to_owned()
                    } else {
                        v.into_owned()
                    },
                )
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.to_string().replace("%2A%2A%2A", "***")
}

fn opt_path(p: Option<&PathBuf>) -> String {
    p.map_or_else(|| "<unset>".to_owned(), |p| p.display().to_string())
}

/// `config show`: one `key = value (source)` line per key, secrets redacted. Works on an invalid
/// configuration too (derived defaults that cannot be computed are shown as such).
pub fn show(layers: &Layers, raw: &RawConfig) -> String {
    let public_url = PublicUrl::parse(raw.public_url.trim()).ok();
    let mut out = String::new();
    out.push_str(&format!(
        "# config file: {}\n",
        layers
            .file()
            .map_or_else(|| "none".to_owned(), |p| p.display().to_string())
    ));
    for key in KEYS {
        let value = match *key {
            "public_url" => raw.public_url.clone(),
            "listen" => raw.listen.clone(),
            "data_dir" => raw.data_dir.display().to_string(),
            "database_url" => redact_url(
                &raw.database_url
                    .clone()
                    .unwrap_or_else(|| default_database_url(&raw.data_dir)),
            ),
            "kek" => if raw.kek.is_some() { "***" } else { "<unset>" }.to_owned(),
            "kek_file" => raw
                .kek_file
                .clone()
                .unwrap_or_else(|| default_kek_file(&raw.data_dir))
                .display()
                .to_string(),
            "smtp_url" => if raw.smtp_url.is_some() {
                "***"
            } else {
                "<unset>"
            }
            .to_owned(),
            "smtp_from" => raw.smtp_from.clone().unwrap_or_else(|| {
                public_url
                    .as_ref()
                    .map_or_else(|| "<derived from public_url>".to_owned(), default_smtp_from)
            }),
            "theme_dir" => opt_path(raw.theme_dir.as_ref()),
            "tls_cert" => opt_path(raw.tls_cert.as_ref()),
            "tls_key" => opt_path(raw.tls_key.as_ref()),
            "breach_check" => raw.breach_check.clone(),
            "breach_check_url" => raw.breach_check_url.clone(),
            "no_migrate" => raw.no_migrate.to_string(),
            "insecure_http" => raw.insecure_http.to_string(),
            "log_format" => raw.log_format.clone().unwrap_or_else(|| {
                if public_url.as_ref().is_some_and(PublicUrl::is_dev_mode) {
                    "pretty".to_owned()
                } else {
                    "json".to_owned()
                }
            }),
            _ => continue,
        };
        out.push_str(&format!("{key} = {value} ({})\n", layers.source(key)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(pairs: &[(&str, Value)]) -> Dict {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn s(v: &str) -> Value {
        Value::from(v.to_owned())
    }

    fn layers(cli: &CliOverrides, env: &[(&str, Value)], file: Option<&[(&str, Value)]>) -> Layers {
        Layers::new(
            cli,
            dict(env),
            file.map(|f| (PathBuf::from("anvilid.toml"), dict(f))),
        )
        .expect("layers")
    }

    fn resolve(l: &Layers) -> anyhow::Result<Config> {
        Config::resolve(l.raw()?)
    }

    #[test]
    fn defaults_resolve_as_documented() {
        let cfg = resolve(&layers(&CliOverrides::default(), &[], None)).expect("defaults");
        assert_eq!(cfg.public_url.as_str(), "http://localhost:8080");
        assert_eq!(cfg.listen, "127.0.0.1:8080".parse().expect("addr"));
        assert_eq!(cfg.data_dir, PathBuf::from("./anvilid-data"));
        assert_eq!(
            cfg.database_url.expose_secret(),
            "sqlite://./anvilid-data/anvilid.db"
        );
        assert_eq!(cfg.kek_file, PathBuf::from("./anvilid-data/kek"));
        assert!(cfg.kek.is_none());
        assert!(cfg.smtp_url.is_none());
        assert_eq!(cfg.smtp_from, "AnvilID <no-reply@localhost>");
        assert_eq!(
            cfg.breach_check,
            BreachCheckMode::Hibp {
                base_url: "https://api.pwnedpasswords.com".to_owned()
            }
        );
        assert!(cfg.migrate);
        assert!(!cfg.insecure_http);
        assert!(cfg.public_url.is_dev_mode());
        assert_eq!(cfg.log_format, LogFormat::Pretty);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn database_url_and_kek_file_derive_from_data_dir() {
        let cli = CliOverrides {
            data_dir: Some(PathBuf::from("/var/lib/anvilid")),
            ..Default::default()
        };
        let cfg = resolve(&layers(&cli, &[], None)).expect("cfg");
        assert_eq!(
            cfg.database_url.expose_secret(),
            "sqlite:///var/lib/anvilid/anvilid.db"
        );
        assert_eq!(cfg.kek_file, PathBuf::from("/var/lib/anvilid/kek"));
    }

    #[test]
    fn env_overrides_file_and_cli_overrides_env() {
        let file = [
            ("public_url", s("https://file.test")),
            ("listen", s("0.0.0.0:1111")),
            ("log_format", s("pretty")),
        ];
        let env = [
            ("public_url", s("https://env.test")),
            ("listen", s("0.0.0.0:2222")),
        ];
        let cli = CliOverrides {
            listen: Some("0.0.0.0:3333".to_owned()),
            ..Default::default()
        };
        let l = layers(&cli, &env, Some(&file));
        let cfg = resolve(&l).expect("cfg");
        assert_eq!(cfg.public_url.as_str(), "https://env.test");
        assert_eq!(cfg.listen, "0.0.0.0:3333".parse().expect("addr"));
        assert_eq!(cfg.log_format, LogFormat::Pretty);
        assert_eq!(l.source("listen"), Source::Cli("--listen".to_owned()));
        assert_eq!(
            l.source("public_url"),
            Source::Env("ANVILID_PUBLIC_URL".to_owned())
        );
        assert_eq!(
            l.source("log_format"),
            Source::File(PathBuf::from("anvilid.toml"))
        );
        assert_eq!(l.source("data_dir"), Source::Default);
    }

    #[test]
    fn production_defaults_to_json_logs() {
        let l = layers(
            &CliOverrides::default(),
            &[("public_url", s("https://id.example.test"))],
            None,
        );
        let cfg = resolve(&l).expect("cfg");
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert!(!cfg.public_url.is_dev_mode());
        assert_eq!(cfg.smtp_from, "AnvilID <no-reply@id.example.test>");
    }

    #[test]
    fn show_lists_sources_and_redacts_secrets() {
        let env = [
            ("public_url", s("https://id.example.test")),
            ("kek", s("c2VjcmV0LWtlay12YWx1ZS1mb3ItdGVzdHMtMDEyMzQ1Ng==")),
            ("smtp_url", s("smtps://mailer:smtp-pass@mail.example.test")),
        ];
        let l = layers(&CliOverrides::default(), &env, None);
        let out = show(&l, &l.raw().expect("raw"));
        assert!(
            out.contains("database_url = sqlite://./anvilid-data/anvilid.db (default)"),
            "{out}"
        );
        assert!(
            out.contains("public_url = https://id.example.test (env ANVILID_PUBLIC_URL)"),
            "{out}"
        );
        assert!(out.contains("kek = *** (env ANVILID_KEK)"), "{out}");
        assert!(
            out.contains("smtp_url = *** (env ANVILID_SMTP_URL)"),
            "{out}"
        );
        assert!(!out.contains("c2VjcmV0"), "{out}");
        assert!(!out.contains("smtp-pass"), "{out}");
    }

    #[test]
    fn show_redacts_postgres_password() {
        let cli = CliOverrides {
            database_url: Some("postgres://anvil:pg-secret@db.example.test/anvil".to_owned()),
            ..Default::default()
        };
        let l = layers(&cli, &[], None);
        let out = show(&l, &l.raw().expect("raw"));
        assert!(
            out.contains(
                "database_url = postgres://anvil:***@db.example.test/anvil (cli --database-url)"
            ),
            "{out}"
        );
        assert!(!out.contains("pg-secret"), "{out}");
        assert_eq!(
            redact_url("postgres://u@h/db?sslmode=require&password=qp-secret"),
            "postgres://u@h/db?sslmode=require&password=***"
        );
        assert_eq!(redact_url("not a url with secret"), "***");
    }

    #[test]
    fn rejects_non_http_public_url() {
        let l = layers(
            &CliOverrides::default(),
            &[("public_url", s("ftp://x"))],
            None,
        );
        let err = resolve(&l).expect_err("ftp").to_string();
        assert!(err.contains("public_url"), "{err}");
    }

    #[test]
    fn plain_http_on_public_host_needs_insecure_http() {
        let env = [("public_url", s("http://example.test"))];
        let err = resolve(&layers(&CliOverrides::default(), &env, None))
            .expect_err("http on a public host")
            .to_string();
        assert!(err.contains("public_url"), "{err}");
        assert!(err.contains("--insecure-http"), "{err}");

        let cli = CliOverrides {
            insecure_http: true,
            ..Default::default()
        };
        let cfg = resolve(&layers(&cli, &env, None)).expect("allowed with insecure_http");
        assert!(cfg.insecure_http);
        assert!(
            cfg.warnings.iter().any(|w| w.contains("insecure_http")),
            "{:?}",
            cfg.warnings
        );
    }

    #[test]
    fn insecure_http_from_env_bool() {
        let env = [
            ("public_url", s("http://example.test")),
            ("insecure_http", s("true")),
        ];
        let cfg = resolve(&layers(&CliOverrides::default(), &env, None)).expect("cfg");
        assert!(cfg.insecure_http);
    }

    #[test]
    fn tls_cert_and_key_go_together() {
        let cli = CliOverrides {
            tls_cert: Some(PathBuf::from("cert.pem")),
            ..Default::default()
        };
        let err = resolve(&layers(&cli, &[], None))
            .expect_err("cert only")
            .to_string();
        assert!(err.contains("tls_key"), "{err}");
        let cli = CliOverrides {
            tls_key: Some(PathBuf::from("key.pem")),
            ..Default::default()
        };
        assert!(resolve(&layers(&cli, &[], None)).is_err());
        let cli = CliOverrides {
            tls_cert: Some(PathBuf::from("cert.pem")),
            tls_key: Some(PathBuf::from("key.pem")),
            ..Default::default()
        };
        assert!(
            resolve(&layers(&cli, &[], None))
                .expect("both")
                .tls
                .is_some()
        );
    }

    #[test]
    fn rejects_bad_enums_listen_and_scheme() {
        for (key, value) in [
            ("breach_check", "maybe"),
            ("log_format", "xml"),
            ("listen", "localhost"),
            ("smtp_url", "http://mail.example.test"),
            ("database_url", "mysql://u:secretpw@h/db"),
        ] {
            let err = resolve(&layers(&CliOverrides::default(), &[(key, s(value))], None))
                .expect_err(key)
                .to_string();
            assert!(err.contains(key), "{key}: {err}");
            assert!(!err.contains("secretpw"), "{err}");
        }
    }

    #[test]
    fn breach_check_off() {
        let env = [("breach_check", s("off"))];
        let cfg = resolve(&layers(&CliOverrides::default(), &env, None)).expect("cfg");
        assert_eq!(cfg.breach_check, BreachCheckMode::Off);
    }

    #[test]
    fn smtp_from_for_ipv6_and_port() {
        let url = PublicUrl::parse("http://[::1]:8080").expect("url");
        assert_eq!(default_smtp_from(&url), "AnvilID <no-reply@[::1]>");
        let url = PublicUrl::parse("https://id.example.test:8443/base").expect("url");
        assert_eq!(
            default_smtp_from(&url),
            "AnvilID <no-reply@id.example.test>"
        );
    }
}
