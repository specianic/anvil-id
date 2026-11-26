//! Configuration (ARCHITECTURE.md §13).
//!
//! Precedence: CLI flags > `ANVILID_*` environment > `anvilid.toml` > defaults. Each layer is kept
//! as its own figment dictionary so `config show` can report where every value came from.
//!
//! Secrets (`kek`, `smtp_url`, credentials inside `database_url`) are accepted from the environment
//! and the config file only (never as CLI flags, which other users can read from the process
//! list), are held as [`SecretString`] once resolved, and are redacted by [`show`].
//!
//! Phase 3 keys (0.2): `trusted_proxies` / `trusted_proxy_header` (client IP behind reverse
//! proxies, OPS-06), `rate_limit_*` (SEC-05), `key_rotation_days` (SEC-02) and
//! `audit_retention_days` (ADM-04).
//!
//! Phase 4 keys (0.3): `outbound_allow_cidrs` (destinations the SSRF-guarded outbound client may
//! reach even inside a blocked range; an explicit list, even an empty one, replaces the
//! development-mode loopback default) and `outbound_ca_file` (extra PEM root certificates for
//! outbound TLS, merged with the built-in roots).
//!
//! Phase 5 keys (0.4): `redis_url` (secret; shared rate-limit backend, see
//! `limiter::build_limiter`), `rate_limit_redis_failure` (`closed` | `local`), `metrics_listen` (separate
//! Prometheus listener), `metrics_on_main_port`, `otel_endpoint` / `otel_service_name` (OTLP/HTTP
//! traces; incoming `traceparent` headers are honoured only from `trusted_proxies`),
//! `shutdown_drain` (readiness turns 503 on SIGTERM, then the node waits this long before it stops
//! accepting) and `database_max_connections` (Postgres pool size; SQLite ignores it).
//!
//! Phase 6 keys (1.0): `saml_experimental` (SAML 2.0 connections, off by default and experimental
//! through 1.0; a warning is logged when on) and `domain_verification_resolvers` (DNS resolvers
//! for organization domain verification, `ip` or `ip:port` entries, port 53 by default; empty =
//! the system resolver configuration).

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anvil_cache::limiter::{LimiterConfig, RateQuota};
use anvil_core::model::PublicUrl;
use anvil_core::service::key_rotation::{DEFAULT_PREPUBLISH, JWKS_MAX_AGE, RotationPolicy};
use anvil_web::adapters::BreachCheckMode;
use anvil_web::adapters::hibp::HIBP_BASE_URL;
use anvil_web::client_ip::{ForwardedHeader, TrustedProxies};
use anyhow::{Context, bail};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::value::{Dict, Value};
use figment::{Figment, Profile, Provider};
use ipnet::IpNet;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::storage::{Backend, Migrations};

/// Environment variable prefix.
pub const ENV_PREFIX: &str = "ANVILID_";
/// Config file looked up in the working directory when none is given.
pub const DEFAULT_CONFIG_FILE: &str = "anvilid.toml";

pub const DEFAULT_PUBLIC_URL: &str = "http://localhost:8080";
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
pub const DEFAULT_DATA_DIR: &str = "./anvilid-data";

/// Signing-key rotation period in days (SEC-02).
pub const DEFAULT_KEY_ROTATION_DAYS: u32 = 90;
/// Longest accepted rotation period (10 years).
pub const MAX_KEY_ROTATION_DAYS: u32 = 3650;
/// Audit events older than this are purged daily; `0` keeps them forever.
pub const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 365;
/// Longest accepted audit retention (100 years).
pub const MAX_AUDIT_RETENTION_DAYS: u32 = 36_500;
/// Default Postgres pool size.
pub const DEFAULT_DATABASE_MAX_CONNECTIONS: u32 = 10;
/// Largest accepted Postgres pool size.
pub const MAX_DATABASE_MAX_CONNECTIONS: u32 = 1000;
/// Default `service.name` of exported traces.
pub const DEFAULT_OTEL_SERVICE_NAME: &str = "anvilid";
/// Longest accepted shutdown drain delay.
pub const MAX_SHUTDOWN_DRAIN: Duration = Duration::from_secs(3600);

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
    "allow_destructive_migrations",
    "insecure_http",
    "log_format",
    "trusted_proxies",
    "trusted_proxy_header",
    "rate_limit_enabled",
    "rate_limit_auth_per_minute",
    "rate_limit_token_per_second",
    "rate_limit_token_client_per_second",
    "rate_limit_admin_per_second",
    "rate_limit_default_per_second",
    "key_rotation_days",
    "audit_retention_days",
    "outbound_allow_cidrs",
    "outbound_ca_file",
    "redis_url",
    "rate_limit_redis_failure",
    "metrics_listen",
    "metrics_on_main_port",
    "otel_endpoint",
    "otel_service_name",
    "shutdown_drain",
    "database_max_connections",
    "saml_experimental",
    "domain_verification_resolvers",
];

/// Keys whose value is a secret as a whole.
const SECRET_KEYS: &[&str] = &["kek", "smtp_url", "redis_url"];

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

    /// Apply pending destructive migrations (`NNNN_destructive_*`) instead of refusing to start.
    /// Take a backup first.
    #[arg(long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_destructive_migrations: bool,

    /// Allow a plain-http public URL on a non-loopback host (development and test setups only).
    #[arg(long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub insecure_http: bool,

    /// Log format: `json` or `pretty` [default: pretty in dev mode, json otherwise].
    #[arg(long, value_name = "FORMAT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,

    /// Comma-separated CIDRs (or single IPs) of reverse proxies whose forwarding header is
    /// trusted for the client IP; empty trusts none [default: loopback in dev mode, none otherwise].
    #[arg(long, value_name = "CIDRS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_proxies: Option<String>,

    /// Forwarding header set by the trusted proxies: `x-forwarded-for` or `forwarded`
    /// [default: x-forwarded-for].
    #[arg(long, value_name = "HEADER")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_proxy_header: Option<String>,

    /// Rate limiting on or off [default: true].
    #[arg(long, value_name = "BOOL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_enabled: Option<bool>,

    /// Requests per minute and client IP on interactive login endpoints [default: 10].
    #[arg(long, value_name = "N")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_auth_per_minute: Option<u32>,

    /// Requests per second and client IP on the token endpoint [default: 50].
    #[arg(long, value_name = "N")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_token_per_second: Option<u32>,

    /// Requests per second and client on the token endpoint [default: 100].
    #[arg(long, value_name = "N")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_token_client_per_second: Option<u32>,

    /// Requests per second and client IP on the admin API [default: 20].
    #[arg(long, value_name = "N")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_admin_per_second: Option<u32>,

    /// Requests per second and client IP on every other endpoint [default: 50].
    #[arg(long, value_name = "N")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_default_per_second: Option<u32>,

    /// Signing-key rotation period in days, at least 1 [default: 90].
    #[arg(long, value_name = "DAYS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_rotation_days: Option<u32>,

    /// Days audit events are kept; 0 keeps them forever [default: 365].
    #[arg(long, value_name = "DAYS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_retention_days: Option<u32>,

    /// Comma-separated CIDRs (or single IPs) the outbound HTTP client may reach even inside
    /// private/loopback/reserved ranges; empty allows none [default: loopback in dev mode,
    /// none otherwise].
    #[arg(long, value_name = "CIDRS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_allow_cidrs: Option<String>,

    /// PEM bundle of extra root certificates trusted for outbound TLS (merged with the
    /// built-in roots).
    #[arg(long, value_name = "PATH")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_ca_file: Option<PathBuf>,

    /// When the shared rate-limit backend (redis_url, env or file only) is unreachable:
    /// `closed` rejects login requests, `local` falls back to the per-node limiter
    /// [default: closed].
    #[arg(long, value_name = "MODE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_redis_failure: Option<String>,

    /// Socket address of a separate listener serving only Prometheus `/metrics`
    /// [default: off].
    #[arg(long, value_name = "ADDR")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_listen: Option<String>,

    /// Also serve `/metrics` on the main listener (never rate limited or tenant-resolved).
    #[arg(long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub metrics_on_main_port: bool,

    /// OTLP/HTTP (protobuf) traces endpoint base URL, e.g. http://collector:4318
    /// [default: off].
    #[arg(long, value_name = "URL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otel_endpoint: Option<String>,

    /// `service.name` of exported traces [default: anvilid].
    #[arg(long, value_name = "NAME")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otel_service_name: Option<String>,

    /// On SIGTERM, how long readiness reports 503 before the server stops accepting: `10s`,
    /// `500ms`, `1m` or plain seconds [default: 0s].
    #[arg(long, value_name = "DURATION")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shutdown_drain: Option<String>,

    /// Postgres connection pool size, 1 to 1000 (SQLite ignores it) [default: 10].
    #[arg(long, value_name = "N")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_max_connections: Option<u32>,

    /// Enable SAML 2.0 enterprise connections (experimental through 1.0) [default: off].
    #[arg(long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub saml_experimental: bool,

    /// Comma-separated DNS resolvers (`ip` or `ip:port`, port 53 by default) for organization
    /// domain verification [default: the system resolver configuration].
    #[arg(long, value_name = "ADDRS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_verification_resolvers: Option<String>,
}

/// A duration given as a string (`10s`, `500ms`, `1m`, `2h`, `10`) or as a number of seconds
/// (TOML integer, or an environment value figment parsed as a number).
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum DurationValue {
    Secs(u64),
    Text(String),
}

impl DurationValue {
    /// The duration, or `None` when the text is not a duration.
    pub fn parse(&self) -> Option<Duration> {
        match self {
            Self::Secs(n) => Some(Duration::from_secs(*n)),
            Self::Text(t) => parse_duration(t),
        }
    }

    fn display(&self) -> String {
        match self {
            Self::Secs(n) => format!("{n}s"),
            Self::Text(t) => t.trim().to_owned(),
        }
    }
}

/// Parses `<n>ms`, `<n>s`, `<n>m`, `<n>h` or a plain number of seconds.
pub fn parse_duration(text: &str) -> Option<Duration> {
    let t = text.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (digits, unit) = t.split_at(split);
    if digits.is_empty() {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    match unit.trim() {
        "" | "s" => Some(Duration::from_secs(n)),
        "ms" => Some(Duration::from_millis(n)),
        "m" => n.checked_mul(60).map(Duration::from_secs),
        "h" => n.checked_mul(3600).map(Duration::from_secs),
        _ => None,
    }
}

/// What the rate limiter does when the shared backend (`redis_url`) is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisFailure {
    /// Login (auth-class) requests are rejected; other classes fall back to the node limiter.
    Closed,
    /// Every class falls back to the per-node limiter.
    Local,
}

/// A URL that may carry credentials: `Debug` never shows the userinfo.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialUrl(pub url::Url);

impl fmt::Debug for CredentialUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact_userinfo(self.0.as_str()))
    }
}

/// A list given either as one comma-separated string (environment, CLI) or as a TOML array.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ListValue {
    One(String),
    Many(Vec<String>),
}

impl ListValue {
    /// The non-empty, trimmed entries.
    pub fn entries(&self) -> Vec<String> {
        let parts: Vec<&str> = match self {
            Self::One(s) => s.split(',').collect(),
            Self::Many(v) => v.iter().flat_map(|s| s.split(',')).collect(),
        };
        parts
            .into_iter()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect()
    }
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
    pub allow_destructive_migrations: bool,
    pub insecure_http: bool,
    pub log_format: Option<String>,
    /// `None` = mode default (loopback in dev mode, none otherwise).
    pub trusted_proxies: Option<ListValue>,
    pub trusted_proxy_header: String,
    pub rate_limit_enabled: bool,
    pub rate_limit_auth_per_minute: u32,
    pub rate_limit_token_per_second: u32,
    pub rate_limit_token_client_per_second: u32,
    pub rate_limit_admin_per_second: u32,
    pub rate_limit_default_per_second: u32,
    pub key_rotation_days: u32,
    pub audit_retention_days: u32,
    /// `None` = mode default (loopback in dev mode, none otherwise).
    pub outbound_allow_cidrs: Option<ListValue>,
    pub outbound_ca_file: Option<PathBuf>,
    pub redis_url: Option<String>,
    pub rate_limit_redis_failure: String,
    pub metrics_listen: Option<String>,
    pub metrics_on_main_port: bool,
    pub otel_endpoint: Option<String>,
    pub otel_service_name: String,
    pub shutdown_drain: DurationValue,
    pub database_max_connections: u32,
    pub saml_experimental: bool,
    /// `None` or empty = the system resolver configuration.
    pub domain_verification_resolvers: Option<ListValue>,
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
            allow_destructive_migrations: false,
            insecure_http: false,
            log_format: None,
            trusted_proxies: None,
            trusted_proxy_header: "x-forwarded-for".to_owned(),
            rate_limit_enabled: true,
            rate_limit_auth_per_minute: DEFAULT_RATE_LIMIT_AUTH_PER_MINUTE,
            rate_limit_token_per_second: DEFAULT_RATE_LIMIT_TOKEN_PER_SECOND,
            rate_limit_token_client_per_second: DEFAULT_RATE_LIMIT_TOKEN_CLIENT_PER_SECOND,
            rate_limit_admin_per_second: DEFAULT_RATE_LIMIT_ADMIN_PER_SECOND,
            rate_limit_default_per_second: DEFAULT_RATE_LIMIT_DEFAULT_PER_SECOND,
            key_rotation_days: DEFAULT_KEY_ROTATION_DAYS,
            audit_retention_days: DEFAULT_AUDIT_RETENTION_DAYS,
            outbound_allow_cidrs: None,
            outbound_ca_file: None,
            redis_url: None,
            rate_limit_redis_failure: "closed".to_owned(),
            metrics_listen: None,
            metrics_on_main_port: false,
            otel_endpoint: None,
            otel_service_name: DEFAULT_OTEL_SERVICE_NAME.to_owned(),
            shutdown_drain: DurationValue::Secs(0),
            database_max_connections: DEFAULT_DATABASE_MAX_CONNECTIONS,
            saml_experimental: false,
            domain_verification_resolvers: None,
        }
    }
}

/// Default quotas, equal to [`LimiterConfig::default`] (a unit test keeps them in sync).
pub const DEFAULT_RATE_LIMIT_AUTH_PER_MINUTE: u32 = 10;
pub const DEFAULT_RATE_LIMIT_TOKEN_PER_SECOND: u32 = 50;
pub const DEFAULT_RATE_LIMIT_TOKEN_CLIENT_PER_SECOND: u32 = 100;
pub const DEFAULT_RATE_LIMIT_ADMIN_PER_SECOND: u32 = 20;
pub const DEFAULT_RATE_LIMIT_DEFAULT_PER_SECOND: u32 = 50;

/// Parses the trusted-proxy list. An entry is a CIDR (`10.0.0.0/8`) or a single address (a host
/// route). Errors name the key and the entry position, never the value.
pub fn parse_trusted_proxies(list: &ListValue) -> anyhow::Result<Vec<IpNet>> {
    parse_cidr_list("trusted_proxies", list)
}

/// Parses the outbound allow-list (same entry syntax as `trusted_proxies`).
pub fn parse_outbound_allow_cidrs(list: &ListValue) -> anyhow::Result<Vec<IpNet>> {
    parse_cidr_list("outbound_allow_cidrs", list)
}

/// Default DNS port of a `domain_verification_resolvers` entry without a port.
pub const DEFAULT_DNS_PORT: u16 = 53;

/// Parses the domain verification resolvers: each entry is an IP address (port 53) or a socket
/// address (`192.0.2.1:5353`, `[2001:db8::1]:53`). Errors name the key and the entry position,
/// never the value.
pub fn parse_domain_verification_resolvers(list: &ListValue) -> anyhow::Result<Vec<SocketAddr>> {
    list.entries()
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            entry
                .parse::<SocketAddr>()
                .ok()
                .or_else(|| {
                    entry
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| SocketAddr::new(ip, DEFAULT_DNS_PORT))
                })
                .filter(|addr| addr.port() != 0)
                .ok_or_else(|| {
                    field_error(
                        "domain_verification_resolvers",
                        format!("entry {} is not an IP address or IP:port", i + 1),
                    )
                })
        })
        .collect()
}

/// Reads and validates the extra outbound CA bundle. Errors name the key, never the content.
pub fn read_outbound_ca(path: &Path) -> anyhow::Result<Vec<u8>> {
    let pem = std::fs::read(path).map_err(|_| {
        field_error(
            "outbound_ca_file",
            format!("cannot read {}", path.display()),
        )
    })?;
    anvil_web::adapters::outbound::validate_ca_pem(&pem).map_err(|_| {
        field_error(
            "outbound_ca_file",
            "is not a PEM bundle of usable certificates",
        )
    })?;
    Ok(pem)
}

fn parse_cidr_list(key: &str, list: &ListValue) -> anyhow::Result<Vec<IpNet>> {
    list.entries()
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            entry
                .parse::<IpNet>()
                .map(|net| net.trunc())
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    field_error(key, format!("entry {} is not an IP address or CIDR", i + 1))
                })
        })
        .collect()
}

/// The rotation policy for a period of `days`: prepublish is 7 days, or half the period when the
/// period is shorter than 14 days (never below the JWKS cache lifetime); retire grace is the
/// default.
pub fn rotation_policy(days: u32) -> anyhow::Result<RotationPolicy> {
    if days == 0 || days > MAX_KEY_ROTATION_DAYS {
        return Err(field_error(
            "key_rotation_days",
            format!("must be between 1 and {MAX_KEY_ROTATION_DAYS}"),
        ));
    }
    let period = time::Duration::days(i64::from(days));
    let prepublish = DEFAULT_PREPUBLISH.min(period / 2).max(JWKS_MAX_AGE);
    RotationPolicy::new(period, prepublish, RotationPolicy::default().retire_grace())
        .map_err(|e| field_error("key_rotation_days", e))
}

fn quota(key: &str, n: u32) -> anyhow::Result<u32> {
    if n == 0 {
        return Err(field_error(
            key,
            "must be at least 1 (set rate_limit_enabled = false to turn limiting off)",
        ));
    }
    Ok(n)
}

/// Maps the `rate_limit_*` keys onto the limiter configuration. The login quota allows a burst
/// of half its per-minute count; the per-second quotas allow a burst of one second's worth.
pub fn rate_limits(raw: &RawConfig) -> anyhow::Result<LimiterConfig> {
    let auth = quota("rate_limit_auth_per_minute", raw.rate_limit_auth_per_minute)?;
    let token = quota(
        "rate_limit_token_per_second",
        raw.rate_limit_token_per_second,
    )?;
    let token_client = quota(
        "rate_limit_token_client_per_second",
        raw.rate_limit_token_client_per_second,
    )?;
    let admin = quota(
        "rate_limit_admin_per_second",
        raw.rate_limit_admin_per_second,
    )?;
    let default = quota(
        "rate_limit_default_per_second",
        raw.rate_limit_default_per_second,
    )?;
    Ok(LimiterConfig {
        enabled: raw.rate_limit_enabled,
        auth: RateQuota::per_minute(auth, (auth / 2).max(1)),
        token: RateQuota::per_second(token, token),
        token_client: RateQuota::per_second(token_client, token_client),
        admin: RateQuota::per_second(admin, admin),
        default: RateQuota::per_second(default, default),
        ..LimiterConfig::default()
    })
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
    /// Pending destructive migrations may run (`--allow-destructive-migrations`).
    pub allow_destructive_migrations: bool,
    pub insecure_http: bool,
    pub log_format: LogFormat,
    /// Reverse proxies trusted for the client IP.
    pub trusted_proxies: TrustedProxies,
    /// Rate limits (`enabled = false` turns limiting off).
    pub rate_limits: LimiterConfig,
    /// Signing-key rotation timings.
    pub rotation: RotationPolicy,
    /// Audit retention; `None` keeps events forever.
    pub audit_retention: Option<time::Duration>,
    /// Explicit outbound allow-list; `None` keeps the web layer's mode default.
    pub outbound_allow_cidrs: Option<Vec<IpNet>>,
    /// Extra outbound root certificates (validated PEM bundle).
    pub outbound_ca_pem: Option<Vec<u8>>,
    /// Shared rate-limit backend (`redis://` or `rediss://`); `None` = in-process limiter.
    pub redis_url: Option<SecretString>,
    /// Behaviour when the shared backend is unreachable.
    pub redis_failure: RedisFailure,
    /// Separate Prometheus listener.
    pub metrics_listen: Option<SocketAddr>,
    /// `/metrics` on the main listener too.
    pub metrics_on_main_port: bool,
    /// OTLP/HTTP traces endpoint base URL; `None` installs no OpenTelemetry layer.
    pub otel_endpoint: Option<CredentialUrl>,
    /// `service.name` of exported traces.
    pub otel_service_name: String,
    /// Readiness-503 period between SIGTERM and the graceful shutdown.
    pub shutdown_drain: Duration,
    /// Postgres pool size (SQLite ignores it).
    pub database_max_connections: u32,
    /// SAML 2.0 connections enabled (experimental; decision Q3).
    pub saml_experimental: bool,
    /// Explicit DNS resolvers for domain verification; empty = system configuration.
    pub domain_verification_resolvers: Vec<SocketAddr>,
    /// Non-fatal findings, logged as warnings on start.
    pub warnings: Vec<String>,
}

fn field_error(key: &str, message: impl fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("invalid configuration: {key}: {message}")
}

impl Config {
    /// How `serve` treats migrations: skipped with `no_migrate`, otherwise run with the
    /// destructive-migration permission.
    pub fn migrations(&self) -> Migrations {
        if self.migrate {
            Migrations::Run {
                allow_destructive: self.allow_destructive_migrations,
            }
        } else {
            Migrations::Skip
        }
    }

    /// Validates the merged configuration and derives the dependent defaults.
    pub fn resolve(raw: RawConfig) -> anyhow::Result<Self> {
        let public_url = PublicUrl::parse(raw.public_url.trim()).map_err(|e| match e {
            anvil_core::error::CoreError::Validation { message, .. } => {
                field_error("public_url", message)
            }
            other => field_error("public_url", other),
        })?;
        let mut warnings = Vec::new();
        let rate_limits = rate_limits(&raw)?;
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

        let header = match raw
            .trusted_proxy_header
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "x-forwarded-for" => ForwardedHeader::XForwardedFor,
            "forwarded" => ForwardedHeader::Forwarded,
            _ => {
                return Err(field_error(
                    "trusted_proxy_header",
                    "must be `x-forwarded-for` or `forwarded`",
                ));
            }
        };
        let trusted_proxies = match &raw.trusted_proxies {
            Some(list) => TrustedProxies {
                cidrs: parse_trusted_proxies(list)?,
                header,
            },
            None if public_url.is_dev_mode() => TrustedProxies {
                header,
                ..TrustedProxies::loopback()
            },
            None => TrustedProxies {
                cidrs: Vec::new(),
                header,
            },
        };
        if !rate_limits.enabled {
            warnings.push(
                "rate_limit_enabled is false: login, token and admin endpoints are not rate \
                 limited"
                    .to_owned(),
            );
        }
        let rotation = rotation_policy(raw.key_rotation_days)?;
        let audit_retention = match raw.audit_retention_days {
            0 => None,
            d if d > MAX_AUDIT_RETENTION_DAYS => {
                return Err(field_error(
                    "audit_retention_days",
                    format!("must be between 0 and {MAX_AUDIT_RETENTION_DAYS}"),
                ));
            }
            d => Some(time::Duration::days(i64::from(d))),
        };

        let outbound_allow_cidrs = raw
            .outbound_allow_cidrs
            .as_ref()
            .map(parse_outbound_allow_cidrs)
            .transpose()?;
        let outbound_ca_pem = raw
            .outbound_ca_file
            .as_deref()
            .map(read_outbound_ca)
            .transpose()?;
        let domain_verification_resolvers = raw
            .domain_verification_resolvers
            .as_ref()
            .map(parse_domain_verification_resolvers)
            .transpose()?
            .unwrap_or_default();

        let redis_url = raw
            .redis_url
            .filter(|u| !u.trim().is_empty())
            .map(|u| {
                // Never echo the value: it may hold a password.
                let ok = url::Url::parse(u.trim())
                    .is_ok_and(|p| matches!(p.scheme(), "redis" | "rediss") && p.has_host());
                if ok {
                    Ok(SecretString::from(u.trim().to_owned()))
                } else {
                    Err(field_error(
                        "redis_url",
                        "must be a redis:// or rediss:// URL with a host",
                    ))
                }
            })
            .transpose()?;
        let redis_failure = match raw
            .rate_limit_redis_failure
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "closed" => RedisFailure::Closed,
            "local" => RedisFailure::Local,
            _ => {
                return Err(field_error(
                    "rate_limit_redis_failure",
                    "must be `closed` or `local`",
                ));
            }
        };
        let metrics_listen = raw
            .metrics_listen
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| {
                v.parse::<SocketAddr>().map_err(|_| {
                    field_error(
                        "metrics_listen",
                        "must be a socket address such as 0.0.0.0:9464",
                    )
                })
            })
            .transpose()?;
        if metrics_listen == Some(listen) {
            return Err(field_error(
                "metrics_listen",
                "must differ from listen (use metrics_on_main_port to serve /metrics there)",
            ));
        }
        if raw.saml_experimental {
            warnings.push(
                "SAML 2.0 is experimental (saml_experimental is set): SAML connections can be \
                 configured and used; it has not had an external security review yet"
                    .to_owned(),
            );
        }
        if raw.metrics_on_main_port {
            warnings.push(
                "metrics_on_main_port is set: /metrics is reachable on the main listener; restrict                  it at the reverse proxy if the listener is public"
                    .to_owned(),
            );
        }
        let otel_endpoint = raw
            .otel_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| match url::Url::parse(v) {
                Ok(u) if matches!(u.scheme(), "http" | "https") && u.has_host() => {
                    Ok(CredentialUrl(u))
                }
                _ => Err(field_error(
                    "otel_endpoint",
                    "must be an absolute http:// or https:// URL",
                )),
            })
            .transpose()?;
        let otel_service_name = raw.otel_service_name.trim().to_owned();
        if otel_service_name.is_empty()
            || otel_service_name.len() > 255
            || otel_service_name.chars().any(char::is_control)
        {
            return Err(field_error(
                "otel_service_name",
                "must be 1 to 255 printable characters",
            ));
        }
        let shutdown_drain = raw
            .shutdown_drain
            .parse()
            .filter(|d| *d <= MAX_SHUTDOWN_DRAIN)
            .ok_or_else(|| {
                field_error(
                    "shutdown_drain",
                    "must be a duration such as 10s, 500ms or 1m, at most 1h",
                )
            })?;
        if !(1..=MAX_DATABASE_MAX_CONNECTIONS).contains(&raw.database_max_connections) {
            return Err(field_error(
                "database_max_connections",
                format!("must be between 1 and {MAX_DATABASE_MAX_CONNECTIONS}"),
            ));
        }

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
            allow_destructive_migrations: raw.allow_destructive_migrations,
            insecure_http: raw.insecure_http,
            log_format,
            trusted_proxies,
            rate_limits,
            rotation,
            audit_retention,
            outbound_allow_cidrs,
            outbound_ca_pem,
            redis_url,
            redis_failure,
            metrics_listen,
            metrics_on_main_port: raw.metrics_on_main_port,
            otel_endpoint,
            otel_service_name,
            shutdown_drain,
            database_max_connections: raw.database_max_connections,
            saml_experimental: raw.saml_experimental,
            domain_verification_resolvers,
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

/// [`redact_url`] that also hides a user name (Redis and OTLP URLs may carry a token there).
pub fn redact_userinfo(raw: &str) -> String {
    let redacted = redact_url(raw);
    let Ok(mut url) = url::Url::parse(&redacted) else {
        return redacted;
    };
    if url.username().is_empty() {
        return redacted;
    }
    if url.set_username("***").is_err() {
        return "***".to_owned();
    }
    url.to_string().replace("%2A%2A%2A", "***")
}

fn opt_str(v: Option<&String>) -> String {
    v.map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map_or_else(|| "<unset>".to_owned(), str::to_owned)
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
            "allow_destructive_migrations" => raw.allow_destructive_migrations.to_string(),
            "insecure_http" => raw.insecure_http.to_string(),
            "log_format" => raw.log_format.clone().unwrap_or_else(|| {
                if public_url.as_ref().is_some_and(PublicUrl::is_dev_mode) {
                    "pretty".to_owned()
                } else {
                    "json".to_owned()
                }
            }),
            "trusted_proxies" => match &raw.trusted_proxies {
                Some(list) => {
                    let entries = list.entries();
                    if entries.is_empty() {
                        "<none>".to_owned()
                    } else {
                        entries.join(", ")
                    }
                }
                None => if public_url.as_ref().is_some_and(PublicUrl::is_dev_mode) {
                    "127.0.0.0/8, ::1/128"
                } else {
                    "<none>"
                }
                .to_owned(),
            },
            "trusted_proxy_header" => raw.trusted_proxy_header.clone(),
            "rate_limit_enabled" => raw.rate_limit_enabled.to_string(),
            "rate_limit_auth_per_minute" => raw.rate_limit_auth_per_minute.to_string(),
            "rate_limit_token_per_second" => raw.rate_limit_token_per_second.to_string(),
            "rate_limit_token_client_per_second" => {
                raw.rate_limit_token_client_per_second.to_string()
            }
            "rate_limit_admin_per_second" => raw.rate_limit_admin_per_second.to_string(),
            "rate_limit_default_per_second" => raw.rate_limit_default_per_second.to_string(),
            "key_rotation_days" => raw.key_rotation_days.to_string(),
            "audit_retention_days" => raw.audit_retention_days.to_string(),
            "outbound_allow_cidrs" => match &raw.outbound_allow_cidrs {
                Some(list) => {
                    let entries = list.entries();
                    if entries.is_empty() {
                        "<none>".to_owned()
                    } else {
                        entries.join(", ")
                    }
                }
                None => if public_url.as_ref().is_some_and(PublicUrl::is_dev_mode) {
                    "127.0.0.0/8, ::1/128"
                } else {
                    "<none>"
                }
                .to_owned(),
            },
            "outbound_ca_file" => opt_path(raw.outbound_ca_file.as_ref()),
            "redis_url" => match raw.redis_url.as_deref().map(str::trim) {
                Some(u) if !u.is_empty() => redact_userinfo(u),
                _ => "<unset>".to_owned(),
            },
            "rate_limit_redis_failure" => raw.rate_limit_redis_failure.clone(),
            "metrics_listen" => opt_str(raw.metrics_listen.as_ref()),
            "metrics_on_main_port" => raw.metrics_on_main_port.to_string(),
            "otel_endpoint" => match raw.otel_endpoint.as_deref().map(str::trim) {
                Some(u) if !u.is_empty() => redact_userinfo(u),
                _ => "<unset>".to_owned(),
            },
            "otel_service_name" => raw.otel_service_name.clone(),
            "shutdown_drain" => raw.shutdown_drain.display(),
            "database_max_connections" => raw.database_max_connections.to_string(),
            "saml_experimental" => raw.saml_experimental.to_string(),
            "domain_verification_resolvers" => {
                let entries = raw
                    .domain_verification_resolvers
                    .as_ref()
                    .map(ListValue::entries)
                    .unwrap_or_default();
                if entries.is_empty() {
                    "<system>".to_owned()
                } else {
                    entries.join(", ")
                }
            }
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
    fn allow_destructive_migrations_defaults_off_and_reads_env_bool() {
        let cfg = resolve(&layers(&CliOverrides::default(), &[], None)).expect("cfg");
        assert!(!cfg.allow_destructive_migrations);
        assert_eq!(
            cfg.migrations(),
            Migrations::Run {
                allow_destructive: false
            }
        );
        let env = [("allow_destructive_migrations", s("true"))];
        let cfg = resolve(&layers(&CliOverrides::default(), &env, None)).expect("cfg");
        assert_eq!(
            cfg.migrations(),
            Migrations::Run {
                allow_destructive: true
            }
        );
        let cli = CliOverrides {
            no_migrate: true,
            allow_destructive_migrations: true,
            ..CliOverrides::default()
        };
        let cfg = resolve(&layers(&cli, &[], None)).expect("cfg");
        assert_eq!(cfg.migrations(), Migrations::Skip);
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
    fn trusted_proxies_from_env_list_and_defaults_by_mode() {
        let env = [
            ("public_url", s("https://id.example.test")),
            (
                "trusted_proxies",
                s("10.0.0.0/8, 192.168.0.0/16,203.0.113.7"),
            ),
            ("trusted_proxy_header", s("Forwarded")),
        ];
        let cfg = resolve(&layers(&CliOverrides::default(), &env, None)).expect("cfg");
        let cidrs: Vec<String> = cfg
            .trusted_proxies
            .cidrs
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(cidrs, ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.7/32"]);
        assert_eq!(cfg.trusted_proxies.header, ForwardedHeader::Forwarded);

        // TOML array form.
        let file = [(
            "trusted_proxies",
            Value::from(vec!["172.16.0.0/12".to_owned(), "::1".to_owned()]),
        )];
        let cfg = resolve(&layers(&CliOverrides::default(), &[], Some(&file))).expect("cfg");
        assert_eq!(cfg.trusted_proxies.cidrs.len(), 2);

        let dev = resolve(&layers(&CliOverrides::default(), &[], None)).expect("dev");
        assert_eq!(dev.trusted_proxies, TrustedProxies::loopback());
        let prod = resolve(&layers(
            &CliOverrides::default(),
            &[("public_url", s("https://id.example.test"))],
            None,
        ))
        .expect("prod");
        assert!(prod.trusted_proxies.cidrs.is_empty());
        // An explicit empty list overrides the dev-mode default.
        let none = resolve(&layers(
            &CliOverrides::default(),
            &[("trusted_proxies", s(""))],
            None,
        ))
        .expect("empty");
        assert!(none.trusted_proxies.cidrs.is_empty());
    }

    #[test]
    fn invalid_trusted_proxy_is_rejected_without_echo() {
        for (key, value) in [
            ("trusted_proxies", "10.0.0.0/8, not-a-cidr-secretish"),
            ("trusted_proxies", "10.0.0.0/33"),
            ("trusted_proxy_header", "x-real-ip"),
        ] {
            let err = resolve(&layers(&CliOverrides::default(), &[(key, s(value))], None))
                .expect_err(value)
                .to_string();
            assert!(err.contains(key), "{err}");
            assert!(!err.contains("secretish"), "{err}");
        }
    }

    #[test]
    fn rate_limits_switch_and_quota_overrides() {
        let cfg = resolve(&layers(&CliOverrides::default(), &[], None)).expect("cfg");
        assert_eq!(cfg.rate_limits, LimiterConfig::default());

        let env = [
            ("rate_limit_enabled", s("false")),
            ("rate_limit_auth_per_minute", s("30")),
            ("rate_limit_admin_per_second", s("5")),
        ];
        let cfg = resolve(&layers(&CliOverrides::default(), &env, None)).expect("cfg");
        assert!(!cfg.rate_limits.enabled);
        assert_eq!(cfg.rate_limits.auth, RateQuota::per_minute(30, 15));
        assert_eq!(cfg.rate_limits.admin, RateQuota::per_second(5, 5));
        assert_eq!(cfg.rate_limits.token, LimiterConfig::default().token);
        assert!(
            cfg.warnings
                .iter()
                .any(|w| w.contains("rate_limit_enabled")),
            "{:?}",
            cfg.warnings
        );

        for key in ["rate_limit_auth_per_minute", "rate_limit_token_per_second"] {
            let err = resolve(&layers(&CliOverrides::default(), &[(key, s("0"))], None))
                .expect_err(key)
                .to_string();
            assert!(err.contains(key), "{err}");
        }
        let err = resolve(&layers(
            &CliOverrides::default(),
            &[("rate_limit_enabled", s("maybe"))],
            None,
        ))
        .expect_err("bool")
        .to_string();
        assert!(err.contains("rate_limit_enabled"), "{err}");
    }

    #[test]
    fn rotation_and_retention_days() {
        let cfg = resolve(&layers(&CliOverrides::default(), &[], None)).expect("cfg");
        assert_eq!(cfg.rotation, RotationPolicy::default());
        assert_eq!(cfg.audit_retention, Some(time::Duration::days(365)));

        let env = [
            ("key_rotation_days", s("1")),
            ("audit_retention_days", s("0")),
        ];
        let cfg = resolve(&layers(&CliOverrides::default(), &env, None)).expect("cfg");
        assert_eq!(cfg.rotation.period(), time::Duration::days(1));
        assert_eq!(cfg.rotation.prepublish(), time::Duration::hours(12));
        assert_eq!(cfg.audit_retention, None);

        let cli = CliOverrides {
            key_rotation_days: Some(30),
            ..Default::default()
        };
        let l = layers(&cli, &[], None);
        let cfg = resolve(&l).expect("cfg");
        assert_eq!(cfg.rotation.period(), time::Duration::days(30));
        assert_eq!(cfg.rotation.prepublish(), time::Duration::days(7));
        assert_eq!(
            l.source("key_rotation_days"),
            Source::Cli("--key-rotation-days".to_owned())
        );

        for (key, value) in [
            ("key_rotation_days", "0"),
            ("key_rotation_days", "99999"),
            ("audit_retention_days", "99999"),
            ("audit_retention_days", "-1"),
        ] {
            let err = resolve(&layers(&CliOverrides::default(), &[(key, s(value))], None))
                .expect_err(value)
                .to_string();
            assert!(err.contains(key), "{key}={value}: {err}");
        }
    }

    #[test]
    fn show_lists_phase3_keys() {
        let env = [
            ("trusted_proxies", s("10.0.0.0/8")),
            ("rate_limit_enabled", s("false")),
        ];
        let l = layers(&CliOverrides::default(), &env, None);
        let out = show(&l, &l.raw().expect("raw"));
        assert!(
            out.contains("trusted_proxies = 10.0.0.0/8 (env ANVILID_TRUSTED_PROXIES)"),
            "{out}"
        );
        assert!(
            out.contains("rate_limit_enabled = false (env ANVILID_RATE_LIMIT_ENABLED)"),
            "{out}"
        );
        assert!(
            out.contains("trusted_proxy_header = x-forwarded-for (default)"),
            "{out}"
        );
        assert!(out.contains("key_rotation_days = 90 (default)"), "{out}");
        assert!(
            out.contains("audit_retention_days = 365 (default)"),
            "{out}"
        );
        assert!(
            out.contains("rate_limit_auth_per_minute = 10 (default)"),
            "{out}"
        );
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
