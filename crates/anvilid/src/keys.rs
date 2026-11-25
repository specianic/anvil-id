//! `anvilid keys rotate`: on-demand signing-key rotation (SEC-02).
//!
//! Without `--immediate` a next key is prepublished in the JWKS (or the existing next key is
//! kept); the scheduled rotation job activates it once caches have seen it. With `--immediate`
//! (key compromise) a new key becomes active at once and the old key is retired with
//! `expires_at = now`, so tokens it signed stop verifying. Audited as `key_rotation_requested`
//! with the system actor.
//!
//! Like `admin setup-url`, this runs next to a running server: no migrations, no serve lock.

use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::{AuditActor, DEFAULT_TENANT_SLUG};
use anvil_core::service::key_rotation::KeyRotationService;
use anvil_jose::Alg;
use anyhow::Context;

use crate::config::{CliOverrides, Config};
use crate::startup;

/// `keys rotate` arguments.
#[derive(Debug, clap::Args)]
pub struct RotateArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// Slug of the tenant whose key is rotated.
    #[arg(long, value_name = "SLUG", default_value = DEFAULT_TENANT_SLUG)]
    pub tenant: String,

    /// Signing algorithm to rotate: RS256, ES256 or Ed25519 (must be enabled for the tenant).
    #[arg(long, value_name = "ALG", default_value = "RS256", value_parser = parse_alg)]
    pub alg: Alg,

    /// Replace the active key now (key compromise): the old key leaves the JWKS at once and
    /// tokens it signed stop verifying.
    #[arg(long)]
    pub immediate: bool,
}

fn parse_alg(s: &str) -> Result<Alg, String> {
    match s.parse::<Alg>() {
        Ok(alg @ (Alg::RS256 | Alg::ES256 | Alg::Ed25519)) => Ok(alg),
        _ => Err("expected RS256, ES256 or Ed25519".to_owned()),
    }
}

/// Runs the rotation and prints the kid of the key that signs next.
pub async fn rotate(cfg: &Config, args: &RotateArgs) -> anyhow::Result<()> {
    let (storage, kek) = startup::open_for_cli(cfg).await?;
    let tenant = storage
        .tenants()
        .get_by_slug(&args.tenant)
        .await
        .context("failed to look up the tenant")?
        .with_context(|| format!("tenant `{}` does not exist", args.tenant))?;
    let service = KeyRotationService {
        storage,
        kek: Arc::new(kek),
        clock: Arc::new(SystemClock),
        policy: cfg.rotation,
    };
    let kid = service
        .rotate_now(&tenant, args.alg, args.immediate, AuditActor::system())
        .await
        .context("key rotation failed")?;
    if args.immediate {
        println!(
            "rotated {} key of tenant {} immediately; active kid: {kid}",
            args.alg, tenant.slug
        );
    } else {
        println!(
            "prepublished {} key of tenant {}; next kid: {kid} (activated by the scheduled \
             rotation once published for {} h)",
            args.alg,
            tenant.slug,
            cfg.rotation.prepublish().whole_hours()
        );
    }
    Ok(())
}
