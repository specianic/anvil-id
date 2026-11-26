//! `anvilid admin recover`: local administrator access recovery (ADM-07).
//!
//! Requires a shell on the host: it opens the database with the server's configuration, next to a
//! running server (no migrations, no serve lock). There is no HTTP equivalent.

use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::error::CoreError;
use anvil_core::service::admin_recovery::AdminRecoveryService;
use anyhow::{Context, bail};
use secrecy::ExposeSecret;

use crate::config::{CliOverrides, Config};
use crate::startup;

/// `admin recover` arguments.
#[derive(Debug, clap::Args)]
pub struct RecoverArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// Email of the system-tenant account to recover: prints a one-time password-reset URL
    /// (valid 1 h) and makes sure the account holds the administrator role. Without --email a
    /// setup URL for a new administrator is printed, but only when no administrator is left.
    #[arg(long, value_name = "EMAIL")]
    pub email: Option<String>,

    /// Also remove the account's TOTP and passkeys (lost second factor).
    #[arg(long, requires = "email")]
    pub reset_mfa: bool,
}

/// Runs `admin recover` and prints the URL.
pub async fn recover(cfg: &Config, args: &RecoverArgs) -> anyhow::Result<()> {
    let (storage, _kek) = startup::open_for_cli(cfg).await?;
    let service = AdminRecoveryService {
        storage,
        clock: Arc::new(SystemClock),
        public_url: cfg.public_url.clone(),
    };
    let Some(email) = &args.email else {
        let url = match service.issue_fresh_admin().await {
            Ok(url) => url,
            Err(CoreError::Conflict(msg)) => bail!("refusing to create a new administrator: {msg}"),
            Err(e) => return Err(e).context("admin recovery failed"),
        };
        println!("No active administrator holds admin:write.");
        println!("Open this setup URL within 1 hour to create a new administrator (one use):");
        println!("Setup URL: {}", url.expose_secret());
        return Ok(());
    };
    let issued = match service.issue(email, args.reset_mfa).await {
        Ok(issued) => issued,
        Err(CoreError::NotFound) => bail!(
            "no system-tenant account has that email; admin recovery only applies to accounts \
             of the system tenant"
        ),
        Err(e @ CoreError::Validation { .. }) => {
            return Err(e).context("invalid --email");
        }
        Err(CoreError::Conflict(msg)) => bail!("cannot recover this account: {msg}"),
        Err(e) => return Err(e).context("admin recovery failed"),
    };
    if issued.role_assigned {
        println!("Assigned the administrator role to {}.", issued.user.email);
    }
    if args.reset_mfa {
        println!(
            "Removed {} second-factor credential(s) (TOTP, passkeys) of {}.",
            issued.mfa_removed, issued.user.email
        );
    }
    println!(
        "Open this URL within 1 hour to set a new password for {} (one use; existing sessions \
         are signed out):",
        issued.user.email
    );
    println!("Recovery URL: {}", issued.url.expose_secret());
    Ok(())
}
