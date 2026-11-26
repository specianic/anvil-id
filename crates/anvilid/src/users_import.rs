//! `anvilid users import <file>` (ADM-08): imports users from an NDJSON file into a tenant
//! through the same service as the admin API, without HTTP (like `tenant apply`).
//!
//! Owned by plan 07-14. Pre-declared by 07-04 with the final argument set; until 07-14 replaces
//! [`run`], the command fails with an explicit "not available yet" error and changes nothing.

use std::path::PathBuf;

use crate::config::{CliOverrides, Config};

/// The marker of the not-yet-available command (removed by plan 07-14).
const TRANSITIONAL: &str = "not available yet (TRANSITIONAL(07-14))";

/// `users import` arguments.
#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// The NDJSON file with one user record per line (`-` for stdin).
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Slug of the tenant to import into.
    #[arg(long, value_name = "SLUG", default_value = "default")]
    pub tenant: String,

    /// Validate every record and print what would change, without writing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Update users that already exist (matched by external id or email) instead of skipping
    /// them.
    #[arg(long)]
    pub update: bool,

    /// Label of the source system, recorded on every imported user and in the audit log.
    #[arg(long, value_name = "LABEL")]
    pub source: Option<String>,
}

/// Runs `users import`. Not implemented yet: always an error, nothing is opened or written.
pub async fn run(_cfg: &Config, args: &ImportArgs) -> anyhow::Result<()> {
    let ImportArgs {
        config: _,
        file,
        tenant,
        dry_run,
        update,
        source,
    } = args;
    anyhow::bail!(
        "users import {} into tenant {tenant:?} (dry run: {dry_run}, update: {update}, source: \
         {source:?}): {TRANSITIONAL}",
        file.display()
    )
}
