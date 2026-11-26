//! `anvilid users export` (ADM-09): exports one user, a tenant's users, or a user's GDPR bundle
//! through the same service as the admin API, without HTTP (like `tenant export`).
//!
//! Owned by plan 07-15. Pre-declared by 07-04 with the final argument set; until 07-15 replaces
//! [`run`], the command fails with an explicit "not available yet" error and writes nothing.

use std::path::PathBuf;

use uuid::Uuid;

use crate::config::{CliOverrides, Config};

/// The marker of the not-yet-available command (removed by plan 07-15).
const TRANSITIONAL: &str = "not available yet (TRANSITIONAL(07-15))";

/// `users export` arguments.
#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// Slug of the tenant to export from.
    #[arg(long, value_name = "SLUG", default_value = "default")]
    pub tenant: String,

    /// Export only this user (id).
    #[arg(long, value_name = "UUID")]
    pub user: Option<Uuid>,

    /// Export the GDPR data bundle of --user (everything stored about the user).
    #[arg(long, requires = "user")]
    pub gdpr: bool,

    /// Include password hashes. CLI only; audited; never part of the GDPR export (decision Q4).
    #[arg(long, conflicts_with = "gdpr")]
    pub include_password_hashes: bool,

    /// Write the export to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// Runs `users export`. Not implemented yet: always an error, nothing is opened or written.
pub async fn run(_cfg: &Config, args: &ExportArgs) -> anyhow::Result<()> {
    let ExportArgs {
        config: _,
        tenant,
        user,
        gdpr,
        include_password_hashes,
        out,
    } = args;
    anyhow::bail!(
        "users export from tenant {tenant:?} (user: {user:?}, gdpr: {gdpr}, password hashes: \
         {include_password_hashes}, out: {out:?}): {TRANSITIONAL}"
    )
}
