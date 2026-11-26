//! `anvilid users export` (ADM-09): exports one user, a tenant's users, or a user's GDPR bundle
//! through the same `UserExportService` as the admin API, without HTTP (like `tenant export`).
//!
//! - default: every user of the tenant as NDJSON (one JSON object per line), read page by page;
//! - `--user <UUID>`: that user as one JSON document;
//! - `--user <UUID> --gdpr`: the user's data-subject bundle (JSON);
//! - `--include-password-hashes`: adds each user's stored PHC string to the bulk export. Only for
//!   the bulk export (refused with `--user` and `--gdpr`, decision Q4), only here (no HTTP path
//!   has it), and audited with `include_password_hashes: true`.
//!
//! Output goes to stdout or to `--out`, which is created with mode 0600 on Unix (an existing file
//! is truncated and set to 0600). Every run is audited as `user_exported` with the actor
//! `system`/`cli`. The audit mirror writes JSON lines to stdout, so it (and logging) is only
//! enabled with `--out` (see `main.rs`); without `--out` stdout carries the export alone and the
//! event is stored in the audit log only.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::error::CoreError;
use anvil_core::model::{ActorKind, AuditActor, RequestContext, UserId};
use anvil_core::service::user_export::{ExportOptions, UserExportService};
use anyhow::{Context, bail};
use uuid::Uuid;

use crate::config::{CliOverrides, Config};
use crate::startup;

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

/// The audit actor of every CLI export.
fn cli_actor() -> AuditActor {
    AuditActor {
        kind: ActorKind::System,
        id: Some("cli".to_owned()),
    }
}

/// Creates (or truncates) `path` with mode 0600 on Unix.
fn create_private(path: &Path) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    // `mode` applies only to new files; an existing file is tightened explicitly.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set the mode of {}", path.display()))?;
    }
    Ok(file)
}

/// Runs `users export`.
pub async fn run(cfg: &Config, args: &ExportArgs) -> anyhow::Result<()> {
    // clap already enforces these; checked again so the rule does not depend on the parser.
    if args.include_password_hashes && (args.user.is_some() || args.gdpr) {
        bail!("--include-password-hashes is only available for the bulk export (without --user)");
    }
    if args.gdpr && args.user.is_none() {
        bail!("--gdpr requires --user");
    }

    let (storage, _kek) = startup::open_for_cli(cfg).await?;
    let tenant = storage
        .tenants()
        .get_by_slug(&args.tenant)
        .await
        .context("failed to look up the tenant")?
        .with_context(|| format!("tenant `{}` does not exist", args.tenant))?;
    let service = UserExportService {
        storage,
        clock: Arc::new(SystemClock),
    };
    let actor = cli_actor();
    let ctx = RequestContext::system();

    let mut out: Box<dyn Write> = match &args.out {
        Some(path) => Box::new(std::io::BufWriter::new(create_private(path)?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout().lock())),
    };

    let not_found = |e: CoreError, id: Uuid| match e {
        CoreError::NotFound => anyhow::anyhow!("user {id} does not exist in `{}`", args.tenant),
        e => anyhow::Error::new(e).context("export failed"),
    };

    let count = match args.user {
        Some(id) if args.gdpr => {
            let bundle = service
                .gdpr_bundle(tenant.id, UserId(id), &actor, &ctx)
                .await
                .map_err(|e| not_found(e, id))?;
            serde_json::to_writer_pretty(&mut out, &bundle).context("failed to write")?;
            writeln!(out).context("failed to write")?;
            1
        }
        Some(id) => {
            let record = service
                .export_user(tenant.id, UserId(id), &actor, &ctx)
                .await
                .map_err(|e| not_found(e, id))?;
            serde_json::to_writer_pretty(&mut out, &record).context("failed to write")?;
            writeln!(out).context("failed to write")?;
            1
        }
        None => {
            let mut export = service.bulk(
                tenant.id,
                ExportOptions {
                    include_password_hashes: args.include_password_hashes,
                },
            );
            let written = write_bulk(&mut export, &mut out).await;
            if written.is_err() {
                export.mark_failed();
            }
            // Audited in every case: success only when every page was read and written.
            let count = export
                .finish(&actor, &ctx)
                .await
                .context("failed to audit the export")?;
            written?;
            count
        }
    };
    out.flush().context("failed to write")?;
    drop(out);

    let mode = match (args.user, args.gdpr) {
        (Some(_), true) => "GDPR bundle",
        (Some(_), false) => "user",
        (None, _) => "users",
    };
    match &args.out {
        Some(path) => eprintln!("exported {count} {mode} to {}", path.display()),
        None => eprintln!("exported {count} {mode}"),
    }
    if args.include_password_hashes {
        eprintln!("the export contains password hashes: store it like a secret");
    }
    Ok(())
}

/// Writes every page as NDJSON. An error stops the export (the audit records a failure).
async fn write_bulk(
    export: &mut anvil_core::service::user_export::BulkExport,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    while let Some(page) = export.next_page().await.context("export failed")? {
        for record in page {
            serde_json::to_writer(&mut *out, &record).context("failed to write")?;
            out.write_all(b"\n").context("failed to write")?;
        }
    }
    Ok(())
}
