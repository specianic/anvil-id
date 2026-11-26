//! `anvilid users import <file>` (ADM-08): imports users from an NDJSON file into a tenant
//! through the same `UserImportService` as the admin API, without HTTP (like `tenant apply`).
//!
//! The command opens the database with the server's configuration (next to a running server, no
//! migrations), resolves the tenant by slug, and streams the file line by line in batches of
//! [`IMPORT_BATCH_MAX`] records, so files of any size use bounded memory. Blank lines are skipped
//! (line numbers stay those of the file). Each batch records one `users_imported` audit event.
//!
//! The summary (counts per outcome, the number of weak hashes, rejected line numbers with their
//! reason codes, and conflicting line numbers) goes to stdout; errors go to stderr. Hashes,
//! salts and record contents are never printed. The exit status is non-zero when any record was
//! rejected (or on any error), zero otherwise; conflicts alone do not fail the command.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::{AuditActor, RequestContext};
use anvil_core::service::user_import::{
    IMPORT_BATCH_MAX, ImportCounts, ImportRequest, MAX_RECORD_BYTES, Outcome, RawRecord,
    RejectReason, UserImportService,
};
use anvil_web::adapters::attribute_schema::JsonSchemaCheck;
use anyhow::{Context, bail};

use crate::config::{CliOverrides, Config};
use crate::startup;

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

    /// Update users that already exist (matched by email) and whose data differs, instead of
    /// reporting a conflict.
    #[arg(long)]
    pub update: bool,

    /// Label of the source system, recorded in the audit log.
    #[arg(long, value_name = "LABEL")]
    pub source: Option<String>,
}

/// Reads the next line (without the newline) into `buf`, keeping at most
/// `MAX_RECORD_BYTES + 1` bytes of an over-long line (the service then rejects it by length) and
/// discarding the rest. `Ok(false)` at end of input.
fn next_line(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    buf.clear();
    let limit = (MAX_RECORD_BYTES + 1) as u64;
    let n = reader.by_ref().take(limit).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(false);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if n as u64 == limit {
        // Over-long: drop the remainder of this line.
        let mut rest = Vec::new();
        loop {
            rest.clear();
            let m = reader
                .by_ref()
                .take(64 * 1024)
                .read_until(b'\n', &mut rest)?;
            if m == 0 || rest.last() == Some(&b'\n') {
                break;
            }
        }
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(true)
}

/// The aggregated result of all batches.
#[derive(Default)]
struct Summary {
    counts: ImportCounts,
    batches: usize,
    rejected: Vec<(usize, RejectReason)>,
    conflicts: Vec<usize>,
}

impl Summary {
    fn print(&self, tenant: &str, dry_run: bool) {
        let c = &self.counts;
        let mode = if dry_run {
            " (dry run, nothing written)"
        } else {
            ""
        };
        println!("users import into tenant `{tenant}`{mode}");
        println!("batches:   {}", self.batches);
        println!("created:   {}", c.created);
        println!("unchanged: {}", c.unchanged);
        println!("updated:   {}", c.updated);
        println!("conflict:  {}", c.conflict);
        println!("rejected:  {}", c.rejected);
        println!("weak hashes accepted: {}", c.weak);
        if !self.rejected.is_empty() {
            println!("rejected lines:");
            for (line, reason) in &self.rejected {
                println!("  line {line}: {}", reason.as_str());
            }
        }
        if !self.conflicts.is_empty() {
            println!(
                "conflicting lines (existing users with different data; --update overwrites):"
            );
            for line in &self.conflicts {
                println!("  line {line}");
            }
        }
    }
}

/// Runs `users import`.
pub async fn run(cfg: &Config, args: &ImportArgs) -> anyhow::Result<()> {
    let input: Box<dyn Read> = if args.file.as_os_str() == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(
            std::fs::File::open(&args.file)
                .with_context(|| format!("failed to open {}", args.file.display()))?,
        )
    };
    let (storage, _kek) = startup::open_for_cli(cfg).await?;
    let tenant = storage
        .tenants()
        .get_by_slug(&args.tenant)
        .await
        .context("tenant lookup failed")?
        .with_context(|| format!("tenant `{}` does not exist", args.tenant))?;
    let service = UserImportService {
        storage,
        clock: Arc::new(SystemClock),
        check: Arc::new(JsonSchemaCheck::new()),
    };
    let ctx = RequestContext::system();
    let mut reader = BufReader::new(input);
    let mut summary = Summary::default();
    let mut buf = Vec::new();
    let mut line_no = 0usize;
    let mut batch: Vec<RawRecord> = Vec::with_capacity(IMPORT_BATCH_MAX);
    let mut eof = false;
    while !eof {
        if next_line(&mut reader, &mut buf)
            .with_context(|| format!("failed to read {}", args.file.display()))?
        {
            line_no += 1;
            if buf.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            // A line that is not UTF-8 cannot be JSON: the service rejects the empty text as
            // `invalid_record`.
            let text = String::from_utf8(std::mem::take(&mut buf)).unwrap_or_default();
            batch.push(RawRecord {
                line: line_no,
                text,
            });
            if batch.len() < IMPORT_BATCH_MAX {
                continue;
            }
        } else {
            eof = true;
            if batch.is_empty() {
                break;
            }
        }
        let report = service
            .import(
                tenant.id,
                ImportRequest {
                    records: std::mem::take(&mut batch),
                    dry_run: args.dry_run,
                    update: args.update,
                    source: args.source.as_deref(),
                    actor: AuditActor::system(),
                    ctx: &ctx,
                },
            )
            .await
            .context("import failed")?;
        summary.batches += 1;
        summary.counts.merge(&report.counts);
        for r in &report.records {
            match (r.outcome, r.reason) {
                (Outcome::Rejected, Some(reason)) => summary.rejected.push((r.line, reason)),
                (Outcome::Conflict, _) => summary.conflicts.push(r.line),
                _ => {}
            }
        }
    }
    summary.print(&args.tenant, args.dry_run);
    if summary.counts.rejected > 0 {
        bail!(
            "{} record(s) rejected; fix the listed lines and run the import again (accepted \
             records are not imported twice)",
            summary.counts.rejected
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_line_splits_and_caps_long_lines() {
        let long = "x".repeat(MAX_RECORD_BYTES + 10);
        let data = format!("a\r\n\n{long}\nb");
        let mut r = BufReader::new(data.as_bytes());
        let mut buf = Vec::new();
        let mut lines = Vec::new();
        while next_line(&mut r, &mut buf).unwrap() {
            lines.push(buf.len());
        }
        assert_eq!(lines, vec![1, 0, MAX_RECORD_BYTES + 1, 1]);
    }
}
