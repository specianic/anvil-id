//! Throwaway Postgres 18 containers for tests (feature `testing`; never in release builds).
//!
//! The one place tests start a Postgres container. Two rules keep Docker from filling up:
//!
//! - The data directory is a tmpfs mount, so a container never creates an anonymous volume.
//! - Tests often keep a container in a `static` that is never dropped, so it outlives the test
//!   process. Each container is labelled with the PID of the process that started it, and every
//!   start first removes labelled containers whose process has exited.

use std::process::Command;

use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::core::Mount;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};

/// Label marking containers started here.
pub const LABEL: &str = "dev.anvilid.test";
/// Label holding the PID of the test process that owns the container.
pub const PID_LABEL: &str = "dev.anvilid.test.pid";

/// Starts a fresh Postgres 18 container and returns it with its server URL (no database name,
/// e.g. `postgres://postgres:postgres@127.0.0.1:32768`). Keep the handle alive while in use.
///
/// # Panics
/// When Docker is not available; Postgres tests need it.
pub async fn start(max_connections: u32) -> (ContainerAsync<Postgres>, String) {
    reap_orphans();
    let container = Postgres::default()
        .with_tag("18-alpine")
        .with_cmd([
            "postgres".to_owned(),
            "-c".to_owned(),
            format!("max_connections={max_connections}"),
        ])
        .with_mount(Mount::tmpfs_mount("/var/lib/postgresql"))
        .with_label(LABEL, "postgres")
        .with_label(PID_LABEL, std::process::id().to_string())
        .start()
        .await
        .expect("docker must be running for Postgres tests");
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("container port 5432 must be mapped");
    // Default credentials of the throwaway testcontainers image, not a secret.
    let url = format!("postgres://postgres:postgres@{host}:{port}");
    (container, url)
}

/// Removes containers (and their volumes) left behind by test processes that have exited.
/// Best effort: any failure only means nothing is reaped this time.
fn reap_orphans() {
    let Ok(out) = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label={LABEL}"),
            "--format",
            &format!("{{{{.ID}}}} {{{{.Label \"{PID_LABEL}\"}}}}"),
        ])
        .output()
    else {
        return;
    };
    let me = std::process::id();
    let orphans: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let (id, pid) = line.split_once(' ')?;
            let pid: u32 = pid.trim().parse().ok()?;
            (pid != me && !process_alive(pid)).then(|| id.to_owned())
        })
        .collect();
    if !orphans.is_empty() {
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v"])
            .args(&orphans)
            .output();
    }
}

/// Whether a local process is still running. Where that can't be told (no `/proc`), report
/// alive so nothing is removed by mistake.
fn process_alive(pid: u32) -> bool {
    let proc = std::path::Path::new("/proc");
    !proc.is_dir() || proc.join(pid.to_string()).exists()
}
