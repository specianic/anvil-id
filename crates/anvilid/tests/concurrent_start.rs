//! Three `anvilid serve` nodes started at the same time on one empty Postgres database all come
//! up (OPS-03, research Pitfall 3): migrations serialise on the advisory lock, exactly one node
//! installs (and announces a setup URL), and console-client reconciliation and signing-key
//! generation treat a concurrent winner's unique violation as success, audited once.
//!
//! Runs under `ANVILID_TEST_DB=postgres` (`just test-pg`, Docker). With any other backend it
//! returns at once: SQLite allows one server per data directory (serve lock).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anvil_core::model::{
    AuditAction, AuditQuery, DEFAULT_TENANT_SLUG, KeyState, PageRequest, SYSTEM_TENANT_SLUG,
};
use anvil_core::ports::Storage;
use anvil_core::service::bootstrap::CONSOLE_CLIENT_ID;
use anvil_jose::Kek;
use anvil_storage_postgres::PostgresStorage;
use secrecy::ExposeSecret;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const NODES: usize = 3;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// One `anvilid serve` process; killed on drop. Output goes to files (never a full pipe).
struct Node {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn spawn(database_url: &str, kek: &str) -> Node {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = free_port();
        let mut cmd = Command::new(BIN);
        cmd.arg("serve")
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--public-url")
            .arg(format!("http://127.0.0.1:{port}"))
            .arg("--data-dir")
            .arg(dir.path())
            .arg("--database-url")
            .arg(database_url)
            .arg("--breach-check")
            .arg("off")
            .current_dir(dir.path())
            .env_clear()
            .env("ANVILID_KEK", kek)
            .stdin(Stdio::null())
            .stdout(File::create(dir.path().join("out.log")).expect("log file"))
            .stderr(File::create(dir.path().join("err.log")).expect("log file"));
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        Node {
            child: cmd.spawn().expect("spawn anvilid"),
            port,
            dir,
        }
    }

    fn log_path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn logs(&self) -> String {
        let out = std::fs::read_to_string(self.log_path("out.log")).unwrap_or_default();
        let err = std::fs::read_to_string(self.log_path("err.log")).unwrap_or_default();
        format!("{out}{err}")
    }

    /// `GET /healthz` answers 200; panics with the logs if the process exited.
    fn healthy(&mut self) -> bool {
        if let Some(status) = self.child.try_wait().expect("try_wait") {
            panic!(
                "node on port {} exited with {status} during a concurrent start:\n{}",
                self.port,
                self.logs()
            );
        }
        let Ok(mut stream) = TcpStream::connect(("127.0.0.1", self.port)) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let port = self.port;
        if write!(
            stream,
            "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        )
        .is_err()
        {
            return false;
        }
        let mut raw = String::new();
        let _ = stream.read_to_string(&mut raw);
        raw.lines().next().is_some_and(|l| l.contains(" 200 "))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_nodes_start_together_on_an_empty_postgres() {
    if std::env::var("ANVILID_TEST_DB").as_deref() != Ok("postgres") {
        eprintln!("concurrent_start runs under ANVILID_TEST_DB=postgres (just test-pg)");
        return;
    }
    let (_container, server_url) = anvil_storage::postgres_container::start(200).await;
    let database_url = format!("{server_url}/postgres");
    // Generated per run; never a fixed key.
    let kek = Kek::generate().to_base64().expose_secret().to_owned();

    // All three at once, before any of them has migrated or installed.
    let mut nodes: Vec<Node> = (0..NODES)
        .map(|_| Node::spawn(&database_url, &kek))
        .collect();
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut up = [false; NODES];
    while !up.iter().all(|u| *u) {
        for (i, node) in nodes.iter_mut().enumerate() {
            up[i] = up[i] || node.healthy();
        }
        assert!(
            Instant::now() < deadline,
            "not every node came up: {up:?}\n{}",
            nodes
                .iter()
                .map(Node::logs)
                .collect::<Vec<_>>()
                .join("\n---\n")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Exactly one node installed and announced the one-time setup URL.
    let all_logs: Vec<String> = nodes.iter().map(Node::logs).collect();
    let announced = all_logs
        .iter()
        .map(|l| l.matches("Setup URL: ").count())
        .sum::<usize>();
    assert_eq!(
        announced,
        1,
        "exactly one setup URL across {NODES} nodes:\n{}",
        all_logs.join("\n---\n")
    );

    let storage = PostgresStorage::connect(&database_url, 2)
        .await
        .expect("connect to Postgres");
    let tenants = storage
        .tenants()
        .list(PageRequest {
            after: None,
            limit: 100,
        })
        .await
        .expect("list tenants")
        .items;
    let mut slugs: Vec<&str> = tenants.iter().map(|t| t.slug.as_str()).collect();
    slugs.sort_unstable();
    assert_eq!(slugs, [DEFAULT_TENANT_SLUG, SYSTEM_TENANT_SLUG]);

    let system = tenants
        .iter()
        .find(|t| t.slug == SYSTEM_TENANT_SLUG)
        .expect("system tenant");
    assert!(
        storage
            .clients()
            .get(system.id, CONSOLE_CLIENT_ID)
            .await
            .expect("console client lookup")
            .is_some(),
        "console client reconciled"
    );
    let created = storage
        .audit()
        .query(
            system.id,
            &AuditQuery {
                action: Some(AuditAction::ClientCreated),
                target: Some(CONSOLE_CLIENT_ID.to_owned()),
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items;
    assert_eq!(
        created.len(),
        1,
        "client_created audited by the winner only"
    );

    // One active key per (tenant, alg).
    for tenant in &tenants {
        let mut active: BTreeMap<String, usize> = BTreeMap::new();
        for key in storage.keys().list(tenant.id).await.expect("list keys") {
            if key.state == KeyState::Active {
                *active.entry(key.alg).or_default() += 1;
            }
        }
        assert!(!active.is_empty(), "{}: no active key", tenant.slug);
        assert!(
            active.values().all(|n| *n == 1),
            "{}: active keys per alg {active:?}",
            tenant.slug
        );
    }

    // Every node keeps serving after the race.
    for node in &mut nodes {
        assert!(node.healthy(), "node on port {} stopped serving", node.port);
    }
}
