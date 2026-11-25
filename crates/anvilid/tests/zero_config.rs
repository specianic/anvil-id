//! Zero-config start (OPS-05, ADM-03): `anvilid serve` in an empty directory with no flags and
//! no environment except the listen address.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const SETUP_PREFIX: &str = "Setup URL: http://localhost:8080/setup?token=";

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// A running server whose stdout and stderr are collected (line by line, both streams) in the
/// background so the pipes never fill up.
struct Server {
    child: Child,
    port: u16,
    output: Arc<Mutex<String>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn output(&self) -> String {
        self.output.lock().expect("output lock").clone()
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command(cwd: &Path, args: &[&str], port: u16) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("ANVILID_LISTEN", format!("127.0.0.1:{port}"))
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd
}

fn collect(stream: impl Read + Send + 'static, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            let mut out = sink.lock().expect("output lock");
            out.push_str(&line);
            out.push('\n');
        }
    });
}

fn spawn_serve(cwd: &Path, port: u16) -> Server {
    let mut child = command(cwd, &["serve"], port)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn anvilid");
    let output = Arc::new(Mutex::new(String::new()));
    collect(child.stdout.take().expect("stdout"), Arc::clone(&output));
    collect(child.stderr.take().expect("stderr"), Arc::clone(&output));
    Server {
        child,
        port,
        output,
    }
}

fn http_get(port: u16, path: &str) -> std::io::Result<(String, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let status = raw.lines().next().unwrap_or_default().to_owned();
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// Starts `serve` in `cwd` and waits until it is healthy (the listener binds after bootstrap,
/// so the setup URL is already logged by then).
fn start(cwd: &Path) -> Server {
    let port = free_port();
    let mut server = spawn_serve(cwd, port);
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            std::thread::sleep(Duration::from_millis(200));
            panic!("anvilid exited early with {status}: {}", server.output());
        }
        if http_get(port, "/healthz").is_ok_and(|(s, _)| s.contains(" 200 ")) {
            // Give the collector threads a moment to drain the startup lines.
            std::thread::sleep(Duration::from_millis(200));
            return server;
        }
        assert!(Instant::now() < deadline, "anvilid did not become healthy");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The tokens of every `Setup URL:` line in `output`.
fn setup_tokens(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| l.split_once(SETUP_PREFIX).map(|(_, t)| t))
        .map(|t| t.split_whitespace().next().unwrap_or_default().to_owned())
        .collect()
}

fn setup_page_status(port: u16, token: &str) -> String {
    http_get(port, &format!("/setup?token={token}"))
        .expect("GET /setup")
        .0
}

#[test]
fn zero_config_start_installs_once_and_prints_the_setup_url() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let data = cwd.path().join("anvilid-data");

    let first = start(cwd.path());
    for file in ["anvilid.db", "kek", "serve.lock"] {
        assert!(data.join(file).exists(), "anvilid-data/{file} missing");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(data.join("kek"))
            .expect("kek metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "KEK file mode");
    }
    let output = first.output();
    let tokens = setup_tokens(&output);
    assert_eq!(
        tokens.len(),
        1,
        "expected exactly one setup URL line: {output}"
    );
    assert!(
        output.to_ascii_lowercase().contains("development mode"),
        "missing dev-mode warning: {output}"
    );
    let status = setup_page_status(first.port, &tokens[0]);
    assert!(status.contains(" 200 "), "setup page: {status}");
    let kek = std::fs::read(data.join("kek")).expect("read kek");

    // A second server on the same data directory is refused by the lock.
    let second = command(cwd.path(), &["serve"], free_port())
        .output()
        .expect("run second serve");
    assert!(!second.status.success(), "second serve must fail");
    let second_err = String::from_utf8_lossy(&second.stderr);
    assert!(second_err.contains("already running"), "{second_err}");

    // `admin setup-url` works next to the running server and issues a usable token.
    let admin = command(cwd.path(), &["admin", "setup-url"], first.port)
        .output()
        .expect("run admin setup-url");
    let admin_out = String::from_utf8_lossy(&admin.stdout);
    assert!(
        admin.status.success(),
        "admin setup-url failed: {admin_out}{}",
        String::from_utf8_lossy(&admin.stderr)
    );
    let admin_tokens = setup_tokens(&admin_out);
    assert_eq!(admin_tokens.len(), 1, "{admin_out}");
    assert_ne!(admin_tokens[0], tokens[0], "a new token is issued");
    let status = setup_page_status(first.port, &admin_tokens[0]);
    assert!(
        status.contains(" 200 "),
        "setup page for new token: {status}"
    );
    first.stop();

    // Restart: already installed, no setup URL, same KEK.
    let restarted = start(cwd.path());
    let output = restarted.output();
    assert!(
        setup_tokens(&output).is_empty(),
        "restart must not print a setup URL: {output}"
    );
    assert_eq!(
        std::fs::read(data.join("kek")).expect("read kek"),
        kek,
        "KEK changed on restart"
    );
    restarted.stop();
}
