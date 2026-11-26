//! `anvilid healthcheck`: exit 0 against a ready server, 1 when not ready or unreachable, and 2
//! (without connecting) for non-loopback or non-http targets.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn command(cwd: &Path, args: &[&str], port: u16) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("ANVILID_LISTEN", format!("127.0.0.1:{port}"))
        .env("ANVILID_PUBLIC_URL", format!("http://127.0.0.1:{port}"))
        .env("ANVILID_BREACH_CHECK", "off")
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd
}

fn healthcheck(cwd: &Path, args: &[&str], port: u16) -> Output {
    let mut all = vec!["healthcheck"];
    all.extend_from_slice(args);
    command(cwd, &all, port).output().expect("run healthcheck")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn live(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = write!(
        s,
        "GET /health/live HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    let mut raw = String::new();
    let _ = s.read_to_string(&mut raw);
    raw.starts_with("HTTP/1.1 200")
}

fn serve(cwd: &Path, port: u16, envs: &[(&str, &str)]) -> Server {
    let mut cmd = command(cwd, &["serve"], port);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn anvilid");
    let mut server = Server(child);
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = server.0.try_wait().expect("try_wait") {
            panic!("anvilid exited early with {status}");
        }
        if live(port) {
            return server;
        }
        assert!(Instant::now() < deadline, "anvilid did not become live");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A one-shot HTTP server answering every request with `status_line`.
fn fake_server(status_line: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = write!(
                stream,
                "{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    (port, handle)
}

#[test]
fn healthcheck_is_ready_against_a_running_server() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let server = serve(cwd.path(), port, &[]);

    // Default target: the port of `listen` on loopback.
    let out = healthcheck(cwd.path(), &[], port);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("ready"), "{}", text(&out));

    for url in [
        format!("http://127.0.0.1:{port}/health/ready"),
        format!("http://localhost:{port}/readyz"),
        format!("http://127.0.0.1:{port}"),
    ] {
        let out = healthcheck(cwd.path(), &["--url", &url], port);
        assert_eq!(out.status.code(), Some(0), "{url}: {}", text(&out));
    }
    drop(server);
}

#[test]
fn healthcheck_fails_when_not_ready_or_unreachable() {
    let cwd = tempfile::tempdir().expect("tempdir");

    let (port, fake) = fake_server("HTTP/1.1 503 Service Unavailable");
    let out = healthcheck(
        cwd.path(),
        &["--url", &format!("http://127.0.0.1:{port}/health/ready")],
        port,
    );
    fake.join().expect("fake server");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("503"), "{}", text(&out));

    // Nothing listens on the port.
    let port = free_port();
    let out = healthcheck(cwd.path(), &[], port);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));

    // Something that is not HTTP.
    let (port, fake) = fake_server("SSH-2.0-nope");
    let out = healthcheck(
        cwd.path(),
        &["--url", &format!("http://127.0.0.1:{port}/")],
        port,
    );
    fake.join().expect("fake server");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}

/// A draining server (SIGTERM with `shutdown_drain`) answers 503, so the probe fails.
#[cfg(unix)]
#[test]
fn healthcheck_fails_while_the_server_drains() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let server = serve(cwd.path(), port, &[("ANVILID_SHUTDOWN_DRAIN", "10s")]);
    let out = healthcheck(cwd.path(), &[], port);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    let status = Command::new("kill")
        .args(["-TERM", &server.0.id().to_string()])
        .status()
        .expect("kill -TERM");
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = healthcheck(cwd.path(), &[], port);
        if out.status.code() == Some(1) {
            assert!(text(&out).contains("503"), "{}", text(&out));
            break;
        }
        assert!(Instant::now() < deadline, "readiness never turned 503");
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(server);
}

#[test]
fn healthcheck_refuses_other_hosts_without_connecting() {
    let cwd = tempfile::tempdir().expect("tempdir");
    // A listener that records whether anything connected to it.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();

    for url in [
        "http://example.com/".to_owned(),
        // TEST-NET-1: a connection attempt would hang for the 2 s timeout.
        "http://192.0.2.1:8080/health/ready".to_owned(),
        format!("http://127.0.0.2:{port}/"),
        format!("https://127.0.0.1:{port}/"),
        format!("http://user:pw@127.0.0.1:{port}/"),
        format!("http://localhost.example.com:{port}/"),
    ] {
        let started = Instant::now();
        let out = healthcheck(cwd.path(), &["--url", &url], port);
        assert_eq!(out.status.code(), Some(2), "{url}: {}", text(&out));
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{url}: refused only after {:?}",
            started.elapsed()
        );
    }
    assert!(
        listener.accept().is_err(),
        "a refused target must not be connected to"
    );

    // A non-loopback listen address needs an explicit --url.
    let out = command(cwd.path(), &["healthcheck"], port)
        .env("ANVILID_LISTEN", "192.0.2.1:8080")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
}
