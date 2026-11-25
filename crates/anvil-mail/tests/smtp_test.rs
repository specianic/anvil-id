//! Synchronous SMTP test send against an in-test SMTP sink (tokio TcpListener speaking enough
//! ESMTP for lettre): success, connection errors, AUTH rejection and the timeout.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anvil_core::model::SmtpTls;
use anvil_core::ports::{SmtpConnection, SmtpTester};
use anvil_mail::LettreSmtpTester;
use anvil_mail::tester::TEST_SUBJECT;
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const PASSWORD: &str = "sink-s3cret-pw";
const USER: &str = "sink-user";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Accepts everything (no AUTH advertised).
    Accept,
    /// Advertises AUTH and rejects it with 535, echoing what it received.
    RejectAuth,
    /// Accepts the connection and never says anything.
    Silent,
}

#[derive(Debug, Default, Clone)]
struct Received {
    rcpt: Vec<String>,
    data: String,
}

type Inbox = Arc<Mutex<Vec<Received>>>;

/// Starts a sink on a free local port; returns the port and what it received.
async fn sink(mode: Mode) -> (u16, Inbox) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let inbox: Inbox = Arc::default();
    let store = inbox.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let store = store.clone();
            tokio::spawn(async move {
                if mode == Mode::Silent {
                    let _keep = stream;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    return;
                }
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                write.write_all(b"220 sink ESMTP\r\n").await.unwrap();
                let mut current = Received::default();
                while let Ok(Some(line)) = lines.next_line().await {
                    let upper = line.to_ascii_uppercase();
                    let reply: String = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                        if mode == Mode::RejectAuth {
                            "250-sink\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n".into()
                        } else {
                            "250-sink\r\n250 OK\r\n".into()
                        }
                    } else if upper.starts_with("AUTH") {
                        format!("535 5.7.8 credentials rejected: {line} {USER} {PASSWORD}\r\n")
                    } else if upper.starts_with("RCPT TO:") {
                        current.rcpt.push(line[8..].trim().to_owned());
                        "250 OK\r\n".into()
                    } else if upper == "DATA" {
                        write.write_all(b"354 go ahead\r\n").await.unwrap();
                        while let Ok(Some(data)) = lines.next_line().await {
                            if data == "." {
                                break;
                            }
                            current.data.push_str(&data);
                            current.data.push('\n');
                        }
                        store.lock().unwrap().push(std::mem::take(&mut current));
                        "250 queued\r\n".into()
                    } else if upper == "QUIT" {
                        let _ = write.write_all(b"221 bye\r\n").await;
                        return;
                    } else {
                        "250 OK\r\n".into()
                    };
                    if write.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, inbox)
}

fn conn(port: u16, with_auth: bool) -> SmtpConnection {
    SmtpConnection {
        host: "127.0.0.1".into(),
        port,
        username: with_auth.then(|| USER.to_owned()),
        password: with_auth.then(|| SecretString::from(PASSWORD.to_owned())),
        from: "AnvilID Test <noreply@acme.example>".into(),
        tls: SmtpTls::None,
    }
}

fn tester(timeout: Duration) -> LettreSmtpTester {
    LettreSmtpTester { timeout }
}

#[tokio::test]
async fn test_send_delivers_to_the_given_address() {
    let (port, inbox) = sink(Mode::Accept).await;
    tester(Duration::from_secs(10))
        .send_test(&conn(port, false), "admin@acme.example")
        .await
        .unwrap();
    let received = inbox.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].rcpt, ["<admin@acme.example>"]);
    assert!(
        received[0]
            .data
            .contains(&format!("Subject: {TEST_SUBJECT}")),
        "{}",
        received[0].data
    );
    assert!(TEST_SUBJECT.to_lowercase().contains("test"));
    assert!(received[0].data.contains("noreply@acme.example"));
}

#[tokio::test]
async fn closed_port_reports_a_connection_error_without_the_password() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let err = tester(Duration::from_secs(10))
        .send_test(&conn(port, true), "admin@acme.example")
        .await
        .unwrap_err();
    assert!(err.to_lowercase().contains("connect"), "{err}");
    assert!(!err.contains(PASSWORD), "{err}");
}

#[tokio::test]
async fn auth_rejection_reports_535_without_credentials() {
    let (port, inbox) = sink(Mode::RejectAuth).await;
    let err = tester(Duration::from_secs(10))
        .send_test(&conn(port, true), "admin@acme.example")
        .await
        .unwrap_err();
    assert!(err.contains("535"), "{err}");
    assert!(!err.contains(PASSWORD), "{err}");
    assert!(!err.contains(USER), "{err}");
    // The base64 AUTH PLAIN argument the sink echoed back is redacted too.
    assert!(!err.contains("AHNpbmstdXNlcgBzaW5rLXMzY3JldC1wdw"), "{err}");
    assert!(inbox.lock().unwrap().is_empty());
}

#[tokio::test]
async fn silent_server_times_out() {
    let (port, _) = sink(Mode::Silent).await;
    let started = Instant::now();
    let err = tester(Duration::from_millis(300))
        .send_test(&conn(port, true), "admin@acme.example")
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(
        err.contains("timed out") || err.to_lowercase().contains("timeout"),
        "{err}"
    );
    assert!(!err.contains(PASSWORD), "{err}");
}

#[test]
fn default_timeout_is_ten_seconds() {
    assert_eq!(LettreSmtpTester::default().timeout, Duration::from_secs(10));
}
