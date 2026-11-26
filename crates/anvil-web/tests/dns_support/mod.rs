//! Local UDP DNS stub for the domain verification adapter tests (test code only).
//!
//! [`DnsStub::start`] binds `127.0.0.1:0` and answers with hickory-proto messages:
//! - TXT records for the names configured with [`DnsStub::set_txt`] (one entry per RR, each RR a
//!   list of character-strings);
//! - NOERROR with no answers (NODATA) for other types at a configured name;
//! - NXDOMAIN for every other name;
//! - SERVFAIL for everything after [`DnsStub::servfail`], silence after [`DnsStub::silent`].
//!
//! Every received query name is recorded exactly as sent ([`DnsStub::queries`]). The stub has
//! no TCP listener: TCP attempts to it are refused.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// How the stub answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Answer,
    ServFail,
    Silent,
}

#[derive(Debug)]
struct State {
    /// Lowercase absolute name (trailing dot) -> RRs, each a list of character-strings.
    records: HashMap<String, Vec<Vec<Vec<u8>>>>,
    mode: Mode,
    queries: Vec<String>,
}

/// A UDP DNS stub on loopback (module docs). The serving task stops on drop.
pub struct DnsStub {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for DnsStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn key(name: &str) -> String {
    let mut k = name.to_ascii_lowercase();
    if !k.ends_with('.') {
        k.push('.');
    }
    k
}

impl DnsStub {
    /// Binds `127.0.0.1:0` and starts answering.
    pub async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind dns stub");
        let addr = socket.local_addr().expect("stub addr");
        let state = Arc::new(Mutex::new(State {
            records: HashMap::new(),
            mode: Mode::Answer,
            queries: Vec::new(),
        }));
        let task = tokio::spawn(serve(socket, Arc::clone(&state)));
        Self { addr, state, task }
    }

    /// The address to pass to `HickoryTxtLookup::new`.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serves `rrs` as the TXT RRset of `name` (replacing any previous one).
    pub fn set_txt(&self, name: &str, rrs: &[&[&[u8]]]) {
        let rrs = rrs
            .iter()
            .map(|rr| rr.iter().map(|s| s.to_vec()).collect())
            .collect();
        self.state
            .lock()
            .expect("stub state")
            .records
            .insert(key(name), rrs);
    }

    /// Answers every following query with SERVFAIL.
    pub fn servfail(&self) {
        self.state.lock().expect("stub state").mode = Mode::ServFail;
    }

    /// Never answers again.
    pub fn silent(&self) {
        self.state.lock().expect("stub state").mode = Mode::Silent;
    }

    /// Every query name received so far, exactly as sent.
    pub fn queries(&self) -> Vec<String> {
        self.state.lock().expect("stub state").queries.clone()
    }
}

async fn serve(socket: UdpSocket, state: Arc<Mutex<State>>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Ok(request) = Message::from_vec(&buf[..len]) else {
            continue;
        };
        let Some(reply) = answer(&request, &state) else {
            continue;
        };
        if let Ok(bytes) = reply.to_vec() {
            let _ = socket.send_to(&bytes, peer).await;
        }
    }
}

fn answer(request: &Message, state: &Mutex<State>) -> Option<Message> {
    let mut state = state.lock().expect("stub state");
    let query = request.queries.first()?.clone();
    state.queries.push(query.name().to_string());
    let id = request.metadata.id;
    let mut reply = match state.mode {
        Mode::Silent => return None,
        Mode::ServFail => Message::error_msg(id, OpCode::Query, ResponseCode::ServFail),
        Mode::Answer => match state.records.get(&key(&query.name().to_string())) {
            None => Message::error_msg(id, OpCode::Query, ResponseCode::NXDomain),
            Some(rrs) => {
                let mut reply = Message::response(id, OpCode::Query);
                if query.query_type() == RecordType::TXT {
                    for rr in rrs {
                        let txt = TXT::try_new(rr.iter().map(|s| s.clone().into_boxed_slice()))
                            .expect("valid txt");
                        reply.add_answer(Record::from_rdata(
                            query.name().clone(),
                            0,
                            RData::TXT(txt),
                        ));
                    }
                }
                reply
            }
        },
    };
    reply.metadata.authoritative = true;
    reply.metadata.recursion_desired = request.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_query(query);
    Some(reply)
}
