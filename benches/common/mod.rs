//! Shared bench helpers: fixtures, and one in-memory driver used for tls-net
//! sessions and for rustls's unbuffered connections driven directly, so the
//! two are compared through the same buffer handling.

#![allow(dead_code)]

use std::hint::black_box;
use std::sync::Arc;

use rustls::client::UnbufferedClientConnection;
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use tls_net::{ClientSession, Event, KeySource, ServerSession, TlsClient, TlsServer, TrustAnchors};

/// A fixture from `tests/data` (also found from `perf/`, which includes this file).
pub fn data(name: &str) -> Vec<u8> {
    let base = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!("{base}/tests/data/{name}"))
        .or_else(|_| std::fs::read(format!("{base}/../tests/data/{name}")))
        .unwrap()
}

/// The default server: one ECDSA P-256 certificate, default policy, tickets on.
pub fn server() -> TlsServer {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap()
}

/// A client trusting the test CA; `resumption` 0 forces full handshakes.
pub fn client(resumption: usize) -> TlsClient {
    TlsClient::builder()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .resumption(resumption)
        .build()
        .unwrap()
}

/// What one driving call did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ev {
    Need,
    Complete,
    Data(usize),
    Other,
}

/// One side of a connection, tls-net or rustls direct.
pub trait Drive {
    /// Processes `input`, writes records to `out`.
    fn drive(&mut self, input: &mut [u8], out: &mut [u8]) -> (usize, usize, Ev);
    /// Encrypts `plain` into `out`; returns bytes written.
    fn send(&mut self, plain: &[u8], out: &mut [u8]) -> usize;
}

macro_rules! tls_net_drive {
    ($t:ty) => {
        impl Drive for $t {
            fn drive(&mut self, input: &mut [u8], out: &mut [u8]) -> (usize, usize, Ev) {
                let p = self.step(input, out).expect("step");
                let ev = match p.event {
                    Event::NeedInput => Ev::Need,
                    Event::HandshakeComplete => Ev::Complete,
                    Event::Data(d) => Ev::Data(black_box(d).len()),
                    _ => Ev::Other,
                };
                (p.consumed, p.written, ev)
            }
            fn send(&mut self, plain: &[u8], out: &mut [u8]) -> usize {
                self.encrypt(plain, out).expect("encrypt")
            }
        }
    };
}
tls_net_drive!(ServerSession);
tls_net_drive!(ClientSession);

/// rustls's unbuffered connection driven the way an application would:
/// received plaintext is copied into the application's buffer once.
pub struct Direct<C> {
    pub conn: C,
    handshaking: bool,
    app: Vec<u8>,
}

impl Direct<UnbufferedServerConnection> {
    pub fn server(server: &TlsServer) -> Self {
        let config = Arc::clone(&server.as_rustls_configs()[0]);
        Direct::new(UnbufferedServerConnection::new(config).unwrap())
    }
}

impl Direct<UnbufferedClientConnection> {
    pub fn client(client: &TlsClient) -> Self {
        let name = "localhost".try_into().unwrap();
        Direct::new(UnbufferedClientConnection::new(client.as_rustls_config(), name).unwrap())
    }
}

impl<C> Direct<C> {
    /// Frees the application buffer (for memory accounting).
    pub fn release_app(&mut self) {
        self.app = Vec::new();
    }

    fn new(conn: C) -> Self {
        Direct {
            conn,
            handshaking: true,
            app: vec![0; 16 * 1024],
        }
    }
}

macro_rules! direct_drive {
    ($t:ty) => {
        impl Drive for Direct<$t> {
            fn drive(&mut self, input: &mut [u8], out: &mut [u8]) -> (usize, usize, Ev) {
                let (mut consumed, mut written) = (0, 0);
                loop {
                    let UnbufferedStatus { discard, state } =
                        self.conn.process_tls_records(&mut input[consumed..]);
                    match state.expect("rustls") {
                        ConnectionState::EncodeTlsData(mut e) => {
                            match e.encode(&mut out[written..]) {
                                Ok(n) => written += n,
                                Err(
                                    EncodeError::InsufficientSize(_) | EncodeError::AlreadyEncoded,
                                ) => {
                                    panic!("encode")
                                }
                            }
                            consumed += discard;
                        }
                        ConnectionState::TransmitTlsData(t) => {
                            t.done();
                            consumed += discard;
                        }
                        ConnectionState::BlockedHandshake => {
                            return (consumed + discard, written, Ev::Need);
                        }
                        ConnectionState::WriteTraffic(_) => {
                            consumed += discard;
                            if std::mem::take(&mut self.handshaking) {
                                return (consumed, written, Ev::Complete);
                            }
                            return (consumed, written, Ev::Need);
                        }
                        ConnectionState::ReadTraffic(mut r) => {
                            let Some(record) = r.next_record() else {
                                consumed += discard;
                                continue;
                            };
                            let record = record.expect("record");
                            let len = record.payload.len();
                            self.app[..len].copy_from_slice(record.payload);
                            black_box(&self.app[..len]);
                            return (consumed + discard + record.discard, written, Ev::Data(len));
                        }
                        _ => return (consumed + discard, written, Ev::Other),
                    }
                }
            }
            fn send(&mut self, plain: &[u8], out: &mut [u8]) -> usize {
                let UnbufferedStatus { state, .. } = self.conn.process_tls_records(&mut []);
                match state.expect("rustls") {
                    ConnectionState::WriteTraffic(mut w) => w.encrypt(plain, out).expect("encrypt"),
                    _ => panic!("not established"),
                }
            }
        }
    };
}
direct_drive!(UnbufferedServerConnection);
direct_drive!(UnbufferedClientConnection);

/// Two byte pipes and a scratch output, reused across connections.
pub struct Pipe {
    c2s: Vec<u8>,
    c2s_len: usize,
    s2c: Vec<u8>,
    s2c_len: usize,
    out: Vec<u8>,
}

impl Default for Pipe {
    fn default() -> Self {
        Pipe {
            c2s: vec![0; 128 * 1024],
            c2s_len: 0,
            s2c: vec![0; 128 * 1024],
            s2c_len: 0,
            out: vec![0; 64 * 1024],
        }
    }
}

fn one(
    side: &mut dyn Drive,
    inbox: &mut [u8],
    inbox_len: &mut usize,
    out: &mut [u8],
    peer: &mut [u8],
    peer_len: &mut usize,
) -> (bool, Ev) {
    let (consumed, written, ev) = side.drive(&mut inbox[..*inbox_len], out);
    inbox.copy_within(consumed..*inbox_len, 0);
    *inbox_len -= consumed;
    peer[*peer_len..*peer_len + written].copy_from_slice(&out[..written]);
    *peer_len += written;
    (consumed > 0 || written > 0 || ev != Ev::Need, ev)
}

impl Pipe {
    /// Runs both sides until both completed the handshake and every byte in
    /// flight (session tickets included) was processed.
    pub fn handshake(&mut self, s: &mut dyn Drive, c: &mut dyn Drive) {
        self.c2s_len = 0;
        self.s2c_len = 0;
        let (mut s_done, mut c_done) = (false, false);
        for _ in 0..64 {
            let (a, ev) = one(
                c,
                &mut self.s2c,
                &mut self.s2c_len,
                &mut self.out,
                &mut self.c2s,
                &mut self.c2s_len,
            );
            c_done |= ev == Ev::Complete;
            let (b, ev) = one(
                s,
                &mut self.c2s,
                &mut self.c2s_len,
                &mut self.out,
                &mut self.s2c,
                &mut self.s2c_len,
            );
            s_done |= ev == Ev::Complete;
            if !a && !b && s_done && c_done && self.c2s_len == 0 && self.s2c_len == 0 {
                return;
            }
        }
        panic!("handshake did not settle (server {s_done}, client {c_done})");
    }
}

/// `count` records of `size` plaintext bytes from `from`, appended to `wire`.
pub fn records(from: &mut dyn Drive, size: usize, count: usize, wire: &mut Vec<u8>) {
    let plain = vec![0x5a; size];
    let mut out = vec![0; size + 1024];
    wire.clear();
    for _ in 0..count {
        let n = from.send(&plain, &mut out);
        wire.extend_from_slice(&out[..n]);
    }
}

/// Receives every record in `wire`; returns plaintext bytes seen.
pub fn receive(to: &mut dyn Drive, wire: &mut [u8], out: &mut [u8]) -> usize {
    let (mut at, mut total) = (0, 0);
    while at < wire.len() {
        let (consumed, _, ev) = to.drive(&mut wire[at..], out);
        if let Ev::Data(n) = ev {
            total += n;
        }
        assert!(consumed > 0, "no progress");
        at += consumed;
    }
    total
}
