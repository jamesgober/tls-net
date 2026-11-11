//! `TlsStream`: a client or server over any blocking `Read + Write` in one
//! call, the Tier 1 way to use a session over a socket (0.10, D-141).

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

use common::data;
use tls_net::{TlsError, TlsServer, TlsStream};

fn server() -> TlsServer {
    tls_net::server_from_pem(&data("site.pem"), &data("site.key")).unwrap()
}

fn client() -> tls_net::TlsClient {
    tls_net::client_with_ca_pem(&data("ca.pem")).unwrap()
}

/// One connection on an ephemeral port, handled by `serve` on its own thread.
fn listen<T: Send + 'static>(
    serve: impl FnOnce(TcpStream) -> T + Send + 'static,
) -> (SocketAddr, JoinHandle<T>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || serve(listener.accept().unwrap().0));
    (addr, handle)
}

fn tls_error(e: &io::Error) -> Option<&TlsError> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
}

#[test]
fn test_stream_echo_round_trip_and_clean_close() {
    let tls = server();
    let (addr, done) = listen(move |tcp| {
        let mut s = tls.accept_stream(tcp).unwrap();
        let mut line = [0u8; 5];
        s.read_exact(&mut line).unwrap();
        s.write_all(&line).unwrap();
        s.close().unwrap();
        line
    });
    let mut s = client()
        .connect_stream("localhost", TcpStream::connect(addr).unwrap())
        .unwrap();
    assert!(s.info().is_some());
    s.write_all(b"hello").unwrap();
    let mut back = Vec::new();
    // close_notify ends the stream cleanly: read_to_end returns Ok.
    s.read_to_end(&mut back).unwrap();
    assert_eq!(back, b"hello");
    assert_eq!(&done.join().unwrap(), b"hello");
}

#[test]
fn test_stream_large_transfer_both_ways_in_order() {
    // More than six records each way, with reads smaller than a record.
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let expect = payload.clone();
    let tls = server();
    let (addr, done) = listen(move |tcp| {
        let mut s = tls.accept_stream(tcp).unwrap();
        let mut got = vec![0u8; 100_000];
        s.read_exact(&mut got).unwrap();
        s.write_all(&got).unwrap();
        s.flush().unwrap();
        s.close().unwrap();
        got == expect
    });
    let mut s = client()
        .connect_stream("localhost", TcpStream::connect(addr).unwrap())
        .unwrap();
    s.write_all(&payload).unwrap();
    let mut back = Vec::new();
    let mut chunk = [0u8; 777];
    loop {
        let n = s.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        back.extend_from_slice(&chunk[..n]);
    }
    assert!(done.join().unwrap(), "server saw other bytes");
    assert_eq!(back.len(), payload.len());
    assert!(back == payload, "client got other bytes");
}

#[test]
fn test_stream_one_byte_reads() {
    let tls = server();
    let (addr, done) = listen(move |tcp| {
        let mut s = tls.accept_stream(tcp).unwrap();
        s.write_all(b"abc").unwrap();
        s.close().unwrap();
    });
    let mut s = client()
        .connect_stream("localhost", TcpStream::connect(addr).unwrap())
        .unwrap();
    let mut one = [0u8; 1];
    let mut got = Vec::new();
    while s.read(&mut one).unwrap() == 1 {
        got.push(one[0]);
    }
    assert_eq!(got, b"abc");
    done.join().unwrap();
}

#[test]
fn test_stream_truncation_without_close_notify_is_an_error() {
    // A peer (or an attacker) that drops the connection without close_notify
    // must not look like a clean end of the stream (T-17).
    let tls = server();
    let (addr, done) = listen(move |tcp| {
        let mut s = tls.accept_stream(tcp).unwrap();
        s.write_all(b"partial").unwrap();
        drop(s.into_inner());
    });
    let mut s = client()
        .connect_stream("localhost", TcpStream::connect(addr).unwrap())
        .unwrap();
    let mut got = Vec::new();
    let e = s.read_to_end(&mut got).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(tls_error(&e), Some(&TlsError::UncleanClose));
    assert_eq!(got, b"partial");
    done.join().unwrap();
}

#[cfg(feature = "webpki-roots")]
#[test]
fn test_stream_untrusted_server_refused_at_connect() {
    // Mozilla's roots do not include the test CA.
    let tls = server();
    let (addr, done) = listen(move |tcp| tls.accept_stream(tcp).map(|_| ()));
    let other = tls_net::client().unwrap();
    let e = other
        .connect_stream("localhost", TcpStream::connect(addr).unwrap())
        .unwrap_err();
    assert!(matches!(e, TlsError::PeerCertificateInvalid(_)), "{e:?}");
    // The server learns of it through the client's alert.
    assert!(done.join().unwrap().is_err());
}

#[test]
fn test_stream_from_a_session_made_another_way() {
    // STARTTLS: the session comes from start_after_plaintext.
    let tls = server();
    let (addr, done) = listen(move |tcp| {
        let session = tls.accept().unwrap();
        let mut s = TlsStream::server(session, tcp).unwrap();
        s.write_all(b"220 ready").unwrap();
        s.close().unwrap();
    });
    let session = client().start_after_plaintext("localhost", b"").unwrap();
    let mut s = TlsStream::client(session, TcpStream::connect(addr).unwrap()).unwrap();
    let mut got = String::new();
    s.read_to_string(&mut got).unwrap();
    assert_eq!(got, "220 ready");
    done.join().unwrap();
}

/// A transport whose reads fail: the handshake reports it as `Transport`.
struct Broken;

impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::ConnectionReset))
    }
}

impl Write for Broken {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_stream_transport_error_reported_with_its_kind() {
    let e = client().connect_stream("localhost", Broken).unwrap_err();
    assert_eq!(
        e,
        TlsError::Transport {
            kind: io::ErrorKind::ConnectionReset
        }
    );
    assert_eq!(e.code(), 47);
}

#[test]
fn test_stream_eof_during_handshake_is_unclean() {
    let (addr, done) = listen(drop);
    let e = client()
        .connect_stream("localhost", TcpStream::connect(addr).unwrap())
        .unwrap_err();
    assert!(
        matches!(e, TlsError::UncleanClose | TlsError::Transport { .. }),
        "{e:?}"
    );
    done.join().unwrap();
}

#[test]
fn test_stream_write_after_close_refused() {
    let tls = server();
    let (addr, done) = listen(move |tcp| {
        let mut s = tls.accept_stream(tcp).unwrap();
        let mut sink = Vec::new();
        let _ = s.read_to_end(&mut sink);
    });
    let mut s = client()
        .connect_stream("localhost", TcpStream::connect(addr).unwrap())
        .unwrap();
    s.close().unwrap();
    let e = s.write_all(b"late").unwrap_err();
    assert_eq!(tls_error(&e), Some(&TlsError::WrongState));
    // close is idempotent.
    s.close().unwrap();
    drop(s);
    done.join().unwrap();
}
