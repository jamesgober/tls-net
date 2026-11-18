//! tls-net as the TLS engine of a real net-io server (FR-6).

#![cfg(all(feature = "net-io", any(feature = "aws-lc", feature = "ring")))]

mod common;

use std::time::{Duration, Instant};

use common::{TcpClient, data};
use net_io::{AllowAll, ListenerSpec, NetError, ServerBuilder, TcpConnection};
use tls_net::{Alpn, KeySource, TlsClient, TlsServer, TrustAnchors};

fn echo(conn: &mut TcpConnection) -> Result<(), NetError> {
    let tls = conn.info().tls.as_ref().map(|t| {
        (
            t.sni().map(str::to_owned),
            t.alpn().map(<[u8]>::to_vec),
            t.version(),
        )
    });
    conn.send_all(format!("{tls:?};").as_bytes())?;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = conn.recv(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        conn.send_all(&buf[..n])?;
    }
}

fn start() -> (net_io::Server, std::net::SocketAddr) {
    let tls = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
        .build()
        .unwrap();
    let server = ServerBuilder::new()
        .handler(echo)
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .workers(32)
        .tls(tls)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let addr = server.listeners()[0]
        .local
        .socket_addr()
        .expect("ip listener");
    (server, addr)
}

fn tls_client() -> tls_net::TlsClient {
    TlsClient::builder()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .alpn(&[Alpn::HTTP_1_1])
        .build()
        .unwrap()
}

#[test]
fn test_net_io_server_carries_tls_end_to_end() {
    let (server, addr) = start();
    let client = tls_client();
    let sock = std::net::TcpStream::connect(addr).unwrap();
    let mut c = TcpClient::new(sock, client.connect("example.test").unwrap());
    c.handshake().unwrap();
    let hello = String::from_utf8(c.read(1).unwrap()).unwrap();
    assert!(
        hello.contains("Some(\"example.test\")") && hello.contains("772"),
        "{hello}"
    );
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut back = Vec::new();
    for part in big.chunks(50_000) {
        c.write(part).unwrap();
        back.extend(c.read(part.len()).unwrap());
    }
    assert!(back == big, "echo differs");
    drop(c);
    let report = server.shutdown(Instant::now() + Duration::from_secs(5));
    let _ = report;
}

#[test]
fn test_net_io_server_many_connections() {
    let (server, addr) = start();
    let client = tls_client();
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let client = client.clone();
            std::thread::spawn(move || {
                for j in 0..10 {
                    let sock = std::net::TcpStream::connect(addr).unwrap();
                    let mut c = TcpClient::new(sock, client.connect("localhost").unwrap());
                    c.handshake().unwrap();
                    c.read(1).unwrap();
                    let msg = format!("thread {i} round {j}");
                    c.write(msg.as_bytes()).unwrap();
                    let got = c.read(msg.len()).unwrap();
                    assert_eq!(got, msg.as_bytes());
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

#[test]
fn test_net_io_server_refuses_plain_http() {
    use std::io::{Read, Write};
    let (server, addr) = start();
    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 64];
    // The connection is closed without a response.
    assert!(matches!(sock.read(&mut buf), Ok(0) | Err(_)));
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

#[test]
fn test_net_io_request_in_the_finished_flight() {
    // The request travels in the same TCP write as the client's Finished.
    let (server, addr) = start();
    let client = tls_client();
    for _ in 0..20 {
        let sock = std::net::TcpStream::connect(addr).unwrap();
        let mut c = TcpClient::new(sock, client.connect("localhost").unwrap());
        c.handshake_with_early_request(b"ping").unwrap();
        let got = c.read(1).unwrap();
        let mut all = got;
        while !all.ends_with(b"ping") {
            all.extend(c.read(1).unwrap());
        }
        assert!(
            all.ends_with(b"ping"),
            "{:?}",
            String::from_utf8_lossy(&all)
        );
    }
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

#[test]
fn test_t13_stalled_handshake_releases_its_slot_at_the_deadline() {
    // One handshake slot. A peer sends one byte of its hello and stalls;
    // net-io's handshake deadline closes it, the session drops, and the
    // slot is free for the next client (T-13).
    use std::io::Write;
    let tls = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .limits(tls_net::HandshakeLimits::server().max_in_progress(1))
        .build()
        .unwrap();
    let limits = net_io::Limits::blocking_defaults()
        .to_builder()
        // Long enough that a loaded test machine still sees the slot held.
        .handshake_timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let server = ServerBuilder::new()
        .handler(echo)
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .workers(4)
        .limits(limits)
        .tls(tls.clone())
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let addr = server.listeners()[0]
        .local
        .socket_addr()
        .expect("ip listener");
    let mut stalled = std::net::TcpStream::connect(addr).unwrap();
    stalled.write_all(&[22]).unwrap();
    // Wait until the stalled handshake holds the slot.
    let start = Instant::now();
    while tls.stats().in_progress == 0 && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(tls.stats().in_progress, 1);
    // After the deadline the slot is back and a client completes.
    let start = Instant::now();
    while tls.stats().in_progress != 0 && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(tls.stats().in_progress, 0, "the deadline released the slot");
    assert!(start.elapsed() < Duration::from_secs(6));
    // The client session is built before the socket connects: net-io's
    // deadline counts from the accept, so building it after spent the
    // handshake's time on a loaded machine (D-116).
    let session = tls_client().connect("localhost").unwrap();
    let sock = std::net::TcpStream::connect(addr).unwrap();
    let mut c = TcpClient::new(sock, session);
    c.handshake().unwrap();
    drop((c, stalled));
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}
