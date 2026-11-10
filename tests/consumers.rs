//! The consumers' shapes (ROADMAP 0.8, D-039, D-119): how serve-net, a
//! back-channel between two services, and smtp-net use tls-net, run here
//! end to end.
//!
//! - Direct mode: a net-io server (the driver serve-net picks, `Auto`)
//!   terminating TLS for two sites with ALPN and tickets, reloaded while
//!   clients connect. curl, OpenSSL, and Go check it with
//!   `TLS_NET_INTEROP=1` and `TLS_NET_GO=1`.
//! - Back-channel: tls-net on both ends over net-io, the server admitting
//!   only the client key it pins.
//! - STARTTLS: an SMTP client that upgrades a plaintext session, against a
//!   scripted server here and against a real MTA with
//!   `TLS_NET_MTA=host:port` (CI runs Postfix).

#![cfg(all(feature = "net-io", any(feature = "aws-lc", feature = "ring")))]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{TcpClient, data};
use net_io::{
    AllowAll, ConnectionInfo, DriverKind, Input, ListenerSpec, NetError, ServerBuilder, Session,
    SessionContext, Step, TcpConnection,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tls_net::{
    Alpn, ClientAuth, ClientBuilder, Event, HandshakeKind, KeySource, ServerIdentity, TlsClient,
    TlsError, TlsServer, TrustAnchors,
};

fn trust() -> TrustAnchors {
    TrustAnchors::from_pem(&data("ca.pem")).unwrap()
}

fn path(name: &str) -> String {
    format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn spki(pem: &str) -> [u8; 32] {
    let cert = CertificateDer::pem_slice_iter(&data(pem))
        .next()
        .unwrap()
        .unwrap();
    tls_net::spki_sha256(cert.as_ref()).unwrap()
}

/// One exchange over a fresh connection: handshake, request, whole reply.
fn exchange(addr: SocketAddr, client: &TlsClient, name: &str) -> (String, HandshakeKind) {
    let session = client.connect(name).unwrap();
    let mut c = TcpClient::new(TcpStream::connect(addr).unwrap(), session);
    c.handshake().unwrap();
    let kind = c.session.info().unwrap().kind;
    c.write(format!("GET / HTTP/1.1\r\nhost: {name}\r\n\r\n").as_bytes())
        .unwrap();
    let reply = String::from_utf8_lossy(&c.read(usize::MAX).unwrap()).into_owned();
    (reply, kind)
}

// Direct mode.

/// Answers each request with what the connection negotiated, then closes.
#[derive(Default)]
struct Site;

impl Session for Site {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let bytes = input.bytes();
        let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Step::Read;
        };
        input.consume(end + 4);
        let tls = cx.info().tls.as_deref();
        let body = format!(
            "sni={} alpn={} version={:#06x}",
            tls.and_then(|t| t.sni()).unwrap_or_default(),
            tls.and_then(|t| t.alpn())
                .map(String::from_utf8_lossy)
                .unwrap_or_default(),
            tls.map_or(0, |t| t.version())
        );
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        if cx.output().push(reply.as_bytes()).is_err() {
            return Step::Abort;
        }
        Step::Close
    }

    fn on_writable(&mut self, _cx: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
}

/// Two sites: `localhost` and its aliases (the default certificate) and
/// `api.other.test`; HTTP/2 preferred, then HTTP/1.1.
fn sites() -> tls_net::ServerBuilder {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .certificate(&data("api.pem"), KeySource::Pem(&data("api.key")))
        .unwrap()
        .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
}

fn direct(tls: &TlsServer) -> (net_io::Server, SocketAddr) {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .driver(DriverKind::Auto)
        .workers(2)
        .sessions(|_: &ConnectionInfo| Site)
        .tls(tls.clone())
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

#[test]
fn test_direct_mode_sites_alpn_and_resumption() {
    let tls = sites().build().unwrap();
    let (server, addr) = direct(&tls);
    let client = ClientBuilder::new()
        .trust(trust())
        .alpn(&[Alpn::HTTP_1_1])
        .resumption(8)
        .build()
        .unwrap();
    let (reply, first) = exchange(addr, &client, "localhost");
    assert!(
        reply.ends_with("sni=localhost alpn=http/1.1 version=0x0304"),
        "{reply}"
    );
    assert_eq!(first, HandshakeKind::Full);
    let (reply, second) = exchange(addr, &client, "localhost");
    assert!(reply.ends_with("version=0x0304"), "{reply}");
    assert_eq!(second, HandshakeKind::Resumed);
    // The second site, by SNI, with HTTP/2 offered first.
    let h2 = ClientBuilder::new()
        .trust(trust())
        .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
        .build()
        .unwrap();
    let (reply, _) = exchange(addr, &h2, "api.other.test");
    assert!(
        reply.ends_with("sni=api.other.test alpn=h2 version=0x0304"),
        "{reply}"
    );
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

#[test]
fn test_direct_mode_reload_under_traffic() {
    // Clients connect without pause while the site set is published again
    // and again: every handshake completes, against the old set or the new.
    let tls = sites().build().unwrap();
    let (server, addr) = direct(&tls);
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU32::new(0));
    let clients: Vec<_> = (0..4)
        .map(|_| {
            let (stop, done) = (Arc::clone(&stop), Arc::clone(&done));
            std::thread::spawn(move || {
                let client = ClientBuilder::new()
                    .trust(trust())
                    .alpn(&[Alpn::HTTP_1_1])
                    .build()
                    .unwrap();
                while !stop.load(Ordering::Relaxed) {
                    let (reply, _) = exchange(addr, &client, "api.other.test");
                    assert!(reply.contains("sni=api.other.test"), "{reply}");
                    done.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    let reload = tls.reload_handle();
    let before = reload.version();
    for _ in 0..20 {
        reload.publish(sites()).unwrap();
        std::thread::sleep(Duration::from_millis(25));
    }
    stop.store(true, Ordering::Relaxed);
    for c in clients {
        c.join().unwrap();
    }
    assert_eq!(reload.version(), before + 20);
    assert!(done.load(Ordering::Relaxed) >= 4);
    assert_eq!(tls.stats().handshakes_failed, 0);
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

#[test]
fn test_direct_mode_curl_openssl_and_go() {
    let interop = std::env::var_os("TLS_NET_INTEROP").is_some();
    let go = std::env::var_os("TLS_NET_GO").is_some();
    if !interop && !go {
        return;
    }
    let tls = sites().build().unwrap();
    let (server, addr) = direct(&tls);
    let port = addr.port().to_string();
    if interop && !cfg!(windows) {
        // curl: the second site by name, HTTP/1.1 (this site speaks no h2).
        let out = Command::new("curl")
            .args(["-sS", "--http1.1", "--cacert", &path("ca.pem"), "--resolve"])
            .arg(format!("api.other.test:{port}:127.0.0.1"))
            .arg(format!("https://api.other.test:{port}/"))
            .output()
            .expect("curl");
        let body = String::from_utf8_lossy(&out.stdout);
        assert!(
            body.contains("sni=api.other.test alpn=http/1.1"),
            "{body} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // OpenSSL: the default site, h2 by ALPN, chain verified.
        let mut child = Command::new("openssl")
            .args(["s_client", "-connect", &addr.to_string()])
            .args(["-servername", "localhost", "-alpn", "h2,http/1.1"])
            .args([
                "-CAfile",
                &path("ca.pem"),
                "-verify_return_error",
                "-brief",
                "-ign_eof",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("openssl");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains("Verification: OK") && text.contains("sni=localhost alpn=h2"),
            "{text}"
        );
    }
    if go {
        let bin = go_peer();
        let out = Command::new(bin)
            .args(["client", "-addr", &addr.to_string(), "-ca", &path("ca.pem")])
            .args([
                "-name",
                "api.other.test",
                "-alpn",
                "http/1.1",
                "-conns",
                "2",
            ])
            .output()
            .expect("tlspeer");
        let lines = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            lines.contains("conn=2 version=TLS1.3 alpn=http/1.1 resumed=true")
                && lines.contains("reply=sni=api.other.test"),
            "{lines}"
        );
    }
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

/// Builds the Go peer of `tests/go.rs`.
fn go_peer() -> std::path::PathBuf {
    let out = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(if cfg!(windows) {
        "tlspeer-consumers.exe"
    } else {
        "tlspeer-consumers"
    });
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&out)
        .arg(".")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/interop/go"))
        .status()
        .expect("go");
    assert!(status.success(), "go build failed");
    out
}

// Back-channel.

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Prints the back-channel server's events, so a failing run shows what the
/// server saw as well as what the client got.
struct Log;

impl tls_net::TlsObserver for Log {
    fn on_event(&self, event: &tls_net::TlsEvent<'_>) {
        eprintln!("server event: {event:?}");
    }
}

/// Answers a line with the principal net-io reports for the connection: the
/// SHA-256 of the verified client key, as the application maps it.
fn echo_line(conn: &mut TcpConnection) -> Result<(), NetError> {
    let mut buf = [0u8; 256];
    let n = conn
        .read(&mut buf)
        .inspect_err(|e| eprintln!("server read: {e:?}"))?;
    let peer = conn
        .info()
        .tls
        .as_deref()
        .and_then(|t| t.peer_spki_sha256())
        .map_or_else(|| "none".to_owned(), |h| hex(h));
    let mut reply = format!("{peer} ").into_bytes();
    reply.extend_from_slice(&buf[..n]);
    conn.write_all(&reply)
        .inspect_err(|e| eprintln!("server write: {e:?}"))?;
    Ok(())
}

/// A back-channel server over net-io admitting the client keys it pins,
/// with the chain checked against the shared CA.
fn back_channel(pins: &[[u8; 32]]) -> (net_io::Server, SocketAddr) {
    let tls = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .client_auth(ClientAuth::pinned(Some(trust()), pins))
        .observer(Arc::new(Log))
        .build()
        .unwrap();
    let server = ServerBuilder::new()
        .handler(echo_line)
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .workers(2)
        .tls(tls)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let addr = server.listeners()[0].local.socket_addr().unwrap();
    (server, addr)
}

fn ask_at(addr: SocketAddr, client: &TlsClient) -> Result<String, TlsError> {
    let to_server = ServerIdentity::Pinned {
        name: tls_net::DnsName::new("localhost").unwrap(),
        spki_sha256: vec![spki("site.pem")],
        require_chain: true,
    };
    let session = client.connect_to(&to_server)?;
    let mut c = TcpClient::new(TcpStream::connect(addr).unwrap(), session);
    c.handshake()
        .inspect_err(|e| eprintln!("handshake: {e:?}"))?;
    c.write(b"status\n")
        .inspect_err(|e| eprintln!("write: {e:?}"))?;
    let got = c.read(1).inspect_err(|e| eprintln!("read: {e:?}"))?;
    Ok(String::from_utf8_lossy(&got).into_owned())
}

fn client_with(cert: &str, key: &str) -> TlsClient {
    ClientBuilder::new()
        .trust(trust())
        .client_certificate(&data(cert), KeySource::Pem(&data(key)))
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn test_back_channel_pinned_client_key() {
    // The server admits the one client key it pins; the client pins the
    // server's key. A client with another key, or none, is refused before
    // any request.
    let (server, addr) = back_channel(&[spki("client.pem")]);
    let ask = |client: &TlsClient| ask_at(addr, client);
    let peer = client_with("client.pem", "client.key");
    assert_eq!(
        ask(&peer).unwrap(),
        format!("{} status\n", hex(&spki("client.pem")))
    );
    // A certificate from the same CA with another key: refused.
    let other = client_with("client-only.pem", "client-only.key");
    assert!(
        ask(&other).map_or(true, |s| s.is_empty()),
        "other key admitted"
    );
    let anonymous = ClientBuilder::new().trust(trust()).build().unwrap();
    assert!(
        ask(&anonymous).map_or(true, |s| s.is_empty()),
        "anonymous admitted"
    );
    // The client side refuses a server whose key is not the pinned one.
    let wrong = ServerIdentity::Pinned {
        name: tls_net::DnsName::new("localhost").unwrap(),
        spki_sha256: vec![spki("api.pem")],
        require_chain: true,
    };
    let session = peer.connect_to(&wrong).unwrap();
    let mut c = TcpClient::new(TcpStream::connect(addr).unwrap(), session);
    assert_eq!(c.handshake(), Err(TlsError::PinMismatch));
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

#[test]
fn test_back_channel_principal_per_peer() {
    // Two pinned peers on one server: net-io's connection facts carry each
    // one's own verified key, so the application can tell them apart (D-120).
    let (a, b) = (spki("client.pem"), spki("client-only.pem"));
    assert_ne!(a, b);
    let (server, addr) = back_channel(&[a, b]);
    let first = client_with("client.pem", "client.key");
    let second = client_with("client-only.pem", "client-only.key");
    for round in 0..2 {
        for (name, client, key) in [("first", &first, &a), ("second", &second, &b)] {
            assert_eq!(
                ask_at(addr, client),
                Ok(format!("{} status\n", hex(key))),
                "round {round}, {name} peer"
            );
        }
    }
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

// STARTTLS.

/// Reads one SMTP reply (all its lines) from a plaintext socket, returning
/// the reply and any bytes that followed it.
fn plain_reply(sock: &mut TcpStream, carry: &mut Vec<u8>) -> String {
    loop {
        if let Some(end) = reply_end(carry) {
            let rest = carry.split_off(end);
            let reply = String::from_utf8_lossy(carry).into_owned();
            *carry = rest;
            return reply;
        }
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).unwrap();
        assert!(n > 0, "server closed: {:?}", String::from_utf8_lossy(carry));
        carry.extend_from_slice(&buf[..n]);
    }
}

/// The end of the first complete reply: the line whose fourth byte is a
/// space ends a multi-line reply.
fn reply_end(buf: &[u8]) -> Option<usize> {
    let mut start = 0;
    while let Some(nl) = buf[start..].windows(2).position(|w| w == b"\r\n") {
        let line = &buf[start..start + nl];
        start += nl + 2;
        if line.len() < 4 || line[3] == b' ' {
            return Some(start);
        }
    }
    None
}

fn tls_reply(c: &mut TcpClient) -> String {
    let mut got = Vec::new();
    while reply_end(&got).is_none() {
        let more = c.read(1).unwrap();
        assert!(
            !more.is_empty(),
            "closed: {:?}",
            String::from_utf8_lossy(&got)
        );
        got.extend(more);
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// EHLO, STARTTLS, the upgrade, EHLO again over TLS, QUIT: what smtp-net
/// does before it sends mail. Returns the EHLO reply received over TLS.
fn starttls_session(addr: SocketAddr, name: &str, client: &TlsClient) -> String {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut carry = Vec::new();
    let greeting = plain_reply(&mut sock, &mut carry);
    assert!(greeting.starts_with("220"), "{greeting}");
    sock.write_all(b"EHLO client.tls-net.test\r\n").unwrap();
    let ehlo = plain_reply(&mut sock, &mut carry);
    assert!(ehlo.contains("STARTTLS"), "{ehlo}");
    sock.write_all(b"STARTTLS\r\n").unwrap();
    let ready = plain_reply(&mut sock, &mut carry);
    assert!(ready.starts_with("220"), "{ready}");
    // Anything after the 220 would be injected plaintext (T-5).
    let session = client.start_after_plaintext(name, &carry).unwrap();
    let mut c = TcpClient::new(sock, session);
    c.handshake().unwrap();
    c.write(b"EHLO client.tls-net.test\r\n").unwrap();
    let secure = tls_reply(&mut c);
    assert!(secure.starts_with("250"), "{secure}");
    c.write(b"QUIT\r\n").unwrap();
    let bye = tls_reply(&mut c);
    assert!(bye.starts_with("221"), "{bye}");
    secure
}

/// A scripted SMTP server: plaintext until STARTTLS, then tls-net.
fn scripted_mta() -> SocketAddr {
    let tls = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        sock.write_all(b"220 mta.test ESMTP\r\n").unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        // Plaintext: EHLO, then STARTTLS, read a byte at a time so nothing
        // after STARTTLS is taken from the socket.
        for answer in [
            &b"250-mta.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n"[..],
            b"220 2.0.0 Ready to start TLS\r\n",
        ] {
            line.clear();
            while !line.ends_with(b"\r\n") {
                sock.read_exact(&mut byte).unwrap();
                line.push(byte[0]);
            }
            sock.write_all(answer).unwrap();
        }
        let mut session = tls.accept().unwrap();
        let (mut inbuf, mut filled, mut out) = (vec![0u8; 64 * 1024], 0, vec![0u8; 64 * 1024]);
        let mut text = Vec::new();
        loop {
            let Ok(p) = session.step(&mut inbuf[..filled], &mut out) else {
                return;
            };
            let (consumed, written) = (p.consumed, p.written);
            let need = matches!(p.event, Event::NeedInput);
            if let Event::Data(d) = p.event {
                text.extend_from_slice(d);
            }
            sock.write_all(&out[..written]).unwrap();
            inbuf.copy_within(consumed..filled, 0);
            filled -= consumed;
            while let Some(nl) = text.windows(2).position(|w| w == b"\r\n") {
                let cmd: Vec<u8> = text.drain(..nl + 2).collect();
                let answer: &[u8] = if cmd.starts_with(b"EHLO") {
                    b"250-mta.test\r\n250 SIZE 10240000\r\n"
                } else {
                    b"221 2.0.0 Bye\r\n"
                };
                let n = session.encrypt(answer, &mut out).unwrap();
                sock.write_all(&out[..n]).unwrap();
                if cmd.starts_with(b"QUIT") {
                    let n = session.close(&mut out).unwrap();
                    sock.write_all(&out[..n]).unwrap();
                    return;
                }
            }
            if need && consumed == 0 && written == 0 {
                match sock.read(&mut inbuf[filled..]) {
                    Ok(0) | Err(_) => return,
                    Ok(k) => filled += k,
                }
            }
        }
    });
    addr
}

#[test]
fn test_starttls_against_scripted_server() {
    let client = ClientBuilder::new().trust(trust()).build().unwrap();
    let secure = starttls_session(scripted_mta(), "localhost", &client);
    assert!(secure.contains("SIZE"), "{secure}");
}

#[test]
fn test_starttls_against_real_mta() {
    let Some(addr) = std::env::var_os("TLS_NET_MTA") else {
        return;
    };
    let addr: SocketAddr = addr.to_str().unwrap().parse().unwrap();
    let name = std::env::var("TLS_NET_MTA_NAME").unwrap_or_else(|_| "localhost".to_owned());
    let client = ClientBuilder::new().trust(trust()).build().unwrap();
    let secure = starttls_session(addr, &name, &client);
    // Postfix stops advertising STARTTLS once TLS is on.
    assert!(!secure.contains("STARTTLS"), "{secure}");
}
