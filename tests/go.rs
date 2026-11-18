//! Interoperability with Go's crypto/tls, both ways: a Go client against a
//! tls-net server and a tls-net client against a Go server, over TLS 1.3 and
//! 1.2, with ALPN, resumption, and mutual TLS. Opt-in (`TLS_NET_GO=1`),
//! because it builds `tests/interop/go` with the `go` tool; CI runs it on
//! Linux.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use common::{TcpClient, data, spawn_https};
use tls_net::{
    Alpn, ClientAuth, Event, KeySource, Policy, TlsClient, TlsServer, TrustAnchors, Version,
};

fn enabled() -> bool {
    std::env::var_os("TLS_NET_GO").is_some()
}

fn path(name: &str) -> String {
    format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// The Go peer, built once per test binary.
fn peer() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(if cfg!(windows) {
            "tlspeer.exe"
        } else {
            "tlspeer"
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
    })
}

/// Runs the Go client to completion; one output line per connection.
fn go_client(addr: SocketAddr, extra: &[&str]) -> Vec<String> {
    let out = Command::new(peer())
        .args(["client", "-addr", &addr.to_string(), "-ca", &path("ca.pem")])
        .args(extra)
        .output()
        .expect("tlspeer");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A Go server on an ephemeral port, killed on drop.
struct GoServer {
    child: Child,
    addr: SocketAddr,
}

impl GoServer {
    fn start(extra: &[&str]) -> GoServer {
        let mut child = Command::new(peer())
            .args([
                "server",
                "-cert",
                &path("site.pem"),
                "-key",
                &path("site.key"),
            ])
            .args(extra)
            .stdout(Stdio::piped())
            .spawn()
            .expect("tlspeer");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let addr = line
            .trim()
            .strip_prefix("listening ")
            .unwrap_or_else(|| panic!("{line:?}"))
            .parse()
            .unwrap();
        GoServer { child, addr }
    }

    /// One exchange: handshake, a line out, the server's line back.
    fn ask(&self, client: &TlsClient) -> String {
        let sock = TcpStream::connect(self.addr).unwrap();
        let mut c = TcpClient::new(sock, client.connect("localhost").unwrap());
        c.handshake().unwrap();
        c.write(b"ping\n").unwrap();
        let reply = c.read(usize::MAX).unwrap();
        String::from_utf8_lossy(&reply).trim().to_owned()
    }
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn site(policy: Policy) -> tls_net::ServerBuilder {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .policy(policy)
}

fn trust() -> TrustAnchors {
    TrustAnchors::from_pem(&data("ca.pem")).unwrap()
}

#[test]
fn test_go_client_tls13_and_tls12() {
    if !enabled() {
        return;
    }
    let addr = spawn_https(site(Policy::compatible()).build().unwrap());
    let l13 = go_client(addr, &[]);
    assert!(
        l13[0].contains("version=TLS1.3") && l13[0].ends_with("reply=hello from tls-net"),
        "{l13:?}"
    );
    let l12 = go_client(addr, &["-max", "1.2"]);
    assert!(
        l12[0].contains("version=TLS1.2") && l12[0].ends_with("reply=hello from tls-net"),
        "{l12:?}"
    );
}

#[test]
fn test_go_client_tls12_refused_by_modern_t2() {
    if !enabled() {
        return;
    }
    let addr = spawn_https(site(Policy::modern()).build().unwrap());
    let lines = go_client(addr, &["-max", "1.2"]);
    assert!(lines[0].contains("error="), "{lines:?}");
}

#[test]
fn test_go_client_alpn_and_resumption() {
    if !enabled() {
        return;
    }
    let server = site(Policy::compatible())
        .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
        .build()
        .unwrap();
    let addr = spawn_https(server);
    let lines = go_client(addr, &["-alpn", "h2,http/1.1", "-conns", "3"]);
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines.iter().all(|l| l.contains("alpn=h2")), "{lines:?}");
    assert!(lines[0].contains("resumed=false"), "{lines:?}");
    assert!(
        lines[1..].iter().all(|l| l.contains("resumed=true")),
        "{lines:?}"
    );
}

/// Accepts one connection, completes the handshake, and answers with the
/// client certificate's first DNS name as tls-net saw it.
fn serve_peer_name(server: TlsServer) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut session = server.accept().unwrap();
        let (mut inbuf, mut filled, mut out) = (vec![0u8; 64 * 1024], 0, vec![0u8; 64 * 1024]);
        let mut request = Vec::new();
        loop {
            let Ok(p) = session.step(&mut inbuf[..filled], &mut out) else {
                return;
            };
            let (consumed, written) = (p.consumed, p.written);
            let need = matches!(p.event, Event::NeedInput);
            if let Event::Data(d) = p.event {
                request.extend_from_slice(d);
            }
            sock.write_all(&out[..written]).unwrap();
            inbuf.copy_within(consumed..filled, 0);
            filled -= consumed;
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                let name = session
                    .info()
                    .and_then(|i| i.peer.as_ref().and_then(|p| p.dns_names.first().cloned()))
                    .unwrap_or_else(|| "none".to_owned());
                let n = session.encrypt(name.as_bytes(), &mut out).unwrap();
                sock.write_all(&out[..n]).unwrap();
                let n = session.close(&mut out).unwrap();
                sock.write_all(&out[..n]).unwrap();
                return;
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
fn test_go_client_certificate_reaches_tls_net_server() {
    if !enabled() {
        return;
    }
    let server = site(Policy::compatible())
        .client_auth(ClientAuth::required(trust()))
        .build()
        .unwrap();
    let addr = serve_peer_name(server);
    let lines = go_client(
        addr,
        &["-cert", &path("client.pem"), "-key", &path("client.key")],
    );
    assert!(lines[0].ends_with("reply=client.test"), "{lines:?}");
}

#[test]
fn test_go_server_tls13_tls12_and_alpn() {
    if !enabled() {
        return;
    }
    let go = GoServer::start(&["-alpn", "h2,http/1.1"]);
    let client = TlsClient::builder()
        .trust(trust())
        .alpn(&[Alpn::H2])
        .build()
        .unwrap();
    let reply = go.ask(&client);
    assert!(
        reply.starts_with("version=TLS1.3 alpn=h2 client=none") && reply.ends_with("echo=ping"),
        "{reply}"
    );
    let tls12 = TlsClient::builder()
        .trust(trust())
        .policy(
            Policy::client_default()
                .versions(&[Version::Tls12])
                .unwrap(),
        )
        .build()
        .unwrap();
    let reply = go.ask(&tls12);
    assert!(reply.starts_with("version=TLS1.2"), "{reply}");
}

#[test]
fn test_go_server_resumes_tls_net_client() {
    if !enabled() {
        return;
    }
    let go = GoServer::start(&[]);
    let client = TlsClient::builder()
        .trust(trust())
        .resumption(8)
        .build()
        .unwrap();
    let first = go.ask(&client);
    let second = go.ask(&client);
    assert!(first.contains("resumed=false"), "{first}");
    assert!(second.contains("resumed=true"), "{second}");
}

#[test]
fn test_go_server_requires_and_verifies_tls_net_client_certificate() {
    if !enabled() {
        return;
    }
    let go = GoServer::start(&["-clientca", &path("ca.pem")]);
    let client = TlsClient::builder()
        .trust(trust())
        .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
        .unwrap()
        .build()
        .unwrap();
    let reply = go.ask(&client);
    assert!(reply.contains("client=client.test"), "{reply}");
    // Without a certificate the Go server refuses the handshake.
    let anonymous = TlsClient::builder().trust(trust()).build().unwrap();
    let sock = TcpStream::connect(go.addr).unwrap();
    let mut c = TcpClient::new(sock, anonymous.connect("localhost").unwrap());
    let refused = c
        .handshake()
        .and_then(|()| c.write(b"ping\n"))
        .and_then(|()| c.read(1));
    assert!(
        refused.is_err() || refused.as_ref().is_ok_and(Vec::is_empty),
        "{refused:?}"
    );
}
