//! The tls-net client against public HTTPS sites with the Mozilla roots.
//! Opt-in (`TLS_NET_NETWORK=1`), because it needs the internet; CI runs it on Linux.

#![cfg(all(feature = "webpki-roots", any(feature = "aws-lc", feature = "ring")))]

mod common;

use common::TcpClient;
use tls_net::{Alpn, ClientBuilder, TrustAnchors};

#[test]
fn test_public_sites_verify_with_mozilla_roots() {
    if std::env::var_os("TLS_NET_NETWORK").is_none() {
        return;
    }
    let client = ClientBuilder::new()
        .trust(TrustAnchors::mozilla())
        .alpn(&[Alpn::HTTP_1_1])
        .build()
        .unwrap();
    for host in [
        "www.rust-lang.org",
        "crates.io",
        "github.com",
        "www.cloudflare.com",
    ] {
        let sock = std::net::TcpStream::connect((host, 443)).unwrap();
        let mut c = TcpClient::new(sock, client.connect(host).unwrap());
        c.handshake().unwrap_or_else(|e| panic!("{host}: {e}"));
        let info = c.session.info().unwrap();
        assert_eq!(info.alpn, Some(b"http/1.1".as_slice()), "{host}");
        c.write(format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
            .unwrap();
        let reply = c.read(9).unwrap();
        assert!(
            reply.starts_with(b"HTTP/1.1 "),
            "{host}: {:?}",
            String::from_utf8_lossy(&reply)
        );
    }
}

#[test]
fn test_public_site_wrong_name_refused() {
    if std::env::var_os("TLS_NET_NETWORK").is_none() {
        return;
    }
    let client = tls_net::client().unwrap();
    // Connect to one host but verify against another name.
    let sock = std::net::TcpStream::connect(("www.rust-lang.org", 443)).unwrap();
    let mut c = TcpClient::new(sock, client.connect("example.com").unwrap());
    assert!(matches!(
        c.handshake(),
        Err(tls_net::TlsError::PeerCertificateInvalid(_))
    ));
}

#[test]
fn test_starttls_to_a_public_relay() {
    // SMTP submission with STARTTLS (port 587), verified with the Mozilla roots.
    use std::io::{Read, Write};
    if std::env::var_os("TLS_NET_NETWORK").is_none() {
        return;
    }
    let host = "smtp.gmail.com";
    let Ok(mut sock) = std::net::TcpStream::connect((host, 587)) else {
        return;
    };
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut buf = Vec::new();
    let until =
        |sock: &mut std::net::TcpStream, buf: &mut Vec<u8>, done: &dyn Fn(&[u8]) -> bool| {
            while !done(buf) {
                let mut chunk = [0u8; 1024];
                let n = sock.read(&mut chunk).unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&chunk[..n]);
            }
        };
    until(&mut sock, &mut buf, &|b| b.ends_with(b"\r\n"));
    buf.clear();
    sock.write_all(b"EHLO tls-net.test\r\n").unwrap();
    until(&mut sock, &mut buf, &|b| {
        b.split(|&c| c == b'\n').any(|l| l.starts_with(b"250 "))
    });
    assert!(buf.windows(8).any(|w| w == b"STARTTLS"));
    buf.clear();
    sock.write_all(b"STARTTLS\r\n").unwrap();
    until(&mut sock, &mut buf, &|b| b.ends_with(b"\r\n"));
    assert!(
        buf.starts_with(b"220"),
        "{:?}",
        String::from_utf8_lossy(&buf)
    );
    let end = buf.iter().position(|&c| c == b'\n').unwrap() + 1;
    let leftover = buf[end..].to_vec();
    let client = tls_net::client().unwrap();
    let mut c = TcpClient::new(sock, client.start_after_plaintext(host, &leftover).unwrap());
    c.handshake().unwrap();
    c.write(b"EHLO tls-net.test\r\n").unwrap();
    let reply = c.read(4).unwrap();
    assert!(
        reply.starts_with(b"250"),
        "{:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[cfg(feature = "platform-verifier")]
#[test]
fn test_platform_verifier_public_sites() {
    if std::env::var_os("TLS_NET_NETWORK").is_none() {
        return;
    }
    let client = ClientBuilder::new()
        .trust(TrustAnchors::platform())
        .alpn(&[Alpn::HTTP_1_1])
        .build()
        .unwrap();
    for host in ["www.rust-lang.org", "github.com"] {
        let sock = std::net::TcpStream::connect((host, 443)).unwrap();
        let mut c = TcpClient::new(sock, client.connect(host).unwrap());
        c.handshake().unwrap_or_else(|e| panic!("{host}: {e}"));
    }
    let sock = std::net::TcpStream::connect(("www.rust-lang.org", 443)).unwrap();
    let mut c = TcpClient::new(sock, client.connect("example.com").unwrap());
    assert!(
        c.handshake().is_err(),
        "the platform verifier refuses a wrong name"
    );
}
