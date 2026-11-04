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
