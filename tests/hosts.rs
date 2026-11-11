//! Host policies against a client that names another host, or none (T-31,
//! D-143). A host policy applies its rules by SNI; the layer above makes it
//! hold by checking each request's `Host` with `HostScope::permits`.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use common::{End, data, pump};
use tls_net::{ClientAuth, HostPolicy, KeySource, TlsClient, TlsServer, TrustAnchors};

fn ca() -> TrustAnchors {
    TrustAnchors::from_pem(&data("ca.pem")).unwrap()
}

/// The configuration of docs/API.md's host policy example: one certificate
/// for `*.example.test` serves every host, and the admin host requires a
/// client certificate.
fn server() -> TlsServer {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .host(
            &["admin.example.test"],
            HostPolicy::new().client_auth(ClientAuth::required(ca())),
        )
        .unwrap()
        .build()
        .unwrap()
}

fn client(sni: bool, certificate: bool) -> TlsClient {
    let mut b = TlsClient::builder().trust(ca()).send_sni(sni);
    if certificate {
        b = b
            .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
            .unwrap();
    }
    b.build().unwrap()
}

/// Runs a handshake; returns the server's SNI, whether it completed, and
/// whether a client certificate was verified.
fn handshake(server: &TlsServer, client: &TlsClient, name: &str) -> (Option<String>, bool, bool) {
    let mut s = server.accept().unwrap();
    let mut c = client.connect(name).unwrap();
    let (mut se, mut ce) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut s, &mut se, &mut c, &mut ce);
    match s.info() {
        Some(info) => (
            info.server_name.map(str::to_owned),
            se.complete,
            info.peer_verified,
        ),
        None => (None, false, false),
    }
}

#[test]
fn test_admin_sni_needs_a_client_certificate() {
    let srv = server();
    let (_, done, _) = handshake(&srv, &client(true, false), "admin.example.test");
    assert!(!done, "the host policy applies to its own SNI");
    let (sni, done, verified) = handshake(&srv, &client(true, true), "admin.example.test");
    assert!(done && verified);
    let scope = srv.host_scope(sni.as_deref());
    assert!(scope.permits("admin.example.test"));
    assert!(
        scope.permits("ADMIN.example.test.:443"),
        "normalised as SNI is"
    );
}

#[test]
fn test_no_sni_session_cannot_serve_the_admin_host() {
    let srv = server();
    // The client verifies the server as admin.example.test (the wildcard
    // covers it) but sends no SNI, so the default group's rules apply.
    let (sni, done, verified) = handshake(&srv, &client(false, false), "admin.example.test");
    assert!(done, "the handshake itself completes without a certificate");
    assert_eq!(sni, None);
    assert!(!verified);
    let scope = srv.host_scope(sni.as_deref());
    assert!(
        !scope.permits("admin.example.test"),
        "Host: admin gets a 421"
    );
    assert!(scope.permits("www.example.test"));
}

#[test]
fn test_sibling_sni_session_cannot_serve_the_admin_host() {
    let srv = server();
    let (sni, done, verified) = handshake(&srv, &client(true, false), "www.example.test");
    assert!(done && !verified);
    assert_eq!(sni.as_deref(), Some("www.example.test"));
    let scope = srv.host_scope(sni.as_deref());
    assert!(!scope.permits("admin.example.test"));
    assert!(!scope.permits("Admin.Example.Test:8443"));
    assert!(scope.permits("www.example.test"));
    assert!(
        scope.permits("other.example.test"),
        "same group: coalescing works"
    );
}

#[test]
fn test_admin_session_does_not_serve_other_groups() {
    let srv = server();
    let scope = srv.host_scope(Some("admin.example.test"));
    assert!(
        !scope.permits("www.example.test"),
        "421, the client retries elsewhere"
    );
    assert!(!scope.permits("127.0.0.1"), "an IP host resolves as no SNI");
}

#[test]
fn test_host_values_parsed_strictly() {
    let srv = server();
    let scope = srv.host_scope(None);
    for ok in [
        "www.example.test",
        "www.example.test:443",
        "127.0.0.1:80",
        "[::1]:443",
        "[::1]",
    ] {
        assert!(scope.permits(ok), "{ok}");
    }
    for bad in [
        "",
        "a b",
        "www.example.test:44x",
        "www.example.test:443:1",
        "[::1",
        "[::1]x",
        "[nothost]:1",
        "www.example.test\r\nX: y",
        "admin.example.test",
    ] {
        assert!(!scope.permits(bad), "{bad:?}");
    }
}

#[test]
fn test_unknown_names_refused_scope_permits_nothing_without_a_name() {
    let srv = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .unknown_name(tls_net::UnknownName::Refuse)
        .build()
        .unwrap();
    assert!(!srv.host_scope(None).permits("localhost"));
    assert!(!srv.host_scope(Some("nothing.test")).permits("nothing.test"));
    assert!(!srv.host_scope(Some("localhost")).permits("nothing.test"));
    assert!(srv.host_scope(Some("localhost")).permits("example.test"));
}

#[test]
fn test_scope_follows_a_reload_that_adds_a_policy() {
    let srv = tls_net::server_from_pem(&data("site.pem"), &data("site.key")).unwrap();
    assert!(
        srv.host_scope(Some("www.example.test"))
            .permits("admin.example.test")
    );
    let next = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .host(
            &["admin.example.test"],
            HostPolicy::new().client_auth(ClientAuth::required(ca())),
        )
        .unwrap();
    srv.reload_handle().publish(next).unwrap();
    assert!(
        !srv.host_scope(Some("www.example.test"))
            .permits("admin.example.test")
    );
}
