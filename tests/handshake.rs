//! Server against client over an in-memory pipe.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use common::{End, data, pump, send};
use tls_net::{
    Alpn, CipherSuite, ClientBuilder, HandshakeKind, HandshakeLimits, KeySource, Policy,
    SessionState, TlsClient, TlsError, TlsServer, TrustAnchors, UnknownName, Version,
};

fn client(policy: Policy, alpn: &[Alpn]) -> TlsClient {
    ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .policy(policy)
        .alpn(alpn)
        .build()
        .unwrap()
}

fn site() -> tls_net::ServerBuilder {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
}

struct Pair {
    server: tls_net::ServerSession,
    client: tls_net::ClientSession,
    s: End,
    c: End,
}

fn connect(server: &TlsServer, client: &TlsClient, name: &str, chunk: usize) -> Pair {
    let mut p = Pair {
        server: server.accept().unwrap(),
        client: client.connect(name).unwrap(),
        s: End::new(chunk),
        c: End::new(chunk),
    };
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    p
}

#[test]
fn test_handshake_tls13_default_policies_complete() {
    let server = site().alpn(&[Alpn::H2, Alpn::HTTP_1_1]).build().unwrap();
    let client = client(Policy::client_default(), &[Alpn::HTTP_1_1, Alpn::H2]);
    let p = connect(&server, &client, "localhost", usize::MAX);
    assert!(
        p.s.complete && p.c.complete,
        "server {:?} client {:?}",
        p.s.error,
        p.c.error
    );
    let si = p.server.info().unwrap();
    let ci = p.client.info().unwrap();
    assert_eq!(si.version, Version::Tls13);
    assert_eq!(si.cipher_suite, CipherSuite::Tls13Aes256GcmSha384);
    // Server preference wins for ALPN.
    assert_eq!(si.alpn, Some(b"h2".as_slice()));
    assert_eq!(ci.alpn, Some(b"h2".as_slice()));
    assert_eq!(si.server_name, Some("localhost"));
    assert_eq!(ci.server_name, Some("localhost"));
    assert_eq!(si.kind, HandshakeKind::Full);
    #[cfg(feature = "aws-lc")]
    assert_eq!(si.group, Some(tls_net::Group::X25519MlKem768));
    assert_eq!(server.handshakes_in_progress(), 0);
}

#[test]
fn test_handshake_byte_at_a_time_same_result() {
    let server = site().build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let mut p = connect(&server, &client, "example.test", 1);
    assert!(
        p.s.complete && p.c.complete,
        "server {:?} client {:?}",
        p.s.error,
        p.c.error
    );
    // Application data both ways, delivered one byte at a time.
    let msg: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    send(&mut p.client, &msg, 7_000, &mut p.s.inbox);
    send(&mut p.server, b"pong", 4, &mut p.c.inbox);
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    assert_eq!(p.s.received, msg);
    assert_eq!(p.c.received, b"pong");
}

#[test]
fn test_bulk_data_and_clean_close() {
    let server = site().build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let mut p = connect(&server, &client, "localhost", usize::MAX);
    let msg = vec![0x5a; 1 << 20];
    send(&mut p.server, &msg, 16_384, &mut p.c.inbox);
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    assert_eq!(p.c.received.len(), msg.len());
    let mut out = vec![0; 64 * 1024];
    let n = p.server.close(&mut out).unwrap();
    assert!(n > 0);
    assert_eq!(p.server.state(), SessionState::Closing);
    assert_eq!(p.server.close(&mut out).unwrap(), 0);
    assert_eq!(
        p.server.encrypt(b"x", &mut out).unwrap_err(),
        TlsError::WrongState
    );
    p.c.inbox.extend_from_slice(&out[..n]);
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    assert!(p.c.peer_closed);
    assert_eq!(p.client.state(), SessionState::HalfClosed);
    assert_eq!(p.client.on_eof(), tls_net::CloseKind::Clean);
}

#[test]
fn test_unclean_eof_is_reported_t17() {
    let server = site().build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let mut p = connect(&server, &client, "localhost", usize::MAX);
    assert_eq!(p.client.on_eof(), tls_net::CloseKind::Unclean);
    assert_eq!(p.client.state(), SessionState::Failed);
    assert_eq!(p.client.error_code(), Some(43));
}

#[test]
fn test_tls12_negotiated_when_only_tls12_allowed() {
    let server = site().build().unwrap();
    let client = client(
        Policy::client_default()
            .versions(&[Version::Tls12])
            .unwrap(),
        &[],
    );
    let p = connect(&server, &client, "localhost", usize::MAX);
    assert!(
        p.s.complete && p.c.complete,
        "{:?} {:?}",
        p.s.error,
        p.c.error
    );
    let i = p.server.info().unwrap();
    assert_eq!(i.version, Version::Tls12);
    assert_eq!(i.cipher_suite, CipherSuite::EcdheEcdsaAes256GcmSha384);
}

#[test]
fn test_modern_server_refuses_tls12_client_t2() {
    let server = site().policy(Policy::modern()).build().unwrap();
    let client = client(
        Policy::client_default()
            .versions(&[Version::Tls12])
            .unwrap(),
        &[],
    );
    let p = connect(&server, &client, "localhost", usize::MAX);
    assert!(!p.s.complete);
    assert_eq!(p.s.error, Some(TlsError::NoCommonVersion));
    assert!(
        matches!(p.c.error, Some(TlsError::AlertReceived { .. })),
        "{:?}",
        p.c.error
    );
}

#[test]
fn test_alpn_no_overlap_refused() {
    let server = site().alpn(&[Alpn::new(b"smtp").unwrap()]).build().unwrap();
    let client = client(Policy::client_default(), &[Alpn::HTTP_1_1]);
    let p = connect(&server, &client, "localhost", usize::MAX);
    assert_eq!(p.s.error, Some(TlsError::NoApplicationProtocol));
    assert_eq!(p.c.error, Some(TlsError::AlertReceived { alert: 120 }));
}

#[test]
fn test_sni_selects_certificate_for_name() {
    let server = site()
        .certificate_for(
            &["api.other.test"],
            &data("api.pem"),
            KeySource::Pem(&data("api.key")),
        )
        .unwrap()
        .build()
        .unwrap();
    let client = client(Policy::client_default(), &[]);
    // The client verifies the name, so completing proves the right certificate.
    for name in ["api.other.test", "localhost", "deep.example.test"] {
        let p = connect(&server, &client, name, usize::MAX);
        assert!(p.c.complete, "{name}: {:?}", p.c.error);
    }
    // A name only the default covers, asked for by SNI that is unknown: default served,
    // and the client refuses the certificate because it does not cover the name.
    let p = connect(&server, &client, "unknown.test", usize::MAX);
    assert!(
        matches!(
            p.c.error,
            Some(TlsError::PeerCertificateInvalid(
                tls_net::CertificateProblem::NameMismatch
            ))
        ),
        "{:?}",
        p.c.error
    );
}

#[test]
fn test_unknown_name_refused_with_unrecognized_name_t25() {
    let server = site().unknown_name(UnknownName::Refuse).build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let p = connect(&server, &client, "unknown.test", usize::MAX);
    assert_eq!(p.s.error, Some(TlsError::UnknownServerName));
    assert_eq!(p.c.error, Some(TlsError::AlertReceived { alert: 112 }));
    let ok = connect(&server, &client, "localhost", usize::MAX);
    assert!(ok.c.complete);
}

#[test]
fn test_capacity_gate_refuses_then_releases() {
    let server = site()
        .limits(HandshakeLimits::server().max_in_progress(1).unwrap())
        .build()
        .unwrap();
    let first = server.accept().unwrap();
    assert_eq!(server.accept().unwrap_err(), TlsError::HandshakeCapacity);
    drop(first);
    let client = client(Policy::client_default(), &[]);
    let p = connect(&server, &client, "localhost", usize::MAX);
    assert!(p.s.complete);
    // A completed handshake released its slot.
    assert!(server.accept().is_ok());
    let zero = site()
        .limits(HandshakeLimits::server().max_in_progress(0).unwrap())
        .build()
        .unwrap();
    assert_eq!(zero.accept().unwrap_err(), TlsError::HandshakeCapacity);
}

#[test]
fn test_server_with_untrusted_ca_refused_t6() {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let server = site().build().unwrap();
    // Trust only an unrelated leaf: the site chain does not lead to it.
    let leaf = CertificateDer::pem_slice_iter(&data("api.pem"))
        .next()
        .unwrap()
        .unwrap();
    let other = ClientBuilder::new()
        .trust(TrustAnchors::from_der(&[leaf.as_ref()]).unwrap())
        .build()
        .unwrap();
    let p = connect(&server, &other, "localhost", usize::MAX);
    assert_eq!(
        p.c.error,
        Some(TlsError::PeerCertificateInvalid(
            tls_net::CertificateProblem::UnknownIssuer
        ))
    );
    assert!(
        matches!(p.s.error, Some(TlsError::AlertReceived { .. })),
        "{:?}",
        p.s.error
    );
}

#[test]
fn test_wrong_name_refused_by_client_t6() {
    let server = site().build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let p = connect(&server, &client, "other.test", usize::MAX);
    assert_eq!(
        p.c.error,
        Some(TlsError::PeerCertificateInvalid(
            tls_net::CertificateProblem::NameMismatch
        ))
    );
}

#[test]
fn test_ip_literal_identity_no_sni() {
    let server = site().build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let p = connect(&server, &client, "127.0.0.1", usize::MAX);
    assert!(p.c.complete, "{:?}", p.c.error);
    assert_eq!(p.server.info().unwrap().server_name, None);
}

#[test]
fn test_rsa_certificate_handshake() {
    let server = TlsServer::builder()
        .certificate(&data("site-rsa.pem"), KeySource::Pem(&data("site-rsa.key")))
        .unwrap()
        .build()
        .unwrap();
    let client = client(Policy::client_default(), &[]);
    let p = connect(&server, &client, "localhost", usize::MAX);
    assert!(p.c.complete, "{:?}", p.c.error);
    let tls12 = client_tls12();
    let p = connect(&server, &tls12, "localhost", usize::MAX);
    assert_eq!(
        p.server.info().unwrap().cipher_suite,
        CipherSuite::EcdheRsaAes256GcmSha384
    );
}

fn client_tls12() -> TlsClient {
    client(
        Policy::client_default()
            .versions(&[Version::Tls12])
            .unwrap(),
        &[],
    )
}

#[test]
fn test_ecdsa_and_rsa_twins_for_one_name_fr19() {
    let server = site()
        .certificate(&data("site-rsa.pem"), KeySource::Pem(&data("site-rsa.key")))
        .unwrap()
        .build()
        .unwrap();
    // A TLS 1.2 client restricted to RSA suites can only use the RSA twin.
    let rsa_only = client(
        Policy::client_default()
            .versions(&[Version::Tls12])
            .unwrap()
            .cipher_suites(&[CipherSuite::EcdheRsaAes128GcmSha256])
            .unwrap(),
        &[],
    );
    let p = connect(&server, &rsa_only, "localhost", usize::MAX);
    assert!(p.c.complete, "{:?} {:?}", p.c.error, p.s.error);
    let any = client(Policy::client_default(), &[]);
    let p = connect(&server, &any, "localhost", usize::MAX);
    assert!(p.c.complete);
}

#[test]
fn test_duplicate_name_refused() {
    let r = site()
        .certificate_for(
            &["localhost"],
            &data("site.pem"),
            KeySource::Pem(&data("site.key")),
        )
        .unwrap()
        .build();
    assert_eq!(
        r.unwrap_err(),
        TlsError::DuplicateName {
            name: "localhost".into()
        }
    );
}

#[test]
fn test_output_too_small_is_output_full() {
    let server = site().build().unwrap();
    let mut s = server.accept().unwrap();
    let mut input = [0u8; 10];
    let mut out = vec![0u8; tls_net::OUTGOING_MIN - 1];
    let p = s.step(&mut input, &mut out).unwrap();
    assert_eq!(
        (p.consumed, p.written, p.event),
        (0, 0, tls_net::Event::OutputFull)
    );
}

#[test]
fn test_not_tls_refused() {
    let server = site().build().unwrap();
    let mut s = server.accept().unwrap();
    let mut input = *b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut out = vec![0u8; 64 * 1024];
    assert_eq!(s.step(&mut input, &mut out).unwrap_err(), TlsError::NotTls);
    assert_eq!(s.state(), SessionState::Failed);
    assert_eq!(
        s.step(&mut input, &mut out).unwrap_err(),
        TlsError::SessionFailed
    );
    assert_eq!(server.handshakes_in_progress(), 0);
}

#[test]
fn test_encrypt_before_handshake_wrong_state() {
    let client = client(Policy::client_default(), &[]);
    let mut c = client.connect("localhost").unwrap();
    let mut out = vec![0u8; 64 * 1024];
    assert_eq!(c.encrypt(b"x", &mut out).unwrap_err(), TlsError::WrongState);
    assert_eq!(c.close(&mut out).unwrap_err(), TlsError::WrongState);
    assert!(c.info().is_none());
}

#[test]
fn test_encrypt_output_too_small_writes_nothing() {
    let server = site().build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let mut p = connect(&server, &client, "localhost", usize::MAX);
    let mut out = vec![0u8; 100];
    let e = p.client.encrypt(&[1u8; 200], &mut out).unwrap_err();
    assert_eq!(e.required(), Some(222));
    let mut out = vec![0u8; 222];
    assert_eq!(p.client.encrypt(&[1u8; 200], &mut out).unwrap(), 222);
    assert_eq!(p.client.encrypt(&[], &mut out).unwrap(), 0);
}

#[test]
fn test_handshake_budget_exceeded() {
    // The server's flight carries a 12 KiB certificate; the client allows 8 KiB.
    let server = TlsServer::builder()
        .certificate(&data("big.pem"), KeySource::Pem(&data("big.key")))
        .unwrap()
        .build()
        .unwrap();
    let small = ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .limits(HandshakeLimits::client().max_handshake_bytes(8192).unwrap())
        .build()
        .unwrap();
    let p = connect(&server, &small, "localhost", usize::MAX);
    assert_eq!(p.c.error, Some(TlsError::HandshakeTooLarge));
    let roomy = client(Policy::client_default(), &[]);
    let p = connect(&server, &roomy, "host-400.big.test", 1);
    assert!(p.c.complete, "{:?}", p.c.error);
}

#[test]
fn test_peer_chain_budget_client_side_t22() {
    let server = site().build().unwrap();
    let strict = ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .limits(HandshakeLimits::client().max_peer_chain_len(1).unwrap())
        .build()
        .unwrap();
    let p = connect(&server, &strict, "localhost", usize::MAX);
    assert_eq!(p.c.error, Some(TlsError::PeerChainTooLarge));
}

#[test]
fn test_resumption_second_connection_resumed() {
    let server = site().build().unwrap();
    let c1 = client(Policy::client_default(), &[]);
    let mut first = connect(&server, &c1, "localhost", usize::MAX);
    // TLS 1.3 tickets arrive after the handshake; let the client read them.
    pump(
        &mut first.server,
        &mut first.s,
        &mut first.client,
        &mut first.c,
    );
    let second = connect(&server, &c1, "localhost", usize::MAX);
    assert_eq!(second.server.info().unwrap().kind, HandshakeKind::Resumed);
    // A separate client never shares tickets (FR-29).
    let other = client(Policy::client_default(), &[]);
    let third = connect(&server, &other, "localhost", usize::MAX);
    assert_eq!(third.server.info().unwrap().kind, HandshakeKind::Full);
}

#[test]
fn test_data_in_the_finished_flight_comes_after_handshake_complete() {
    // curl and other clients send their first request in the same flight as
    // their Finished. HandshakeComplete must come first (net-io refuses
    // plaintext before it), then the data, nothing lost.
    let server = site().build().unwrap();
    let client = client(Policy::client_default(), &[]);
    let (mut srv, mut cli) = (
        server.accept().unwrap(),
        client.connect("localhost").unwrap(),
    );
    let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
    let mut to_s = Vec::new();
    c.run(&mut cli, &mut to_s);
    s.inbox.extend(to_s);
    let mut to_c = Vec::new();
    s.run(&mut srv, &mut to_c);
    c.inbox.extend(to_c);
    let mut to_s = Vec::new();
    c.run(&mut cli, &mut to_s);
    assert!(c.complete && !s.complete);
    send(&mut cli, b"GET / HTTP/1.1\r\n\r\n", 100, &mut to_s);
    let mut input = to_s;
    let mut out = vec![0u8; 64 * 1024];
    let mut events = Vec::new();
    let mut data = Vec::new();
    for _ in 0..8 {
        let p = srv.step(&mut input, &mut out).unwrap();
        let consumed = p.consumed;
        match p.event {
            tls_net::Event::HandshakeComplete => events.push("complete"),
            tls_net::Event::Data(d) => {
                events.push("data");
                data.extend_from_slice(d);
            }
            tls_net::Event::NeedInput => break,
            _ => events.push("other"),
        }
        input.drain(..consumed);
    }
    let first_data = events.iter().position(|e| *e == "data").unwrap();
    let complete = events.iter().position(|e| *e == "complete").unwrap();
    assert!(complete < first_data, "{events:?}");
    assert_eq!(data, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(srv.state(), SessionState::Established);
    // The server can answer at once.
    assert!(srv.encrypt(b"HTTP/1.1 200 OK\r\n\r\n", &mut out).is_ok());
}
