//! Attack tests: each must fail to get through (PLAN section 8).

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{End, RawHello, data, pump, refuse};
use tls_net::{
    CertificateProblem, ClientBuilder, Crls, Event, HandshakeKind, KeySource, Policy,
    RevocationPolicy, TicketMode, TlsClient, TlsError, TlsServer, TrustAnchors, UnknownName,
};

fn server() -> TlsServer {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap()
}

/// The alert description in a plaintext alert record, if `sent` is one.
fn alert(sent: &[u8]) -> Option<u8> {
    (sent.len() == 7 && sent[0] == 21 && sent[5] == 2).then(|| sent[6])
}

const ECDHE_SUITES: [u16; 4] = [0xc02b, 0xc02f, 0xc02c, 0xc030];

#[test]
fn test_t1_tls11_only_client_gets_protocol_version() {
    let mut hello = RawHello::tls12(&ECDHE_SUITES);
    hello.legacy_version = 0x0302;
    let (sent, err) = refuse(&server(), &hello.record());
    assert_eq!(err, Some(TlsError::NoCommonVersion));
    assert_eq!(alert(&sent), Some(70), "protocol_version alert");
}

#[test]
fn test_t3_cbc_only_client_gets_handshake_failure() {
    // TLS_RSA_WITH_AES_128_CBC_SHA and TLS_RSA_WITH_3DES_EDE_CBC_SHA only.
    let (sent, err) = refuse(&server(), &RawHello::tls12(&[0x002f, 0x000a]).record());
    assert_eq!(err, Some(TlsError::NoCommonCipherSuite));
    assert_eq!(alert(&sent), Some(40), "handshake_failure alert");
}

#[test]
fn test_t3_policy_cannot_name_weak_suites() {
    assert_eq!(tls_net::CipherSuite::from_wire(0x002f), None);
    assert_eq!(tls_net::CipherSuite::from_wire(0x000a), None);
    assert_eq!(tls_net::Version::from_wire(0x0302), None);
    assert!(Policy::compatible().cipher_suites(&[]).is_err());
}

#[test]
fn test_t7_tls12_client_without_ems_refused() {
    let mut hello = RawHello::tls12(&ECDHE_SUITES);
    hello.extensions.retain(|(t, _)| *t != 23);
    let (sent, err) = refuse(&server(), &hello.record());
    assert_eq!(err, Some(TlsError::ExtendedMasterSecretRequired));
    assert_eq!(alert(&sent), Some(40));
}

#[test]
fn test_t5_starttls_injection_refused() {
    let client = ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .build()
        .unwrap();
    for leftover in [b"2".as_slice(), b"250 injected\r\n", &[0u8; 100]] {
        assert_eq!(
            client
                .start_after_plaintext("smtp.example.test", leftover)
                .unwrap_err(),
            TlsError::StartTlsInjection
        );
    }
    assert!(
        client
            .start_after_plaintext("smtp.example.test", b"")
            .is_ok()
    );
}

#[test]
fn test_t9_weak_or_wrong_configuration_refused_by_name() {
    type Check = fn(&TlsError) -> bool;
    let cases: [(&str, &str, Check); 7] = [
        ("rsa1024.pem", "rsa1024.key", |e| {
            matches!(e, TlsError::WeakKey { bits: 1024 })
        }),
        ("sha1.pem", "sha1.key", |e| {
            *e == TlsError::WeakSignatureAlgorithm
        }),
        ("site.pem", "api.key", |e| *e == TlsError::KeyMismatch),
        ("site.reversed.pem", "site.key", |e| {
            matches!(e, TlsError::ChainOrder { position: 0 })
        }),
        ("expired.pem", "expired.key", |e| {
            matches!(e, TlsError::CertificateExpired { .. })
        }),
        ("client-only.pem", "client-only.key", |e| {
            *e == TlsError::WrongPurpose
        }),
        ("p521.pem", "p521.key", |e| {
            *e == TlsError::UnsupportedKeyType
        }),
    ];
    for (chain, key, ok) in cases {
        let e = TlsServer::builder()
            .certificate(&data(chain), KeySource::Pem(&data(key)))
            .unwrap_err();
        assert!(ok(&e), "{chain}: {e}");
    }
    let wrong_name = TlsServer::builder().certificate_for(
        &["other.test"],
        &data("site.pem"),
        KeySource::Pem(&data("site.key")),
    );
    assert!(matches!(wrong_name, Err(TlsError::NameNotCovered { .. })));
}

#[test]
fn test_t13_capacity_refuses_before_any_parse() {
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .limits(
            tls_net::HandshakeLimits::server()
                .max_in_progress(10)
                .unwrap(),
        )
        .build()
        .unwrap();
    let held: Vec<_> = (0..10).map(|_| server.accept().unwrap()).collect();
    for _ in 0..1000 {
        assert_eq!(server.accept().unwrap_err(), TlsError::HandshakeCapacity);
    }
    assert_eq!(server.handshakes_in_progress(), 10);
    drop(held);
    assert_eq!(server.handshakes_in_progress(), 0);
}

#[test]
fn test_t14_malformed_hellos_refused_never_panic() {
    let good = RawHello::tls12(&ECDHE_SUITES).sni(b"localhost").record();
    let server = server();
    // Every truncation: incomplete (no error) or refused, never a panic.
    for n in 0..good.len() {
        let (_, err) = refuse(&server, &good[..n]);
        assert!(err.is_none(), "{n}: {err:?}");
    }
    // Every single-byte corruption: whatever the verdict, no panic.
    for i in 0..good.len() {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut bad = good.clone();
            bad[i] ^= flip;
            let _ = refuse(&server, &bad);
        }
    }
}

#[test]
fn test_t20_control_bytes_in_sni_treated_as_absent() {
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .unknown_name(UnknownName::Refuse)
        .build()
        .unwrap();
    for name in [
        b"local\r\nhost".as_slice(),
        b"a\x00b",
        b"\x1b[31mx",
        b"host name",
    ] {
        let (sent, err) = refuse(&server, &RawHello::tls12(&ECDHE_SUITES).sni(name).record());
        assert_eq!(err, Some(TlsError::UnknownServerName), "{name:?}");
        assert_eq!(alert(&sent), Some(112));
    }
    let e = tls_net::DnsName::new("a\r\n\x1b[0m").unwrap_err();
    assert!(
        !e.to_string().contains('\r') && !e.to_string().contains('\x1b'),
        "{e}"
    );
}

#[test]
fn test_t25_every_unknown_name_gets_identical_alert() {
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .unknown_name(UnknownName::Refuse)
        .build()
        .unwrap();
    let mut first: Option<Vec<u8>> = None;
    for i in 0..1000 {
        let name = format!("probe-{i}.hidden.test");
        let (sent, err) = refuse(
            &server,
            &RawHello::tls12(&ECDHE_SUITES).sni(name.as_bytes()).record(),
        );
        assert_eq!(err, Some(TlsError::UnknownServerName));
        match &first {
            None => first = Some(sent),
            Some(f) => assert_eq!(&sent, f),
        }
    }
    // No SNI at all gets the same bytes.
    let (sent, _) = refuse(&server, &RawHello::tls12(&ECDHE_SUITES).record());
    assert_eq!(Some(sent), first);
}

fn test_ca_client() -> ClientBuilder {
    ClientBuilder::new().trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
}

/// The handshake between a tls-net client and a plain rustls server that
/// serves `chain` (which tls-net's own server would refuse to load);
/// `None` when it completes, else the client's error.
fn against_rustls_server(chain: &str, key: &str, client: &TlsClient) -> Option<TlsError> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    #[cfg(feature = "aws-lc")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(not(feature = "aws-lc"))]
    let provider = rustls::crypto::ring::default_provider();
    let certs = CertificateDer::pem_slice_iter(&data(chain))
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(&data(key)).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let mut session = client.connect("localhost").unwrap();
    let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
    let mut out = vec![0u8; 64 * 1024];
    for _ in 0..16 {
        loop {
            let (consumed, written, complete, idle) = match session.step(&mut to_client, &mut out) {
                Ok(p) => (
                    p.consumed,
                    p.written,
                    matches!(p.event, Event::HandshakeComplete),
                    matches!(p.event, Event::NeedInput),
                ),
                Err(e) => return Some(e),
            };
            to_server.extend_from_slice(&out[..written]);
            to_client.drain(..consumed);
            if complete {
                return None;
            }
            if idle && consumed == 0 && written == 0 {
                break;
            }
        }
        let mut rd = &to_server[..];
        while !rd.is_empty() {
            server.read_tls(&mut rd).unwrap();
        }
        to_server.clear();
        let _ = server.process_new_packets();
        while server.wants_write() {
            server.write_tls(&mut to_client).unwrap();
        }
    }
    panic!("the handshake neither completed nor failed")
}

#[test]
fn test_t6_expired_and_self_signed_server_certificates_refused() {
    let client = test_ca_client().build().unwrap();
    assert_eq!(
        against_rustls_server("site.pem", "site.key", &client),
        None,
        "control"
    );
    assert_eq!(
        against_rustls_server("expired.pem", "expired.key", &client),
        Some(TlsError::PeerCertificateInvalid(
            CertificateProblem::Expired
        ))
    );
    assert_eq!(
        against_rustls_server("selfsigned.pem", "selfsigned.key", &client),
        Some(TlsError::PeerCertificateInvalid(
            CertificateProblem::UnknownIssuer
        ))
    );
}

#[test]
fn test_t6_revoked_server_certificate_refused_by_crl() {
    let server = server();
    let with = |crl: &str| {
        let client = test_ca_client()
            .crls(
                Crls::from_pem(&data(crl)).unwrap(),
                RevocationPolicy::END_ENTITY_ONLY,
            )
            .build()
            .unwrap();
        let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
        let (mut ss, mut cs) = (
            server.accept().unwrap(),
            client.connect("localhost").unwrap(),
        );
        pump(&mut ss, &mut s, &mut cs, &mut c);
        (c.complete, c.error)
    };
    assert_eq!(with("inter-empty.crl.pem"), (true, None), "control");
    assert_eq!(
        with("inter-revokes-site.crl.pem"),
        (false, Some(TlsError::PeerCertificateRevoked))
    );
}

#[test]
fn test_t11_clients_never_resume_with_each_others_tickets() {
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .tickets(
            TicketMode::Ephemeral {
                period: Duration::from_secs(3600),
            },
            2,
        )
        .build()
        .unwrap();
    let kind = |client: &TlsClient| {
        let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
        let (mut ss, mut cs) = (
            server.accept().unwrap(),
            client.connect("localhost").unwrap(),
        );
        pump(&mut ss, &mut s, &mut cs, &mut c);
        assert!(c.complete, "{:?}", c.error);
        ss.info().unwrap().kind
    };
    let (a, b) = (
        test_ca_client().resumption(64).build().unwrap(),
        test_ca_client().resumption(64).build().unwrap(),
    );
    assert_eq!(kind(&a), HandshakeKind::Full);
    assert_eq!(
        kind(&a),
        HandshakeKind::Resumed,
        "a resumes with its own ticket"
    );
    assert_eq!(kind(&b), HandshakeKind::Full, "b holds none of a's tickets");
    assert_eq!(kind(&b), HandshakeKind::Resumed);
}

#[test]
fn test_t18_reload_with_expired_certificate_refused_old_one_kept() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
    // Checkouts leave key files group-readable; allow that so the refusal
    // below is the expiry check's, not the permission check's.
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .allow_group_readable_key(true)
        .build()
        .unwrap();
    let before = server.stats().snapshot_version;
    let refused =
        server.reload_from_files(format!("{dir}expired.pem"), format!("{dir}expired.key"));
    let cause = match &refused {
        Err(TlsError::ReloadRefused { source }) => source.as_ref(),
        Err(e) => e,
        Ok(()) => panic!("an expired certificate was published"),
    };
    assert!(
        matches!(cause, TlsError::CertificateExpired { .. }),
        "{refused:?}"
    );
    assert_eq!(server.stats().snapshot_version, before);
    let client = test_ca_client().build().unwrap();
    let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
    let (mut ss, mut cs) = (
        server.accept().unwrap(),
        client.connect("localhost").unwrap(),
    );
    pump(&mut ss, &mut s, &mut cs, &mut c);
    assert!(
        c.complete,
        "the old certificate is still served: {:?}",
        c.error
    );
}
