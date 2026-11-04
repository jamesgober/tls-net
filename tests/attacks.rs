//! Attack tests: each must fail to get through (PLAN section 8).

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use common::{RawHello, data, refuse};
use tls_net::{ClientBuilder, KeySource, Policy, TlsError, TlsServer, TrustAnchors, UnknownName};

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
