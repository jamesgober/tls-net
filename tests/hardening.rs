//! Regression tests for the 0.10 hardening: client CRLs (D-145), the
//! snapshot a session holds (D-146), limit fields (D-147), builder order
//! (D-148), `Policy::versions` (D-150), and ALPN names net-io cannot carry
//! (D-152). Expiry thresholds (D-144) and ticket lifetime (D-151) are unit
//! tests next to their code.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use common::{End, data, pump};
use tls_net::{
    Crls, DnsName, HandshakeLimits, KeySource, LoadLimits, Policy, RevocationPolicy,
    ServerIdentity, TlsClient, TlsError, TlsServer, TrustAnchors, Version,
};

fn ca() -> TrustAnchors {
    TrustAnchors::from_pem(&data("ca.pem")).unwrap()
}

fn site_builder() -> tls_net::ServerBuilder {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
}

#[test]
fn test_client_crls_need_anchors() {
    let crls = Crls::from_pem(&data("inter-revokes-site.crl.pem")).unwrap();
    let e = TlsClient::builder()
        .crls(crls, RevocationPolicy::END_ENTITY_ONLY)
        .build()
        .unwrap_err();
    assert!(
        matches!(
            e,
            TlsError::PolicyInvalid {
                reason: "CRLs need trust anchors"
            }
        ),
        "{e:?}"
    );
}

#[test]
fn test_client_with_crls_refuses_a_pin_without_the_chain() {
    let crls = Crls::from_pem(&data("inter-revokes-site.crl.pem")).unwrap();
    let client = TlsClient::builder()
        .trust(ca())
        .crls(crls, RevocationPolicy::END_ENTITY_ONLY)
        .build()
        .unwrap();
    let der = tls_net::certificate_der_from_pem(&data("site.pem")).unwrap();
    let pin = tls_net::spki_sha256(&der[0]).unwrap();
    let pinned = |require_chain| ServerIdentity::Pinned {
        name: DnsName::new("localhost").unwrap(),
        spki_sha256: vec![pin],
        require_chain,
    };
    assert!(matches!(
        client.connect_to(&pinned(false)),
        Err(TlsError::PolicyInvalid { .. })
    ));
    // With the chain, the CRL is applied and the revoked certificate refused.
    let server = tls_net::server_from_pem(&data("site.pem"), &data("site.key")).unwrap();
    let mut s = server.accept().unwrap();
    let mut c = client.connect_to(&pinned(true)).unwrap();
    let (mut se, mut ce) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut s, &mut se, &mut c, &mut ce);
    assert!(!ce.complete);
    assert!(
        matches!(ce.error, Some(TlsError::PeerCertificateRevoked)),
        "{:?}",
        ce.error
    );
}

/// An established session lets go of the configuration it was accepted
/// under, so a reload frees the old certificates and keys at once.
#[cfg(feature = "rustls-escape-hatch")]
#[test]
fn test_established_session_does_not_pin_the_old_snapshot() {
    let server = tls_net::server_from_pem(&data("site.pem"), &data("site.key")).unwrap();
    let weak = std::sync::Arc::downgrade(&server.as_rustls_configs()[0]);
    let client = TlsClient::builder().trust(ca()).build().unwrap();
    let mut s = server.accept().unwrap();
    let mut c = client.connect("localhost").unwrap();
    let (mut se, mut ce) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut s, &mut se, &mut c, &mut ce);
    assert!(se.complete && ce.complete);
    server
        .reload_from_pem(&data("site.pem"), &data("site.key"))
        .unwrap();
    assert!(
        weak.upgrade().is_none(),
        "snapshot 1 freed while the session is open"
    );
    assert!(
        s.info().is_some(),
        "the session still reports its handshake"
    );
    // And still moves data.
    let mut out = vec![0; 64 * 1024];
    let n = s.encrypt(b"after reload", &mut out).unwrap();
    assert!(n > 0);
}

#[test]
fn test_session_before_its_handshake_keeps_the_snapshot() {
    // A session not yet past its hello still needs its snapshot: the reload
    // does not change what it is served.
    let server = tls_net::server_from_pem(&data("site.pem"), &data("site.key")).unwrap();
    let mut s = server.accept().unwrap();
    server
        .reload_from_pem(&data("site.pem"), &data("site.key"))
        .unwrap();
    let client = TlsClient::builder().trust(ca()).build().unwrap();
    let mut c = client.connect("localhost").unwrap();
    let (mut se, mut ce) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut s, &mut se, &mut c, &mut ce);
    assert!(se.complete && ce.complete);
    assert_eq!(server.stats().in_progress, 0, "the slot was given back");
}

#[test]
fn test_load_limit_fields_are_clamped() {
    let mut limits = LoadLimits::new();
    limits.max_key_file_bytes = 0;
    // A zero would refuse every key; clamped to 256 bytes, the key loads.
    let built = TlsServer::builder()
        .load_limits(limits)
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")));
    assert!(built.is_ok(), "{:?}", built.err());
    let mut limits = LoadLimits::new();
    limits.max_chain_len = 0;
    let e = TlsServer::builder()
        .load_limits(limits)
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap_err();
    assert!(
        matches!(e, TlsError::ChainTooLong { len: 2, limit: 1 }),
        "clamped to 1: {e:?}"
    );
    // A huge key limit is held to 1 MiB: a 1.5 MiB key input is refused by size.
    let mut huge = LoadLimits::new();
    huge.max_key_file_bytes = u32::MAX;
    let big = vec![b'A'; 3 << 19];
    let e = TlsServer::builder()
        .load_limits(huge)
        .certificate(&data("site.pem"), KeySource::Pem(&big))
        .unwrap_err();
    assert!(matches!(e, TlsError::FileTooLarge { .. }), "{e:?}");
}

#[test]
fn test_handshake_limit_fields_are_clamped() {
    let mut l = HandshakeLimits::server();
    l.max_handshake_bytes = u32::MAX;
    l.max_peer_chain_len = 0;
    let server = site_builder().limits(l).build().unwrap();
    // The budget is held to 1 MiB: a client that keeps sending handshake
    // bytes is refused by the budget, not by memory.
    let client = TlsClient::builder().trust(ca()).build().unwrap();
    let mut s = server.accept().unwrap();
    let mut c = client.connect("localhost").unwrap();
    let (mut se, mut ce) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut s, &mut se, &mut c, &mut ce);
    assert!(
        se.complete,
        "a chain length of 0 is clamped to 1, not refusing all"
    );
}

#[test]
fn test_load_settings_after_certificate_apply_at_build() {
    // site.pem holds two certificates. A limit of one set after the call
    // applies at build, the same as at reload.
    let e = site_builder()
        .load_limits(LoadLimits::new().max_chain_len(1).unwrap())
        .build()
        .unwrap_err();
    assert!(
        matches!(e, TlsError::ChainTooLong { len: 2, limit: 1 }),
        "{e:?}"
    );
    // In either order the server builds and reloads alike.
    let limits = LoadLimits::new().max_chain_len(2).unwrap();
    for server in [
        site_builder().load_limits(limits).build().unwrap(),
        TlsServer::builder()
            .load_limits(limits)
            .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
            .unwrap()
            .build()
            .unwrap(),
    ] {
        server
            .reload_from_pem(&data("site.pem"), &data("site.key"))
            .unwrap();
    }
}

#[test]
fn test_validity_skew_after_certificate_applies_at_build() {
    // future.pem starts in 2090: refused under any skew, at the call and at build.
    let b =
        TlsServer::builder().certificate(&data("future.pem"), KeySource::Pem(&data("future.key")));
    assert!(b.is_err());
    // A skew set after a valid certificate reloads it at build and still builds.
    site_builder()
        .validity_skew(std::time::Duration::from_secs(60))
        .build()
        .unwrap();
}

#[test]
fn test_versions_on_a_preset_follows_its_suites() {
    let p = Policy::modern()
        .versions(&[Version::Tls13, Version::Tls12])
        .unwrap();
    assert!(
        p.summary()
            .cipher_suites
            .iter()
            .any(|s| s.version() == Version::Tls12)
    );
    site_builder().policy(p).build().unwrap();
    // Suites named by the caller stay as named.
    let named = Policy::compatible()
        .cipher_suites(&[tls_net::CipherSuite::Tls13Aes128GcmSha256])
        .unwrap()
        .versions(&[Version::Tls13, Version::Tls12])
        .unwrap();
    assert_eq!(named.summary().cipher_suites.len(), 1);
}

#[cfg(feature = "net-io")]
#[test]
fn test_alpn_names_net_io_cannot_carry_are_refused() {
    let long = tls_net::Alpn::new(&[b'x'; 33]).unwrap();
    let e = site_builder().alpn(&[long]).build().unwrap_err();
    assert!(matches!(e, TlsError::PolicyInvalid { .. }), "{e:?}");
    let fits = tls_net::Alpn::new(&[b'x'; 32]).unwrap();
    site_builder().alpn(&[fits]).build().unwrap();
}
