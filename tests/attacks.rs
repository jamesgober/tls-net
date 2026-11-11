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
    let client = TlsClient::builder()
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
        .limits(tls_net::HandshakeLimits::server().max_in_progress(10))
        .build()
        .unwrap();
    let held: Vec<_> = (0..10).map(|_| server.accept().unwrap()).collect();
    for _ in 0..1000 {
        assert_eq!(server.accept().unwrap_err(), TlsError::HandshakeCapacity);
    }
    assert_eq!(server.stats().in_progress, 10);
    drop(held);
    assert_eq!(server.stats().in_progress, 0);
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
    TlsClient::builder().trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
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
    let before = server.stats().config_version;
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
    assert_eq!(server.stats().config_version, before);
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

/// Steps `session` over `input` until it fails or waits; returns the bytes it
/// wrote and whether it failed.
/// One `step`: consumed, written, and whether the session waits for input.
type Step<'a> = dyn FnMut(&mut Vec<u8>, &mut [u8]) -> Result<(usize, usize, bool), TlsError> + 'a;

fn drive_junk(step: &mut Step<'_>, input: &[u8]) -> (Vec<u8>, bool) {
    let (mut input, mut out, mut sent) = (input.to_vec(), vec![0u8; 64 * 1024], Vec::new());
    for _ in 0..64 {
        match step(&mut input, &mut out) {
            Ok((consumed, written, waiting)) => {
                sent.extend_from_slice(&out[..written]);
                input.drain(..consumed);
                if waiting && consumed == 0 && written == 0 {
                    return (sent, false);
                }
            }
            Err(_) => return (sent, true),
        }
    }
    panic!("the session neither failed nor waited")
}

/// Plaintext fatal alerts in `sent` (records of type 21, level 2).
fn fatal_alerts(sent: &[u8]) -> usize {
    let (mut i, mut n) = (0, 0);
    while i + 5 <= sent.len() {
        let len = usize::from(u16::from_be_bytes([sent[i + 3], sent[i + 4]]));
        if sent[i] == 21 && sent.get(i + 5) == Some(&2) {
            n += 1;
        }
        i += 5 + len;
    }
    n
}

#[test]
fn test_t14_junk_from_a_server_fails_the_client_with_one_alert_d111() {
    // Found by the session_step_client fuzz target: one byte 0xd3 as the
    // server's first flight made rustls queue a second fatal alert.
    let client = test_ca_client().build().unwrap();
    for junk in [
        &[0xd3][..],
        &[0x00],
        &[0x17, 0x03, 0x03, 0x00, 0x01, 0x00],
        &[0x16, 0x02, 0x00, 0x00, 0x01, 0x00],
    ] {
        let mut session = client.connect("localhost").unwrap();
        let mut out = vec![0u8; 64 * 1024];
        assert!(
            session.step(&mut [], &mut out).unwrap().written > 0,
            "the hello"
        );
        let mut step = |i: &mut Vec<u8>, o: &mut [u8]| {
            session
                .step(i, o)
                .map(|p| (p.consumed, p.written, matches!(p.event, Event::NeedInput)))
        };
        let (sent, failed) = drive_junk(&mut step, junk);
        assert!(failed, "{junk:?}");
        assert!(fatal_alerts(&sent) <= 1, "{junk:?}: {sent:?}");
    }
}

#[test]
fn test_t14_junk_after_a_server_hello_fails_with_one_alert_d111() {
    // The server side: a valid hello, then junk where the client's next
    // flight belongs.
    let server = server();
    let client = test_ca_client().build().unwrap();
    let mut out = vec![0u8; 64 * 1024];
    let mut c = client.connect("localhost").unwrap();
    let n = c.step(&mut [], &mut out).unwrap().written;
    let hello = out[..n].to_vec();
    for junk in [
        &[0xd3][..],
        &[0x17, 0x03, 0x03, 0x00, 0x01, 0x00],
        &[0x15, 0x03, 0x03, 0x00, 0x01, 0x07],
    ] {
        let mut session = server.accept().unwrap();
        let mut input = hello.clone();
        input.extend_from_slice(junk);
        let mut step = |i: &mut Vec<u8>, o: &mut [u8]| {
            session
                .step(i, o)
                .map(|p| (p.consumed, p.written, matches!(p.event, Event::NeedInput)))
        };
        let (sent, failed) = drive_junk(&mut step, &input);
        assert!(failed, "{junk:?}");
        assert!(fatal_alerts(&sent) <= 1, "{junk:?}");
    }
}

/// `record` (one record holding a ClientHello) with each extension passed
/// through `edit`: `None` drops it, `Some(body)` keeps or replaces it. Every
/// length is recomputed, as an attacker in the path would.
/// An extension edit: type and body in, the new body or `None` to drop it.
type Edit = dyn Fn(u16, &[u8]) -> Option<Vec<u8>>;

fn rewrite_hello(record: &[u8], edit: &Edit) -> Vec<u8> {
    let hs = &record[5 + 4..];
    let at = |i: usize| usize::from(u16::from_be_bytes([hs[i], hs[i + 1]]));
    let mut i = 2 + 32;
    i += 1 + usize::from(hs[i]);
    i += 2 + at(i);
    i += 1 + usize::from(hs[i]);
    let head = &hs[..i];
    let end = i + 2 + at(i);
    i += 2;
    let mut exts = Vec::new();
    while i < end {
        let typ = u16::from_be_bytes([hs[i], hs[i + 1]]);
        let len = at(i + 2);
        if let Some(body) = edit(typ, &hs[i + 4..i + 4 + len]) {
            exts.extend_from_slice(&typ.to_be_bytes());
            exts.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
            exts.extend_from_slice(&body);
        }
        i += 4 + len;
    }
    let mut hello = head.to_vec();
    hello.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    hello.extend_from_slice(&exts);
    let mut msg = vec![1];
    msg.extend_from_slice(&u32::try_from(hello.len()).unwrap().to_be_bytes()[1..]);
    msg.extend_from_slice(&hello);
    let mut rec = record[..3].to_vec();
    rec.extend_from_slice(&u16::try_from(msg.len()).unwrap().to_be_bytes());
    rec.extend_from_slice(&msg);
    rec
}

/// A tls-net handshake whose first ClientHello is rewritten in transit.
fn with_rewritten_hello(server: &TlsServer, client: &TlsClient, edit: &Edit) -> (End, End) {
    let (mut ss, mut cs) = (
        server.accept().unwrap(),
        client.connect("localhost").unwrap(),
    );
    let mut out = vec![0u8; 64 * 1024];
    let n = cs.step(&mut [], &mut out).unwrap().written;
    let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
    s.inbox = rewrite_hello(&out[..n], edit);
    pump(&mut ss, &mut s, &mut cs, &mut c);
    (s, c)
}

#[test]
fn test_rewrite_hello_unchanged_completes() {
    // The helper itself: a pass-through rewrite still completes.
    let (s, c) = with_rewritten_hello(&server(), &test_ca_client().build().unwrap(), &|_, b| {
        Some(b.to_vec())
    });
    assert!(s.complete && c.complete, "{:?} {:?}", s.error, c.error);
}

#[test]
fn test_t1_downgrade_to_tls12_refused_by_the_client() {
    // supported_versions stripped in transit: the server, able to do TLS
    // 1.3, answers TLS 1.2 with RFC 8446's downgrade sentinel in its
    // random, and the client, which offered 1.3, refuses.
    let (_, c) = with_rewritten_hello(&server(), &test_ca_client().build().unwrap(), &|t, b| {
        (t != 43).then(|| b.to_vec())
    });
    assert!(!c.complete);
    assert_eq!(c.error, Some(TlsError::PeerMisbehaved), "{:?}", c.error);
}

#[test]
fn test_t4_groups_rewritten_in_transit_fail_the_handshake() {
    // The supported_groups list reordered in transit (the attacker's way to
    // steer the group choice): the transcripts differ and neither side
    // completes.
    let (s, c) = with_rewritten_hello(&server(), &test_ca_client().build().unwrap(), &|t, b| {
        if t != 10 {
            return Some(b.to_vec());
        }
        let mut groups: Vec<[u8; 2]> = b[2..].chunks(2).map(|g| [g[0], g[1]]).collect();
        assert!(groups.len() >= 2);
        groups.reverse();
        let mut body = b[..2].to_vec();
        body.extend(groups.concat());
        Some(body)
    });
    assert!(!c.complete && !s.complete);
    assert!(c.error.is_some(), "the client must fail");
}

#[test]
fn test_t20_events_never_carry_raw_control_bytes() {
    use std::sync::Mutex;
    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);
    impl tls_net::TlsObserver for Log {
        fn on_event(&self, event: &tls_net::TlsEvent<'_>) {
            self.0.lock().unwrap().push(format!("{event:?}"));
        }
    }
    let log = Arc::new(Log::default());
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .observer(Arc::clone(&log) as Arc<dyn tls_net::TlsObserver>)
        .hello_sampling(1)
        .build()
        .unwrap();
    let hello = RawHello::tls12(&ECDHE_SUITES).sni(b"evil\r\n\x1b[31mred\x00.test");
    let _ = refuse(&server, &hello.record());
    let events = log.0.lock().unwrap();
    assert!(!events.is_empty(), "the hello is sampled");
    for e in events.iter() {
        assert!(!e.chars().any(char::is_control), "raw control byte in {e}");
    }
}

/// The handshake between a plain rustls client (any configuration, any
/// client chain) and a tls-net server: whether it completed, and the
/// server's error.
fn against_rustls_client(
    server: &TlsServer,
    config: rustls::ClientConfig,
) -> (bool, Option<TlsError>) {
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut client = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut session = server.accept().unwrap();
    let (mut inbox, mut out) = (Vec::new(), vec![0u8; 64 * 1024]);
    for _ in 0..64 {
        while client.wants_write() {
            client.write_tls(&mut inbox).unwrap();
        }
        loop {
            let (consumed, written, complete, idle) = match session.step(&mut inbox, &mut out) {
                Ok(p) => (
                    p.consumed,
                    p.written,
                    matches!(p.event, Event::HandshakeComplete),
                    matches!(p.event, Event::NeedInput),
                ),
                Err(e) => return (false, Some(e)),
            };
            let mut back = &out[..written];
            while !back.is_empty() {
                client.read_tls(&mut back).unwrap();
            }
            let _ = client.process_new_packets();
            inbox.drain(..consumed);
            if complete {
                return (true, None);
            }
            if idle && consumed == 0 && written == 0 {
                break;
            }
        }
        if !client.wants_write() && !client.is_handshaking() {
            return (false, None);
        }
    }
    panic!("the handshake neither completed nor failed")
}

fn rustls_client_with_chain(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> rustls::ClientConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    #[cfg(feature = "aws-lc")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(not(feature = "aws-lc"))]
    let provider = rustls::crypto::ring::default_provider();
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&data("ca.pem")) {
        roots.add(c.unwrap()).unwrap();
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            chain,
            PrivateKeyDer::from_pem_slice(&data("client.key")).unwrap(),
        )
        .unwrap()
}

#[test]
fn test_t22_huge_client_chains_refused() {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .client_auth(tls_net::ClientAuth::required(
            TrustAnchors::from_pem(&data("ca.pem")).unwrap(),
        ))
        .build()
        .unwrap();
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&data("client.pem"))
        .map(Result::unwrap)
        .collect();
    let (done, err) = against_rustls_client(&server, rustls_client_with_chain(chain.clone()));
    assert!(done, "control: {err:?}");
    // 50 certificates: the client's own chain padded with its intermediate.
    let mut fifty = chain.clone();
    while fifty.len() < 50 {
        fifty.push(chain[1].clone());
    }
    let (done, err) = against_rustls_client(&server, rustls_client_with_chain(fifty));
    assert!(!done);
    assert!(
        matches!(
            err,
            Some(TlsError::PeerChainTooLarge | TlsError::HandshakeTooLarge)
        ),
        "{err:?}"
    );
    // A 1 MiB "certificate" after the real ones: refused by tls-net's
    // budgets or, first, by rustls's 64 KiB limit on one handshake message
    // (reported as PeerMisbehaved).
    let mut big = chain;
    big.push(CertificateDer::from(vec![0x30; 1 << 20]));
    let (done, err) = against_rustls_client(&server, rustls_client_with_chain(big));
    assert!(!done);
    assert!(
        matches!(
            err,
            Some(
                TlsError::HandshakeTooLarge
                    | TlsError::PeerChainTooLarge
                    | TlsError::PeerMisbehaved
            )
        ),
        "{err:?}"
    );
}

#[test]
fn test_t25_unknown_name_refusal_time_does_not_depend_on_the_name() {
    // Opt-in (release build, TLS_NET_TIMING=1, as T-21): refusing names that
    // share a suffix with a hosted wildcard takes as long as refusing names
    // that share nothing, so timing does not reveal what is hosted.
    if std::env::var_os("TLS_NET_TIMING").is_none() {
        return;
    }
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .unknown_name(UnknownName::Refuse)
        .build()
        .unwrap();
    let hello = |name: &str| RawHello::tls12(&ECDHE_SUITES).sni(name.as_bytes()).record();
    let near: Vec<Vec<u8>> = (0..64)
        .map(|i| hello(&format!("a{i}.b.example.test")))
        .collect();
    let far: Vec<Vec<u8>> = (0..64)
        .map(|i| hello(&format!("a{i}.b.unrelated.test")))
        .collect();
    let time = |h: &[u8]| {
        let t = std::time::Instant::now();
        std::hint::black_box(refuse(&server, h));
        t.elapsed()
    };
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for round in 0..2001 {
        let i = round % 64;
        a.push(time(&near[i]));
        b.push(time(&far[i]));
    }
    a.sort_unstable();
    b.sort_unstable();
    let ratio = a[a.len() / 2].as_secs_f64() / b[b.len() / 2].as_secs_f64();
    assert!((0.8..1.25).contains(&ratio), "median ratio {ratio}");
}

#[test]
fn test_t14_second_bad_record_after_a_failure_sends_no_second_alert_d111() {
    // Found by the fuzz targets on the first D-111 fix: a record that fails
    // in rustls's state machine (a ChangeCipherSpec before the ServerHello),
    // followed by a malformed one. Server side: a hello, then the same.
    let client = test_ca_client().build().unwrap();
    let mut session = client.connect("localhost").unwrap();
    let mut out = vec![0u8; 64 * 1024];
    assert!(session.step(&mut [], &mut out).unwrap().written > 0);
    let mut step = |i: &mut Vec<u8>, o: &mut [u8]| {
        session
            .step(i, o)
            .map(|p| (p.consumed, p.written, matches!(p.event, Event::NeedInput)))
    };
    let (sent, failed) = drive_junk(&mut step, &[0x14, 0x03, 0x00, 0x00, 0x01, 0x01, 0xba]);
    assert!(failed);
    assert!(fatal_alerts(&sent) <= 1, "{sent:?}");

    let server = server();
    let crash: [u8; 57] = [
        0x84, 0x16, 0x03, 0x03, 0x00, 0x32, 0x01, 0x00, 0x00, 0x2e, 0xbf, 0x77, 0x76, 0x16, 0x53,
        0x12, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x05, 0x61, 0x9d, 0x19, 0x61,
        0x61, 0x02, 0x2e, 0x00, 0x16, 0x03, 0x03, 0x00, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x34, 0x06, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x01, 0x61,
    ];
    // The fuzz target's first byte is its chunk size; replay in its chunks.
    let chunk = usize::from(crash[0]);
    let mut s = server.accept().unwrap();
    let (mut input, mut sent) = (Vec::new(), Vec::new());
    'feed: for part in crash[1..].chunks(chunk) {
        input.extend_from_slice(part);
        for _ in 0..64 {
            match s.step(&mut input, &mut out) {
                Ok(p) => {
                    let (consumed, written) = (p.consumed, p.written);
                    let need = matches!(p.event, Event::NeedInput);
                    sent.extend_from_slice(&out[..written]);
                    input.drain(..consumed);
                    if need && consumed == 0 && written == 0 {
                        continue 'feed;
                    }
                }
                Err(_) => break 'feed,
            }
        }
    }
    assert!(fatal_alerts(&sent) <= 1, "{sent:?}");
}

/// A tls-net client that completed against a plain rustls server sending
/// records of at most 64 bytes, and the records of that server's ticket
/// flight, not yet delivered.
fn split_ticket_flight(client: &TlsClient) -> (tls_net::ClientSession, Vec<Vec<u8>>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    #[cfg(feature = "aws-lc")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(not(feature = "aws-lc"))]
    let provider = rustls::crypto::ring::default_provider();
    let certs = CertificateDer::pem_slice_iter(&data("site.pem"))
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(&data("site.key")).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.max_fragment_size = Some(64);
    config.send_tls13_tickets = 1;
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let mut session = client.connect("localhost").unwrap();
    let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
    let mut out = vec![0u8; 64 * 1024];
    let mut complete = false;
    for _ in 0..16 {
        loop {
            let p = session.step(&mut to_client, &mut out).unwrap();
            let (consumed, written) = (p.consumed, p.written);
            complete |= matches!(p.event, Event::HandshakeComplete);
            let idle = matches!(p.event, Event::NeedInput);
            to_server.extend_from_slice(&out[..written]);
            to_client.drain(..consumed);
            if idle && consumed == 0 && written == 0 {
                break;
            }
        }
        let mut rd = &to_server[..];
        while !rd.is_empty() {
            server.read_tls(&mut rd).unwrap();
        }
        to_server.clear();
        server.process_new_packets().unwrap();
        while server.wants_write() {
            server.write_tls(&mut to_client).unwrap();
        }
        if complete {
            break;
        }
    }
    assert!(complete, "the handshake did not complete");
    let mut records = Vec::new();
    let mut rest = &to_client[..];
    while rest.len() >= 5 {
        let len = 5 + usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        records.push(rest[..len].to_vec());
        rest = &rest[len..];
    }
    (session, records)
}

#[test]
fn test_t29_partial_post_handshake_message_leaves_encrypt_and_close_safe() {
    // A peer sends one complete record holding only part of a handshake
    // message (here the server's ticket, split over 64-byte records).
    // rustls keeps the part inside the caller's input; encrypt and close
    // must not call into rustls without it (D-126).
    let client = test_ca_client().resumption(4).build().unwrap();
    let (mut session, records) = split_ticket_flight(&client);
    assert!(
        records.len() >= 2,
        "the ticket fits one record: {records:?}"
    );
    let mut out = vec![0u8; 64 * 1024];
    let mut input = records[0].clone();
    let p = session.step(&mut input, &mut out).unwrap();
    assert!(matches!(p.event, Event::NeedInput));
    let consumed = p.consumed;
    assert_eq!(
        session.encrypt(b"request", &mut out),
        Err(TlsError::WrongState)
    );
    assert_eq!(session.close(&mut out), Err(TlsError::WrongState));
    // Not fatal: with the rest of the message the session goes on.
    let mut input: Vec<u8> = input[consumed..].to_vec();
    for r in &records[1..] {
        input.extend_from_slice(r);
    }
    loop {
        let p = session.step(&mut input, &mut out).unwrap();
        let (consumed, written) = (p.consumed, p.written);
        let idle = matches!(p.event, Event::NeedInput);
        input.drain(..consumed);
        if idle && consumed == 0 && written == 0 {
            break;
        }
    }
    assert!(input.is_empty(), "{} bytes left", input.len());
    assert!(session.encrypt(b"request", &mut out).unwrap() > 0);
    assert!(session.close(&mut out).unwrap() > 0);
}

/// The kind of the server's completed handshake, or the first error either
/// side saw.
fn resumes(server: &TlsServer, client: &TlsClient) -> Result<HandshakeKind, TlsError> {
    let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
    let (mut ss, mut cs) = (
        server.accept().unwrap(),
        client.connect("localhost").unwrap(),
    );
    pump(&mut ss, &mut s, &mut cs, &mut c);
    if let Some(e) = s.error.or(c.error) {
        return Err(e);
    }
    Ok(ss.info().unwrap().kind)
}

#[test]
fn test_t30_resumption_follows_a_client_auth_change() {
    // rustls does not ask for a certificate again on resumption. A session
    // made under looser client-authentication rules must not resume after
    // a publish tightens them, with tickets or with the session cache
    // (D-125).
    use tls_net::ClientAuth;
    let ca = || TrustAnchors::from_pem(&data("ca.pem")).unwrap();
    for mode in [
        TicketMode::Ephemeral {
            period: Duration::from_secs(3600),
        },
        TicketMode::Off,
    ] {
        let site = || {
            TlsServer::builder()
                .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
                .unwrap()
                .tickets(mode.clone(), 2)
        };
        let server = site().build().unwrap();
        let anonymous = test_ca_client().resumption(8).build().unwrap();
        assert_eq!(resumes(&server, &anonymous), Ok(HandshakeKind::Full));
        assert_eq!(
            resumes(&server, &anonymous),
            Ok(HandshakeKind::Resumed),
            "{mode:?}"
        );
        server
            .reload_handle()
            .publish(site().client_auth(ClientAuth::required(ca())))
            .unwrap();
        assert_eq!(
            resumes(&server, &anonymous),
            Err(TlsError::PeerCertificateRequired),
            "{mode:?}: an anonymous session resumed under required client auth"
        );
    }
}

#[test]
fn test_t30_resumption_follows_a_removed_pin() {
    use tls_net::ClientAuth;
    let pin = |pem: &str| {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let cert = CertificateDer::pem_slice_iter(&data(pem))
            .next()
            .unwrap()
            .unwrap();
        tls_net::spki_sha256(cert.as_ref()).unwrap()
    };
    let ca = || TrustAnchors::from_pem(&data("ca.pem")).unwrap();
    let site = |pins: &[[u8; 32]]| {
        TlsServer::builder()
            .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
            .unwrap()
            .client_auth(ClientAuth::pinned(Some(ca()), pins))
    };
    let server = site(&[pin("client.pem"), pin("client-only.pem")])
        .build()
        .unwrap();
    let other = test_ca_client()
        .client_certificate(
            &data("client-only.pem"),
            KeySource::Pem(&data("client-only.key")),
        )
        .unwrap()
        .resumption(8)
        .build()
        .unwrap();
    assert_eq!(resumes(&server, &other), Ok(HandshakeKind::Full));
    assert_eq!(resumes(&server, &other), Ok(HandshakeKind::Resumed));
    // The operator drops the second peer's pin.
    server
        .reload_handle()
        .publish(site(&[pin("client.pem")]))
        .unwrap();
    assert!(
        resumes(&server, &other).is_err(),
        "a removed pin still resumed"
    );
}

struct RefuseAll;

impl tls_net::HelloHook for RefuseAll {
    fn on_client_hello(&self, _: &tls_net::HelloContext<'_>) -> tls_net::HelloVerdict {
        tls_net::HelloVerdict::Refuse(tls_net::RefuseReason::Fingerprint)
    }
}

#[test]
fn test_t14_lenient_hello_keeps_the_hook() {
    // refuse_malformed(false) lets a hello tls-net cannot read go on to
    // rustls. A peer picks that path by going over a budget (here 513
    // suites), so it must not skip what depends on the hello: the hook,
    // host groups, a required ALPN (D-127).
    let limits = tls_net::HelloLimits::new().refuse_malformed(false);
    let mut suites = vec![0x0a0a; 509];
    suites.extend(ECDHE_SUITES);
    let hello = RawHello::tls12(&suites).sni(b"localhost").record();
    let lenient = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .hello_limits(limits)
        .build()
        .unwrap();
    let (sent, err) = refuse(&lenient, &hello);
    assert!(err.is_none() && !sent.is_empty(), "control: {err:?}");
    let hooked = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .hello_limits(limits)
        .hello_hook(Arc::new(RefuseAll))
        .build()
        .unwrap();
    let (sent, err) = refuse(&hooked, &hello);
    assert!(sent.is_empty(), "the server answered: {} bytes", sent.len());
    assert!(
        matches!(err, Some(TlsError::HelloOverBudget { .. })),
        "{err:?}"
    );
}

#[test]
fn test_close_with_a_short_output_keeps_close_notify() {
    // rustls marks close_notify sent before it checks the output's size; a
    // close into 8 bytes must leave it to a retry with room (D-129).
    let server = server();
    let client = test_ca_client().build().unwrap();
    let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
    let (mut ss, mut cs) = (
        server.accept().unwrap(),
        client.connect("localhost").unwrap(),
    );
    pump(&mut ss, &mut s, &mut cs, &mut c);
    assert!(c.complete && s.complete);
    assert!(matches!(
        cs.close(&mut [0u8; 8]),
        Err(TlsError::OutputFull { .. })
    ));
    let mut out = vec![0u8; 64];
    let n = cs.close(&mut out).unwrap();
    assert!(n > 0, "close_notify was lost");
    let mut wire = out[..n].to_vec();
    let mut buf = vec![0u8; 64 * 1024];
    let p = ss.step(&mut wire, &mut buf).unwrap();
    assert_eq!(p.event, Event::PeerClosed);
}

#[test]
fn test_hello_over_several_records_reports_the_input_it_needs() {
    // A hello may be up to 65,535 bytes over 16 records (HelloLimits); the
    // session must ask net-io for room for all of it, not one record.
    let limits = tls_net::HelloLimits::new().max_hello_bytes(40_000).unwrap();
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .hello_limits(limits)
        .build()
        .unwrap();
    let mut hello = RawHello::tls12(&ECDHE_SUITES).sni(b"localhost");
    hello.extensions.push((21, vec![0; 30_000]));
    let record = hello.record();
    let message = &record[5..];
    let mut wire = Vec::new();
    for part in message.chunks(16_000) {
        wire.extend([22, 3, 1]);
        wire.extend(u16::try_from(part.len()).unwrap().to_be_bytes());
        wire.extend(part);
    }
    let mut s = server.accept().unwrap();
    let mut out = vec![0u8; 64 * 1024];
    let mut first = wire[..16_010].to_vec();
    let p = s.step(&mut first, &mut out).unwrap();
    assert_eq!((p.consumed, p.event), (0, Event::NeedInput));
    assert!(
        s.input_capacity_required() >= wire.len(),
        "asks for {}, the hello needs {}",
        s.input_capacity_required(),
        wire.len()
    );
}
