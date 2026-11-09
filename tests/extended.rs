//! 0.4: mutual TLS, pins, host policies, reload, tickets, the hook, custody.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{End, data, pump, send};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tls_net::{
    Alpn, AlpnPolicy, CipherSuite, ClientAuth, ClientBuilder, DnsName, ExpiryState, HandshakeKind,
    HelloContext, HelloHook, HelloVerdict, HostPolicy, KeySource, Policy, RefuseReason,
    ServerBuilder, ServerIdentity, SessionState, TicketMode, TicketSeed, TlsClient, TlsError,
    TlsServer, TrustAnchors, Version,
};

fn ca() -> TrustAnchors {
    TrustAnchors::from_pem(&data("ca.pem")).unwrap()
}

fn site() -> ServerBuilder {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
}

fn plain_client() -> TlsClient {
    ClientBuilder::new().trust(ca()).build().unwrap()
}

fn mtls_client() -> TlsClient {
    ClientBuilder::new()
        .trust(ca())
        .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
        .unwrap()
        .build()
        .unwrap()
}

struct Pair {
    server: tls_net::ServerSession,
    client: tls_net::ClientSession,
    s: End,
    c: End,
}

fn run(server: &TlsServer, client: tls_net::ClientSession) -> Pair {
    let mut p = Pair {
        server: server.accept().unwrap(),
        client,
        s: End::new(usize::MAX),
        c: End::new(usize::MAX),
    };
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    p
}

fn connect(server: &TlsServer, client: &TlsClient, name: &str) -> Pair {
    run(server, client.connect(name).unwrap())
}

fn spki(pem: &str) -> [u8; 32] {
    let cert = CertificateDer::pem_slice_iter(&data(pem))
        .next()
        .unwrap()
        .unwrap();
    tls_net::spki_sha256(cert.as_ref()).unwrap()
}

#[test]
fn test_mtls_required_identity_reaches_server() {
    let server = site()
        .client_auth(ClientAuth::required(ca()))
        .build()
        .unwrap();
    let p = connect(&server, &mtls_client(), "localhost");
    assert!(
        p.s.complete && p.c.complete,
        "{:?} {:?}",
        p.s.error,
        p.c.error
    );
    let peer = p.server.info().unwrap().peer.unwrap().clone();
    assert_eq!(peer.dns_names, ["client.test"]);
    assert_eq!(peer.uri_names, ["spiffe://test/client"]);
    assert_eq!(peer.spki_sha256, spki("client.pem"));
    // The client sees the server's identity too.
    assert_eq!(
        p.client.info().unwrap().peer.unwrap().spki_sha256,
        spki("site.pem")
    );
}

#[test]
fn test_mtls_required_without_certificate_refused() {
    let server = site()
        .client_auth(ClientAuth::required(ca()))
        .build()
        .unwrap();
    let p = connect(&server, &plain_client(), "localhost");
    assert_eq!(p.s.error, Some(TlsError::PeerCertificateRequired));
}

#[test]
fn test_mtls_optional_anonymous_or_identified() {
    let server = site()
        .client_auth(ClientAuth::optional(ca()))
        .build()
        .unwrap();
    let anon = connect(&server, &plain_client(), "localhost");
    assert!(anon.s.complete);
    assert!(anon.server.info().unwrap().peer.is_none());
    let known = connect(&server, &mtls_client(), "localhost");
    assert!(known.server.info().unwrap().peer.is_some());
}

#[test]
fn test_mtls_pinned_client_key() {
    let right = site()
        .client_auth(ClientAuth::pinned(None, &[spki("client.pem")]))
        .build()
        .unwrap();
    let p = connect(&right, &mtls_client(), "localhost");
    assert!(p.s.complete, "{:?}", p.s.error);
    let wrong = site()
        .client_auth(ClientAuth::pinned(Some(ca()), &[[7; 32]]))
        .build()
        .unwrap();
    let p = connect(&wrong, &mtls_client(), "localhost");
    assert_eq!(p.s.error, Some(TlsError::PinMismatch));
}

#[test]
fn test_pinned_server_identity_with_and_without_chain() {
    let server = site().build().unwrap();
    let client = plain_client();
    let name = DnsName::new("localhost").unwrap();
    for require_chain in [true, false] {
        let id = ServerIdentity::Pinned {
            name: name.clone(),
            spki_sha256: vec![spki("site.pem")],
            require_chain,
        };
        let p = run(&server, client.connect_to(&id).unwrap());
        assert!(
            p.c.complete,
            "require_chain {require_chain}: {:?}",
            p.c.error
        );
        let bad = ServerIdentity::Pinned {
            name: name.clone(),
            spki_sha256: vec![[1; 32]],
            require_chain,
        };
        let p = run(&server, client.connect_to(&bad).unwrap());
        assert_eq!(p.c.error, Some(TlsError::PinMismatch));
    }
    // A client without anchors can only use a pin without a chain.
    let bare = ClientBuilder::new().build().unwrap();
    assert!(bare.connect("localhost").is_err());
    let id = ServerIdentity::Pinned {
        name,
        spki_sha256: vec![spki("site.pem")],
        require_chain: false,
    };
    let p = run(&server, bare.connect_to(&id).unwrap());
    assert!(p.c.complete, "{:?}", p.c.error);
}

/// A rustls server that presents site.pem but signs with api.key: anyone who
/// copied the public certificate could do this.
#[cfg(feature = "aws-lc")]
#[derive(Debug)]
struct Forged(Arc<rustls::sign::CertifiedKey>);

#[cfg(feature = "aws-lc")]
impl rustls::server::ResolvesServerCert for Forged {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[cfg(feature = "aws-lc")]
#[test]
fn test_t6b_pinned_certificate_with_wrong_key_refused() {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&data("site.pem"))
        .map(|c| c.unwrap())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&data("api.key")).unwrap();
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).unwrap();
    let forged = rustls::sign::CertifiedKey::new(chain, signer);
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(Forged(Arc::new(forged))));
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let bare = ClientBuilder::new().build().unwrap();
    let id = ServerIdentity::Pinned {
        name: DnsName::new("localhost").unwrap(),
        spki_sha256: vec![spki("site.pem")],
        require_chain: false,
    };
    let mut client = bare.connect_to(&id).unwrap();
    let mut out = vec![0u8; 64 * 1024];
    let mut inbox: Vec<u8> = Vec::new();
    let mut result = Ok(());
    for _ in 0..20 {
        match client.step(&mut inbox, &mut out) {
            Ok(p) => {
                let (c, w) = (p.consumed, p.written);
                inbox.drain(..c);
                let mut to_server = &out[..w];
                while !to_server.is_empty() {
                    server.read_tls(&mut to_server).unwrap();
                }
                let _ = server.process_new_packets();
                let mut back = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut back).unwrap();
                }
                inbox.extend(back);
            }
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    assert_eq!(
        result,
        Err(TlsError::PeerCertificateInvalid(
            tls_net::CertificateProblem::BadSignature
        )),
        "a copied certificate without its key must not pass a pin"
    );
}

#[test]
fn test_host_policy_admin_requires_cert_and_alpn_t15() {
    let server = site()
        .alpn(&[Alpn::HTTP_1_1])
        .host(
            &["admin.example.test"],
            HostPolicy::new()
                .alpn(&[Alpn::H2])
                .alpn_policy(AlpnPolicy::Required)
                .client_auth(ClientAuth::required(ca())),
        )
        .unwrap()
        .build()
        .unwrap();
    // www: no client certificate, http/1.1.
    let http1 = ClientBuilder::new()
        .trust(ca())
        .alpn(&[Alpn::HTTP_1_1])
        .build()
        .unwrap();
    let www = connect(&server, &http1, "www.example.test");
    assert!(www.c.complete, "{:?}", www.c.error);
    assert_eq!(
        www.server.info().unwrap().alpn,
        Some(b"http/1.1".as_slice())
    );
    // admin without ALPN: no_application_protocol before rustls runs.
    let p = connect(&server, &plain_client(), "admin.example.test");
    assert_eq!(p.s.error, Some(TlsError::NoApplicationProtocol));
    assert_eq!(p.c.error, Some(TlsError::AlertReceived { alert: 120 }));
    // admin with h2 but no certificate: refused.
    let h2 = ClientBuilder::new()
        .trust(ca())
        .alpn(&[Alpn::H2])
        .build()
        .unwrap();
    let p = connect(&server, &h2, "admin.example.test");
    assert_eq!(p.s.error, Some(TlsError::PeerCertificateRequired));
    // admin with both: served with h2 and an identity.
    let both = ClientBuilder::new()
        .trust(ca())
        .alpn(&[Alpn::H2])
        .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
        .unwrap()
        .build()
        .unwrap();
    let p = connect(&server, &both, "admin.example.test");
    assert!(p.s.complete, "{:?}", p.s.error);
    let info = p.server.info().unwrap();
    assert_eq!(info.alpn, Some(b"h2".as_slice()));
    assert!(info.peer.is_some());
    assert_eq!(server.sni_disagreements(), 0);
}

#[test]
fn test_host_policy_name_must_be_covered() {
    let r = site()
        .host(&["nothing.other.test"], HostPolicy::new())
        .unwrap()
        .build();
    assert!(matches!(r, Err(TlsError::NameNotCovered { .. })));
    let r = site()
        .host(&["a.example.test"], HostPolicy::new())
        .unwrap()
        .host(&["a.example.test"], HostPolicy::new());
    assert!(matches!(r, Err(TlsError::DuplicateName { .. })));
}

#[test]
fn test_reload_keeps_handshakes_in_progress_t19() {
    let server = site().build().unwrap();
    let client = ClientBuilder::new()
        .trust(ca())
        .policy(
            Policy::client_default()
                .versions(&[Version::Tls12])
                .unwrap(),
        )
        .build()
        .unwrap();
    // A handshake that started before the reload.
    let mut before = Pair {
        server: server.accept().unwrap(),
        client: client.connect("localhost").unwrap(),
        s: End::new(usize::MAX),
        c: End::new(usize::MAX),
    };
    let mut to_s = Vec::new();
    before.c.run(&mut before.client, &mut to_s);
    before.s.inbox.extend(to_s);
    let mut to_c = Vec::new();
    before.s.run(&mut before.server, &mut to_c);
    before.c.inbox.extend(to_c);
    // Reload to the RSA certificate.
    server
        .reload_from_pem(&data("site-rsa.pem"), &data("site-rsa.key"))
        .unwrap();
    assert_eq!(server.version(), 2);
    pump(
        &mut before.server,
        &mut before.s,
        &mut before.client,
        &mut before.c,
    );
    assert!(before.c.complete, "{:?}", before.c.error);
    assert_eq!(
        before.server.info().unwrap().cipher_suite,
        CipherSuite::EcdheEcdsaAes256GcmSha384
    );
    let after = connect(&server, &client, "localhost");
    assert_eq!(
        after.server.info().unwrap().cipher_suite,
        CipherSuite::EcdheRsaAes256GcmSha384
    );
    // A half-written pair (new chain, old key) is refused; the old one
    // stays, and a handshake in flight across the refusal completes.
    let mut during = Pair {
        server: server.accept().unwrap(),
        client: client.connect("localhost").unwrap(),
        s: End::new(usize::MAX),
        c: End::new(usize::MAX),
    };
    let mut to_s = Vec::new();
    during.c.run(&mut during.client, &mut to_s);
    during.s.inbox.extend(to_s);
    let e = server
        .reload_from_pem(&data("site.pem"), &data("site-rsa.key"))
        .unwrap_err();
    assert!(matches!(e, TlsError::ReloadRefused { .. }), "{e}");
    assert_eq!(server.version(), 2);
    pump(
        &mut during.server,
        &mut during.s,
        &mut during.client,
        &mut during.c,
    );
    assert!(during.c.complete, "{:?}", during.c.error);
    let still = connect(&server, &client, "localhost");
    assert_eq!(
        still.server.info().unwrap().cipher_suite,
        CipherSuite::EcdheRsaAes256GcmSha384
    );
}

#[test]
fn test_reload_handle_publish_and_resumption_across_reload_fr32() {
    let server = site()
        .tickets(
            TicketMode::Ratchet {
                seed: TicketSeed::Random,
                period: Duration::from_secs(3600),
            },
            2,
        )
        .build()
        .unwrap();
    let client = plain_client();
    let mut first = connect(&server, &client, "localhost");
    pump(
        &mut first.server,
        &mut first.s,
        &mut first.client,
        &mut first.c,
    );
    let outcome = server
        .reload_handle()
        .publish(
            site()
                .certificate_for(
                    &["api.other.test"],
                    &data("api.pem"),
                    KeySource::Pem(&data("api.key")),
                )
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        (outcome.version, outcome.entries, outcome.expiring),
        (2, 2, 0)
    );
    let second = connect(&server, &client, "localhost");
    assert_eq!(
        second.server.info().unwrap().kind,
        HandshakeKind::Resumed,
        "tickets survive a reload"
    );
    let api = connect(&server, &client, "api.other.test");
    assert!(api.c.complete);
    // A failed publish leaves the old configuration.
    let bad = TlsServer::builder();
    assert!(matches!(
        server.reload_handle().publish(bad),
        Err(TlsError::ReloadRefused { .. })
    ));
    assert_eq!(server.reload_handle().version(), 2);
}

#[test]
fn test_tickets_tls12_stateless_and_off() {
    let tls12 = ClientBuilder::new()
        .trust(ca())
        .policy(
            Policy::client_default()
                .versions(&[Version::Tls12])
                .unwrap(),
        )
        .build()
        .unwrap();
    let on = site()
        .tickets(
            TicketMode::Ephemeral {
                period: Duration::from_secs(3600),
            },
            2,
        )
        .session_cache(0)
        .build()
        .unwrap();
    let _ = connect(&on, &tls12, "localhost");
    let again = connect(&on, &tls12, "localhost");
    assert_eq!(
        again.server.info().unwrap().kind,
        HandshakeKind::Resumed,
        "TLS 1.2 stateless ticket"
    );
    let off = site()
        .tickets(TicketMode::Off, 0)
        .session_cache(0)
        .build()
        .unwrap();
    let c = plain_client();
    let mut a = connect(&off, &c, "localhost");
    pump(&mut a.server, &mut a.s, &mut a.client, &mut a.c);
    let b = connect(&off, &c, "localhost");
    assert_eq!(b.server.info().unwrap().kind, HandshakeKind::Full);
}

#[test]
fn test_expiry_report_states() {
    let server = site()
        .certificate_for(
            &["api.other.test"],
            &data("api.pem"),
            KeySource::Pem(&data("api.key")),
        )
        .unwrap()
        .build()
        .unwrap();
    let now = server.expiry_report(SystemTime::now());
    assert_eq!(now.entries.len(), 2);
    assert_eq!(now.worst, ExpiryState::Ok);
    assert!(now.entries[0].days_remaining > 20_000);
    let late = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_000_000);
    assert_eq!(server.expiry_report(late).worst, ExpiryState::Critical);
    let after = SystemTime::UNIX_EPOCH + Duration::from_secs(4_200_000_000);
    assert_eq!(server.expiry_report(after).worst, ExpiryState::Expired);
}

struct RefuseJa4(tls_net::Ja4);

impl HelloHook for RefuseJa4 {
    fn on_client_hello(&self, ctx: &HelloContext<'_>) -> HelloVerdict {
        if ctx.fingerprint.ja4 == Some(self.0) {
            HelloVerdict::Refuse(RefuseReason::Fingerprint)
        } else {
            HelloVerdict::Continue
        }
    }
}

#[test]
fn test_hook_refuses_by_fingerprint_without_alert() {
    // Learn the client's JA4 from one handshake, then refuse it.
    let open = site().build().unwrap();
    // No resumption: a resumed hello carries other extensions and so another JA4.
    let client = ClientBuilder::new()
        .trust(ca())
        .resumption(0)
        .build()
        .unwrap();
    let p = connect(&open, &client, "localhost");
    let ja4 = p.server.info().unwrap().fingerprint.unwrap().ja4.unwrap();
    assert_eq!(ja4.as_str().len(), 36);
    let guarded = site().hello_hook(Arc::new(RefuseJa4(ja4))).build().unwrap();
    let mut s = guarded.accept().unwrap();
    let mut c = client.connect("localhost").unwrap();
    let mut out = vec![0u8; 64 * 1024];
    let hello = c.step(&mut [], &mut out).unwrap().written;
    let mut input = out[..hello].to_vec();
    let mut sout = vec![0u8; 64 * 1024];
    assert_eq!(
        s.step(&mut input, &mut sout).unwrap_err(),
        TlsError::Refused(RefuseReason::Fingerprint)
    );
    assert_eq!(s.state(), SessionState::Failed);
    assert_eq!(guarded.handshakes_in_progress(), 0);
}

#[test]
fn test_internal_preset_back_channel_t2_t4() {
    let server = site()
        .policy(Policy::internal())
        .alpn(&[Alpn::new(b"svc-bc/1").unwrap()])
        .alpn_policy(AlpnPolicy::Required)
        .client_auth(ClientAuth::required(ca()))
        .build();
    #[cfg(all(feature = "ring", not(feature = "aws-lc")))]
    assert_eq!(server.unwrap_err(), TlsError::PostQuantumUnavailable);
    #[cfg(feature = "aws-lc")]
    {
        let server = server.unwrap();
        let peer = ClientBuilder::new()
            .trust(ca())
            .policy(Policy::internal())
            .alpn(&[Alpn::new(b"svc-bc/1").unwrap()])
            .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
            .unwrap()
            .build()
            .unwrap();
        let p = connect(&server, &peer, "localhost");
        assert!(p.s.complete, "{:?} {:?}", p.s.error, p.c.error);
        let info = p.server.info().unwrap();
        assert_eq!(info.version, Version::Tls13);
        assert_eq!(info.group, Some(tls_net::Group::X25519MlKem768));
        // A peer with only a classical group is refused (post-quantum
        // stripping, T-4). P-256, so the test also runs in FIPS builds.
        let classical = ClientBuilder::new()
            .trust(ca())
            .policy(
                Policy::client_default()
                    .groups(&[tls_net::Group::Secp256r1])
                    .unwrap(),
            )
            .alpn(&[Alpn::new(b"svc-bc/1").unwrap()])
            .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
            .unwrap()
            .build()
            .unwrap();
        let p = connect(&server, &classical, "localhost");
        assert!(!p.s.complete);
        assert!(
            matches!(
                p.s.error,
                Some(TlsError::NoCommonGroup | TlsError::NoCommonVersion)
            ),
            "{:?}",
            p.s.error
        );
        // Unknown names are refused on internal listeners.
        let p = connect(&server, &peer, "other.test");
        assert_eq!(p.s.error, Some(TlsError::UnknownServerName));
    }
}

#[test]
fn test_max_fragment_size_limits_records() {
    let server = site()
        .policy(Policy::compatible().max_fragment_size(Some(1024)).unwrap())
        .build()
        .unwrap();
    let mut p = connect(&server, &plain_client(), "localhost");
    let mut out = vec![0u8; 64 * 1024];
    let n = p.server.encrypt(&[7u8; 4096], &mut out).unwrap();
    // Four records of 1,024 bytes plus 22 bytes of overhead each.
    assert_eq!(n, 4 * (1024 + 22));
    p.c.inbox.extend_from_slice(&out[..n]);
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    assert_eq!(p.c.received.len(), 4096);
}

#[test]
fn test_server_reader_follows_reloads() {
    let server = site().build().unwrap();
    let mut reader = server.reader();
    let client = ClientBuilder::new()
        .trust(ca())
        .policy(
            Policy::client_default()
                .versions(&[Version::Tls12])
                .unwrap(),
        )
        .build()
        .unwrap();
    let s = reader.accept().unwrap();
    let mut p = Pair {
        server: s,
        client: client.connect("localhost").unwrap(),
        s: End::new(usize::MAX),
        c: End::new(usize::MAX),
    };
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    assert_eq!(
        p.server.info().unwrap().cipher_suite,
        CipherSuite::EcdheEcdsaAes256GcmSha384
    );
    server
        .reload_from_pem(&data("site-rsa.pem"), &data("site-rsa.key"))
        .unwrap();
    let mut p = Pair {
        server: reader.accept().unwrap(),
        client: client.connect("localhost").unwrap(),
        s: End::new(usize::MAX),
        c: End::new(usize::MAX),
    };
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    assert_eq!(
        p.server.info().unwrap().cipher_suite,
        CipherSuite::EcdheRsaAes256GcmSha384
    );
}

#[test]
fn test_reload_under_load_zero_failed_handshakes() {
    // Handshakes on four threads while a fifth reloads every 2 ms, until at
    // least 20 reloads and 200 handshakes have happened (scaled down from
    // PLAN's 10-minute run, which the soak covers, D-081).
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
    let server = site().build().unwrap();
    let client = plain_client();
    let stop = Arc::new(AtomicBool::new(false));
    let reloads = Arc::new(AtomicU64::new(0));
    let handshakes = Arc::new(AtomicU64::new(0));
    let reloader = {
        let (server, stop, reloads) = (server.clone(), Arc::clone(&stop), Arc::clone(&reloads));
        std::thread::spawn(move || {
            while !stop.load(Relaxed) {
                let n = reloads.load(Relaxed);
                let (chain, key) = if n % 2 == 0 {
                    ("site-rsa.pem", "site-rsa.key")
                } else {
                    ("site.pem", "site.key")
                };
                server.reload_from_pem(&data(chain), &data(key)).unwrap();
                reloads.fetch_add(1, Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let (server, client, stop, handshakes) = (
                server.clone(),
                client.clone(),
                Arc::clone(&stop),
                Arc::clone(&handshakes),
            );
            std::thread::spawn(move || {
                while !stop.load(Relaxed) {
                    let p = connect(&server, &client, "localhost");
                    assert!(
                        p.s.complete && p.c.complete,
                        "{:?} {:?}",
                        p.s.error,
                        p.c.error
                    );
                    handshakes.fetch_add(1, Relaxed);
                }
            })
        })
        .collect();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while (reloads.load(Relaxed) < 20 || handshakes.load(Relaxed) < 200)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    stop.store(true, Relaxed);
    for w in workers {
        w.join().unwrap();
    }
    reloader.join().unwrap();
    assert!(
        reloads.load(Relaxed) >= 20,
        "{} reloads",
        reloads.load(Relaxed)
    );
    assert!(
        handshakes.load(Relaxed) >= 200,
        "{} handshakes",
        handshakes.load(Relaxed)
    );
}

#[test]
fn test_ocsp_staple_accepted_and_refused() {
    assert!(
        site()
            .ocsp_staple("localhost", &data("site.ocsp"))
            .unwrap()
            .build()
            .is_ok()
    );
    assert!(
        site()
            .ocsp_staple("localhost", &data("site.revoked.ocsp"))
            .is_err()
    );
    assert!(
        site()
            .ocsp_staple("localhost", b"\x30\x03\x0a\x01\x01")
            .is_err()
    );
    let r = site()
        .ocsp_staple("api.other.test", &data("site.ocsp"))
        .unwrap()
        .build();
    assert!(matches!(r, Err(TlsError::NameNotCovered { .. })));
}

#[cfg(feature = "key-vault")]
#[test]
fn test_key_vault_custody_both_modes() {
    use key_vault::{KeyVaultBuilder, RawKey};
    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let handle = vault
        .register("site", RawKey::new(data("site.key.der")))
        .unwrap();
    for custody in [
        tls_net::KeyCustody::Resident,
        tls_net::KeyCustody::PerSignature,
    ] {
        let server = TlsServer::builder()
            .certificate(
                &data("site.pem"),
                KeySource::Vault {
                    vault: Arc::clone(&vault),
                    handle,
                    custody,
                },
            )
            .unwrap()
            .build()
            .unwrap();
        let p = connect(&server, &plain_client(), "localhost");
        assert!(p.c.complete, "{custody:?}: {:?}", p.c.error);
    }
    // A vault that normalises keys hands out a digest, not a key.
    let hashing = Arc::new(KeyVaultBuilder::new().build());
    let h = hashing
        .register("site", RawKey::new(data("site.key.der")))
        .unwrap();
    let r = TlsServer::builder().certificate(
        &data("site.pem"),
        KeySource::Vault {
            vault: hashing,
            handle: h,
            custody: tls_net::KeyCustody::Resident,
        },
    );
    assert_eq!(r.unwrap_err(), TlsError::VaultKeyUnusable);
}

#[test]
fn test_send_with_records_survives_close() {
    let server = site().build().unwrap();
    let mut p = connect(&server, &plain_client(), "localhost");
    send(&mut p.client, b"bye", 3, &mut p.s.inbox);
    pump(&mut p.server, &mut p.s, &mut p.client, &mut p.c);
    assert_eq!(p.s.received, b"bye");
}

#[test]
fn test_t16_server_name_is_normalised_sni() {
    let server = site().build().unwrap();
    let client = plain_client();
    let p = connect(&server, &client, "LocalHost.");
    assert!(p.c.complete, "{:?}", p.c.error);
    assert_eq!(p.server.info().unwrap().server_name, Some("localhost"));
}

#[test]
fn test_t22_client_chain_over_budget_refused() {
    let server = site()
        .client_auth(ClientAuth::required(ca()))
        .limits(
            tls_net::HandshakeLimits::server()
                .max_peer_chain_len(1)
                .unwrap(),
        )
        .build()
        .unwrap();
    let p = connect(&server, &mtls_client(), "localhost");
    assert_eq!(p.s.error, Some(TlsError::PeerChainTooLarge));
}

#[cfg(feature = "aws-lc")]
#[test]
fn test_t10_early_data_never_reaches_the_application() {
    // A rustls client with early data enabled resumes: tls-net offers no
    // 0-RTT window, so nothing can arrive as early data; data sent after the
    // handshake arrives normally.
    let server = site().build().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&data("ca.pem")) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.enable_early_data = true;
    let config = Arc::new(config);
    let mut received = Vec::new();
    for round in 0..2 {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut client = rustls::ClientConnection::new(Arc::clone(&config), name).unwrap();
        if round == 1 {
            // tls-net's tickets never allow early data (max_early_data_size 0),
            // so a resuming client has no 0-RTT window at all.
            assert!(
                client.early_data().is_none(),
                "the server must not offer early data"
            );
        }
        let mut s = server.accept().unwrap();
        let mut inbox: Vec<u8> = Vec::new();
        let mut out = vec![0u8; 64 * 1024];
        let mut sent_late = false;
        for _ in 0..40 {
            let mut wire = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut wire).unwrap();
            }
            inbox.extend(wire);
            loop {
                match s.step(&mut inbox, &mut out) {
                    Ok(p) => {
                        let (c, w) = (p.consumed, p.written);
                        let need = matches!(p.event, tls_net::Event::NeedInput);
                        if let tls_net::Event::Data(d) = p.event {
                            received.extend_from_slice(d);
                        }
                        let mut back = &out[..w];
                        while !back.is_empty() {
                            client.read_tls(&mut back).unwrap();
                        }
                        let _ = client.process_new_packets();
                        inbox.drain(..c);
                        if need && w == 0 && c == 0 {
                            break;
                        }
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            if !client.is_handshaking() && !sent_late {
                use std::io::Write;
                client.writer().write_all(b"LATE").unwrap();
                sent_late = true;
            }
        }
        if round == 1 {
            assert!(!client.is_early_data_accepted());
            // The resumption happened, so the client held a ticket and the
            // missing 0-RTT window above is the server's doing.
            assert_eq!(
                client.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            );
            assert_eq!(s.info().unwrap().kind, HandshakeKind::Resumed);
        }
    }
    assert!(
        !received.windows(5).any(|w| w == b"EARLY"),
        "early data reached the application"
    );
    assert_eq!(received, b"LATELATE");
}

#[cfg(feature = "aws-lc")]
#[test]
fn test_t2_t4_internal_listener_refuses_tls12_and_x25519_only_peers() {
    let server = site()
        .policy(Policy::internal())
        .alpn(&[Alpn::new(b"svc-bc/1").unwrap()])
        .alpn_policy(AlpnPolicy::Required)
        .client_auth(ClientAuth::required(ca()))
        .build()
        .unwrap();
    let peer = |policy: Policy| {
        ClientBuilder::new()
            .trust(ca())
            .policy(policy)
            .alpn(&[Alpn::new(b"svc-bc/1").unwrap()])
            .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
            .unwrap()
            .build()
            .unwrap()
    };
    // T-2: a TLS 1.2-only peer.
    let tls12 = peer(
        Policy::client_default()
            .versions(&[Version::Tls12])
            .unwrap(),
    );
    let p = connect(&server, &tls12, "localhost");
    assert!(!p.s.complete);
    assert_eq!(p.s.error, Some(TlsError::NoCommonVersion));
    // T-4: a TLS 1.3 peer offering X25519 alone (no post-quantum group).
    // X25519 is not approved in a FIPS build, where P-256 covers this case.
    #[cfg(not(feature = "fips"))]
    {
        let classical = peer(
            Policy::client_default()
                .versions(&[Version::Tls13])
                .unwrap()
                .groups(&[tls_net::Group::X25519])
                .unwrap(),
        );
        let p = connect(&server, &classical, "localhost");
        assert!(!p.s.complete);
        assert_eq!(p.s.error, Some(TlsError::NoCommonGroup));
    }
}

#[test]
fn test_settings_that_would_do_less_than_they_say_are_refused() {
    // D-131: the internal preset is for links that authenticate the client,
    // and CRLs without anchors would never be checked.
    let refused = |b: ServerBuilder| matches!(b.build(), Err(TlsError::PolicyInvalid { .. }));
    assert!(
        refused(site().policy(Policy::internal())),
        "internal without client auth"
    );
    assert!(refused(
        site()
            .policy(Policy::internal())
            .client_auth(ClientAuth::optional(ca()))
    ));
    let crls = || tls_net::Crls::from_pem(&data("inter-empty.crl.pem")).unwrap();
    let pin = [7u8; 32];
    assert!(refused(site().client_auth(
        ClientAuth::pinned(None, &[pin]).with_crls(crls(), tls_net::RevocationPolicy::default())
    )));
    assert!(refused(site().client_auth(
        ClientAuth::none().with_crls(crls(), tls_net::RevocationPolicy::default())
    )));
    // With anchors the CRLs apply, and the build goes through.
    assert!(
        site()
            .client_auth(
                ClientAuth::pinned(Some(ca()), &[pin])
                    .with_crls(crls(), tls_net::RevocationPolicy::default())
            )
            .build()
            .is_ok()
    );
}

#[test]
fn test_pinned_identity_resumes() {
    // rustls resumes only with the verifier that made the session, so a
    // pinned identity keeps one configuration per pin set (D-133).
    let server = site()
        .tickets(
            TicketMode::Ephemeral {
                period: Duration::from_secs(3600),
            },
            2,
        )
        .build()
        .unwrap();
    let client = ClientBuilder::new()
        .trust(ca())
        .resumption(8)
        .build()
        .unwrap();
    let spki = {
        let cert = CertificateDer::pem_slice_iter(&data("site.pem"))
            .next()
            .unwrap()
            .unwrap();
        tls_net::spki_sha256(cert.as_ref()).unwrap()
    };
    let kind = |require_chain: bool| {
        let id = ServerIdentity::Pinned {
            name: DnsName::new("localhost").unwrap(),
            spki_sha256: vec![spki],
            require_chain,
        };
        let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
        let (mut ss, mut cs) = (server.accept().unwrap(), client.connect_to(&id).unwrap());
        pump(&mut ss, &mut s, &mut cs, &mut c);
        assert!(c.complete, "{:?} {:?}", s.error, c.error);
        ss.info().unwrap().kind
    };
    for require_chain in [true, false] {
        assert_eq!(kind(require_chain), HandshakeKind::Full);
        assert_eq!(
            kind(require_chain),
            HandshakeKind::Resumed,
            "require_chain {require_chain}"
        );
    }
}

#[cfg(feature = "platform-verifier")]
#[test]
fn test_pinned_identity_with_platform_anchors() {
    // A chain-checked pin uses the verifier the client was built with, the
    // platform's included; it was refused as "anchors could not be used"
    // (D-133).
    let client = ClientBuilder::new()
        .trust(TrustAnchors::platform())
        .build()
        .unwrap();
    let id = ServerIdentity::Pinned {
        name: DnsName::new("example.com").unwrap(),
        spki_sha256: vec![[1; 32]],
        require_chain: true,
    };
    assert!(client.connect_to(&id).is_ok());
}

#[test]
fn test_reload_keeps_the_names_a_certificate_was_configured_for() {
    // A certificate added with certificate_for serves only its names; a
    // reload_from_pem must not turn it into the default for every name
    // (D-136).
    let server = TlsServer::builder()
        .certificate_for(&["api.other.test"], &data("api.pem"), KeySource::Pem(&data("api.key")))
        .unwrap()
        .build()
        .unwrap();
    let client = ClientBuilder::new().trust(ca()).build().unwrap();
    let served = |name: &str| {
        let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
        let (mut ss, mut cs) = (server.accept().unwrap(), client.connect(name).unwrap());
        pump(&mut ss, &mut s, &mut cs, &mut c);
        s.error.clone()
    };
    assert_eq!(served("api.other.test"), None);
    assert_eq!(served("unknown.test"), Some(TlsError::UnknownServerName));
    server
        .reload_from_pem(&data("api.pem"), &data("api.key"))
        .unwrap();
    assert_eq!(served("api.other.test"), None);
    assert_eq!(
        served("unknown.test"),
        Some(TlsError::UnknownServerName),
        "the reload made the certificate the default"
    );
}

#[test]
fn test_ocsp_staple_goes_to_its_own_certificate() {
    // site.ocsp is for site.pem. A server whose only certificate for the
    // name is another one (here RSA) must not send it (D-137).
    let rsa_only = TlsServer::builder()
        .certificate(&data("site-rsa.pem"), KeySource::Pem(&data("site-rsa.key")))
        .unwrap()
        .ocsp_staple("localhost", &data("site.ocsp"))
        .unwrap()
        .build();
    assert!(
        matches!(rsa_only, Err(TlsError::PolicyInvalid { .. })),
        "{rsa_only:?}"
    );
    // With both, the staple goes to site.pem and the build goes through.
    assert!(
        site()
            .certificate(&data("site-rsa.pem"), KeySource::Pem(&data("site-rsa.key")))
            .unwrap()
            .ocsp_staple("localhost", &data("site.ocsp"))
            .unwrap()
            .build()
            .is_ok()
    );
}
