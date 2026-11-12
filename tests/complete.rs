//! 0.5: events, statistics, ticket hand-off, STARTTLS end to end, and the
//! attack tests that need the whole crate (T-8, T-23, T-24, T-27).

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{End, TcpClient, data, pump};
use tls_net::{
    HandshakeLimits, KeySource, Policy, ServerBuilder, TicketMode, TicketSeed, TlsClient, TlsError,
    TlsEvent, TlsObserver, TlsServer, TrustAnchors, UnknownName,
};

fn ca() -> TrustAnchors {
    TrustAnchors::from_pem(&data("ca.pem")).unwrap()
}

fn site() -> ServerBuilder {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
}

fn client() -> TlsClient {
    TlsClient::builder().trust(ca()).build().unwrap()
}

fn connect(
    server: &TlsServer,
    client: &TlsClient,
    name: &str,
) -> (tls_net::ServerSession, End, tls_net::ClientSession, End) {
    let (mut s, mut c) = (server.accept().unwrap(), client.connect(name).unwrap());
    let (mut se, mut ce) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut s, &mut se, &mut c, &mut ce);
    (s, se, c, ce)
}

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl TlsObserver for Recorder {
    fn on_event(&self, event: &TlsEvent<'_>) {
        let line = match event {
            TlsEvent::HandshakeCompleted {
                server_name, kind, ..
            } => format!("completed {server_name:?} {kind:?}"),
            TlsEvent::HandshakeFailed { code, .. } => format!("failed {code}"),
            TlsEvent::HelloCaptured { fingerprint, .. } => {
                format!("captured {}", fingerprint.ja4.is_some())
            }
            TlsEvent::HelloRefused { reason, .. } => format!("refused {reason:?}"),
            TlsEvent::ReloadApplied { version, .. } => format!("reload {version}"),
            TlsEvent::ReloadRefused { code, .. } => format!("reload refused {code}"),
            TlsEvent::CertificateExpiring { state, .. } => format!("expiring {state:?}"),
            TlsEvent::TicketKeyRotated { reseeded, .. } => format!("rotated {reseeded}"),
            TlsEvent::HandshakeCapacityReached { limit, .. } => format!("capacity {limit}"),
            _ => "other".into(),
        };
        self.0.lock().unwrap().push(line);
    }
}

impl Recorder {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

#[test]
fn test_events_and_stats_server() {
    let rec = Arc::new(Recorder::default());
    let server = site()
        .observer(Arc::clone(&rec) as Arc<dyn TlsObserver>)
        .hello_sampling(1)
        .unknown_name(UnknownName::Refuse)
        .limits(HandshakeLimits::server().max_in_progress(4))
        .build()
        .unwrap();
    let c = client();
    let _ = connect(&server, &c, "localhost");
    let _ = connect(&server, &c, "localhost");
    let _ = connect(&server, &c, "unknown.test");
    let held: Vec<_> = (0..4).map(|_| server.accept().unwrap()).collect();
    assert!(server.accept().is_err());
    assert!(server.accept().is_err());
    drop(held);
    server
        .reload_from_pem(&data("site.pem"), &data("site.key"))
        .unwrap();
    assert!(
        server
            .reload_from_pem(&data("site.pem"), &data("api.key"))
            .is_err()
    );
    let _ = server
        .expiry_report(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_000_000));

    let lines = rec.lines();
    assert!(
        lines.contains(&"completed Some(\"localhost\") Full".to_string()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"completed Some(\"localhost\") Resumed".to_string()),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .filter(|l| l.starts_with("captured true"))
            .count()
            >= 3,
        "{lines:?}"
    );
    assert!(
        lines.contains(&"refused UnknownName".to_string()),
        "{lines:?}"
    );
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("capacity")).count(),
        1,
        "rate-limited: {lines:?}"
    );
    assert!(
        lines.contains(&"reload 2".to_string()) && lines.contains(&"reload refused 16".to_string()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"expiring Critical".to_string()),
        "{lines:?}"
    );

    let stats = server.stats();
    assert_eq!(stats.handshakes_full, 1, "{lines:?}");
    assert_eq!(stats.handshakes_resumed, 1);
    assert_eq!(stats.hello_refusals, 1);
    assert_eq!(stats.capacity_refusals, 2);
    assert_eq!(stats.config_version, 2);
    assert!(stats.tickets_issued >= 2);
    #[cfg(feature = "aws-lc")]
    assert_eq!(
        stats.post_quantum_handshakes, 2,
        "a TLS 1.3 resumption still runs the key exchange"
    );
}

#[test]
fn test_events_client_failure() {
    let rec = Arc::new(Recorder::default());
    let server = site().build().unwrap();
    let c = TlsClient::builder()
        .trust(ca())
        .observer(Arc::clone(&rec) as Arc<dyn TlsObserver>)
        .build()
        .unwrap();
    let _ = connect(&server, &c, "wrong-name.test");
    let _ = connect(&server, &c, "localhost");
    let lines = rec.lines();
    assert!(lines.contains(&"failed 37".to_string()), "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("completed Some(\"localhost\")")),
        "{lines:?}"
    );
}

fn ratchet() -> TicketMode {
    TicketMode::Ratchet {
        seed: TicketSeed::Random,
        period: Duration::from_secs(3600),
    }
}

#[test]
fn test_ticket_handoff_keeps_resumption() {
    // The old process issues a ticket, hands its keys to the new one, and
    // the client resumes against the new process.
    let old = site()
        .tickets(ratchet(), 2)
        .session_cache(0)
        .build()
        .unwrap();
    let new = site()
        .tickets(ratchet(), 2)
        .session_cache(0)
        .build()
        .unwrap();
    let c = client();
    let (mut s, mut se, mut cl, mut ce) = connect(&old, &c, "localhost");
    pump(&mut s, &mut se, &mut cl, &mut ce);
    let wrap = [0x42u8; 32];
    let sealed = old.ticket_keys().unwrap().export_sealed(&wrap).unwrap();
    assert!(!format!("{sealed:?}").contains("42"));
    new.ticket_keys()
        .unwrap()
        .import_sealed(&wrap, sealed.as_bytes())
        .unwrap();
    let (s2, ..) = connect(&new, &c, "localhost");
    assert_eq!(s2.info().unwrap().kind, tls_net::HandshakeKind::Resumed);
}

#[test]
fn test_t24_sealed_keys_refused_when_wrong() {
    let old = site().tickets(ratchet(), 2).build().unwrap();
    let new = site().tickets(ratchet(), 2).build().unwrap();
    let sealed = old.ticket_keys().unwrap().export_sealed(&[1; 32]).unwrap();
    let handle = new.ticket_keys().unwrap();
    assert!(
        handle.import_sealed(&[2; 32], sealed.as_bytes()).is_err(),
        "wrong wrap key"
    );
    for i in 0..sealed.as_bytes().len() {
        let mut bad = sealed.as_bytes().to_vec();
        bad[i] ^= 1;
        assert!(
            handle.import_sealed(&[1; 32], &bad).is_err(),
            "tampered at {i}"
        );
    }
    assert!(
        handle
            .import_sealed(&[1; 32], &sealed.as_bytes()[..20])
            .is_err()
    );
    // Ephemeral rings neither export nor import.
    let eph = site().build().unwrap();
    assert!(eph.ticket_keys().unwrap().export_sealed(&[1; 32]).is_err());
    assert!(
        eph.ticket_keys()
            .unwrap()
            .import_sealed(&[1; 32], sealed.as_bytes())
            .is_err()
    );
    // Urgent rotation invalidates outstanding tickets.
    let c = client();
    let (mut s, mut se, mut cl, mut ce) = connect(&old, &c, "localhost");
    pump(&mut s, &mut se, &mut cl, &mut ce);
    old.ticket_keys().unwrap().rotate_now().unwrap();
    let c2 = TlsClient::builder().trust(ca()).build().unwrap();
    let _ = c2;
    let (s3, ..) = connect(&old, &c, "localhost");
    assert_ne!(
        s3.info().unwrap().kind,
        tls_net::HandshakeKind::Resumed,
        "tickets from before rotate_now"
    );
}

/// A scripted SMTP relay: greeting, EHLO with STARTTLS, `220`, then TLS.
fn smtp_relay(server: TlsServer, extra_after_220: &'static [u8]) -> std::net::SocketAddr {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let mut w = sock.try_clone().unwrap();
        let mut r = BufReader::new(sock.try_clone().unwrap());
        let _ = w.write_all(b"220 relay.test ESMTP\r\n");
        let mut line = String::new();
        let _ = r.read_line(&mut line);
        let _ = w.write_all(b"250-relay.test\r\n250 STARTTLS\r\n");
        line.clear();
        let _ = r.read_line(&mut line);
        let mut reply = b"220 2.0.0 Ready to start TLS\r\n".to_vec();
        reply.extend_from_slice(extra_after_220);
        let _ = w.write_all(&reply);
        drop(r);
        let mut session = server.accept().unwrap();
        let mut inbuf = vec![0u8; 64 * 1024];
        let mut filled = 0;
        let mut out = vec![0u8; 64 * 1024];
        let mut s = sock;
        use std::io::Read;
        loop {
            let Ok(p) = session.step(&mut inbuf[..filled], &mut out) else {
                return;
            };
            let (c, wr) = (p.consumed, p.written);
            let need = matches!(p.event, tls_net::Event::NeedInput);
            let data = if let tls_net::Event::Data(d) = p.event {
                Some(d.to_vec())
            } else {
                None
            };
            if wr > 0 {
                let _ = s.write_all(&out[..wr]);
            }
            inbuf.copy_within(c..filled, 0);
            filled -= c;
            if let Some(d) = data {
                if d.starts_with(b"EHLO") {
                    let n = session
                        .encrypt(b"250 relay.test over TLS\r\n", &mut out)
                        .unwrap();
                    let _ = s.write_all(&out[..n]);
                }
            }
            if need && wr == 0 && c == 0 {
                match s.read(&mut inbuf[filled..]) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => filled += n,
                }
            }
        }
    });
    addr
}

/// The SMTP side up to the `220` reply; returns the socket and whatever
/// arrived after the reply line.
fn smtp_upgrade(addr: std::net::SocketAddr) -> (std::net::TcpStream, Vec<u8>) {
    use std::io::{Read, Write};
    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new();
    let read_until = |sock: &mut std::net::TcpStream, buf: &mut Vec<u8>, end: &[u8]| loop {
        if let Some(i) = buf.windows(end.len()).position(|w| w == end) {
            let rest = buf.split_off(i + end.len());
            return std::mem::replace(buf, rest);
        }
        let mut chunk = [0u8; 512];
        let n = sock.read(&mut chunk).unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&chunk[..n]);
    };
    read_until(&mut sock, &mut buf, b"ESMTP\r\n");
    sock.write_all(b"EHLO me\r\n").unwrap();
    read_until(&mut sock, &mut buf, b"250 STARTTLS\r\n");
    sock.write_all(b"STARTTLS\r\n").unwrap();
    read_until(&mut sock, &mut buf, b"TLS\r\n");
    // Give an injected tail time to arrive in the same read window.
    std::thread::sleep(Duration::from_millis(50));
    sock.set_nonblocking(true).unwrap();
    let mut chunk = [0u8; 512];
    while let Ok(n) = sock.read(&mut chunk) {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    sock.set_nonblocking(false).unwrap();
    (sock, buf)
}

#[test]
fn test_starttls_against_scripted_relay() {
    let addr = smtp_relay(site().build().unwrap(), b"");
    let (sock, leftover) = smtp_upgrade(addr);
    let c = client();
    let mut tls = TcpClient::new(
        sock,
        c.start_after_plaintext("localhost", &leftover).unwrap(),
    );
    tls.handshake().unwrap();
    tls.write(b"EHLO me\r\n").unwrap();
    assert_eq!(tls.read(10).unwrap(), b"250 relay.test over TLS\r\n");
}

#[test]
fn test_t5_starttls_injection_end_to_end() {
    let addr = smtp_relay(site().build().unwrap(), b"250 injected\r\n");
    let (_sock, leftover) = smtp_upgrade(addr);
    assert_eq!(leftover, b"250 injected\r\n");
    assert_eq!(
        client()
            .start_after_plaintext("localhost", &leftover)
            .unwrap_err(),
        TlsError::StartTlsInjection
    );
}

#[test]
fn test_policy_summary_and_fips_mode() {
    let s = Policy::compatible().summary();
    assert_eq!(s.versions.len(), 2);
    assert!(s.extended_master_secret && s.server_order && !s.fips);
    let server = site().build().unwrap();
    #[cfg(not(feature = "fips"))]
    {
        assert!(!server.is_fips());
        assert!(!client().is_fips());
        let r = site().policy(Policy::fips()).build();
        assert_eq!(r.unwrap_err(), TlsError::FipsUnavailable);
    }
    #[cfg(feature = "fips")]
    {
        let fips = site().policy(Policy::fips()).build().unwrap();
        assert!(fips.is_fips());
        assert_eq!(fips.provider_name(), "aws-lc-rs (FIPS)");
        let _ = server;
    }
}

#[cfg(feature = "rustls-escape-hatch")]
#[test]
fn test_escape_hatch_exposes_configs() {
    let server = site().build().unwrap();
    assert_eq!(server.as_rustls_configs().len(), 1);
    assert!(
        !client()
            .as_rustls_config()
            .alpn_protocols
            .iter()
            .any(|a| a.is_empty())
    );
}

#[cfg(feature = "dangerous-keylog")]
#[test]
fn test_key_log_receives_lines() {
    #[derive(Default)]
    struct Sink(Mutex<Vec<String>>);
    impl tls_net::KeyLogSink for Sink {
        fn log(&self, label: &str, _random: &[u8], _secret: &[u8]) {
            self.0.lock().unwrap().push(label.to_string());
        }
    }
    let sink = Arc::new(Sink::default());
    let server = site()
        .dangerous_key_log(Arc::clone(&sink) as Arc<dyn tls_net::KeyLogSink>)
        .build()
        .unwrap();
    let _ = connect(&server, &client(), "localhost");
    let labels = sink.0.lock().unwrap().clone();
    assert!(
        labels.iter().any(|l| l == "SERVER_TRAFFIC_SECRET_0"),
        "{labels:?}"
    );
}

#[test]
fn test_t8_no_key_bytes_in_debug_or_display() {
    use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
    let key = PrivateKeyDer::from_pem_slice(&data("site.key")).unwrap();
    let der = key.secret_der().to_vec();
    let builder = site();
    let server = builder.clone().build().unwrap();
    let (s, _, c, _) = connect(&server, &client(), "localhost");
    let mut outputs = vec![
        format!("{builder:?}"),
        format!("{server:?}"),
        format!("{s:?}"),
        format!("{c:?}"),
        format!("{:?}", KeySource::Pem(&data("site.key"))),
        format!("{:?}", KeySource::Der(&der)),
        format!("{:?}", server.expiry_report(std::time::SystemTime::now())),
        format!("{:?}", server.stats()),
    ];
    for e in [
        TlsError::KeyMismatch,
        TlsError::VaultKeyUnusable,
        TlsError::EncryptedPrivateKey,
    ] {
        outputs.push(format!("{e:?} {e}"));
    }
    let hexed = |b: &[u8]| {
        b.iter().fold(String::new(), |mut s, x| {
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
            s
        })
    };
    for out in &outputs {
        for window in der.windows(16) {
            let as_text = String::from_utf8_lossy(window);
            assert!(
                !out.contains(&*as_text) || window.iter().all(u8::is_ascii_alphanumeric),
                "raw key bytes in {out}"
            );
            assert!(!out.contains(&hexed(window)), "hex key bytes in {out}");
            assert!(
                !out.contains(&format!("{window:?}")),
                "listed key bytes in {out}"
            );
        }
    }
}

#[test]
fn test_t23_no_banned_crate_in_the_tree() {
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "-e",
            "normal",
            "--prefix",
            "none",
            "--all-features",
            "--manifest-path",
        ])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .output();
    // Offline, cargo cannot resolve the tree; on CI (where `CI` is set) that
    // fails the test rather than passing it unchecked.
    let ran = out.as_ref().is_ok_and(|o| o.status.success());
    if !ran {
        assert!(
            std::env::var_os("CI").is_none(),
            "cargo tree failed: {out:?}"
        );
        return;
    }
    let out = out.unwrap();
    let tree = String::from_utf8_lossy(&out.stdout);
    for banned in [
        "openssl ",
        "openssl-sys ",
        "native-tls ",
        "tokio ",
        "async-std ",
        "rustls-pemfile ",
    ] {
        assert!(
            !tree.lines().any(|l| l.starts_with(banned)),
            "{banned} in the tree"
        );
    }
}

#[test]
fn test_t27_half_open_handshakes_hold_no_rustls_state() {
    // Sessions that have sent one byte of a ClientHello hold only tls-net's
    // session struct: the rustls connection is created after the hello.
    let server = site()
        .limits(HandshakeLimits::server().max_in_progress(10_000))
        .build()
        .unwrap();
    let mut sessions = Vec::with_capacity(10_000);
    let mut out = vec![0u8; 64 * 1024];
    for _ in 0..10_000 {
        let mut s = server.accept().unwrap();
        let mut one = [22u8];
        let p = s.step(&mut one, &mut out).unwrap();
        assert_eq!(p.event, tls_net::Event::NeedInput);
        sessions.push(s);
    }
    assert_eq!(server.stats().in_progress, 10_000);
    assert!(server.accept().is_err(), "the cap holds");
    assert!(
        std::mem::size_of::<tls_net::ServerSession>() < 2048,
        "{}",
        std::mem::size_of::<tls_net::ServerSession>()
    );
    drop(sessions);
    assert_eq!(server.stats().in_progress, 0);
}

#[test]
fn test_t8_no_ticket_key_bytes_in_debug() {
    let secret = [0xa5u8; 32];
    let seed = || TicketSeed::from_bytes(secret);
    let ratchet = TicketMode::Ratchet {
        seed: seed(),
        period: Duration::from_secs(3600),
    };
    let derived = TicketMode::Derived {
        root: seed(),
        period: Duration::from_secs(3600),
    };
    let builder = site().tickets(ratchet.clone(), 2);
    let server = builder.clone().build().unwrap();
    let handle = server.ticket_keys().unwrap();
    let sealed = handle.export_sealed(&[7; 32]).unwrap();
    let outputs = [
        format!("{ratchet:?}"),
        format!("{derived:?}"),
        format!("{builder:?}"),
        format!("{server:?}"),
        format!("{handle:?}"),
        format!("{sealed:?}"),
    ];
    let hexed = secret.iter().fold(String::new(), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    });
    for out in &outputs {
        assert!(!out.contains(&hexed[..16]), "hex key bytes in {out}");
        assert!(
            !out.contains(&format!("{:?}", &secret[..8])[1..20]),
            "listed key bytes in {out}"
        );
        assert!(!out.contains("165, 165, 165"), "listed key bytes in {out}");
    }
}
