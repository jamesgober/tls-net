//! QUIC (feature `quic`): the RFC 9001 appendix A vectors through tls-net's
//! keys, handshakes between a client and a server in memory, the refusals,
//! the gates a QUIC accept shares with TCP, and the key update chain.

#![cfg(all(feature = "quic", any(feature = "aws-lc", feature = "ring")))]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::data;
use tls_net::quic::{KeyChange, Keys, QuicSession, Secrets, Side, initial_keys, retry_tag};
use tls_net::{
    Alpn, ClientAuth, HandshakeKind, HandshakeLimits, HelloContext, HelloHook, HelloLimits,
    HelloVerdict, HostPolicy, KeySource, Policy, RefuseReason, SessionState, TlsClient, TlsError,
    TlsServer, TrustAnchors, UnknownName, Version,
};

fn h(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "{s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn alpn(name: &[u8]) -> Alpn {
    Alpn::new(name).unwrap()
}

fn ca() -> TrustAnchors {
    TrustAnchors::from_pem(&data("ca.pem")).unwrap()
}

fn server_builder() -> tls_net::ServerBuilder {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .alpn(&[alpn(b"h3")])
}

fn server() -> TlsServer {
    server_builder().build().unwrap()
}

fn client_with(protocols: &[Alpn]) -> TlsClient {
    TlsClient::builder()
        .trust(ca())
        .alpn(protocols)
        .build()
        .unwrap()
}

fn client() -> TlsClient {
    client_with(&[alpn(b"h3")])
}

/// What one endpoint received from the handshake.
#[derive(Default)]
struct Got {
    handshake: Option<Keys>,
    one_rtt: Option<(Keys, Secrets)>,
}

impl Got {
    fn take(&mut self, change: KeyChange) {
        match change {
            KeyChange::Handshake { keys } => self.handshake = Some(keys),
            KeyChange::OneRtt { keys, next } => self.one_rtt = Some((keys, next)),
        }
    }
}

/// Moves everything `from` has to send into `to`. `Err(true)` when `to`
/// failed reading it.
fn flush(
    from: &mut QuicSession,
    to: &mut QuicSession,
    got: &mut Got,
    chunk: usize,
) -> Result<bool, (bool, TlsError)> {
    let mut moved = false;
    loop {
        let mut out = Vec::new();
        let change = from.write_handshake(&mut out);
        if !out.is_empty() {
            moved = true;
            for piece in out.chunks(chunk) {
                to.read_handshake(piece).map_err(|e| (true, e))?;
            }
        }
        match change {
            Some(c) => {
                moved = true;
                got.take(c);
            }
            None if out.is_empty() => return Ok(moved),
            None => {}
        }
    }
}

/// Runs a handshake to its end. On failure: which side failed (`true` for
/// the server) and the error.
fn handshake_in(
    c: &mut QuicSession,
    s: &mut QuicSession,
    chunk: usize,
) -> Result<(Got, Got), (bool, TlsError)> {
    let (mut cg, mut sg) = (Got::default(), Got::default());
    for _ in 0..32 {
        let a = flush(c, s, &mut cg, chunk)?;
        let b = flush(s, c, &mut sg, chunk).map_err(|(to, e)| (!to, e))?;
        if !a && !b {
            break;
        }
    }
    Ok((cg, sg))
}

fn handshake(c: &mut QuicSession, s: &mut QuicSession) -> Result<(Got, Got), (bool, TlsError)> {
    handshake_in(c, s, usize::MAX)
}

/// `sender` seals a packet and `receiver` opens it.
fn exchange(sender: &tls_net::quic::PacketKey, receiver: &tls_net::quic::PacketKey, pn: u64) {
    let header = b"short header";
    let plain = b"application data".to_vec();
    let mut packet = plain.clone();
    let tag = sender.seal(pn, header, &mut packet).unwrap();
    assert_ne!(packet, plain);
    packet.extend_from_slice(&tag);
    let n = receiver.open(pn, header, &mut packet).unwrap();
    assert_eq!(&packet[..n], &plain[..]);
    packet[0] ^= 1;
    assert_eq!(
        receiver.open(pn, header, &mut packet),
        Err(TlsError::DecryptFailed)
    );
}

// RFC 9001 appendix A. The bytes are the RFC's.

const DCID: &str = "8394c8f03e515708";

const CLIENT_CRYPTO: &[&str] = &[
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69",
    "484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a",
    "00080006001d0017001800100007000504616c706e000500050100000000003300260024001d0020",
    "9370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
    "0d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffff",
    "ffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806",
    "048000ffff",
];
const CLIENT_PACKET: &[&str] = &[
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8ba",
    "b936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a12",
    "82a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6",
    "005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde5",
    "35d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e",
    "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e3",
    "0c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63",
    "ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d874",
    "3eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf8",
    "2a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc29",
    "62e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f0",
    "5796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c",
    "1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a",
    "0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd",
    "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de3",
    "54270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a",
    "4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e5",
    "66d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef",
    "023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbb",
    "e2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd8",
    "04a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc852",
    "44259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5",
    "e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
];
const SERVER_PAYLOAD: &[&str] = &[
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566d",
    "c5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d10",
    "81287c834d5311bcf32bb9da1a002b00020304",
];
const SERVER_PACKET: &[&str] = &[
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a",
    "1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9",
    "c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d",
    "20398c276456cbc42158407dd074ee",
];

/// Protects `header || payload` with an Initial packet's keys, exactly as
/// RFC 9001 section 5.4 says: seal, then mask the first byte's low 4 bits
/// and the packet number from a sample 4 bytes after its start.
fn protect(keys: &Keys, header: &[u8], pn_offset: usize, pn: u64, payload: &[u8]) -> Vec<u8> {
    let mut body = payload.to_vec();
    let tag = keys.local.packet.seal(pn, header, &mut body).unwrap();
    let mut packet = [header, &body, &tag].concat();
    let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
    let mask = keys.local.header.mask(&sample).unwrap();
    assert_eq!(mask[0] & 0xe0, 0, "the top 3 bits are never set");
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

/// The peer's side of `protect`: unmask, then open.
fn unprotect(keys: &Keys, packet: &[u8], pn_offset: usize, pn: u64) -> Vec<u8> {
    let mut packet = packet.to_vec();
    let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
    let mask = keys.remote.header.mask(&sample).unwrap();
    packet[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    let (header, rest) = packet.split_at_mut(pn_offset + pn_len);
    let n = keys.remote.packet.open(pn, header, rest).unwrap();
    rest[..n].to_vec()
}

#[test]
fn test_a2_client_initial_is_the_rfc_packet() {
    let header = h("c300000001088394c8f03e5157080000449e00000002");
    let mut payload = h(&CLIENT_CRYPTO.concat());
    payload.resize(1162, 0);
    let client = initial_keys(&h(DCID), Side::Client).unwrap();
    let packet = protect(&client, &header, 18, 2, &payload);
    assert_eq!(packet, h(&CLIENT_PACKET.concat()));
    let server = initial_keys(&h(DCID), Side::Server).unwrap();
    assert_eq!(unprotect(&server, &packet, 18, 2), payload);
}

#[test]
fn test_a3_server_initial_is_the_rfc_packet() {
    let header = h("c1000000010008f067a5502a4262b50040750001");
    let payload = h(&SERVER_PAYLOAD.concat());
    let server = initial_keys(&h(DCID), Side::Server).unwrap();
    let packet = protect(&server, &header, 18, 1, &payload);
    assert_eq!(packet, h(&SERVER_PACKET.concat()));
    let client = initial_keys(&h(DCID), Side::Client).unwrap();
    assert_eq!(unprotect(&client, &packet, 18, 1), payload);
}

#[test]
fn test_a4_retry_tag_is_the_rfc_tag() {
    // The Retry Pseudo-Packet: the original DCID with its length, then the
    // Retry packet without its tag.
    let retry = h("ff000000010008f067a5502a4262b5746f6b656e");
    let pseudo = [&[8u8][..], &h(DCID), &retry].concat();
    assert_eq!(
        retry_tag(&pseudo).unwrap().to_vec(),
        h("04a265ba2eff4d829058fb3f0f2496ba")
    );
    let mut other = pseudo.clone();
    other[1] ^= 1;
    assert_ne!(retry_tag(&other).unwrap(), retry_tag(&pseudo).unwrap());
}

#[test]
fn test_initial_keys_connection_id_lengths() {
    assert!(initial_keys(&[], Side::Client).is_ok());
    assert!(initial_keys(&[7; 20], Side::Server).is_ok());
    assert_eq!(
        initial_keys(&[7; 21], Side::Client).unwrap_err(),
        TlsError::QuicInput {
            what: "connection ID"
        }
    );
    let keys = initial_keys(&h(DCID), Side::Client).unwrap();
    assert_eq!(keys.local.packet.tag_len(), 16);
    assert!(keys.local.packet.confidentiality_limit() > 0);
    assert!(keys.local.packet.integrity_limit() > 0);
    // The client's sealing key is the server's opening key.
    let server = initial_keys(&h(DCID), Side::Server).unwrap();
    exchange(&keys.local.packet, &server.remote.packet, 0);
    exchange(&server.local.packet, &keys.remote.packet, 1);
}

#[test]
fn test_handshake_in_memory_reaches_one_rtt() {
    let srv = server();
    let mut c = client()
        .connect_quic("localhost", b"client transport parameters".to_vec())
        .unwrap();
    let mut s = srv
        .accept_quic(b"server transport parameters".to_vec())
        .unwrap();
    assert_eq!(s.state(), SessionState::Hello);
    assert_eq!(c.state(), SessionState::Handshake);
    assert!(c.is_handshaking() && s.is_handshaking());
    assert!(c.info().is_none());

    let (cg, sg) = handshake(&mut c, &mut s).unwrap();
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(s.state(), SessionState::Established);
    assert_eq!(
        s.peer_transport_parameters(),
        Some(&b"client transport parameters"[..])
    );
    assert_eq!(
        c.peer_transport_parameters(),
        Some(&b"server transport parameters"[..])
    );
    assert_eq!(c.alpn(), Some(&b"h3"[..]));
    assert_eq!(s.alpn(), Some(&b"h3"[..]));
    assert_eq!(s.server_name(), Some("localhost"));
    assert_eq!(c.server_name(), Some("localhost"));
    assert!(c.negotiated_suite().is_some());
    assert_eq!(c.negotiated_suite(), s.negotiated_suite());
    assert_eq!(c.alert(), None);

    let info = s.info().unwrap();
    assert_eq!(info.version, Version::Tls13);
    assert_eq!(info.kind, HandshakeKind::Full);
    assert_eq!(info.alpn, Some(&b"h3"[..]));
    let ja4 = s.fingerprint().unwrap().ja4.unwrap();
    assert!(ja4.as_str().starts_with('q'), "{ja4}");
    let peer = c.info().unwrap().peer.unwrap();
    assert!(peer.dns_names.iter().any(|n| n == "localhost"));

    // Each level's keys work across the two ends.
    let (ch, sh) = (cg.handshake.unwrap(), sg.handshake.unwrap());
    exchange(&ch.local.packet, &sh.remote.packet, 0);
    exchange(&sh.local.packet, &ch.remote.packet, 0);
    let ((c1, mut cnext), (s1, mut snext)) = (cg.one_rtt.unwrap(), sg.one_rtt.unwrap());
    exchange(&c1.local.packet, &s1.remote.packet, 7);
    exchange(&s1.local.packet, &c1.remote.packet, 7);
    // A key update on both ends gives matching keys again, and new ones.
    for pn in 0..2 {
        let (cn, sn) = (cnext.next_packet_keys(), snext.next_packet_keys());
        exchange(&cn.local, &sn.remote, pn);
        exchange(&sn.local, &cn.remote, pn);
        let header = b"h";
        let mut a = b"same input".to_vec();
        let mut b = a.clone();
        let ta = cn.local.seal(9, header, &mut a).unwrap();
        let tb = c1.local.packet.seal(9, header, &mut b).unwrap();
        assert_ne!((a, ta), (b, tb), "a new key phase has new keys");
    }
    assert_eq!(srv.stats().in_progress, 0);
    assert_eq!(srv.stats().handshakes_full, 1);
}

#[test]
fn test_handshake_with_crypto_data_split_into_single_bytes() {
    let mut c = client().connect_quic("localhost", vec![1]).unwrap();
    let mut s = server().accept_quic(vec![2]).unwrap();
    handshake_in(&mut c, &mut s, 1).unwrap();
    assert!(!c.is_handshaking() && !s.is_handshaking());
}

#[test]
fn test_resumption_over_quic() {
    let srv = server();
    let cl = client();
    for kind in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let mut c = cl.connect_quic("localhost", vec![1]).unwrap();
        let mut s = srv.accept_quic(vec![2]).unwrap();
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.info().unwrap().kind, kind);
    }
}

#[test]
fn test_no_alpn_refused_at_construction() {
    let e = TlsClient::builder()
        .trust(ca())
        .build()
        .unwrap()
        .connect_quic("localhost", vec![])
        .unwrap_err();
    assert!(matches!(e, TlsError::PolicyInvalid { .. }), "{e}");
    let bare = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap();
    let e = bare.accept_quic(vec![]).unwrap_err();
    assert!(matches!(e, TlsError::PolicyInvalid { .. }), "{e}");
    assert_eq!(bare.stats().in_progress, 0, "no slot is taken");
    // A host group without ALPN is enough to refuse: its group is known
    // only once the hello has arrived.
    let mixed = server_builder()
        .host(&["admin.example.test"], HostPolicy::new().alpn(&[]))
        .unwrap()
        .build()
        .unwrap();
    assert!(mixed.accept_quic(vec![]).is_err());
}

#[test]
fn test_tls12_only_policy_refused_at_construction() {
    let tls12 = Policy::compatible().versions(&[Version::Tls12]).unwrap();
    let srv = server_builder().policy(tls12.clone()).build().unwrap();
    assert!(matches!(
        srv.accept_quic(vec![]).unwrap_err(),
        TlsError::PolicyInvalid { .. }
    ));
    let cl = TlsClient::builder()
        .trust(ca())
        .alpn(&[alpn(b"h3")])
        .policy(tls12)
        .build()
        .unwrap();
    assert!(matches!(
        cl.connect_quic("localhost", vec![]).unwrap_err(),
        TlsError::PolicyInvalid { .. }
    ));
}

#[test]
fn test_policy_with_tls12_still_negotiates_tls13() {
    // The default policy allows TLS 1.2 for TCP; QUIC uses TLS 1.3 only.
    let mut c = client().connect_quic("localhost", vec![1]).unwrap();
    let mut s = server_builder()
        .policy(Policy::compatible())
        .build()
        .unwrap()
        .accept_quic(vec![2])
        .unwrap();
    handshake(&mut c, &mut s).unwrap();
    assert_eq!(s.info().unwrap().version, Version::Tls13);
}

#[test]
fn test_alpn_mismatch_fails_with_alert_120() {
    let srv = server();
    let mut c = client_with(&[alpn(b"hq-interop")])
        .connect_quic("localhost", vec![1])
        .unwrap();
    let mut s = srv.accept_quic(vec![2]).unwrap();
    let (server_failed, e) = handshake(&mut c, &mut s).err().unwrap();
    assert!(server_failed);
    assert_eq!(e, TlsError::NoApplicationProtocol);
    assert_eq!(s.alert(), Some(120));
    assert_eq!(s.state(), SessionState::Failed);
    let mut out = Vec::new();
    assert!(s.write_handshake(&mut out).is_none() && out.is_empty());
    assert_eq!(s.read_handshake(b"x"), Err(TlsError::SessionFailed));
    assert_eq!(srv.stats().in_progress, 0);
    assert_eq!(srv.stats().handshakes_failed, 1);
}

/// A TCP client's ClientHello without ALPN, as QUIC CRYPTO data (the
/// handshake message, without its record header).
fn hello_without_alpn() -> Vec<u8> {
    let tcp = TlsClient::builder().trust(ca()).build().unwrap();
    let mut session = tcp.connect("localhost").unwrap();
    let mut out = vec![0u8; tls_net::MIN_OUTPUT_BUFFER];
    let p = session.step(&mut [], &mut out).unwrap();
    out[5..p.written].to_vec()
}

#[test]
fn test_hello_without_alpn_refused_with_alert_120() {
    let srv = server();
    let mut s = srv.accept_quic(vec![]).unwrap();
    let e = s.read_handshake(&hello_without_alpn()).unwrap_err();
    assert_eq!(e, TlsError::NoApplicationProtocol);
    assert_eq!(s.alert(), Some(120));
    assert_eq!(srv.stats().hello_refusals, 1);
    assert_eq!(srv.stats().in_progress, 0);
}

#[test]
fn test_record_framed_hello_is_malformed_without_an_alert() {
    let mut record = vec![22, 3, 1, 0, 0];
    record.extend_from_slice(&hello_without_alpn());
    let mut s = server().accept_quic(vec![]).unwrap();
    assert_eq!(
        s.read_handshake(&record).unwrap_err(),
        TlsError::HelloMalformed
    );
    assert_eq!(s.alert(), None);
}

#[test]
fn test_hello_over_budget_refused() {
    let srv = server_builder()
        .hello_limits(HelloLimits::new().max_hello_bytes(512).unwrap())
        .build()
        .unwrap();
    let mut s = srv.accept_quic(vec![]).unwrap();
    // A handshake header announcing a 1,000-byte ClientHello.
    assert_eq!(
        s.read_handshake(&[1, 0, 0x03, 0xe8]).unwrap_err(),
        TlsError::HelloTooLarge
    );
    assert_eq!(srv.stats().hello_refusals, 1);
}

#[test]
fn test_handshake_budget_applies() {
    let srv = server_builder()
        .limits(HandshakeLimits::server().max_handshake_bytes(4096).unwrap())
        .build()
        .unwrap();
    let mut s = srv.accept_quic(vec![]).unwrap();
    s.read_handshake(&[1, 0, 0x02]).unwrap();
    assert_eq!(
        s.read_handshake(&vec![0; 5000]).unwrap_err(),
        TlsError::HandshakeTooLarge
    );
}

struct Deny(AtomicUsize);

impl HelloHook for Deny {
    fn on_client_hello(&self, ctx: &HelloContext<'_>) -> HelloVerdict {
        assert!(ctx.view.is_quic());
        assert_eq!(ctx.view.record_version(), 0);
        assert!(ctx.fingerprint.ja4.unwrap().as_str().starts_with('q'));
        self.0.fetch_add(1, Ordering::Relaxed);
        HelloVerdict::Refuse(RefuseReason::Policy)
    }
}

#[test]
fn test_hello_hook_refuses_without_an_alert() {
    let hook = Arc::new(Deny(AtomicUsize::new(0)));
    let srv = server_builder().hello_hook(hook.clone()).build().unwrap();
    let mut c = client().connect_quic("localhost", vec![]).unwrap();
    let mut s = srv.accept_quic(vec![]).unwrap();
    let (server_failed, e) = handshake(&mut c, &mut s).err().unwrap();
    assert!(server_failed);
    assert_eq!(e, TlsError::Refused(RefuseReason::Policy));
    assert_eq!(s.alert(), None);
    assert_eq!(hook.0.load(Ordering::Relaxed), 1);
    assert_eq!(srv.stats().hello_refusals, 1);
}

#[test]
fn test_unknown_name_refused_with_alert_112() {
    let srv = server_builder()
        .unknown_name(UnknownName::Refuse)
        .build()
        .unwrap();
    let cl = TlsClient::builder()
        .trust(ca())
        .alpn(&[alpn(b"h3")])
        .build()
        .unwrap();
    let mut c = cl.connect_quic("unknown.invalid", vec![]).unwrap();
    let mut s = srv.accept_quic(vec![]).unwrap();
    let (_, e) = handshake(&mut c, &mut s).err().unwrap();
    assert_eq!(e, TlsError::UnknownServerName);
    assert_eq!(s.alert(), Some(112));
}

#[test]
fn test_host_policy_selects_its_group_and_scope() {
    // The admin host requires a client certificate over QUIC as over TCP,
    // and has its own ALPN.
    let srv = server_builder()
        .host(
            &["admin.example.test"],
            HostPolicy::new()
                .client_auth(ClientAuth::required(ca()))
                .alpn(&[alpn(b"admin")]),
        )
        .unwrap()
        .build()
        .unwrap();
    let anonymous = client_with(&[alpn(b"admin")]);
    let mut c = anonymous
        .connect_quic("admin.example.test", vec![])
        .unwrap();
    let mut s = srv.accept_quic(vec![]).unwrap();
    assert!(handshake(&mut c, &mut s).is_err(), "no client certificate");

    let with_cert = TlsClient::builder()
        .trust(ca())
        .alpn(&[alpn(b"admin")])
        .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
        .unwrap()
        .build()
        .unwrap();
    let mut c = with_cert
        .connect_quic("admin.example.test", vec![])
        .unwrap();
    let mut s = srv.accept_quic(vec![]).unwrap();
    handshake(&mut c, &mut s).unwrap();
    let info = s.info().unwrap();
    assert!(info.peer_verified);
    assert_eq!(info.alpn, Some(&b"admin"[..]));
    let scope = srv.host_scope(s.server_name());
    assert!(scope.permits("admin.example.test"));
    assert!(!scope.permits("www.example.test"));

    // The default group's ALPN does not reach the admin host.
    let mut c = client().connect_quic("admin.example.test", vec![]).unwrap();
    let mut s = srv.accept_quic(vec![]).unwrap();
    assert!(handshake(&mut c, &mut s).is_err());
}

#[test]
fn test_capacity_gate_and_slot_release() {
    let srv = server_builder()
        .limits(HandshakeLimits::server().max_in_progress(1))
        .build()
        .unwrap();
    let first = srv.accept_quic(vec![]).unwrap();
    assert_eq!(
        srv.accept_quic(vec![]).unwrap_err(),
        TlsError::HandshakeCapacity
    );
    drop(first);
    assert_eq!(srv.stats().in_progress, 0);
    let mut c = client().connect_quic("localhost", vec![]).unwrap();
    let mut s = srv.worker_acceptor().accept_quic(vec![]).unwrap();
    handshake(&mut c, &mut s).unwrap();
    assert_eq!(srv.stats().in_progress, 0, "released at completion");
    assert!(srv.accept_quic(vec![]).is_ok());
}

/// RFC 9001 appendix A.5: the ChaCha20-Poly1305 key schedule and the
/// `quic ku` step, checked against rustls's own HKDF, which then derives the
/// expected keys of each key phase from the secrets of a real handshake.
#[cfg(all(feature = "dangerous-keylog", not(feature = "fips")))]
mod key_update {
    use std::sync::Mutex;

    use rustls::crypto::cipher::{AeadKey, Iv};
    use rustls::crypto::tls13::{Hkdf, OkmBlock};

    use super::*;

    #[cfg(feature = "aws-lc")]
    use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 as CHACHA;
    #[cfg(all(feature = "ring", not(feature = "aws-lc")))]
    use rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 as CHACHA;

    fn suite() -> &'static rustls::Tls13CipherSuite {
        match CHACHA {
            rustls::SupportedCipherSuite::Tls13(t) => t,
            rustls::SupportedCipherSuite::Tls12(_) => unreachable!(),
        }
    }

    /// HKDF-Expand-Label (RFC 8446 section 7.1) with an empty context.
    fn expand(hkdf: &dyn Hkdf, secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
        let full = [b"tls13 ".as_slice(), label].concat();
        let length = u16::try_from(len).unwrap().to_be_bytes();
        let label_len = [u8::try_from(full.len()).unwrap()];
        let info: [&[u8]; 4] = [&length, &label_len, &full, &[0]];
        let mut out = vec![0; len];
        hkdf.expander_for_okm(&OkmBlock::new(secret))
            .expand_slice(&info, &mut out)
            .unwrap();
        out
    }

    /// The packet key a secret gives, built by rustls from its key and iv.
    fn packet_key(secret: &[u8]) -> Box<dyn rustls::quic::PacketKey> {
        let s = suite();
        let key: [u8; 32] = expand(s.hkdf_provider, secret, b"quic key", 32)
            .try_into()
            .unwrap();
        let iv: [u8; 12] = expand(s.hkdf_provider, secret, b"quic iv", 12)
            .try_into()
            .unwrap();
        s.quic.unwrap().packet_key(AeadKey::from(key), Iv::new(iv))
    }

    #[test]
    fn test_a5_chacha20_key_schedule_and_key_update() {
        let hkdf = suite().hkdf_provider;
        let secret = h("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        assert_eq!(
            expand(hkdf, &secret, b"quic key", 32),
            h("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        );
        assert_eq!(
            expand(hkdf, &secret, b"quic iv", 12),
            h("e0459b3474bdd0e44a41c144")
        );
        assert_eq!(
            expand(hkdf, &secret, b"quic hp", 32),
            h("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        );
        assert_eq!(
            expand(hkdf, &secret, b"quic ku", 32),
            h("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        );
        // The A.5 packet: header 4200bff4, packet number 654360564, payload
        // 01. Header protection does not touch the payload, so the sealed
        // payload and tag are the RFC packet's last 17 bytes.
        let key = packet_key(&secret);
        let mut payload = [0x01u8];
        let tag = key
            .encrypt_in_place(654_360_564, &h("4200bff4"), &mut payload)
            .unwrap();
        assert_eq!(
            [&payload[..], tag.as_ref()].concat(),
            h("655e5cd55c41f69080575d7999c25a5bfb")
        );
    }

    #[derive(Default)]
    struct Log(Mutex<Vec<(String, Vec<u8>)>>);

    impl tls_net::KeyLogSink for Log {
        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .push((label.to_owned(), secret.to_vec()));
        }
    }

    impl Log {
        fn secret(&self, label: &str) -> Vec<u8> {
            let log = self.0.lock().unwrap();
            log.iter().find(|(l, _)| l == label).unwrap().1.clone()
        }
    }

    /// Whether two keys seal alike.
    fn same(ours: &tls_net::quic::PacketKey, reference: &dyn rustls::quic::PacketKey) -> bool {
        let header = b"key phase check";
        let mut a = b"payload".to_vec();
        let mut b = a.clone();
        let ta = ours.seal(42, header, &mut a).unwrap();
        let tb = reference.encrypt_in_place(42, header, &mut b).unwrap();
        a == b && ta[..] == *tb.as_ref()
    }

    #[test]
    fn test_next_packet_keys_follow_the_quic_ku_chain() {
        let log = Arc::new(Log::default());
        let chacha = Policy::modern()
            .cipher_suites(&[tls_net::CipherSuite::Tls13ChaCha20Poly1305Sha256])
            .unwrap();
        let srv = server_builder()
            .policy(chacha)
            .dangerous_key_log(log.clone())
            .build()
            .unwrap();
        let mut c = client().connect_quic("localhost", vec![]).unwrap();
        let mut s = srv.accept_quic(vec![]).unwrap();
        let (cg, sg) = handshake(&mut c, &mut s).unwrap();
        let hkdf = suite().hkdf_provider;
        let mut client_secret = log.secret("CLIENT_TRAFFIC_SECRET_0");
        let mut server_secret = log.secret("SERVER_TRAFFIC_SECRET_0");

        let ((c1, mut cnext), (s1, mut snext)) = (cg.one_rtt.unwrap(), sg.one_rtt.unwrap());
        assert!(same(&c1.local.packet, &*packet_key(&client_secret)));
        assert!(same(&s1.local.packet, &*packet_key(&server_secret)));
        for _ in 0..2 {
            client_secret = expand(hkdf, &client_secret, b"quic ku", 32);
            server_secret = expand(hkdf, &server_secret, b"quic ku", 32);
            let (cn, sn) = (cnext.next_packet_keys(), snext.next_packet_keys());
            assert!(same(&cn.local, &*packet_key(&client_secret)));
            assert!(same(&sn.remote, &*packet_key(&client_secret)));
            assert!(same(&sn.local, &*packet_key(&server_secret)));
            assert!(same(&cn.remote, &*packet_key(&server_secret)));
        }
    }
}
