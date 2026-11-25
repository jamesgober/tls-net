#![no_main]

//! Arbitrary server CRYPTO data into a QUIC client session, as pieces of
//! `u16 length || bytes`, each read in one call (one per encryption
//! level): never panics, and a failed session hands out nothing more.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tls_net::{Alpn, TlsClient, TrustAnchors};

fn client() -> &'static TlsClient {
    static CLIENT: OnceLock<TlsClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let ca = include_bytes!("../../tests/data/ca.pem");
        TlsClient::builder()
            .trust(TrustAnchors::from_pem(ca).unwrap())
            .alpn(&[Alpn::new(b"h3").unwrap()])
            .build()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let mut session = client().connect_quic("localhost", vec![1, 2, 3]).unwrap();
    let mut out = Vec::new();
    while session.write_handshake(&mut out).is_some() {}
    let mut rest = data;
    while rest.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let (piece, tail) = rest[2..].split_at(len);
        rest = tail;
        if session.read_handshake(piece).is_err() {
            let mut out = Vec::new();
            assert!(session.write_handshake(&mut out).is_none() && out.is_empty());
            return;
        }
        let mut out = Vec::new();
        while session.write_handshake(&mut out).is_some() {}
        let _ = (session.info(), session.peer_transport_parameters(), session.alpn());
    }
});
