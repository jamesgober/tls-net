#![no_main]

//! Arbitrary bytes as CRYPTO data into a QUIC server session, split into
//! chunks chosen by the first byte: never panics, and a failed session
//! hands out nothing more.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tls_net::{Alpn, KeySource, TlsServer};

fn server() -> &'static TlsServer {
    static SERVER: OnceLock<TlsServer> = OnceLock::new();
    SERVER.get_or_init(|| {
        let chain = include_bytes!("../../tests/data/site.pem");
        let key = include_bytes!("../../tests/data/site.key");
        TlsServer::builder()
            .certificate(chain, KeySource::Pem(key))
            .unwrap()
            .alpn(&[Alpn::new(b"h3").unwrap()])
            .build()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, rest)) = data.split_first() else { return };
    let chunk = usize::from(chunk).max(1);
    let mut session = server().accept_quic(vec![1, 2, 3]).unwrap();
    for part in rest.chunks(chunk) {
        if session.read_handshake(part).is_err() {
            assert!(session.is_handshaking());
            let mut out = Vec::new();
            assert!(session.write_handshake(&mut out).is_none() && out.is_empty());
            assert!(session.read_handshake(part).is_err());
            return;
        }
        let mut out = Vec::new();
        while session.write_handshake(&mut out).is_some() {}
        let _ = (session.peer_transport_parameters(), session.alpn(), session.negotiated_suite());
    }
    assert_eq!(session.alert(), None);
});
