//! Property tests: the parser never panics or over-reads, normalisation is
//! idempotent, and chunking never changes what a session delivers.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use common::{End, RawHello, data, pump, send};
use proptest::prelude::*;
use tls_net::{
    HelloLimits, HelloParse, KeySource, TlsClient, TlsServer, TrustAnchors, parse_client_hello,
};

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn prop_hello_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..20_000)) {
        if let Ok(HelloParse::Complete { view, length }) = parse_client_hello(&bytes, &HelloLimits::new()) {
            prop_assert!(length <= bytes.len());
            let _ = (view.cipher_suites().count(), view.extensions().count(), view.alpn().count());
        }
    }

    #[test]
    fn prop_hello_parser_tls_prefix_never_panics(body in proptest::collection::vec(any::<u8>(), 0..2_000), split in 1usize..64) {
        // A plausible record and handshake header in front of random bytes,
        // split into records of `split` bytes.
        let mut msg = vec![1u8];
        msg.extend(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        msg.extend(&body);
        let mut input = Vec::new();
        for part in msg.chunks(split) {
            input.extend([22, 3, 1]);
            input.extend(u16::try_from(part.len()).unwrap().to_be_bytes());
            input.extend(part);
        }
        let limits = HelloLimits::new().max_records(16).unwrap();
        let _ = parse_client_hello(&input, &limits);
    }

    #[test]
    fn prop_normalize_idempotent(name in "[A-Za-z0-9.\\-]{0,80}") {
        if let Some(n) = tls_net::normalize_server_name(&name) {
            prop_assert_eq!(tls_net::normalize_server_name(n.as_str()), Some(n));
            prop_assert!(n.as_str().bytes().all(|b| !b.is_ascii_uppercase()));
        }
    }

    #[test]
    fn prop_hello_split_into_records_parses_the_same(name in "[a-z]{1,20}\\.test", split in 40usize..300) {
        let whole = RawHello::tls12(&[0xc02b, 0xc02f]).sni(name.as_bytes()).record();
        // Re-frame the same handshake message into records of `split` bytes.
        let msg = &whole[5..];
        let mut framed = Vec::new();
        for part in msg.chunks(split) {
            framed.extend([22, 3, 1]);
            framed.extend(u16::try_from(part.len()).unwrap().to_be_bytes());
            framed.extend(part);
        }
        let limits = HelloLimits::new().max_records(16).unwrap();
        let a = parse_client_hello(&whole, &limits).unwrap();
        let b = parse_client_hello(&framed, &limits).unwrap();
        match (a, b) {
            (HelloParse::Complete { view: a, .. }, HelloParse::Complete { view: b, .. }) => {
                prop_assert_eq!(a.normalized_server_name(), b.normalized_server_name());
                prop_assert_eq!(a.cipher_suites().collect::<Vec<_>>(), b.cipher_suites().collect::<Vec<_>>());
                prop_assert_eq!(a.extension_types().collect::<Vec<_>>(), b.extension_types().collect::<Vec<_>>());
            }
            _ => prop_assert!(false, "both must be complete"),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn prop_any_chunking_delivers_the_same_plaintext(chunk in 1usize..4_000, sizes in proptest::collection::vec(1usize..20_000, 1..6)) {
        let server = TlsServer::builder().certificate(&data("site.pem"), KeySource::Pem(&data("site.key"))).unwrap().build().unwrap();
        let client = TlsClient::builder().trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap()).build().unwrap();
        let (mut s, mut c) = (server.accept().unwrap(), client.connect("localhost").unwrap());
        let (mut se, mut ce) = (End::new(chunk), End::new(chunk));
        pump(&mut s, &mut se, &mut c, &mut ce);
        prop_assert!(se.complete && ce.complete);
        let msg: Vec<u8> = sizes.iter().enumerate().flat_map(|(i, n)| std::iter::repeat_n(i as u8, *n)).collect();
        send(&mut c, &msg, 16_384, &mut se.inbox);
        pump(&mut s, &mut se, &mut c, &mut ce);
        prop_assert_eq!(se.received, msg);
    }
}
