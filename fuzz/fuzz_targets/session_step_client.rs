#![no_main]

//! Arbitrary bytes as the server's reply into a client session; `encrypt`
//! and `close` are called between steps too (D-126).

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tls_net::{Event, TlsClient};

fn client() -> &'static TlsClient {
    static CLIENT: OnceLock<TlsClient> = OnceLock::new();
    CLIENT.get_or_init(|| tls_net::client_with_ca_pem(include_bytes!("../../tests/data/ca.pem")).unwrap())
}

fuzz_target!(|data: &[u8]| {
    let mut session = client().connect("localhost").unwrap();
    let mut out = vec![0u8; 64 * 1024];
    let p = session.step(&mut [], &mut out).unwrap();
    assert!(p.written > 0);
    let mut input = data.to_vec();
    for _ in 0..64 {
        match session.step(&mut input, &mut out) {
            Ok(p) => {
                let (consumed, need) = (p.consumed, matches!(p.event, Event::NeedInput));
                input.drain(..consumed);
                let _ = session.encrypt(b"x", &mut out);
                if need && consumed == 0 {
                    let _ = session.close(&mut out);
                    return;
                }
            }
            Err(_) => return,
        }
    }
});
