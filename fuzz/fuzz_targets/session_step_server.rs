#![no_main]

//! Arbitrary bytes as ciphertext into a server session, split into chunks
//! chosen by the first byte: never panics, budgets hold. `encrypt` and
//! `close` are called between chunks too (D-126).

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tls_net::{Event, KeySource, TlsServer};

fn server() -> &'static TlsServer {
    static SERVER: OnceLock<TlsServer> = OnceLock::new();
    SERVER.get_or_init(|| {
        let chain = include_bytes!("../../tests/data/site.pem");
        let key = include_bytes!("../../tests/data/site.key");
        TlsServer::builder().certificate(chain, KeySource::Pem(key)).unwrap().build().unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, rest)) = data.split_first() else { return };
    let chunk = usize::from(chunk).max(1);
    let mut session = server().accept().unwrap();
    let mut input = Vec::new();
    let mut out = vec![0u8; 64 * 1024];
    for part in rest.chunks(chunk) {
        input.extend_from_slice(part);
        loop {
            match session.step(&mut input, &mut out) {
                Ok(p) => {
                    let (consumed, written) = (p.consumed, p.written);
                    let need = matches!(p.event, Event::NeedInput);
                    assert!(consumed <= input.len() && written <= out.len());
                    input.drain(..consumed);
                    if need && consumed == 0 && written == 0 {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        let _ = session.encrypt(b"x", &mut out);
    }
    let _ = session.close(&mut out);
});
