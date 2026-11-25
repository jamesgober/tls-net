#![no_main]

//! The ClientHello parser on arbitrary bytes as QUIC CRYPTO data (no record
//! layer): never panics, never reads past its input, and a complete view is
//! marked as QUIC, with a JA4 that starts with `q`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tls_net::fuzz::quic_hello(data);
});
