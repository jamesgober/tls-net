#![no_main]

//! Arbitrary bytes as a session ticket: never panics, never opens (T-12).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(!tls_net::fuzz::ticket_open(data), "a forged ticket opened");
});
