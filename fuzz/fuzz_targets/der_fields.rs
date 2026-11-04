#![no_main]

//! The DER field reader on arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tls_net::fuzz::der_fields(data);
});
