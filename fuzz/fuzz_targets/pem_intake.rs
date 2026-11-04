#![no_main]

//! PEM and DER key and certificate intake on arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tls_net::fuzz::pem_intake(data);
});
