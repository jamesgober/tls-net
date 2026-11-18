#![no_main]

//! `HostScope::permits` on arbitrary `Host` values: never panics, and never
//! permits a value that is not a host name, IPv4, or bracketed IPv6 address.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tls_net::fuzz::host_value(data);
});
