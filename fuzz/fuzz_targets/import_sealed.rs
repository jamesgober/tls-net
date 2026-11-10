#![no_main]

//! Arbitrary bytes as a ticket-key hand-off (T-24, D-130): as the sealed
//! export they never import; sealed as an export's plaintext under the right
//! key and header, only the two layouts an export has import. Never panics.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (forged, imported) = tls_net::fuzz::import_sealed(data);
    assert!(!forged, "forged ticket keys imported");
    let layout = matches!((data.first(), data.len()), (Some(0), 33) | (Some(1), 65));
    assert_eq!(imported, layout, "an export's plaintext was misread");
});
