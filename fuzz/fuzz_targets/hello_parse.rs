#![no_main]

//! The ClientHello parser on arbitrary bytes: never panics, never reads past
//! its input, and every accessor of a complete view works.

use libfuzzer_sys::fuzz_target;
use tls_net::{HelloLimits, HelloParse, HelloParser};

fuzz_target!(|data: &[u8]| {
    let limits = HelloLimits::new();
    if let Ok(HelloParse::Complete { view, length }) = HelloParser::parse(data, &limits) {
        assert!(length <= data.len());
        let _ = view.cipher_suites().count();
        let _ = view.extension_types().count();
        let _ = view.extensions().count();
        let _ = view.alpn().count();
        let _ = view.groups().count();
        let _ = view.signature_algorithms().count();
        let _ = view.supported_versions().count();
        let _ = view.key_share_groups().count();
        let _ = view.point_formats().count();
        let _ = (view.server_name(), view.normalized_server_name(), view.raw(), format!("{view:?}"));
        let ja4 = tls_net::Ja4::compute(&view);
        assert_eq!(ja4.as_str().len(), 36);
        let mut s = String::new();
        tls_net::ja4_raw(&view, &mut s);
        tls_net::ja4_original(&view, &mut s);
        tls_net::ja3_string(&view, &mut s);
    }
});
