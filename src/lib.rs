//! # tls_net
//!
//! TLS for net-io: a thin adapter that plugs rustls into net-io's TLS seam, with certificate loading and hot reload, SNI, ALPN, client certificates, ClientHello capture, and a policy shaped by shield-sec.
//!
//! ## Status
//!
//! Scaffold. The design is written down in `dev/PLAN.md` and the milestone
//! schedule in `dev/ROADMAP.md` (both in the
//! [repository](https://github.com/jamesgober/tls-net)); the public API
//! begins with `0.2.0`.

#![doc(html_root_url = "https://docs.rs/tls-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
