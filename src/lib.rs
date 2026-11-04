//! # tls_net
//!
//! TLS for net-io: a thin adapter that plugs rustls into net-io's TLS seam,
//! with certificate loading and hot reload, SNI, ALPN, client certificates,
//! ClientHello capture, and a policy that cannot express anything weak.
//!
//! tls-net never implements TLS or cryptography. rustls does the protocol
//! and its provider (aws-lc-rs by default) does the cryptography; tls-net
//! drives rustls's sans-IO connection API over buffers the caller owns.
//!
//! ## Status
//!
//! Design lock (`0.2.0`). The public API that `0.3.0` to `1.0.0` build is
//! written down in `docs/API.md`, and the design and decisions in
//! `dev/PLAN.md` (both in the
//! [repository](https://github.com/jamesgober/tls-net)). This release ships
//! only [`VERSION`] and declares the Cargo features; the server, the client,
//! and the net-io adapter arrive in `0.3.0`.
//!
//! ## Features
//!
//! | Feature | Default | Effect |
//! |---|---|---|
//! | `aws-lc` | on | aws-lc-rs provider with X25519MLKEM768 |
//! | `ring` | off | ring provider, without post-quantum groups |
//! | `prebuilt-nasm` | off | Windows x86-64 without NASM |
//! | `webpki-roots` | on | bundled Mozilla roots for clients |
//! | `platform-verifier` | off | the operating system's trust store |
//! | `key-vault` | on | keys and ticket keys held in key-vault |
//! | `net-io` | off | the net-io seam (on by default from `0.3.0`) |
//! | `ja3-md5` | off | JA3 MD5 fingerprint label |
//! | `rustls-escape-hatch` | off | raw rustls configurations, outside semver |
//! | `dangerous-keylog` | off | key log output for debugging only |

#![doc(html_root_url = "https://docs.rs/tls-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Crate version string, populated by Cargo at build time.
///
/// ```
/// assert_eq!(tls_net::VERSION, env!("CARGO_PKG_VERSION"));
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn test_version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
