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
//! ## Quick start
//!
//! ```no_run
//! # fn main() -> Result<(), tls_net::TlsError> {
//! // Server: certificate files from the operator, default policy, ALPN http/1.1.
//! let server = tls_net::server_from_files("/etc/tls/site.pem", "/etc/tls/site.key")?;
//! let mut session = server.accept()?; // one per accepted connection
//!
//! // Client: Mozilla roots, server verification always on.
//! let client = tls_net::client()?;
//! let mut session = client.connect("example.com")?;
//! # Ok(()) }
//! ```
//!
//! A session never touches a socket: [`ServerSession::step`] takes ciphertext
//! from a buffer the caller owns and writes records into another one, and
//! with the `net-io` feature a [`TlsServer`] is a net-io `TlsAcceptor`. The
//! full contract is in `docs/API.md` in the
//! [repository](https://github.com/jamesgober/tls-net).
//!
//! ## Features
//!
//! | Feature | Default | Effect |
//! |---|---|---|
//! | `aws-lc` | on | aws-lc-rs provider with X25519MLKEM768 |
//! | `ring` | off | ring provider, without post-quantum groups |
//! | `fips` | off | FIPS 140-3 mode over aws-lc-rs (needs CMake and Go) |
//! | `prebuilt-nasm` | off | Windows x86-64 without NASM |
//! | `webpki-roots` | on | bundled Mozilla roots for clients |
//! | `platform-verifier` | off | the operating system's trust store |
//! | `key-vault` | on | keys and ticket keys held in key-vault |
//! | `net-io` | on | the net-io seam |
//! | `ja3-md5` | off | JA3 MD5 fingerprint label |
//! | `rustls-escape-hatch` | off | raw rustls configurations, outside semver |
//! | `dangerous-keylog` | off | key log output for debugging only |

#![doc(html_root_url = "https://docs.rs/tls-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod certs;
mod client;
#[cfg(feature = "key-vault")]
mod custody;
mod der;
mod error;
mod expiry;
mod fingerprint;
mod hello;
mod hook;
mod identity;
mod limits;
#[cfg(feature = "ja3-md5")]
mod md5;
mod observe;
mod pem;
mod policy;
mod provider;
#[cfg(feature = "net-io")]
mod seam;
mod server;
mod session;
mod snapshot;
mod sni;
mod sync;
mod tickets;
mod verify;

/// Entry points for the SNI table bench only (`--cfg tls_net_bench`); the
/// table is crate-private and has no public way to be timed alone.
#[cfg(tls_net_bench)]
#[doc(hidden)]
pub mod bench {
    use std::sync::Arc;

    /// An SNI table holding `names` (and `*.`-prefixed wildcards) for one key.
    pub struct Sni(crate::sni::SniTable);

    impl Sni {
        /// Builds the table; `key_der` is a PKCS#8 key the provider accepts.
        ///
        /// # Panics
        ///
        /// On a key the provider refuses or a duplicate name.
        #[must_use]
        pub fn new(names: &[String], key_der: &[u8]) -> Sni {
            let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.to_vec().into());
            let key = crate::provider::load_key(&der).expect("key");
            let certified = Arc::new(rustls::sign::CertifiedKey::new(Vec::new(), key));
            let mut table = crate::sni::SniTable::new();
            let entry = table.add_key(certified, crate::sni::EntryKey::Other);
            for name in names {
                assert!(table.add_name(name, entry, 0), "duplicate {name}");
            }
            Sni(table)
        }

        /// Normalises `name` as a ClientHello's SNI is and looks it up.
        #[must_use]
        pub fn lookup(&self, name: &str) -> bool {
            let normalized = crate::sni::normalize_server_name(name);
            self.0
                .lookup(normalized.as_ref().map(crate::sni::NormalizedName::as_str))
                .is_some()
        }
    }

    /// The configuration cell a reload swaps (here holding a counter).
    pub struct Swap(crate::snapshot::Snapshot<u64>);

    impl Swap {
        /// A cell holding 0.
        #[must_use]
        pub fn new() -> Swap {
            Swap(crate::snapshot::Snapshot::new(0))
        }

        /// Publishes `value`; returns the new version.
        pub fn publish(&self, value: u64) -> u64 {
            self.0.publish(value)
        }

        /// Reads the current value.
        #[must_use]
        pub fn load(&self) -> u64 {
            *self.0.load()
        }
    }

    impl Default for Swap {
        fn default() -> Self {
            Swap::new()
        }
    }
}

/// Entry points for the fuzz targets only (`cargo fuzz` sets `cfg(fuzzing)`).
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzz {
    /// The DER field reader on arbitrary bytes.
    pub fn der_fields(data: &[u8]) -> bool {
        let _ = crate::der::key_form(data);
        crate::der::parse_certificate(data).is_some()
    }

    /// Opens arbitrary bytes as a session ticket: never panics, never succeeds
    /// on anything this ring did not seal.
    pub fn ticket_open(data: &[u8]) -> bool {
        use rustls::server::ProducesTickets;
        use std::sync::OnceLock;
        static RING: OnceLock<Option<crate::tickets::TicketKeyRing>> = OnceLock::new();
        let ring = RING.get_or_init(|| {
            let mode = crate::tickets::TicketMode::Ratchet {
                seed: crate::tickets::TicketSeed::from_bytes([5; 32]),
                period: std::time::Duration::from_secs(3600),
            };
            crate::tickets::TicketKeyRing::new(&mode).ok().flatten()
        });
        ring.as_ref().is_some_and(|r| r.decrypt(data).is_some())
    }

    /// PEM and DER intake on arbitrary bytes.
    pub fn pem_intake(data: &[u8]) {
        let _ = crate::pem::key_from_pem(data);
        let _ = crate::pem::key_from_der(data);
        if let Ok(certs) = crate::pem::certificates(data, 16) {
            for c in certs {
                let _ = crate::der::parse_certificate(c.as_ref());
            }
        }
    }
}

pub use certs::{KeySource, LoadLimits};
pub use client::{
    ClientBuilder, DnsName, ServerIdentity, TlsClient, TrustAnchors, client, client_with_ca_pem,
};
#[cfg(feature = "key-vault")]
pub use custody::KeyCustody;
pub use error::{Action, CertificateProblem, ErrorCategory, RefuseReason, TlsError};
pub use expiry::{CertificateInfo, ExpiryReport, ExpiryState, KeyType};
#[cfg(feature = "ja3-md5")]
pub use fingerprint::ja3_md5;
pub use fingerprint::{Fingerprint, FingerprintKinds, Ja4, ja3_string, ja4_original, ja4_raw};
pub use hello::{ClientHelloView, HelloLimits, HelloParse, HelloParser, is_grease};
pub use hook::{HelloContext, HelloHook, HelloVerdict};
pub use identity::{
    HandshakeInfo, HandshakeKind, PeerIdentity, certificate_der_from_pem, spki_sha256,
};
pub use limits::HandshakeLimits;
pub use observe::{HelloRefusal, ServerStats, TlsEvent, TlsObserver};
pub use policy::{CipherSuite, Group, Policy, PolicySummary, SignatureScheme, Version};
pub use provider::default_provider_name;
#[cfg(feature = "dangerous-keylog")]
pub use server::KeyLogSink;
pub use server::{
    Alpn, AlpnPolicy, HostPolicy, ReloadHandle, ReloadOutcome, ServerBuilder, ServerReader,
    TlsServer, UnknownName, server_from_files, server_from_pem,
};
pub use session::{
    ClientSession, CloseKind, Event, INCOMING_MIN, MAX_RECORD_PAYLOAD, OUTGOING_MIN, Progress,
    ServerSession, SessionState,
};
pub use sni::{NormalizedName, normalize_server_name};
pub use tickets::{SealedTicketKeys, TicketKeyRingHandle, TicketMode, TicketSeed};
pub use verify::{ClientAuth, Crls, RevocationPolicy};

/// Crate version string, populated by Cargo at build time.
///
/// ```
/// assert_eq!(tls_net::VERSION, env!("CARGO_PKG_VERSION"));
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn test_thread_safety_nfr13() {
        assert_send::<ServerSession>();
        assert_send::<ClientSession>();
        assert_send_sync::<TlsServer>();
        assert_send_sync::<TlsClient>();
        assert_send_sync::<Policy>();
        assert_send_sync::<TrustAnchors>();
        assert_send_sync::<TlsError>();
    }

    #[cfg(not(any(feature = "aws-lc", feature = "ring")))]
    #[test]
    fn test_no_provider_every_constructor_refuses() {
        let chain =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/site.pem")).unwrap();
        let key =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/site.key")).unwrap();
        assert_eq!(
            server_from_pem(&chain, &key).unwrap_err(),
            TlsError::NoProvider
        );
        assert_eq!(client().unwrap_err(), TlsError::NoProvider);
        let ca = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.pem")).unwrap();
        assert_eq!(client_with_ca_pem(&ca).unwrap_err(), TlsError::NoProvider);
        assert_eq!(default_provider_name(), None);
    }

    #[test]
    fn test_version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
