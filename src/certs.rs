//! Certificate entries: a chain and its key, checked before use (FR-11 to
//! FR-14, PLAN 6.5).

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;

use crate::der::{self, KeyAlg};
use crate::error::TlsError;
use crate::pem::{self, KeyDer};
use crate::sni::{self, EntryKey};

/// Where a private key comes from. Key bytes are never copied into a
/// long-lived tls-net buffer, and every buffer tls-net decodes into is wiped.
///
/// ```
/// use tls_net::KeySource;
/// let pem = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/site.key"))?;
/// let source = KeySource::Pem(&pem);
/// assert_eq!(format!("{source:?}"), "KeySource::Pem");
/// # Ok::<(), std::io::Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum KeySource<'a> {
    /// One PEM block: `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1), or
    /// `EC PRIVATE KEY` (SEC1).
    Pem(&'a [u8]),
    /// PKCS#8, PKCS#1, or SEC1 DER; the form is detected.
    Der(&'a [u8]),
    /// A PEM file: size gate and, on Unix, the permission check first.
    File(&'a Path),
}

impl fmt::Debug for KeySource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::Pem(_) => f.write_str("KeySource::Pem"),
            KeySource::Der(_) => f.write_str("KeySource::Der"),
            KeySource::File(p) => write!(f, "KeySource::File({})", p.display()),
        }
    }
}

/// Budgets for certificate and key intake.
///
/// ```
/// let limits = tls_net::LoadLimits::new().max_chain_len(4)?;
/// assert_eq!(limits.max_chain_len, 4);
/// assert!(tls_net::LoadLimits::new().max_chain_len(0).is_err());
/// # Ok::<(), tls_net::TlsError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadLimits {
    /// Largest chain input in bytes (default 1 MiB).
    pub max_chain_file_bytes: u32,
    /// Largest key input in bytes (default 64 KiB).
    pub max_key_file_bytes: u32,
    /// Most certificates in a chain (default 10).
    pub max_chain_len: u8,
    /// Whether each certificate must be issued by the next (default on).
    pub check_chain_order: bool,
}

impl Default for LoadLimits {
    fn default() -> Self {
        LoadLimits::new()
    }
}

impl LoadLimits {
    /// The defaults.
    #[must_use]
    pub const fn new() -> Self {
        LoadLimits {
            max_chain_file_bytes: 1 << 20,
            max_key_file_bytes: 64 << 10,
            max_chain_len: 10,
            check_chain_order: true,
        }
    }

    /// Largest chain input, 1 KiB to 16 MiB.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` outside the range.
    pub fn max_chain_file_bytes(mut self, n: u32) -> Result<Self, TlsError> {
        if !(1024..=16 << 20).contains(&n) {
            return Err(TlsError::PolicyInvalid {
                reason: "max_chain_file_bytes must be 1 KiB to 16 MiB",
            });
        }
        self.max_chain_file_bytes = n;
        Ok(self)
    }

    /// Largest key input, 256 bytes to 1 MiB.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` outside the range.
    pub fn max_key_file_bytes(mut self, n: u32) -> Result<Self, TlsError> {
        if !(256..=1 << 20).contains(&n) {
            return Err(TlsError::PolicyInvalid {
                reason: "max_key_file_bytes must be 256 bytes to 1 MiB",
            });
        }
        self.max_key_file_bytes = n;
        Ok(self)
    }

    /// Most certificates in a chain, 1 to 32.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` outside the range.
    pub fn max_chain_len(mut self, n: u8) -> Result<Self, TlsError> {
        if !(1..=32).contains(&n) {
            return Err(TlsError::PolicyInvalid {
                reason: "max_chain_len must be 1 to 32",
            });
        }
        self.max_chain_len = n;
        Ok(self)
    }

    /// Whether to check that each certificate is issued by the next.
    #[must_use]
    pub const fn check_chain_order(mut self, on: bool) -> Self {
        self.check_chain_order = on;
        self
    }
}

/// What a certificate is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    Server,
    #[allow(dead_code, reason = "client certificates arrive in 0.4")]
    Client,
}

/// Options for one load.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LoadOptions {
    pub(crate) limits: LoadLimits,
    pub(crate) purpose: Purpose,
    pub(crate) now: SystemTime,
    pub(crate) skew: Duration,
    pub(crate) allow_group_readable: bool,
}

impl LoadOptions {
    pub(crate) fn new(purpose: Purpose) -> Self {
        LoadOptions {
            limits: LoadLimits::new(),
            purpose,
            now: SystemTime::now(),
            skew: Duration::from_secs(300),
            allow_group_readable: false,
        }
    }
}

/// The chain input.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Chain<'a> {
    Pem(&'a [u8]),
    Der(&'a [&'a [u8]]),
}

/// A validated certificate entry.
#[derive(Clone)]
#[allow(dead_code, reason = "validity and SPKI feed the expiry report (0.4)")]
pub(crate) struct CertificateEntry {
    pub(crate) certified: Arc<CertifiedKey>,
    /// Normalised names this entry serves (configured, or the SANs).
    pub(crate) names: Vec<Box<str>>,
    pub(crate) key: KeyAlg,
    pub(crate) not_before: SystemTime,
    pub(crate) not_after: SystemTime,
    pub(crate) spki_sha256: [u8; 32],
}

impl fmt::Debug for CertificateEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateEntry")
            .field("names", &self.names)
            .field("key", &self.key)
            .field("chain_len", &self.certified.cert.len())
            .finish_non_exhaustive()
    }
}

impl CertificateEntry {
    pub(crate) fn entry_key(&self) -> EntryKey {
        match self.key {
            KeyAlg::Rsa { .. } => EntryKey::Rsa,
            _ => EntryKey::Other,
        }
    }
}

/// Loads and checks one entry. `names` are the configured names, or `None`
/// to take them from the certificate's SANs.
pub(crate) fn load(
    chain: Chain<'_>,
    key: KeySource<'_>,
    names: Option<&[&str]>,
    opts: &LoadOptions,
) -> Result<CertificateEntry, TlsError> {
    let limits = &opts.limits;
    let max_len = usize::from(limits.max_chain_len);
    let chain = match chain {
        Chain::Pem(pem) => {
            gate(pem.len(), limits.max_chain_file_bytes)?;
            pem::certificates(pem, max_len)?
        }
        Chain::Der(der) => {
            let total: usize = der.iter().map(|d| d.len()).sum();
            gate(total, limits.max_chain_file_bytes)?;
            pem::certificates_der(der, max_len)?
        }
    };
    let key = read_key(key, opts)?;

    let leaf = der::parse_certificate(chain[0].as_ref()).ok_or(TlsError::PemInvalid {
        what: "certificate DER",
    })?;
    match leaf.key {
        KeyAlg::Rsa { bits } if bits < 2048 => return Err(TlsError::WeakKey { bits }),
        KeyAlg::EcdsaOther | KeyAlg::Other => return Err(TlsError::UnsupportedKeyType),
        _ => {}
    }
    if leaf.weak_signature {
        return Err(TlsError::WeakSignatureAlgorithm);
    }

    let signing = crate::provider::load_key(&key.as_der())?;
    drop(key);
    let certified = CertifiedKey::new(chain.clone(), signing);
    if certified.keys_match().is_err() {
        // The key of a later certificate: the chain is in the wrong order.
        let spki = certified.key.public_key();
        let later = chain
            .iter()
            .skip(1)
            .filter_map(|c| der::parse_certificate(c.as_ref()))
            .any(|f| spki.as_ref().is_some_and(|k| k.as_ref() == f.spki));
        return Err(if later {
            TlsError::ChainOrder { position: 0 }
        } else {
            TlsError::KeyMismatch
        });
    }

    if leaf.not_before > opts.now + opts.skew {
        return Err(TlsError::CertificateNotYetValid {
            not_before: leaf.not_before,
        });
    }
    if opts.now >= leaf.not_after {
        return Err(TlsError::CertificateExpired {
            not_after: leaf.not_after,
        });
    }

    let names = covered_names(names, &leaf)?;

    if let Some(eku) = leaf.eku {
        let allowed = match opts.purpose {
            Purpose::Server => eku.server,
            Purpose::Client => eku.client,
        };
        if !allowed {
            return Err(TlsError::WrongPurpose);
        }
    }

    if limits.check_chain_order {
        check_order(&chain)?;
    }

    Ok(CertificateEntry {
        names,
        key: leaf.key,
        not_before: leaf.not_before,
        not_after: leaf.not_after,
        spki_sha256: crypt_io::hash::sha256(leaf.spki),
        certified: Arc::new(certified),
    })
}

fn gate(len: usize, limit: u32) -> Result<(), TlsError> {
    if len > limit as usize {
        return Err(TlsError::FileTooLarge {
            path: Default::default(),
            limit: u64::from(limit),
        });
    }
    Ok(())
}

fn read_key(key: KeySource<'_>, opts: &LoadOptions) -> Result<KeyDer, TlsError> {
    let limit = opts.limits.max_key_file_bytes;
    match key {
        KeySource::Pem(pem) => {
            gate(pem.len(), limit)?;
            pem::key_from_pem(pem)
        }
        KeySource::Der(der) => {
            gate(der.len(), limit)?;
            pem::key_from_der(der)
        }
        KeySource::File(path) => {
            let bytes = pem::read_file(path, limit, true, opts.allow_group_readable)?;
            pem::key_from_pem(&bytes)
        }
    }
}

fn covered_names(
    names: Option<&[&str]>,
    leaf: &der::CertFacts<'_>,
) -> Result<Vec<Box<str>>, TlsError> {
    match names {
        Some(names) => {
            let mut out: Vec<Box<str>> = Vec::with_capacity(names.len());
            for name in names {
                let normal = sni::normalize_pattern(name).ok_or_else(|| TlsError::InvalidName {
                    name: crate::error::escape(name.as_bytes()),
                })?;
                let normal = normal.as_str();
                if !leaf
                    .dns_names
                    .iter()
                    .any(|san| sni::san_covers(san, normal))
                {
                    return Err(TlsError::NameNotCovered {
                        name: normal.into(),
                    });
                }
                if out.iter().any(|n| &**n == normal) {
                    return Err(TlsError::DuplicateName {
                        name: normal.into(),
                    });
                }
                out.push(normal.into());
            }
            Ok(out)
        }
        None => {
            if leaf.dns_names.is_empty() && leaf.ip_addresses.is_empty() {
                return Err(TlsError::NameNotCovered {
                    name: "(no subject alternative name)".into(),
                });
            }
            let mut out: Vec<Box<str>> = Vec::new();
            for san in &leaf.dns_names {
                if let Some(n) = sni::normalize_pattern(san) {
                    if !out.iter().any(|o| **o == *n.as_str()) {
                        out.push(n.as_str().into());
                    }
                }
            }
            Ok(out)
        }
    }
}

fn check_order(chain: &[CertificateDer<'static>]) -> Result<(), TlsError> {
    let mut facts = Vec::with_capacity(chain.len());
    for c in chain {
        facts.push(
            der::parse_certificate(c.as_ref()).ok_or(TlsError::PemInvalid {
                what: "certificate DER",
            })?,
        );
    }
    for (i, pair) in facts.windows(2).enumerate() {
        if pair[0].issuer != pair[1].subject {
            return Err(TlsError::ChainOrder { position: i });
        }
    }
    Ok(())
}

#[cfg(all(test, any(feature = "aws-lc", feature = "ring")))]
mod tests {
    use super::*;

    fn data(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn try_load(
        chain: &str,
        key: &str,
        names: Option<&[&str]>,
    ) -> Result<CertificateEntry, TlsError> {
        load(
            Chain::Pem(&data(chain)),
            KeySource::Pem(&data(key)),
            names,
            &LoadOptions::new(Purpose::Server),
        )
    }

    #[test]
    fn test_load_site_names_from_sans() {
        let e = try_load("site.pem", "site.key", None).unwrap();
        assert_eq!(
            &*e.names,
            [
                "localhost".into(),
                "example.test".into(),
                "*.example.test".into()
            ] as [Box<str>; 3]
        );
        assert_eq!(e.entry_key(), EntryKey::Other);
        assert_eq!(e.certified.cert.len(), 2);
    }

    #[test]
    fn test_load_key_forms_all_accepted() {
        assert!(try_load("site-rsa.pem", "site-rsa.pkcs1.key", None).is_ok());
        assert!(try_load("site.pem", "site.sec1.key", None).is_ok());
        let der = data("site.key.der");
        let opts = LoadOptions::new(Purpose::Server);
        assert!(
            load(
                Chain::Pem(&data("site.pem")),
                KeySource::Der(&der),
                None,
                &opts
            )
            .is_ok()
        );
    }

    #[test]
    fn test_load_refusals_have_their_own_error() {
        assert_eq!(
            try_load("site.pem", "api.key", None).unwrap_err(),
            TlsError::KeyMismatch
        );
        assert_eq!(
            try_load("rsa1024.pem", "rsa1024.key", None).unwrap_err(),
            TlsError::WeakKey { bits: 1024 }
        );
        assert_eq!(
            try_load("p521.pem", "p521.key", None).unwrap_err(),
            TlsError::UnsupportedKeyType
        );
        assert_eq!(
            try_load("sha1.pem", "sha1.key", None).unwrap_err(),
            TlsError::WeakSignatureAlgorithm
        );
        assert!(matches!(
            try_load("expired.pem", "expired.key", None),
            Err(TlsError::CertificateExpired { .. })
        ));
        assert!(matches!(
            try_load("future.pem", "future.key", None),
            Err(TlsError::CertificateNotYetValid { .. })
        ));
        assert_eq!(
            try_load("client-only.pem", "client-only.key", None).unwrap_err(),
            TlsError::WrongPurpose
        );
        assert!(matches!(
            try_load("no-san.pem", "no-san.key", None),
            Err(TlsError::NameNotCovered { .. })
        ));
        assert_eq!(
            try_load("site.reversed.pem", "site.key", None).unwrap_err(),
            TlsError::ChainOrder { position: 0 }
        );
        assert_eq!(
            try_load("site.encrypted.key", "site.key", None).unwrap_err(),
            TlsError::NoCertificate
        );
        assert_eq!(
            try_load("site.pem", "site.encrypted.key", None).unwrap_err(),
            TlsError::EncryptedPrivateKey
        );
    }

    #[test]
    fn test_load_chain_order_checked() {
        // The leaf alone, then the intermediate twice: the second is not issued by the third.
        let mut chain = data("site.pem");
        chain.extend(data("inter.pem"));
        let opts = LoadOptions::new(Purpose::Server);
        let r = load(
            Chain::Pem(&chain),
            KeySource::Pem(&data("site.key")),
            None,
            &opts,
        );
        assert_eq!(r.unwrap_err(), TlsError::ChainOrder { position: 1 });
        let relaxed = LoadOptions {
            limits: LoadLimits::new().check_chain_order(false),
            ..opts
        };
        assert!(
            load(
                Chain::Pem(&chain),
                KeySource::Pem(&data("site.key")),
                None,
                &relaxed
            )
            .is_ok()
        );
    }

    #[test]
    fn test_load_configured_names_coverage() {
        assert!(
            try_load(
                "site.pem",
                "site.key",
                Some(&["a.example.test", "LOCALHOST."])
            )
            .is_ok()
        );
        let e = try_load("site.pem", "site.key", Some(&["a.b.example.test"])).unwrap_err();
        assert_eq!(
            e,
            TlsError::NameNotCovered {
                name: "a.b.example.test".into()
            }
        );
        assert!(matches!(
            try_load("site.pem", "site.key", Some(&["bad name"])),
            Err(TlsError::InvalidName { .. })
        ));
        assert!(matches!(
            try_load(
                "site.pem",
                "site.key",
                Some(&["x.example.test", "X.example.test"])
            ),
            Err(TlsError::DuplicateName { .. })
        ));
    }

    #[test]
    fn test_load_budgets() {
        let opts = LoadOptions {
            limits: LoadLimits::new().max_chain_len(1).unwrap(),
            ..LoadOptions::new(Purpose::Server)
        };
        let r = load(
            Chain::Pem(&data("site.pem")),
            KeySource::Pem(&data("site.key")),
            None,
            &opts,
        );
        assert_eq!(r.unwrap_err(), TlsError::ChainTooLong { len: 2, limit: 1 });
        let opts = LoadOptions {
            limits: LoadLimits::new().max_key_file_bytes(256).unwrap(),
            ..LoadOptions::new(Purpose::Server)
        };
        let r = load(
            Chain::Pem(&data("site.pem")),
            KeySource::Pem(&data("site-rsa.key")),
            None,
            &opts,
        );
        assert!(matches!(r, Err(TlsError::FileTooLarge { limit: 256, .. })));
    }

    #[test]
    fn test_load_validity_skew_and_explicit_time() {
        let base = LoadOptions::new(Purpose::Server);
        let nb = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        let inside = LoadOptions {
            now: nb - Duration::from_secs(299),
            ..base
        };
        assert!(
            load(
                Chain::Pem(&data("site.pem")),
                KeySource::Pem(&data("site.key")),
                None,
                &inside
            )
            .is_ok()
        );
        let outside = LoadOptions {
            now: nb - Duration::from_secs(301),
            ..base
        };
        assert!(
            load(
                Chain::Pem(&data("site.pem")),
                KeySource::Pem(&data("site.key")),
                None,
                &outside
            )
            .is_err()
        );
    }

    #[test]
    fn test_client_purpose_needs_client_auth() {
        let opts = LoadOptions::new(Purpose::Client);
        assert!(
            load(
                Chain::Pem(&data("client.pem")),
                KeySource::Pem(&data("client.key")),
                None,
                &opts
            )
            .is_ok()
        );
        assert_eq!(
            load(
                Chain::Pem(&data("site.pem")),
                KeySource::Pem(&data("site.key")),
                None,
                &opts
            )
            .unwrap_err(),
            TlsError::WrongPurpose
        );
        assert!(
            load(
                Chain::Pem(&data("no-eku.pem")),
                KeySource::Pem(&data("no-eku.key")),
                None,
                &opts
            )
            .is_ok()
        );
    }

    #[test]
    fn test_debug_never_prints_key() {
        let e = try_load("site.pem", "site.key", None).unwrap();
        let s = format!("{e:?}");
        assert!(!s.contains("BEGIN") && s.contains("names"));
    }
}
