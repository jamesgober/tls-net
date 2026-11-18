//! `Policy`: versions, cipher suites, key exchange groups, and the settings
//! around them. Nothing weaker than these enums can be named, so a weak
//! configuration cannot be written.

use std::sync::Arc;

use rustls::SupportedProtocolVersion;
use rustls::crypto::CryptoProvider;

use crate::error::TlsError;
use crate::provider;

/// A TLS protocol version. Nothing below TLS 1.2 exists here (RFC 8996).
///
/// ```
/// assert_eq!(tls_net::Version::Tls13.wire(), 0x0304);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Version {
    /// TLS 1.2 (RFC 5246).
    Tls12,
    /// TLS 1.3 (RFC 8446, RFC 9846).
    Tls13,
}

impl Version {
    /// The protocol version code point.
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            Version::Tls12 => 0x0303,
            Version::Tls13 => 0x0304,
        }
    }

    /// The version for a code point, if it is one tls-net supports.
    ///
    /// ```
    /// assert_eq!(tls_net::Version::from_wire(0x0302), None);
    /// ```
    #[must_use]
    pub const fn from_wire(code: u16) -> Option<Version> {
        match code {
            0x0303 => Some(Version::Tls12),
            0x0304 => Some(Version::Tls13),
            _ => None,
        }
    }

    fn rustls(self) -> &'static SupportedProtocolVersion {
        match self {
            Version::Tls12 => &rustls::version::TLS12,
            Version::Tls13 => &rustls::version::TLS13,
        }
    }
}

/// A cipher suite: AEAD with ECDHE only.
///
/// ```
/// use tls_net::{CipherSuite, Version};
/// assert_eq!(CipherSuite::Tls13Aes128GcmSha256.wire(), 0x1301);
/// assert_eq!(CipherSuite::EcdheRsaAes128GcmSha256.version(), Version::Tls12);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// `TLS_AES_256_GCM_SHA384`.
    Tls13Aes256GcmSha384,
    /// `TLS_AES_128_GCM_SHA256`.
    Tls13Aes128GcmSha256,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    Tls13ChaCha20Poly1305Sha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    EcdheEcdsaAes256GcmSha384,
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    EcdheEcdsaAes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    EcdheEcdsaChaCha20Poly1305Sha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    EcdheRsaAes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    EcdheRsaChaCha20Poly1305Sha256,
}

const ALL_SUITES: [CipherSuite; 9] = [
    CipherSuite::Tls13Aes256GcmSha384,
    CipherSuite::Tls13Aes128GcmSha256,
    CipherSuite::Tls13ChaCha20Poly1305Sha256,
    CipherSuite::EcdheEcdsaAes256GcmSha384,
    CipherSuite::EcdheEcdsaAes128GcmSha256,
    CipherSuite::EcdheEcdsaChaCha20Poly1305Sha256,
    CipherSuite::EcdheRsaAes256GcmSha384,
    CipherSuite::EcdheRsaAes128GcmSha256,
    CipherSuite::EcdheRsaChaCha20Poly1305Sha256,
];

impl CipherSuite {
    /// The IANA code point.
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            CipherSuite::Tls13Aes256GcmSha384 => 0x1302,
            CipherSuite::Tls13Aes128GcmSha256 => 0x1301,
            CipherSuite::Tls13ChaCha20Poly1305Sha256 => 0x1303,
            CipherSuite::EcdheEcdsaAes256GcmSha384 => 0xc02c,
            CipherSuite::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            CipherSuite::EcdheEcdsaChaCha20Poly1305Sha256 => 0xcca9,
            CipherSuite::EcdheRsaAes256GcmSha384 => 0xc030,
            CipherSuite::EcdheRsaAes128GcmSha256 => 0xc02f,
            CipherSuite::EcdheRsaChaCha20Poly1305Sha256 => 0xcca8,
        }
    }

    /// The suite for a code point, if tls-net supports it.
    ///
    /// ```
    /// // TLS_RSA_WITH_AES_128_CBC_SHA cannot be named.
    /// assert_eq!(tls_net::CipherSuite::from_wire(0x002f), None);
    /// ```
    #[must_use]
    pub fn from_wire(code: u16) -> Option<CipherSuite> {
        ALL_SUITES.into_iter().find(|s| s.wire() == code)
    }

    /// The protocol version the suite belongs to.
    #[must_use]
    pub const fn version(self) -> Version {
        match self {
            CipherSuite::Tls13Aes256GcmSha384
            | CipherSuite::Tls13Aes128GcmSha256
            | CipherSuite::Tls13ChaCha20Poly1305Sha256 => Version::Tls13,
            _ => Version::Tls12,
        }
    }
}

/// A key exchange group.
///
/// ```
/// assert_eq!(tls_net::Group::X25519MlKem768.wire(), 0x11ec);
/// assert!(tls_net::Group::X25519MlKem768.is_post_quantum());
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    /// X25519 with ML-KEM-768 (hybrid post-quantum).
    X25519MlKem768,
    /// secp256r1 with ML-KEM-768 (hybrid post-quantum); in no preset.
    Secp256r1MlKem768,
    /// X25519.
    X25519,
    /// NIST P-256.
    Secp256r1,
    /// NIST P-384.
    Secp384r1,
}

const ALL_GROUPS: [Group; 5] = [
    Group::X25519MlKem768,
    Group::Secp256r1MlKem768,
    Group::X25519,
    Group::Secp256r1,
    Group::Secp384r1,
];

impl Group {
    /// The IANA code point.
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            Group::X25519MlKem768 => 0x11ec,
            Group::Secp256r1MlKem768 => 0x11eb,
            Group::X25519 => 0x001d,
            Group::Secp256r1 => 0x0017,
            Group::Secp384r1 => 0x0018,
        }
    }

    /// The group for a code point, if tls-net supports it.
    #[must_use]
    pub fn from_wire(code: u16) -> Option<Group> {
        ALL_GROUPS.into_iter().find(|g| g.wire() == code)
    }

    /// Whether the group is a post-quantum hybrid.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(self, Group::X25519MlKem768 | Group::Secp256r1MlKem768)
    }
}

/// A signature scheme. RSA PKCS#1 v1.5 schemes are used only for TLS 1.2 and
/// certificate signatures; rustls refuses them for TLS 1.3 handshake
/// signatures (D-033).
///
/// ```
/// assert_eq!(tls_net::SignatureScheme::Ed25519.wire(), 0x0807);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// `ecdsa_secp256r1_sha256`.
    EcdsaP256Sha256,
    /// `ecdsa_secp384r1_sha384`.
    EcdsaP384Sha384,
    /// `ed25519`.
    Ed25519,
    /// `rsa_pss_rsae_sha256`.
    RsaPssSha256,
    /// `rsa_pss_rsae_sha384`.
    RsaPssSha384,
    /// `rsa_pss_rsae_sha512`.
    RsaPssSha512,
    /// `rsa_pkcs1_sha256`.
    RsaPkcs1Sha256,
    /// `rsa_pkcs1_sha384`.
    RsaPkcs1Sha384,
    /// `rsa_pkcs1_sha512`.
    RsaPkcs1Sha512,
}

impl SignatureScheme {
    /// The IANA code point.
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            SignatureScheme::EcdsaP256Sha256 => 0x0403,
            SignatureScheme::EcdsaP384Sha384 => 0x0503,
            SignatureScheme::Ed25519 => 0x0807,
            SignatureScheme::RsaPssSha256 => 0x0804,
            SignatureScheme::RsaPssSha384 => 0x0805,
            SignatureScheme::RsaPssSha512 => 0x0806,
            SignatureScheme::RsaPkcs1Sha256 => 0x0401,
            SignatureScheme::RsaPkcs1Sha384 => 0x0501,
            SignatureScheme::RsaPkcs1Sha512 => 0x0601,
        }
    }

    /// The scheme for a code point, if tls-net names it.
    #[must_use]
    pub fn from_wire(code: u16) -> Option<SignatureScheme> {
        [
            SignatureScheme::EcdsaP256Sha256,
            SignatureScheme::EcdsaP384Sha384,
            SignatureScheme::Ed25519,
            SignatureScheme::RsaPssSha256,
            SignatureScheme::RsaPssSha384,
            SignatureScheme::RsaPssSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512,
        ]
        .into_iter()
        .find(|s| s.wire() == code)
    }
}

/// Which preset a policy started from; the builders read it for defaults
/// that belong to the listener (tickets, unknown names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Preset {
    Compatible,
    Modern,
    Internal,
    Client,
    Fips,
}

/// What a policy allows, for logs and audits.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySummary {
    /// Allowed versions.
    pub versions: Vec<Version>,
    /// Allowed cipher suites, in order.
    pub cipher_suites: Vec<CipherSuite>,
    /// Allowed groups, in order.
    pub groups: Vec<Group>,
    /// Extended master secret required for TLS 1.2.
    pub extended_master_secret: bool,
    /// The server's suite order wins.
    pub server_order: bool,
    /// Only post-quantum groups.
    pub post_quantum_required: bool,
    /// Plaintext bytes per record, if lowered.
    pub max_fragment_size: Option<u16>,
    /// The FIPS preset.
    pub fips: bool,
}

impl std::fmt::Display for PolicySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v: Vec<&str> = self
            .versions
            .iter()
            .map(|v| {
                if *v == Version::Tls13 {
                    "TLS1.3"
                } else {
                    "TLS1.2"
                }
            })
            .collect();
        write!(f, "versions {} suites", v.join(","))?;
        for s in &self.cipher_suites {
            write!(f, " {:#06x}", s.wire())?;
        }
        f.write_str(" groups")?;
        for g in &self.groups {
            write!(f, " {:#06x}", g.wire())?;
        }
        write!(
            f,
            " ems={} server_order={} pq_required={} fips={}",
            self.extended_master_secret, self.server_order, self.post_quantum_required, self.fips
        )?;
        if let Some(n) = self.max_fragment_size {
            write!(f, " fragment={n}")?;
        }
        Ok(())
    }
}

/// Versions, cipher suites, key exchange groups, and the settings around
/// them. Presets: [`compatible`](Policy::compatible) (the server default),
/// [`modern`](Policy::modern), and [`client_default`](Policy::client_default).
///
/// Setters check their own argument; checks against the crypto provider run
/// when a server or client is built.
///
/// ```
/// use tls_net::{CipherSuite, Policy};
/// let policy = Policy::modern().cipher_suites(&[
///     CipherSuite::Tls13ChaCha20Poly1305Sha256,
///     CipherSuite::Tls13Aes256GcmSha384,
/// ])?;
/// assert!(Policy::modern().cipher_suites(&[]).is_err());
/// # Ok::<(), tls_net::TlsError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    versions: Vec<Version>,
    suites: Vec<CipherSuite>,
    groups: Vec<Group>,
    /// Groups named by the caller must exist; preset groups the provider
    /// lacks (ML-KEM with ring) are skipped.
    groups_explicit: bool,
    /// The same for suites (ChaCha20 in a FIPS build, D-095).
    suites_explicit: bool,
    ems: bool,
    server_order: bool,
    post_quantum: bool,
    max_fragment: Option<u16>,
    preset: Preset,
}

impl Default for Policy {
    fn default() -> Self {
        Policy::compatible()
    }
}

/// A preset's suites for these versions: every suite tls-net names, without
/// ChaCha20 for FIPS.
fn preset_suites(versions: &[Version], preset: Preset) -> Vec<CipherSuite> {
    ALL_SUITES
        .into_iter()
        .filter(|s| versions.contains(&s.version()))
        .filter(|s| {
            preset != Preset::Fips
                || !matches!(
                    s,
                    CipherSuite::Tls13ChaCha20Poly1305Sha256
                        | CipherSuite::EcdheEcdsaChaCha20Poly1305Sha256
                        | CipherSuite::EcdheRsaChaCha20Poly1305Sha256
                )
        })
        .collect()
}

impl Policy {
    fn base(versions: &[Version], preset: Preset) -> Policy {
        Policy {
            versions: versions.to_vec(),
            suites: preset_suites(versions, preset),
            groups: vec![
                Group::X25519MlKem768,
                Group::X25519,
                Group::Secp256r1,
                Group::Secp384r1,
            ],
            groups_explicit: false,
            suites_explicit: false,
            ems: true,
            server_order: true,
            post_quantum: false,
            max_fragment: None,
            preset,
        }
    }

    /// TLS 1.3 and TLS 1.2 (AEAD suites with ECDHE only, extended master
    /// secret required), X25519MLKEM768 first. The server default.
    #[must_use]
    pub fn compatible() -> Policy {
        Policy::base(&[Version::Tls13, Version::Tls12], Preset::Compatible)
    }

    /// TLS 1.3 only.
    #[must_use]
    pub fn modern() -> Policy {
        Policy::base(&[Version::Tls13], Preset::Modern)
    }

    /// TLS 1.3 only, X25519MLKEM768 only (post-quantum required). Servers
    /// built with it refuse unknown names, send no tickets, and need
    /// `ClientAuth::required` or `pinned` (D-131).
    #[must_use]
    pub fn internal() -> Policy {
        let mut p = Policy::base(&[Version::Tls13], Preset::Internal);
        p.groups = vec![Group::X25519MlKem768];
        p.post_quantum = true;
        p
    }

    /// FIPS 140-3: TLS 1.3 and TLS 1.2 with AES-GCM suites only and NIST
    /// curves (with ML-KEM hybrids where the module offers them). Building a
    /// server or client with it outside a FIPS build fails with
    /// `FipsUnavailable` (D-084).
    #[must_use]
    pub fn fips() -> Policy {
        let mut p = Policy::base(&[Version::Tls13, Version::Tls12], Preset::Fips);
        p.groups = vec![
            Group::Secp256r1MlKem768,
            Group::X25519MlKem768,
            Group::Secp256r1,
            Group::Secp384r1,
        ];
        p
    }

    /// Whether this is the FIPS preset.
    pub(crate) fn requires_fips(&self) -> bool {
        self.preset == Preset::Fips
    }

    /// A one-line description for logs and audits.
    ///
    /// ```
    /// let s = tls_net::Policy::modern().summary();
    /// assert_eq!(s.versions, [tls_net::Version::Tls13]);
    /// assert!(s.to_string().starts_with("versions TLS1.3"));
    /// ```
    #[must_use]
    pub fn summary(&self) -> PolicySummary {
        PolicySummary {
            versions: self.versions.clone(),
            cipher_suites: self
                .suites
                .iter()
                .copied()
                .filter(|s| self.versions.contains(&s.version()))
                .collect(),
            groups: self
                .groups
                .iter()
                .copied()
                .filter(|g| !self.post_quantum || g.is_post_quantum())
                .collect(),
            extended_master_secret: self.ems,
            server_order: self.server_order,
            post_quantum_required: self.post_quantum,
            max_fragment_size: self.max_fragment,
            fips: self.preset == Preset::Fips,
        }
    }

    /// The client default: TLS 1.3 and TLS 1.2, the same suites and groups as
    /// `compatible`, extended master secret required.
    #[must_use]
    pub fn client_default() -> Policy {
        Policy::base(&[Version::Tls13, Version::Tls12], Preset::Client)
    }

    /// The allowed versions.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for an empty list or a duplicate.
    pub fn versions(mut self, versions: &[Version]) -> Result<Policy, TlsError> {
        self.versions = list(versions, "version list")?;
        // Unless the suites were named, they follow the versions, so
        // `modern().versions(&[Tls13, Tls12])` gains the TLS 1.2 suites (D-150).
        if !self.suites_explicit {
            self.suites = preset_suites(&self.versions, self.preset);
        }
        Ok(self)
    }

    /// The allowed cipher suites, in the server's order of preference.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for an empty list or a duplicate.
    pub fn cipher_suites(mut self, suites: &[CipherSuite]) -> Result<Policy, TlsError> {
        self.suites = list(suites, "cipher suite list")?;
        self.suites_explicit = true;
        Ok(self)
    }

    /// The allowed key exchange groups. The client's order decides which one
    /// is used (rustls picks the first of the client's groups the server allows).
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for an empty list or a duplicate.
    pub fn groups(mut self, groups: &[Group]) -> Result<Policy, TlsError> {
        self.groups = list(groups, "group list")?;
        self.groups_explicit = true;
        Ok(self)
    }

    /// Require extended master secret for TLS 1.2 (on in every preset).
    #[must_use]
    pub fn require_extended_master_secret(mut self, on: bool) -> Policy {
        self.ems = on;
        self
    }

    /// Let the server's cipher suite order win over the client's (on in every preset).
    #[must_use]
    pub fn server_order(mut self, on: bool) -> Policy {
        self.server_order = on;
        self
    }

    /// Allow only post-quantum hybrid groups.
    #[must_use]
    pub fn require_post_quantum(mut self, on: bool) -> Policy {
        self.post_quantum = on;
        self
    }

    /// The largest plaintext fragment per record, or `None` for 16,384.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` below 32 or above 16,384 bytes.
    pub fn max_fragment_size(mut self, bytes: Option<u16>) -> Result<Policy, TlsError> {
        if let Some(n) = bytes {
            if !(32..=16_384).contains(&n) {
                return Err(TlsError::PolicyInvalid {
                    reason: "max_fragment_size must be 32 to 16,384 bytes",
                });
            }
        }
        self.max_fragment = bytes;
        Ok(self)
    }

    pub(crate) fn preset(&self) -> Preset {
        self.preset
    }

    pub(crate) fn ems(&self) -> bool {
        self.ems
    }

    pub(crate) fn server_order_wins(&self) -> bool {
        self.server_order
    }

    pub(crate) fn fragment(&self) -> Option<usize> {
        self.max_fragment.map(usize::from)
    }

    pub(crate) fn rustls_versions(&self) -> Vec<&'static SupportedProtocolVersion> {
        let mut v: Vec<_> = self.versions.clone();
        v.sort_by(|a, b| b.cmp(a));
        v.into_iter().map(Version::rustls).collect()
    }

    /// A provider restricted to this policy's suites and groups, in policy
    /// order. Fails rather than falling back (FR-8).
    pub(crate) fn provider(&self) -> Result<Arc<CryptoProvider>, TlsError> {
        let parts = provider::parts().ok_or(TlsError::NoProvider)?;
        let mut cipher_suites = Vec::new();
        for s in &self.suites {
            if !self.versions.contains(&s.version()) {
                continue;
            }
            match parts
                .all_suites
                .iter()
                .find(|p| u16::from(p.suite()) == s.wire() && approved(p.fips()))
            {
                Some(found) => cipher_suites.push(*found),
                None if !self.suites_explicit => {}
                None => {
                    return Err(TlsError::PolicyInvalid {
                        reason: "a cipher suite is not available in this provider",
                    });
                }
            }
        }
        for v in &self.versions {
            let wire = match v {
                Version::Tls12 => rustls::ProtocolVersion::TLSv1_2,
                Version::Tls13 => rustls::ProtocolVersion::TLSv1_3,
            };
            if !cipher_suites.iter().any(|s| s.version().version == wire) {
                return Err(TlsError::PolicyInvalid {
                    reason: "an allowed version has no cipher suite",
                });
            }
        }
        let mut kx_groups = Vec::new();
        for g in &self.groups {
            if self.post_quantum && !g.is_post_quantum() {
                continue;
            }
            match parts
                .all_groups
                .iter()
                .find(|p| u16::from(p.name()) == g.wire() && approved(p.fips()))
            {
                Some(found) => kx_groups.push(*found),
                None if !self.groups_explicit && !self.post_quantum => {}
                None if g.is_post_quantum() => return Err(TlsError::PostQuantumUnavailable),
                None => {
                    return Err(TlsError::PolicyInvalid {
                        reason: "a group is not available in this provider",
                    });
                }
            }
        }
        if kx_groups.is_empty() {
            return Err(if self.post_quantum {
                TlsError::PostQuantumUnavailable
            } else {
                TlsError::PolicyInvalid {
                    reason: "no key exchange group",
                }
            });
        }
        Ok(Arc::new(CryptoProvider {
            cipher_suites,
            kx_groups,
            ..parts.base
        }))
    }
}

/// In a FIPS build only what rustls itself reports as FIPS-approved is used,
/// so every built configuration passes rustls's `fips()` check (D-095).
fn approved(fips: bool) -> bool {
    fips || !cfg!(feature = "fips")
}

fn list<T: Copy + PartialEq>(items: &[T], what: &'static str) -> Result<Vec<T>, TlsError> {
    if items.is_empty() {
        return Err(TlsError::PolicyInvalid {
            reason: what_empty(what),
        });
    }
    for (i, a) in items.iter().enumerate() {
        if items[i + 1..].contains(a) {
            return Err(TlsError::PolicyInvalid {
                reason: what_duplicate(what),
            });
        }
    }
    Ok(items.to_vec())
}

fn what_empty(what: &'static str) -> &'static str {
    match what {
        "version list" => "the version list is empty",
        "cipher suite list" => "the cipher suite list is empty",
        _ => "the group list is empty",
    }
}

fn what_duplicate(what: &'static str) -> &'static str {
    match what {
        "version list" => "the version list repeats a version",
        "cipher suite list" => "the cipher suite list repeats a suite",
        _ => "the group list repeats a group",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presets_versions_and_groups() {
        assert!(Policy::compatible().versions.contains(&Version::Tls12));
        assert!(!Policy::modern().versions.contains(&Version::Tls12));
        assert_eq!(Policy::internal().groups, [Group::X25519MlKem768]);
        assert_eq!(Policy::compatible().suites.len(), 9);
        assert_eq!(Policy::modern().suites.len(), 3);
    }

    #[test]
    fn test_setters_refuse_empty_and_duplicates() {
        assert!(Policy::compatible().versions(&[]).is_err());
        assert!(
            Policy::compatible()
                .groups(&[Group::X25519, Group::X25519])
                .is_err()
        );
        assert!(Policy::compatible().max_fragment_size(Some(31)).is_err());
        assert!(
            Policy::compatible()
                .max_fragment_size(Some(16_385))
                .is_err()
        );
        assert!(Policy::compatible().max_fragment_size(Some(32)).is_ok());
    }

    #[test]
    fn test_wire_round_trip() {
        for s in ALL_SUITES {
            assert_eq!(CipherSuite::from_wire(s.wire()), Some(s));
        }
        for g in ALL_GROUPS {
            assert_eq!(Group::from_wire(g.wire()), Some(g));
        }
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn test_provider_internal_only_post_quantum() {
        let p = Policy::internal().provider().unwrap();
        assert_eq!(p.kx_groups.len(), 1);
        assert_eq!(u16::from(p.kx_groups[0].name()), 0x11ec);
        // AES-256-GCM, AES-128-GCM, and ChaCha20 (not approved in FIPS builds).
        let expected = if cfg!(feature = "fips") { 2 } else { 3 };
        assert_eq!(p.cipher_suites.len(), expected);
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn test_provider_version_without_suite_refused() {
        let p = Policy::compatible()
            .cipher_suites(&[CipherSuite::Tls13Aes128GcmSha256])
            .unwrap();
        assert_eq!(
            p.provider().unwrap_err(),
            TlsError::PolicyInvalid {
                reason: "an allowed version has no cipher suite"
            }
        );
    }

    #[cfg(all(feature = "ring", not(feature = "aws-lc")))]
    #[test]
    fn test_provider_ring_refuses_post_quantum() {
        assert_eq!(
            Policy::internal().provider().unwrap_err(),
            TlsError::PostQuantumUnavailable
        );
        assert_eq!(Policy::compatible().provider().unwrap().kx_groups.len(), 3);
        assert_eq!(
            Policy::compatible()
                .groups(&[Group::X25519MlKem768])
                .unwrap()
                .provider()
                .unwrap_err(),
            TlsError::PostQuantumUnavailable
        );
    }

    #[cfg(not(any(feature = "aws-lc", feature = "ring")))]
    #[test]
    fn test_provider_none_without_feature() {
        assert_eq!(
            Policy::compatible().provider().unwrap_err(),
            TlsError::NoProvider
        );
    }
}
