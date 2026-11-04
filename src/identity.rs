//! What a completed handshake negotiated, and who the peer is.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::fingerprint::Fingerprint;
use crate::policy::{CipherSuite, Group, Version};

/// How the handshake ran.
///
/// ```
/// assert_ne!(tls_net::HandshakeKind::Full, tls_net::HandshakeKind::Resumed);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeKind {
    /// A full handshake.
    Full,
    /// A full handshake after a HelloRetryRequest (the client had no key
    /// share for the group the server picked).
    FullWithHelloRetry,
    /// A resumed session.
    Resumed,
}

/// The results of a completed handshake, borrowed from the session.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeInfo<'s> {
    /// The protocol version.
    pub version: Version,
    /// The cipher suite.
    pub cipher_suite: CipherSuite,
    /// The key exchange group; `None` for a TLS 1.2 resumption.
    pub group: Option<Group>,
    /// The application protocol (ALPN), if one was negotiated.
    pub alpn: Option<&'s [u8]>,
    /// Server side: the normalised SNI. Client side: the name connected to.
    pub server_name: Option<&'s str>,
    /// Full, full after a retry, or resumed.
    pub kind: HandshakeKind,
    /// The peer's certificate identity, when it sent one.
    pub peer: Option<&'s PeerIdentity>,
    /// Server side: the ClientHello's fingerprints, when enabled.
    pub fingerprint: Option<&'s Fingerprint>,
    /// Always `false` until early data (P3) exists.
    pub early_data_accepted: bool,
}

impl<'s> HandshakeInfo<'s> {
    pub(crate) fn new(
        version: Version,
        cipher_suite: CipherSuite,
        group: Option<Group>,
        alpn: Option<&'s [u8]>,
        server_name: Option<&'s str>,
        kind: HandshakeKind,
    ) -> Self {
        HandshakeInfo {
            version,
            cipher_suite,
            group,
            alpn,
            server_name,
            kind,
            peer: None,
            fingerprint: None,
            early_data_accepted: false,
        }
    }
}

/// The peer's certificate identity (FR-24), built once when the handshake
/// completes and only when the peer sent a certificate. Map `spki_sha256`
/// (it survives re-issuance with the same key) or a URI SAN to a principal.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// SHA-256 of the end-entity SubjectPublicKeyInfo.
    pub spki_sha256: [u8; 32],
    /// The end-entity certificate, DER.
    pub end_entity: Arc<[u8]>,
    /// DNS subject alternative names.
    pub dns_names: Vec<String>,
    /// IP subject alternative names.
    pub ip_addresses: Vec<IpAddr>,
    /// URI subject alternative names (for example SPIFFE ids).
    pub uri_names: Vec<String>,
    /// The serial number, big-endian.
    pub serial: Vec<u8>,
    /// Start of validity.
    pub not_before: SystemTime,
    /// End of validity.
    pub not_after: SystemTime,
}

impl PeerIdentity {
    /// Reads the identity from a DER certificate.
    pub(crate) fn from_der(der: &[u8]) -> Option<PeerIdentity> {
        let f = crate::der::parse_certificate(der)?;
        Some(PeerIdentity {
            spki_sha256: crypt_io::hash::sha256(f.spki),
            end_entity: Arc::from(der),
            dns_names: f.dns_names.iter().map(|s| (*s).to_owned()).collect(),
            ip_addresses: f.ip_addresses.clone(),
            uri_names: f.uri_names.iter().map(|s| (*s).to_owned()).collect(),
            serial: f.serial.to_vec(),
            not_before: f.not_before,
            not_after: f.not_after,
        })
    }
}

/// The SHA-256 of a certificate's SubjectPublicKeyInfo: the value an SPKI
/// pin holds (`ClientAuth::pinned`, `ServerIdentity::Pinned`).
///
/// # Errors
///
/// `PemInvalid` when the DER is not a certificate.
///
/// ```
/// let pem = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.pem"))?;
/// let der = tls_net::certificate_der_from_pem(&pem)?;
/// let pin = tls_net::spki_sha256(&der[0])?;
/// assert_eq!(pin.len(), 32);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn spki_sha256(certificate_der: &[u8]) -> Result<[u8; 32], crate::error::TlsError> {
    let f = crate::der::parse_certificate(certificate_der).ok_or(
        crate::error::TlsError::PemInvalid {
            what: "certificate DER",
        },
    )?;
    Ok(crypt_io::hash::sha256(f.spki))
}

/// The DER of every `CERTIFICATE` block in `pem` (at most 4,096), for
/// computing pins or passing DER elsewhere.
///
/// # Errors
///
/// `PemInvalid`, `NoCertificate`, `ChainTooLong`.
pub fn certificate_der_from_pem(pem: &[u8]) -> Result<Vec<Vec<u8>>, crate::error::TlsError> {
    Ok(crate::pem::certificates(pem, 4096)?
        .into_iter()
        .map(|c| c.to_vec())
        .collect())
}
