//! Peer verification beyond rustls's defaults: client authentication modes,
//! SPKI pins that sit on top of real signature checks (T-6b), and CRLs.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, SignatureScheme,
};

use crate::client::TrustAnchors;
use crate::error::TlsError;

/// Certificate revocation lists, loaded from PEM or DER. Fetching them is
/// the caller's (or cert-net's) job; tls-net does no I/O.
///
/// ```
/// assert!(tls_net::Crls::from_pem(b"").is_err());
/// ```
#[derive(Clone)]
pub struct Crls(Arc<Vec<CertificateRevocationListDer<'static>>>);

impl fmt::Debug for Crls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Crls({})", self.0.len())
    }
}

impl Crls {
    /// CRLs from `X509 CRL` PEM blocks.
    ///
    /// # Errors
    ///
    /// `PemInvalid`; `PolicyInvalid` when the input holds no CRL.
    pub fn from_pem(pem: &[u8]) -> Result<Crls, TlsError> {
        let mut out = Vec::new();
        for crl in CertificateRevocationListDer::pem_slice_iter(pem) {
            out.push(crl.map_err(|_| TlsError::PemInvalid { what: "CRL PEM" })?);
        }
        if out.is_empty() {
            return Err(TlsError::PolicyInvalid {
                reason: "no CRL found",
            });
        }
        Ok(Crls(Arc::new(out)))
    }

    /// CRLs from DER.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for an empty list.
    pub fn from_der(der: &[&[u8]]) -> Result<Crls, TlsError> {
        if der.is_empty() {
            return Err(TlsError::PolicyInvalid {
                reason: "no CRL found",
            });
        }
        Ok(Crls(Arc::new(
            der.iter()
                .map(|d| CertificateRevocationListDer::from(d.to_vec()))
                .collect(),
        )))
    }

    /// How many CRLs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none (never, for a built value).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// How CRLs are applied. The default checks the whole chain, refuses a
/// certificate whose status no CRL covers, and accepts an expired CRL
/// (rustls-webpki's defaults).
///
/// ```
/// use tls_net::RevocationPolicy;
/// let p = RevocationPolicy::END_ENTITY_ONLY.union(RevocationPolicy::ENFORCE_EXPIRY);
/// assert!(p.contains(RevocationPolicy::ENFORCE_EXPIRY));
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevocationPolicy(u8);

impl RevocationPolicy {
    /// Check only the end-entity certificate.
    pub const END_ENTITY_ONLY: Self = RevocationPolicy(1);
    /// A certificate no CRL covers passes.
    pub const ALLOW_UNKNOWN_STATUS: Self = RevocationPolicy(2);
    /// An expired CRL fails.
    pub const ENFORCE_EXPIRY: Self = RevocationPolicy(4);

    /// Both sets of flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        RevocationPolicy(self.0 | other.0)
    }

    /// Whether every flag of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Debug)]
enum Mode {
    None,
    Optional(TrustAnchors),
    Required(TrustAnchors),
    Pinned(Option<TrustAnchors>, Vec<[u8; 32]>),
}

/// Client certificates on a server: none (default), optional, required, or
/// pinned. CRLs and hiding the CA names are modifiers.
///
/// ```
/// let ca = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.pem"))?;
/// let anchors = tls_net::TrustAnchors::from_pem(&ca)?;
/// let auth = tls_net::ClientAuth::required(anchors).hide_ca_names();
/// assert!(auth.is_required());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct ClientAuth {
    mode: Mode,
    crls: Option<(Crls, RevocationPolicy)>,
    hide_ca_names: bool,
}

impl Default for ClientAuth {
    fn default() -> Self {
        ClientAuth::none()
    }
}

impl ClientAuth {
    /// No client certificates.
    #[must_use]
    pub fn none() -> Self {
        ClientAuth {
            mode: Mode::None,
            crls: None,
            hide_ca_names: false,
        }
    }

    /// A client may send a certificate; one that does must chain to `anchors`.
    /// Without one the session is anonymous (`HandshakeInfo::peer` is `None`).
    #[must_use]
    pub fn optional(anchors: TrustAnchors) -> Self {
        ClientAuth {
            mode: Mode::Optional(anchors),
            ..ClientAuth::none()
        }
    }

    /// A client must send a certificate that chains to `anchors`.
    #[must_use]
    pub fn required(anchors: TrustAnchors) -> Self {
        ClientAuth {
            mode: Mode::Required(anchors),
            ..ClientAuth::none()
        }
    }

    /// A client must send a certificate whose SPKI SHA-256 is one of `pins`.
    /// With `anchors` the chain is verified first; without, a self-issued
    /// certificate is accepted when its key matches a pin. In both cases the
    /// handshake signature and the validity window are verified (T-6b).
    #[must_use]
    pub fn pinned(anchors: Option<TrustAnchors>, pins: &[[u8; 32]]) -> Self {
        ClientAuth {
            mode: Mode::Pinned(anchors, pins.to_vec()),
            ..ClientAuth::none()
        }
    }

    /// Checks client certificates against these CRLs.
    #[must_use]
    pub fn with_crls(mut self, crls: Crls, policy: RevocationPolicy) -> Self {
        self.crls = Some((crls, policy));
        self
    }

    /// Sends no CA names in the certificate request (when the names are sensitive).
    #[must_use]
    pub fn hide_ca_names(mut self) -> Self {
        self.hide_ca_names = true;
        self
    }

    /// Whether a client certificate is required.
    #[must_use]
    pub fn is_required(&self) -> bool {
        matches!(self.mode, Mode::Required(_) | Mode::Pinned(..))
    }

    /// SHA-256 over everything that decides whether a client certificate is
    /// accepted: the mode, the anchors, the pins, the CRLs and their policy
    /// (D-125). Tickets and cached sessions are bound to it, so a session
    /// authenticated under other rules does not resume here. Computed once
    /// per build; the CA-name setting is left out, since it accepts nothing.
    pub(crate) fn binding(&self) -> [u8; 32] {
        fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
            buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(bytes);
        }
        fn anchors(buf: &mut Vec<u8>, a: &TrustAnchors) {
            buf.push(u8::from(a.platform));
            buf.extend_from_slice(&(a.roots.roots.len() as u64).to_be_bytes());
            for r in &a.roots.roots {
                put(buf, r.subject.as_ref());
                put(buf, r.subject_public_key_info.as_ref());
                match &r.name_constraints {
                    Some(nc) => {
                        buf.push(1);
                        put(buf, nc.as_ref());
                    }
                    None => buf.push(0),
                }
            }
        }
        let mut buf = b"tls-net client-auth binding v1".to_vec();
        match &self.mode {
            Mode::None => buf.push(0),
            Mode::Optional(a) => {
                buf.push(1);
                anchors(&mut buf, a);
            }
            Mode::Required(a) => {
                buf.push(2);
                anchors(&mut buf, a);
            }
            Mode::Pinned(a, pins) => {
                buf.push(3);
                match a {
                    Some(a) => {
                        buf.push(1);
                        anchors(&mut buf, a);
                    }
                    None => buf.push(0),
                }
                let mut pins = pins.clone();
                pins.sort_unstable();
                pins.dedup();
                buf.extend_from_slice(&(pins.len() as u64).to_be_bytes());
                for p in &pins {
                    buf.extend_from_slice(p);
                }
            }
        }
        match &self.crls {
            Some((crls, policy)) => {
                buf.push(1);
                buf.push(policy.0);
                buf.extend_from_slice(&(crls.0.len() as u64).to_be_bytes());
                for c in crls.0.iter() {
                    put(&mut buf, c.as_ref());
                }
            }
            None => buf.push(0),
        }
        crypt_io::hash::sha256(&buf)
    }

    /// Whether client certificates are requested at all.
    pub(crate) fn is_enabled(&self) -> bool {
        !matches!(self.mode, Mode::None)
    }

    /// The rustls verifier for this mode, built with the explicit provider.
    pub(crate) fn verifier(
        &self,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
        let webpki = |anchors: &TrustAnchors,
                      optional: bool|
         -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
            if anchors.is_empty() {
                return Err(TlsError::PolicyInvalid {
                    reason: "client certificate anchors are empty",
                });
            }
            let mut b =
                WebPkiClientVerifier::builder_with_provider(anchors.roots(), Arc::clone(provider));
            if let Some((crls, policy)) = &self.crls {
                b = b.with_crls(crls.0.iter().cloned());
                if policy.contains(RevocationPolicy::END_ENTITY_ONLY) {
                    b = b.only_check_end_entity_revocation();
                }
                if policy.contains(RevocationPolicy::ALLOW_UNKNOWN_STATUS) {
                    b = b.allow_unknown_revocation_status();
                }
                if policy.contains(RevocationPolicy::ENFORCE_EXPIRY) {
                    b = b.enforce_revocation_expiration();
                }
            }
            if optional {
                b = b.allow_unauthenticated();
            }
            if self.hide_ca_names {
                b = b.clear_root_hint_subjects();
            }
            b.build().map_err(|_| TlsError::PolicyInvalid {
                reason: "client certificate anchors could not be used",
            })
        };
        // CRLs are checked by the webpki verifier, which needs anchors: with
        // none they would be accepted and never applied (D-131).
        if self.crls.is_some() && matches!(self.mode, Mode::None | Mode::Pinned(None, _)) {
            return Err(TlsError::PolicyInvalid {
                reason: "CRLs need client certificate anchors",
            });
        }
        match &self.mode {
            Mode::None => Ok(Arc::new(rustls::server::NoClientAuth)),
            Mode::Optional(a) => webpki(a, true),
            Mode::Required(a) => webpki(a, false),
            Mode::Pinned(anchors, pins) => {
                if pins.is_empty() {
                    return Err(TlsError::PolicyInvalid {
                        reason: "a pinned client needs at least one pin",
                    });
                }
                let inner = anchors.as_ref().map(|a| webpki(a, false)).transpose()?;
                Ok(Arc::new(PinnedClient {
                    inner,
                    pins: Pins(pins.clone()),
                    algs: provider.signature_verification_algorithms,
                }))
            }
        }
    }
}

/// A set of SPKI SHA-256 pins, compared in constant time.
#[derive(Clone)]
pub(crate) struct Pins(pub(crate) Vec<[u8; 32]>);

impl fmt::Debug for Pins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pins({})", self.0.len())
    }
}

impl Pins {
    /// Whether `cert`'s SPKI SHA-256 is one of the pins. Every pin is
    /// compared, without an early exit (T-21).
    fn matches(&self, cert: &CertificateDer<'_>) -> bool {
        let Some(facts) = crate::der::parse_certificate(cert.as_ref()) else {
            return false;
        };
        any_pin(&self.0, &crypt_io::hash::sha256(facts.spki))
    }
}

/// Compares `hash` with every pin in constant time, without an early exit.
fn any_pin(pins: &[[u8; 32]], hash: &[u8; 32]) -> bool {
    let mut hit = false;
    for pin in pins {
        hit |= crypt_io::Tag::new(*pin).ct_eq(hash);
    }
    hit
}

/// The error a pinned verifier reports; mapped back to `TlsError::PinMismatch`.
#[derive(Debug)]
pub(crate) struct PinMismatch;

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("peer key matches no pin")
    }
}

impl std::error::Error for PinMismatch {}

fn pin_mismatch() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(PinMismatch))))
}

/// Recovers `PinMismatch` from a rustls error.
pub(crate) fn pin_error(other: &OtherError) -> Option<TlsError> {
    other
        .0
        .downcast_ref::<PinMismatch>()
        .map(|_| TlsError::PinMismatch)
}

/// Checks the validity window of a self-issued pinned certificate.
fn check_validity(cert: &CertificateDer<'_>, now: UnixTime) -> Result<(), rustls::Error> {
    let facts = crate::der::parse_certificate(cert.as_ref()).ok_or(
        rustls::Error::InvalidCertificate(CertificateError::BadEncoding),
    )?;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(now.as_secs());
    if now < facts.not_before {
        return Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidYet,
        ));
    }
    if now >= facts.not_after {
        return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
    }
    Ok(())
}

/// A client verifier that requires a pinned key, on top of the normal chain
/// verification when anchors are given. Handshake signatures are always
/// verified with the provider's algorithms.
#[derive(Debug)]
struct PinnedClient {
    inner: Option<Arc<dyn ClientCertVerifier>>,
    pins: Pins,
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.as_ref().map_or(&[], |i| i.root_hint_subjects())
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match &self.inner {
            Some(inner) => {
                inner.verify_client_cert(end_entity, intermediates, now)?;
            }
            None => check_validity(end_entity, now)?,
        }
        if !self.pins.matches(end_entity) {
            return Err(pin_mismatch());
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The client side: a pinned server identity (`ServerIdentity::Pinned`).
#[derive(Debug)]
pub(crate) struct PinnedServer {
    pub(crate) inner: Option<Arc<dyn ServerCertVerifier>>,
    pub(crate) pins: Pins,
    pub(crate) algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match &self.inner {
            Some(inner) => {
                inner.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )?;
            }
            None => check_validity(end_entity, now)?,
        }
        if !self.pins.matches(end_entity) {
            return Err(pin_mismatch());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A server verifier with optional CRLs, built with the explicit provider.
pub(crate) fn server_verifier(
    anchors: &TrustAnchors,
    crls: Option<&(Crls, RevocationPolicy)>,
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<WebPkiServerVerifier>, TlsError> {
    let mut b = WebPkiServerVerifier::builder_with_provider(anchors.roots(), Arc::clone(provider));
    if let Some((crls, policy)) = crls {
        b = b.with_crls(crls.0.iter().cloned());
        if policy.contains(RevocationPolicy::END_ENTITY_ONLY) {
            b = b.only_check_end_entity_revocation();
        }
        if policy.contains(RevocationPolicy::ALLOW_UNKNOWN_STATUS) {
            b = b.allow_unknown_revocation_status();
        }
        if policy.contains(RevocationPolicy::ENFORCE_EXPIRY) {
            b = b.enforce_revocation_expiration();
        }
    }
    b.build().map_err(|_| TlsError::PolicyInvalid {
        reason: "the trust anchors could not be used",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-21: a pin that differs in its first byte takes as long to refuse as
    /// one that differs in its last byte. Opt-in (`TLS_NET_TIMING=1`, run
    /// with `--release` in CI): timing on shared machines is noisy, so the
    /// test takes the median of interleaved rounds and allows 25 percent.
    #[test]
    fn test_t21_pin_comparison_time_does_not_depend_on_the_data() {
        use std::hint::black_box;
        use std::time::Instant;
        if std::env::var_os("TLS_NET_TIMING").is_none() {
            return;
        }
        let hash = [0x5a; 32];
        let mut first = [[0x5a; 32]; 4];
        let mut last = [[0x5a; 32]; 4];
        for pin in &mut first {
            pin[0] ^= 1;
        }
        for pin in &mut last {
            pin[31] ^= 1;
        }
        let time = |pins: &[[u8; 32]]| {
            let start = Instant::now();
            for _ in 0..20_000 {
                black_box(any_pin(black_box(pins), black_box(&hash)));
            }
            start.elapsed().as_nanos()
        };
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for round in 0..101 {
            if round % 2 == 0 {
                a.push(time(&first));
                b.push(time(&last));
            } else {
                b.push(time(&last));
                a.push(time(&first));
            }
        }
        a.sort_unstable();
        b.sort_unstable();
        #[allow(clippy::cast_precision_loss)]
        let ratio = a[50] as f64 / b[50] as f64;
        assert!(
            (0.8..1.25).contains(&ratio),
            "first-byte vs last-byte median ratio {ratio:.3}"
        );
    }

    #[test]
    fn test_pins_match_only_the_right_key() {
        let pem =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/site.pem")).unwrap();
        let cert = CertificateDer::pem_slice_iter(&pem)
            .next()
            .unwrap()
            .unwrap();
        let spki =
            crypt_io::hash::sha256(crate::der::parse_certificate(cert.as_ref()).unwrap().spki);
        assert!(Pins(vec![[0; 32], spki]).matches(&cert));
        assert!(!Pins(vec![[0; 32]]).matches(&cert));
        let mut near = spki;
        near[31] ^= 1;
        assert!(!Pins(vec![near]).matches(&cert));
    }

    #[test]
    fn test_pin_error_round_trip() {
        let rustls::Error::InvalidCertificate(CertificateError::Other(o)) = pin_mismatch() else {
            panic!("shape");
        };
        assert_eq!(pin_error(&o), Some(TlsError::PinMismatch));
    }
}
