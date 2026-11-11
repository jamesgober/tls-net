//! `TlsClient` and `ClientBuilder`: trust anchors, server identities, and the
//! STARTTLS helper. Server verification is always on (FR-25).

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::{ResolvesClientCert, Resumption, UnbufferedClientConnection};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, SignatureScheme};

use crate::certs::{self, CertificateEntry, Chain, KeySource, LoadOptions, Purpose};
use crate::error::{self, TlsError};
use crate::limits::HandshakeLimits;
use crate::observe::{Observation, TlsObserver};
use crate::policy::Policy;
use crate::server::Alpn;
use crate::session::ClientSession;
use crate::verify::{Crls, PinnedServer, Pins, RevocationPolicy};

/// Certificates a client trusts as roots.
///
/// ```
/// let ca = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.pem"))?;
/// let anchors = tls_net::TrustAnchors::from_pem(&ca)?;
/// assert_eq!(anchors.len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct TrustAnchors {
    pub(crate) roots: Arc<RootCertStore>,
    /// Verify with the operating system instead (feature `platform-verifier`).
    pub(crate) platform: bool,
}

impl fmt::Debug for TrustAnchors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrustAnchors({} roots)", self.roots.len())
    }
}

/// The most anchors one PEM or DER input may hold.
const MAX_ANCHORS: usize = 4096;

impl TrustAnchors {
    /// The Mozilla root program bundle (webpki-roots): the same roots on every
    /// platform, updated with tls-net releases.
    #[cfg(feature = "webpki-roots")]
    #[must_use]
    pub fn mozilla() -> TrustAnchors {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        TrustAnchors {
            roots: Arc::new(roots),
            platform: false,
        }
    }

    /// Anchors from PEM `CERTIFICATE` blocks (a private CA).
    ///
    /// # Errors
    ///
    /// `PemInvalid`, `NoCertificate`, `ChainTooLong` (over 4,096), `BadAnchor`.
    pub fn from_pem(pem: &[u8]) -> Result<TrustAnchors, TlsError> {
        let certs = crate::pem::certificates(pem, MAX_ANCHORS)?;
        TrustAnchors::from_certs(certs)
    }

    /// Anchors from DER certificates.
    ///
    /// # Errors
    ///
    /// `NoCertificate`, `ChainTooLong` (over 4,096), `BadAnchor`.
    pub fn from_der(certs: &[&[u8]]) -> Result<TrustAnchors, TlsError> {
        TrustAnchors::from_certs(crate::pem::certificates_der(certs, MAX_ANCHORS)?)
    }

    fn from_certs(certs: Vec<CertificateDer<'static>>) -> Result<TrustAnchors, TlsError> {
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|_| TlsError::BadAnchor)?;
        }
        Ok(TrustAnchors {
            roots: Arc::new(roots),
            platform: false,
        })
    }

    /// The operating system's verifier (feature `platform-verifier`): Windows
    /// and macOS use the OS store with revocation; Linux uses the system
    /// bundle without revocation. `len()` is 0 (the OS holds the roots).
    #[cfg(feature = "platform-verifier")]
    #[must_use]
    pub fn platform() -> TrustAnchors {
        TrustAnchors {
            roots: Arc::new(RootCertStore::empty()),
            platform: true,
        }
    }

    #[cfg(feature = "platform-verifier")]
    pub(crate) fn is_platform(&self) -> bool {
        self.platform
    }

    pub(crate) fn roots(&self) -> Arc<RootCertStore> {
        Arc::clone(&self.roots)
    }

    /// How many anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether there are none (and the platform verifier is not used).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty() && !self.platform
    }
}

/// A validated DNS name in A-label form, as the caller gave it.
///
/// ```
/// assert_eq!(tls_net::DnsName::new("smtp.example.com")?.as_str(), "smtp.example.com");
/// assert!(tls_net::DnsName::new("caf\u{e9}.example").is_err());
/// assert!(tls_net::DnsName::new("10.0.0.1").is_err());
/// # Ok::<(), tls_net::TlsError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DnsName(Box<str>);

impl DnsName {
    /// Validates `s` as a DNS name (A-labels only; IP literals are refused).
    ///
    /// # Errors
    ///
    /// `InvalidName`.
    pub fn new(s: &str) -> Result<DnsName, TlsError> {
        let invalid = || TlsError::InvalidName {
            name: error::escape(s.as_bytes()),
        };
        if s.parse::<IpAddr>().is_ok() {
            return Err(invalid());
        }
        rustls::pki_types::DnsName::try_from(s).map_err(|_| invalid())?;
        Ok(DnsName(s.into()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who the client expects to talk to.
///
/// ```
/// use tls_net::ServerIdentity;
/// assert!(matches!(ServerIdentity::parse("example.com")?, ServerIdentity::Dns(_)));
/// assert!(matches!(ServerIdentity::parse("::1")?, ServerIdentity::Ip(_)));
/// # Ok::<(), tls_net::TlsError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerIdentity {
    /// A DNS name: sent as SNI and checked against the certificate.
    Dns(DnsName),
    /// An IP address: no SNI is sent (RFC 6066); the certificate must carry it.
    Ip(IpAddr),
    /// A DNS name whose server key must match one of the SPKI SHA-256 pins.
    /// With `require_chain` the chain is verified against the client's
    /// anchors first; without, a self-issued certificate is accepted when its
    /// key matches a pin (the name is not checked). The handshake signature
    /// and the validity window are always verified (T-6b).
    Pinned {
        /// Sent as SNI (and checked, with `require_chain`).
        name: DnsName,
        /// SHA-256 of acceptable SubjectPublicKeyInfos.
        spki_sha256: Vec<[u8; 32]>,
        /// Verify the chain against the anchors as well. Required on a
        /// client with CRLs, which are checked on the chain only.
        require_chain: bool,
    },
}

impl ServerIdentity {
    /// A DNS name or an IP literal.
    ///
    /// # Errors
    ///
    /// `InvalidName`.
    pub fn parse(s: &str) -> Result<ServerIdentity, TlsError> {
        match s.parse::<IpAddr>() {
            Ok(ip) => Ok(ServerIdentity::Ip(ip)),
            Err(_) => DnsName::new(s).map(ServerIdentity::Dns),
        }
    }

    fn server_name(&self) -> Result<(ServerName<'static>, Box<str>), TlsError> {
        match self {
            ServerIdentity::Dns(d) | ServerIdentity::Pinned { name: d, .. } => {
                let name =
                    rustls::pki_types::DnsName::try_from(d.as_str().to_owned()).map_err(|_| {
                        TlsError::InvalidName {
                            name: error::escape(d.as_str().as_bytes()),
                        }
                    })?;
                Ok((ServerName::DnsName(name), d.0.clone()))
            }
            ServerIdentity::Ip(ip) => {
                Ok((ServerName::IpAddress((*ip).into()), ip.to_string().into()))
            }
        }
    }
}

struct Inner {
    /// Verifies against the anchors; refuses every certificate without them.
    config: Arc<rustls::ClientConfig>,
    anchors: bool,
    /// CRLs were given: a pin alone is refused (D-145).
    crls: bool,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
    limits: HandshakeLimits,
    provider_name: &'static str,
    /// The anchors' chain verifier (webpki with the CRLs, or the platform's),
    /// for pinned identities that also require a chain (D-133).
    chain: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    /// One configuration per pin set, so a pinned identity resumes: rustls
    /// resumes only with the verifier that made the session (D-133).
    pinned: std::sync::Mutex<Vec<PinnedConfig>>,
    obs: Arc<Observation>,
}

/// A pin set (sorted), whether it requires a chain, and its configuration.
type PinnedConfig = (Vec<[u8; 32]>, bool, Arc<rustls::ClientConfig>);

/// The most pinned configurations a client keeps (the oldest goes first).
const PINNED_CONFIGS: usize = 16;

/// One client certificate for mutual TLS.
#[derive(Debug)]
struct OneClientCert(Arc<CertifiedKey>);

impl ResolvesClientCert for OneClientCert {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The verifier of a client without anchors: every certificate is refused
/// unless a pinned identity replaces it for one connection.
#[derive(Debug)]
struct NoAnchors(rustls::crypto::WebPkiSupportedAlgorithms);

impl rustls::client::danger::ServerCertVerifier for NoAnchors {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// A TLS client. Keep it and reuse it: it holds the resumption store, which
/// separate clients never share (FR-29).
///
/// ```
/// let ca = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.pem"))?;
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
/// let client = tls_net::client_with_ca_pem(&ca)?;
/// let session = client.connect("localhost")?;
/// assert_eq!(session.state(), tls_net::SessionState::Handshake);
/// # }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct TlsClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsClient")
            .field("anchors", &self.inner.anchors)
            .field("provider", &self.inner.provider_name)
            .finish_non_exhaustive()
    }
}

impl TlsClient {
    /// A builder for trust, policy, ALPN, and resumption.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// A session for `server_name` (a DNS name, or an IP literal for which no
    /// SNI is sent). The name is used for verification exactly as given.
    ///
    /// # Errors
    ///
    /// `InvalidName`; `PolicyInvalid` when the client has no trust anchors.
    pub fn connect(&self, server_name: &str) -> Result<ClientSession, TlsError> {
        self.connect_to(&ServerIdentity::parse(server_name)?)
    }

    /// Connects over a blocking transport and runs the handshake: a
    /// [`TlsStream`](crate::TlsStream) that reads and writes plaintext.
    ///
    /// ```no_run
    /// # #[cfg(feature = "webpki-roots")] {
    /// use std::io::Write;
    /// let tcp = std::net::TcpStream::connect("example.com:443")?;
    /// let mut tls = tls_net::client()?.connect_stream("example.com", tcp)?;
    /// tls.write_all(b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n")?;
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As `connect`; then the handshake's error, `Transport` when the
    /// transport fails, or `UncleanClose` when it ends first.
    pub fn connect_stream<S: std::io::Read + std::io::Write>(
        &self,
        server_name: &str,
        io: S,
    ) -> Result<crate::TlsStream<S>, TlsError> {
        crate::TlsStream::client(self.connect(server_name)?, io)
    }

    /// A session for an identity.
    ///
    /// # Errors
    ///
    /// As `connect`.
    pub fn connect_to(&self, identity: &ServerIdentity) -> Result<ClientSession, TlsError> {
        let no_anchors = TlsError::PolicyInvalid {
            reason: "no trust anchors",
        };
        let config = match identity {
            ServerIdentity::Pinned {
                spki_sha256,
                require_chain,
                ..
            } => {
                if spki_sha256.is_empty() {
                    return Err(TlsError::PolicyInvalid {
                        reason: "a pinned identity needs at least one pin",
                    });
                }
                if *require_chain && !self.inner.anchors {
                    return Err(no_anchors);
                }
                // A pin alone checks no CRL: a client that has CRLs checks the
                // chain too, so a revoked certificate is refused (D-145).
                if !*require_chain && self.inner.crls {
                    return Err(TlsError::PolicyInvalid {
                        reason: "a client with CRLs needs require_chain on a pinned identity",
                    });
                }
                self.pinned_config(spki_sha256, *require_chain)
            }
            _ if !self.inner.anchors => return Err(no_anchors),
            _ => Arc::clone(&self.inner.config),
        };
        let (name, shown) = identity.server_name()?;
        let conn =
            UnbufferedClientConnection::new(config, name).map_err(|e| error::from_rustls(&e))?;
        Ok(ClientSession::new(
            conn,
            shown,
            &self.inner.limits,
            Arc::clone(&self.inner.obs),
        ))
    }

    /// The configuration for a pin set: kept, so a second connection to the
    /// same pinned identity resumes. The resumption store is the client's
    /// (it sits behind an Arc), and the chain verifier is the one the client
    /// was built with, the platform's included.
    fn pinned_config(&self, pins: &[[u8; 32]], require_chain: bool) -> Arc<rustls::ClientConfig> {
        let mut key = pins.to_vec();
        key.sort_unstable();
        key.dedup();
        let mut cache = self
            .inner
            .pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, _, config)) = cache
            .iter()
            .find(|(k, chain, _)| *k == key && *chain == require_chain)
        {
            return Arc::clone(config);
        }
        let mut config = (*self.inner.config).clone();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(PinnedServer {
                inner: if require_chain {
                    self.inner.chain.clone()
                } else {
                    None
                },
                pins: Pins(key.clone()),
                algs: self.inner.algs,
            }));
        let config = Arc::new(config);
        if cache.len() == PINNED_CONFIGS {
            cache.remove(0);
        }
        cache.push((key, require_chain, Arc::clone(&config)));
        config
    }

    /// A session that starts TLS after a plaintext phase (STARTTLS).
    /// `leftover` is every byte received after the upgrade reply; it must be
    /// empty, because bytes there would be treated as if they came over TLS
    /// (response injection, T-5).
    ///
    /// # Errors
    ///
    /// `StartTlsInjection` when `leftover` is not empty; otherwise as `connect`.
    ///
    /// ```
    /// let ca = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.pem"))?;
    /// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
    /// let client = tls_net::client_with_ca_pem(&ca)?;
    /// let e = client.start_after_plaintext("localhost", b"250 injected\r\n").unwrap_err();
    /// assert_eq!(e, tls_net::TlsError::StartTlsInjection);
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn start_after_plaintext(
        &self,
        server_name: &str,
        leftover: &[u8],
    ) -> Result<ClientSession, TlsError> {
        if !leftover.is_empty() {
            return Err(TlsError::StartTlsInjection);
        }
        self.connect(server_name)
    }

    /// The crypto provider: `"aws-lc-rs"`, `"aws-lc-rs (FIPS)"`, or `"ring"`.
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.inner.provider_name
    }

    /// Whether the configuration runs in FIPS mode (rustls `ClientConfig::fips`).
    #[must_use]
    pub fn is_fips(&self) -> bool {
        self.inner.config.fips()
    }

    /// The built rustls configuration. Outside semver (feature
    /// `rustls-escape-hatch`).
    #[cfg(feature = "rustls-escape-hatch")]
    #[must_use]
    pub fn as_rustls_config(&self) -> Arc<rustls::ClientConfig> {
        Arc::clone(&self.inner.config)
    }
}

/// Builds a [`TlsClient`].
#[must_use]
pub struct ClientBuilder {
    trust: Option<TrustAnchors>,
    policy: Policy,
    alpn: Vec<Alpn>,
    resumption: usize,
    send_sni: bool,
    limits: HandshakeLimits,
    certificate: Option<CertificateEntry>,
    crls: Option<(Crls, RevocationPolicy)>,
    observer: Option<Arc<dyn TlsObserver>>,
    #[cfg(feature = "dangerous-keylog")]
    key_log: Option<Arc<dyn crate::server::KeyLogSink>>,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// No anchors yet, the client default policy, resumption for 256 sessions.
    /// `TlsClient::builder()` is the public way in (one way to start, S-6).
    pub(crate) fn new() -> Self {
        ClientBuilder {
            trust: None,
            policy: Policy::client_default(),
            alpn: Vec::new(),
            resumption: 256,
            send_sni: true,
            limits: HandshakeLimits::client(),
            certificate: None,
            crls: None,
            observer: None,
            #[cfg(feature = "dangerous-keylog")]
            key_log: None,
        }
    }

    /// Sends NSS key log lines to `sink` (feature `dangerous-keylog`). For
    /// debugging only; refused together with FIPS.
    #[cfg(feature = "dangerous-keylog")]
    pub fn dangerous_key_log(mut self, sink: Arc<dyn crate::server::KeyLogSink>) -> Self {
        self.key_log = Some(sink);
        self
    }

    /// The observer that receives this client's events.
    pub fn observer(mut self, observer: Arc<dyn TlsObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// A client certificate for mutual TLS: the same load-time checks as a
    /// server certificate, with `clientAuth` in place of `serverAuth`.
    ///
    /// # Errors
    ///
    /// `TLS-0010` to `TLS-0020` from the load-time checks.
    pub fn client_certificate(
        mut self,
        chain_pem: &[u8],
        key: KeySource<'_>,
    ) -> Result<Self, TlsError> {
        let entry = certs::load(
            Chain::Pem(chain_pem),
            key,
            None,
            &LoadOptions::new(Purpose::Client),
        )?;
        self.certificate = Some(entry);
        Ok(self)
    }

    /// Checks server certificates against these CRLs. They are checked on
    /// the chain, so they need [`trust`](Self::trust), and a pinned identity
    /// on this client needs `require_chain: true`; `build` and `connect_to`
    /// refuse otherwise.
    pub fn crls(mut self, crls: Crls, policy: RevocationPolicy) -> Self {
        self.crls = Some((crls, policy));
        self
    }

    /// The trust anchors.
    pub fn trust(mut self, anchors: TrustAnchors) -> Self {
        self.trust = Some(anchors);
        self
    }

    /// The policy (default `Policy::client_default()`).
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// The ALPN protocols to offer, in order.
    pub fn alpn(mut self, protocols: &[Alpn]) -> Self {
        self.alpn = protocols.to_vec();
        self
    }

    /// Sessions kept for resumption; 0 disables it.
    pub fn resumption(mut self, sessions: usize) -> Self {
        self.resumption = sessions;
        self
    }

    /// Whether to send SNI (default on).
    pub fn send_sni(mut self, on: bool) -> Self {
        self.send_sni = on;
        self
    }

    /// The handshake budgets (client defaults: 128 KiB, 10 certificates of at most 32 KiB).
    pub fn limits(mut self, limits: HandshakeLimits) -> Self {
        self.limits = limits.clamped();
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// `NoProvider`, `PolicyInvalid`, `PostQuantumUnavailable`.
    pub fn build(self) -> Result<TlsClient, TlsError> {
        let provider_name = crate::provider::parts().ok_or(TlsError::NoProvider)?.name;
        let provider = self.policy.provider()?;
        let algs = provider.signature_verification_algorithms;
        let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&self.policy.rustls_versions())
            .map_err(|_| TlsError::PolicyInvalid {
                reason: "the provider cannot do these versions",
            })?;
        let anchors = self.trust.is_some();
        // CRLs are checked on the chain, so without anchors they would never
        // be applied (D-145; the server refuses the same since D-131).
        if self.crls.is_some() && !anchors {
            return Err(TlsError::PolicyInvalid {
                reason: "CRLs need trust anchors",
            });
        }
        let chain: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>> = match &self.trust {
            #[cfg(feature = "platform-verifier")]
            Some(anchors) if anchors.is_platform() => {
                if self.crls.is_some() {
                    return Err(TlsError::PolicyInvalid {
                        reason: "CRLs cannot be combined with the platform verifier",
                    });
                }
                let v = rustls_platform_verifier::Verifier::new(Arc::clone(&provider)).map_err(
                    |_| TlsError::PolicyInvalid {
                        reason: "the platform verifier is not available",
                    },
                )?;
                Some(Arc::new(v))
            }
            Some(anchors) => Some(crate::verify::server_verifier(
                anchors,
                self.crls.as_ref(),
                &provider,
            )?),
            None => None,
        };
        let builder = builder.dangerous().with_custom_certificate_verifier(
            chain.clone().unwrap_or_else(|| Arc::new(NoAnchors(algs))),
        );
        let mut config = match self.certificate {
            Some(entry) => builder
                .with_client_cert_resolver(Arc::new(OneClientCert(Arc::clone(&entry.certified)))),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = self.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        config.enable_sni = self.send_sni;
        config.resumption = if self.resumption == 0 {
            Resumption::disabled()
        } else {
            Resumption::in_memory_sessions(self.resumption)
        };
        config.require_ems = self.policy.ems();
        config.max_fragment_size = self.policy.fragment().map(|f| f + 5);
        if self.policy.requires_fips() && !config.fips() {
            return Err(TlsError::FipsUnavailable);
        }
        #[cfg(feature = "dangerous-keylog")]
        if let Some(sink) = &self.key_log {
            if config.fips() || self.policy.requires_fips() {
                return Err(TlsError::PolicyInvalid {
                    reason: "key logging is refused together with FIPS",
                });
            }
            config.key_log = Arc::new(crate::server::KeyLogAdapter(Arc::clone(sink)));
        }
        Ok(TlsClient {
            inner: Arc::new(Inner {
                config: Arc::new(config),
                anchors,
                crls: self.crls.is_some(),
                algs,
                limits: self.limits,
                provider_name,
                chain,
                pinned: std::sync::Mutex::new(Vec::new()),
                obs: Arc::new(Observation::new(self.observer, 0)),
            }),
        })
    }
}

/// A client with the Mozilla roots, the client default policy, and
/// resumption on. Verification is always on.
///
/// # Errors
///
/// `NoProvider`; `PolicyInvalid` without the `webpki-roots` feature.
pub fn client() -> Result<TlsClient, TlsError> {
    #[cfg(feature = "webpki-roots")]
    {
        TlsClient::builder().trust(TrustAnchors::mozilla()).build()
    }
    #[cfg(not(feature = "webpki-roots"))]
    {
        crate::provider::parts().ok_or(TlsError::NoProvider)?;
        Err(TlsError::PolicyInvalid {
            reason: "no trust anchors",
        })
    }
}

/// A client that trusts only the given CA certificates.
///
/// # Errors
///
/// `NoProvider`, `PemInvalid`, `NoCertificate`, `BadAnchor`.
pub fn client_with_ca_pem(ca_pem: &[u8]) -> Result<TlsClient, TlsError> {
    TlsClient::builder()
        .trust(TrustAnchors::from_pem(ca_pem)?)
        .build()
}
