//! `TlsClient` and `ClientBuilder`: trust anchors, server identities, and the
//! STARTTLS helper. Server verification is always on (FR-25).

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::{Resumption, UnbufferedClientConnection};
use rustls::pki_types::{CertificateDer, ServerName};

use crate::error::{self, TlsError};
use crate::limits::HandshakeLimits;
use crate::policy::Policy;
use crate::server::Alpn;
use crate::session::ClientSession;

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
    roots: Arc<RootCertStore>,
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
        })
    }

    /// How many anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
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
            ServerIdentity::Dns(d) => {
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
    config: Option<Arc<rustls::ClientConfig>>,
    limits: HandshakeLimits,
    provider_name: &'static str,
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
            .field("anchors", &self.inner.config.is_some())
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

    /// A session for an identity.
    ///
    /// # Errors
    ///
    /// As `connect`.
    pub fn connect_to(&self, identity: &ServerIdentity) -> Result<ClientSession, TlsError> {
        let config = self.inner.config.as_ref().ok_or(TlsError::PolicyInvalid {
            reason: "no trust anchors",
        })?;
        let (name, shown) = identity.server_name()?;
        let conn = UnbufferedClientConnection::new(Arc::clone(config), name)
            .map_err(|e| error::from_rustls(&e))?;
        Ok(ClientSession::new(conn, shown, &self.inner.limits))
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

    /// The crypto provider: `"aws-lc-rs"` or `"ring"`.
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.inner.provider_name
    }
}

/// Builds a [`TlsClient`].
#[must_use]
#[derive(Debug)]
pub struct ClientBuilder {
    trust: Option<TrustAnchors>,
    policy: Policy,
    alpn: Vec<Alpn>,
    resumption: usize,
    send_sni: bool,
    limits: HandshakeLimits,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder::new()
    }
}

impl ClientBuilder {
    /// No anchors yet, the client default policy, resumption for 256 sessions.
    pub fn new() -> Self {
        ClientBuilder {
            trust: None,
            policy: Policy::client_default(),
            alpn: Vec::new(),
            resumption: 256,
            send_sni: true,
            limits: HandshakeLimits::client(),
        }
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
        self.limits = limits;
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
        let config = match self.trust {
            None => None,
            Some(anchors) => {
                let mut config = rustls::ClientConfig::builder_with_provider(provider)
                    .with_protocol_versions(&self.policy.rustls_versions())
                    .map_err(|_| TlsError::PolicyInvalid {
                        reason: "the provider cannot do these versions",
                    })?
                    .with_root_certificates(Arc::clone(&anchors.roots))
                    .with_no_client_auth();
                config.alpn_protocols = self.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
                config.enable_sni = self.send_sni;
                config.resumption = if self.resumption == 0 {
                    Resumption::disabled()
                } else {
                    Resumption::in_memory_sessions(self.resumption)
                };
                config.require_ems = self.policy.ems();
                config.max_fragment_size = self.policy.fragment().map(|f| f + 5);
                Some(Arc::new(config))
            }
        };
        Ok(TlsClient {
            inner: Arc::new(Inner {
                config,
                limits: self.limits,
                provider_name,
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
        ClientBuilder::new().trust(TrustAnchors::mozilla()).build()
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
    ClientBuilder::new()
        .trust(TrustAnchors::from_pem(ca_pem)?)
        .build()
}
