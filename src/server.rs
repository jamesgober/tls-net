//! `TlsServer` and `ServerBuilder`: certificates, SNI, ALPN, policy, budgets,
//! and the handshake capacity gate.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use rustls::server::ServerSessionMemoryCache;

use crate::certs::{self, CertificateEntry, Chain, KeySource, LoadLimits, LoadOptions, Purpose};
use crate::error::TlsError;
use crate::hello::HelloLimits;
use crate::limits::HandshakeLimits;
use crate::pem;
use crate::policy::{Policy, Preset};
use crate::session::ServerSession;
use crate::sni::{GroupResolver, SniTable};

/// An application protocol name for ALPN (RFC 7301): 1 to 255 bytes.
///
/// ```
/// use tls_net::Alpn;
/// assert_eq!(Alpn::H2.as_bytes(), b"h2");
/// assert_eq!(Alpn::new(b"smtp")?.as_bytes(), b"smtp");
/// assert!(Alpn::new(b"").is_err());
/// # Ok::<(), tls_net::TlsError>(())
/// ```
#[derive(Clone)]
pub struct Alpn(AlpnBytes);

#[derive(Clone)]
enum AlpnBytes {
    Static(&'static [u8]),
    Owned(Box<[u8]>),
}

impl Alpn {
    /// `http/1.1`.
    pub const HTTP_1_1: Alpn = Alpn(AlpnBytes::Static(b"http/1.1"));
    /// `h2`.
    pub const H2: Alpn = Alpn(AlpnBytes::Static(b"h2"));

    /// A protocol name of 1 to 255 bytes.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for an empty or over-long name.
    pub fn new(bytes: &[u8]) -> Result<Alpn, TlsError> {
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(TlsError::PolicyInvalid {
                reason: "an ALPN name must be 1 to 255 bytes",
            });
        }
        Ok(Alpn(AlpnBytes::Owned(bytes.into())))
    }

    /// The name.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            AlpnBytes::Static(b) => b,
            AlpnBytes::Owned(b) => b,
        }
    }
}

impl PartialEq for Alpn {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Alpn {}

impl std::hash::Hash for Alpn {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Debug for Alpn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Alpn({})", crate::error::escape(self.as_bytes()))
    }
}

/// What a ClientHello without SNI, or with a name no certificate covers, gets.
///
/// ```
/// assert_ne!(tls_net::UnknownName::UseDefault, tls_net::UnknownName::Refuse);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownName {
    /// Serve the default certificate (the first `certificate` call).
    UseDefault,
    /// Send `unrecognized_name` and fail with `UnknownServerName` (the same
    /// 7 bytes for every name, T-25).
    Refuse,
}

/// The handshake capacity gate (FR-46): one atomic per session.
#[derive(Debug)]
pub(crate) struct Capacity {
    in_progress: AtomicU32,
    max: u32,
}

/// One handshake slot; released when dropped.
#[derive(Debug)]
pub(crate) struct CapacitySlot(Arc<Capacity>);

impl Drop for CapacitySlot {
    fn drop(&mut self) {
        self.0.in_progress.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Capacity {
    fn acquire(self: &Arc<Self>) -> Option<CapacitySlot> {
        let prev = self.in_progress.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max {
            self.in_progress.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(CapacitySlot(Arc::clone(self)))
    }
}

/// One configuration snapshot: what every session started from it uses.
pub(crate) struct ServerState {
    /// One rustls configuration per host group.
    pub(crate) configs: Vec<Arc<rustls::ServerConfig>>,
    pub(crate) table: Arc<SniTable>,
    pub(crate) hello_limits: HelloLimits,
    pub(crate) limits: HandshakeLimits,
    pub(crate) entries: Vec<CertificateEntry>,
}

struct Inner {
    state: Arc<ServerState>,
    capacity: Arc<Capacity>,
    provider_name: &'static str,
}

/// A TLS server: certificates, policy, and budgets, ready to accept sessions.
///
/// Cloning is one `Arc` increment; clones share everything.
///
/// ```
/// let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
/// let chain = std::fs::read(format!("{dir}site.pem"))?;
/// let key = std::fs::read(format!("{dir}site.key"))?;
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
/// let server = tls_net::server_from_pem(&chain, &key)?;
/// let session = server.accept()?;
/// assert_eq!(session.state(), tls_net::SessionState::Hello);
/// # }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct TlsServer {
    inner: Arc<Inner>,
}

impl fmt::Debug for TlsServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsServer")
            .field("entries", &self.inner.state.entries.len())
            .field(
                "in_progress",
                &self.inner.capacity.in_progress.load(Ordering::Relaxed),
            )
            .field("provider", &self.inner.provider_name)
            .finish_non_exhaustive()
    }
}

impl TlsServer {
    /// A builder for a server with several certificates, ALPN, or a policy.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// A session for one accepted connection, in state `Hello`. Takes a
    /// handshake capacity slot first; the slot is released when the
    /// handshake completes, fails, or the session is dropped.
    ///
    /// # Errors
    ///
    /// `HandshakeCapacity` (`TLS-0030`) at the limit.
    pub fn accept(&self) -> Result<ServerSession, TlsError> {
        let slot = self
            .inner
            .capacity
            .acquire()
            .ok_or(TlsError::HandshakeCapacity)?;
        Ok(ServerSession::new(Arc::clone(&self.inner.state), slot))
    }

    /// The crypto provider: `"aws-lc-rs"` or `"ring"`.
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.inner.provider_name
    }

    /// Handshakes in progress now.
    #[must_use]
    pub fn handshakes_in_progress(&self) -> u32 {
        self.inner.capacity.in_progress.load(Ordering::Relaxed)
    }
}

/// A certificate waiting for `build`.
struct Pending {
    entry: CertificateEntry,
    is_default: bool,
}

/// Builds a [`TlsServer`]. Methods that parse return `Result` at once, so an
/// error points at the call that caused it.
///
/// ```
/// use tls_net::{Alpn, KeySource, Policy, TlsServer};
/// let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
/// let (chain, key) = (std::fs::read(format!("{dir}site.pem"))?, std::fs::read(format!("{dir}site.key"))?);
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
/// let server = TlsServer::builder()
///     .certificate(&chain, KeySource::Pem(&key))?
///     .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
///     .policy(Policy::modern())
///     .build()?;
/// # }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub struct ServerBuilder {
    pending: Vec<Pending>,
    unknown: Option<UnknownName>,
    alpn: Vec<Alpn>,
    policy: Policy,
    limits: HandshakeLimits,
    load_limits: LoadLimits,
}

impl fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("certificates", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        ServerBuilder::new()
    }
}

impl ServerBuilder {
    /// An empty builder with the `compatible` policy and default budgets.
    pub fn new() -> Self {
        ServerBuilder {
            pending: Vec::new(),
            unknown: None,
            alpn: Vec::new(),
            policy: Policy::compatible(),
            limits: HandshakeLimits::server(),
            load_limits: LoadLimits::new(),
        }
    }

    fn options(&self) -> LoadOptions {
        LoadOptions {
            limits: self.load_limits,
            ..LoadOptions::new(Purpose::Server)
        }
    }

    /// The default certificate: served for any name it covers (its SANs), and
    /// for unknown names when `UnknownName::UseDefault`. The first call
    /// registers the default; later calls add entries named by their SANs.
    ///
    /// # Errors
    ///
    /// `TLS-0011` to `TLS-0019` from the load-time checks.
    pub fn certificate(mut self, chain_pem: &[u8], key: KeySource<'_>) -> Result<Self, TlsError> {
        let entry = certs::load(Chain::Pem(chain_pem), key, None, &self.options())?;
        let is_default = !self.pending.iter().any(|p| p.is_default);
        self.pending.push(Pending { entry, is_default });
        Ok(self)
    }

    /// A certificate for explicit names (exact or `*.` wildcards), each of
    /// which the certificate must cover.
    ///
    /// # Errors
    ///
    /// `TLS-0011` to `TLS-0019`; `NameNotCovered` for a name outside its SANs.
    pub fn certificate_for(
        mut self,
        names: &[&str],
        chain_pem: &[u8],
        key: KeySource<'_>,
    ) -> Result<Self, TlsError> {
        if names.is_empty() {
            return Err(TlsError::PolicyInvalid {
                reason: "certificate_for needs at least one name",
            });
        }
        let entry = certs::load(Chain::Pem(chain_pem), key, Some(names), &self.options())?;
        self.pending.push(Pending {
            entry,
            is_default: false,
        });
        Ok(self)
    }

    /// As [`certificate`](Self::certificate), with the chain as DER.
    ///
    /// # Errors
    ///
    /// As `certificate`.
    pub fn certificate_der(
        mut self,
        chain_der: &[&[u8]],
        key: KeySource<'_>,
    ) -> Result<Self, TlsError> {
        let entry = certs::load(Chain::Der(chain_der), key, None, &self.options())?;
        let is_default = !self.pending.iter().any(|p| p.is_default);
        self.pending.push(Pending { entry, is_default });
        Ok(self)
    }

    /// What unknown names get. Default: `UseDefault` with a default
    /// certificate, else `Refuse`; `Policy::internal()` refuses.
    pub fn unknown_name(mut self, behaviour: UnknownName) -> Self {
        self.unknown = Some(behaviour);
        self
    }

    /// The ALPN protocols, in the server's order of preference.
    pub fn alpn(mut self, protocols: &[Alpn]) -> Self {
        self.alpn = protocols.to_vec();
        self
    }

    /// The policy (default `Policy::compatible()`).
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// The handshake budgets.
    pub fn limits(mut self, limits: HandshakeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Budgets for certificate and key intake. Set before adding certificates.
    pub fn load_limits(mut self, limits: LoadLimits) -> Self {
        self.load_limits = limits;
        self
    }

    /// Checks everything and builds the server.
    ///
    /// # Errors
    ///
    /// `NoProvider`; `PolicyInvalid` (no certificate, duplicate ALPN names,
    /// an inconsistent policy); `PostQuantumUnavailable`; `DuplicateName`.
    pub fn build(self) -> Result<TlsServer, TlsError> {
        let provider_name = crate::provider::parts().ok_or(TlsError::NoProvider)?.name;
        if self.pending.is_empty() {
            return Err(TlsError::PolicyInvalid {
                reason: "a server needs at least one certificate",
            });
        }
        for (i, a) in self.alpn.iter().enumerate() {
            if self.alpn[i + 1..].contains(a) {
                return Err(TlsError::PolicyInvalid {
                    reason: "the ALPN list repeats a name",
                });
            }
        }
        #[cfg(feature = "net-io")]
        if self.policy.fragment().is_some_and(|f| f < 512) {
            return Err(TlsError::PolicyInvalid {
                reason: "max_fragment_size below 512 does not fit net-io's write path",
            });
        }
        let provider = self.policy.provider()?;

        let mut table = SniTable::new();
        let group = 0;
        let mut entries = Vec::with_capacity(self.pending.len());
        for p in self.pending {
            let index = table.add_key(Arc::clone(&p.entry.certified), p.entry.entry_key());
            for name in &p.entry.names {
                if !table.add_name(name, index, group) {
                    return Err(TlsError::DuplicateName { name: name.clone() });
                }
            }
            if p.is_default {
                let refuse = match self.unknown {
                    Some(u) => u == UnknownName::Refuse,
                    None => self.policy.preset() == Preset::Internal,
                };
                table.set_default(index, group, !refuse);
            }
            entries.push(p.entry);
        }
        let table = Arc::new(table);

        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&self.policy.rustls_versions())
            .map_err(|_| TlsError::PolicyInvalid {
                reason: "the provider cannot serve these versions",
            })?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(GroupResolver {
                table: Arc::clone(&table),
                group,
            }));
        config.alpn_protocols = self.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        config.ignore_client_order = self.policy.server_order_wins();
        config.max_fragment_size = self.policy.fragment().map(|f| f + 5);
        config.require_ems = self.policy.ems();
        config.session_storage = ServerSessionMemoryCache::new(1024);
        if self.policy.preset() == Preset::Internal {
            config.send_tls13_tickets = 0;
        }

        let state = ServerState {
            configs: vec![Arc::new(config)],
            table,
            hello_limits: HelloLimits::new(),
            limits: self.limits,
            entries,
        };
        let capacity = Arc::new(Capacity {
            in_progress: AtomicU32::new(0),
            max: self.limits.max_in_progress,
        });
        Ok(TlsServer {
            inner: Arc::new(Inner {
                state: Arc::new(state),
                capacity,
                provider_name,
            }),
        })
    }
}

/// A server with `Policy::compatible()`, this chain and key as the default
/// certificate, ALPN `http/1.1`, and default budgets.
///
/// # Errors
///
/// `TLS-0001`, `TLS-0011`, `TLS-0013` to `TLS-0019`.
///
/// ```
/// let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
/// let (chain, key) = (std::fs::read(format!("{dir}site.pem"))?, std::fs::read(format!("{dir}site.key"))?);
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))]
/// let server = tls_net::server_from_pem(&chain, &key)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn server_from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<TlsServer, TlsError> {
    ServerBuilder::new()
        .certificate(chain_pem, KeySource::Pem(key_pem))?
        .alpn(&[Alpn::HTTP_1_1])
        .build()
}

/// As [`server_from_pem`], reading the files with the size gate and, on
/// Unix, the key file permission check (mode `0600` or stricter).
///
/// # Errors
///
/// As `server_from_pem`, plus `TLS-0010` and `TLS-0012`.
pub fn server_from_files(
    chain: impl AsRef<Path>,
    key: impl AsRef<Path>,
) -> Result<TlsServer, TlsError> {
    let limits = LoadLimits::new();
    let chain = pem::read_file(chain.as_ref(), limits.max_chain_file_bytes, false, false)?;
    ServerBuilder::new()
        .certificate(&chain, KeySource::File(key.as_ref()))?
        .alpn(&[Alpn::HTTP_1_1])
        .build()
}
