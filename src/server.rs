//! `TlsServer` and `ServerBuilder`: certificates, SNI and host groups, ALPN,
//! client authentication, tickets, the hello hook, budgets, the capacity
//! gate, reload, and expiry reports.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::sync::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache, StoresServerSessions};
use rustls::sign::CertifiedKey;

use crate::certs::{self, CertificateEntry, Chain, KeySource, LoadLimits, LoadOptions, Purpose};
use crate::error::TlsError;
use crate::expiry::{self, ExpiryReport};
use crate::fingerprint::FingerprintKinds;
use crate::hello::HelloLimits;
use crate::hook::HelloHook;
use crate::limits::HandshakeLimits;
use crate::observe::{Observation, ServerStats, TlsEvent, TlsObserver};
use crate::pem;
use crate::policy::{Policy, Preset};
use crate::session::ServerSession;
use crate::snapshot::{Reader, Snapshot};
use crate::sni::{self, GroupResolver, SniTable};
use crate::tickets::{BoundTickets, TicketKeyRing, TicketKeyRingHandle, TicketMode};
use crate::verify::ClientAuth;

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

/// Whether a listener requires ALPN.
///
/// ```
/// assert_eq!(tls_net::AlpnPolicy::default(), tls_net::AlpnPolicy::Optional);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AlpnPolicy {
    /// A ClientHello without ALPN is served (default).
    #[default]
    Optional,
    /// A ClientHello without ALPN is refused with `no_application_protocol`
    /// (T-15, cross-protocol attacks).
    Required,
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

/// Overrides for named hosts (FR-21); unset fields inherit the server's.
///
/// ```
/// use tls_net::{Alpn, AlpnPolicy, HostPolicy};
/// let admin = HostPolicy::new().alpn(&[Alpn::H2]).alpn_policy(AlpnPolicy::Required);
/// # let _ = admin;
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct HostPolicy {
    /// The ALPN list for these hosts.
    pub alpn: Option<Vec<Alpn>>,
    /// Whether these hosts require ALPN.
    pub alpn_policy: Option<AlpnPolicy>,
    /// Client certificates for these hosts.
    pub client_auth: Option<ClientAuth>,
    /// The policy for these hosts.
    pub policy: Option<Policy>,
}

impl HostPolicy {
    /// No overrides.
    #[must_use]
    pub fn new() -> Self {
        HostPolicy::default()
    }

    /// The ALPN list for these hosts.
    #[must_use]
    pub fn alpn(mut self, protocols: &[Alpn]) -> Self {
        self.alpn = Some(protocols.to_vec());
        self
    }

    /// Whether these hosts require ALPN.
    #[must_use]
    pub fn alpn_policy(mut self, policy: AlpnPolicy) -> Self {
        self.alpn_policy = Some(policy);
        self
    }

    /// Client certificates for these hosts.
    #[must_use]
    pub fn client_auth(mut self, auth: ClientAuth) -> Self {
        self.client_auth = Some(auth);
        self
    }

    /// The policy for these hosts.
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// The handshake capacity gate (FR-46): one atomic per session.
#[derive(Debug)]
pub(crate) struct Capacity {
    in_progress: AtomicU32,
    max: u32,
}

/// One handshake slot. It holds no reference: the session that owns it
/// releases it through its snapshot's `capacity` (D-102).
#[derive(Debug)]
pub(crate) struct CapacitySlot(());

impl Capacity {
    fn acquire(&self) -> Option<CapacitySlot> {
        let prev = self.in_progress.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max {
            self.in_progress.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(CapacitySlot(()))
    }

    /// Gives back a slot `acquire` handed out.
    pub(crate) fn release(&self, slot: CapacitySlot) {
        let CapacitySlot(()) = slot;
        self.in_progress.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What a host group's sessions need besides its rustls configuration.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Group {
    pub(crate) alpn_required: bool,
    /// The group requires a client certificate (checked again on resumption, D-125).
    pub(crate) auth_required: bool,
    pub(crate) max_handshake_bytes: u32,
}

/// One configuration snapshot: what every session started from it uses.
pub(crate) struct ServerState {
    /// One rustls configuration per host group.
    pub(crate) configs: Vec<Arc<rustls::ServerConfig>>,
    pub(crate) groups: Vec<Group>,
    pub(crate) table: Arc<SniTable>,
    pub(crate) hello_limits: HelloLimits,
    pub(crate) limits: HandshakeLimits,
    pub(crate) entries: Vec<CertificateEntry>,
    pub(crate) hook: Option<Arc<dyn HelloHook>>,
    pub(crate) fingerprints: FingerprintKinds,
    pub(crate) obs: Arc<Observation>,
    /// The server's handshake gate, the same in every snapshot.
    pub(crate) capacity: Arc<Capacity>,
}

/// The wall clock for the checks at completion. Unit tests move it forward
/// to reach a client certificate's expiry on resumption (D-125).
pub(crate) fn wall_clock() -> SystemTime {
    #[cfg(test)]
    let ahead = Duration::from_secs(tests::CLOCK_AHEAD.load(std::sync::atomic::Ordering::Relaxed));
    #[cfg(not(test))]
    let ahead = Duration::ZERO;
    SystemTime::now() + ahead
}

/// One group's view of the shared session cache: every key is prefixed
/// with the group's client-authentication binding (D-125), so a session
/// stored under one set of rules is not found under another.
struct BoundCache {
    inner: Arc<dyn StoresServerSessions>,
    bind: [u8; 32],
}

impl fmt::Debug for BoundCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundCache").finish_non_exhaustive()
    }
}

impl BoundCache {
    fn key(&self, key: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(32 + key.len());
        k.extend_from_slice(&self.bind);
        k.extend_from_slice(key);
        k
    }
}

impl StoresServerSessions for BoundCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(self.key(&key), value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(&self.key(key))
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.take(&self.key(key))
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

/// State that belongs to the server's lifetime, carried across reloads (FR-32).
struct Shared {
    capacity: Arc<Capacity>,
    tickets: Option<Arc<TicketKeyRing>>,
    cache: Arc<dyn StoresServerSessions>,
    obs: Arc<Observation>,
}

struct Inner {
    snapshot: Arc<Snapshot<ServerState>>,
    provider_name: &'static str,
    shared: Shared,
    /// The settings without certificates, for `reload_from_*`; the lock also
    /// serialises publishes.
    template: Mutex<ServerBuilder>,
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
            .field("version", &self.inner.snapshot.version())
            .field(
                "in_progress",
                &self
                    .inner
                    .shared
                    .capacity
                    .in_progress
                    .load(Ordering::Relaxed),
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
            .shared
            .capacity
            .acquire()
            .ok_or_else(|| self.inner.refuse())?;
        Ok(ServerSession::new(self.inner.snapshot.load(), slot))
    }

    /// The server's counters, read without locking.
    #[must_use]
    pub fn stats(&self) -> ServerStats {
        use std::sync::atomic::Ordering::Relaxed;
        let obs = &self.inner.shared.obs;
        let h = &obs.handshakes;
        let (issued, rejected) = self.inner.shared.tickets.as_ref().map_or((0, 0), |t| {
            (t.issued.load(Relaxed), t.rejected.load(Relaxed))
        });
        ServerStats {
            handshakes_full: h.full.load(Relaxed),
            handshakes_resumed: h.resumed.load(Relaxed),
            handshakes_failed: h.failed.load(Relaxed),
            in_progress: self.handshakes_in_progress(),
            capacity_refusals: obs.refusals.capacity.load(Relaxed),
            hello_refusals: obs.refusals.hello.load(Relaxed),
            tickets_issued: issued,
            tickets_rejected: rejected,
            snapshot_version: self.version(),
            tls12_handshakes: h.tls12.load(Relaxed),
            post_quantum_handshakes: h.post_quantum.load(Relaxed),
            sni_disagreements: self.sni_disagreements(),
        }
    }

    /// The ticket key ring, for hand-off across restarts (`Ratchet` mode) or
    /// an urgent rotation; `None` when tickets are off.
    #[must_use]
    pub fn ticket_keys(&self) -> Option<TicketKeyRingHandle> {
        self.inner
            .shared
            .tickets
            .as_ref()
            .map(|r| TicketKeyRingHandle::new(Arc::clone(r)))
    }

    /// A per-worker handle: one atomic load per `accept`, a lock only after a reload.
    #[must_use]
    pub fn reader(&self) -> ServerReader {
        ServerReader {
            inner: Arc::clone(&self.inner),
            reader: Reader::new(Arc::clone(&self.inner.snapshot)),
        }
    }

    /// A handle that publishes new configurations.
    #[must_use]
    pub fn reload_handle(&self) -> ReloadHandle {
        ReloadHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// For a server with one certificate: replaces it, keeping every other
    /// setting, the ticket keys, and the session cache. Handshakes already
    /// running finish with the old certificate.
    ///
    /// # Errors
    ///
    /// `ReloadRefused` with the load error as source; the old certificate stays.
    pub fn reload_from_pem(&self, chain_pem: &[u8], key_pem: &[u8]) -> Result<(), TlsError> {
        self.reload_single(|b| b.certificate(chain_pem, KeySource::Pem(key_pem)))
    }

    /// As [`reload_from_pem`](Self::reload_from_pem), reading the files.
    ///
    /// # Errors
    ///
    /// As `reload_from_pem`, plus file errors as the source.
    pub fn reload_from_files(
        &self,
        chain: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<(), TlsError> {
        self.reload_single(|b| {
            let limits = b.load_limits;
            let chain = pem::read_file(chain.as_ref(), limits.max_chain_file_bytes, false, false)?;
            b.certificate(&chain, KeySource::File(key.as_ref()))
        })
    }

    fn reload_single(
        &self,
        add: impl FnOnce(ServerBuilder) -> Result<ServerBuilder, TlsError>,
    ) -> Result<(), TlsError> {
        let template = self
            .inner
            .template
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let r = (|| {
            if !template.hosts.is_empty() || self.inner.snapshot.load().entries.len() != 1 {
                return Err(TlsError::PolicyInvalid {
                    reason: "this server has several certificates or host policies; use ReloadHandle::publish",
                });
            }
            add(template.clone())?.state(&self.inner.shared)
        })();
        match r {
            Ok(state) => {
                let entries = state.entries.len();
                let version = self.inner.snapshot.publish(state);
                self.inner
                    .shared
                    .obs
                    .emit(&TlsEvent::ReloadApplied { version, entries });
                Ok(())
            }
            Err(e) => Err(self.inner.reload_refused(e)),
        }
    }

    /// Every loaded certificate with days remaining and a state. Never fails;
    /// `now` is a parameter so the caller (the health check) controls time.
    #[must_use]
    pub fn expiry_report(&self, now: SystemTime) -> ExpiryReport {
        let report = expiry::report(&self.inner.snapshot.load().entries, now);
        for e in report
            .entries
            .iter()
            .filter(|e| e.state >= expiry::ExpiryState::Warn)
        {
            self.inner.shared.obs.emit(&TlsEvent::CertificateExpiring {
                names: &e.names,
                not_after: e.not_after,
                state: e.state,
            });
        }
        report
    }

    /// The crypto provider: `"aws-lc-rs"`, `"aws-lc-rs (FIPS)"`, or `"ring"`.
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.inner.provider_name
    }

    /// Whether every configuration runs in FIPS mode (rustls `ServerConfig::fips`).
    #[must_use]
    pub fn is_fips(&self) -> bool {
        self.inner.snapshot.load().configs.iter().all(|c| c.fips())
    }

    /// The built rustls configurations, one per host group. Outside semver
    /// (feature `rustls-escape-hatch`): for debugging and rustls-only wiring.
    #[cfg(feature = "rustls-escape-hatch")]
    #[must_use]
    pub fn as_rustls_configs(&self) -> Vec<Arc<rustls::ServerConfig>> {
        self.inner.snapshot.load().configs.clone()
    }

    /// Handshakes in progress now.
    #[must_use]
    pub fn handshakes_in_progress(&self) -> u32 {
        self.inner
            .shared
            .capacity
            .in_progress
            .load(Ordering::Relaxed)
    }

    /// The current configuration version (1 at build, +1 per reload).
    #[must_use]
    pub fn version(&self) -> u64 {
        self.inner.snapshot.version()
    }

    /// Times rustls's view of the SNI fell outside the session's host group (D-064).
    #[must_use]
    pub fn sni_disagreements(&self) -> u64 {
        self.inner
            .snapshot
            .load()
            .table
            .group_mismatches
            .load(Ordering::Relaxed)
    }
}

/// A per-worker accept handle (`Send`, not `Sync`).
pub struct ServerReader {
    inner: Arc<Inner>,
    reader: Reader<ServerState>,
}

impl Inner {
    /// A capacity refusal: counted, evented at most once per second.
    fn refuse(&self) -> TlsError {
        self.shared.obs.capacity(
            self.shared.capacity.in_progress.load(Ordering::Relaxed),
            self.shared.capacity.max,
        );
        TlsError::HandshakeCapacity
    }

    fn reload_refused(&self, cause: TlsError) -> TlsError {
        self.shared.obs.emit(&TlsEvent::ReloadRefused {
            version: self.snapshot.version(),
            code: cause.code(),
        });
        TlsError::ReloadRefused {
            source: Box::new(cause),
        }
    }
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner")
            .field("version", &self.snapshot.version())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ServerReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerReader")
            .field("server", &self.inner)
            .finish()
    }
}

impl ServerReader {
    /// As [`TlsServer::accept`], reading the snapshot without a lock in the
    /// steady state.
    ///
    /// # Errors
    ///
    /// `HandshakeCapacity` at the limit.
    pub fn accept(&mut self) -> Result<ServerSession, TlsError> {
        let slot = self
            .inner
            .shared
            .capacity
            .acquire()
            .ok_or_else(|| self.inner.refuse())?;
        Ok(ServerSession::new(
            crate::sync::Shared::clone(self.reader.get()),
            slot,
        ))
    }
}

/// Publishes new configurations for a running server (FR-30 to FR-32).
#[derive(Clone)]
pub struct ReloadHandle {
    inner: Arc<Inner>,
}

impl fmt::Debug for ReloadHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadHandle")
            .field("version", &self.inner.snapshot.version())
            .finish()
    }
}

/// What a publish did.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// The new configuration version.
    pub version: u64,
    /// Certificates in it.
    pub entries: usize,
    /// Certificates in `Warn` or worse.
    pub expiring: usize,
}

impl ReloadHandle {
    /// Builds and validates `next` completely, carries the ticket keys and
    /// the session cache over, and swaps. The ticket mode in `next` is
    /// ignored: it belongs to the server's lifetime. On failure the old
    /// configuration stays in force.
    ///
    /// # Errors
    ///
    /// `ReloadRefused` with the cause as source.
    pub fn publish(&self, next: ServerBuilder) -> Result<ReloadOutcome, TlsError> {
        let mut template = self
            .inner
            .template
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let settings = next.settings();
        let state = next
            .state(&self.inner.shared)
            .map_err(|e| self.inner.reload_refused(e))?;
        let entries = state.entries.len();
        let expiring = expiry::report(&state.entries, SystemTime::now())
            .entries
            .iter()
            .filter(|e| e.state >= expiry::ExpiryState::Warn)
            .count();
        let version = self.inner.snapshot.publish(state);
        self.inner
            .shared
            .obs
            .emit(&TlsEvent::ReloadApplied { version, entries });
        *template = settings;
        Ok(ReloadOutcome {
            version,
            entries,
            expiring,
        })
    }

    /// The current configuration version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.inner.snapshot.version()
    }
}

/// A certificate waiting for `build`.
#[derive(Clone)]
struct Pending {
    entry: CertificateEntry,
    is_default: bool,
}

/// Builds a [`TlsServer`]. Methods that parse return `Result` at once, so an
/// error points at the call that caused it. Set `load_limits`,
/// `allow_group_readable_key`, and `validity_skew` before adding certificates.
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
#[derive(Clone)]
pub struct ServerBuilder {
    pending: Vec<Pending>,
    unknown: Option<UnknownName>,
    alpn: Vec<Alpn>,
    alpn_policy: AlpnPolicy,
    policy: Policy,
    limits: HandshakeLimits,
    limits_set: bool,
    load_limits: LoadLimits,
    hello_limits: HelloLimits,
    client_auth: ClientAuth,
    hosts: Vec<(Vec<Box<str>>, HostPolicy)>,
    tickets: Option<(TicketMode, u8)>,
    session_cache: usize,
    ocsp: Vec<(Box<str>, Vec<u8>)>,
    hook: Option<Arc<dyn HelloHook>>,
    fingerprints: FingerprintKinds,
    allow_group_readable: bool,
    skew: Duration,
    observer: Option<Arc<dyn TlsObserver>>,
    sampling: u32,
    #[cfg(feature = "dangerous-keylog")]
    key_log: Option<Arc<dyn KeyLogSink>>,
}

/// Receives NSS key log lines (for Wireshark while debugging). Feature
/// `dangerous-keylog`; never enable it in production, and it is refused
/// together with FIPS (D-040).
#[cfg(feature = "dangerous-keylog")]
pub trait KeyLogSink: Send + Sync + 'static {
    /// One line: label, client random, secret.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
}

#[cfg(feature = "dangerous-keylog")]
pub(crate) struct KeyLogAdapter(pub(crate) Arc<dyn KeyLogSink>);

#[cfg(feature = "dangerous-keylog")]
impl fmt::Debug for KeyLogAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyLogAdapter")
    }
}

#[cfg(feature = "dangerous-keylog")]
impl rustls::KeyLog for KeyLogAdapter {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0.log(label, client_random, secret);
    }
}

impl fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("certificates", &self.pending.len())
            .field("hosts", &self.hosts.len())
            .finish_non_exhaustive()
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        ServerBuilder::new()
    }
}

/// The largest OCSP staple accepted.
const MAX_STAPLE: usize = 16 << 10;

impl ServerBuilder {
    /// An empty builder with the `compatible` policy and default budgets.
    pub fn new() -> Self {
        ServerBuilder {
            pending: Vec::new(),
            unknown: None,
            alpn: Vec::new(),
            alpn_policy: AlpnPolicy::Optional,
            policy: Policy::compatible(),
            limits: HandshakeLimits::server(),
            limits_set: false,
            load_limits: LoadLimits::new(),
            hello_limits: HelloLimits::new(),
            client_auth: ClientAuth::none(),
            hosts: Vec::new(),
            tickets: None,
            session_cache: 1024,
            ocsp: Vec::new(),
            hook: None,
            fingerprints: FingerprintKinds::JA4,
            allow_group_readable: false,
            skew: Duration::from_secs(300),
            observer: None,
            sampling: 0,
            #[cfg(feature = "dangerous-keylog")]
            key_log: None,
        }
    }

    /// Sends NSS key log lines to `sink` (feature `dangerous-keylog`): anyone
    /// with them can decrypt the traffic. For debugging only.
    #[cfg(feature = "dangerous-keylog")]
    pub fn dangerous_key_log(mut self, sink: Arc<dyn KeyLogSink>) -> Self {
        self.key_log = Some(sink);
        self
    }

    /// The observer that receives this server's events. Belongs to the
    /// server's lifetime: ignored by `ReloadHandle::publish`.
    pub fn observer(mut self, observer: Arc<dyn TlsObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Emit `HelloCaptured` for one ClientHello in `one_in` (0, the default, never).
    pub fn hello_sampling(mut self, one_in: u32) -> Self {
        self.sampling = one_in;
        self
    }

    /// These settings without certificates (the reload template).
    fn settings(&self) -> ServerBuilder {
        ServerBuilder {
            pending: Vec::new(),
            ocsp: Vec::new(),
            ..self.clone()
        }
    }

    fn options(&self) -> LoadOptions {
        LoadOptions {
            limits: self.load_limits,
            skew: self.skew,
            allow_group_readable: self.allow_group_readable,
            ..LoadOptions::new(Purpose::Server)
        }
    }

    /// The default certificate: served for any name it covers (its SANs), and
    /// for unknown names when `UnknownName::UseDefault`. The first call
    /// registers the default; later calls add entries named by their SANs.
    ///
    /// # Errors
    ///
    /// `TLS-0010` to `TLS-0020` from the load-time checks.
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
    /// `TLS-0010` to `TLS-0020`; `NameNotCovered` for a name outside its SANs.
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

    /// Whether ALPN is required (default optional).
    pub fn alpn_policy(mut self, policy: AlpnPolicy) -> Self {
        self.alpn_policy = policy;
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
        self.limits_set = true;
        self
    }

    /// Budgets for certificate and key intake. Set before adding certificates.
    pub fn load_limits(mut self, limits: LoadLimits) -> Self {
        self.load_limits = limits;
        self
    }

    /// Budgets for the ClientHello parser.
    pub fn hello_limits(mut self, limits: HelloLimits) -> Self {
        self.hello_limits = limits;
        self
    }

    /// Client certificates (default none).
    pub fn client_auth(mut self, auth: ClientAuth) -> Self {
        self.client_auth = auth;
        self
    }

    /// Overrides for named hosts. Each name must be covered by a certificate
    /// already added; the hosts' sessions use their own rustls configuration.
    ///
    /// # Errors
    ///
    /// `InvalidName`, `DuplicateName` (a name in two host policies).
    pub fn host(mut self, names: &[&str], policy: HostPolicy) -> Result<Self, TlsError> {
        if names.is_empty() {
            return Err(TlsError::PolicyInvalid {
                reason: "a host policy needs at least one name",
            });
        }
        let mut normal = Vec::with_capacity(names.len());
        for name in names {
            let n = sni::normalize_pattern(name).ok_or_else(|| TlsError::InvalidName {
                name: crate::error::escape(name.as_bytes()),
            })?;
            let n: Box<str> = n.as_str().into();
            if self.hosts.iter().any(|(ns, _)| ns.contains(&n)) || normal.contains(&n) {
                return Err(TlsError::DuplicateName { name: n });
            }
            normal.push(n);
        }
        self.hosts.push((normal, policy));
        Ok(self)
    }

    /// Stateless tickets: the key ring mode and tickets per full handshake
    /// (0 to 8; 0 stops issuing while still accepting valid tickets). Default:
    /// `Ephemeral` with 6-hour epochs and 2 tickets; `Policy::internal()`: off.
    pub fn tickets(mut self, mode: TicketMode, per_handshake: u8) -> Self {
        self.tickets = Some((mode, per_handshake));
        self
    }

    /// Entries in the stateful session cache (TLS 1.2 session ids and TLS 1.3
    /// without tickets); default 1,024, 0 disables it.
    pub fn session_cache(mut self, capacity: usize) -> Self {
        self.session_cache = capacity;
        self
    }

    /// An OCSP staple for the certificate that serves `name`, sent to clients
    /// that ask for one. Checked now: at most 16 KiB, a successful response,
    /// status good, and `nextUpdate` (if present) in the future.
    ///
    /// # Errors
    ///
    /// `PemInvalid { what: "OCSP response" }` for a malformed, revoked, or
    /// stale staple; `InvalidName`.
    pub fn ocsp_staple(mut self, name: &str, staple_der: &[u8]) -> Result<Self, TlsError> {
        let n = sni::normalize_pattern(name).ok_or_else(|| TlsError::InvalidName {
            name: crate::error::escape(name.as_bytes()),
        })?;
        check_staple(staple_der, SystemTime::now())?;
        self.ocsp.push((n.as_str().into(), staple_der.to_vec()));
        Ok(self)
    }

    /// The hook that sees every ClientHello before the handshake continues.
    pub fn hello_hook(mut self, hook: Arc<dyn HelloHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Which fingerprints to compute for every ClientHello (default JA4).
    pub fn fingerprints(mut self, kinds: FingerprintKinds) -> Self {
        self.fingerprints = kinds;
        self
    }

    /// Allow key files readable by group or others (Unix). Off by default;
    /// set before adding certificates.
    pub fn allow_group_readable_key(mut self, allow: bool) -> Self {
        self.allow_group_readable = allow;
        self
    }

    /// Clock skew allowed on `not_before` (default 5 minutes, at most 1 day);
    /// set before adding certificates.
    pub fn validity_skew(mut self, skew: Duration) -> Self {
        self.skew = skew.min(Duration::from_secs(86_400));
        self
    }

    /// Checks everything and builds the server.
    ///
    /// # Errors
    ///
    /// `NoProvider`; `PolicyInvalid` (no certificate, duplicate ALPN names,
    /// an inconsistent policy, empty client anchors); `PostQuantumUnavailable`;
    /// `DuplicateName`; `NameNotCovered` (a host or staple name).
    pub fn build(self) -> Result<TlsServer, TlsError> {
        let provider_name = crate::provider::parts().ok_or(TlsError::NoProvider)?.name;
        let internal = self.policy.preset() == Preset::Internal;
        let default_tickets = || {
            if internal {
                (TicketMode::Off, 0)
            } else {
                (
                    TicketMode::Ephemeral {
                        period: Duration::from_secs(6 * 3600),
                    },
                    2,
                )
            }
        };
        let (mode, _) = self.tickets.clone().unwrap_or_else(default_tickets);
        let obs = Arc::new(Observation::new(self.observer.clone(), self.sampling));
        let tickets = TicketKeyRing::new(&mode)?.map(|mut r| {
            r.obs = Some(Arc::clone(&obs));
            Arc::new(r)
        });
        let cache: Arc<dyn StoresServerSessions> = if self.session_cache == 0 {
            Arc::new(NoServerSessionStorage {})
        } else {
            ServerSessionMemoryCache::new(self.session_cache)
        };
        let shared = Shared {
            capacity: Arc::new(Capacity {
                in_progress: AtomicU32::new(0),
                max: self.limits.max_in_progress,
            }),
            tickets,
            cache,
            obs,
        };
        let settings = self.settings();
        let state = self.state(&shared)?;
        Ok(TlsServer {
            inner: Arc::new(Inner {
                snapshot: Arc::new(Snapshot::new(state)),
                provider_name,
                shared,
                template: Mutex::new(settings),
            }),
        })
    }

    /// Builds one complete snapshot; nothing is shared with a running server
    /// except the ticket ring and the session cache.
    fn state(self, shared: &Shared) -> Result<ServerState, TlsError> {
        if self.pending.is_empty() {
            return Err(TlsError::PolicyInvalid {
                reason: "a server needs at least one certificate",
            });
        }
        let internal = self.policy.preset() == Preset::Internal;
        let per_handshake = match &self.tickets {
            Some((_, n)) => usize::from((*n).min(8)),
            None if internal => 0,
            None => 2,
        };

        let mut entries: Vec<CertificateEntry> =
            self.pending.iter().map(|p| p.entry.clone()).collect();
        for (name, staple) in &self.ocsp {
            let mut hit = false;
            for e in &mut entries {
                if e.names
                    .iter()
                    .any(|n| **n == **name || sni::san_covers(n, name))
                {
                    let mut ck: CertifiedKey = (*e.certified).clone();
                    ck.ocsp = Some(staple.clone());
                    e.certified = Arc::new(ck);
                    hit = true;
                }
            }
            if !hit {
                return Err(TlsError::NameNotCovered { name: name.clone() });
            }
        }

        let mut table = SniTable::new();
        for (p, e) in self.pending.iter().zip(&entries) {
            let index = table.add_key(Arc::clone(&e.certified), e.entry_key());
            for name in &e.names {
                if !table.add_name(name, index, 0) {
                    return Err(TlsError::DuplicateName { name: name.clone() });
                }
            }
            if p.is_default {
                let refuse = match self.unknown {
                    Some(u) => u == UnknownName::Refuse,
                    None => internal,
                };
                table.set_default(index, 0, !refuse);
            }
        }

        // Group 0 is the server's own settings; group i + 1 is host policy i.
        let mut settings: Vec<(Vec<Alpn>, AlpnPolicy, ClientAuth, Policy)> = vec![(
            self.alpn.clone(),
            self.alpn_policy,
            self.client_auth.clone(),
            self.policy.clone(),
        )];
        for (i, (names, hp)) in self.hosts.iter().enumerate() {
            for name in names {
                if !table.assign(name, i + 1) {
                    return Err(TlsError::NameNotCovered { name: name.clone() });
                }
            }
            settings.push((
                hp.alpn.clone().unwrap_or_else(|| self.alpn.clone()),
                hp.alpn_policy.unwrap_or(self.alpn_policy),
                hp.client_auth
                    .clone()
                    .unwrap_or_else(|| self.client_auth.clone()),
                hp.policy.clone().unwrap_or_else(|| self.policy.clone()),
            ));
        }
        let table = Arc::new(table);

        let mut configs = Vec::with_capacity(settings.len());
        let mut groups = Vec::with_capacity(settings.len());
        for (group, (alpn, alpn_policy, auth, policy)) in settings.into_iter().enumerate() {
            for (i, a) in alpn.iter().enumerate() {
                if alpn[i + 1..].contains(a) {
                    return Err(TlsError::PolicyInvalid {
                        reason: "the ALPN list repeats a name",
                    });
                }
            }
            if alpn_policy == AlpnPolicy::Required && alpn.is_empty() {
                return Err(TlsError::PolicyInvalid {
                    reason: "ALPN is required but no protocol is configured",
                });
            }
            #[cfg(feature = "net-io")]
            if policy.fragment().is_some_and(|f| f < 512) {
                return Err(TlsError::PolicyInvalid {
                    reason: "max_fragment_size below 512 does not fit net-io's write path",
                });
            }
            let provider = policy.provider()?;
            let verifier = auth.verifier(&provider)?;
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&policy.rustls_versions())
                .map_err(|_| TlsError::PolicyInvalid {
                    reason: "the provider cannot serve these versions",
                })?
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(Arc::new(GroupResolver {
                    table: Arc::clone(&table),
                    group,
                }));
            config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
            config.ignore_client_order = policy.server_order_wins();
            config.max_fragment_size = policy.fragment().map(|f| f + 5);
            config.require_ems = policy.ems();
            // Resumption is bound to the group's client-authentication rules
            // (D-125): rustls does not ask for a certificate again on resume.
            let bind = auth.binding();
            config.session_storage = Arc::new(BoundCache {
                inner: Arc::clone(&shared.cache),
                bind,
            });
            if let Some(ring) = &shared.tickets {
                config.ticketer = Arc::new(BoundTickets {
                    ring: Arc::clone(ring),
                    bind,
                });
            }
            config.send_tls13_tickets = if policy.preset() == Preset::Internal {
                0
            } else {
                per_handshake
            };
            #[cfg(feature = "dangerous-keylog")]
            if let Some(sink) = &self.key_log {
                config.key_log = Arc::new(KeyLogAdapter(Arc::clone(sink)));
            }
            if policy.requires_fips() && !config.fips() {
                return Err(TlsError::FipsUnavailable);
            }
            #[cfg(feature = "dangerous-keylog")]
            if self.key_log.is_some() && (config.fips() || policy.requires_fips()) {
                return Err(TlsError::PolicyInvalid {
                    reason: "key logging is refused together with FIPS",
                });
            }
            let client_auth = auth.is_enabled();
            let max_handshake_bytes = if client_auth && !self.limits_set {
                96 << 10
            } else {
                self.limits.max_handshake_bytes
            };
            configs.push(Arc::new(config));
            groups.push(Group {
                alpn_required: alpn_policy == AlpnPolicy::Required,
                auth_required: auth.is_required(),
                max_handshake_bytes,
            });
        }

        Ok(ServerState {
            configs,
            groups,
            table,
            hello_limits: self.hello_limits,
            limits: self.limits,
            entries,
            hook: self.hook,
            fingerprints: self.fingerprints,
            obs: Arc::clone(&shared.obs),
            capacity: Arc::clone(&shared.capacity),
        })
    }
}

fn check_staple(der: &[u8], now: SystemTime) -> Result<(), TlsError> {
    let bad = TlsError::PemInvalid {
        what: "OCSP response",
    };
    if der.len() > MAX_STAPLE || der.first() != Some(&0x30) {
        return Err(bad);
    }
    let facts = crate::der::ocsp_facts(der).ok_or(bad.clone())?;
    if !facts.good || facts.this_update > now + Duration::from_secs(300) {
        return Err(bad);
    }
    if facts.next_update.is_some_and(|n| n <= now) {
        return Err(bad);
    }
    Ok(())
}

/// A server with `Policy::compatible()`, this chain and key as the default
/// certificate, ALPN `http/1.1`, ephemeral tickets, and default budgets.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientBuilder, Event, HandshakeKind, TrustAnchors};

    pub(crate) static CLOCK_AHEAD: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    fn data(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// Runs a server and a client session against each other in memory.
    fn handshake(server: &TlsServer, client: &crate::TlsClient) -> Result<HandshakeKind, TlsError> {
        let mut s = server.accept()?;
        let mut c = client.connect("localhost")?;
        let (mut to_s, mut to_c) = (Vec::new(), Vec::new());
        let mut out = vec![0u8; 64 * 1024];
        for _ in 0..64 {
            let mut moved = false;
            loop {
                let p = c.step(&mut to_c, &mut out)?;
                let (n, w, need) = (p.consumed, p.written, p.event == Event::NeedInput);
                to_s.extend_from_slice(&out[..w]);
                to_c.drain(..n);
                moved |= n > 0 || w > 0;
                if need && n == 0 && w == 0 {
                    break;
                }
            }
            loop {
                let p = s.step(&mut to_s, &mut out)?;
                let (n, w, need) = (p.consumed, p.written, p.event == Event::NeedInput);
                to_c.extend_from_slice(&out[..w]);
                to_s.drain(..n);
                moved |= n > 0 || w > 0;
                if need && n == 0 && w == 0 {
                    break;
                }
            }
            if !moved {
                break;
            }
        }
        s.info().map(|i| i.kind).ok_or(TlsError::WrongState)
    }

    #[test]
    fn test_resumed_client_certificate_checked_for_expiry() {
        // rustls carries the client chain in the ticket and issues fresh
        // tickets on every resumption, so without this check an identity
        // would outlive its certificate (D-125).
        let ca = TrustAnchors::from_pem(&data("ca.pem")).unwrap();
        let server = ServerBuilder::new()
            .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
            .unwrap()
            .client_auth(ClientAuth::required(ca.clone()))
            .build()
            .unwrap();
        let client = ClientBuilder::new()
            .trust(ca)
            .client_certificate(&data("client.pem"), KeySource::Pem(&data("client.key")))
            .unwrap()
            .resumption(8)
            .build()
            .unwrap();
        assert_eq!(handshake(&server, &client), Ok(HandshakeKind::Full));
        assert_eq!(handshake(&server, &client), Ok(HandshakeKind::Resumed));
        use rustls::pki_types::pem::PemObject;
        let pem = data("client.pem");
        let leaf = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .next()
            .unwrap()
            .unwrap();
        let not_after = crate::der::parse_certificate(leaf.as_ref())
            .unwrap()
            .not_after;
        let ahead = not_after
            .duration_since(SystemTime::now())
            .unwrap()
            .as_secs()
            + 1;
        CLOCK_AHEAD.store(ahead, std::sync::atomic::Ordering::Relaxed);
        let late = handshake(&server, &client);
        CLOCK_AHEAD.store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            late,
            Err(TlsError::PeerCertificateInvalid(
                crate::error::CertificateProblem::Expired
            ))
        );
    }

    #[test]
    fn test_staple_checks() {
        let now = SystemTime::now();
        let good =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/site.ocsp")).unwrap();
        assert!(check_staple(&good, now).is_ok());
        let revoked = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/site.revoked.ocsp"
        ))
        .unwrap();
        assert!(check_staple(&revoked, now).is_err());
        assert!(check_staple(b"\x30\x00", now).is_err());
        assert!(check_staple(&vec![0x30; MAX_STAPLE + 1], now).is_err());
        let far = SystemTime::UNIX_EPOCH + Duration::from_secs(5_000_000_000);
        assert!(check_staple(&good, far).is_err(), "stale after nextUpdate");
    }
}

#[cfg(all(test, tls_net_loom))]
mod loom_tests {
    use super::*;

    /// Two sessions race for one slot: at most one holds it, and the count
    /// returns to zero when both are gone.
    #[test]
    fn loom_capacity_gate_never_over_admits() {
        loom::model(|| {
            let gate = Arc::new(Capacity {
                in_progress: AtomicU32::new(0),
                max: 1,
            });
            let other = {
                let gate = Arc::clone(&gate);
                loom::thread::spawn(move || {
                    let slot = gate.acquire();
                    let held = slot.is_some();
                    if let Some(slot) = slot {
                        gate.release(slot);
                    }
                    held
                })
            };
            let mine = gate.acquire();
            let held_here = mine.is_some();
            let held_there = other.join().unwrap();
            assert!(!(held_here && held_there) || gate.in_progress.load(Ordering::Relaxed) <= 1);
            assert!(held_here || held_there || gate.in_progress.load(Ordering::Relaxed) == 0);
            if let Some(slot) = mine {
                gate.release(slot);
            }
            if !held_there {
                assert_eq!(gate.in_progress.load(Ordering::Relaxed), 0);
            }
        });
    }
}
