//! Session tickets under a rotating key ring (FR-34 to FR-36, PLAN 6.8).
//!
//! Ticket format version 1:
//!
//! ```text
//!  0      1             9                          33                          n-16      n
//!  | 0x01 | epoch (u64) | nonce (24 bytes, random) | ciphertext of the session | tag (16) |
//! ```
//!
//! XChaCha20-Poly1305 (crypt-io) under the ring key for `epoch`, with the
//! first 9 bytes as associated data. A random 192-bit nonce needs no
//! coordination between processes or hosts. A ticket that fails to open in
//! any way gives `None`, which rustls turns into a full handshake.

use std::fmt;
use std::sync::Arc;

use crate::sync::{AtomicU64, Ordering, RwLock};
use std::time::{Duration, SystemTime};

use crypt_io::{Crypt, Zeroizing};
use rustls::server::ProducesTickets;

use crate::error::TlsError;
use crate::observe::{Observation, TlsEvent};

/// Ticket format version.
/// Ticket format 2 adds the issue time (D-151).
const VERSION: u8 = 2;
/// Version, epoch, and issue time in seconds: the associated data.
const HEADER: usize = 17;
/// How far in the future a ticket's issue time may be: another server of a
/// fleet that shares ticket keys may run a little ahead.
const ISSUE_SKEW: u64 = 300;
/// Header, nonce, and tag.
pub(crate) const OVERHEAD: usize = HEADER + 24 + 16;
/// Forward steps of a ratchet before the ring reseeds instead.
const MAX_RATCHET_STEPS: u64 = 1_000;
const RATCHET_INFO: &[u8] = b"tls-net ticket ratchet v1";
const DERIVE_INFO: &[u8] = b"tls-net ticket derive v1";

/// How a server's ticket keys are made (D-010).
///
/// ```
/// use std::time::Duration;
/// use tls_net::{TicketMode, TicketSeed};
/// let mode = TicketMode::Ratchet { seed: TicketSeed::Random, period: Duration::from_secs(6 * 3600) };
/// # let _ = mode;
/// ```
#[non_exhaustive]
#[derive(Clone)]
pub enum TicketMode {
    /// No stateless tickets; TLS 1.3 resumption uses the stateful cache.
    Off,
    /// Random keys per process, a new one every `period`.
    Ephemeral {
        /// Epoch length, 1 minute to 24 hours.
        period: Duration,
    },
    /// A forward-only HKDF chain: old keys cannot be recomputed from the
    /// current one. Survives a restart through sealed export and import.
    Ratchet {
        /// The first key.
        seed: TicketSeed,
        /// Epoch length, 1 minute to 24 hours.
        period: Duration,
    },
    /// Keys derived from a root shared by a cluster: anyone holding the root
    /// can derive every past key, so rotate the root.
    Derived {
        /// The shared root.
        root: TicketSeed,
        /// Epoch length, 1 minute to 24 hours.
        period: Duration,
    },
}

impl fmt::Debug for TicketMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TicketMode::Off => f.write_str("TicketMode::Off"),
            TicketMode::Ephemeral { period } => write!(f, "TicketMode::Ephemeral({period:?})"),
            TicketMode::Ratchet { period, .. } => write!(f, "TicketMode::Ratchet({period:?})"),
            TicketMode::Derived { period, .. } => write!(f, "TicketMode::Derived({period:?})"),
        }
    }
}

/// Where the first ticket key (ratchet) or the root (derived) comes from.
#[non_exhaustive]
#[derive(Clone)]
pub enum TicketSeed {
    /// 32 bytes from the operating system's random source.
    Random,
    /// 32 bytes given by the caller; wiped when the server drops it.
    Bytes(Arc<Zeroizing<[u8; 32]>>),
    /// A key held in key-vault (at least 32 bytes; the first 32 are used).
    #[cfg(feature = "key-vault")]
    Vault {
        /// The vault.
        vault: Arc<key_vault::KeyVault>,
        /// The key.
        handle: key_vault::KeyHandle,
    },
}

impl TicketSeed {
    /// A seed from 32 bytes; the copy tls-net keeps is wiped on drop.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> TicketSeed {
        TicketSeed::Bytes(Arc::new(Zeroizing::new(bytes)))
    }

    fn key(&self) -> Result<Zeroizing<[u8; 32]>, TlsError> {
        match self {
            TicketSeed::Random => random_key(),
            TicketSeed::Bytes(b) => Ok(Zeroizing::new(***b)),
            #[cfg(feature = "key-vault")]
            TicketSeed::Vault { vault, handle } => {
                let mut out = Zeroizing::new([0u8; 32]);
                let ok = vault
                    .with_key(*handle, |bytes| {
                        if bytes.len() < 32 {
                            return false;
                        }
                        out.copy_from_slice(&bytes[..32]);
                        true
                    })
                    .map_err(|_| TlsError::Vault {
                        kind: "ticket seed could not be read",
                    })?;
                if !ok {
                    return Err(TlsError::Vault {
                        kind: "ticket seed is shorter than 32 bytes",
                    });
                }
                Ok(out)
            }
        }
    }
}

fn random_key() -> Result<Zeroizing<[u8; 32]>, TlsError> {
    crypt_io::generate_key().map_err(|_| TlsError::Other)
}

/// Ring mode with what it needs to make keys.
enum Kind {
    Ephemeral,
    Ratchet,
    Derived(Zeroizing<[u8; 32]>),
}

impl Kind {
    fn name(&self) -> &'static str {
        match self {
            Kind::Ephemeral => "ephemeral",
            Kind::Ratchet => "ratchet",
            Kind::Derived(_) => "derived",
        }
    }
}

struct RingState {
    epoch: u64,
    current: Zeroizing<[u8; 32]>,
    previous: Option<Zeroizing<[u8; 32]>>,
}

/// The clock the ring reads: seconds since the Unix epoch.
pub(crate) type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// The ticket key ring. At most two keys are accepted at any time: the
/// current epoch's and the previous one's.
pub(crate) struct TicketKeyRing {
    kind: Kind,
    period: u64,
    clock: Clock,
    state: RwLock<RingState>,
    pub(crate) issued: AtomicU64,
    pub(crate) rejected: AtomicU64,
    pub(crate) reseeds: AtomicU64,
    pub(crate) obs: Option<Arc<Observation>>,
}

impl fmt::Debug for TicketKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketKeyRing")
            .field("mode", &self.kind.name())
            .field("period", &self.period)
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

impl TicketKeyRing {
    /// A ring for `mode`, or `None` for `TicketMode::Off`.
    pub(crate) fn new(mode: &TicketMode) -> Result<Option<TicketKeyRing>, TlsError> {
        TicketKeyRing::with_clock(mode, system_clock())
    }

    pub(crate) fn with_clock(
        mode: &TicketMode,
        clock: Clock,
    ) -> Result<Option<TicketKeyRing>, TlsError> {
        let (kind, period, first) = match mode {
            TicketMode::Off => return Ok(None),
            TicketMode::Ephemeral { period } => (Kind::Ephemeral, *period, random_key()?),
            TicketMode::Ratchet { seed, period } => (Kind::Ratchet, *period, seed.key()?),
            TicketMode::Derived { root, period } => {
                let root = root.key()?;
                (Kind::Derived(root), *period, Zeroizing::new([0u8; 32]))
            }
        };
        if !(Duration::from_secs(60)..=Duration::from_secs(86_400)).contains(&period) {
            return Err(TlsError::PolicyInvalid {
                reason: "the ticket period must be 1 minute to 24 hours",
            });
        }
        let period = period.as_secs();
        let epoch = clock() / period;
        let (current, previous) = match &kind {
            Kind::Derived(root) => (
                derive(root, epoch)?,
                epoch.checked_sub(1).map(|e| derive(root, e)).transpose()?,
            ),
            _ => (first, None),
        };
        Ok(Some(TicketKeyRing {
            kind,
            period,
            clock,
            state: RwLock::new(RingState {
                epoch,
                current,
                previous,
            }),
            issued: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            reseeds: AtomicU64::new(0),
            obs: None,
        }))
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .epoch
    }

    /// Advances the ring if the clock entered a later epoch. Lazy: there is
    /// no timer (NFR-9). A clock that moves back never moves the ring back.
    fn advance(&self) {
        let now = (self.clock)() / self.period;
        if now <= self.epoch() {
            return;
        }
        self.advance_to(now);
    }

    /// The state for use at `secs` (read from the ring's clock): one read
    /// lock when the ring is current, which is every call but the first of
    /// an epoch.
    fn current_at(&self, secs: u64) -> impl std::ops::Deref<Target = RingState> + '_ {
        let now = secs / self.period;
        {
            let st = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if now <= st.epoch {
                return st;
            }
        }
        self.advance_to(now);
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn advance_to(&self, now: u64) {
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now <= st.epoch {
            return;
        }
        let steps = now - st.epoch;
        let reseeded = matches!(self.kind, Kind::Ratchet) && steps > MAX_RATCHET_STEPS;
        let next = match &self.kind {
            Kind::Derived(root) => {
                let cur = derive(root, now);
                let prev = derive(root, now - 1);
                match (cur, prev) {
                    (Ok(c), Ok(p)) => Some((c, Some(p))),
                    _ => None,
                }
            }
            Kind::Ephemeral => match random_key() {
                Ok(fresh) => {
                    let prev = if steps == 1 {
                        Some(Zeroizing::new(*st.current))
                    } else {
                        None
                    };
                    Some((fresh, prev))
                }
                Err(_) => None,
            },
            Kind::Ratchet if steps > MAX_RATCHET_STEPS => {
                self.reseeds.fetch_add(1, Ordering::Relaxed);
                random_key().ok().map(|k| (k, None))
            }
            Kind::Ratchet => {
                let mut key = Zeroizing::new(*st.current);
                let mut prev = None;
                let mut ok = true;
                for e in st.epoch + 1..=now {
                    match ratchet(&key, e) {
                        Ok(k) => {
                            prev = Some(std::mem::replace(&mut key, k));
                        }
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                // Only the key of epoch now-1 stays; older ones are dropped (wiped).
                ok.then_some((key, prev))
            }
        };
        match next {
            Some((current, previous)) => {
                *st = RingState {
                    epoch: now,
                    current,
                    previous,
                };
                drop(st);
                if let Some(obs) = &self.obs {
                    obs.emit(&TlsEvent::TicketKeyRotated {
                        epoch: now,
                        reseeded,
                    });
                }
            }
            None => {
                // The keys could not be made: stop accepting old tickets rather
                // than keep keys past their epoch (fail closed).
                st.previous = None;
            }
        }
    }

    /// Seals `plain` under the current key. The associated data is the
    /// header and `bind`, the group's client-authentication binding (D-125):
    /// `bind` is not sent, so a ticket opens only where it was issued.
    fn seal(&self, plain: &[u8], bind: &[u8; 32]) -> Option<Vec<u8>> {
        let secs = (self.clock)();
        let st = self.current_at(secs);
        let mut aad = [0u8; HEADER + 32];
        aad[0] = VERSION;
        aad[1..9].copy_from_slice(&st.epoch.to_be_bytes());
        aad[9..HEADER].copy_from_slice(&secs.to_be_bytes());
        aad[HEADER..].copy_from_slice(bind);
        // One allocation: the capacity covers the header, so moving the
        // sealed bytes up to make room for it does not reallocate.
        let mut out = Vec::with_capacity(OVERHEAD + plain.len());
        Crypt::xchacha20_poly1305()
            .encrypt_with_aad_into(st.current.as_slice(), plain, &aad, &mut out)
            .ok()?;
        drop(st);
        out.splice(0..0, aad[..HEADER].iter().copied());
        self.issued.fetch_add(1, Ordering::Relaxed);
        Some(out)
    }

    fn open(&self, ticket: &[u8], bind: &[u8; 32]) -> Option<Vec<u8>> {
        let opened = self.try_open(ticket, bind);
        if opened.is_none() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
        opened
    }

    fn try_open(&self, ticket: &[u8], bind: &[u8; 32]) -> Option<Vec<u8>> {
        if ticket.len() < OVERHEAD || ticket[0] != VERSION {
            return None;
        }
        let epoch = u64::from_be_bytes(ticket[1..9].try_into().ok()?);
        let issued = u64::from_be_bytes(ticket[9..HEADER].try_into().ok()?);
        // A ticket opens for the lifetime it was issued with, one period,
        // not for as long as its epoch's key is held (D-151). The issue time
        // is authenticated, so it cannot be moved.
        let secs = (self.clock)();
        let st = self.current_at(secs);
        if issued > secs.saturating_add(ISSUE_SKEW) || secs.saturating_sub(issued) > self.period {
            return None;
        }
        let key = if epoch == st.epoch {
            &st.current
        } else if Some(epoch) == st.epoch.checked_sub(1) {
            st.previous.as_ref()?
        } else {
            return None;
        };
        let mut aad = [0u8; HEADER + 32];
        aad[..HEADER].copy_from_slice(&ticket[..HEADER]);
        aad[HEADER..].copy_from_slice(bind);
        Crypt::xchacha20_poly1305()
            .decrypt_with_aad(key.as_slice(), &ticket[HEADER..], &aad)
            .ok()
    }
}

/// Export format version for sealed ticket keys (2 adds the period, D-130).
const EXPORT_VERSION: u8 = 2;
const MODE_RATCHET: u8 = 1;
/// Version, mode, epoch, period in seconds: the associated data of an export.
const EXPORT_HEADER: usize = 18;

/// Ticket keys sealed for a hand-off to the process that takes over the
/// listening sockets. Wiped on drop.
pub struct SealedTicketKeys(Zeroizing<Vec<u8>>);

impl SealedTicketKeys {
    /// The sealed bytes, to pass with the sockets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SealedTicketKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedTicketKeys({} bytes)", self.0.len())
    }
}

/// A server's ticket key ring: hand-off across restarts and urgent rotation.
///
/// ```
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
/// use std::time::Duration;
/// use tls_net::{KeySource, TicketMode, TicketSeed, TlsServer};
/// let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
/// let (chain, key) = (std::fs::read(format!("{dir}site.pem")).unwrap(), std::fs::read(format!("{dir}site.key")).unwrap());
/// let mode = TicketMode::Ratchet { seed: TicketSeed::Random, period: Duration::from_secs(3600) };
/// let old = TlsServer::builder().certificate(&chain, KeySource::Pem(&key)).unwrap().tickets(mode.clone(), 2).build().unwrap();
/// let new = TlsServer::builder().certificate(&chain, KeySource::Pem(&key)).unwrap().tickets(mode, 2).build().unwrap();
/// let wrap = [9u8; 32];
/// let sealed = old.ticket_keys().unwrap().export_sealed(&wrap).unwrap();
/// new.ticket_keys().unwrap().import_sealed(&wrap, sealed.as_bytes()).unwrap();
/// # }
/// ```
#[derive(Clone)]
pub struct TicketKeyRingHandle {
    ring: Arc<TicketKeyRing>,
}

impl fmt::Debug for TicketKeyRingHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.ring, f)
    }
}

/// The `import_sealed` fuzz target: `data` imported as a sealed export,
/// then sealed as an export's plaintext under the right key and header and
/// imported. Returns whether each import succeeded. A fresh ring per input,
/// so a crash replays alone.
#[cfg(fuzzing)]
pub(crate) fn fuzz_import(data: &[u8]) -> (bool, bool) {
    let mode = TicketMode::Ratchet {
        seed: TicketSeed::from_bytes([5; 32]),
        period: Duration::from_secs(3600),
    };
    let Ok(Some(ring)) = TicketKeyRing::new(&mode) else {
        return (false, false);
    };
    let handle = TicketKeyRingHandle::new(Arc::new(ring));
    let wrap = [9u8; 32];
    let forged = handle.import_sealed(&wrap, data).is_ok();
    let mut header = [0u8; EXPORT_HEADER];
    header[0] = EXPORT_VERSION;
    header[1] = MODE_RATCHET;
    header[2..10].copy_from_slice(&handle.ring.epoch().to_be_bytes());
    header[10..].copy_from_slice(&handle.ring.period.to_be_bytes());
    let Ok(sealed) = Crypt::xchacha20_poly1305().encrypt_with_aad(&wrap, data, &header) else {
        return (forged, false);
    };
    let mut whole = header.to_vec();
    whole.extend_from_slice(&sealed);
    (forged, handle.import_sealed(&wrap, &whole).is_ok())
}

impl TicketKeyRingHandle {
    pub(crate) fn new(ring: Arc<TicketKeyRing>) -> Self {
        TicketKeyRingHandle { ring }
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.ring.epoch()
    }

    /// Seals the current and previous keys under `wrap_key` (a key both
    /// processes already hold). Only `Ratchet` rings export: an ephemeral
    /// ring has nothing to keep, and derived rings share their root already.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for other modes.
    pub fn export_sealed(&self, wrap_key: &[u8; 32]) -> Result<SealedTicketKeys, TlsError> {
        if !matches!(self.ring.kind, Kind::Ratchet) {
            return Err(TlsError::PolicyInvalid {
                reason: "only ratchet ticket rings export their keys",
            });
        }
        self.ring.advance();
        let st = self
            .ring
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut header = [0u8; EXPORT_HEADER];
        header[0] = EXPORT_VERSION;
        header[1] = MODE_RATCHET;
        header[2..10].copy_from_slice(&st.epoch.to_be_bytes());
        header[10..].copy_from_slice(&self.ring.period.to_be_bytes());
        let mut plain = Zeroizing::new(Vec::with_capacity(65));
        plain.push(u8::from(st.previous.is_some()));
        plain.extend_from_slice(st.current.as_slice());
        if let Some(p) = &st.previous {
            plain.extend_from_slice(p.as_slice());
        }
        let sealed = Crypt::xchacha20_poly1305()
            .encrypt_with_aad(wrap_key, &plain, &header)
            .map_err(|_| TlsError::Other)?;
        let mut out = Zeroizing::new(Vec::with_capacity(EXPORT_HEADER + sealed.len()));
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(SealedTicketKeys(out))
    }

    /// Adopts keys sealed by [`export_sealed`](Self::export_sealed) in the
    /// process that handed off the sockets.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for a mode or period mismatch, an export older than
    /// this ring's previous epoch or more than one epoch ahead of it, a wrong
    /// wrap key, or any tampering (T-24).
    pub fn import_sealed(&self, wrap_key: &[u8; 32], sealed: &[u8]) -> Result<(), TlsError> {
        let refused = TlsError::PolicyInvalid {
            reason: "the sealed ticket keys were refused",
        };
        if !matches!(self.ring.kind, Kind::Ratchet) {
            return Err(TlsError::PolicyInvalid {
                reason: "only ratchet ticket rings import keys",
            });
        }
        if sealed.len() < EXPORT_HEADER || sealed[0] != EXPORT_VERSION || sealed[1] != MODE_RATCHET
        {
            return Err(refused);
        }
        let field = |r: std::ops::Range<usize>| -> Result<u64, TlsError> {
            Ok(u64::from_be_bytes(
                sealed[r].try_into().map_err(|_| refused.clone())?,
            ))
        };
        let (epoch, period) = (field(2..10)?, field(10..EXPORT_HEADER)?);
        // Another period would give an epoch this ring's clock reaches at
        // another time; an epoch more than one ahead would stop rotation
        // until this clock caught up (D-130).
        if period != self.ring.period {
            return Err(refused);
        }
        self.ring.advance();
        let mine = self.ring.epoch();
        if epoch.saturating_add(1) < mine || epoch > mine.saturating_add(1) {
            return Err(refused);
        }
        let plain = Crypt::xchacha20_poly1305()
            .decrypt_with_aad(wrap_key, &sealed[EXPORT_HEADER..], &sealed[..EXPORT_HEADER])
            .map_err(|_| refused.clone())?;
        let plain = Zeroizing::new(plain);
        let key = |range: std::ops::Range<usize>| -> Option<Zeroizing<[u8; 32]>> {
            let bytes: [u8; 32] = plain.get(range)?.try_into().ok()?;
            Some(Zeroizing::new(bytes))
        };
        let (current, previous) = match plain.first() {
            Some(0) if plain.len() == 33 => (key(1..33), None),
            Some(1) if plain.len() == 65 => (key(1..33), key(33..65)),
            _ => return Err(refused),
        };
        let current = current.ok_or(refused)?;
        {
            let mut st = self
                .ring
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *st = RingState {
                epoch,
                current,
                previous,
            };
        }
        // Catch up if the export is from the previous epoch.
        self.ring.advance();
        Ok(())
    }

    /// Replaces the current key with a random one now and drops the previous
    /// one: every outstanding ticket then needs a full handshake (for a
    /// suspected compromise). Not for derived rings, whose keys come from
    /// the shared root.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` for derived rings.
    pub fn rotate_now(&self) -> Result<u64, TlsError> {
        if matches!(self.ring.kind, Kind::Derived(_)) {
            return Err(TlsError::PolicyInvalid {
                reason: "rotate the root of a derived ring instead",
            });
        }
        let fresh = random_key()?;
        let epoch = {
            let mut st = self
                .ring
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.current = fresh;
            st.previous = None;
            st.epoch
        };
        if let Some(obs) = &self.ring.obs {
            obs.emit(&TlsEvent::TicketKeyRotated {
                epoch,
                reseeded: true,
            });
        }
        Ok(epoch)
    }
}

/// One server group's view of the shared ring: tickets sealed with the
/// group's client-authentication binding (D-125). The ring, its epochs, and
/// its counters are shared; only the associated data differs.
pub(crate) struct BoundTickets {
    pub(crate) ring: Arc<TicketKeyRing>,
    pub(crate) bind: [u8; 32],
}

impl fmt::Debug for BoundTickets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundTickets")
            .field("ring", &self.ring)
            .finish_non_exhaustive()
    }
}

/// The rustls side: decrypt input is fully attacker-controlled; every
/// failure is `None` and nothing panics.
impl ProducesTickets for BoundTickets {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        u32::try_from(self.ring.period).unwrap_or(u32::MAX)
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.ring.seal(plain, &self.bind)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.ring.open(cipher, &self.bind)
    }
}

/// Unbound sealing, for the unit tests and (opening only) the fuzz target.
#[cfg(any(test, fuzzing))]
impl TicketKeyRing {
    #[cfg(test)]
    pub(crate) fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.seal(plain, &[0; 32])
    }

    pub(crate) fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.open(cipher, &[0; 32])
    }
}

fn ratchet(key: &[u8; 32], epoch: u64) -> Result<Zeroizing<[u8; 32]>, TlsError> {
    hkdf(key, RATCHET_INFO, epoch)
}

fn derive(root: &[u8; 32], epoch: u64) -> Result<Zeroizing<[u8; 32]>, TlsError> {
    hkdf(root, DERIVE_INFO, epoch)
}

fn hkdf(ikm: &[u8; 32], label: &[u8], epoch: u64) -> Result<Zeroizing<[u8; 32]>, TlsError> {
    let mut info = [0u8; 40];
    let n = label.len();
    info[..n].copy_from_slice(label);
    info[n..n + 8].copy_from_slice(&epoch.to_be_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    crypt_io::kdf::hkdf_sha256_into(ikm, None, &info[..n + 8], out.as_mut_slice())
        .map_err(|_| TlsError::Other)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64 as Time;

    use super::*;

    const HOUR: u64 = 3600;

    fn ring(mode: TicketMode, t: &Arc<Time>) -> TicketKeyRing {
        let t2 = Arc::clone(t);
        TicketKeyRing::with_clock(&mode, Arc::new(move || t2.load(Ordering::Relaxed)))
            .unwrap()
            .unwrap()
    }

    fn hours(n: u64) -> TicketMode {
        TicketMode::Ratchet {
            seed: TicketSeed::from_bytes([7; 32]),
            period: Duration::from_secs(n * HOUR),
        }
    }

    #[test]
    fn test_seal_open_round_trip_and_overhead() {
        let t = Arc::new(Time::new(1_000 * HOUR));
        let r = ring(hours(6), &t);
        let sealed = r.encrypt(b"session state").unwrap();
        assert_eq!(sealed.len(), b"session state".len() + OVERHEAD);
        assert_eq!(r.decrypt(&sealed).unwrap(), b"session state");
        assert_eq!(r.issued.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_previous_epoch_accepted_older_refused_t11() {
        let t = Arc::new(Time::new(1_000 * HOUR));
        let r = ring(hours(1), &t);
        let old = r.encrypt(b"x").unwrap();
        t.store(1_001 * HOUR, Ordering::Relaxed);
        assert_eq!(r.decrypt(&old).unwrap(), b"x", "epoch e-1 still opens");
        t.store(1_002 * HOUR, Ordering::Relaxed);
        assert!(r.decrypt(&old).is_none(), "epoch e-2 is refused");
        assert_eq!(r.rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_ratchet_old_key_not_recomputable_from_current() {
        // After two rotations the epoch-e ticket cannot be opened even by a
        // ring rebuilt from the current key: the chain only goes forward.
        let t = Arc::new(Time::new(1_000 * HOUR));
        let r = ring(hours(1), &t);
        let ticket = r.encrypt(b"x").unwrap();
        t.store(1_002 * HOUR, Ordering::Relaxed);
        r.advance();
        let current = *r.state.read().unwrap().current;
        let rebuilt = ring(
            TicketMode::Ratchet {
                seed: TicketSeed::from_bytes(current),
                period: Duration::from_secs(HOUR),
            },
            &t,
        );
        assert!(rebuilt.decrypt(&ticket).is_none());
        assert_ne!(current, [7; 32]);
    }

    #[test]
    fn test_clock_backwards_does_not_move_ring_back() {
        let t = Arc::new(Time::new(1_000 * HOUR));
        let r = ring(hours(1), &t);
        t.store(1_005 * HOUR, Ordering::Relaxed);
        r.advance();
        t.store(900 * HOUR, Ordering::Relaxed);
        r.advance();
        assert_eq!(r.epoch(), 1_005);
    }

    #[test]
    fn test_ticket_refused_after_its_lifetime_though_key_still_held() {
        // Sealed at the start of epoch 1,000; the key stays open until epoch
        // 1,002, but the ticket's lifetime is one period (D-151).
        let t = Arc::new(Time::new(1_000 * HOUR));
        let r = ring(hours(1), &t);
        let ticket = r.encrypt(b"x").unwrap();
        t.store(1_001 * HOUR, Ordering::Relaxed);
        assert!(r.decrypt(&ticket).is_some(), "exactly one period old");
        t.store(1_001 * HOUR + 1, Ordering::Relaxed);
        assert!(r.decrypt(&ticket).is_none(), "older than its lifetime");
        // Sealed late in epoch 1,001, it opens in epoch 1,002 within its lifetime.
        t.store(1_002 * HOUR - 60, Ordering::Relaxed);
        let late = r.encrypt(b"y").unwrap();
        t.store(1_002 * HOUR + 1_800, Ordering::Relaxed);
        assert!(r.decrypt(&late).is_some());
        // An issue time from the future beyond the skew is refused; it is
        // authenticated, so changing it fails the tag as well.
        let mut moved = late.clone();
        moved[16] ^= 1;
        assert!(r.decrypt(&moved).is_none());
    }

    #[test]
    fn test_ratchet_large_jump_reseeds() {
        let t = Arc::new(Time::new(10_000 * 60));
        let r = ring(
            TicketMode::Ratchet {
                seed: TicketSeed::Random,
                period: Duration::from_secs(60),
            },
            &t,
        );
        let ticket = r.encrypt(b"x").unwrap();
        t.store((10_000 + MAX_RATCHET_STEPS + 1) * 60, Ordering::Relaxed);
        assert!(r.decrypt(&ticket).is_none());
        assert_eq!(r.reseeds.load(Ordering::Relaxed), 1);
        assert_eq!(r.epoch(), 10_000 + MAX_RATCHET_STEPS + 1);
    }

    #[test]
    fn test_derived_two_hosts_share_tickets() {
        let t = Arc::new(Time::new(500 * HOUR));
        let mode = TicketMode::Derived {
            root: TicketSeed::from_bytes([9; 32]),
            period: Duration::from_secs(HOUR),
        };
        let (a, b) = (ring(mode.clone(), &t), ring(mode, &t));
        let ticket = a.encrypt(b"shared").unwrap();
        assert_eq!(b.decrypt(&ticket).unwrap(), b"shared");
    }

    #[test]
    fn test_ephemeral_rings_do_not_share() {
        let t = Arc::new(Time::new(500 * HOUR));
        let mode = TicketMode::Ephemeral {
            period: Duration::from_secs(HOUR),
        };
        let (a, b) = (ring(mode.clone(), &t), ring(mode, &t));
        assert!(b.decrypt(&a.encrypt(b"x").unwrap()).is_none());
    }

    #[test]
    fn test_tampered_tickets_all_fail_t12() {
        let t = Arc::new(Time::new(1_000 * HOUR));
        let r = ring(hours(1), &t);
        let good = r.encrypt(b"session").unwrap();
        for i in 0..good.len() {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[i] ^= 1 << bit;
                assert!(r.decrypt(&bad).is_none(), "byte {i} bit {bit}");
            }
        }
        for n in 0..good.len() {
            assert!(r.decrypt(&good[..n]).is_none(), "truncated to {n}");
        }
        assert!(r.decrypt(&[]).is_none());
        assert!(r.decrypt(&[0u8; 200]).is_none());
    }

    #[test]
    fn test_random_tickets_all_fail_t12() {
        // Arbitrary bytes of every length up to well past a real ticket,
        // from a fixed-seed generator (reproducible): none opens.
        let t = Arc::new(Time::new(1_000 * HOUR));
        let r = ring(hours(1), &t);
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..4_000 {
            let len = usize::try_from(next() % 400).unwrap_or(0);
            let bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
            assert!(r.decrypt(&bytes).is_none(), "random ticket {i} opened");
        }
        assert_eq!(r.rejected.load(Ordering::Relaxed), 4_000);
    }

    #[test]
    fn test_export_older_than_one_epoch_refused_t24() {
        let t = Arc::new(Time::new(1_000 * HOUR));
        let old = Arc::new(ring(hours(1), &t));
        let sealed = TicketKeyRingHandle::new(Arc::clone(&old))
            .export_sealed(&[1; 32])
            .unwrap();
        // The importing process, one epoch later: taken.
        t.store(1_001 * HOUR, Ordering::Relaxed);
        let next = TicketKeyRingHandle::new(Arc::new(ring(hours(1), &t)));
        assert!(next.import_sealed(&[1; 32], sealed.as_bytes()).is_ok());
        // Two epochs later: refused.
        t.store(1_002 * HOUR, Ordering::Relaxed);
        let late = TicketKeyRingHandle::new(Arc::new(ring(hours(1), &t)));
        assert!(late.import_sealed(&[1; 32], sealed.as_bytes()).is_err());
    }

    #[test]
    fn test_export_from_another_period_or_the_future_refused_t24() {
        // A period change across the hand-off, or an exporter whose clock
        // runs ahead, would set an epoch this ring's clock reaches only much
        // later, freezing rotation until then (D-130).
        let t = Arc::new(Time::new(1_000 * HOUR));
        let hourly = Arc::new(ring(hours(1), &t));
        let sealed = TicketKeyRingHandle::new(Arc::clone(&hourly))
            .export_sealed(&[1; 32])
            .unwrap();
        let six = TicketKeyRingHandle::new(Arc::new(ring(hours(6), &t)));
        assert!(six.import_sealed(&[1; 32], sealed.as_bytes()).is_err());
        // An exporter two epochs ahead of the importer: refused; one ahead
        // (clock skew at an epoch boundary): taken.
        t.store(1_002 * HOUR, Ordering::Relaxed);
        let ahead = TicketKeyRingHandle::new(Arc::new(ring(hours(1), &t)))
            .export_sealed(&[1; 32])
            .unwrap();
        t.store(1_000 * HOUR, Ordering::Relaxed);
        let behind = TicketKeyRingHandle::new(Arc::new(ring(hours(1), &t)));
        assert!(behind.import_sealed(&[1; 32], ahead.as_bytes()).is_err());
        t.store(1_001 * HOUR, Ordering::Relaxed);
        let near = TicketKeyRingHandle::new(Arc::new(ring(hours(1), &t)))
            .export_sealed(&[1; 32])
            .unwrap();
        t.store(1_000 * HOUR, Ordering::Relaxed);
        assert!(behind.import_sealed(&[1; 32], near.as_bytes()).is_ok());
    }

    #[test]
    fn test_period_out_of_range_refused() {
        for secs in [59, 86_401] {
            let mode = TicketMode::Ephemeral {
                period: Duration::from_secs(secs),
            };
            assert!(TicketKeyRing::new(&mode).is_err());
        }
        assert!(TicketKeyRing::new(&TicketMode::Off).unwrap().is_none());
    }
}

#[cfg(all(test, tls_net_loom))]
mod loom_tests {
    use std::sync::atomic::AtomicU64 as Time;

    use super::*;

    /// A ticket sealed in epoch e opens while another thread advances the
    /// ring to e+1; the ring never ends up in a mixed state.
    #[test]
    fn loom_rotation_and_open_race() {
        loom::model(|| {
            let t = Arc::new(Time::new(100 * 3600));
            let t2 = Arc::clone(&t);
            let mode = TicketMode::Ratchet {
                seed: TicketSeed::from_bytes([3; 32]),
                period: Duration::from_secs(3600),
            };
            let ring = Arc::new(
                TicketKeyRing::with_clock(
                    &mode,
                    Arc::new(move || t2.load(std::sync::atomic::Ordering::Relaxed)),
                )
                .unwrap()
                .unwrap(),
            );
            let ticket = ring.encrypt(b"s").unwrap();
            t.store(101 * 3600, std::sync::atomic::Ordering::Relaxed);
            let other = {
                let ring = Arc::clone(&ring);
                loom::thread::spawn(move || ring.encrypt(b"n").is_some())
            };
            assert_eq!(ring.decrypt(&ticket).as_deref(), Some(&b"s"[..]));
            assert!(other.join().unwrap());
            assert_eq!(ring.epoch(), 101);
        });
    }
}
