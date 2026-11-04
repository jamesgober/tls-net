//! Events and statistics (FR-45, PLAN 6.14). Emitting allocates nothing;
//! borrowed fields are valid during the call only.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::error::RefuseReason;
use crate::expiry::ExpiryState;
use crate::fingerprint::Fingerprint;
use crate::hello::ClientHelloView;
use crate::identity::HandshakeKind;
use crate::policy::{CipherSuite, Group, Version};
use crate::session::SessionState;

/// Receives tls-net's events. One observer per server or client, set at
/// build; called synchronously on the thread that caused the event, so keep
/// it short (count, sample, enqueue).
///
/// ```
/// struct Count(std::sync::atomic::AtomicU64);
/// impl tls_net::TlsObserver for Count {
///     fn on_event(&self, event: &tls_net::TlsEvent<'_>) {
///         if let tls_net::TlsEvent::HandshakeFailed { .. } = event {
///             self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
///         }
///     }
/// }
/// ```
pub trait TlsObserver: Send + Sync + 'static {
    /// One event. The default does nothing.
    fn on_event(&self, event: &TlsEvent<'_>) {
        let _ = event;
    }
}

/// Why a ClientHello was refused before the handshake.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloRefusal {
    /// The hello hook refused it.
    Hook(RefuseReason),
    /// The parser rejected it.
    Malformed,
    /// A parser budget was exceeded.
    OverBudget,
    /// No certificate serves the name and unknown names are refused.
    UnknownName,
    /// ALPN is required and the hello had none.
    AlpnRequired,
}

/// Something tls-net did. Every string in an event is safe to log: SNI is
/// normalised (letters, digits, `-`, `.`) and ALPN is one of the configured
/// names (T-20).
#[non_exhaustive]
#[derive(Debug)]
pub enum TlsEvent<'a> {
    /// A handshake completed.
    HandshakeCompleted {
        /// The session's tag.
        tag: u64,
        /// The version.
        version: Version,
        /// The cipher suite.
        cipher_suite: CipherSuite,
        /// The key exchange group.
        group: Option<Group>,
        /// The ALPN protocol.
        alpn: Option<&'a [u8]>,
        /// The normalised SNI (server) or the name connected to (client).
        server_name: Option<&'a str>,
        /// Full, after a retry, or resumed.
        kind: HandshakeKind,
        /// From the first `step` to completion.
        duration: Duration,
        /// Whether the peer sent a certificate (server side: a client certificate).
        peer_certificate: bool,
        /// The ClientHello's fingerprint (server side).
        fingerprint: Option<&'a Fingerprint>,
    },
    /// A handshake failed.
    HandshakeFailed {
        /// The session's tag.
        tag: u64,
        /// The error code (`TLS-nnnn`).
        code: u16,
        /// The alert sent or received.
        alert: Option<u8>,
        /// Where the session was.
        stage: SessionState,
    },
    /// A sampled ClientHello (`ServerBuilder::hello_sampling`).
    HelloCaptured {
        /// The session's tag.
        tag: u64,
        /// The parsed hello.
        view: &'a ClientHelloView<'a>,
        /// Its fingerprint.
        fingerprint: &'a Fingerprint,
    },
    /// A ClientHello was refused before the handshake.
    HelloRefused {
        /// The session's tag.
        tag: u64,
        /// Why.
        reason: HelloRefusal,
    },
    /// A reload was applied.
    ReloadApplied {
        /// The new configuration version.
        version: u64,
        /// Certificates in it.
        entries: usize,
    },
    /// A reload was refused; the old configuration stays.
    ReloadRefused {
        /// The configuration version still in force.
        version: u64,
        /// The error code of the cause.
        code: u16,
    },
    /// A certificate is in `Warn` or worse (from `expiry_report`).
    CertificateExpiring {
        /// Its names.
        names: &'a [String],
        /// When it expires.
        not_after: SystemTime,
        /// Its state.
        state: ExpiryState,
    },
    /// The ticket key ring moved to a new epoch.
    TicketKeyRotated {
        /// The new epoch.
        epoch: u64,
        /// The ring was reseeded from the random source (a large clock jump).
        reseeded: bool,
    },
    /// A session was refused at the handshake capacity (at most once per second).
    HandshakeCapacityReached {
        /// Handshakes in progress.
        in_progress: u32,
        /// The limit.
        limit: u32,
    },
}

/// A server's counters, read without locking.
///
/// ```
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
/// let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
/// let server = tls_net::server_from_pem(&std::fs::read(format!("{dir}site.pem")).unwrap(), &std::fs::read(format!("{dir}site.key")).unwrap()).unwrap();
/// assert_eq!(server.stats().handshakes_full, 0);
/// # }
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Full handshakes completed.
    pub handshakes_full: u64,
    /// Resumed handshakes completed.
    pub handshakes_resumed: u64,
    /// Handshakes that failed.
    pub handshakes_failed: u64,
    /// Handshakes in progress now.
    pub in_progress: u32,
    /// Sessions refused at the capacity limit.
    pub capacity_refusals: u64,
    /// ClientHellos refused before the handshake.
    pub hello_refusals: u64,
    /// Tickets issued.
    pub tickets_issued: u64,
    /// Tickets that did not open (forged, old, or from another ring).
    pub tickets_rejected: u64,
    /// The configuration version.
    pub snapshot_version: u64,
    /// Completed handshakes over TLS 1.2.
    pub tls12_handshakes: u64,
    /// Completed handshakes with a post-quantum key exchange.
    pub post_quantum_handshakes: u64,
    /// Times rustls's SNI disagreed with the session's host group (D-064).
    pub sni_disagreements: u64,
}

/// Counters written by handshakes, on their own cache line.
#[repr(align(64))]
#[derive(Debug, Default)]
pub(crate) struct HandshakeCounters {
    pub(crate) full: AtomicU64,
    pub(crate) resumed: AtomicU64,
    pub(crate) failed: AtomicU64,
    pub(crate) tls12: AtomicU64,
    pub(crate) post_quantum: AtomicU64,
}

/// Counters written by refusals, on their own cache line.
#[repr(align(64))]
#[derive(Debug, Default)]
pub(crate) struct RefusalCounters {
    pub(crate) capacity: AtomicU64,
    pub(crate) hello: AtomicU64,
    /// When the last capacity event was emitted, in milliseconds since `start`.
    pub(crate) capacity_event_ms: AtomicU64,
    pub(crate) hello_seen: AtomicU64,
}

/// A server's lifetime observation state.
pub(crate) struct Observation {
    pub(crate) observer: Option<std::sync::Arc<dyn TlsObserver>>,
    pub(crate) handshakes: HandshakeCounters,
    pub(crate) refusals: RefusalCounters,
    pub(crate) start: Instant,
    /// Emit `HelloCaptured` for one hello in this many (0 = never).
    pub(crate) sampling: u32,
}

impl fmt::Debug for Observation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observation")
            .field("observer", &self.observer.is_some())
            .finish_non_exhaustive()
    }
}

impl Observation {
    pub(crate) fn new(observer: Option<std::sync::Arc<dyn TlsObserver>>, sampling: u32) -> Self {
        Observation {
            observer,
            handshakes: HandshakeCounters::default(),
            refusals: RefusalCounters::default(),
            start: Instant::now(),
            sampling,
        }
    }

    pub(crate) fn emit(&self, event: &TlsEvent<'_>) {
        if let Some(o) = &self.observer {
            o.on_event(event);
        }
    }

    /// Whether this hello is sampled.
    pub(crate) fn sample(&self) -> bool {
        if self.sampling == 0 || self.observer.is_none() {
            return false;
        }
        let n = self.refusals.hello_seen.fetch_add(1, Ordering::Relaxed);
        n % u64::from(self.sampling) == 0
    }

    /// A capacity refusal: counted always, evented at most once per second.
    pub(crate) fn capacity(&self, in_progress: u32, limit: u32) {
        self.refusals.capacity.fetch_add(1, Ordering::Relaxed);
        if self.observer.is_none() {
            return;
        }
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.refusals.capacity_event_ms.load(Ordering::Relaxed);
        if (now.saturating_sub(last) >= 1000 || last == 0)
            && self
                .refusals
                .capacity_event_ms
                .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.emit(&TlsEvent::HandshakeCapacityReached { in_progress, limit });
        }
    }
}
