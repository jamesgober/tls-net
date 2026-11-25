//! QUIC (RFC 9001): the TLS handshake for a QUIC transport, and the keys it
//! protects packets with (feature `quic`, D-153).
//!
//! tls-net runs the handshake and hands out keys; the transport (quic-net or
//! another) frames CRYPTO data, protects packets, and sends them. Nothing here
//! does I/O. The handshake goes through the same gates as one over TCP: the
//! capacity slot, the hello parser and its budgets, the hello hook, the SNI
//! table and host groups, the handshake budgets, the checks at completion,
//! and the observer.
//!
//! ```
//! # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
//! use tls_net::{Alpn, TlsClient, TlsServer, TrustAnchors};
//! use tls_net::quic::KeyChange;
//!
//! let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
//! let read = |f: &str| std::fs::read(format!("{dir}{f}")).unwrap();
//! let h3 = Alpn::new(b"h3").unwrap();
//! let server = TlsServer::builder()
//!     .certificate(&read("site.pem"), tls_net::KeySource::Pem(&read("site.key")))?
//!     .alpn(&[h3.clone()])
//!     .build()?;
//! let client = TlsClient::builder()
//!     .trust(TrustAnchors::from_pem(&read("ca.pem"))?)
//!     .alpn(&[h3])
//!     .build()?;
//!
//! let mut c = client.connect_quic("localhost", b"client params".to_vec())?;
//! let mut s = server.accept_quic(b"server params".to_vec())?;
//! // Pass CRYPTO data each way until neither side has more to say. A real
//! // transport sends each piece at its encryption level.
//! let (mut c_done, mut s_done) = (false, false);
//! while !(c_done && s_done) {
//!     let mut out = Vec::new();
//!     c_done = c.write_handshake(&mut out).is_none() && out.is_empty();
//!     if !out.is_empty() { s.read_handshake(&out)?; }
//!     let mut out = Vec::new();
//!     s_done = s.write_handshake(&mut out).is_none() && out.is_empty();
//!     if !out.is_empty() { c.read_handshake(&out)?; }
//! }
//! assert!(!c.is_handshaking() && !s.is_handshaking());
//! assert_eq!(s.peer_transport_parameters(), Some(&b"client params"[..]));
//! assert_eq!(c.alpn(), Some(&b"h3"[..]));
//! # }
//! # Ok::<(), tls_net::TlsError>(())
//! ```

use std::cell::OnceCell;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use rustls::quic as rq;

use crate::error::{self, TlsError};
use crate::fingerprint::Fingerprint;
use crate::hello::{HelloParse, parse_quic_client_hello};
use crate::hook::{HelloContext, HelloVerdict};
use crate::identity::{HandshakeInfo, PeerIdentity};
use crate::observe::{HelloRefusal, Observation, TlsEvent};
use crate::policy::CipherSuite;
use crate::server::{CapacitySlot, Group as HostGroup, ServerState};
use crate::session::{self, SessionState};

/// The alerts tls-net sends on its own refusals.
const UNRECOGNIZED_NAME: u8 = 112;
const NO_APPLICATION_PROTOCOL: u8 = 120;

/// The longest connection ID QUIC version 1 allows (RFC 9000 section 17.2).
const MAX_CID_LEN: usize = 20;

/// Which end of the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The endpoint that opened the connection.
    Client,
    /// The endpoint that accepted it.
    Server,
}

impl From<Side> for rustls::Side {
    fn from(side: Side) -> Self {
        match side {
            Side::Client => rustls::Side::Client,
            Side::Server => rustls::Side::Server,
        }
    }
}

/// The server's part of a session: what the hello path and the checks at
/// completion need.
struct ServerPart {
    /// The snapshot the session was accepted under; `None` once the
    /// handshake has ended (D-146).
    state: Option<crate::sync::Shared<ServerState>>,
    slot: Option<CapacitySlot>,
    /// The transport parameters to send, until the connection exists.
    params: Option<Vec<u8>>,
    /// CRYPTO data received before the ClientHello was complete.
    hello: Vec<u8>,
    sni: Option<Box<str>>,
    fingerprint: Option<Fingerprint>,
    group: Option<HostGroup>,
    refusal: Option<HelloRefusal>,
}

/// The client's part.
struct ClientPart {
    server_name: Box<str>,
    max_chain_len: usize,
    max_cert_bytes: usize,
}

enum Role {
    Server(Box<ServerPart>),
    Client(ClientPart),
}

/// The TLS side of one QUIC connection. Created by
/// [`TlsServer::accept_quic`](crate::TlsServer::accept_quic) or
/// [`TlsClient::connect_quic`](crate::TlsClient::connect_quic).
///
/// Feed it the CRYPTO data that arrives with [`read_handshake`](Self::read_handshake),
/// take the CRYPTO data to send with [`write_handshake`](Self::write_handshake),
/// and install the keys each [`KeyChange`] hands out.
///
/// A server must not process 1-RTT packets until
/// [`is_handshaking`](Self::is_handshaking) is `false` (RFC 9001 section 5.7);
/// before then the client is not authenticated. A failed session stays
/// failed: close the connection with `CRYPTO_ERROR` (`0x100 +`
/// [`alert`](Self::alert)) when there is an alert, and without a TLS reason
/// when there is none.
///
/// `Send`, not `Sync`.
pub struct QuicSession {
    conn: Option<rq::Connection>,
    role: Role,
    state: SessionState,
    tag: u64,
    started: Instant,
    alert: Option<u8>,
    failure: Option<u16>,
    /// CRYPTO bytes read so far, against the handshake budget.
    received: usize,
    max_received: usize,
    obs: Arc<Observation>,
    reported: bool,
    /// Built on first use from the peer's certificate (D-104).
    peer: OnceCell<Option<Box<PeerIdentity>>>,
}

impl fmt::Debug for QuicSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicSession")
            .field("state", &self.state)
            .field("tag", &self.tag)
            .field("server_name", &self.server_name())
            .finish_non_exhaustive()
    }
}

impl Drop for QuicSession {
    fn drop(&mut self) {
        self.release();
    }
}

impl QuicSession {
    pub(crate) fn server(
        state: crate::sync::Shared<ServerState>,
        slot: CapacitySlot,
        params: Vec<u8>,
    ) -> Self {
        let max = state.limits.max_handshake_bytes as usize;
        let obs = Arc::clone(&state.obs);
        QuicSession {
            conn: None,
            role: Role::Server(Box::new(ServerPart {
                state: Some(state),
                slot: Some(slot),
                params: Some(params),
                hello: Vec::new(),
                sni: None,
                fingerprint: None,
                group: None,
                refusal: None,
            })),
            state: SessionState::Hello,
            tag: 0,
            started: Instant::now(),
            alert: None,
            failure: None,
            received: 0,
            max_received: max,
            obs,
            reported: false,
            peer: OnceCell::new(),
        }
    }

    pub(crate) fn client(
        config: Arc<rustls::ClientConfig>,
        name: rustls::pki_types::ServerName<'static>,
        shown: Box<str>,
        params: Vec<u8>,
        limits: &crate::limits::HandshakeLimits,
        obs: Arc<Observation>,
    ) -> Result<Self, TlsError> {
        let conn = rq::ClientConnection::new(config, rq::Version::V1, name, params)
            .map_err(|e| error::from_rustls(&e))?;
        Ok(QuicSession {
            conn: Some(conn.into()),
            role: Role::Client(ClientPart {
                server_name: shown,
                max_chain_len: usize::from(limits.max_peer_chain_len),
                max_cert_bytes: limits.max_peer_cert_bytes as usize,
            }),
            state: SessionState::Handshake,
            tag: 0,
            started: Instant::now(),
            alert: None,
            failure: None,
            received: 0,
            max_received: limits.max_handshake_bytes as usize,
            obs,
            reported: false,
            peer: OnceCell::new(),
        })
    }

    /// CRYPTO data received from the peer, in order, at the level it arrived
    /// at; rustls knows which level it expects. On a server, the bytes before
    /// the ClientHello is whole are kept and parsed by tls-net first, as over
    /// TCP.
    ///
    /// # Errors
    ///
    /// The handshake's error; the session is then failed and
    /// [`alert`](Self::alert) gives the alert to close with, when there is
    /// one. `SessionFailed` on a session that failed earlier.
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if self.state == SessionState::Failed {
            return Err(TlsError::SessionFailed);
        }
        let before = self.state;
        let r = self.read_inner(data);
        if let Err(e) = &r {
            self.fail(e);
        }
        self.observe(before);
        r
    }

    fn read_inner(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.received = self.received.saturating_add(data.len());
        if self.received > self.max_received {
            return Err(TlsError::HandshakeTooLarge);
        }
        if self.state == SessionState::Hello {
            if !self.hello(data)? {
                return Ok(());
            }
        } else {
            let conn = self.conn.as_mut().ok_or(TlsError::WrongState)?;
            conn.read_hs(data).map_err(|e| error::from_rustls(&e))?;
        }
        if self.state == SessionState::Handshake
            && self.conn.as_ref().is_some_and(|c| !c.is_handshaking())
        {
            self.complete()?;
            self.state = SessionState::Established;
            self.release();
        }
        Ok(())
    }

    /// The server's hello path: buffers CRYPTO data until the ClientHello
    /// is whole, then runs it through the same gates as `ServerSession`.
    /// `true` once the rustls connection exists and has read the bytes.
    fn hello(&mut self, data: &[u8]) -> Result<bool, TlsError> {
        let Role::Server(part) = &mut self.role else {
            return Err(TlsError::WrongState);
        };
        let Some(state) = part.state.clone() else {
            return Err(TlsError::Other);
        };
        part.hello.extend_from_slice(data);
        let buffered = std::mem::take(&mut part.hello);
        let view = match parse_quic_client_hello(&buffered, &state.hello_limits) {
            Ok(HelloParse::Incomplete { .. }) => {
                part.hello = buffered;
                return Ok(false);
            }
            Ok(HelloParse::Complete { view, .. }) => view,
            Err(e) => {
                // QUIC has no lenient path: a hello tls-net cannot read is
                // refused, without an alert (D-014).
                part.refusal = Some(if e.code() == 32 {
                    HelloRefusal::OverBudget
                } else {
                    HelloRefusal::Malformed
                });
                return Err(e);
            }
        };
        part.sni = view.normalized_server_name().map(|n| n.as_str().into());
        let kinds = state.fingerprints;
        let fingerprint = Fingerprint::compute(&view, kinds);
        if let Some(hook) = &state.hook {
            let ctx = HelloContext {
                view: &view,
                fingerprint: &fingerprint,
                server_name: part.sni.as_deref(),
                tag: self.tag,
            };
            if let HelloVerdict::Refuse(reason) = hook.on_client_hello(&ctx) {
                part.refusal = Some(HelloRefusal::Hook(reason));
                return Err(TlsError::Refused(reason));
            }
        }
        if state.obs.sample() {
            state.obs.emit(&TlsEvent::HelloCaptured {
                tag: self.tag,
                view: &view,
                fingerprint: &fingerprint,
            });
        }
        if kinds != crate::fingerprint::FingerprintKinds::NONE {
            part.fingerprint = Some(fingerprint);
        }
        let Some(slot) = state.table.lookup(part.sni.as_deref()) else {
            part.refusal = Some(HelloRefusal::UnknownName);
            self.alert = Some(UNRECOGNIZED_NAME);
            return Err(TlsError::UnknownServerName);
        };
        let group = state
            .groups
            .get(slot.group)
            .copied()
            .ok_or(TlsError::Other)?;
        part.group = Some(group);
        // QUIC always needs ALPN (RFC 9001 section 8.1).
        if !view.has_alpn() {
            part.refusal = Some(HelloRefusal::AlpnRequired);
            self.alert = Some(NO_APPLICATION_PROTOCOL);
            return Err(TlsError::NoApplicationProtocol);
        }
        self.max_received = group.max_handshake_bytes as usize;
        if self.received > self.max_received {
            return Err(TlsError::HandshakeTooLarge);
        }
        let config = state
            .configs
            .get(slot.group)
            .cloned()
            .ok_or(TlsError::Other)?;
        let params = part.params.take().unwrap_or_default();
        let conn = rq::ServerConnection::new(config, rq::Version::V1, params)
            .map_err(|e| error::from_rustls(&e))?;
        let mut conn = rq::Connection::from(conn);
        self.state = SessionState::Handshake;
        let r = conn.read_hs(&buffered);
        self.conn = Some(conn);
        r.map_err(|e| error::from_rustls(&e))?;
        Ok(true)
    }

    /// The checks once rustls has finished: TLS 1.3, then the server's or
    /// the client's checks as over TCP.
    fn complete(&mut self) -> Result<(), TlsError> {
        let Some(conn) = self.conn.as_ref() else {
            return Err(TlsError::Other);
        };
        // rustls never negotiates anything else for QUIC; checked again so a
        // change there cannot pass unseen.
        if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            self.alert = Some(70);
            return Err(TlsError::NoCommonVersion);
        }
        let r = match &self.role {
            Role::Server(part) => {
                let state = part.state.as_ref().ok_or(TlsError::Other)?;
                session::check_server_completion(conn, part.group, &state.limits)
            }
            Role::Client(part) => session::check_peer_chain(
                conn.peer_certificates(),
                part.max_chain_len,
                part.max_cert_bytes,
            ),
        };
        if let Err(e) = &r {
            self.alert = Some(completion_alert(e));
        }
        r
    }

    fn fail(&mut self, e: &TlsError) {
        self.state = SessionState::Failed;
        self.failure = Some(e.code());
        if self.alert.is_none() {
            self.alert = self.conn.as_ref().and_then(|c| c.alert()).map(u8::from);
        }
        self.release();
    }

    /// Counters and events after a read, as for `ServerSession`.
    fn observe(&mut self, before: SessionState) {
        if self.state == SessionState::Established && before != SessionState::Established {
            if let Some(conn) = &self.conn {
                if let Some(mut info) = session::handshake_info(conn, self.server_name()) {
                    if let Role::Server(part) = &self.role {
                        info.fingerprint = part.fingerprint.as_ref();
                    }
                    session::report_completion(&self.obs, &info, self.tag, self.started.elapsed());
                }
            }
        }
        if self.state == SessionState::Failed && !self.reported {
            self.reported = true;
            let refusal = match &self.role {
                Role::Server(part) => part.refusal,
                Role::Client(_) => None,
            };
            if let Some(reason) = refusal {
                self.obs
                    .refusals
                    .hello
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.obs.emit(&TlsEvent::HelloRefused {
                    tag: self.tag,
                    reason,
                });
            } else if matches!(before, SessionState::Hello | SessionState::Handshake) {
                session::report_failure(&self.obs, self.tag, self.failure, self.alert, before);
            }
        }
        // Once the handshake has ended nothing reads the snapshot (D-146).
        if !matches!(self.state, SessionState::Hello | SessionState::Handshake) {
            if let Role::Server(part) = &mut self.role {
                if part.slot.is_none() {
                    part.state = None;
                    part.hello = Vec::new();
                }
            }
        }
    }

    /// Gives back the handshake slot, if the session still holds one.
    fn release(&mut self) {
        if let Role::Server(part) = &mut self.role {
            if let (Some(state), Some(slot)) = (&part.state, part.slot.take()) {
                state.capacity.release(slot);
            }
        }
    }

    /// Appends the CRYPTO data to send at the current write level. When it
    /// returns a [`KeyChange`], the bytes appended before the call returned
    /// go at the old level and the next call's at the new one.
    ///
    /// Nothing is written, and no keys are handed out, after a failure.
    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        if self.state == SessionState::Failed {
            return None;
        }
        self.conn.as_mut()?.write_hs(out).map(KeyChange::from)
    }

    /// The peer's encoded transport parameters, once they have arrived.
    #[must_use]
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.conn.as_ref()?.quic_transport_parameters()
    }

    /// The TLS alert to close the connection with: send `CRYPTO_ERROR` with
    /// `0x100 +` this value. `None` before a failure, and for refusals that
    /// send nothing (a hello tls-net cannot read, the hello hook, a capacity
    /// or budget refusal), which are closed without a TLS reason.
    #[must_use]
    pub fn alert(&self) -> Option<u8> {
        if self.state != SessionState::Failed {
            return None;
        }
        self.alert
    }

    /// `true` until the handshake has finished and tls-net's checks passed.
    #[must_use]
    pub fn is_handshaking(&self) -> bool {
        self.state != SessionState::Established
    }

    /// Where the session is: `Hello` (server, before the ClientHello),
    /// `Handshake`, `Established`, or `Failed`.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// The agreed application protocol.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.conn.as_ref()?.alpn_protocol()
    }

    /// On a server, the normalised SNI from the ClientHello; on a client,
    /// the name it connected to.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        match &self.role {
            Role::Server(part) => part.sni.as_deref(),
            Role::Client(part) => Some(&part.server_name),
        }
    }

    /// The cipher suite, known once the ServerHello has been processed:
    /// for logs and the AEAD limits.
    #[must_use]
    pub fn negotiated_suite(&self) -> Option<CipherSuite> {
        let suite = self.conn.as_ref()?.negotiated_cipher_suite()?;
        CipherSuite::from_wire(u16::from(suite.suite()))
    }

    /// The handshake's results, the peer's identity included; `None` until
    /// [`is_handshaking`](Self::is_handshaking) is `false`.
    #[must_use]
    pub fn info(&self) -> Option<HandshakeInfo<'_>> {
        if self.state != SessionState::Established {
            return None;
        }
        let conn = self.conn.as_ref()?;
        let mut info = session::handshake_info(conn, self.server_name())?;
        info.peer = session::peer_identity(conn.peer_certificates(), &self.peer);
        if let Role::Server(part) = &self.role {
            info.fingerprint = part.fingerprint.as_ref();
        }
        Some(info)
    }

    /// The ClientHello's fingerprints (server), once parsed. JA4 starts with
    /// `q` for a hello that came over QUIC.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        match &self.role {
            Role::Server(part) => part.fingerprint.as_ref(),
            Role::Client(_) => None,
        }
    }

    /// An opaque id echoed in events (for example a connection id).
    pub fn set_tag(&mut self, tag: u64) {
        self.tag = tag;
    }

    /// The code of the error that failed the session.
    #[must_use]
    pub fn error_code(&self) -> Option<u16> {
        self.failure
    }
}

/// The alert for a failure of tls-net's own checks at completion.
fn completion_alert(e: &TlsError) -> u8 {
    match e {
        TlsError::NoApplicationProtocol => NO_APPLICATION_PROTOCOL,
        TlsError::PeerCertificateRequired => 116,
        TlsError::PeerCertificateInvalid(crate::error::CertificateProblem::Expired) => 45,
        TlsError::PeerChainTooLarge => 42,
        _ => 80,
    }
}

/// New keys from the handshake.
pub enum KeyChange {
    /// Keys for the Handshake packet number space.
    Handshake {
        /// Both directions' keys.
        keys: Keys,
    },
    /// Keys for 1-RTT packets, and the secrets for key updates.
    OneRtt {
        /// Both directions' keys.
        keys: Keys,
        /// The secrets for the next key phases.
        next: Secrets,
    },
}

impl From<rq::KeyChange> for KeyChange {
    fn from(change: rq::KeyChange) -> Self {
        match change {
            rq::KeyChange::Handshake { keys } => KeyChange::Handshake { keys: keys.into() },
            rq::KeyChange::OneRtt { keys, next } => KeyChange::OneRtt {
                keys: keys.into(),
                next: Secrets(next),
            },
        }
    }
}

impl fmt::Debug for KeyChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyChange::Handshake { .. } => "KeyChange::Handshake",
            KeyChange::OneRtt { .. } => "KeyChange::OneRtt",
        })
    }
}

/// Keys for one packet number space: `local` protects what this endpoint
/// sends, `remote` opens what it receives.
#[derive(Debug)]
pub struct Keys {
    /// For packets this endpoint sends.
    pub local: DirectionalKeys,
    /// For packets the peer sends.
    pub remote: DirectionalKeys,
}

impl From<rq::Keys> for Keys {
    fn from(keys: rq::Keys) -> Self {
        Keys {
            local: keys.local.into(),
            remote: keys.remote.into(),
        }
    }
}

/// The packet and header protection keys for one direction.
#[derive(Debug)]
pub struct DirectionalKeys {
    /// Protects the payload.
    pub packet: PacketKey,
    /// Protects the first byte and the packet number.
    pub header: HeaderKey,
}

impl From<rq::DirectionalKeys> for DirectionalKeys {
    fn from(keys: rq::DirectionalKeys) -> Self {
        DirectionalKeys {
            packet: PacketKey(keys.packet),
            header: HeaderKey(keys.header),
        }
    }
}

/// A packet protection key (RFC 9001 section 5.3). `Send + Sync`.
pub struct PacketKey(Box<dyn rq::PacketKey>);

impl fmt::Debug for PacketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketKey").finish_non_exhaustive()
    }
}

impl PacketKey {
    /// Encrypts `payload` in place, with the nonce from `packet_number` and
    /// `header` as associated data, and returns the tag to append.
    ///
    /// # Errors
    ///
    /// `QuicInput` when the payload is longer than the AEAD allows.
    pub fn seal(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; 16], TlsError> {
        let refused = TlsError::QuicInput {
            what: "packet payload",
        };
        let tag = self
            .0
            .encrypt_in_place(packet_number, header, payload)
            .map_err(|_| refused.clone())?;
        tag.as_ref().try_into().map_err(|_| refused)
    }

    /// Decrypts `payload_and_tag` (the ciphertext followed by its tag) in
    /// place and returns the plaintext's length.
    ///
    /// # Errors
    ///
    /// `DecryptFailed` when the packet does not authenticate.
    pub fn open(
        &self,
        packet_number: u64,
        header: &[u8],
        payload_and_tag: &mut [u8],
    ) -> Result<usize, TlsError> {
        self.0
            .decrypt_in_place(packet_number, header, payload_and_tag)
            .map(<[u8]>::len)
            .map_err(|_| TlsError::DecryptFailed)
    }

    /// The tag's length: 16 for every QUIC version 1 suite.
    #[must_use]
    pub fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    /// Packets this key may seal before a key update (RFC 9001 section 6.6).
    #[must_use]
    pub fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    /// Packets that may fail to open under this key before the connection
    /// must close (RFC 9001 section 6.6).
    #[must_use]
    pub fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

/// A header protection key (RFC 9001 section 5.4). `Send + Sync`.
pub struct HeaderKey(Box<dyn rq::HeaderProtectionKey>);

impl fmt::Debug for HeaderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderKey").finish_non_exhaustive()
    }
}

impl HeaderKey {
    /// The 5-byte mask for a 16-byte ciphertext sample (RFC 9001 section
    /// 5.4.1). Apply the low 4 bits of `mask[0]` to a long header's first
    /// byte, the low 5 to a short header's, and `mask[1..]` to the packet
    /// number; the top 3 bits of `mask[0]` are always 0.
    ///
    /// # Errors
    ///
    /// `QuicInput` if the provider refuses the sample (it never does for a
    /// QUIC version 1 suite).
    pub fn mask(&self, sample: &[u8; 16]) -> Result<[u8; 5], TlsError> {
        // rustls applies the mask rather than returning it. Applied to a
        // short header with a 4-byte packet number, all zeros, it leaves the
        // mask itself: the first byte's low 5 bits and the 4 packet number
        // bytes, which are all QUIC ever uses.
        const SHORT_PN4: u8 = 0x03;
        let mut first = SHORT_PN4;
        let mut pn = [0u8; 4];
        self.0
            .encrypt_in_place(sample, &mut first, &mut pn)
            .map_err(|_| TlsError::QuicInput {
                what: "header sample",
            })?;
        Ok([first ^ SHORT_PN4, pn[0], pn[1], pn[2], pn[3]])
    }
}

/// The 1-RTT secrets, for key updates (RFC 9001 section 6). Header keys do
/// not change across key phases; only packet keys do.
#[derive(Clone)]
pub struct Secrets(rq::Secrets);

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secrets").finish_non_exhaustive()
    }
}

impl Secrets {
    /// The packet keys of the next key phase; each call moves one phase on.
    pub fn next_packet_keys(&mut self) -> PacketKeySet {
        let set = self.0.next_packet_keys();
        PacketKeySet {
            local: PacketKey(set.local),
            remote: PacketKey(set.remote),
        }
    }
}

/// Packet keys for one key phase.
#[derive(Debug)]
pub struct PacketKeySet {
    /// For packets this endpoint sends.
    pub local: PacketKey,
    /// For packets the peer sends.
    pub remote: PacketKey,
}

/// The Initial keys from the client's first Destination Connection ID
/// (RFC 9001 section 5.2). They need no session, so a server can open a
/// client's first packet, and answer it, before accepting anything.
///
/// ```
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
/// let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
/// let keys = tls_net::quic::initial_keys(&dcid, tls_net::quic::Side::Client)?;
/// assert_eq!(keys.local.packet.tag_len(), 16);
/// # }
/// # Ok::<(), tls_net::TlsError>(())
/// ```
///
/// # Errors
///
/// `QuicInput` for a connection ID over 20 bytes; `NoProvider` in a build
/// without a provider.
pub fn initial_keys(client_dcid: &[u8], side: Side) -> Result<Keys, TlsError> {
    if client_dcid.len() > MAX_CID_LEN {
        return Err(TlsError::QuicInput {
            what: "connection ID",
        });
    }
    let suite = initial_suite()?;
    Ok(suite.keys(client_dcid, side.into(), rq::Version::V1).into())
}

/// The provider's TLS_AES_128_GCM_SHA256 with its QUIC algorithm.
fn initial_suite() -> Result<rq::Suite, TlsError> {
    let parts = crate::provider::parts().ok_or(TlsError::NoProvider)?;
    parts
        .all_suites
        .iter()
        .find(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        .and_then(|s| match s {
            rustls::SupportedCipherSuite::Tls13(t) => t.quic_suite(),
            rustls::SupportedCipherSuite::Tls12(_) => None,
        })
        .ok_or(TlsError::NoProvider)
}

/// The Retry Integrity Tag (RFC 9001 section 5.8): AES-128-GCM under the
/// version 1 key and nonce, with `pseudo_packet` (the Retry Pseudo-Packet)
/// as associated data and nothing to encrypt.
///
/// rustls has no AEAD under a fixed key, so this one call goes to the
/// provider (aws-lc-rs or ring) directly (D-155).
///
/// ```
/// # #[cfg(any(feature = "aws-lc", feature = "ring"))] {
/// let tag = tls_net::quic::retry_tag(b"pseudo-packet")?;
/// assert_eq!(tag.len(), 16);
/// # }
/// # Ok::<(), tls_net::TlsError>(())
/// ```
///
/// # Errors
///
/// `NoProvider` in a build without a provider.
pub fn retry_tag(pseudo_packet: &[u8]) -> Result<[u8; 16], TlsError> {
    retry::tag(pseudo_packet)
}

/// RFC 9001 section 5.8, version 1.
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

#[cfg(feature = "aws-lc")]
mod retry {
    use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    pub(super) fn tag(pseudo: &[u8]) -> Result<[u8; 16], crate::TlsError> {
        seal(pseudo).ok_or(crate::TlsError::Other)
    }

    fn seal(pseudo: &[u8]) -> Option<[u8; 16]> {
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &super::RETRY_KEY).ok()?);
        let nonce = Nonce::assume_unique_for_key(super::RETRY_NONCE);
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(pseudo), &mut [])
            .ok()?;
        tag.as_ref().try_into().ok()
    }
}

#[cfg(all(feature = "ring", not(feature = "aws-lc")))]
mod retry {
    use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    pub(super) fn tag(pseudo: &[u8]) -> Result<[u8; 16], crate::TlsError> {
        seal(pseudo).ok_or(crate::TlsError::Other)
    }

    fn seal(pseudo: &[u8]) -> Option<[u8; 16]> {
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &super::RETRY_KEY).ok()?);
        let nonce = Nonce::assume_unique_for_key(super::RETRY_NONCE);
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(pseudo), &mut [])
            .ok()?;
        tag.as_ref().try_into().ok()
    }
}

#[cfg(not(any(feature = "aws-lc", feature = "ring")))]
mod retry {
    pub(super) fn tag(_pseudo: &[u8]) -> Result<[u8; 16], crate::TlsError> {
        let _ = (super::RETRY_KEY, super::RETRY_NONCE);
        Err(crate::TlsError::NoProvider)
    }
}
