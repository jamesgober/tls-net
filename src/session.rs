//! Server and client sessions: the step loop over rustls's unbuffered API
//! (PLAN 6.3).

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};

use crate::error::{self, TlsError};
use crate::hello::{HelloParse, HelloParser};
use crate::identity::{HandshakeInfo, HandshakeKind};
use crate::policy::{CipherSuite, Group, Version};
use crate::server::{CapacitySlot, ServerState};
use crate::sni::NormalizedName;

/// The largest plaintext in one TLS record.
pub const MAX_RECORD_PAYLOAD: usize = 16_384;
/// The free output space `step` needs: one maximum wire record (rustls's
/// `MAX_WIRE_SIZE`: 16,384 + 2,048 + 5).
pub const OUTGOING_MIN: usize = 18_437;
/// The input buffer a session needs once established: one maximum wire record.
pub const INCOMING_MIN: usize = 18_437;

/// The fatal `unrecognized_name` alert in a plaintext record (D-031).
const UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

/// What one `step` did.
///
/// `consumed` bytes must be removed from the front of the input before the
/// next `step` (after any `Data` slice has been used); `written` bytes at the
/// start of the output must be sent, whatever the event.
#[must_use]
#[non_exhaustive]
#[derive(Debug)]
pub struct Progress<'i> {
    /// Input bytes consumed.
    pub consumed: usize,
    /// Bytes written at the start of the output.
    pub written: usize,
    /// What to do next.
    pub event: Event<'i>,
}

/// The next thing a driver does after a `step`.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'i> {
    /// Read more ciphertext, append it after the unconsumed bytes, call `step` again.
    NeedInput,
    /// Send the `written` bytes at the start of the output, all of them, then call `step` again.
    Transmit,
    /// The handshake finished (once); `info()` is now `Some`.
    HandshakeComplete,
    /// Plaintext, a slice of the input; use it, then call `step` again.
    Data(&'i [u8]),
    /// Fewer than `OUTGOING_MIN` bytes free in the output; flush and call again.
    OutputFull,
    /// `close_notify` received; the plaintext stream ended cleanly.
    PeerClosed,
    /// Both directions closed.
    Closed,
}

/// How a TLS stream ended.
///
/// ```
/// assert_ne!(tls_net::CloseKind::Clean, tls_net::CloseKind::Unclean);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseKind {
    /// `close_notify` was received.
    Clean,
    /// The transport ended without it (truncation, T-17).
    Unclean,
}

/// Where a session is.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Server: waiting for the ClientHello.
    Hello,
    /// The handshake is running.
    Handshake,
    /// The handshake finished.
    Established,
    /// The peer sent `close_notify`; sending still works.
    HalfClosed,
    /// This side sent `close_notify`.
    Closing,
    /// Both directions closed.
    Closed,
    /// The session failed; see `error_code()`.
    Failed,
}

/// The two rustls connection types, behind one shape.
pub(crate) trait Engine: Send {
    type Data;
    fn process<'c, 'i>(&'c mut self, input: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data>;
    fn common(&self) -> &rustls::CommonState;
}

impl Engine for UnbufferedServerConnection {
    type Data = ServerConnectionData;
    fn process<'c, 'i>(
        &'c mut self,
        input: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ServerConnectionData> {
        self.process_tls_records(input)
    }
    fn common(&self) -> &rustls::CommonState {
        self
    }
}

impl Engine for UnbufferedClientConnection {
    type Data = ClientConnectionData;
    fn process<'c, 'i>(
        &'c mut self,
        input: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ClientConnectionData> {
        self.process_tls_records(input)
    }
    fn common(&self) -> &rustls::CommonState {
        self
    }
}

/// What the rustls loop stopped on.
enum Stop {
    NeedInput,
    Room,
    Complete,
    Data { len: usize },
    PeerClosed,
    Closed,
    Failed(TlsError),
}

/// State shared by both session kinds.
pub(crate) struct Core<C> {
    conn: Option<C>,
    pub(crate) state: SessionState,
    /// The error to return on the next `step` after an alert was handed out (D-051).
    pending: Option<TlsError>,
    failure: Option<u16>,
    alert: Option<u8>,
    handshake_bytes: usize,
    max_handshake_bytes: usize,
    held: usize,
    /// Plaintext that arrived with the last handshake flight: it sits at the
    /// front of the next input and is handed out before rustls runs again,
    /// so `HandshakeComplete` always comes first.
    held_plain: usize,
    /// `close_notify` that arrived with the last handshake flight.
    held_peer_closed: bool,
    peer_closed: bool,
    pub(crate) tag: u64,
    pub(crate) started: Option<Instant>,
}

impl<C: Engine> Core<C> {
    pub(crate) fn new(conn: Option<C>, state: SessionState, max_handshake_bytes: u32) -> Self {
        Core {
            conn,
            state,
            pending: None,
            failure: None,
            alert: None,
            handshake_bytes: 0,
            max_handshake_bytes: max_handshake_bytes as usize,
            held: 0,
            held_plain: 0,
            held_peer_closed: false,
            peer_closed: false,
            tag: 0,
            started: None,
        }
    }

    pub(crate) fn set_conn(&mut self, conn: C) {
        self.conn = Some(conn);
        self.state = SessionState::Handshake;
    }

    pub(crate) fn fail(&mut self, e: TlsError) -> TlsError {
        self.state = SessionState::Failed;
        self.failure = Some(e.code());
        if let TlsError::AlertReceived { alert } = e {
            self.alert = Some(alert);
        }
        e
    }

    /// Fails with `e` and hands `written` bytes (an alert) out first (D-051).
    fn fail_after_transmit<'i>(
        &mut self,
        e: TlsError,
        consumed: usize,
        written: usize,
    ) -> Result<Progress<'i>, TlsError> {
        let e = self.fail(e);
        if written == 0 {
            return Err(e);
        }
        self.pending = Some(e);
        Ok(Progress {
            consumed,
            written,
            event: Event::Transmit,
        })
    }

    /// Steps 1 and 2 of `step`: terminal states and the output check.
    pub(crate) fn precheck<'i>(&mut self, output: &[u8]) -> Option<Result<Progress<'i>, TlsError>> {
        match self.state {
            SessionState::Failed => {
                return Some(Err(self.pending.take().unwrap_or(TlsError::SessionFailed)));
            }
            SessionState::Closed => {
                return Some(Ok(Progress {
                    consumed: 0,
                    written: 0,
                    event: Event::Closed,
                }));
            }
            _ => {}
        }
        if output.len() < OUTGOING_MIN {
            return Some(Ok(Progress {
                consumed: 0,
                written: 0,
                event: Event::OutputFull,
            }));
        }
        if self.started.is_none() {
            self.started = Some(Instant::now());
        }
        None
    }

    /// Whether something that arrived with the last handshake flight waits.
    pub(crate) fn has_held(&self) -> bool {
        self.held_plain > 0 || self.held_peer_closed
    }

    /// Hands out what arrived with the last handshake flight, before rustls
    /// runs again (D-066).
    pub(crate) fn take_held<'i>(&mut self, input: &'i mut [u8]) -> Result<Progress<'i>, TlsError> {
        if self.held_plain > 0 {
            let len = std::mem::take(&mut self.held_plain);
            if input.len() < len {
                return Err(self.fail(TlsError::WrongState));
            }
            return Ok(Progress {
                consumed: len,
                written: 0,
                event: Event::Data(&input[..len]),
            });
        }
        self.held_peer_closed = false;
        self.peer_closed = true;
        self.state = SessionState::HalfClosed;
        Ok(Progress {
            consumed: 0,
            written: 0,
            event: Event::PeerClosed,
        })
    }

    /// Writes tls-net's own `unrecognized_name` alert and fails (D-031).
    pub(crate) fn refuse_unknown_name<'i>(
        &mut self,
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError> {
        output[..UNRECOGNIZED_NAME.len()].copy_from_slice(&UNRECOGNIZED_NAME);
        self.alert = Some(112);
        self.fail_after_transmit(TlsError::UnknownServerName, 0, UNRECOGNIZED_NAME.len())
    }

    /// Step 4: runs rustls until it needs the caller.
    pub(crate) fn run<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError> {
        let mut consumed = 0usize;
        let mut written = 0usize;
        let mut stop = self.drive(input, output, &mut consumed, &mut written);
        // rustls hands out application data (or close_notify) that came in the
        // same flight as the peer's Finished before it reports the handshake
        // complete. Report completion first; keep the plaintext at the front
        // of the unconsumed input for the next call.
        if self.state == SessionState::Handshake
            && self
                .conn
                .as_ref()
                .is_some_and(|c| !c.common().is_handshaking())
        {
            match stop {
                Stop::Data { len } => {
                    consumed -= len;
                    self.held_plain = len;
                    stop = Stop::Complete;
                }
                Stop::PeerClosed => {
                    self.held_peer_closed = true;
                    stop = Stop::Complete;
                }
                _ => {}
            }
        }
        if matches!(self.state, SessionState::Handshake) {
            self.handshake_bytes = self.handshake_bytes.saturating_add(consumed);
            if self.handshake_bytes.saturating_add(self.held) > self.max_handshake_bytes {
                return self.fail_after_transmit(TlsError::HandshakeTooLarge, consumed, written);
            }
        }
        let event = match stop {
            Stop::NeedInput => Event::NeedInput,
            Stop::Room => Event::Transmit,
            Stop::Complete => {
                self.state = SessionState::Established;
                Event::HandshakeComplete
            }
            Stop::Data { len } => {
                // The plaintext was copied to the front of the consumed bytes.
                let start = consumed - len;
                return Ok(Progress {
                    consumed,
                    written,
                    event: Event::Data(&input[start..consumed]),
                });
            }
            Stop::PeerClosed => {
                self.peer_closed = true;
                self.state = if self.state == SessionState::Closing {
                    SessionState::Closed
                } else {
                    SessionState::HalfClosed
                };
                Event::PeerClosed
            }
            Stop::Closed => {
                self.state = SessionState::Closed;
                Event::Closed
            }
            Stop::Failed(e) => return self.fail_after_transmit(e, consumed, written),
        };
        let event = if written > 0 && event == Event::NeedInput {
            Event::Transmit
        } else {
            event
        };
        Ok(Progress {
            consumed,
            written,
            event,
        })
    }

    fn drive(
        &mut self,
        input: &mut [u8],
        output: &mut [u8],
        consumed: &mut usize,
        written: &mut usize,
    ) -> Stop {
        let Some(conn) = self.conn.as_mut() else {
            return Stop::Failed(TlsError::WrongState);
        };
        let mut failed: Option<TlsError> = None;
        loop {
            if output.len() - *written < OUTGOING_MIN {
                return match failed.take() {
                    Some(e) => Stop::Failed(e),
                    None => Stop::Room,
                };
            }
            let rest = &mut input[*consumed..];
            let rest_len = rest.len();
            let UnbufferedStatus { discard, state } = conn.process(rest);
            let state = match state {
                Ok(state) => state,
                Err(e) => {
                    *consumed += discard;
                    if failed.is_some() {
                        // The queued alert (if any) is encoded; stop.
                        return Stop::Failed(failed.unwrap_or(TlsError::Other));
                    }
                    let mapped = error::from_rustls(&e);
                    if let TlsError::AlertReceived { alert } = mapped {
                        self.alert = Some(alert);
                    }
                    failed = Some(mapped);
                    continue;
                }
            };
            match state {
                ConnectionState::EncodeTlsData(mut enc) => {
                    match enc.encode(&mut output[*written..]) {
                        Ok(n) => *written += n,
                        Err(EncodeError::InsufficientSize(_))
                        | Err(EncodeError::AlreadyEncoded) => {
                            return Stop::Failed(TlsError::Other);
                        }
                    }
                    *consumed += discard;
                }
                ConnectionState::TransmitTlsData(t) => {
                    t.done();
                    *consumed += discard;
                    if let Some(e) = failed.take() {
                        return Stop::Failed(e);
                    }
                }
                ConnectionState::BlockedHandshake => {
                    *consumed += discard;
                    self.held = rest_len - discard;
                    return match failed.take() {
                        Some(e) => Stop::Failed(e),
                        None => Stop::NeedInput,
                    };
                }
                ConnectionState::WriteTraffic(_) => {
                    *consumed += discard;
                    if let Some(e) = failed.take() {
                        return Stop::Failed(e);
                    }
                    self.held = 0;
                    if self.state == SessionState::Handshake {
                        return Stop::Complete;
                    }
                    return Stop::NeedInput;
                }
                ConnectionState::ReadTraffic(mut read) => {
                    // rustls 0.23 hands out an owned copy (D-035). Bounce it
                    // through the spare output (at least OUTGOING_MIN bytes,
                    // more than any record) so it can land at the end of the
                    // input bytes this call discards.
                    let (len, extra) = match read.next_record() {
                        Some(Ok(record)) => {
                            let len = record.payload.len();
                            if len > output.len() - *written {
                                return Stop::Failed(TlsError::Other);
                            }
                            output[*written..*written + len].copy_from_slice(record.payload);
                            (len, record.discard)
                        }
                        Some(Err(e)) => return Stop::Failed(error::from_rustls(&e)),
                        None => {
                            *consumed += discard;
                            continue;
                        }
                    };
                    let discard = discard + extra;
                    if len > discard {
                        return Stop::Failed(TlsError::Other);
                    }
                    let end = *consumed + discard;
                    input[end - len..end].copy_from_slice(&output[*written..*written + len]);
                    *consumed = end;
                    return Stop::Data { len };
                }
                ConnectionState::ReadEarlyData(_) => {
                    *consumed += discard;
                    return Stop::Failed(TlsError::EarlyDataRefused);
                }
                ConnectionState::PeerClosed => {
                    *consumed += discard;
                    return Stop::PeerClosed;
                }
                ConnectionState::Closed => {
                    *consumed += discard;
                    return Stop::Closed;
                }
                _ => {
                    *consumed += discard;
                    return Stop::Failed(TlsError::Other);
                }
            }
        }
    }

    pub(crate) fn encrypt(
        &mut self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, TlsError> {
        if !matches!(
            self.state,
            SessionState::Established | SessionState::HalfClosed
        ) {
            return Err(TlsError::WrongState);
        }
        if plaintext.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.as_mut().ok_or(TlsError::WrongState)?;
        let mut written = 0;
        loop {
            let status = conn.process(&mut []);
            match status.state {
                Ok(ConnectionState::WriteTraffic(mut w)) => {
                    return match w.encrypt(plaintext, &mut output[written..]) {
                        Ok(n) => Ok(written + n),
                        Err(EncryptError::InsufficientSize(s)) => Err(TlsError::OutputFull {
                            required: written + s.required_size,
                        }),
                        Err(EncryptError::EncryptExhausted) => {
                            Err(self.fail(TlsError::KeyUsageExhausted))
                        }
                    };
                }
                Ok(ConnectionState::EncodeTlsData(mut enc)) => {
                    match enc.encode(&mut output[written..]) {
                        Ok(n) => written += n,
                        Err(EncodeError::InsufficientSize(s)) => {
                            return Err(TlsError::OutputFull {
                                required: written + s.required_size,
                            });
                        }
                        Err(EncodeError::AlreadyEncoded) => return Err(self.fail(TlsError::Other)),
                    }
                }
                Ok(ConnectionState::TransmitTlsData(t)) => t.done(),
                Ok(_) => return Err(TlsError::WrongState),
                Err(e) => return Err(self.fail(error::from_rustls(&e))),
            }
        }
    }

    pub(crate) fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        match self.state {
            SessionState::Closing | SessionState::Closed => return Ok(0),
            SessionState::Established | SessionState::HalfClosed => {}
            _ => return Err(TlsError::WrongState),
        }
        let conn = self.conn.as_mut().ok_or(TlsError::WrongState)?;
        let status = conn.process(&mut []);
        match status.state {
            Ok(ConnectionState::WriteTraffic(mut w)) => match w.queue_close_notify(output) {
                Ok(n) => {
                    self.state = if self.peer_closed {
                        SessionState::Closed
                    } else {
                        SessionState::Closing
                    };
                    Ok(n)
                }
                Err(EncryptError::InsufficientSize(s)) => Err(TlsError::OutputFull {
                    required: s.required_size,
                }),
                Err(EncryptError::EncryptExhausted) => Err(self.fail(TlsError::KeyUsageExhausted)),
            },
            Ok(_) => Err(TlsError::WrongState),
            Err(e) => Err(self.fail(error::from_rustls(&e))),
        }
    }

    pub(crate) fn on_eof(&mut self) -> CloseKind {
        if self.peer_closed {
            return CloseKind::Clean;
        }
        if !matches!(self.state, SessionState::Failed | SessionState::Closed) {
            let _ = self.fail(TlsError::UncleanClose);
        }
        CloseKind::Unclean
    }

    pub(crate) fn input_capacity_required(&self) -> usize {
        match self.state {
            SessionState::Hello | SessionState::Handshake => {
                INCOMING_MIN.max(self.held.saturating_add(1))
            }
            _ => INCOMING_MIN,
        }
    }

    pub(crate) fn established(&self) -> bool {
        matches!(
            self.state,
            SessionState::Established | SessionState::HalfClosed | SessionState::Closing
        ) || (self.state == SessionState::Closed
            && self
                .conn
                .as_ref()
                .is_some_and(|c| !c.common().is_handshaking()))
    }

    pub(crate) fn info<'s>(&'s self, server_name: Option<&'s str>) -> Option<HandshakeInfo<'s>> {
        if !self.established() {
            return None;
        }
        let common = self.conn.as_ref()?.common();
        let version = match common.protocol_version()? {
            rustls::ProtocolVersion::TLSv1_3 => Version::Tls13,
            rustls::ProtocolVersion::TLSv1_2 => Version::Tls12,
            _ => return None,
        };
        let cipher_suite =
            CipherSuite::from_wire(u16::from(common.negotiated_cipher_suite()?.suite()))?;
        let group = common
            .negotiated_key_exchange_group()
            .and_then(|g| Group::from_wire(u16::from(g.name())));
        let kind = match common.handshake_kind()? {
            rustls::HandshakeKind::Full => HandshakeKind::Full,
            rustls::HandshakeKind::FullWithHelloRetryRequest => HandshakeKind::FullWithHelloRetry,
            rustls::HandshakeKind::Resumed => HandshakeKind::Resumed,
        };
        Some(HandshakeInfo::new(
            version,
            cipher_suite,
            group,
            common.alpn_protocol(),
            server_name,
            kind,
        ))
    }

    pub(crate) fn peer_chain(&self) -> Option<&[rustls::pki_types::CertificateDer<'static>]> {
        self.conn.as_ref()?.common().peer_certificates()
    }

    pub(crate) fn error_code(&self) -> Option<u16> {
        self.failure
    }

    pub(crate) fn alert(&self) -> Option<u8> {
        self.alert
    }
}

/// One server-side TLS connection. Created by [`TlsServer::accept`](crate::TlsServer::accept);
/// driven with [`step`](ServerSession::step).
///
/// `Send`, not `Sync`: one connection is driven by one thread at a time.
pub struct ServerSession {
    core: Core<UnbufferedServerConnection>,
    state: Arc<ServerState>,
    slot: Option<CapacitySlot>,
    sni: Option<NormalizedName>,
}

impl fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSession")
            .field("state", &self.core.state)
            .field("tag", &self.core.tag)
            .field("server_name", &self.sni)
            .finish_non_exhaustive()
    }
}

impl ServerSession {
    pub(crate) fn new(state: Arc<ServerState>, slot: CapacitySlot) -> Self {
        let max = state.limits.max_handshake_bytes;
        ServerSession {
            core: Core::new(None, SessionState::Hello, max),
            state,
            slot: Some(slot),
            sni: None,
        }
    }

    /// Takes ciphertext from `input` and writes records to send into `output`.
    ///
    /// See `docs/API.md` ("Sessions") for the full contract: at most one
    /// `Data` per call; `consumed` bytes leave the front of `input` after the
    /// event is handled; `written` bytes at the start of `output` are sent.
    /// A failure with an alert to send comes back as `Transmit` first and the
    /// error on the next call (D-051).
    ///
    /// # Errors
    ///
    /// Any session error, `TLS-0030` to `TLS-0050`.
    pub fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError> {
        if let Some(done) = self.core.precheck(output) {
            return done;
        }
        if self.core.has_held() {
            return self.core.take_held(input);
        }
        if self.core.state == SessionState::Hello {
            match HelloParser::parse(input, &self.state.hello_limits) {
                Ok(HelloParse::Incomplete { .. }) => {
                    return Ok(Progress {
                        consumed: 0,
                        written: 0,
                        event: Event::NeedInput,
                    });
                }
                Ok(HelloParse::Complete { view, .. }) => {
                    self.sni = view.normalized_server_name();
                    let Some(slot) = self
                        .state
                        .table
                        .lookup(self.sni.as_ref().map(NormalizedName::as_str))
                    else {
                        self.release();
                        return self.core.refuse_unknown_name(output);
                    };
                    let config = self
                        .state
                        .configs
                        .get(slot.group)
                        .cloned()
                        .ok_or(TlsError::Other)?;
                    match UnbufferedServerConnection::new(config) {
                        Ok(conn) => self.core.set_conn(conn),
                        Err(e) => {
                            self.release();
                            return Err(self.core.fail(error::from_rustls(&e)));
                        }
                    }
                }
                Err(e) if self.state.hello_limits.refuse_malformed || is_not_tls(&e) => {
                    self.release();
                    return Err(self.core.fail(e));
                }
                Err(_) => {
                    // refuse_malformed is off: rustls decides, no fingerprint.
                    let config = self.state.configs.first().cloned().ok_or(TlsError::Other)?;
                    let conn = UnbufferedServerConnection::new(config)
                        .map_err(|e| self.core.fail(error::from_rustls(&e)))?;
                    self.core.set_conn(conn);
                }
            }
        }
        let result = self.core.run(input, output);
        match &result {
            Ok(p) if p.event == Event::HandshakeComplete => self.release(),
            Err(_) => self.release(),
            _ if self.core.state == SessionState::Failed => self.release(),
            _ => {}
        }
        result
    }

    fn release(&mut self) {
        self.slot = None;
    }

    /// Encrypts all of `plaintext` into `output`, or writes nothing.
    ///
    /// # Errors
    ///
    /// `OutputFull` (with the bytes needed), `WrongState` before the
    /// handshake or after `close`, `KeyUsageExhausted`.
    pub fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        self.core.encrypt(plaintext, output)
    }

    /// Writes `close_notify`. A second call writes nothing.
    ///
    /// # Errors
    ///
    /// `WrongState` before the handshake completes, `OutputFull`.
    pub fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        self.core.close(output)
    }

    /// The transport ended: `Clean` if `close_notify` was received; otherwise
    /// `Unclean` and the session fails with `UncleanClose` (T-17).
    pub fn on_eof(&mut self) -> CloseKind {
        self.release();
        self.core.on_eof()
    }

    /// Where the session is.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.core.state
    }

    /// The handshake's results; `None` before `HandshakeComplete`.
    #[must_use]
    pub fn info(&self) -> Option<HandshakeInfo<'_>> {
        self.core
            .info(self.sni.as_ref().map(NormalizedName::as_str))
    }

    /// The smallest input buffer the session needs now (D-029).
    #[must_use]
    pub fn input_capacity_required(&self) -> usize {
        self.core.input_capacity_required()
    }

    /// An opaque id echoed in events (for example a connection id).
    pub fn set_tag(&mut self, tag: u64) {
        self.core.tag = tag;
    }

    /// The code of the error that failed the session.
    #[must_use]
    pub fn error_code(&self) -> Option<u16> {
        self.core.error_code()
    }

    /// The TLS alert sent or received when the session failed.
    #[must_use]
    pub fn alert(&self) -> Option<u8> {
        self.core.alert()
    }
}

fn is_not_tls(e: &TlsError) -> bool {
    matches!(
        e,
        TlsError::NotTls
            | TlsError::BadRecord
            | TlsError::HelloTooLarge
            | TlsError::HelloTooFragmented
    )
}

/// One client-side TLS connection. Created by [`TlsClient::connect`](crate::TlsClient::connect).
///
/// `Send`, not `Sync`.
pub struct ClientSession {
    core: Core<UnbufferedClientConnection>,
    server_name: Box<str>,
    max_chain_len: usize,
    max_cert_bytes: usize,
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSession")
            .field("state", &self.core.state)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    pub(crate) fn new(
        conn: UnbufferedClientConnection,
        server_name: Box<str>,
        limits: &crate::limits::HandshakeLimits,
    ) -> Self {
        ClientSession {
            core: Core::new(
                Some(conn),
                SessionState::Handshake,
                limits.max_handshake_bytes,
            ),
            server_name,
            max_chain_len: usize::from(limits.max_peer_chain_len),
            max_cert_bytes: limits.max_peer_cert_bytes as usize,
        }
    }

    /// As [`ServerSession::step`]; the first call writes the ClientHello.
    ///
    /// # Errors
    ///
    /// Any session error, `TLS-0032` to `TLS-0050`.
    pub fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError> {
        if let Some(done) = self.core.precheck(output) {
            return done;
        }
        if self.core.has_held() {
            return self.core.take_held(input);
        }
        let p = self.core.run(input, output)?;
        if p.event == Event::HandshakeComplete {
            let too_large = self.core.peer_chain().is_some_and(|chain| {
                chain.len() > self.max_chain_len
                    || chain.iter().any(|c| c.len() > self.max_cert_bytes)
            });
            if too_large {
                return Err(self.core.fail(TlsError::PeerChainTooLarge));
            }
        }
        Ok(p)
    }

    /// As [`ServerSession::encrypt`].
    ///
    /// # Errors
    ///
    /// As [`ServerSession::encrypt`].
    pub fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        self.core.encrypt(plaintext, output)
    }

    /// As [`ServerSession::close`].
    ///
    /// # Errors
    ///
    /// As [`ServerSession::close`].
    pub fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        self.core.close(output)
    }

    /// As [`ServerSession::on_eof`].
    pub fn on_eof(&mut self) -> CloseKind {
        self.core.on_eof()
    }

    /// Where the session is.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.core.state
    }

    /// The handshake's results; `None` before `HandshakeComplete`.
    /// `server_name` is the name this client connected to.
    #[must_use]
    pub fn info(&self) -> Option<HandshakeInfo<'_>> {
        self.core.info(Some(&self.server_name))
    }

    /// The smallest input buffer the session needs now (D-029).
    #[must_use]
    pub fn input_capacity_required(&self) -> usize {
        self.core.input_capacity_required()
    }

    /// An opaque id echoed in events.
    pub fn set_tag(&mut self, tag: u64) {
        self.core.tag = tag;
    }

    /// The code of the error that failed the session.
    #[must_use]
    pub fn error_code(&self) -> Option<u16> {
        self.core.error_code()
    }

    /// The TLS alert sent or received when the session failed.
    #[must_use]
    pub fn alert(&self) -> Option<u8> {
        self.core.alert()
    }
}
