//! Server and client sessions: the step loop over rustls's unbuffered API
//! (PLAN 6.3).

use std::cell::OnceCell;
use std::fmt;
use std::time::Instant;

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};

use crate::error::{self, TlsError};
use crate::fingerprint::Fingerprint;
use crate::hello::{HelloParse, parse_client_hello};
use crate::hook::{HelloContext, HelloVerdict};
use crate::identity::{HandshakeInfo, HandshakeKind, PeerIdentity};
use crate::observe::{HelloRefusal, Observation, TlsEvent};
use crate::policy::{CipherSuite, Group, Version};
use crate::server::{CapacitySlot, Group as HostGroup, ServerState};

/// The largest plaintext in one TLS record.
pub const MAX_RECORD_PAYLOAD: usize = 16_384;
/// The free output space `step` needs: one maximum wire record (rustls's
/// `MAX_WIRE_SIZE`: 16,384 + 2,048 + 5).
pub const MIN_OUTPUT_BUFFER: usize = 18_437;
/// Room `close` asks for: a close_notify record is at most 31 bytes
/// (TLS 1.2 with AES-GCM's explicit nonce), with margin.
const CLOSE_NOTIFY_MAX: usize = 64;
/// The input buffer a session needs once established: one maximum wire record.
pub const MIN_INPUT_BUFFER: usize = 18_437;

/// The fatal `unrecognized_name` alert in a plaintext record (D-031).
const UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];
/// The fatal `no_application_protocol` alert in a plaintext record.
const NO_APPLICATION_PROTOCOL: [u8; 7] = [21, 3, 3, 0, 2, 2, 120];

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
    /// Fewer than `MIN_OUTPUT_BUFFER` bytes free in the output; flush and call again.
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
    /// Whether this is the server side.
    const SERVER: bool;
    fn process<'c, 'i>(&'c mut self, input: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data>;
    fn common(&self) -> &rustls::CommonState;
}

impl Engine for UnbufferedServerConnection {
    type Data = ServerConnectionData;
    const SERVER: bool = true;
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
    const SERVER: bool = false;
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

/// Whether `bytes` starts with a whole TLS record (header and payload).
fn complete_record_at(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes.len() - 5 >= usize::from(u16::from_be_bytes([bytes[3], bytes[4]]))
}

/// The alert rustls queues with `e`, where rustls defines which: a
/// certificate a verifier refused goes through the public `CertificateError`
/// mapping, and a server that requires a client certificate and got none
/// sends `certificate_required`. Every other alert rustls picks internally
/// and does not expose, so it is not guessed here.
fn sent_alert(e: &rustls::Error, server: bool) -> Option<u8> {
    match e {
        rustls::Error::InvalidCertificate(c) => {
            Some(u8::from(rustls::AlertDescription::from(c.clone())))
        }
        rustls::Error::NoCertificatesPresented if server => {
            Some(u8::from(rustls::AlertDescription::CertificateRequired))
        }
        _ => None,
    }
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
    /// rustls holds part of a post-handshake message (a ticket or a key
    /// update split over records) in the caller's unconsumed input, so it
    /// must not run on any other buffer until the next `step` (D-126).
    partial_message: bool,
    /// The input the hello parser last asked for, while in `Hello`.
    pub(crate) hello_needed: usize,
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
            partial_message: false,
            hello_needed: 0,
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
        if output.len() < MIN_OUTPUT_BUFFER {
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

    /// Writes `no_application_protocol` and fails: ALPN is required (T-15).
    pub(crate) fn refuse_no_alpn<'i>(
        &mut self,
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError> {
        output[..NO_APPLICATION_PROTOCOL.len()].copy_from_slice(&NO_APPLICATION_PROTOCOL);
        self.alert = Some(120);
        self.fail_after_transmit(
            TlsError::NoApplicationProtocol,
            0,
            NO_APPLICATION_PROTOCOL.len(),
        )
    }

    pub(crate) fn set_max_handshake_bytes(&mut self, n: u32) {
        self.max_handshake_bytes = n as usize;
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
        // rustls reads every complete record before it stops for anything but
        // data, so a complete record it left undiscarded holds part of a
        // handshake message: rustls reads it again from the caller's next
        // input, and a call on an empty buffer would index past its end (D-126).
        self.partial_message = !matches!(stop, Stop::Data { .. } | Stop::Failed(_))
            && complete_record_at(&input[consumed..]);
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
            if output.len() - *written < MIN_OUTPUT_BUFFER {
                return match failed.take() {
                    Some(e) => Stop::Failed(e),
                    None => Stop::Room,
                };
            }
            // After a failure rustls is called only while it holds queued
            // records (the alert): it hands those out before reading input,
            // whereas a call with nothing queued would parse the next record
            // and, if that record is malformed too, queue a second fatal
            // alert (D-111).
            if failed.is_some() && !conn.common().wants_write() {
                return Stop::Failed(failed.unwrap_or(TlsError::Other));
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
                    } else if let Some(alert) = sent_alert(&e, C::SERVER) {
                        self.alert = Some(alert);
                    }
                    failed = Some(mapped);
                    continue;
                }
            };
            if failed.is_some()
                && !matches!(
                    state,
                    ConnectionState::EncodeTlsData(_) | ConnectionState::TransmitTlsData(_)
                )
            {
                return Stop::Failed(failed.unwrap_or(TlsError::Other));
            }
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
                    // through the spare output (at least MIN_OUTPUT_BUFFER bytes,
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
        if self.partial_message {
            return Err(TlsError::WrongState);
        }
        let conn = self.conn.as_mut().ok_or(TlsError::WrongState)?;
        // Records `step` left queued (its output was full) go out through
        // `step`: encoding them here could lose them to a short output, or
        // put them after this call's bytes (D-129).
        if conn.common().wants_write() {
            return Err(TlsError::WrongState);
        }
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
        if self.partial_message {
            return Err(TlsError::WrongState);
        }
        let conn = self.conn.as_mut().ok_or(TlsError::WrongState)?;
        if conn.common().wants_write() {
            return Err(TlsError::WrongState);
        }
        // rustls marks close_notify sent before it checks the output's size,
        // so a short output would lose it (D-129).
        if output.len() < CLOSE_NOTIFY_MAX {
            return Err(TlsError::OutputFull {
                required: CLOSE_NOTIFY_MAX,
            });
        }
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
            // A hello may span up to 16 records of up to 65,535 bytes in
            // all (`HelloLimits`): ask for what the parser said it needs.
            SessionState::Hello => MIN_INPUT_BUFFER.max(self.hello_needed),
            SessionState::Handshake => MIN_INPUT_BUFFER.max(self.held.saturating_add(1)),
            _ => MIN_INPUT_BUFFER,
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
            self.peer_chain().is_some_and(|c| !c.is_empty()),
        ))
    }

    pub(crate) fn peer_chain(&self) -> Option<&[rustls::pki_types::CertificateDer<'static>]> {
        self.conn.as_ref()?.common().peer_certificates()
    }

    fn resumed(&self) -> bool {
        self.conn.as_ref().and_then(|c| c.common().handshake_kind())
            == Some(rustls::HandshakeKind::Resumed)
    }

    fn alpn_negotiated(&self) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|c| c.common().alpn_protocol().is_some())
    }

    /// The peer's identity, parsed from its end-entity certificate on the
    /// first call and kept in `cell` (D-104).
    fn peer_identity<'a>(
        &self,
        cell: &'a OnceCell<Option<Box<PeerIdentity>>>,
    ) -> Option<&'a PeerIdentity> {
        cell.get_or_init(|| {
            self.peer_chain()
                .and_then(|chain| chain.first())
                .and_then(|c| PeerIdentity::from_der(c.as_ref()))
                .map(Box::new)
        })
        .as_deref()
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
    /// The snapshot the session was accepted under; `None` once the
    /// handshake has ended (D-146).
    state: Option<crate::sync::Shared<ServerState>>,
    slot: Option<CapacitySlot>,
    /// Boxed so an idle session does not carry a 254-byte name buffer (D-096).
    sni: Option<Box<str>>,
    fingerprint: Option<Fingerprint>,
    /// Built on first use from the client certificate; boxed (D-096, D-104).
    peer: OnceCell<Option<Box<PeerIdentity>>>,
    /// The host group's rules, checked again at completion.
    group: Option<HostGroup>,
    refusal: Option<HelloRefusal>,
    reported: bool,
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

impl Drop for ServerSession {
    fn drop(&mut self) {
        self.release();
    }
}

impl ServerSession {
    pub(crate) fn new(state: crate::sync::Shared<ServerState>, slot: CapacitySlot) -> Self {
        let max = state.limits.max_handshake_bytes;
        ServerSession {
            core: Core::new(None, SessionState::Hello, max),
            state: Some(state),
            slot: Some(slot),
            sni: None,
            fingerprint: None,
            peer: OnceCell::new(),
            group: None,
            refusal: None,
            reported: false,
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
        let before = self.core.state;
        let r = self.step_inner(input, output);
        let complete = matches!(&r, Ok(p) if p.event == Event::HandshakeComplete);
        self.observe(before, complete);
        r
    }

    /// Counters and events after a step. Once the handshake has ended, the
    /// session lets go of its configuration snapshot (D-146): nothing after
    /// it reads the snapshot, and holding it would keep every certificate and
    /// private key of an old configuration alive after a reload.
    fn observe(&mut self, before: SessionState, complete: bool) {
        let Some(state) = &self.state else {
            return;
        };
        let obs = &state.obs;
        if complete {
            // Without the peer identity, which is built on first use (D-104).
            if let Some(mut info) = self.core.info(self.sni.as_deref()) {
                info.fingerprint = self.fingerprint.as_ref();
                record_completion(obs, &info, &self.core);
            }
        }
        if self.core.state == SessionState::Failed && !self.reported {
            self.reported = true;
            if let Some(reason) = self.refusal {
                obs.refusals
                    .hello
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                obs.emit(&TlsEvent::HelloRefused {
                    tag: self.core.tag,
                    reason,
                });
            } else if matches!(before, SessionState::Hello | SessionState::Handshake) {
                record_failure(obs, &self.core, before);
            }
        }
        let ended = !matches!(
            self.core.state,
            SessionState::Hello | SessionState::Handshake
        );
        if ended && self.slot.is_none() {
            self.state = None;
        }
    }

    fn step_inner<'i>(
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
            let Some(state) = self.state.as_ref() else {
                return Err(self.core.fail(TlsError::Other));
            };
            match parse_client_hello(input, &state.hello_limits) {
                Ok(HelloParse::Incomplete { needed }) => {
                    self.core.hello_needed = needed;
                    return Ok(Progress {
                        consumed: 0,
                        written: 0,
                        event: Event::NeedInput,
                    });
                }
                Ok(HelloParse::Complete { view, .. }) => {
                    self.sni = view.normalized_server_name().map(|n| n.as_str().into());
                    let kinds = state.fingerprints;
                    let fingerprint = Fingerprint::compute(&view, kinds);
                    if let Some(hook) = &state.hook {
                        let ctx = HelloContext {
                            view: &view,
                            fingerprint: &fingerprint,
                            server_name: self.sni.as_deref(),
                            tag: self.core.tag,
                        };
                        if let HelloVerdict::Refuse(reason) = hook.on_client_hello(&ctx) {
                            // No alert: a scanner learns nothing (D-014).
                            self.refusal = Some(HelloRefusal::Hook(reason));
                            release(&mut self.slot, Some(state));
                            return Err(self.core.fail(TlsError::Refused(reason)));
                        }
                    }
                    if state.obs.sample() {
                        state.obs.emit(&TlsEvent::HelloCaptured {
                            tag: self.core.tag,
                            view: &view,
                            fingerprint: &fingerprint,
                        });
                    }
                    if kinds != crate::fingerprint::FingerprintKinds::NONE {
                        self.fingerprint = Some(fingerprint);
                    }
                    let Some(slot) = state.table.lookup(self.sni.as_deref()) else {
                        self.refusal = Some(HelloRefusal::UnknownName);
                        release(&mut self.slot, Some(state));
                        return self.core.refuse_unknown_name(output);
                    };
                    let group = state
                        .groups
                        .get(slot.group)
                        .copied()
                        .ok_or(TlsError::Other)?;
                    self.group = Some(group);
                    if group.alpn_required && !view.has_alpn() {
                        self.refusal = Some(HelloRefusal::AlpnRequired);
                        release(&mut self.slot, Some(state));
                        return self.core.refuse_no_alpn(output);
                    }
                    self.core.set_max_handshake_bytes(group.max_handshake_bytes);
                    let config = state
                        .configs
                        .get(slot.group)
                        .cloned()
                        .ok_or(TlsError::Other)?;
                    match UnbufferedServerConnection::new(config) {
                        Ok(conn) => self.core.set_conn(conn),
                        Err(e) => {
                            release(&mut self.slot, Some(state));
                            return Err(self.core.fail(error::from_rustls(&e)));
                        }
                    }
                }
                Err(e) if state.hello_limits.refuse_malformed || is_not_tls(&e) => {
                    self.refusal = Some(if e.code() == 32 {
                        HelloRefusal::OverBudget
                    } else {
                        HelloRefusal::Malformed
                    });
                    release(&mut self.slot, Some(state));
                    return Err(self.core.fail(e));
                }
                Err(e) => {
                    // refuse_malformed is off: rustls decides, without a
                    // fingerprint. Only where nothing else depends on the
                    // hello: with a hook, host groups, or a required ALPN the
                    // hello is refused as before (D-127).
                    let first = state.groups.first().copied();
                    let lenient = state.groups.len() == 1
                        && state.hook.is_none()
                        && first.is_some_and(|g| !g.alpn_required);
                    if !lenient {
                        self.refusal = Some(HelloRefusal::Malformed);
                        release(&mut self.slot, Some(state));
                        return Err(self.core.fail(e));
                    }
                    self.group = first;
                    let config = state.configs.first().cloned().ok_or(TlsError::Other)?;
                    let conn = UnbufferedServerConnection::new(config)
                        .map_err(|e| self.core.fail(error::from_rustls(&e)))?;
                    self.core.set_conn(conn);
                }
            }
        }
        let result = self.core.run(input, output);
        match &result {
            Ok(p) if p.event == Event::HandshakeComplete => {
                self.release();
                if let Err(e) = self.complete() {
                    return Err(self.core.fail(e));
                }
            }
            Err(_) => self.release(),
            _ if self.core.state == SessionState::Failed => self.release(),
            _ => {}
        }
        result
    }

    /// At completion: the group's rules again, then the client certificate's
    /// budgets. rustls checks ALPN on the first hello only, so a second hello
    /// after a HelloRetryRequest could drop it (D-127); and it does not ask
    /// for a certificate on resumption, so a resumed session is checked
    /// against the group's rules and its certificate's expiry (D-125).
    fn complete(&mut self) -> Result<(), TlsError> {
        if let Some(g) = self.group {
            if g.alpn_required && !self.core.alpn_negotiated() {
                return Err(TlsError::NoApplicationProtocol);
            }
            if self.core.resumed() {
                match self.core.peer_chain().and_then(|c| c.first()) {
                    None if g.auth_required => return Err(TlsError::PeerCertificateRequired),
                    None => {}
                    Some(cert) => {
                        let expired = crate::der::parse_certificate(cert.as_ref())
                            .is_none_or(|f| f.not_after <= crate::server::wall_clock());
                        if expired {
                            return Err(TlsError::PeerCertificateInvalid(
                                crate::error::CertificateProblem::Expired,
                            ));
                        }
                    }
                }
            }
        }
        let Some(state) = &self.state else {
            return Err(TlsError::Other);
        };
        let limits = state.limits;
        if let Some(chain) = self.core.peer_chain() {
            let too_large = chain.len() > usize::from(limits.max_peer_chain_len)
                || chain
                    .iter()
                    .any(|c| c.len() > limits.max_peer_cert_bytes as usize);
            if too_large {
                return Err(TlsError::PeerChainTooLarge);
            }
        }
        Ok(())
    }

    fn release(&mut self) {
        release(&mut self.slot, self.state.as_ref());
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
        let mut info = self.core.info(self.sni.as_deref())?;
        info.peer = self.core.peer_identity(&self.peer);
        info.fingerprint = self.fingerprint.as_ref();
        Some(info)
    }

    /// The ClientHello's fingerprints, once parsed (before the handshake completes).
    #[must_use]
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.fingerprint.as_ref()
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

    /// The TLS alert received, or sent, when the session failed. Sent alerts
    /// are known for tls-net's own refusals, a refused certificate, and a
    /// missing client certificate the server requires; for other failures
    /// rustls picks the alert without exposing it, and this is `None` (D-139).
    #[must_use]
    pub fn alert(&self) -> Option<u8> {
        self.core.alert()
    }
}

/// Gives back the handshake slot, if the session still holds one. A free
/// function, so the hello path can call it while it borrows the snapshot.
fn release(slot: &mut Option<CapacitySlot>, state: Option<&crate::sync::Shared<ServerState>>) {
    if let Some(state) = state {
        if let Some(slot) = slot.take() {
            state.capacity.release(slot);
        }
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
    /// Built on first use from the server's certificate (D-104).
    peer: OnceCell<Option<Box<PeerIdentity>>>,
    obs: std::sync::Arc<Observation>,
    reported: bool,
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
        obs: std::sync::Arc<Observation>,
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
            peer: OnceCell::new(),
            obs,
            reported: false,
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
        let before = self.core.state;
        let r = self.step_inner(input, output);
        if matches!(&r, Ok(p) if p.event == Event::HandshakeComplete) {
            // Without the peer identity, which is built on first use (D-104).
            if let Some(info) = self.core.info(Some(&self.server_name)) {
                record_completion(&self.obs, &info, &self.core);
            }
        }
        if self.core.state == SessionState::Failed && !self.reported {
            self.reported = true;
            if before == SessionState::Handshake {
                record_failure(&self.obs, &self.core, before);
            }
        }
        r
    }

    fn step_inner<'i>(
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
        let mut info = self.core.info(Some(&self.server_name))?;
        info.peer = self.core.peer_identity(&self.peer);
        Some(info)
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

    /// The TLS alert received, or sent, when the session failed. Sent alerts
    /// are known for tls-net's own refusals, a refused certificate, and a
    /// missing client certificate the server requires; for other failures
    /// rustls picks the alert without exposing it, and this is `None` (D-139).
    #[must_use]
    pub fn alert(&self) -> Option<u8> {
        self.core.alert()
    }
}

/// Counts and reports a completed handshake.
fn record_completion<C: Engine>(obs: &Observation, info: &HandshakeInfo<'_>, core: &Core<C>) {
    use std::sync::atomic::Ordering::Relaxed;
    let c = &obs.handshakes;
    match info.kind {
        HandshakeKind::Resumed => c.resumed.fetch_add(1, Relaxed),
        _ => c.full.fetch_add(1, Relaxed),
    };
    if info.version == crate::policy::Version::Tls12 {
        c.tls12.fetch_add(1, Relaxed);
    }
    if info
        .group
        .is_some_and(crate::policy::Group::is_post_quantum)
    {
        c.post_quantum.fetch_add(1, Relaxed);
    }
    obs.emit(&TlsEvent::HandshakeCompleted {
        tag: core.tag,
        version: info.version,
        cipher_suite: info.cipher_suite,
        group: info.group,
        alpn: info.alpn,
        server_name: info.server_name,
        kind: info.kind,
        duration: core.started.map(|t| t.elapsed()).unwrap_or_default(),
        peer_certificate: info.peer_verified,
        fingerprint: info.fingerprint,
    });
}

/// Counts and reports a failed handshake.
fn record_failure<C: Engine>(obs: &Observation, core: &Core<C>, stage: SessionState) {
    obs.handshakes
        .failed
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    obs.emit(&TlsEvent::HandshakeFailed {
        tag: core.tag,
        code: core.error_code().unwrap_or(0),
        alert: core.alert(),
        stage,
    });
}
