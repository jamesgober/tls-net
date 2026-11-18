//! `TlsStream`: a session over any blocking `Read + Write` (Tier 1, D-141).
//!
//! The session stays sans-IO; this is the loop every blocking caller would
//! otherwise write around `step`: read ciphertext when the session needs
//! it, send what it writes, and hand plaintext out through `Read`.

use std::fmt;
use std::io::{self, Read, Write};

use crate::error::TlsError;
use crate::identity::HandshakeInfo;
use crate::session::{
    ClientSession, CloseKind, Event, MAX_RECORD_PAYLOAD, MIN_OUTPUT_BUFFER, ServerSession,
    SessionState,
};

/// Either session kind, so `TlsStream` has one type parameter: the transport.
enum Side {
    Server(ServerSession),
    Client(ClientSession),
}

macro_rules! side {
    ($self:expr, $s:ident => $e:expr) => {
        match $self {
            Side::Server($s) => $e,
            Side::Client($s) => $e,
        }
    };
}

/// A TLS connection over a blocking transport, usually a `TcpStream`.
/// Reads return plaintext; writes encrypt.
///
/// `read` returns `Ok(0)` only after the peer's `close_notify`. A transport
/// that ends without it is an `UnexpectedEof` error carrying
/// [`TlsError::UncleanClose`], so a truncated response never looks complete
/// (T-17). Errors from TLS come back as `io::Error`s whose inner error is the
/// [`TlsError`] (`e.get_ref()` and `downcast_ref`).
///
/// For blocking transports, with or without timeouts. A write that fails
/// part way leaves the connection unusable, and every later call fails.
/// Servers on net-io do not need this: net-io drives the session itself.
///
/// Cost: one input buffer of [`MIN_INPUT_BUFFER`](crate::MIN_INPUT_BUFFER)
/// (it grows for a hello or a certificate chain larger than one record), one
/// output buffer of [`MIN_OUTPUT_BUFFER`], and one extra copy of each record's
/// plaintext when the caller's buffer is smaller than the record.
///
/// ```no_run
/// use std::io::{Read, Write};
/// # #[cfg(feature = "webpki-roots")] {
/// let tcp = std::net::TcpStream::connect("example.com:443")?;
/// let mut tls = tls_net::client()?.connect_stream("example.com", tcp)?;
/// tls.write_all(b"GET / HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n")?;
/// let mut page = Vec::new();
/// tls.read_to_end(&mut page)?;
/// # }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct TlsStream<S> {
    io: S,
    side: Side,
    input: Vec<u8>,
    filled: usize,
    output: Vec<u8>,
    /// Plaintext of the last record that did not fit the caller's buffer.
    plain: Vec<u8>,
    plain_at: usize,
    /// The peer sent `close_notify`.
    peer_closed: bool,
    /// The transport reported its end.
    ended: bool,
    /// A write to the transport failed part way, or the session failed.
    broken: bool,
}

impl<S> fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = side!(&self.side, s => s.state());
        f.debug_struct("TlsStream")
            .field("state", &state)
            .field("peer_closed", &self.peer_closed)
            .finish_non_exhaustive()
    }
}

/// What one turn of the session produced.
enum Turn {
    Progress,
    Data,
    PeerClosed,
}

impl<S: Read + Write> TlsStream<S> {
    /// Runs a client session's handshake over `io`. For a session from
    /// [`TlsClient::connect_to`](crate::TlsClient::connect_to) or
    /// [`TlsClient::start_after_plaintext`](crate::TlsClient::start_after_plaintext);
    /// [`TlsClient::connect_stream`](crate::TlsClient::connect_stream) does
    /// both steps for a name.
    ///
    /// # Errors
    ///
    /// The handshake's error, `Transport` when the transport fails, or
    /// `UncleanClose` when it ends first.
    pub fn client(session: ClientSession, io: S) -> Result<TlsStream<S>, TlsError> {
        TlsStream::start(Side::Client(session), io)
    }

    /// Runs a server session's handshake over `io`. For a session from
    /// [`WorkerAcceptor::accept`](crate::WorkerAcceptor::accept);
    /// [`TlsServer::accept_stream`](crate::TlsServer::accept_stream) does
    /// both steps.
    ///
    /// # Errors
    ///
    /// As [`client`](Self::client).
    pub fn server(session: ServerSession, io: S) -> Result<TlsStream<S>, TlsError> {
        TlsStream::start(Side::Server(session), io)
    }

    fn start(side: Side, io: S) -> Result<TlsStream<S>, TlsError> {
        let input = vec![0; side!(&side, s => s.input_capacity_required())];
        let mut stream = TlsStream {
            io,
            side,
            input,
            filled: 0,
            output: vec![0; MIN_OUTPUT_BUFFER],
            plain: Vec::new(),
            plain_at: 0,
            peer_closed: false,
            ended: false,
            broken: false,
        };
        while side!(&stream.side, s => s.info()).is_none() {
            match stream.turn() {
                Ok(Turn::Progress) => {}
                // Plaintext or close_notify with the last flight waits for `read`.
                Ok(Turn::Data) => {}
                Ok(Turn::PeerClosed) => {}
                Err(e) => return Err(tls_error(e)),
            }
            // close_notify before the handshake finished: it never will.
            if stream.peer_closed && side!(&stream.side, s => s.info()).is_none() {
                return Err(TlsError::UncleanClose);
            }
        }
        Ok(stream)
    }

    /// The handshake's facts: version, cipher suite, ALPN, the peer.
    #[must_use]
    pub fn info(&self) -> Option<HandshakeInfo<'_>> {
        side!(&self.side, s => s.info())
    }

    /// Sends `close_notify`, so the peer's read ends cleanly. Does not wait
    /// for the peer's; reading after this still works until it arrives.
    /// Closing twice does nothing.
    ///
    /// # Errors
    ///
    /// `WrongState` on a failed session; `Transport` when the send fails.
    pub fn close(&mut self) -> Result<(), TlsError> {
        self.usable().map_err(tls_error)?;
        let n = side!(&mut self.side, s => s.close(&mut self.output))?;
        self.send(n).map_err(tls_error)?;
        self.io.flush().map_err(transport)
    }

    /// The transport.
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// The transport. Reading or writing it directly corrupts the TLS stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// The transport, ending the TLS stream without `close_notify` (call
    /// [`close`](Self::close) first for a clean end).
    pub fn into_inner(self) -> S {
        self.io
    }

    fn usable(&self) -> io::Result<()> {
        if self.broken {
            return Err(to_io(TlsError::WrongState));
        }
        Ok(())
    }

    /// Sends the first `n` bytes of the output, all of them.
    fn send(&mut self, n: usize) -> io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        if let Err(e) = self.io.write_all(&self.output[..n]) {
            self.broken = true;
            return Err(e);
        }
        Ok(())
    }

    /// One `step`, with the transport I/O it asks for.
    fn turn(&mut self) -> io::Result<Turn> {
        self.usable()?;
        let p = match side!(&mut self.side, s => s.step(&mut self.input[..self.filled], &mut self.output))
        {
            Ok(p) => p,
            Err(e) => {
                self.broken = true;
                return Err(to_io(e));
            }
        };
        let (consumed, written) = (p.consumed, p.written);
        let mut turn = Turn::Progress;
        let mut need = false;
        match p.event {
            Event::Data(d) => {
                self.plain.clear();
                self.plain.extend_from_slice(d);
                self.plain_at = 0;
                turn = Turn::Data;
            }
            Event::NeedInput => need = true,
            Event::PeerClosed | Event::Closed => {
                self.peer_closed = true;
                turn = Turn::PeerClosed;
            }
            Event::OutputFull if written == 0 => {
                self.broken = true;
                return Err(to_io(TlsError::OutputFull {
                    required: MIN_OUTPUT_BUFFER,
                }));
            }
            _ => {}
        }
        self.send(written)?;
        self.input.copy_within(consumed..self.filled, 0);
        self.filled -= consumed;
        if need && written == 0 && consumed == 0 {
            self.fill()?;
        }
        Ok(turn)
    }

    /// Reads more ciphertext from the transport. After the transport ended,
    /// a session that still needs input cannot progress.
    fn fill(&mut self) -> io::Result<()> {
        if self.ended {
            self.broken = true;
            return Err(to_io(TlsError::UncleanClose));
        }
        let want = side!(&self.side, s => s.input_capacity_required()).max(self.filled + 1);
        if self.input.len() < want {
            self.input.resize(want, 0);
        }
        let n = self.io.read(&mut self.input[self.filled..])?;
        if n == 0 {
            self.ended = true;
            if side!(&mut self.side, s => s.on_eof()) == CloseKind::Clean {
                self.peer_closed = true;
                return Ok(());
            }
            self.broken = true;
            return Err(to_io(TlsError::UncleanClose));
        }
        self.filled += n;
        Ok(())
    }

    /// Copies held plaintext into `buf`.
    fn take_plain(&mut self, buf: &mut [u8]) -> usize {
        let rest = &self.plain[self.plain_at..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.plain_at += n;
        n
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.plain_at < self.plain.len() {
                return Ok(self.take_plain(buf));
            }
            if self.peer_closed {
                return Ok(0);
            }
            self.turn()?;
        }
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    /// Encrypts up to one record of `buf` and sends it.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.usable()?;
        if buf.is_empty() {
            return Ok(0);
        }
        let part = &buf[..buf.len().min(MAX_RECORD_PAYLOAD)];
        loop {
            match side!(&mut self.side, s => s.encrypt(part, &mut self.output)) {
                Ok(n) => {
                    self.send(n)?;
                    return Ok(part.len());
                }
                // Records the session queued, or part of a post-handshake
                // message, go through `step` first (D-126, D-129).
                Err(TlsError::WrongState)
                    if matches!(
                        side!(&self.side, s => s.state()),
                        SessionState::Established | SessionState::HalfClosed
                    ) =>
                {
                    self.turn()?;
                }
                Err(e) => return Err(to_io(e)),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

/// A `TlsError` as an `io::Error` whose inner error is the `TlsError`.
fn to_io(e: TlsError) -> io::Error {
    let kind = match &e {
        TlsError::UncleanClose => io::ErrorKind::UnexpectedEof,
        TlsError::Transport { kind } => *kind,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, e)
}

/// The `TlsError` inside an `io::Error`, or the transport's error kind.
fn tls_error(e: io::Error) -> TlsError {
    match e.get_ref().and_then(|i| i.downcast_ref::<TlsError>()) {
        Some(t) => t.clone(),
        None => transport(e),
    }
}

fn transport(e: io::Error) -> TlsError {
    TlsError::Transport { kind: e.kind() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_io_kinds_and_round_trip() {
        let e = to_io(TlsError::UncleanClose);
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(tls_error(e), TlsError::UncleanClose);
        let e = to_io(TlsError::PinMismatch);
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(tls_error(e), TlsError::PinMismatch);
        let e = io::Error::from(io::ErrorKind::TimedOut);
        assert_eq!(
            tls_error(e),
            TlsError::Transport {
                kind: io::ErrorKind::TimedOut
            }
        );
        let e = to_io(TlsError::Transport {
            kind: io::ErrorKind::BrokenPipe,
        });
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }
}
