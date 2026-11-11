//! net-io's TLS seam over tls-net's sessions (feature `net-io`): type
//! conversions only, no extra state, no allocation (D-023, D-036).

use net_io::{
    ConnectionInfo, TlsAcceptor, TlsCloseKind, TlsEvent, TlsFailure, TlsInfo, TlsProgress,
    TlsSession,
};

use crate::error::TlsError;
use crate::identity::HandshakeInfo;
use crate::server::TlsServer;
use crate::session::{ClientSession, CloseKind, Event, Progress, ServerSession};

fn failure(e: &TlsError) -> TlsFailure {
    use TlsError as E;
    match e {
        E::Refused(_) => TlsFailure::HelloRefused,
        E::HandshakeCapacity => TlsFailure::Capacity,
        E::OutputFull { .. } => TlsFailure::OutputFull,
        E::WrongState | E::SessionFailed => TlsFailure::State,
        E::PeerMisbehaved
        | E::DecryptFailed
        | E::HelloMalformed
        | E::NotTls
        | E::BadRecord
        | E::DuplicateExtension
        | E::HelloTooLarge
        | E::HelloTooFragmented
        | E::HelloOverBudget { .. }
        | E::HandshakeTooLarge
        | E::PeerChainTooLarge
        | E::UncleanClose
        | E::Transport { .. } => TlsFailure::Protocol,
        _ => TlsFailure::Handshake,
    }
}

fn convert(e: &TlsError, alert: Option<u8>) -> net_io::TlsError {
    net_io::TlsError::new(failure(e), e.code(), alert)
}

fn progress(p: Progress<'_>) -> TlsProgress<'_> {
    let event = match p.event {
        Event::NeedInput => TlsEvent::NeedInput,
        Event::Transmit => TlsEvent::Transmit,
        Event::HandshakeComplete => TlsEvent::HandshakeComplete,
        Event::Data(d) => TlsEvent::Data(d),
        Event::OutputFull => TlsEvent::OutputFull,
        Event::PeerClosed => TlsEvent::PeerClosed,
        Event::Closed => TlsEvent::Closed,
    };
    TlsProgress {
        consumed: p.consumed,
        written: p.written,
        event,
    }
}

fn info(i: Option<HandshakeInfo<'_>>) -> Option<TlsInfo> {
    let i = i?;
    let (version, suite) = (i.version.wire(), i.cipher_suite.wire());
    // net-io keeps at most 32 bytes of ALPN; a longer name is reported as absent.
    let t = TlsInfo::new(i.server_name, i.alpn, version, suite)
        .or_else(|| TlsInfo::new(i.server_name, None, version, suite))?;
    // A peer identity exists only for a certificate rustls verified (the chain,
    // or a pin), so the hash net-io carries is never from unverified bytes.
    Some(match i.peer {
        Some(p) => t.with_peer_spki_sha256(p.spki_sha256),
        None => t,
    })
}

fn close_kind(k: CloseKind) -> TlsCloseKind {
    match k {
        CloseKind::Clean => TlsCloseKind::Clean,
        CloseKind::Unclean => TlsCloseKind::Unclean,
    }
}

impl TlsAcceptor for TlsServer {
    type Session = ServerSession;

    fn session(&self, _info: &ConnectionInfo) -> Result<ServerSession, net_io::TlsError> {
        self.accept().map_err(|e| convert(&e, None))
    }
}

macro_rules! seam_session {
    ($t:ty) => {
        impl TlsSession for $t {
            fn step<'i>(
                &mut self,
                input: &'i mut [u8],
                output: &mut [u8],
            ) -> Result<TlsProgress<'i>, net_io::TlsError> {
                match <$t>::step(self, input, output) {
                    Ok(p) => Ok(progress(p)),
                    Err(e) => Err(convert(&e, self.alert())),
                }
            }

            fn encrypt(
                &mut self,
                plaintext: &[u8],
                output: &mut [u8],
            ) -> Result<usize, net_io::TlsError> {
                <$t>::encrypt(self, plaintext, output).map_err(|e| convert(&e, None))
            }

            fn close(&mut self, output: &mut [u8]) -> Result<usize, net_io::TlsError> {
                <$t>::close(self, output).map_err(|e| convert(&e, None))
            }

            fn on_transport_closed(&mut self) -> TlsCloseKind {
                close_kind(self.on_eof())
            }

            fn info(&self) -> Option<TlsInfo> {
                info(<$t>::info(self))
            }

            fn input_capacity_required(&self) -> usize {
                <$t>::input_capacity_required(self)
            }
        }
    };
}

seam_session!(ServerSession);
seam_session!(ClientSession);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_kinds() {
        assert_eq!(
            failure(&TlsError::Refused(crate::RefuseReason::Banned)),
            TlsFailure::HelloRefused
        );
        assert_eq!(failure(&TlsError::HandshakeCapacity), TlsFailure::Capacity);
        assert_eq!(failure(&TlsError::NotTls), TlsFailure::Protocol);
        assert_eq!(failure(&TlsError::NoCommonGroup), TlsFailure::Handshake);
        let e = convert(&TlsError::UnknownServerName, Some(112));
        assert_eq!((e.code, e.alert), (34, Some(112)));
    }
}
