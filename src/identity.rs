//! What a completed handshake negotiated.

use crate::policy::{CipherSuite, Group, Version};

/// How the handshake ran.
///
/// ```
/// assert_ne!(tls_net::HandshakeKind::Full, tls_net::HandshakeKind::Resumed);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeKind {
    /// A full handshake.
    Full,
    /// A full handshake after a HelloRetryRequest (the client had no key
    /// share for the group the server picked).
    FullWithHelloRetry,
    /// A resumed session.
    Resumed,
}

/// The results of a completed handshake, borrowed from the session.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeInfo<'s> {
    /// The protocol version.
    pub version: Version,
    /// The cipher suite.
    pub cipher_suite: CipherSuite,
    /// The key exchange group; `None` for a TLS 1.2 resumption.
    pub group: Option<Group>,
    /// The application protocol (ALPN), if one was negotiated.
    pub alpn: Option<&'s [u8]>,
    /// Server side: the normalised SNI. Client side: the name connected to.
    pub server_name: Option<&'s str>,
    /// Full, full after a retry, or resumed.
    pub kind: HandshakeKind,
    /// Always `false` until early data (P3) exists.
    pub early_data_accepted: bool,
}

impl<'s> HandshakeInfo<'s> {
    pub(crate) fn new(
        version: Version,
        cipher_suite: CipherSuite,
        group: Option<Group>,
        alpn: Option<&'s [u8]>,
        server_name: Option<&'s str>,
        kind: HandshakeKind,
    ) -> Self {
        HandshakeInfo {
            version,
            cipher_suite,
            group,
            alpn,
            server_name,
            kind,
            early_data_accepted: false,
        }
    }
}
