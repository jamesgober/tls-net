//! Handshake budgets (FR-46, FR-47, PLAN 6.13).

use crate::error::TlsError;

/// Budgets for handshakes: how many may run at once (server), how many bytes
/// the peer may send before the handshake completes, and the size of the
/// peer's certificate chain.
///
/// ```
/// let limits = tls_net::HandshakeLimits::server().max_in_progress(64)?;
/// assert_eq!(limits.max_in_progress, 64);
/// assert!(tls_net::HandshakeLimits::server().max_handshake_bytes(10).is_err());
/// # Ok::<(), tls_net::TlsError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeLimits {
    /// Handshakes in progress per server (server default 1,024).
    pub max_in_progress: u32,
    /// Inbound bytes before the handshake completes (server 32 KiB, client 128 KiB).
    pub max_handshake_bytes: u32,
    /// Most certificates in the peer's chain (server side 5, client side 10).
    pub max_peer_chain_len: u8,
    /// Largest certificate in the peer's chain (server side 16 KiB, client side 32 KiB).
    pub max_peer_cert_bytes: u32,
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        HandshakeLimits::server()
    }
}

impl HandshakeLimits {
    /// The server defaults.
    #[must_use]
    pub const fn server() -> Self {
        HandshakeLimits {
            max_in_progress: 1024,
            max_handshake_bytes: 32 << 10,
            max_peer_chain_len: 5,
            max_peer_cert_bytes: 16 << 10,
        }
    }

    /// The client defaults.
    #[must_use]
    pub const fn client() -> Self {
        HandshakeLimits {
            max_in_progress: 1024,
            max_handshake_bytes: 128 << 10,
            max_peer_chain_len: 10,
            max_peer_cert_bytes: 32 << 10,
        }
    }

    /// Handshakes in progress; 0 refuses every new session (for a drain).
    ///
    /// # Errors
    ///
    /// Never; returns `Result` for symmetry with the other setters.
    pub fn max_in_progress(mut self, n: u32) -> Result<Self, TlsError> {
        self.max_in_progress = n;
        Ok(self)
    }

    /// Inbound handshake bytes, 4 KiB to 1 MiB.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` outside the range.
    pub fn max_handshake_bytes(mut self, n: u32) -> Result<Self, TlsError> {
        if !(4 << 10..=1 << 20).contains(&n) {
            return Err(TlsError::PolicyInvalid {
                reason: "max_handshake_bytes must be 4 KiB to 1 MiB",
            });
        }
        self.max_handshake_bytes = n;
        Ok(self)
    }

    /// Certificates in the peer's chain, 1 to 16.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` outside the range.
    pub fn max_peer_chain_len(mut self, n: u8) -> Result<Self, TlsError> {
        if !(1..=16).contains(&n) {
            return Err(TlsError::PolicyInvalid {
                reason: "max_peer_chain_len must be 1 to 16",
            });
        }
        self.max_peer_chain_len = n;
        Ok(self)
    }

    /// Largest peer certificate, 1 KiB to 64 KiB.
    ///
    /// # Errors
    ///
    /// `PolicyInvalid` outside the range.
    pub fn max_peer_cert_bytes(mut self, n: u32) -> Result<Self, TlsError> {
        if !(1 << 10..=64 << 10).contains(&n) {
            return Err(TlsError::PolicyInvalid {
                reason: "max_peer_cert_bytes must be 1 KiB to 64 KiB",
            });
        }
        self.max_peer_cert_bytes = n;
        Ok(self)
    }
}
