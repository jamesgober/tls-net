//! The hello hook (FR-40): the connection gate's look at the ClientHello and
//! its fingerprints before the handshake continues.

use crate::error::RefuseReason;
use crate::fingerprint::Fingerprint;
use crate::hello::ClientHelloView;

/// Decides whether a connection continues after its ClientHello. Runs
/// synchronously inside `step`, before the rustls connection exists: it must
/// be a lookup, never I/O.
///
/// ```
/// use tls_net::{HelloContext, HelloHook, HelloVerdict, RefuseReason};
/// struct NoSni;
/// impl HelloHook for NoSni {
///     fn on_client_hello(&self, ctx: &HelloContext<'_>) -> HelloVerdict {
///         if ctx.server_name.is_none() { HelloVerdict::Refuse(RefuseReason::Policy) } else { HelloVerdict::Continue }
///     }
/// }
/// ```
pub trait HelloHook: Send + Sync + 'static {
    /// The verdict for one ClientHello.
    fn on_client_hello(&self, ctx: &HelloContext<'_>) -> HelloVerdict;
}

/// What the hook sees.
#[non_exhaustive]
pub struct HelloContext<'a> {
    /// The parsed ClientHello.
    pub view: &'a ClientHelloView<'a>,
    /// Its fingerprints (the kinds the server enables).
    pub fingerprint: &'a Fingerprint,
    /// The normalised SNI.
    pub server_name: Option<&'a str>,
    /// The session's tag (for example a connection id).
    pub tag: u64,
}

/// The hook's answer.
///
/// ```
/// assert_ne!(tls_net::HelloVerdict::Continue, tls_net::HelloVerdict::Refuse(tls_net::RefuseReason::Banned));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloVerdict {
    /// Go on with the handshake.
    Continue,
    /// Close without an alert (D-014); the session fails with `Refused`.
    Refuse(RefuseReason),
}
