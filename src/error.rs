//! `TlsError`: every failure tls-net reports, with a stable code, a category,
//! an action, and a public message that reveals nothing about keys or
//! configuration.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

/// Every failure tls-net reports.
///
/// Each variant has a stable code (`TLS-nnnn`, see [`TlsError::code`]), a
/// [`ErrorCategory`] that carries the retry rule, an [`Action`], and a
/// [`public_message`](TlsError::public_message) that is safe to show a remote
/// party. `Display` is the operator message: it may name a file or a
/// configured name, never key material, and bytes that came from the network
/// are escaped.
///
/// ```
/// let e = tls_net::TlsError::KeyMismatch;
/// assert_eq!(e.code(), 16);
/// assert_eq!(e.to_string(), "TLS-0016: the private key does not match the certificate");
/// assert_eq!(e.category(), tls_net::ErrorCategory::InvalidArgument);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsError {
    /// An unexpected failure inside rustls or its provider (`TLS-0000`).
    Other,
    /// This build has no crypto provider feature (`TLS-0001`).
    NoProvider,
    /// The configuration is inconsistent or out of range (`TLS-0002`).
    PolicyInvalid {
        /// What is wrong.
        reason: &'static str,
    },
    /// The policy needs post-quantum key exchange and the provider has none (`TLS-0003`).
    PostQuantumUnavailable,
    /// The policy needs FIPS mode and the build is not in FIPS mode (`TLS-0004`).
    FipsUnavailable,
    /// A certificate or key file could not be read (`TLS-0010`).
    Io {
        /// The file.
        path: PathBuf,
        /// The operating system's error kind.
        kind: io::ErrorKind,
    },
    /// A certificate or key input is larger than its budget (`TLS-0011`).
    FileTooLarge {
        /// The file, or empty for byte input.
        path: PathBuf,
        /// The budget in bytes.
        limit: u64,
    },
    /// A private key file is readable by group or others (`TLS-0012`).
    KeyFilePermissions {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// PEM or DER input is malformed (`TLS-0013`).
    PemInvalid {
        /// What could not be decoded.
        what: &'static str,
    },
    /// The chain input holds no certificate (`TLS-0014`).
    NoCertificate,
    /// The key input holds no private key (`TLS-0014`).
    NoPrivateKey,
    /// The key input holds more than one private key (`TLS-0014`).
    MultiplePrivateKeys,
    /// The private key is encrypted; decrypt it before loading (`TLS-0014`).
    EncryptedPrivateKey,
    /// The key algorithm is not supported by the provider or the policy (`TLS-0015`).
    UnsupportedKeyType,
    /// The key is too small (`TLS-0015`).
    WeakKey {
        /// Its size in bits.
        bits: u32,
    },
    /// The certificate is signed with SHA-1 or another refused algorithm (`TLS-0015`).
    WeakSignatureAlgorithm,
    /// A trust anchor could not be used (`TLS-0015`).
    BadAnchor,
    /// The private key does not match the end-entity certificate (`TLS-0016`).
    KeyMismatch,
    /// The certificate expired (`TLS-0017`).
    CertificateExpired {
        /// When it expired.
        not_after: SystemTime,
    },
    /// The certificate is not valid yet (`TLS-0017`).
    CertificateNotYetValid {
        /// When it becomes valid.
        not_before: SystemTime,
    },
    /// The certificate's extended key usage does not allow this use (`TLS-0017`).
    WrongPurpose,
    /// A configured name is not in the certificate's subject alternative names (`TLS-0018`).
    NameNotCovered {
        /// The name.
        name: Box<str>,
    },
    /// The same name is registered by two certificates of the same key type (`TLS-0018`).
    DuplicateName {
        /// The name.
        name: Box<str>,
    },
    /// A name is not a valid DNS name or IP address (`TLS-0018`).
    InvalidName {
        /// The name, escaped.
        name: Box<str>,
    },
    /// The chain has more certificates than allowed (`TLS-0019`).
    ChainTooLong {
        /// Certificates found.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// The chain is not in issuing order (`TLS-0019`).
    ChainOrder {
        /// Index of the first certificate not issued by the next one.
        position: usize,
    },
    /// The key from key-vault does not parse as a private key (`TLS-0020`).
    VaultKeyUnusable,
    /// key-vault refused the request (`TLS-0020`).
    Vault {
        /// What failed.
        kind: &'static str,
    },
    /// A reload was refused; the old configuration is still in use (`TLS-0021`).
    ReloadRefused {
        /// Why.
        source: Box<TlsError>,
    },
    /// The server is at its handshake capacity (`TLS-0030`).
    HandshakeCapacity,
    /// The ClientHello is malformed (`TLS-0031`).
    HelloMalformed,
    /// The first bytes are not a TLS handshake record (`TLS-0031`).
    NotTls,
    /// A TLS record header is invalid (`TLS-0031`).
    BadRecord,
    /// The ClientHello repeats an extension (`TLS-0031`).
    DuplicateExtension,
    /// The ClientHello is larger than its budget (`TLS-0032`).
    HelloTooLarge,
    /// The ClientHello is split over more records than allowed (`TLS-0032`).
    HelloTooFragmented,
    /// A list in the ClientHello is longer than its budget (`TLS-0032`).
    HelloOverBudget {
        /// Which list.
        what: &'static str,
    },
    /// The peer sent more handshake bytes than the budget (`TLS-0032`).
    HandshakeTooLarge,
    /// The peer's certificate chain is longer or larger than allowed (`TLS-0032`).
    PeerChainTooLarge,
    /// The hello hook refused the connection (`TLS-0033`).
    Refused(RefuseReason),
    /// The client asked for a name this server does not serve (`TLS-0034`).
    UnknownServerName,
    /// No protocol version in common (`TLS-0035`).
    NoCommonVersion,
    /// No cipher suite in common (`TLS-0035`).
    NoCommonCipherSuite,
    /// No key exchange group in common (`TLS-0035`).
    NoCommonGroup,
    /// No signature scheme in common (`TLS-0035`).
    NoCommonSignatureScheme,
    /// The TLS 1.2 peer does not offer extended master secret (`TLS-0035`).
    ExtendedMasterSecretRequired,
    /// No application protocol (ALPN) in common, or ALPN was required and absent (`TLS-0036`).
    NoApplicationProtocol,
    /// The peer's certificate was not accepted (`TLS-0037`).
    PeerCertificateInvalid(CertificateProblem),
    /// The peer sent no certificate where one is required (`TLS-0038`).
    PeerCertificateRequired,
    /// The peer's certificate is revoked (`TLS-0039`).
    PeerCertificateRevoked,
    /// The peer's key does not match any pin (`TLS-0040`).
    PinMismatch,
    /// The peer sent a fatal alert (`TLS-0041`).
    AlertReceived {
        /// The alert description code.
        alert: u8,
    },
    /// A record failed to decrypt (`TLS-0042`).
    DecryptFailed,
    /// The peer broke the protocol (`TLS-0042`).
    PeerMisbehaved,
    /// The transport ended without `close_notify` (`TLS-0043`).
    UncleanClose,
    /// The transport under a [`TlsStream`](crate::TlsStream) failed: a reset,
    /// a timeout, a refused write (`TLS-0047`).
    Transport {
        /// The operating system's error kind.
        kind: io::ErrorKind,
    },
    /// The traffic keys reached their usage limit; reconnect (`TLS-0044`).
    KeyUsageExhausted,
    /// Bytes arrived after the STARTTLS reply, before the handshake (`TLS-0045`).
    StartTlsInjection,
    /// The server refused early data (`TLS-0046`).
    EarlyDataRefused,
    /// The output buffer is too small (`TLS-0050`).
    OutputFull {
        /// Bytes needed.
        required: usize,
    },
    /// The call is not valid in the session's state (`TLS-0050`).
    WrongState,
    /// The session failed earlier (`TLS-0050`).
    SessionFailed,
}

/// The error-suite category of a [`TlsError`]: says whether and how to retry.
///
/// ```
/// assert_eq!(tls_net::TlsError::HandshakeCapacity.category(), tls_net::ErrorCategory::ResourceExhausted);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// The input or configuration is wrong; never retry as is.
    InvalidArgument,
    /// The system is not in a state that allows the operation.
    FailedPrecondition,
    /// A named thing does not exist.
    NotFound,
    /// Refused by policy.
    PermissionDenied,
    /// The peer's identity was not accepted.
    Unauthenticated,
    /// A budget or capacity was reached; retry later.
    ResourceExhausted,
    /// Temporarily unavailable; retry.
    Unavailable,
    /// The operation was cut off; retry at a higher level.
    Aborted,
    /// A defect or an unexpected failure.
    Internal,
}

/// What to do about a [`TlsError`].
///
/// ```
/// assert_eq!(tls_net::TlsError::KeyMismatch.action(), tls_net::Action::FixConfig);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Nothing: the peer or the input was at fault.
    None,
    /// Fix the configuration.
    FixConfig,
    /// Retry later.
    Retry,
    /// Retry only if the request is idempotent.
    RetryIdempotent,
    /// Retry without early data.
    RetryWithoutEarlyData,
    /// Tell an operator.
    Operator,
}

/// Why a peer's certificate was not accepted.
///
/// ```
/// let e = tls_net::TlsError::PeerCertificateInvalid(tls_net::CertificateProblem::Expired);
/// assert_eq!(e.code(), 37);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateProblem {
    /// It expired.
    Expired,
    /// It is not valid yet.
    NotYetValid,
    /// It does not chain to a trusted anchor.
    UnknownIssuer,
    /// A signature in the chain is invalid.
    BadSignature,
    /// It does not cover the expected name.
    NameMismatch,
    /// It has a critical extension that is not understood.
    UnhandledCriticalExtension,
    /// Its extended key usage does not allow this use.
    InvalidPurpose,
    /// It is malformed.
    BadEncoding,
    /// Revocation status could not be determined.
    UnknownRevocationStatus,
    /// Another reason.
    Other,
}

/// Why a hello hook refused a connection.
///
/// ```
/// let e = tls_net::TlsError::Refused(tls_net::RefuseReason::Banned);
/// assert_eq!(e.code(), 33);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefuseReason {
    /// The client is banned.
    Banned,
    /// The fingerprint is refused.
    Fingerprint,
    /// Another policy refused it.
    Policy,
    /// A reason the hook names.
    Other(&'static str),
}

impl TlsError {
    /// The stable code, shown as `TLS-nnnn`.
    ///
    /// ```
    /// assert_eq!(tls_net::TlsError::NoProvider.code(), 1);
    /// ```
    #[must_use]
    pub fn code(&self) -> u16 {
        use TlsError as E;
        match self {
            E::Other => 0,
            E::NoProvider => 1,
            E::PolicyInvalid { .. } => 2,
            E::PostQuantumUnavailable => 3,
            E::FipsUnavailable => 4,
            E::Io { .. } => 10,
            E::FileTooLarge { .. } => 11,
            E::KeyFilePermissions { .. } => 12,
            E::PemInvalid { .. } => 13,
            E::NoCertificate
            | E::NoPrivateKey
            | E::MultiplePrivateKeys
            | E::EncryptedPrivateKey => 14,
            E::UnsupportedKeyType
            | E::WeakKey { .. }
            | E::WeakSignatureAlgorithm
            | E::BadAnchor => 15,
            E::KeyMismatch => 16,
            E::CertificateExpired { .. } | E::CertificateNotYetValid { .. } | E::WrongPurpose => 17,
            E::NameNotCovered { .. } | E::DuplicateName { .. } | E::InvalidName { .. } => 18,
            E::ChainTooLong { .. } | E::ChainOrder { .. } => 19,
            E::VaultKeyUnusable | E::Vault { .. } => 20,
            E::ReloadRefused { .. } => 21,
            E::HandshakeCapacity => 30,
            E::HelloMalformed | E::NotTls | E::BadRecord | E::DuplicateExtension => 31,
            E::HelloTooLarge
            | E::HelloTooFragmented
            | E::HelloOverBudget { .. }
            | E::HandshakeTooLarge
            | E::PeerChainTooLarge => 32,
            E::Refused(_) => 33,
            E::UnknownServerName => 34,
            E::NoCommonVersion
            | E::NoCommonCipherSuite
            | E::NoCommonGroup
            | E::NoCommonSignatureScheme
            | E::ExtendedMasterSecretRequired => 35,
            E::NoApplicationProtocol => 36,
            E::PeerCertificateInvalid(_) => 37,
            E::PeerCertificateRequired => 38,
            E::PeerCertificateRevoked => 39,
            E::PinMismatch => 40,
            E::AlertReceived { .. } => 41,
            E::DecryptFailed | E::PeerMisbehaved => 42,
            E::UncleanClose => 43,
            E::KeyUsageExhausted => 44,
            E::StartTlsInjection => 45,
            E::EarlyDataRefused => 46,
            E::Transport { .. } => 47,
            E::OutputFull { .. } | E::WrongState | E::SessionFailed => 50,
        }
    }

    /// The error-suite category.
    #[must_use]
    pub fn category(&self) -> ErrorCategory {
        use ErrorCategory as C;
        match self.code() {
            0 => C::Internal,
            1 | 3 | 4 | 12 | 17 | 20 | 21 | 35 | 36 | 46 | 50 => C::FailedPrecondition,
            10 | 43 | 47 => C::Unavailable,
            30 | 32 => C::ResourceExhausted,
            33 | 45 => C::PermissionDenied,
            34 => C::NotFound,
            37..=40 => C::Unauthenticated,
            41 | 42 | 44 => C::Aborted,
            _ => C::InvalidArgument,
        }
    }

    /// What to do about it.
    #[must_use]
    pub fn action(&self) -> Action {
        match self.code() {
            0 | 40 | 45 => Action::Operator,
            1..=4 | 11..=21 => Action::FixConfig,
            10 | 30 | 41 | 44 => Action::Retry,
            43 | 47 => Action::RetryIdempotent,
            46 => Action::RetryWithoutEarlyData,
            _ => Action::None,
        }
    }

    /// A message safe to show a remote party or an end user.
    ///
    /// ```
    /// assert_eq!(tls_net::TlsError::HandshakeCapacity.public_message(), "Server is busy");
    /// ```
    #[must_use]
    pub fn public_message(&self) -> &'static str {
        match self.code() {
            1 => "TLS is not available in this build",
            2..=4 => "TLS configuration is invalid",
            10..=12 => "Certificate files could not be read",
            13 | 14 => "Certificate or key is malformed",
            15 | 16 => "Certificate or key is not allowed",
            17 => "Certificate is not valid now",
            18 | 19 => "Certificate does not cover the configured names",
            20 => "Key store error",
            21 => "New certificates were refused; the old ones are still in use",
            30 => "Server is busy",
            35 | 36 => "Client and server have no TLS settings in common",
            37..=40 => "Certificate was not accepted",
            43 | 44 => "Connection closed early",
            45 => "Mail server sent unexpected data",
            47 => "Connection failed",
            _ => "Secure connection failed",
        }
    }

    /// The bytes an `OutputFull` error needs; `None` for every other error.
    ///
    /// ```
    /// assert_eq!(tls_net::TlsError::OutputFull { required: 99 }.required(), Some(99));
    /// ```
    #[must_use]
    pub fn required(&self) -> Option<usize> {
        match self {
            TlsError::OutputFull { required } => Some(*required),
            _ => None,
        }
    }

    /// The four-digit code as shown in messages, for example `TLS-0016`.
    pub(crate) fn code_str(&self) -> CodeStr {
        CodeStr(self.code())
    }
}

pub(crate) struct CodeStr(u16);

impl fmt::Display for CodeStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS-{:04}", self.0)
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TlsError as E;
        write!(f, "{}: ", self.code_str())?;
        match self {
            E::Other => f.write_str("unexpected failure in the TLS library"),
            E::NoProvider => f.write_str("this build has no crypto provider (enable the aws-lc or ring feature)"),
            E::PolicyInvalid { reason } => write!(f, "invalid TLS configuration: {reason}"),
            E::PostQuantumUnavailable => {
                f.write_str("the policy requires post-quantum key exchange, which the crypto provider lacks")
            }
            E::FipsUnavailable => f.write_str("the policy requires FIPS mode, which this build does not provide"),
            E::Io { path, kind } => write!(f, "cannot read {}: {kind}", path.display()),
            E::FileTooLarge { path, limit } if path.as_os_str().is_empty() => {
                write!(f, "input is larger than its {limit}-byte budget")
            }
            E::FileTooLarge { path, limit } => {
                write!(f, "{} is larger than its {limit}-byte budget", path.display())
            }
            E::KeyFilePermissions { path, mode } => write!(
                f,
                "private key file {} is readable by group or others (mode {mode:04o}); use mode 0600",
                path.display()
            ),
            E::PemInvalid { what } => write!(f, "malformed {what}"),
            E::NoCertificate => f.write_str("no certificate found"),
            E::NoPrivateKey => f.write_str("no private key found"),
            E::MultiplePrivateKeys => f.write_str("more than one private key found; give exactly one"),
            E::EncryptedPrivateKey => f.write_str("the private key is encrypted; decrypt it before loading"),
            E::UnsupportedKeyType => f.write_str("unsupported key type"),
            E::WeakKey { bits } => write!(f, "key of {bits} bits is too small"),
            E::WeakSignatureAlgorithm => f.write_str("certificate signed with a refused algorithm (SHA-1 or older)"),
            E::BadAnchor => f.write_str("a trust anchor could not be used"),
            E::KeyMismatch => f.write_str("the private key does not match the certificate"),
            E::CertificateExpired { not_after } => write!(f, "certificate expired at {}", Rfc3339(*not_after)),
            E::CertificateNotYetValid { not_before } => {
                write!(f, "certificate is not valid before {}", Rfc3339(*not_before))
            }
            E::WrongPurpose => f.write_str("certificate's extended key usage does not allow this use"),
            E::NameNotCovered { name } => write!(f, "certificate does not cover the name {name}"),
            E::DuplicateName { name } => write!(f, "the name {name} is registered twice"),
            E::InvalidName { name } => write!(f, "invalid name {name}"),
            E::ChainTooLong { len, limit } => write!(f, "chain of {len} certificates exceeds the limit of {limit}"),
            E::ChainOrder { position } => {
                write!(f, "chain certificate {position} is not issued by the next one; put the chain in issuing order")
            }
            E::VaultKeyUnusable => f.write_str(
                "key from key-vault is not a private key; build the vault with normalize_with_blake3(false)",
            ),
            E::Vault { kind } => write!(f, "key-vault error: {kind}"),
            E::ReloadRefused { source } => write!(f, "reload refused, old configuration kept: {source}"),
            E::HandshakeCapacity => f.write_str("too many handshakes in progress"),
            E::HelloMalformed => f.write_str("malformed ClientHello"),
            E::NotTls => f.write_str("not a TLS connection"),
            E::BadRecord => f.write_str("invalid TLS record header"),
            E::DuplicateExtension => f.write_str("ClientHello repeats an extension"),
            E::HelloTooLarge => f.write_str("ClientHello larger than its budget"),
            E::HelloTooFragmented => f.write_str("ClientHello split over too many records"),
            E::HelloOverBudget { what } => write!(f, "ClientHello {what} list longer than its budget"),
            E::HandshakeTooLarge => f.write_str("peer sent more handshake bytes than the budget"),
            E::PeerChainTooLarge => f.write_str("peer certificate chain too long or too large"),
            E::Refused(reason) => write!(f, "connection refused by the hello hook ({reason:?})"),
            E::UnknownServerName => f.write_str("client asked for a name this server does not serve"),
            E::NoCommonVersion => f.write_str("no TLS version in common"),
            E::NoCommonCipherSuite => f.write_str("no cipher suite in common"),
            E::NoCommonGroup => f.write_str("no key exchange group in common"),
            E::NoCommonSignatureScheme => f.write_str("no signature scheme in common"),
            E::ExtendedMasterSecretRequired => f.write_str("TLS 1.2 peer does not support extended master secret"),
            E::NoApplicationProtocol => f.write_str("no application protocol (ALPN) in common"),
            E::PeerCertificateInvalid(problem) => write!(f, "peer certificate not accepted ({problem:?})"),
            E::PeerCertificateRequired => f.write_str("peer sent no certificate"),
            E::PeerCertificateRevoked => f.write_str("peer certificate is revoked"),
            E::PinMismatch => f.write_str("peer key matches no pin"),
            E::AlertReceived { alert } => write!(f, "peer sent alert {alert}"),
            E::DecryptFailed => f.write_str("record failed to decrypt"),
            E::PeerMisbehaved => f.write_str("peer broke the TLS protocol"),
            E::UncleanClose => f.write_str("connection closed without close_notify"),
            E::Transport { kind } => write!(f, "transport failed: {kind}"),
            E::KeyUsageExhausted => f.write_str("traffic keys reached their usage limit; reconnect"),
            E::StartTlsInjection => f.write_str("bytes arrived after the STARTTLS reply, before the handshake"),
            E::EarlyDataRefused => f.write_str("early data refused"),
            E::OutputFull { required } => write!(f, "output buffer too small; {required} bytes needed"),
            E::WrongState => f.write_str("call not valid in the session's state"),
            E::SessionFailed => f.write_str("the session failed earlier"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::ReloadRefused { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// A `SystemTime` shown as an RFC 3339 UTC timestamp (no allocation).
struct Rfc3339(SystemTime);

impl fmt::Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = match self.0.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
        };
        let (y, m, d) = crate::der::civil_from_days(secs.div_euclid(86_400));
        let rem = secs.rem_euclid(86_400);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    }
}

/// Maps a rustls error to a tls-net error. Detail stays out: the mapped
/// variant never carries rustls's strings.
pub(crate) fn from_rustls(e: &rustls::Error) -> TlsError {
    use rustls::{CertificateError as Ce, Error as R, PeerIncompatible as Pi};
    match e {
        R::InvalidCertificate(c) => match c {
            Ce::Revoked => TlsError::PeerCertificateRevoked,
            Ce::Expired | Ce::ExpiredContext { .. } => {
                TlsError::PeerCertificateInvalid(CertificateProblem::Expired)
            }
            Ce::NotValidYet | Ce::NotValidYetContext { .. } => {
                TlsError::PeerCertificateInvalid(CertificateProblem::NotYetValid)
            }
            Ce::UnknownIssuer => {
                TlsError::PeerCertificateInvalid(CertificateProblem::UnknownIssuer)
            }
            Ce::BadSignature => TlsError::PeerCertificateInvalid(CertificateProblem::BadSignature),
            Ce::NotValidForName | Ce::NotValidForNameContext { .. } => {
                TlsError::PeerCertificateInvalid(CertificateProblem::NameMismatch)
            }
            Ce::UnhandledCriticalExtension => {
                TlsError::PeerCertificateInvalid(CertificateProblem::UnhandledCriticalExtension)
            }
            Ce::InvalidPurpose | Ce::InvalidPurposeContext { .. } => {
                TlsError::PeerCertificateInvalid(CertificateProblem::InvalidPurpose)
            }
            Ce::BadEncoding => TlsError::PeerCertificateInvalid(CertificateProblem::BadEncoding),
            Ce::UnknownRevocationStatus => {
                TlsError::PeerCertificateInvalid(CertificateProblem::UnknownRevocationStatus)
            }
            Ce::Other(other) => crate::verify::pin_error(other)
                .unwrap_or(TlsError::PeerCertificateInvalid(CertificateProblem::Other)),
            _ => TlsError::PeerCertificateInvalid(CertificateProblem::Other),
        },
        R::NoCertificatesPresented => TlsError::PeerCertificateRequired,
        R::PeerIncompatible(p) => match p {
            Pi::NoCipherSuitesInCommon => TlsError::NoCommonCipherSuite,
            Pi::NoKxGroupsInCommon
            | Pi::KeyShareExtensionRequired
            | Pi::NamedGroupsExtensionRequired => TlsError::NoCommonGroup,
            Pi::NoSignatureSchemesInCommon
            | Pi::NoCertificateRequestSignatureSchemesInCommon
            | Pi::SignatureAlgorithmsExtensionRequired => TlsError::NoCommonSignatureScheme,
            Pi::ExtendedMasterSecretExtensionRequired => TlsError::ExtendedMasterSecretRequired,
            Pi::ServerDoesNotSupportTls12Or13
            | Pi::ServerTlsVersionIsDisabledByOurConfig
            | Pi::SupportedVersionsExtensionRequired
            | Pi::Tls12NotOffered
            | Pi::Tls12NotOfferedOrEnabled => TlsError::NoCommonVersion,
            _ => TlsError::PeerMisbehaved,
        },
        R::NoApplicationProtocol => TlsError::NoApplicationProtocol,
        R::AlertReceived(a) => TlsError::AlertReceived {
            alert: u8::from(*a),
        },
        R::DecryptError => TlsError::DecryptFailed,
        R::EncryptError => TlsError::KeyUsageExhausted,
        R::PeerMisbehaved(_)
        | R::InvalidMessage(_)
        | R::InappropriateMessage { .. }
        | R::InappropriateHandshakeMessage { .. }
        | R::PeerSentOversizedRecord
        | R::UnsupportedNameType => TlsError::PeerMisbehaved,
        R::InconsistentKeys(_) => TlsError::KeyMismatch,
        _ => TlsError::Other,
    }
}

/// Escapes bytes from the network for messages and events: printable ASCII
/// stays, everything else becomes `\xNN` (T-20).
pub(crate) fn escape(bytes: &[u8]) -> Box<str> {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if (0x20..0x7f).contains(&b) && b != b'\\' {
            s.push(char::from(b));
        } else {
            use fmt::Write as _;
            let _ = write!(s, "\\x{b:02x}");
        }
    }
    s.into_boxed_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_every_variant_has_category_action_and_message() {
        let all = [
            TlsError::Other,
            TlsError::NoProvider,
            TlsError::PolicyInvalid { reason: "x" },
            TlsError::Io {
                path: "a".into(),
                kind: io::ErrorKind::NotFound,
            },
            TlsError::KeyMismatch,
            TlsError::HandshakeCapacity,
            TlsError::UnknownServerName,
            TlsError::PinMismatch,
            TlsError::UncleanClose,
            TlsError::Transport {
                kind: io::ErrorKind::ConnectionReset,
            },
            TlsError::OutputFull { required: 1 },
        ];
        for e in &all {
            assert!(e.to_string().starts_with(&format!("TLS-{:04}: ", e.code())));
            assert!(!e.public_message().is_empty());
            let _ = (e.category(), e.action());
        }
    }

    #[test]
    fn test_category_retry_rules_match_table() {
        assert_eq!(
            TlsError::HandshakeCapacity.category(),
            ErrorCategory::ResourceExhausted
        );
        assert_eq!(TlsError::HandshakeCapacity.action(), Action::Retry);
        assert_eq!(TlsError::UncleanClose.action(), Action::RetryIdempotent);
        let reset = TlsError::Transport {
            kind: io::ErrorKind::ConnectionReset,
        };
        assert_eq!(reset.action(), Action::RetryIdempotent);
        assert_eq!(reset.category(), ErrorCategory::Unavailable);
        assert_eq!(reset.public_message(), "Connection failed");
        assert_eq!(
            TlsError::UnknownServerName.category(),
            ErrorCategory::NotFound
        );
        assert_eq!(TlsError::PinMismatch.action(), Action::Operator);
        assert_eq!(TlsError::Other.category(), ErrorCategory::Internal);
        assert_eq!(
            TlsError::NoCommonGroup.category(),
            ErrorCategory::FailedPrecondition
        );
    }

    #[test]
    fn test_display_time_rfc3339() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600);
        let e = TlsError::CertificateExpired { not_after: t };
        assert_eq!(
            e.to_string(),
            "TLS-0017: certificate expired at 2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn test_escape_control_bytes_escaped() {
        assert_eq!(&*escape(b"a\r\n\x1b[0m\\"), "a\\x0d\\x0a\\x1b[0m\\x5c");
    }

    #[test]
    fn test_reload_refused_has_source() {
        use std::error::Error as _;
        let e = TlsError::ReloadRefused {
            source: Box::new(TlsError::KeyMismatch),
        };
        assert_eq!(
            e.source().map(ToString::to_string).as_deref(),
            Some("TLS-0016: the private key does not match the certificate")
        );
    }

    #[test]
    fn test_from_rustls_maps_alert_and_decrypt() {
        let e = from_rustls(&rustls::Error::AlertReceived(
            rustls::AlertDescription::HandshakeFailure,
        ));
        assert_eq!(e, TlsError::AlertReceived { alert: 40 });
        assert_eq!(
            from_rustls(&rustls::Error::DecryptError),
            TlsError::DecryptFailed
        );
        assert_eq!(
            from_rustls(&rustls::Error::NoApplicationProtocol),
            TlsError::NoApplicationProtocol
        );
    }
}
