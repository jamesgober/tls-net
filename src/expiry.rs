//! Certificate expiry reports (FR-33, PLAN 6.7). Proportional thresholds keep
//! short-lived certificates from warning right after issuance.

use std::time::{Duration, SystemTime};

use crate::certs::CertificateEntry;
use crate::der::KeyAlg;

/// How close a certificate is to expiry.
///
/// ```
/// assert!(tls_net::ExpiryState::Warn < tls_net::ExpiryState::Critical);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExpiryState {
    /// More than the warning threshold left.
    Ok,
    /// Less than max(7 days, lifetime / 3) left.
    Warn,
    /// Less than max(2 days, lifetime / 10) left.
    Critical,
    /// At or after `not_after`.
    Expired,
}

/// A certificate's key type.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// ECDSA on P-256.
    EcdsaP256,
    /// ECDSA on P-384.
    EcdsaP384,
    /// Ed25519.
    Ed25519,
    /// RSA of this size.
    Rsa {
        /// Modulus size in bits.
        bits: u16,
    },
}

impl KeyType {
    pub(crate) fn from_alg(alg: KeyAlg) -> Option<KeyType> {
        Some(match alg {
            KeyAlg::EcdsaP256 => KeyType::EcdsaP256,
            KeyAlg::EcdsaP384 => KeyType::EcdsaP384,
            KeyAlg::Ed25519 => KeyType::Ed25519,
            KeyAlg::Rsa { bits } => KeyType::Rsa {
                bits: u16::try_from(bits).unwrap_or(u16::MAX),
            },
            _ => return None,
        })
    }
}

/// One loaded certificate.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateInfo {
    /// The names it serves.
    pub names: Vec<String>,
    /// Start of validity.
    pub not_before: SystemTime,
    /// End of validity.
    pub not_after: SystemTime,
    /// Whole days left; negative after expiry.
    pub days_remaining: i64,
    /// Its state.
    pub state: ExpiryState,
    /// Its key type.
    pub key_type: KeyType,
    /// SHA-256 of its SubjectPublicKeyInfo.
    pub spki_sha256: [u8; 32],
}

/// Every loaded certificate with its expiry state.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiryReport {
    /// One per certificate.
    pub entries: Vec<CertificateInfo>,
    /// The worst state of any entry (`Ok` when there are none).
    pub worst: ExpiryState,
}

const DAY: u64 = 86_400;

fn secs(d: Duration) -> u64 {
    d.as_secs()
}

/// The state of one certificate at `now`.
pub(crate) fn state_at(
    not_before: SystemTime,
    not_after: SystemTime,
    now: SystemTime,
) -> (ExpiryState, i64) {
    let Ok(left) = not_after.duration_since(now) else {
        let past = now.duration_since(not_after).map(secs).unwrap_or(0);
        return (
            ExpiryState::Expired,
            -i64::try_from(past.div_ceil(DAY)).unwrap_or(i64::MAX),
        );
    };
    let left = secs(left);
    if left == 0 {
        return (ExpiryState::Expired, 0);
    }
    let lifetime = not_after.duration_since(not_before).map(secs).unwrap_or(0);
    let warn = (7 * DAY).max(lifetime / 3);
    let critical = (2 * DAY).max(lifetime / 10);
    let state = if left < critical {
        ExpiryState::Critical
    } else if left < warn {
        ExpiryState::Warn
    } else {
        ExpiryState::Ok
    };
    (state, i64::try_from(left / DAY).unwrap_or(i64::MAX))
}

pub(crate) fn report(entries: &[CertificateEntry], now: SystemTime) -> ExpiryReport {
    let mut out = Vec::with_capacity(entries.len());
    let mut worst = ExpiryState::Ok;
    for e in entries {
        let (state, days_remaining) = state_at(e.not_before, e.not_after, now);
        worst = worst.max(state);
        out.push(CertificateInfo {
            names: e.names.iter().map(|n| n.to_string()).collect(),
            not_before: e.not_before,
            not_after: e.not_after,
            days_remaining,
            state,
            key_type: KeyType::from_alg(e.key).unwrap_or(KeyType::EcdsaP256),
            spki_sha256: e.spki_sha256,
        });
    }
    ExpiryReport {
        entries: out,
        worst,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(days: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(days * DAY)
    }

    #[test]
    fn test_thresholds_47_day_certificate() {
        // Issued at day 0, expires at day 47: warn below 15.67 days, critical below 4.7.
        let (nb, na) = (at(1000), at(1047));
        assert_eq!(state_at(nb, na, at(1001)).0, ExpiryState::Ok);
        assert_eq!(state_at(nb, na, at(1031)).0, ExpiryState::Ok);
        assert_eq!(state_at(nb, na, at(1032)).0, ExpiryState::Warn);
        assert_eq!(state_at(nb, na, at(1043)).0, ExpiryState::Critical);
        assert_eq!(state_at(nb, na, at(1047)), (ExpiryState::Expired, 0));
        assert_eq!(state_at(nb, na, at(1050)), (ExpiryState::Expired, -3));
    }

    #[test]
    fn test_thresholds_long_certificate_floor_at_7_and_2_days() {
        let (nb, na) = (at(0), at(3650));
        assert_eq!(
            state_at(nb, na, at(2500)).0,
            ExpiryState::Warn,
            "lifetime/3 dominates"
        );
        assert_eq!(
            state_at(nb, na, at(3600)).0,
            ExpiryState::Critical,
            "lifetime/10 dominates"
        );
        let (nb, na) = (at(0), at(15));
        assert_eq!(state_at(nb, na, at(7)).0, ExpiryState::Ok);
        assert_eq!(state_at(nb, na, at(9)).0, ExpiryState::Warn, "7-day floor");
        assert_eq!(
            state_at(nb, na, at(14)).0,
            ExpiryState::Critical,
            "2-day floor"
        );
    }
}
