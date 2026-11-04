//! Server names: normalisation (FR-17), SAN coverage (RFC 9525), the SNI
//! table, and the per-group certificate resolver rustls calls (D-032).

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{SignatureAlgorithm, SignatureScheme as RustlsScheme};

/// The longest DNS name, without a trailing dot (RFC 1035).
pub(crate) const MAX_NAME: usize = 253;

/// A server name after normalisation: ASCII lowercase, one trailing dot
/// removed, letters, digits, `-` and `.` only, labels of 1 to 63 bytes, and
/// not an IP literal. Held inline, so normalising allocates nothing.
///
/// ```
/// let n = tls_net::normalize_server_name("WWW.Example.COM.").unwrap();
/// assert_eq!(n.as_str(), "www.example.com");
/// assert!(tls_net::normalize_server_name("127.0.0.1").is_none());
/// assert!(tls_net::normalize_server_name("a\r\nb").is_none());
/// ```
#[derive(Clone, Copy)]
pub struct NormalizedName {
    buf: [u8; MAX_NAME],
    len: u8,
}

impl NormalizedName {
    /// The normalised name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only ASCII bytes are ever stored.
        std::str::from_utf8(&self.buf[..usize::from(self.len)]).unwrap_or("")
    }

    /// Normalises bytes as they arrive in a ClientHello, which may sit in
    /// several records (`chunks` are read in order).
    pub(crate) fn from_chunks<'a>(
        len: usize,
        chunks: impl Iterator<Item = &'a u8>,
    ) -> Option<NormalizedName> {
        if len == 0 || len > MAX_NAME + 1 {
            return None;
        }
        let mut buf = [0u8; MAX_NAME + 1];
        let mut n = 0;
        for &b in chunks.take(len) {
            buf[n] = b.to_ascii_lowercase();
            n += 1;
        }
        if n != len {
            return None;
        }
        finish(&buf[..n], false)
    }
}

impl PartialEq for NormalizedName {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for NormalizedName {}

impl fmt::Debug for NormalizedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for NormalizedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalises a server name by the rule tls-net applies to SNI (FR-17):
/// ASCII lowercase, one trailing dot removed; `None` for an IP literal, an
/// empty or over-long name, a label outside 1 to 63 bytes, or any byte other
/// than letters, digits, `-`, and `.`.
#[must_use]
pub fn normalize_server_name(name: &str) -> Option<NormalizedName> {
    NormalizedName::from_chunks(name.len(), name.as_bytes().iter())
}

/// Validates a lowercase name; `wildcard` allows a leading `*.` label.
fn finish(bytes: &[u8], wildcard: bool) -> Option<NormalizedName> {
    let bytes = bytes.strip_suffix(b".").unwrap_or(bytes);
    if bytes.is_empty() || bytes.len() > MAX_NAME {
        return None;
    }
    let body = match bytes.strip_prefix(b"*.") {
        Some(rest) if wildcard => rest,
        _ => bytes,
    };
    if body.is_empty() {
        return None;
    }
    let mut last_all_digits = false;
    for label in body.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.first() == Some(&b'-') || label.last() == Some(&b'-') {
            return None;
        }
        if !label
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return None;
        }
        last_all_digits = label.iter().all(u8::is_ascii_digit);
    }
    // A last label of digits only is an IP literal or not a host name.
    if last_all_digits {
        return None;
    }
    let mut out = NormalizedName {
        buf: [0; MAX_NAME],
        len: 0,
    };
    out.buf[..bytes.len()].copy_from_slice(bytes);
    out.len = u8::try_from(bytes.len()).ok()?;
    Some(out)
}

/// A configured name: an exact DNS name or a single-label wildcard
/// (`*.example.com`), normalised.
pub(crate) fn normalize_pattern(name: &str) -> Option<NormalizedName> {
    if name.is_empty() || name.len() > MAX_NAME + 1 {
        return None;
    }
    let lower: Vec<u8> = name.bytes().map(|b| b.to_ascii_lowercase()).collect();
    finish(&lower, true)
}

/// Whether a certificate SAN dNSName covers a configured name (RFC 9525: one
/// leftmost `*` label only; never the CN).
pub(crate) fn san_covers(san: &str, name: &str) -> bool {
    let Some(san) = normalize_pattern(san) else {
        return false;
    };
    let (san, name) = (san.as_str(), name);
    if san == name {
        return true;
    }
    match (san.strip_prefix("*."), name.strip_prefix("*.")) {
        (Some(suffix), None) => name.split_once('.').is_some_and(|(_, rest)| rest == suffix),
        _ => false,
    }
}

/// The key type of an entry, for choosing between an ECDSA and an RSA
/// certificate registered for the same name (FR-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKey {
    Rsa,
    Other,
}

/// Up to two entries for one name: one non-RSA (preferred) and one RSA.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Slot {
    pub(crate) preferred: Option<usize>,
    pub(crate) rsa: Option<usize>,
    pub(crate) group: usize,
}

impl Slot {
    fn put(&mut self, entry: usize, key: EntryKey) -> bool {
        let place = match key {
            EntryKey::Rsa => &mut self.rsa,
            EntryKey::Other => &mut self.preferred,
        };
        if place.is_some() {
            return false;
        }
        *place = Some(entry);
        true
    }
}

/// The SNI table of one configuration snapshot.
#[derive(Debug, Default)]
pub(crate) struct SniTable {
    exact: HashMap<Box<str>, Slot>,
    wildcard: HashMap<Box<str>, Slot>,
    default: Option<Slot>,
    /// Whether an unknown name gets the default entry.
    use_default: bool,
    /// The certified keys, indexed by slot entries.
    keys: Vec<(Arc<CertifiedKey>, EntryKey)>,
    /// rustls's view of the SNI fell outside the session's group (D-032).
    pub(crate) group_mismatches: AtomicU64,
}

impl SniTable {
    pub(crate) fn new() -> Self {
        SniTable::default()
    }

    /// Adds an entry; returns its index.
    pub(crate) fn add_key(&mut self, key: Arc<CertifiedKey>, kind: EntryKey) -> usize {
        self.keys.push((key, kind));
        self.keys.len() - 1
    }

    /// Registers `name` (normalised, maybe `*.`-prefixed) for `entry`.
    /// `false` if the name already has an entry of the same key type.
    pub(crate) fn add_name(&mut self, name: &str, entry: usize, group: usize) -> bool {
        let kind = self.keys[entry].1;
        let (map, key) = match name.strip_prefix("*.") {
            Some(suffix) => (&mut self.wildcard, suffix),
            None => (&mut self.exact, name),
        };
        let slot = map.entry(key.into()).or_insert(Slot {
            group,
            ..Slot::default()
        });
        if slot.group != group {
            return false;
        }
        slot.put(entry, kind)
    }

    /// Puts a host-policy name into `group`: the entries that serve it now
    /// (exact, or the wildcard that covers it) serve it in that group. A
    /// `*.` name moves the wildcard itself. `false` if no certificate covers it.
    pub(crate) fn assign(&mut self, name: &str, group: usize) -> bool {
        if let Some(suffix) = name.strip_prefix("*.") {
            return match self.wildcard.get_mut(suffix) {
                Some(slot) => {
                    slot.group = group;
                    true
                }
                None => false,
            };
        }
        let found = self.exact.get(name).copied().or_else(|| {
            let (_, parent) = name.split_once('.')?;
            self.wildcard.get(parent).copied()
        });
        match found {
            Some(slot) => {
                self.exact.insert(name.into(), Slot { group, ..slot });
                true
            }
            None => false,
        }
    }

    pub(crate) fn set_default(&mut self, entry: usize, group: usize, use_default: bool) {
        let mut slot = Slot {
            group,
            ..Slot::default()
        };
        slot.put(entry, self.keys[entry].1);
        self.default = Some(slot);
        self.use_default = use_default;
    }

    /// The slot for a normalised name: exact, then wildcard, then the default
    /// (when unknown names get it). At most two hash lookups, no allocation.
    pub(crate) fn lookup(&self, name: Option<&str>) -> Option<Slot> {
        if let Some(name) = name {
            if let Some(slot) = self.exact.get(name) {
                return Some(*slot);
            }
            if let Some((_, parent)) = name.split_once('.') {
                if let Some(slot) = self.wildcard.get(parent) {
                    return Some(*slot);
                }
            }
        }
        if self.use_default { self.default } else { None }
    }

    fn choose(&self, slot: Slot, schemes: &[RustlsScheme]) -> Option<Arc<CertifiedKey>> {
        let fits = |i: usize| {
            let alg = self.keys[i].0.key.algorithm();
            schemes.iter().any(|s| scheme_algorithm(*s) == Some(alg))
        };
        let pick = match (slot.preferred, slot.rsa) {
            (Some(p), Some(r)) => {
                if fits(p) {
                    p
                } else {
                    r
                }
            }
            (Some(p), None) => p,
            (None, Some(r)) => r,
            (None, None) => return None,
        };
        Some(self.keys[pick].0.clone())
    }
}

fn scheme_algorithm(s: RustlsScheme) -> Option<SignatureAlgorithm> {
    use RustlsScheme as S;
    Some(match s {
        S::ECDSA_NISTP256_SHA256 | S::ECDSA_NISTP384_SHA384 | S::ECDSA_NISTP521_SHA512 => {
            SignatureAlgorithm::ECDSA
        }
        S::ED25519 => SignatureAlgorithm::ED25519,
        S::RSA_PSS_SHA256
        | S::RSA_PSS_SHA384
        | S::RSA_PSS_SHA512
        | S::RSA_PKCS1_SHA256
        | S::RSA_PKCS1_SHA384
        | S::RSA_PKCS1_SHA512 => SignatureAlgorithm::RSA,
        _ => return None,
    })
}

/// The certificate resolver of one host group: resolves only names that
/// belong to its group, with the same normalisation on rustls's view of the
/// SNI. A disagreement with tls-net's own parse can only cause a refusal.
#[derive(Debug)]
pub(crate) struct GroupResolver {
    pub(crate) table: Arc<SniTable>,
    pub(crate) group: usize,
}

impl ResolvesServerCert for GroupResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().and_then(normalize_server_name);
        let slot = self.table.lookup(name.as_ref().map(NormalizedName::as_str));
        match slot {
            Some(slot) if slot.group == self.group => {
                self.table.choose(slot, hello.signature_schemes())
            }
            _ => {
                self.table.group_mismatches.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_lowercase_and_trailing_dot() {
        assert_eq!(
            normalize_server_name("A.Example.Test.").unwrap().as_str(),
            "a.example.test"
        );
        assert!(normalize_server_name("a.example.test..").is_none());
    }

    #[test]
    fn test_normalize_refuses_bad_input() {
        for bad in [
            "",
            ".",
            "127.0.0.1",
            "::1",
            "a_b.test",
            "-a.test",
            "a-.test",
            "a..b",
            "*.test",
            "caf\u{e9}.test",
            "a\0b",
            "a b",
            "a\x1b[0m",
        ] {
            assert!(normalize_server_name(bad).is_none(), "{bad:?}");
        }
        assert!(normalize_server_name(&"a".repeat(63)).is_some());
        assert!(normalize_server_name(&"a".repeat(64)).is_none());
        let long = vec!["a".repeat(63); 4].join(".");
        assert_eq!(long.len(), 255);
        assert!(normalize_server_name(&long).is_none());
        let max = format!("{}.{}", "a".repeat(63), vec!["b".repeat(61); 3].join("."));
        assert_eq!(max.len(), 249);
        assert!(normalize_server_name(&max).is_some());
        assert!(normalize_server_name("xn--caf-dma.test").is_some());
    }

    #[test]
    fn test_normalize_idempotent() {
        for n in ["Example.COM.", "x.y", "xn--a.b"] {
            let once = normalize_server_name(n).unwrap();
            assert_eq!(normalize_server_name(once.as_str()).unwrap(), once);
        }
    }

    #[test]
    fn test_san_covers_wildcard_rules() {
        assert!(san_covers("*.example.test", "a.example.test"));
        assert!(!san_covers("*.example.test", "a.b.example.test"));
        assert!(!san_covers("*.example.test", "example.test"));
        assert!(san_covers("*.example.test", "*.example.test"));
        assert!(!san_covers("f*.example.test", "foo.example.test"));
        assert!(san_covers("Example.TEST", "example.test"));
        assert!(!san_covers("a.*.test", "a.b.test"));
    }

    #[test]
    fn test_pattern_allows_leading_wildcard_only() {
        assert_eq!(
            normalize_pattern("*.Example.test").unwrap().as_str(),
            "*.example.test"
        );
        assert!(normalize_pattern("a.*.test").is_none());
        assert!(normalize_pattern("*").is_none());
    }
}
