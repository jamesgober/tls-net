//! ClientHello fingerprints (FR-39): JA4 (FoxIO, BSD 3-Clause), its raw and
//! original-order forms, and the JA3 string (Salesforce). JA4 is the primary
//! fingerprint; JA3 changes on most Chrome connections because Chrome
//! permutes its extensions, and is kept for existing intelligence feeds.

use std::fmt;

use crate::hello::{ClientHelloView, is_grease};

/// The most cipher suites `HelloLimits` allows; sorting uses stack arrays of
/// this size (2 KiB), so fingerprints never allocate and stay exact.
const MAX_LIST: usize = 1024;
/// Extensions are capped at 128 by `HelloLimits`.
const MAX_EXT: usize = 128;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A JA4 fingerprint: 36 ASCII bytes, `a_b_c`.
///
/// ```
/// let ja4 = tls_net::Ja4::parse("t13d1516h2_8daaf6152771_e5627efa2ab1").unwrap();
/// assert_eq!(ja4.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ja4([u8; 36]);

impl Ja4 {
    /// Computes JA4 from a parsed ClientHello. Never fails: missing pieces
    /// have defined encodings. The same hello gives the same value on every
    /// platform, and it does not change when ciphers or extensions are
    /// reordered.
    #[must_use]
    pub fn compute(view: &ClientHelloView<'_>) -> Ja4 {
        let mut out = [b'0'; 36];
        out[0] = b't';
        out[1..3].copy_from_slice(version_code(view));
        out[3] = if view.has_server_name() { b'd' } else { b'i' };

        let mut ciphers = [0u16; MAX_LIST];
        let nc = collect(view.cipher_suites(), &mut ciphers);
        let mut exts = [0u16; MAX_EXT];
        let ne = collect(view.extension_types(), &mut exts);
        two_digits(&mut out[4..6], nc);
        two_digits(&mut out[6..8], ne);
        out[8..10].copy_from_slice(&alpn_code(view));
        out[10] = b'_';

        ciphers[..nc].sort_unstable();
        out[11..23].copy_from_slice(&hash12(|h| join(h, &ciphers[..nc])));
        out[23] = b'_';

        // Extensions without SNI and ALPN, sorted; then the signature
        // algorithms in wire order.
        let mut sorted = [0u16; MAX_EXT];
        let mut n = 0;
        for &e in &exts[..ne] {
            if e != 0x0000 && e != 0x0010 {
                sorted[n] = e;
                n += 1;
            }
        }
        sorted[..n].sort_unstable();
        let mut sigs = [0u16; MAX_EXT];
        let ns = collect(view.signature_algorithms(), &mut sigs);
        out[24..36].copy_from_slice(&hash12(|h| {
            join(h, &sorted[..n]);
            if ns > 0 {
                h.update(b"_");
                join(h, &sigs[..ns]);
            }
        }));
        if nc == 0 {
            out[11..23].fill(b'0');
        }
        if n == 0 {
            out[24..36].fill(b'0');
        }
        Ja4(out)
    }

    /// Parses a JA4 string (for configured lists of refused fingerprints):
    /// 36 printable ASCII bytes with `_` at 10 and 23; `None` otherwise.
    #[must_use]
    pub fn parse(s: &str) -> Option<Ja4> {
        let bytes: [u8; 36] = s.as_bytes().try_into().ok()?;
        (bytes[10] == b'_' && bytes[23] == b'_' && bytes.iter().all(u8::is_ascii_graphic))
            .then_some(Ja4(bytes))
    }

    /// The fingerprint.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Display for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ja4({})", self.as_str())
    }
}

/// JA4_r: the JA4 prefix, then the sorted cipher list and the sorted
/// extension list (without SNI and ALPN) and the signature algorithms,
/// unhashed. Written into `out`, which is cleared first.
pub fn ja4_raw(view: &ClientHelloView<'_>, out: &mut String) {
    raw(view, out, true);
}

/// JA4_ro: as [`ja4_raw`], with ciphers and extensions in wire order and SNI
/// and ALPN kept.
pub fn ja4_original(view: &ClientHelloView<'_>, out: &mut String) {
    raw(view, out, false);
}

fn raw(view: &ClientHelloView<'_>, out: &mut String, sorted: bool) {
    out.clear();
    let ja4 = Ja4::compute(view);
    out.push_str(&ja4.as_str()[..10]);
    let mut ciphers = [0u16; MAX_LIST];
    let nc = collect(view.cipher_suites(), &mut ciphers);
    let mut exts = [0u16; MAX_EXT];
    let mut ne = 0;
    for e in view.extension_types().filter(|e| !is_grease(*e)) {
        if ne < MAX_EXT && (!sorted || (e != 0 && e != 0x10)) {
            exts[ne] = e;
            ne += 1;
        }
    }
    if sorted {
        ciphers[..nc].sort_unstable();
        exts[..ne].sort_unstable();
    }
    out.push('_');
    hex_list(out, &ciphers[..nc]);
    out.push('_');
    hex_list(out, &exts[..ne]);
    let mut sigs = [0u16; MAX_EXT];
    let ns = collect(view.signature_algorithms(), &mut sigs);
    if ns > 0 {
        out.push('_');
        hex_list(out, &sigs[..ns]);
    }
}

/// The JA3 string: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`,
/// decimal values joined by `-`, GREASE ignored. Written into `out`, which is
/// cleared first.
///
/// ```
/// let mut s = String::new();
/// # let _ = &mut s;
/// // tls_net::ja3_string(&view, &mut s);  // "771,4865-4866-...,0-23-...,29-23-24,0"
/// ```
pub fn ja3_string(view: &ClientHelloView<'_>, out: &mut String) {
    out.clear();
    write_ja3(view, out);
}

/// The JA3 MD5 digest as 32 lowercase hex bytes (feature `ja3-md5`). MD5 is
/// used as a label here, never for security; the JA3 string is streamed into
/// it, so nothing is allocated.
///
/// ```
/// # let _ = tls_net::ja3_md5;
/// ```
#[cfg(feature = "ja3-md5")]
#[must_use]
pub fn ja3_md5(view: &ClientHelloView<'_>) -> [u8; 32] {
    let mut h = crate::md5::Md5::new();
    write_ja3(view, &mut h);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    for (i, b) in digest.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 15)];
    }
    out
}

fn write_ja3(view: &ClientHelloView<'_>, out: &mut impl fmt::Write) {
    let _ = write!(out, "{}", view.legacy_version());
    let _ = out.write_char(',');
    dec_list(out, view.cipher_suites());
    let _ = out.write_char(',');
    dec_list(out, view.extension_types());
    let _ = out.write_char(',');
    dec_list(out, view.groups());
    let _ = out.write_char(',');
    let mut first = true;
    for p in view.point_formats() {
        if !first {
            let _ = out.write_char('-');
        }
        first = false;
        let _ = write!(out, "{p}");
    }
}

/// Which fingerprints a server computes for every ClientHello.
///
/// ```
/// use tls_net::FingerprintKinds;
/// assert!(FingerprintKinds::JA4.contains(FingerprintKinds::JA4));
/// assert!(!FingerprintKinds::NONE.contains(FingerprintKinds::JA4));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FingerprintKinds(u8);

impl FingerprintKinds {
    /// None: the parse still runs (for SNI), no fingerprint is computed.
    pub const NONE: Self = FingerprintKinds(0);
    /// JA4 (the default).
    pub const JA4: Self = FingerprintKinds(1);
    /// The JA3 MD5 label (feature `ja3-md5`).
    #[cfg(feature = "ja3-md5")]
    pub const JA3_MD5: Self = FingerprintKinds(2);

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        FingerprintKinds(self.0 | other.0)
    }

    /// Whether every kind in `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl Default for FingerprintKinds {
    fn default() -> Self {
        FingerprintKinds::JA4
    }
}

/// The fingerprints of one ClientHello.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fingerprint {
    /// JA4, when enabled.
    pub ja4: Option<Ja4>,
    /// The JA3 MD5 label as lowercase hex, when enabled (feature `ja3-md5`).
    pub ja3_md5: Option<[u8; 32]>,
}

impl Fingerprint {
    pub(crate) fn compute(view: &ClientHelloView<'_>, kinds: FingerprintKinds) -> Fingerprint {
        #[cfg(feature = "ja3-md5")]
        let ja3_md5 = kinds
            .contains(FingerprintKinds::JA3_MD5)
            .then(|| ja3_md5(view));
        #[cfg(not(feature = "ja3-md5"))]
        let ja3_md5 = None;
        Fingerprint {
            ja4: kinds
                .contains(FingerprintKinds::JA4)
                .then(|| Ja4::compute(view)),
            ja3_md5,
        }
    }
}

fn collect(values: impl Iterator<Item = u16>, out: &mut [u16]) -> usize {
    let mut n = 0;
    for v in values.filter(|v| !is_grease(*v)) {
        if n == out.len() {
            break;
        }
        out[n] = v;
        n += 1;
    }
    n
}

fn two_digits(out: &mut [u8], n: usize) {
    let n = n.min(99);
    out[0] = b'0' + u8::try_from(n / 10).unwrap_or(9);
    out[1] = b'0' + u8::try_from(n % 10).unwrap_or(9);
}

fn version_code(view: &ClientHelloView<'_>) -> &'static [u8; 2] {
    let best = view
        .supported_versions()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(view.legacy_version());
    match best {
        0x0304 => b"13",
        0x0303 => b"12",
        0x0302 => b"11",
        0x0301 => b"10",
        0x0300 => b"s3",
        0x0002 => b"s2",
        0xfeff => b"d1",
        0xfefd => b"d2",
        0xfefc => b"d3",
        _ => b"00",
    }
}

fn alpn_code(view: &ClientHelloView<'_>) -> [u8; 2] {
    match view.first_alpn_ends() {
        None => *b"00",
        Some((first, last)) if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() => {
            [first, last]
        }
        // Non-alphanumeric: the first and last characters of the hex form.
        Some((first, last)) => [HEX[usize::from(first >> 4)], HEX[usize::from(last & 0x0f)]],
    }
}

/// Feeds `values` as comma-joined 4-digit lowercase hex into a hasher.
fn join(h: &mut crypt_io::hash::Sha256Hasher, values: &[u16]) {
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            h.update(b",");
        }
        h.update(&hex4(*v));
    }
}

fn hex4(v: u16) -> [u8; 4] {
    [
        HEX[usize::from(v >> 12)],
        HEX[usize::from((v >> 8) & 15)],
        HEX[usize::from((v >> 4) & 15)],
        HEX[usize::from(v & 15)],
    ]
}

fn hash12(feed: impl FnOnce(&mut crypt_io::hash::Sha256Hasher)) -> [u8; 12] {
    let mut h = crypt_io::hash::Sha256Hasher::new();
    feed(&mut h);
    let digest = h.finalize();
    let mut out = [0u8; 12];
    for (i, b) in digest.iter().take(6).enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 15)];
    }
    out
}

fn hex_list(out: &mut String, values: &[u16]) {
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        for b in hex4(*v) {
            out.push(char::from(b));
        }
    }
}

fn dec_list(out: &mut impl fmt::Write, values: impl Iterator<Item = u16>) {
    let mut first = true;
    for v in values.filter(|v| !is_grease(*v)) {
        if !first {
            let _ = out.write_char('-');
        }
        first = false;
        let _ = write!(out, "{v}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::tests::HelloBuilder;
    use crate::hello::{HelloLimits, HelloParse, parse_client_hello};

    /// The ClientHello behind FoxIO's published JA4 example
    /// `t13d1516h2_8daaf6152771_e5627efa2ab1` (15 ciphers, 16 extensions,
    /// ALPN h2), with GREASE added and lists shuffled as a browser sends them.
    fn foxio_example(shuffle: bool) -> Vec<u8> {
        let mut b = HelloBuilder::new();
        b.ciphers = vec![
            0x1a1a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        if shuffle {
            b.ciphers.reverse();
        }
        let sigs: [u16; 8] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut sig = (u16::try_from(sigs.len() * 2).unwrap())
            .to_be_bytes()
            .to_vec();
        for s in sigs {
            sig.extend(s.to_be_bytes());
        }
        let mut exts: Vec<(u16, Vec<u8>)> = vec![
            (0x2a2a, vec![]),
            (0x0005, vec![1, 0, 0, 0, 0]),
            (0x000a, vec![0, 4, 0x2a, 0x2a, 0, 0x1d]),
            (0x000b, vec![1, 0]),
            (0x000d, sig),
            (0x0012, vec![]),
            (0x0015, vec![0, 0]),
            (0x0017, vec![]),
            (0x001b, vec![2, 0, 2]),
            (0x0023, vec![]),
            (0x002b, vec![4, 0x2a, 0x2a, 3, 4]),
            (0x002d, vec![1, 1]),
            (0x0033, vec![0, 6, 0, 0x1d, 0, 2, 0xaa, 0xbb]),
            (0x4469, vec![0, 3, 2, b'h', b'2']),
            (0xff01, vec![0]),
        ];
        if shuffle {
            exts.reverse();
        }
        let mut b = b.sni(b"example.test").alpn(&[b"h2", b"http/1.1"]);
        b.extensions.splice(0..0, exts);
        b.records(16_384)
    }

    fn view_of(bytes: &[u8]) -> ClientHelloView<'_> {
        match parse_client_hello(bytes, &HelloLimits::new()).unwrap() {
            HelloParse::Complete { view, .. } => view,
            HelloParse::Incomplete { .. } => panic!("incomplete"),
        }
    }

    #[test]
    fn test_ja4_known_answer_foxio_example() {
        let bytes = foxio_example(false);
        assert_eq!(
            Ja4::compute(&view_of(&bytes)).as_str(),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn test_ja4_invariant_under_permutation() {
        let (a, b) = (foxio_example(false), foxio_example(true));
        assert_eq!(Ja4::compute(&view_of(&a)), Ja4::compute(&view_of(&b)));
        let (mut ja3a, mut ja3b) = (String::new(), String::new());
        ja3_string(&view_of(&a), &mut ja3a);
        ja3_string(&view_of(&b), &mut ja3b);
        assert_ne!(ja3a, ja3b, "JA3 is order-sensitive");
    }

    #[test]
    fn test_ja4_raw_lists() {
        let bytes = foxio_example(true);
        let mut s = String::new();
        ja4_raw(&view_of(&bytes), &mut s);
        assert_eq!(
            s,
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_\
             0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
             0403,0804,0401,0503,0805,0501,0806,0601"
        );
        ja4_original(&view_of(&bytes), &mut s);
        assert!(s.starts_with("t13d1516h2_0035,002f,"), "{s}");
    }

    #[test]
    fn test_ja3_string_shape() {
        let bytes = foxio_example(false);
        let mut s = String::new();
        ja3_string(&view_of(&bytes), &mut s);
        assert!(s.starts_with("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-10-11-13-"), "{s}");
        assert!(s.ends_with(",29,0"), "{s}");
    }

    #[cfg(feature = "ja3-md5")]
    #[test]
    fn test_ja3_md5_is_md5_of_the_string() {
        let bytes = foxio_example(false);
        let view = view_of(&bytes);
        let mut s = String::new();
        ja3_string(&view, &mut s);
        let mut h = crate::md5::Md5::new();
        h.update(s.as_bytes());
        let digest: String = h.finalize().iter().fold(String::new(), |mut s, x| {
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
            s
        });
        assert_eq!(std::str::from_utf8(&ja3_md5(&view)).unwrap(), digest);
        let fp = Fingerprint::compute(
            &view,
            FingerprintKinds::JA4.union(FingerprintKinds::JA3_MD5),
        );
        assert!(fp.ja4.is_some() && fp.ja3_md5.is_some());
    }

    #[test]
    fn test_ja4_no_sni_no_alpn_no_extensions() {
        let bytes = HelloBuilder::new().records(16_384);
        let ja4 = Ja4::compute(&view_of(&bytes));
        assert_eq!(&ja4.as_str()[..10], "t12i020000");
        assert_eq!(&ja4.as_str()[24..], "000000000000");
    }

    #[test]
    fn test_ja4_alpn_hex_fallback() {
        let bytes = HelloBuilder::new().alpn(&[&[0xab, 0x01]]).records(16_384);
        assert_eq!(&Ja4::compute(&view_of(&bytes)).as_str()[8..10], "a1");
    }
}
