//! The ClientHello parser: bounded, zero-copy, linear in the hello length,
//! across record boundaries (FR-38, T-14).
//!
//! The handshake message is read as one logical stream over the payloads of
//! up to `max_records` TLS records, without copying. Every length is checked
//! against the remaining input before use and every count against its limit
//! before iteration; all arithmetic is checked.

use std::fmt;

use crate::error::TlsError;
use crate::sni::NormalizedName;

/// The most records any limit allows.
const MAX_SEGMENTS: usize = 16;
/// TLS record header size.
const RECORD_HEADER: usize = 5;
/// Largest TLS plaintext record payload.
const MAX_RECORD: usize = 16_384;

/// Budgets for the ClientHello parser.
///
/// ```
/// let limits = tls_net::HelloLimits::new().max_hello_bytes(4096)?;
/// assert_eq!(limits.max_hello_bytes, 4096);
/// assert!(tls_net::HelloLimits::new().max_records(0).is_err());
/// # Ok::<(), tls_net::TlsError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloLimits {
    /// Largest handshake message (default 16 KiB).
    pub max_hello_bytes: u32,
    /// Most records the hello may span (default 4).
    pub max_records: u8,
    /// Most cipher suites (default 512).
    pub max_ciphers: u16,
    /// Most extensions (default 64).
    pub max_extensions: u8,
    /// Most ALPN names (default 32).
    pub max_alpn: u8,
    /// Most supported groups (default 64).
    pub max_groups: u8,
    /// Most signature algorithms (default 64).
    pub max_signature_algorithms: u8,
    /// Most key shares (default 8).
    pub max_key_shares: u8,
    /// Refuse a hello the parser rejects (default on, D-013).
    pub refuse_malformed: bool,
}

impl Default for HelloLimits {
    fn default() -> Self {
        HelloLimits::new()
    }
}

macro_rules! setter {
    ($(#[$doc:meta])* $name:ident: $t:ty, $lo:expr, $hi:expr, $msg:literal) => {
        $(#[$doc])*
        ///
        /// # Errors
        ///
        /// `PolicyInvalid` outside the range.
        pub fn $name(mut self, n: $t) -> Result<Self, TlsError> {
            if !($lo..=$hi).contains(&n) {
                return Err(TlsError::PolicyInvalid { reason: $msg });
            }
            self.$name = n;
            Ok(self)
        }
    };
}

impl HelloLimits {
    /// The defaults.
    #[must_use]
    pub const fn new() -> Self {
        HelloLimits {
            max_hello_bytes: 16 << 10,
            max_records: 4,
            max_ciphers: 512,
            max_extensions: 64,
            max_alpn: 32,
            max_groups: 64,
            max_signature_algorithms: 64,
            max_key_shares: 8,
            refuse_malformed: true,
        }
    }

    setter!(/// Largest handshake message, 512 to 65,535 bytes.
        max_hello_bytes: u32, 512, 65_535, "max_hello_bytes must be 512 to 65,535");
    setter!(/// Most records, 1 to 16.
        max_records: u8, 1, 16, "max_records must be 1 to 16");
    setter!(/// Most cipher suites, 1 to 1,024 (the fingerprint arrays' size).
        max_ciphers: u16, 1, 1024, "max_ciphers must be 1 to 1,024");
    setter!(/// Most extensions, 1 to 128.
        max_extensions: u8, 1, 128, "max_extensions must be 1 to 128");
    setter!(/// Most ALPN names, 1 to 64.
        max_alpn: u8, 1, 64, "max_alpn must be 1 to 64");
    setter!(/// Most supported groups, 1 to 128.
        max_groups: u8, 1, 128, "max_groups must be 1 to 128");
    setter!(/// Most signature algorithms, 1 to 128.
        max_signature_algorithms: u8, 1, 128, "max_signature_algorithms must be 1 to 128");
    setter!(/// Most key shares, 1 to 16.
        max_key_shares: u8, 1, 16, "max_key_shares must be 1 to 16");

    /// Every limit held to its setter's range. The fields are public, so a
    /// caller can assign one outside it; the parser's fixed arrays (128
    /// extensions, 1,024 suites) must never see such a value (D-128).
    #[must_use]
    pub(crate) fn clamped(self) -> Self {
        HelloLimits {
            max_hello_bytes: self.max_hello_bytes.clamp(512, 65_535),
            max_records: self.max_records.clamp(1, 16),
            max_ciphers: self.max_ciphers.clamp(1, 1024),
            max_extensions: self.max_extensions.clamp(1, 128),
            max_alpn: self.max_alpn.clamp(1, 64),
            max_groups: self.max_groups.clamp(1, 128),
            max_signature_algorithms: self.max_signature_algorithms.clamp(1, 128),
            max_key_shares: self.max_key_shares.clamp(1, 16),
            refuse_malformed: self.refuse_malformed,
        }
    }

    /// Whether to refuse a hello the parser rejects (on by default). Off lets
    /// it continue to rustls without a fingerprint: for emergencies only.
    #[must_use]
    pub const fn refuse_malformed(mut self, on: bool) -> Self {
        self.refuse_malformed = on;
        self
    }
}

/// The result of [`HelloParser::parse`].
#[non_exhaustive]
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the view is kept inline so parsing allocates nothing"
)]
pub enum HelloParse<'a> {
    /// More bytes are needed: `needed` is the total the input must hold
    /// before the parser can make progress (exact once the hello's length is
    /// known and it sits in one record).
    Incomplete {
        /// Total bytes needed.
        needed: usize,
    },
    /// A complete ClientHello.
    Complete {
        /// The parsed view, borrowing the input.
        view: ClientHelloView<'a>,
        /// Bytes of the records that hold the hello.
        length: usize,
    },
}

/// Parses a ClientHello from the start of a TLS byte stream.
///
/// ```
/// use tls_net::{HelloLimits, HelloParse, HelloParser};
/// assert!(matches!(HelloParser::parse(b"\x16\x03\x01", &HelloLimits::new()), Ok(HelloParse::Incomplete { needed: 5 })));
/// assert_eq!(HelloParser::parse(b"GET / HTTP/1.1\r\n", &HelloLimits::new()).unwrap_err(), tls_net::TlsError::NotTls);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct HelloParser;

impl HelloParser {
    /// Parses one ClientHello within `limits`. Nothing is allocated.
    ///
    /// # Errors
    ///
    /// `NotTls`, `BadRecord`, `HelloMalformed`, `DuplicateExtension`
    /// (`TLS-0031`); `HelloTooLarge`, `HelloTooFragmented`,
    /// `HelloOverBudget` (`TLS-0032`).
    pub fn parse<'a>(input: &'a [u8], limits: &HelloLimits) -> Result<HelloParse<'a>, TlsError> {
        let limits = &limits.clamped();
        let max_records = usize::from(limits.max_records).min(MAX_SEGMENTS);
        let mut segs: [&'a [u8]; MAX_SEGMENTS] = [&[]; MAX_SEGMENTS];
        let mut nseg = 0usize;
        let mut pos = 0usize;
        let mut have = 0usize;
        let mut hello_len: Option<usize> = None;
        let mut record_version = 0u16;
        loop {
            if let Some(len) = hello_len {
                if have >= len + 4 {
                    break;
                }
            }
            if nseg == max_records {
                return Err(TlsError::HelloTooFragmented);
            }
            let Some(header) = input.get(pos..pos + RECORD_HEADER) else {
                check_prefix(&input[pos.min(input.len())..])?;
                return Ok(HelloParse::Incomplete {
                    needed: pos + RECORD_HEADER,
                });
            };
            let (typ, version, len) = (
                header[0],
                u16::from_be_bytes([header[1], header[2]]),
                usize::from(u16::from_be_bytes([header[3], header[4]])),
            );
            check_header(typ, version)?;
            if len == 0 || len > MAX_RECORD {
                return Err(TlsError::BadRecord);
            }
            if nseg == 0 {
                record_version = version;
            }
            let body_start = pos + RECORD_HEADER;
            let end = body_start + len;
            // The hello's length is known as soon as its 4-byte header is in.
            let Some(payload) = input.get(body_start..end) else {
                if hello_len.is_none() {
                    let avail = &input[body_start.min(input.len())..];
                    if let Some(l) = early_length(&segs[..nseg], avail) {
                        check_hello_len(l, limits)?;
                    }
                }
                return Ok(HelloParse::Incomplete { needed: end });
            };
            segs[nseg] = payload;
            nseg += 1;
            have += len;
            pos = end;
            if hello_len.is_none() && have >= 4 {
                let stream = Stream::new(&segs[..nseg]);
                if stream.byte(0) != Some(1) {
                    return Err(TlsError::HelloMalformed);
                }
                let l = stream.u24(1).ok_or(TlsError::HelloMalformed)?;
                check_hello_len(l, limits)?;
                hello_len = Some(l);
            }
        }
        let total = hello_len.unwrap_or(0) + 4;
        // The records must end exactly with the hello.
        if have != total {
            return Err(TlsError::HelloMalformed);
        }
        let stream = Stream::new(&segs[..nseg]);
        let view = parse_body(stream, record_version, limits)?;
        Ok(HelloParse::Complete { view, length: pos })
    }
}

fn check_prefix(rest: &[u8]) -> Result<(), TlsError> {
    match rest {
        [] => Ok(()),
        [t] => check_type(*t),
        [t, major, ..] => {
            check_type(*t)?;
            if *major != 3 {
                Err(TlsError::BadRecord)
            } else {
                Ok(())
            }
        }
    }
}

fn check_type(t: u8) -> Result<(), TlsError> {
    match t {
        22 => Ok(()),
        20 | 21 | 23 | 24 => Err(TlsError::BadRecord),
        _ => Err(TlsError::NotTls),
    }
}

/// Any `{03,XX}` record version: RFC 5246 appendix E.1 requires a server
/// to accept them on a ClientHello, RFC 8446 section 5.1 says to ignore the
/// field, and rustls does the same (D-110). It never selects the protocol.
fn check_header(typ: u8, version: u16) -> Result<(), TlsError> {
    check_type(typ)?;
    if version >> 8 != 3 {
        return Err(TlsError::BadRecord);
    }
    Ok(())
}

fn check_hello_len(len: usize, limits: &HelloLimits) -> Result<(), TlsError> {
    if len > limits.max_hello_bytes as usize {
        return Err(TlsError::HelloTooLarge);
    }
    if len < 38 {
        return Err(TlsError::HelloMalformed);
    }
    Ok(())
}

/// The hello length from complete segments plus a partial record, if the
/// 4-byte handshake header is already in.
fn early_length(segs: &[&[u8]], partial: &[u8]) -> Option<usize> {
    let mut hdr = [0u8; 4];
    let mut n = 0;
    for b in segs
        .iter()
        .flat_map(|s| s.iter())
        .chain(partial.iter())
        .take(4)
    {
        hdr[n] = *b;
        n += 1;
    }
    (n == 4 && hdr[0] == 1)
        .then(|| (usize::from(hdr[1]) << 16) | (usize::from(hdr[2]) << 8) | usize::from(hdr[3]))
}

/// The record payloads of one hello, read as one logical stream.
#[derive(Clone, Copy)]
struct Stream<'a> {
    segs: [&'a [u8]; MAX_SEGMENTS],
    n: usize,
    len: usize,
}

impl<'a> Stream<'a> {
    fn new(segs: &[&'a [u8]]) -> Self {
        let mut s = Stream {
            segs: [&[]; MAX_SEGMENTS],
            n: segs.len(),
            len: 0,
        };
        for (i, seg) in segs.iter().enumerate() {
            s.segs[i] = seg;
            s.len += seg.len();
        }
        s
    }

    fn cursor(&self, pos: usize) -> Cursor<'a> {
        let mut c = Cursor {
            segs: self.segs,
            n: self.n,
            seg: 0,
            off: 0,
            pos: 0,
        };
        c.skip(pos);
        c
    }

    fn byte(&self, pos: usize) -> Option<u8> {
        self.cursor(pos).u8()
    }

    fn u24(&self, pos: usize) -> Option<usize> {
        let mut c = self.cursor(pos);
        Some((usize::from(c.u8()?) << 16) | (usize::from(c.u8()?) << 8) | usize::from(c.u8()?))
    }

    /// A contiguous slice, if the range does not cross a record boundary.
    fn slice(&self, pos: usize, len: usize) -> Option<&'a [u8]> {
        let c = self.cursor(pos);
        let seg = c.segs.get(c.seg)?;
        seg.get(c.off..c.off.checked_add(len)?)
    }
}

/// A forward reader over the logical stream.
#[derive(Clone, Copy)]
struct Cursor<'a> {
    segs: [&'a [u8]; MAX_SEGMENTS],
    n: usize,
    seg: usize,
    off: usize,
    pos: usize,
}

impl Cursor<'_> {
    fn u8(&mut self) -> Option<u8> {
        while self.seg < self.n {
            if let Some(&b) = self.segs[self.seg].get(self.off) {
                self.off += 1;
                self.pos += 1;
                return Some(b);
            }
            self.seg += 1;
            self.off = 0;
        }
        None
    }

    fn u16(&mut self) -> Option<u16> {
        Some((u16::from(self.u8()?) << 8) | u16::from(self.u8()?))
    }

    fn skip(&mut self, mut n: usize) {
        while n > 0 && self.seg < self.n {
            let left = self.segs[self.seg].len() - self.off;
            if n < left {
                self.off += n;
                self.pos += n;
                return;
            }
            n -= left;
            self.pos += left;
            self.seg += 1;
            self.off = 0;
        }
    }
}

/// A byte range inside the logical stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Span {
    pos: u32,
    len: u32,
}

impl Span {
    fn new(pos: usize, len: usize) -> Option<Span> {
        Some(Span {
            pos: u32::try_from(pos).ok()?,
            len: u32::try_from(len).ok()?,
        })
    }
    fn pos(self) -> usize {
        self.pos as usize
    }
    fn len(self) -> usize {
        self.len as usize
    }
}

/// A parsed ClientHello, borrowing the input. Cheap to copy.
#[derive(Clone, Copy)]
pub struct ClientHelloView<'a> {
    stream: Stream<'a>,
    record_version: u16,
    legacy_version: u16,
    session_id_len: u8,
    ciphers: Span,
    extensions: Span,
    extension_count: u8,
    server_name: Option<Span>,
    alpn: Option<Span>,
    groups: Option<Span>,
    point_formats: Option<Span>,
    signature_algorithms: Option<Span>,
    supported_versions: Option<Span>,
    key_share: Option<Span>,
    padding: Option<u16>,
    pre_shared_key: bool,
    early_data: bool,
    encrypted_client_hello: bool,
}

fn parse_body<'a>(
    stream: Stream<'a>,
    record_version: u16,
    limits: &HelloLimits,
) -> Result<ClientHelloView<'a>, TlsError> {
    let bad = || TlsError::HelloMalformed;
    let end = stream.len;
    let mut c = stream.cursor(4);
    let legacy_version = c.u16().ok_or_else(bad)?;
    c.skip(32);
    let session_id_len = c.u8().ok_or_else(bad)?;
    if session_id_len > 32 {
        return Err(bad());
    }
    c.skip(usize::from(session_id_len));
    let cipher_len = usize::from(c.u16().ok_or_else(bad)?);
    if cipher_len < 2 || cipher_len % 2 != 0 {
        return Err(bad());
    }
    if cipher_len / 2 > usize::from(limits.max_ciphers) {
        return Err(TlsError::HelloOverBudget {
            what: "cipher suite",
        });
    }
    let ciphers = Span::new(c.pos, cipher_len).ok_or_else(bad)?;
    c.skip(cipher_len);
    let comp_len = usize::from(c.u8().ok_or_else(bad)?);
    if comp_len == 0 {
        return Err(bad());
    }
    let mut null = false;
    for _ in 0..comp_len {
        null |= c.u8().ok_or_else(bad)? == 0;
    }
    if !null || c.pos > end {
        return Err(bad());
    }
    let mut view = ClientHelloView {
        stream,
        record_version,
        legacy_version,
        session_id_len,
        ciphers,
        extensions: Span::default(),
        extension_count: 0,
        server_name: None,
        alpn: None,
        groups: None,
        point_formats: None,
        signature_algorithms: None,
        supported_versions: None,
        key_share: None,
        padding: None,
        pre_shared_key: false,
        early_data: false,
        encrypted_client_hello: false,
    };
    if c.pos == end {
        return Ok(view);
    }
    let ext_len = usize::from(c.u16().ok_or_else(bad)?);
    if c.pos + ext_len != end {
        return Err(bad());
    }
    view.extensions = Span::new(c.pos, ext_len).ok_or_else(bad)?;
    let mut seen = [0u16; 128];
    let mut count = 0usize;
    while c.pos < end {
        if count == usize::from(limits.max_extensions) {
            return Err(TlsError::HelloOverBudget { what: "extension" });
        }
        if view.pre_shared_key {
            // pre_shared_key must be the last extension.
            return Err(bad());
        }
        let typ = c.u16().ok_or_else(bad)?;
        let len = usize::from(c.u16().ok_or_else(bad)?);
        let data_pos = c.pos;
        if data_pos + len > end {
            return Err(bad());
        }
        if seen[..count].contains(&typ) {
            return Err(TlsError::DuplicateExtension);
        }
        seen[count] = typ;
        count += 1;
        let span = Span::new(data_pos, len).ok_or_else(bad)?;
        extension(&mut view, typ, span, limits)?;
        c.skip(len);
    }
    view.extension_count = u8::try_from(count).map_err(|_| bad())?;
    Ok(view)
}

/// Reads one known extension into the view, checking its inner lengths.
fn extension(
    view: &mut ClientHelloView<'_>,
    typ: u16,
    span: Span,
    limits: &HelloLimits,
) -> Result<(), TlsError> {
    let bad = || TlsError::HelloMalformed;
    let mut c = view.stream.cursor(span.pos());
    let end = span.pos() + span.len();
    match typ {
        0x0000 => {
            let list = usize::from(c.u16().ok_or_else(bad)?);
            if list + 2 != span.len() || list < 3 {
                return Err(bad());
            }
            if c.u8() != Some(0) {
                return Err(bad());
            }
            let len = usize::from(c.u16().ok_or_else(bad)?);
            // Exactly one host_name entry of 1 to 255 bytes.
            if len == 0 || len > 255 || 3 + len != list {
                return Err(bad());
            }
            view.server_name = Span::new(c.pos, len);
        }
        0x0010 => {
            let list = usize::from(c.u16().ok_or_else(bad)?);
            if list + 2 != span.len() || list < 2 {
                return Err(bad());
            }
            let mut n = 0usize;
            while c.pos < end {
                let len = usize::from(c.u8().ok_or_else(bad)?);
                if len == 0 || c.pos + len > end {
                    return Err(bad());
                }
                n += 1;
                if n > usize::from(limits.max_alpn) {
                    return Err(TlsError::HelloOverBudget { what: "ALPN" });
                }
                c.skip(len);
            }
            view.alpn = Span::new(span.pos() + 2, list);
        }
        0x000a => {
            view.groups = Some(u16_list(
                &mut c,
                span,
                2,
                usize::from(limits.max_groups),
                "group",
            )?)
        }
        0x000d => {
            view.signature_algorithms = Some(u16_list(
                &mut c,
                span,
                2,
                usize::from(limits.max_signature_algorithms),
                "signature algorithm",
            )?);
        }
        0x002b => {
            view.supported_versions = Some(u16_list(&mut c, span, 1, 127, "supported version")?)
        }
        0x000b => {
            let len = usize::from(c.u8().ok_or_else(bad)?);
            if len + 1 != span.len() {
                return Err(bad());
            }
            view.point_formats = Span::new(span.pos() + 1, len);
        }
        0x0033 => {
            let list = usize::from(c.u16().ok_or_else(bad)?);
            if list + 2 != span.len() {
                return Err(bad());
            }
            let mut n = 0usize;
            while c.pos < end {
                c.u16().ok_or_else(bad)?;
                let len = usize::from(c.u16().ok_or_else(bad)?);
                if c.pos + len > end {
                    return Err(bad());
                }
                n += 1;
                if n > usize::from(limits.max_key_shares) {
                    return Err(TlsError::HelloOverBudget { what: "key share" });
                }
                c.skip(len);
            }
            view.key_share = Span::new(span.pos() + 2, list);
        }
        0x0029 => view.pre_shared_key = true,
        0x002a => view.early_data = true,
        0xfe0d => view.encrypted_client_hello = true,
        0x0015 => view.padding = u16::try_from(span.len()).ok(),
        _ => {}
    }
    Ok(())
}

/// A length-prefixed list of `u16` values; `prefix` is 1 or 2 bytes.
fn u16_list(
    c: &mut Cursor<'_>,
    span: Span,
    prefix: usize,
    max: usize,
    what: &'static str,
) -> Result<Span, TlsError> {
    let bad = || TlsError::HelloMalformed;
    let list = if prefix == 1 {
        usize::from(c.u8().ok_or_else(bad)?)
    } else {
        usize::from(c.u16().ok_or_else(bad)?)
    };
    if list + prefix != span.len() || list % 2 != 0 {
        return Err(bad());
    }
    if list / 2 > max {
        return Err(TlsError::HelloOverBudget { what });
    }
    Span::new(span.pos() + prefix, list).ok_or_else(bad)
}

/// An iterator over `u16` values in a span.
#[derive(Clone)]
pub(crate) struct U16s<'a> {
    cursor: Cursor<'a>,
    left: usize,
}

impl Iterator for U16s<'_> {
    type Item = u16;
    fn next(&mut self) -> Option<u16> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        self.cursor.u16()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<'a> ClientHelloView<'a> {
    fn u16s(&self, span: Option<Span>) -> U16s<'a> {
        let span = span.unwrap_or_default();
        U16s {
            cursor: self.stream.cursor(span.pos()),
            left: span.len() / 2,
        }
    }

    /// The legacy version of the first record header.
    #[must_use]
    pub fn record_version(&self) -> u16 {
        self.record_version
    }

    /// The hello's legacy version field.
    #[must_use]
    pub fn legacy_version(&self) -> u16 {
        self.legacy_version
    }

    /// The `supported_versions` list, in wire order.
    pub fn supported_versions(&self) -> impl Iterator<Item = u16> + 'a {
        self.u16s(self.supported_versions)
    }

    /// The cipher suites, in wire order, GREASE included.
    pub fn cipher_suites(&self) -> impl Iterator<Item = u16> + 'a {
        self.u16s(Some(self.ciphers))
    }

    /// The extension types, in wire order.
    pub fn extension_types(&self) -> impl Iterator<Item = u16> + 'a {
        let mut c = self.stream.cursor(self.extensions.pos());
        let end = self.extensions.pos() + self.extensions.len();
        std::iter::from_fn(move || {
            if c.pos >= end {
                return None;
            }
            let typ = c.u16()?;
            let len = usize::from(c.u16()?);
            c.skip(len);
            Some(typ)
        })
    }

    /// The extensions as `(type, data)`, in wire order. An extension whose
    /// data crosses a record boundary has empty data here; use the typed
    /// accessors for those.
    pub fn extensions(&self) -> impl Iterator<Item = (u16, &'a [u8])> + 'a {
        let stream = self.stream;
        let mut c = stream.cursor(self.extensions.pos());
        let end = self.extensions.pos() + self.extensions.len();
        std::iter::from_fn(move || {
            if c.pos >= end {
                return None;
            }
            let typ = c.u16()?;
            let len = usize::from(c.u16()?);
            let data = stream.slice(c.pos, len).unwrap_or(&[]);
            c.skip(len);
            Some((typ, data))
        })
    }

    /// The number of extensions.
    #[must_use]
    pub fn extension_count(&self) -> usize {
        usize::from(self.extension_count)
    }

    /// The SNI as sent, when it is letters, digits, `-` and `.` only and sits
    /// in one record; `None` otherwise (T-20).
    #[must_use]
    pub fn server_name(&self) -> Option<&'a str> {
        let span = self.server_name?;
        let bytes = self.stream.slice(span.pos(), span.len())?;
        bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
            .then(|| std::str::from_utf8(bytes).ok())
            .flatten()
    }

    /// Whether the hello carries a `server_name` extension.
    #[must_use]
    pub fn has_server_name(&self) -> bool {
        self.server_name.is_some()
    }

    /// The SNI normalised by the FR-17 rule, read across record boundaries.
    #[must_use]
    pub fn normalized_server_name(&self) -> Option<NormalizedName> {
        let span = self.server_name?;
        let mut c = self.stream.cursor(span.pos());
        let bytes = std::iter::from_fn(move || c.u8());
        let mut buf = [0u8; 255];
        let mut n = 0;
        for b in bytes.take(span.len()) {
            buf[n] = b;
            n += 1;
        }
        NormalizedName::from_chunks(n, buf[..n].iter())
    }

    /// The ALPN names offered, in wire order (names that cross a record
    /// boundary are skipped here; [`has_alpn`](Self::has_alpn) reports the extension).
    pub fn alpn(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let stream = self.stream;
        let span = self.alpn.unwrap_or_default();
        let mut c = stream.cursor(span.pos());
        let end = span.pos() + span.len();
        std::iter::from_fn(move || {
            loop {
                if c.pos >= end {
                    return None;
                }
                let len = usize::from(c.u8()?);
                let item = stream.slice(c.pos, len);
                c.skip(len);
                if item.is_some() {
                    return item;
                }
            }
        })
    }

    /// Whether the hello offers ALPN.
    #[must_use]
    pub fn has_alpn(&self) -> bool {
        self.alpn.is_some()
    }

    /// The first and last bytes of the first ALPN name, read across record
    /// boundaries (for JA4).
    pub(crate) fn first_alpn_ends(&self) -> Option<(u8, u8)> {
        let span = self.alpn?;
        let mut c = self.stream.cursor(span.pos());
        let len = usize::from(c.u8()?);
        let first = c.u8()?;
        c.skip(len.saturating_sub(2));
        let last = if len == 1 { first } else { c.u8()? };
        Some((first, last))
    }

    /// The supported groups, in wire order.
    pub fn groups(&self) -> impl Iterator<Item = u16> + 'a {
        self.u16s(self.groups)
    }

    /// The EC point formats, in wire order.
    pub fn point_formats(&self) -> impl Iterator<Item = u8> + 'a {
        let span = self.point_formats.unwrap_or_default();
        let mut c = self.stream.cursor(span.pos());
        let mut left = span.len();
        std::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            left -= 1;
            c.u8()
        })
    }

    /// The signature algorithms, in wire order.
    pub fn signature_algorithms(&self) -> impl Iterator<Item = u16> + 'a {
        self.u16s(self.signature_algorithms)
    }

    /// The groups of the key shares, in wire order.
    pub fn key_share_groups(&self) -> impl Iterator<Item = u16> + 'a {
        let span = self.key_share.unwrap_or_default();
        let mut c = self.stream.cursor(span.pos());
        let end = span.pos() + span.len();
        std::iter::from_fn(move || {
            if c.pos >= end {
                return None;
            }
            let group = c.u16()?;
            let len = usize::from(c.u16()?);
            c.skip(len);
            Some(group)
        })
    }

    /// Whether the hello offers a pre-shared key (resumption).
    #[must_use]
    pub fn has_pre_shared_key(&self) -> bool {
        self.pre_shared_key
    }

    /// Whether the hello asks for early data.
    #[must_use]
    pub fn has_early_data(&self) -> bool {
        self.early_data
    }

    /// Whether the hello carries an `encrypted_client_hello` extension.
    #[must_use]
    pub fn has_encrypted_client_hello(&self) -> bool {
        self.encrypted_client_hello
    }

    /// The length of the legacy session id.
    #[must_use]
    pub fn session_id_len(&self) -> u8 {
        self.session_id_len
    }

    /// The length of the padding extension, if present.
    #[must_use]
    pub fn padding_len(&self) -> Option<u16> {
        self.padding
    }

    /// The whole handshake message, when it sits in one record.
    #[must_use]
    pub fn raw(&self) -> Option<&'a [u8]> {
        (self.stream.n == 1).then(|| self.stream.segs[0])
    }
}

impl fmt::Debug for ClientHelloView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHelloView")
            .field(
                "legacy_version",
                &format_args!("{:#06x}", self.legacy_version),
            )
            .field("ciphers", &(self.ciphers.len() / 2))
            .field("extensions", &self.extension_count)
            .field("server_name", &self.normalized_server_name())
            .field("records", &self.stream.n)
            .finish_non_exhaustive()
    }
}

/// Whether a value is a GREASE code point (RFC 8701): `0x0A0A`, `0x1A1A`, up
/// to `0xFAFA`.
///
/// ```
/// assert!(tls_net::is_grease(0x3a3a));
/// assert!(!tls_net::is_grease(0x1301));
/// ```
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a ClientHello record from parts, for tests.
    pub(crate) struct HelloBuilder {
        pub(crate) ciphers: Vec<u16>,
        pub(crate) extensions: Vec<(u16, Vec<u8>)>,
        pub(crate) session_id: Vec<u8>,
    }

    impl HelloBuilder {
        pub(crate) fn new() -> Self {
            HelloBuilder {
                ciphers: vec![0x1301, 0x1302],
                extensions: Vec::new(),
                session_id: vec![0; 32],
            }
        }
        pub(crate) fn sni(mut self, name: &[u8]) -> Self {
            let mut d = Vec::new();
            d.extend(u16::try_from(name.len() + 3).unwrap().to_be_bytes());
            d.push(0);
            d.extend(u16::try_from(name.len()).unwrap().to_be_bytes());
            d.extend(name);
            self.extensions.push((0, d));
            self
        }
        pub(crate) fn alpn(mut self, names: &[&[u8]]) -> Self {
            let mut list = Vec::new();
            for n in names {
                list.push(u8::try_from(n.len()).unwrap());
                list.extend(*n);
            }
            let mut d = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
            d.extend(list);
            self.extensions.push((16, d));
            self
        }
        pub(crate) fn ext(mut self, typ: u16, data: Vec<u8>) -> Self {
            self.extensions.push((typ, data));
            self
        }
        pub(crate) fn body(&self) -> Vec<u8> {
            let mut b = vec![3, 3];
            b.extend([7u8; 32]);
            b.push(u8::try_from(self.session_id.len()).unwrap());
            b.extend(&self.session_id);
            b.extend(u16::try_from(self.ciphers.len() * 2).unwrap().to_be_bytes());
            for c in &self.ciphers {
                b.extend(c.to_be_bytes());
            }
            b.extend([1, 0]);
            let mut ext = Vec::new();
            for (t, d) in &self.extensions {
                ext.extend(t.to_be_bytes());
                ext.extend(u16::try_from(d.len()).unwrap().to_be_bytes());
                ext.extend(d);
            }
            b.extend(u16::try_from(ext.len()).unwrap().to_be_bytes());
            b.extend(ext);
            let mut msg = vec![1];
            msg.extend(&u32::try_from(b.len()).unwrap().to_be_bytes()[1..]);
            msg.extend(b);
            msg
        }
        /// The hello split into records of at most `chunk` payload bytes.
        pub(crate) fn records(&self, chunk: usize) -> Vec<u8> {
            let msg = self.body();
            let mut out = Vec::new();
            for part in msg.chunks(chunk) {
                out.extend([22, 3, 1]);
                out.extend(u16::try_from(part.len()).unwrap().to_be_bytes());
                out.extend(part);
            }
            out
        }
    }

    fn complete(input: &[u8]) -> ClientHelloView<'_> {
        match HelloParser::parse(input, &HelloLimits::new()).unwrap() {
            HelloParse::Complete { view, length } => {
                assert_eq!(length, input.len());
                view
            }
            HelloParse::Incomplete { needed } => panic!("incomplete, needs {needed}"),
        }
    }

    #[test]
    fn test_limit_assigned_out_of_range_is_held_to_its_range() {
        // The fields are public: an assignment skips the setter's check. The
        // parser must not index past its 128-entry extension array (D-128).
        let mut limits = HelloLimits::new();
        limits.max_extensions = 200;
        let mut b = HelloBuilder::new();
        for typ in 0..129u16 {
            b = b.ext(0xfe00 + typ, Vec::new());
        }
        let records = b.records(16_000);
        assert!(matches!(
            HelloParser::parse(&records, &limits),
            Err(TlsError::HelloOverBudget { .. })
        ));
    }

    #[test]
    fn test_parse_fields_one_record() {
        let h = HelloBuilder::new()
            .sni(b"Example.TEST")
            .alpn(&[b"h2", b"http/1.1"])
            .records(16_384);
        let v = complete(&h);
        assert_eq!(v.server_name(), Some("Example.TEST"));
        assert_eq!(v.normalized_server_name().unwrap().as_str(), "example.test");
        assert_eq!(
            v.alpn().collect::<Vec<_>>(),
            [b"h2".as_slice(), b"http/1.1"]
        );
        assert_eq!(v.cipher_suites().collect::<Vec<_>>(), [0x1301, 0x1302]);
        assert_eq!(v.extension_types().collect::<Vec<_>>(), [0, 16]);
        assert_eq!(v.first_alpn_ends(), Some((b'h', b'2')));
        assert!(v.raw().is_some());
    }

    #[test]
    fn test_parse_split_every_record_size_same_view() {
        let b = HelloBuilder::new().sni(b"a.example.test").alpn(&[b"h2"]);
        let one = b.records(16_384);
        let v1 = complete(&one);
        for chunk in [b.body().len().div_ceil(4), 40, 64, 100] {
            let many = b.records(chunk);
            let v = complete(&many);
            assert_eq!(
                v.normalized_server_name(),
                v1.normalized_server_name(),
                "chunk {chunk}"
            );
            assert_eq!(
                v.cipher_suites().collect::<Vec<_>>(),
                v1.cipher_suites().collect::<Vec<_>>()
            );
            assert_eq!(
                v.extension_types().collect::<Vec<_>>(),
                v1.extension_types().collect::<Vec<_>>()
            );
            assert_eq!(v.first_alpn_ends(), v1.first_alpn_ends());
        }
    }

    #[test]
    fn test_parse_every_prefix_incomplete_or_error_never_panics() {
        let h = HelloBuilder::new().sni(b"a.example.test").records(50);
        for n in 0..h.len() {
            match HelloParser::parse(&h[..n], &HelloLimits::new()) {
                Ok(HelloParse::Incomplete { needed }) => assert!(needed > n),
                Ok(HelloParse::Complete { .. }) => panic!("complete at {n}"),
                Err(TlsError::HelloTooFragmented) => {}
                Err(e) => panic!("{e} at {n}"),
            }
        }
    }

    #[test]
    fn test_parse_incomplete_exact_after_header() {
        let h = HelloBuilder::new().records(16_384);
        assert!(
            matches!(HelloParser::parse(&h[..9], &HelloLimits::new()), Ok(HelloParse::Incomplete { needed }) if needed == h.len())
        );
    }

    #[test]
    fn test_any_03xx_record_version_accepted_d110() {
        let hello = HelloBuilder::new().records(16_384);
        for minor in [0u8, 1, 2, 3, 4, 0xff] {
            let mut h = hello.clone();
            h[2] = minor;
            match HelloParser::parse(&h, &HelloLimits::new()) {
                Ok(HelloParse::Complete { view, .. }) => {
                    assert_eq!(view.record_version(), 0x0300 | u16::from(minor));
                }
                other => panic!("record version 0x03{minor:02x}: {other:?}"),
            }
        }
    }

    #[test]
    fn test_parse_refusals() {
        let l = HelloLimits::new();
        assert_eq!(
            HelloParser::parse(b"\x80\x2e\x01", &l).unwrap_err(),
            TlsError::NotTls
        );
        assert_eq!(
            HelloParser::parse(b"PROXY TCP4 ", &l).unwrap_err(),
            TlsError::NotTls
        );
        assert_eq!(
            HelloParser::parse(b"\x15\x03\x03\x00\x02\x02\x28", &l).unwrap_err(),
            TlsError::BadRecord
        );
        for version in [[2u8, 0], [4, 1], [0, 0], [0xff, 0xff]] {
            let header = [22, version[0], version[1], 0, 0x10];
            assert_eq!(
                HelloParser::parse(&header, &l).unwrap_err(),
                TlsError::BadRecord,
                "{version:?}"
            );
        }
        assert_eq!(
            HelloParser::parse(b"\x16\x03\x01\x00\x00", &l).unwrap_err(),
            TlsError::BadRecord
        );
        assert_eq!(
            HelloParser::parse(b"\x16\x03\x01\x40\x01", &l).unwrap_err(),
            TlsError::BadRecord
        );
        let mut big = vec![22, 3, 1, 0x40, 0];
        big.extend([1, 0, 0x40, 1]);
        assert_eq!(
            HelloParser::parse(&big, &l).unwrap_err(),
            TlsError::HelloTooLarge
        );
        let frag = HelloBuilder::new().records(20);
        assert_eq!(
            HelloParser::parse(&frag, &l).unwrap_err(),
            TlsError::HelloTooFragmented
        );
        let dup = HelloBuilder::new()
            .sni(b"a.test")
            .sni(b"b.test")
            .records(16_384);
        assert_eq!(
            HelloParser::parse(&dup, &l).unwrap_err(),
            TlsError::DuplicateExtension
        );
        let psk_not_last = HelloBuilder::new()
            .ext(41, vec![0, 0])
            .sni(b"a.test")
            .records(16_384);
        assert_eq!(
            HelloParser::parse(&psk_not_last, &l).unwrap_err(),
            TlsError::HelloMalformed
        );
    }

    #[test]
    fn test_parse_budgets_at_n_and_n_plus_one() {
        let l = HelloLimits::new().max_ciphers(4).unwrap();
        let mut b = HelloBuilder::new();
        b.ciphers = vec![1, 2, 3, 4];
        assert!(HelloParser::parse(&b.records(16_384), &l).is_ok());
        b.ciphers.push(5);
        assert_eq!(
            HelloParser::parse(&b.records(16_384), &l).unwrap_err(),
            TlsError::HelloOverBudget {
                what: "cipher suite"
            }
        );

        let names: Vec<&[u8]> = vec![b"x"; 32];
        assert!(
            HelloParser::parse(
                &HelloBuilder::new().alpn(&names).records(16_384),
                &HelloLimits::new()
            )
            .is_ok()
        );
        let names: Vec<&[u8]> = vec![b"x"; 33];
        assert_eq!(
            HelloParser::parse(
                &HelloBuilder::new().alpn(&names).records(16_384),
                &HelloLimits::new()
            )
            .unwrap_err(),
            TlsError::HelloOverBudget { what: "ALPN" }
        );
        let mut many = HelloBuilder::new();
        for t in 0..64u16 {
            many = many.ext(0x7000 + t, vec![]);
        }
        assert!(HelloParser::parse(&many.records(16_384), &HelloLimits::new()).is_ok());
        let many = many.ext(0x7100, vec![]);
        assert_eq!(
            HelloParser::parse(&many.records(16_384), &HelloLimits::new()).unwrap_err(),
            TlsError::HelloOverBudget { what: "extension" }
        );
    }

    #[test]
    fn test_parse_budgets_at_n_minus_one_n_n_plus_one_t14() {
        let parse = |b: &HelloBuilder, l: &HelloLimits| {
            HelloParser::parse(&b.records(16_384), l).map(|_| ())
        };
        // Cipher suites, limit 4.
        let l = HelloLimits::new().max_ciphers(4).unwrap();
        for (n, ok) in [(3u16, true), (4, true), (5, false)] {
            let mut b = HelloBuilder::new();
            b.ciphers = (1..=n).collect();
            assert_eq!(parse(&b, &l).is_ok(), ok, "{n} cipher suites");
        }
        // ALPN names, default limit 32.
        for (n, ok) in [(31, true), (32, true), (33, false)] {
            let names: Vec<&[u8]> = vec![b"x"; n];
            let b = HelloBuilder::new().alpn(&names);
            assert_eq!(parse(&b, &HelloLimits::new()).is_ok(), ok, "{n} ALPN names");
        }
        // Extensions, default limit 64.
        for (n, ok) in [(63u16, true), (64, true), (65, false)] {
            let mut b = HelloBuilder::new();
            for t in 0..n {
                b = b.ext(0x7000 + t, vec![]);
            }
            assert_eq!(parse(&b, &HelloLimits::new()).is_ok(), ok, "{n} extensions");
        }
        // The hello's length, default limit 16 KiB, padded with extension 21.
        let max = HelloLimits::new().max_hello_bytes as usize;
        let bare = HelloBuilder::new().ext(21, vec![]).body().len() - 4;
        for (len, ok) in [(max - 1, true), (max, true), (max + 1, false)] {
            let b = HelloBuilder::new().ext(21, vec![0; len - bare]);
            assert_eq!(b.body().len() - 4, len);
            let r = parse(&b, &HelloLimits::new());
            assert_eq!(r.is_ok(), ok, "a {len}-byte hello: {r:?}");
            if !ok {
                assert_eq!(r.unwrap_err(), TlsError::HelloTooLarge);
            }
        }
        // Records, default limit 4: a 400-byte hello in 3, 4, and 5 records.
        let bare = HelloBuilder::new().ext(21, vec![]).body().len();
        let b = HelloBuilder::new().ext(21, vec![0; 400 - bare]);
        assert_eq!(b.body().len(), 400);
        for (chunk, records, ok) in [(134, 3, true), (100, 4, true), (80, 5, false)] {
            let wire = b.records(chunk);
            assert_eq!(wire.len(), 400 + 5 * records);
            let r = HelloParser::parse(&wire, &HelloLimits::new());
            assert_eq!(r.is_ok(), ok, "{records} records: {r:?}");
            if !ok {
                assert_eq!(r.unwrap_err(), TlsError::HelloTooFragmented);
            }
        }
    }

    #[test]
    fn test_parse_bad_sni_shapes() {
        let l = HelloLimits::new();
        for bad in [vec![0, 0], vec![0, 3, 0, 0, 0], vec![0, 4, 1, 0, 1, b'a']] {
            let h = HelloBuilder::new().ext(0, bad).records(16_384);
            assert_eq!(
                HelloParser::parse(&h, &l).unwrap_err(),
                TlsError::HelloMalformed
            );
        }
        let ctrl = HelloBuilder::new().sni(b"a\r\nb.test").records(16_384);
        let v = complete(&ctrl);
        assert!(
            v.server_name().is_none()
                && v.normalized_server_name().is_none()
                && v.has_server_name()
        );
        let ip = HelloBuilder::new().sni(b"10.0.0.1").records(16_384);
        assert!(complete(&ip).normalized_server_name().is_none());
    }

    #[test]
    fn test_parse_trailing_bytes_refused() {
        let mut h = HelloBuilder::new().records(16_384);
        h[4] += 1;
        h.push(0);
        assert_eq!(
            HelloParser::parse(&h, &HelloLimits::new()).unwrap_err(),
            TlsError::HelloMalformed
        );
    }

    #[test]
    fn test_is_grease_all_sixteen() {
        let n = (0..=u16::MAX).filter(|v| is_grease(*v)).count();
        assert_eq!(n, 16);
    }
}
