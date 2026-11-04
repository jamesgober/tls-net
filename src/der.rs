//! A bounded DER reader for X.509 facts: validity, names, key type and size,
//! extended key usage, signature algorithm, issuer and subject.
//!
//! It is used for load-time checks, expiry reports, and `PeerIdentity`. It
//! never decides whether a chain is trusted; rustls-webpki does. Every length
//! is checked against the remaining input before use, so it cannot read past
//! its input and never panics (fuzz target `der_fields`).

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Maximum subject alternative names kept per certificate.
const MAX_NAMES: usize = 1024;

/// A DER element: its tag and contents.
#[derive(Clone, Copy, Debug)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// A forward-only reader over DER bytes.
#[derive(Clone, Copy, Debug)]
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Reads one element. Only definite lengths of at most four bytes.
    fn next(&mut self) -> Option<Tlv<'a>> {
        let (&tag, rest) = self.rest.split_first()?;
        // Multi-byte tags do not occur in the structures read here.
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = len.checked_mul(256)?.checked_add(usize::from(b))?;
            }
            rest = &rest[n..];
            len
        };
        if rest.len() < len {
            return None;
        }
        let (value, after) = rest.split_at(len);
        self.rest = after;
        Some(Tlv { tag, value })
    }

    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let tlv = self.next()?;
        (tlv.tag == tag).then_some(tlv.value)
    }

    /// Reads an element if it has `tag`; leaves the reader alone otherwise.
    fn optional(&mut self, tag: u8) -> Option<&'a [u8]> {
        let mut probe = *self;
        let tlv = probe.next()?;
        if tlv.tag == tag {
            *self = probe;
            Some(tlv.value)
        } else {
            None
        }
    }

    /// The raw bytes of the next element (tag and length included).
    fn raw_next(&mut self) -> Option<&'a [u8]> {
        let start = self.rest;
        self.next()?;
        let used = start.len() - self.rest.len();
        Some(&start[..used])
    }
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
/// Signature algorithms refused on certificates: MD2, MD5, SHA-1 with RSA,
/// ECDSA with SHA-1, DSA with SHA-1.
const WEAK_SIGNATURES: &[&[u8]] = &[
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01],
    &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03],
];

/// The public key algorithm of a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyAlg {
    EcdsaP256,
    EcdsaP384,
    EcdsaOther,
    Ed25519,
    Rsa { bits: u32 },
    Other,
}

/// What the extended key usage extension allows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Eku {
    pub(crate) server: bool,
    pub(crate) client: bool,
    pub(crate) any: bool,
}

/// Facts read from one certificate.
#[derive(Clone, Debug)]
pub(crate) struct CertFacts<'a> {
    pub(crate) serial: &'a [u8],
    pub(crate) issuer: &'a [u8],
    pub(crate) subject: &'a [u8],
    pub(crate) not_before: SystemTime,
    pub(crate) not_after: SystemTime,
    /// The whole SubjectPublicKeyInfo (for SPKI pins).
    pub(crate) spki: &'a [u8],
    pub(crate) key: KeyAlg,
    pub(crate) weak_signature: bool,
    pub(crate) dns_names: Vec<&'a str>,
    pub(crate) ip_addresses: Vec<IpAddr>,
    pub(crate) uri_names: Vec<&'a str>,
    /// `None` when the certificate has no EKU extension.
    pub(crate) eku: Option<Eku>,
}

/// What an OCSP response says about its first certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OcspFacts {
    /// `certStatus` is `good`.
    pub(crate) good: bool,
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: Option<SystemTime>,
}

/// Reads an OCSPResponse (RFC 6960): `successful`, a BasicOCSPResponse, and
/// the first SingleResponse's status and update times. `None` if malformed.
/// The response's signature is checked by the client, not here.
pub(crate) fn ocsp_facts(der: &[u8]) -> Option<OcspFacts> {
    let mut outer = Reader::new(der);
    let mut resp = Reader::new(outer.expect(SEQUENCE)?);
    if !outer.is_empty() {
        return None;
    }
    // responseStatus ENUMERATED: 0 = successful.
    if resp.expect(0x0a)? != [0] {
        return None;
    }
    let mut bytes = Reader::new(Reader::new(resp.expect(0xa0)?).expect(SEQUENCE)?);
    bytes.expect(OID)?;
    let basic = bytes.expect(OCTET_STRING)?;
    let mut basic = Reader::new(Reader::new(basic).expect(SEQUENCE)?);
    let mut data = Reader::new(basic.expect(SEQUENCE)?);
    data.optional(0xa0); // version
    data.next()?; // responderID
    data.expect(GENERALIZED_TIME)?; // producedAt
    let mut responses = Reader::new(data.expect(SEQUENCE)?);
    let mut single = Reader::new(responses.expect(SEQUENCE)?);
    single.expect(SEQUENCE)?; // certID
    let status = single.next()?;
    let this_update = time(single.next()?)?;
    let next_update = match single.optional(0xa0) {
        Some(inner) => Some(time(Reader::new(inner).next()?)?),
        None => None,
    };
    Some(OcspFacts {
        good: status.tag == 0x80,
        this_update,
        next_update,
    })
}

/// The form of a DER private key, from its structure: PKCS#8 is
/// `SEQUENCE { INTEGER 0, SEQUENCE alg, OCTET STRING }`, PKCS#1 is
/// `SEQUENCE { INTEGER 0, INTEGER n, .. }`, SEC1 is
/// `SEQUENCE { INTEGER 1, OCTET STRING, .. }`.
pub(crate) fn key_form(der: &[u8]) -> Option<KeyForm> {
    let mut outer = Reader::new(der);
    let body = outer.expect(SEQUENCE)?;
    if !outer.is_empty() {
        return None;
    }
    let mut r = Reader::new(body);
    let version = r.expect(INTEGER)?;
    let next = r.next()?;
    match (version, next.tag) {
        ([0], SEQUENCE) => Some(KeyForm::Pkcs8),
        ([0], INTEGER) => Some(KeyForm::Pkcs1),
        ([1], OCTET_STRING) => Some(KeyForm::Sec1),
        _ => None,
    }
}

/// A private key's DER form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyForm {
    Pkcs8,
    Pkcs1,
    Sec1,
}

/// Reads the facts of one DER certificate. `None` if it is malformed.
pub(crate) fn parse_certificate(der: &[u8]) -> Option<CertFacts<'_>> {
    let mut outer = Reader::new(der);
    let cert = outer.expect(SEQUENCE)?;
    if !outer.is_empty() {
        return None;
    }
    let mut cert = Reader::new(cert);
    let tbs = cert.expect(SEQUENCE)?;
    let sig_alg = cert.expect(SEQUENCE)?;
    cert.expect(BIT_STRING)?;
    if !cert.is_empty() {
        return None;
    }
    let weak_signature = {
        let mut r = Reader::new(sig_alg);
        let oid = r.expect(OID)?;
        WEAK_SIGNATURES.contains(&oid)
    };

    let mut tbs = Reader::new(tbs);
    tbs.optional(0xa0); // version
    let serial = tbs.expect(INTEGER)?;
    tbs.expect(SEQUENCE)?; // signature
    let issuer = tbs.raw_next()?;
    let validity = tbs.expect(SEQUENCE)?;
    let subject = tbs.raw_next()?;
    let spki = tbs.raw_next()?;
    tbs.optional(0x81);
    tbs.optional(0x82);
    let extensions = tbs.optional(0xa3);

    let (not_before, not_after) = {
        let mut v = Reader::new(validity);
        let nb = time(v.next()?)?;
        let na = time(v.next()?)?;
        (nb, na)
    };
    let key = key_alg(spki)?;

    let mut facts = CertFacts {
        serial,
        issuer,
        subject,
        not_before,
        not_after,
        spki,
        key,
        weak_signature,
        dns_names: Vec::new(),
        ip_addresses: Vec::new(),
        uri_names: Vec::new(),
        eku: None,
    };
    if let Some(ext) = extensions {
        let mut r = Reader::new(Reader::new(ext).expect(SEQUENCE)?);
        while !r.is_empty() {
            let mut e = Reader::new(r.expect(SEQUENCE)?);
            let oid = e.expect(OID)?;
            e.optional(BOOLEAN);
            let value = e.expect(OCTET_STRING)?;
            if oid == OID_SAN {
                names(value, &mut facts)?;
            } else if oid == OID_EKU {
                facts.eku = Some(eku(value)?);
            }
        }
    }
    Some(facts)
}

fn key_alg(spki: &[u8]) -> Option<KeyAlg> {
    let mut r = Reader::new(Reader::new(spki).expect(SEQUENCE)?);
    let mut alg = Reader::new(r.expect(SEQUENCE)?);
    let key_bits = r.expect(BIT_STRING)?;
    let oid = alg.expect(OID)?;
    Some(match oid {
        o if o == OID_EC_PUBLIC_KEY => match alg.expect(OID) {
            Some(c) if c == OID_P256 => KeyAlg::EcdsaP256,
            Some(c) if c == OID_P384 => KeyAlg::EcdsaP384,
            _ => KeyAlg::EcdsaOther,
        },
        o if o == OID_ED25519 => KeyAlg::Ed25519,
        o if o == OID_RSA || o == OID_RSA_PSS => {
            let (&unused, key) = key_bits.split_first()?;
            if unused != 0 {
                return None;
            }
            let mut k = Reader::new(Reader::new(key).expect(SEQUENCE)?);
            let modulus = k.expect(INTEGER)?;
            KeyAlg::Rsa {
                bits: integer_bits(modulus),
            }
        }
        _ => KeyAlg::Other,
    })
}

/// Bit length of a positive DER INTEGER.
fn integer_bits(int: &[u8]) -> u32 {
    let mut bytes = int;
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    match bytes.first() {
        None => 0,
        Some(&first) => {
            let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX / 8);
            len.saturating_mul(8).saturating_sub(first.leading_zeros())
        }
    }
}

fn names<'a>(value: &'a [u8], facts: &mut CertFacts<'a>) -> Option<()> {
    let mut r = Reader::new(Reader::new(value).expect(SEQUENCE)?);
    let mut count = 0usize;
    while !r.is_empty() {
        let name = r.next()?;
        count += 1;
        if count > MAX_NAMES {
            return None;
        }
        match name.tag {
            0x82 => facts.dns_names.push(std::str::from_utf8(name.value).ok()?),
            0x86 => facts.uri_names.push(std::str::from_utf8(name.value).ok()?),
            0x87 => match name.value.len() {
                4 => {
                    let b: [u8; 4] = name.value.try_into().ok()?;
                    facts.ip_addresses.push(IpAddr::from(b));
                }
                16 => {
                    let b: [u8; 16] = name.value.try_into().ok()?;
                    facts.ip_addresses.push(IpAddr::from(b));
                }
                _ => return None,
            },
            _ => {}
        }
    }
    Some(())
}

fn eku(value: &[u8]) -> Option<Eku> {
    let mut r = Reader::new(Reader::new(value).expect(SEQUENCE)?);
    let mut out = Eku::default();
    while !r.is_empty() {
        let oid = r.expect(OID)?;
        if oid == OID_SERVER_AUTH {
            out.server = true;
        } else if oid == OID_CLIENT_AUTH {
            out.client = true;
        } else if oid == OID_EKU_ANY {
            out.any = true;
        }
    }
    Some(out)
}

fn time(tlv: Tlv<'_>) -> Option<SystemTime> {
    let digits = |s: &[u8]| -> Option<i64> {
        s.iter().try_fold(0i64, |acc, &b| {
            b.is_ascii_digit().then(|| acc * 10 + i64::from(b - b'0'))
        })
    };
    let (year, rest) = match tlv.tag {
        UTC_TIME if tlv.value.len() == 13 => {
            let yy = digits(&tlv.value[..2])?;
            (
                if yy >= 50 { 1900 + yy } else { 2000 + yy },
                &tlv.value[2..],
            )
        }
        GENERALIZED_TIME if tlv.value.len() == 15 => (digits(&tlv.value[..4])?, &tlv.value[4..]),
        _ => return None,
    };
    if rest.get(10) != Some(&b'Z') {
        return None;
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let min = digits(&rest[6..8])?;
    let sec = digits(&rest[8..10])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + min * 60 + sec;
    if secs >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(secs).ok()?))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day number since 1970-01-01.
pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(name: &str) -> Vec<u8> {
        let pem = std::fs::read(format!(
            "{}/tests/data/{name}.pem",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        rustls::pki_types::pem::PemObject::pem_slice_iter(&pem)
            .map(|c: Result<rustls::pki_types::CertificateDer<'static>, _>| c.unwrap().to_vec())
            .next()
            .unwrap()
    }

    #[test]
    fn test_parse_certificate_site_facts() {
        let d = der("site");
        let f = parse_certificate(&d).unwrap();
        assert_eq!(f.key, KeyAlg::EcdsaP256);
        assert_eq!(f.dns_names, ["localhost", "example.test", "*.example.test"]);
        assert_eq!(f.ip_addresses, [IpAddr::from([127, 0, 0, 1])]);
        assert_eq!(
            f.eku,
            Some(Eku {
                server: true,
                client: false,
                any: false
            })
        );
        assert!(!f.weak_signature);
        let nb = f
            .not_before
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(nb, 1_767_225_600);
    }

    #[test]
    fn test_parse_certificate_key_sizes() {
        assert_eq!(
            parse_certificate(&der("site-rsa")).unwrap().key,
            KeyAlg::Rsa { bits: 2048 }
        );
        assert_eq!(
            parse_certificate(&der("rsa1024")).unwrap().key,
            KeyAlg::Rsa { bits: 1024 }
        );
        assert_eq!(
            parse_certificate(&der("p384")).unwrap().key,
            KeyAlg::EcdsaP384
        );
        assert_eq!(
            parse_certificate(&der("p521")).unwrap().key,
            KeyAlg::EcdsaOther
        );
        assert_eq!(
            parse_certificate(&der("ed25519")).unwrap().key,
            KeyAlg::Ed25519
        );
    }

    #[test]
    fn test_parse_certificate_sha1_is_weak() {
        assert!(parse_certificate(&der("sha1")).unwrap().weak_signature);
    }

    #[test]
    fn test_parse_certificate_eku_and_uri() {
        assert_eq!(parse_certificate(&der("no-eku")).unwrap().eku, None);
        let c = der("client");
        let f = parse_certificate(&c).unwrap();
        assert_eq!(f.uri_names, ["spiffe://test/client"]);
        assert!(f.eku.unwrap().client);
    }

    #[test]
    fn test_parse_certificate_truncated_every_length_is_none() {
        let d = der("site");
        for n in 0..d.len() {
            assert!(parse_certificate(&d[..n]).is_none(), "prefix {n}");
        }
        let mut long = d.clone();
        long.push(0);
        assert!(parse_certificate(&long).is_none());
    }

    #[test]
    fn test_integer_bits_leading_zero() {
        assert_eq!(integer_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(integer_bits(&[0x01]), 1);
        assert_eq!(integer_bits(&[]), 0);
    }

    #[test]
    fn test_civil_round_trip() {
        for days in [-719_468, -1, 0, 1, 10_957, 20_454, 47_482, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
    }

    #[test]
    fn test_time_utc_and_generalized() {
        let t = time(Tlv {
            tag: UTC_TIME,
            value: b"260101000000Z",
        })
        .unwrap();
        let g = time(Tlv {
            tag: GENERALIZED_TIME,
            value: b"20260101000000Z",
        })
        .unwrap();
        assert_eq!(t, g);
        assert!(
            time(Tlv {
                tag: UTC_TIME,
                value: b"261301000000Z"
            })
            .is_none()
        );
        assert!(
            time(Tlv {
                tag: UTC_TIME,
                value: b"26010100000+Z"
            })
            .is_none()
        );
    }
}
