//! Size-gated certificate and key intake over rustls-pki-types (D-008).
//!
//! tls-net adds the size gate, the Unix permission check, a label scan (so an
//! encrypted key is named rather than reported as "no key"), and key
//! counting. Every buffer that holds key bytes is wiped when dropped.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crypt_io::Zeroizing;
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

use crate::error::TlsError;

/// A private key in DER form, wiped on drop.
pub(crate) struct KeyDer {
    der: Zeroizing<Vec<u8>>,
    kind: KeyKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyKind {
    Pkcs8,
    Pkcs1,
    Sec1,
}

impl KeyDer {
    /// A borrowed view for the provider; no copy.
    pub(crate) fn as_der(&self) -> PrivateKeyDer<'_> {
        match self.kind {
            KeyKind::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.der.as_slice())),
            KeyKind::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(self.der.as_slice())),
            KeyKind::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(self.der.as_slice())),
        }
    }
}

impl std::fmt::Debug for KeyDer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyDer({:?}, {} bytes)", self.kind, self.der.len())
    }
}

/// Reads a file with the size gate (metadata first, then a bounded read) and,
/// for keys on Unix, the permission check (FR-49).
pub(crate) fn read_file(
    path: &Path,
    limit: u32,
    is_key: bool,
    allow_group_readable: bool,
) -> Result<Zeroizing<Vec<u8>>, TlsError> {
    let io = |e: std::io::Error| TlsError::Io {
        path: path.to_path_buf(),
        kind: e.kind(),
    };
    let file = File::open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    let too_large = || TlsError::FileTooLarge {
        path: path.to_path_buf(),
        limit: u64::from(limit),
    };
    if meta.len() > u64::from(limit) {
        return Err(too_large());
    }
    if is_key && !allow_group_readable {
        check_permissions(path, &meta)?;
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0)));
    // Bounded by the same limit in case the file grew after the metadata call.
    file.take(u64::from(limit) + 1)
        .read_to_end(&mut buf)
        .map_err(io)?;
    if buf.len() > limit as usize {
        return Err(too_large());
    }
    Ok(buf)
}

#[cfg(unix)]
fn check_permissions(path: &Path, meta: &std::fs::Metadata) -> Result<(), TlsError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(TlsError::KeyFilePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Windows: the ACL check is P3 (D-028); `docs/PLATFORM-NOTES.md` says so.
#[cfg(not(unix))]
fn check_permissions(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), TlsError> {
    Ok(())
}

/// Every `CERTIFICATE` block in `pem`, at most `max` of them.
pub(crate) fn certificates(
    pem: &[u8],
    max: usize,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut out = Vec::new();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|_| TlsError::PemInvalid {
            what: "certificate PEM",
        })?;
        if out.len() == max {
            let len = max + 1 + CertificateDer::pem_slice_iter(pem).skip(max + 1).count();
            return Err(TlsError::ChainTooLong { len, limit: max });
        }
        out.push(cert);
    }
    if out.is_empty() {
        return Err(TlsError::NoCertificate);
    }
    Ok(out)
}

/// DER certificates, at most `max`.
pub(crate) fn certificates_der(
    der: &[&[u8]],
    max: usize,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    if der.is_empty() {
        return Err(TlsError::NoCertificate);
    }
    if der.len() > max {
        return Err(TlsError::ChainTooLong {
            len: der.len(),
            limit: max,
        });
    }
    Ok(der
        .iter()
        .map(|d| CertificateDer::from(d.to_vec()))
        .collect())
}

/// Exactly one private key from PEM.
pub(crate) fn key_from_pem(pem: &[u8]) -> Result<KeyDer, TlsError> {
    let mut keys = 0usize;
    for label in labels(pem) {
        match label {
            b"ENCRYPTED PRIVATE KEY" => return Err(TlsError::EncryptedPrivateKey),
            b"PRIVATE KEY" | b"RSA PRIVATE KEY" | b"EC PRIVATE KEY" => keys += 1,
            _ => {}
        }
    }
    match keys {
        0 => return Err(TlsError::NoPrivateKey),
        1 => {}
        _ => return Err(TlsError::MultiplePrivateKeys),
    }
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        let (kind, der) = section.map_err(|_| TlsError::PemInvalid {
            what: "private key PEM",
        })?;
        let der = Zeroizing::new(der);
        let kind = match kind {
            SectionKind::PrivateKey => KeyKind::Pkcs8,
            SectionKind::RsaPrivateKey => KeyKind::Pkcs1,
            SectionKind::EcPrivateKey => KeyKind::Sec1,
            _ => continue,
        };
        return Ok(KeyDer { der, kind });
    }
    Err(TlsError::NoPrivateKey)
}

/// A private key from DER; the form (PKCS#8, PKCS#1, SEC1) is detected.
pub(crate) fn key_from_der(der: &[u8]) -> Result<KeyDer, TlsError> {
    use crate::der::KeyForm;
    let kind = match crate::der::key_form(der) {
        Some(KeyForm::Pkcs8) => KeyKind::Pkcs8,
        Some(KeyForm::Pkcs1) => KeyKind::Pkcs1,
        Some(KeyForm::Sec1) => KeyKind::Sec1,
        None => {
            return Err(TlsError::PemInvalid {
                what: "private key DER",
            });
        }
    };
    Ok(KeyDer {
        der: Zeroizing::new(der.to_vec()),
        kind,
    })
}

/// The labels of every `-----BEGIN <label>-----` line.
fn labels(pem: &[u8]) -> impl Iterator<Item = &[u8]> {
    pem.split(|&b| b == b'\n').filter_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        line.strip_prefix(b"-----BEGIN ")?.strip_suffix(b"-----")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn test_key_from_pem_forms() {
        assert_eq!(
            key_from_pem(&data("site.key")).unwrap().kind,
            KeyKind::Pkcs8
        );
        assert_eq!(
            key_from_pem(&data("site-rsa.pkcs1.key")).unwrap().kind,
            KeyKind::Pkcs1
        );
        assert_eq!(
            key_from_pem(&data("site.sec1.key")).unwrap().kind,
            KeyKind::Sec1
        );
    }

    #[test]
    fn test_key_from_pem_encrypted_named() {
        assert_eq!(
            key_from_pem(&data("site.encrypted.key")).unwrap_err(),
            TlsError::EncryptedPrivateKey
        );
    }

    #[test]
    fn test_key_from_pem_none_and_two() {
        assert_eq!(
            key_from_pem(&data("site.pem")).unwrap_err(),
            TlsError::NoPrivateKey
        );
        assert_eq!(key_from_pem(b"").unwrap_err(), TlsError::NoPrivateKey);
        let mut two = data("site.key");
        two.extend(data("api.key"));
        assert_eq!(
            key_from_pem(&two).unwrap_err(),
            TlsError::MultiplePrivateKeys
        );
    }

    #[test]
    fn test_key_from_pem_bad_base64() {
        let bad = b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            key_from_pem(bad).unwrap_err(),
            TlsError::PemInvalid {
                what: "private key PEM"
            }
        );
    }

    #[test]
    fn test_key_from_der_detects_form() {
        assert_eq!(
            key_from_der(&data("site.key.der")).unwrap().kind,
            KeyKind::Pkcs8
        );
        assert!(key_from_der(b"\x30\x00").is_err());
    }

    #[test]
    fn test_certificates_count_and_limit() {
        assert_eq!(certificates(&data("site.pem"), 10).unwrap().len(), 2);
        assert_eq!(
            certificates(&data("site.pem"), 1).unwrap_err(),
            TlsError::ChainTooLong { len: 2, limit: 1 }
        );
        assert_eq!(
            certificates(b"# only a comment\n", 10).unwrap_err(),
            TlsError::NoCertificate
        );
    }

    #[test]
    fn test_read_file_size_gate() {
        let dir = std::env::temp_dir().join(format!("tls-net-pem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("big.pem");
        std::fs::write(&p, vec![b'a'; 101]).unwrap();
        assert!(matches!(
            read_file(&p, 100, false, false),
            Err(TlsError::FileTooLarge { limit: 100, .. })
        ));
        assert_eq!(read_file(&p, 101, false, false).unwrap().len(), 101);
        let missing = dir.join("missing.pem");
        assert!(matches!(
            read_file(&missing, 100, false, false),
            Err(TlsError::Io { .. })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_read_file_key_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tls-net-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k.key");
        std::fs::write(&p, data("site.key")).unwrap();
        for (mode, ok) in [(0o600, true), (0o400, true), (0o640, false), (0o644, false)] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let r = read_file(&p, 65_536, true, false);
            assert_eq!(r.is_ok(), ok, "mode {mode:o}");
            if !ok {
                assert!(
                    matches!(r, Err(TlsError::KeyFilePermissions { mode: m, .. }) if m == mode)
                );
                assert!(read_file(&p, 65_536, true, true).is_ok());
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
