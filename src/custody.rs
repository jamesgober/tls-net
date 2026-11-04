//! Private keys held in key-vault (FR-15, PLAN 6.6).
//!
//! `Resident`: the key's DER exists only inside the vault's scoped callback;
//! the provider parses it once and keeps the parsed key for the life of the
//! entry. `PerSignature`: the key is fetched and parsed for every signature
//! and dropped afterwards, so no parsed key stays between handshakes.

use std::fmt;
use std::sync::Arc;

use rustls::pki_types::{
    PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    SubjectPublicKeyInfoDer,
};
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use crate::der::{KeyForm, key_form};
use crate::error::TlsError;

/// How a key from key-vault is held (D-009).
///
/// ```
/// assert_eq!(tls_net::KeyCustody::default(), tls_net::KeyCustody::Resident);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KeyCustody {
    /// Parsed once into the provider (default).
    #[default]
    Resident,
    /// Fetched and parsed for every signature [est. 10 to 30 µs per ECDSA
    /// P-256 handshake, 50 to 150 µs for RSA-2048].
    PerSignature,
}

/// A borrowed private key over bytes from the vault: no copy.
fn borrowed(der: &[u8]) -> Option<PrivateKeyDer<'_>> {
    Some(match key_form(der)? {
        KeyForm::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
        KeyForm::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
        KeyForm::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
    })
}

/// Parses the key inside the vault's callback. A vault built with BLAKE3
/// normalisation hands out a 32-byte digest, which is not a key.
fn parse(der: &[u8]) -> Result<Arc<dyn SigningKey>, TlsError> {
    let key = borrowed(der).ok_or(TlsError::VaultKeyUnusable)?;
    crate::provider::load_key(&key).map_err(|e| match e {
        TlsError::NoProvider => TlsError::NoProvider,
        _ => TlsError::VaultKeyUnusable,
    })
}

fn vault_error(e: &key_vault::Error) -> TlsError {
    let kind = match e {
        key_vault::Error::LockedOut => "locked out",
        key_vault::Error::KeyNotFound => "key not found",
        _ => "access failed",
    };
    TlsError::Vault { kind }
}

/// Loads a key from the vault under the given custody.
pub(crate) fn load(
    vault: &Arc<key_vault::KeyVault>,
    handle: key_vault::KeyHandle,
    custody: KeyCustody,
) -> Result<Arc<dyn SigningKey>, TlsError> {
    let resident = vault
        .with_key(handle, parse)
        .map_err(|e| vault_error(&e))??;
    match custody {
        KeyCustody::Resident => Ok(resident),
        KeyCustody::PerSignature => {
            let public = resident.public_key().map(|k| k.into_owned());
            let algorithm = resident.algorithm();
            drop(resident);
            Ok(Arc::new(VaultSigningKey {
                vault: Arc::clone(vault),
                handle,
                algorithm,
                public,
            }))
        }
    }
}

/// A signing key that is fetched and parsed for each signature.
struct VaultSigningKey {
    vault: Arc<key_vault::KeyVault>,
    handle: key_vault::KeyHandle,
    algorithm: SignatureAlgorithm,
    public: Option<SubjectPublicKeyInfoDer<'static>>,
}

impl fmt::Debug for VaultSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningKey for VaultSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // The parsed key lives in the signer for this one signature only.
        self.vault
            .with_key(self.handle, |der| parse(der).ok()?.choose_scheme(offered))
            .ok()
            .flatten()
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.public
            .as_ref()
            .map(|k| SubjectPublicKeyInfoDer::from(k.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}
