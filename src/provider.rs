//! The crypto provider, chosen at build time by feature and passed explicitly
//! to every rustls configuration. tls-net never reads or installs rustls's
//! process-default provider (D-043, T-28).

use rustls::SupportedCipherSuite;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};

/// Every cipher suite and group the build's provider implements, in the
/// provider's preference order, or `None` without a provider feature.
pub(crate) struct ProviderParts {
    pub(crate) base: CryptoProvider,
    pub(crate) all_suites: &'static [SupportedCipherSuite],
    pub(crate) all_groups: &'static [&'static dyn SupportedKxGroup],
    pub(crate) name: &'static str,
}

#[cfg(all(feature = "aws-lc", not(feature = "fips")))]
pub(crate) fn parts() -> Option<ProviderParts> {
    use rustls::crypto::aws_lc_rs as p;
    Some(ProviderParts {
        base: p::default_provider(),
        all_suites: p::ALL_CIPHER_SUITES,
        all_groups: p::ALL_KX_GROUPS,
        name: "aws-lc-rs",
    })
}

/// FIPS builds take only the provider's default (approved) suites and groups.
#[cfg(feature = "fips")]
pub(crate) fn parts() -> Option<ProviderParts> {
    use rustls::crypto::aws_lc_rs as p;
    Some(ProviderParts {
        base: rustls::crypto::default_fips_provider(),
        all_suites: p::DEFAULT_CIPHER_SUITES,
        all_groups: p::DEFAULT_KX_GROUPS,
        name: "aws-lc-rs (FIPS)",
    })
}

#[cfg(all(feature = "ring", not(feature = "aws-lc")))]
pub(crate) fn parts() -> Option<ProviderParts> {
    use rustls::crypto::ring as p;
    Some(ProviderParts {
        base: p::default_provider(),
        all_suites: p::ALL_CIPHER_SUITES,
        all_groups: p::ALL_KX_GROUPS,
        name: "ring",
    })
}

#[cfg(not(any(feature = "aws-lc", feature = "ring")))]
pub(crate) fn parts() -> Option<ProviderParts> {
    None
}

/// The provider this build uses: `"aws-lc-rs"`, `"ring"`, or `None` in a build
/// without a provider feature. Installing a process-default rustls provider
/// elsewhere never changes it.
///
/// ```
/// # #[cfg(feature = "aws-lc")]
/// assert_eq!(tls_net::default_provider_name(), Some("aws-lc-rs"));
/// ```
#[must_use]
pub fn default_provider_name() -> Option<&'static str> {
    parts().map(|p| p.name)
}

/// Parses a private key into a signing key, borrowing the DER so the only
/// copy stays in tls-net's wiped buffer.
#[cfg(feature = "aws-lc")]
pub(crate) fn load_key(
    der: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, crate::error::TlsError> {
    rustls::crypto::aws_lc_rs::sign::any_supported_type(der)
        .map_err(|_| crate::error::TlsError::UnsupportedKeyType)
}

/// Parses a private key into a signing key, borrowing the DER so the only
/// copy stays in tls-net's wiped buffer.
#[cfg(all(feature = "ring", not(feature = "aws-lc")))]
pub(crate) fn load_key(
    der: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, crate::error::TlsError> {
    rustls::crypto::ring::sign::any_supported_type(der)
        .map_err(|_| crate::error::TlsError::UnsupportedKeyType)
}

/// Without a provider no key can be loaded.
#[cfg(not(any(feature = "aws-lc", feature = "ring")))]
pub(crate) fn load_key(
    _der: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, crate::error::TlsError> {
    Err(crate::error::TlsError::NoProvider)
}
