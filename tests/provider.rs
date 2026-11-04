//! T-28: a process-default rustls provider installed by another crate never
//! changes tls-net's provider (D-043). Its own test binary, because the
//! default is process-wide.

#![cfg(feature = "aws-lc")]

mod common;

use common::{End, data, pump};
use tls_net::{ClientBuilder, Group, KeySource, TlsServer, TrustAnchors};

#[test]
fn test_t28_process_default_provider_is_ignored() {
    // Another crate installs a provider that only knows secp384r1.
    let mut other = rustls::crypto::aws_lc_rs::default_provider();
    other.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP384R1];
    other.install_default().unwrap();

    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap();
    let client = ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .build()
        .unwrap();
    assert!(server.provider_name().starts_with("aws-lc-rs"));
    let (mut s, mut c) = (
        server.accept().unwrap(),
        client.connect("localhost").unwrap(),
    );
    let (mut se, mut ce) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut s, &mut se, &mut c, &mut ce);
    assert!(se.complete && ce.complete);
    // tls-net's own provider still offers X25519MLKEM768 first.
    assert_eq!(s.info().unwrap().group, Some(Group::X25519MlKem768));
}
