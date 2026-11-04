//! Interoperability with other TLS stacks: OpenSSL `s_client` and curl
//! against a tls-net server. Opt-in (`TLS_NET_INTEROP=1`), because it needs
//! the `openssl` and `curl` binaries; CI runs it on Linux.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{data, spawn_https};
use tls_net::{Alpn, KeySource, Policy, TlsServer};

fn enabled() -> bool {
    std::env::var_os("TLS_NET_INTEROP").is_some()
}

fn server(policy: Policy) -> std::net::SocketAddr {
    let s = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .alpn(&[Alpn::HTTP_1_1])
        .policy(policy)
        .build()
        .unwrap();
    spawn_https(s)
}

fn s_client(addr: std::net::SocketAddr, extra: &[&str]) -> String {
    let ca = format!("{}/tests/data/ca.pem", env!("CARGO_MANIFEST_DIR"));
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &addr.to_string(),
            "-servername",
            "localhost",
            "-CAfile",
            &ca,
        ])
        .args(["-verify_return_error", "-brief", "-ign_eof"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn openssl_at_least_3_5() -> bool {
    let out = Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    out.ok().and_then(|v| {
        let ver = v.split_whitespace().nth(1)?.to_owned();
        let mut parts = ver.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
        Some((parts.next()?, parts.next()?) >= (3, 5))
    }) == Some(true)
}

#[test]
fn test_interop_openssl_tls13_groups() {
    if !enabled() {
        return;
    }
    let addr = server(Policy::compatible());
    let mut groups = vec!["X25519", "P-256", "P-384"];
    if openssl_at_least_3_5() && cfg!(feature = "aws-lc") {
        groups.insert(0, "X25519MLKEM768");
    }
    for g in groups {
        let out = s_client(addr, &["-groups", g]);
        assert!(
            out.contains("Verification: OK") && out.contains("TLSv1.3"),
            "{g}: {out}"
        );
        assert!(out.contains("hello from tls-net"), "{g}: {out}");
    }
}

#[test]
fn test_interop_openssl_tls12() {
    if !enabled() {
        return;
    }
    let addr = server(Policy::compatible());
    let out = s_client(addr, &["-tls1_2"]);
    assert!(
        out.contains("TLSv1.2") && out.contains("hello from tls-net"),
        "{out}"
    );
}

#[test]
fn test_interop_openssl_tls12_refused_by_modern_t2() {
    if !enabled() {
        return;
    }
    let addr = server(Policy::modern());
    let out = s_client(addr, &["-tls1_2"]);
    assert!(
        !out.contains("hello from tls-net") && out.to_lowercase().contains("alert"),
        "{out}"
    );
}

#[test]
fn test_interop_openssl_tls11_refused_t1() {
    if !enabled() {
        return;
    }
    let addr = server(Policy::compatible());
    let out = s_client(addr, &["-tls1_1", "-cipher", "DEFAULT@SECLEVEL=0"]);
    assert!(!out.contains("hello from tls-net"), "{out}");
}

#[test]
fn test_interop_curl_get() {
    if !enabled() || cfg!(windows) {
        // curl on Windows uses Schannel, which ignores --cacert.
        return;
    }
    let addr = server(Policy::compatible());
    let ca = format!("{}/tests/data/ca.pem", env!("CARGO_MANIFEST_DIR"));
    for extra in [&[][..], &["--tlsv1.2", "--tls-max", "1.2"][..]] {
        let out = Command::new("curl")
            .args([
                "-sS",
                "--cacert",
                &ca,
                "--resolve",
                &format!("localhost:{}:127.0.0.1", addr.port()),
            ])
            .args(extra)
            .arg(format!("https://localhost:{}/", addr.port()))
            .output()
            .expect("curl");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"hello from tls-net\n");
    }
}
