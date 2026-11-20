//! tls-net's QUIC layer against rustls's QUIC connection, measured in
//! alternation as in `paired.rs`: the full and resumed handshake in memory,
//! and the per-packet key operations.
//!
//! ```text
//! cargo bench --bench quic --features rustls-escape-hatch,quic
//! ```

mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use common::data;
use rustls::quic as rq;
use tls_net::quic::{QuicSession, Side, initial_keys};
use tls_net::{Alpn, KeySource, TlsClient, TlsServer, TrustAnchors};

/// The two QUIC connection types, behind one shape.
trait Hs {
    fn read(&mut self, data: &[u8]);
    fn write(&mut self, out: &mut Vec<u8>) -> bool;
}

impl Hs for QuicSession {
    fn read(&mut self, data: &[u8]) {
        self.read_handshake(data).unwrap();
    }
    fn write(&mut self, out: &mut Vec<u8>) -> bool {
        self.write_handshake(out).is_some()
    }
}

impl Hs for rq::Connection {
    fn read(&mut self, data: &[u8]) {
        self.read_hs(data).unwrap();
    }
    fn write(&mut self, out: &mut Vec<u8>) -> bool {
        self.write_hs(out).is_some()
    }
}

fn flush<A: Hs, B: Hs>(from: &mut A, to: &mut B, out: &mut Vec<u8>) -> bool {
    let mut moved = false;
    loop {
        out.clear();
        let change = from.write(out);
        if !out.is_empty() {
            moved = true;
            to.read(out);
        }
        if change {
            moved = true;
        } else if out.is_empty() {
            return moved;
        }
    }
}

fn handshake<A: Hs, B: Hs>(c: &mut A, s: &mut B, out: &mut Vec<u8>) {
    loop {
        let a = flush(c, s, out);
        let b = flush(s, c, out);
        if !a && !b {
            return;
        }
    }
}

fn median(v: &mut [Duration]) -> Duration {
    v.sort_unstable();
    v[v.len() / 2]
}

fn report(label: &str, a: &mut [Duration], b: &mut [Duration]) {
    let (ma, mb) = (median(a), median(b));
    println!(
        "{label:<28} tls-net {:>10.2?}  rustls {:>10.2?}  ratio {:.3}",
        ma,
        mb,
        ma.as_secs_f64() / mb.as_secs_f64()
    );
}

fn h3() -> Alpn {
    Alpn::new(b"h3").unwrap()
}

fn server() -> TlsServer {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .alpn(&[h3()])
        .build()
        .unwrap()
}

fn client(resumption: usize) -> TlsClient {
    TlsClient::builder()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .alpn(&[h3()])
        .resumption(resumption)
        .build()
        .unwrap()
}

fn main() {
    let rounds: usize = std::env::var("PAIRED_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let params = vec![0x04, 0x04, 0x80, 0x10, 0x00, 0x00];
    let mut out = Vec::with_capacity(8192);

    for (label, resumption) in [("quic_handshake_full", 0), ("quic_handshake_resumed", 64)] {
        let (srv, cli) = (server(), client(resumption));
        let (dsrv, dcli) = (server(), client(resumption));
        let sconfig = dsrv.as_rustls_configs()[0].clone();
        let cconfig = dcli.as_rustls_config();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let (mut a, mut b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
        for i in 0..rounds + 50 {
            let t = Instant::now();
            let mut c = cli.connect_quic("localhost", params.clone()).unwrap();
            let mut s = srv.accept_quic(params.clone()).unwrap();
            handshake(&mut c, &mut s, &mut out);
            let ta = t.elapsed();
            assert!(!s.is_handshaking());
            let t = Instant::now();
            let mut c: rq::Connection = rq::ClientConnection::new(
                cconfig.clone(),
                rq::Version::V1,
                name.clone(),
                params.clone(),
            )
            .unwrap()
            .into();
            let mut s: rq::Connection =
                rq::ServerConnection::new(sconfig.clone(), rq::Version::V1, params.clone())
                    .unwrap()
                    .into();
            handshake(&mut c, &mut s, &mut out);
            let tb = t.elapsed();
            if i >= 50 {
                a.push(ta);
                b.push(tb);
            }
        }
        report(label, &mut a, &mut b);
    }

    // Per packet: a 1,200-byte Initial sealed, its header mask, and opened.
    let ours = initial_keys(&[7; 8], Side::Client).unwrap();
    let theirs = initial_keys(&[7; 8], Side::Server).unwrap();
    let header = [0xc3u8; 22];
    let (mut a, mut b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
    let mut packet = vec![0u8; 1200];
    for i in 0..rounds + 50 {
        let t = Instant::now();
        let tag = ours
            .local
            .packet
            .seal(1, &header, &mut packet[..1184])
            .unwrap();
        packet[1184..].copy_from_slice(&tag);
        let sample: [u8; 16] = packet[4..20].try_into().unwrap();
        black_box(ours.local.header.mask(&sample).unwrap());
        let n = theirs.remote.packet.open(1, &header, &mut packet).unwrap();
        let ta = t.elapsed();
        assert_eq!(n, 1184);
        packet.iter_mut().for_each(|b| *b = 0);
        let t = Instant::now();
        let mut first = 0xc3;
        let mut pn = [0u8; 4];
        let tag = black_box(raw_seal(&mut packet[..1184], &header));
        packet[1184..].copy_from_slice(&tag);
        raw_mask(&packet[4..20], &mut first, &mut pn);
        black_box((first, pn));
        let n = raw_open(&mut packet, &header);
        let tb = t.elapsed();
        assert_eq!(n, 1184);
        packet.iter_mut().for_each(|b| *b = 0);
        if i >= 50 {
            a.push(ta);
            b.push(tb);
        }
    }
    report("initial_seal_mask_open", &mut a, &mut b);
}

/// rustls's Initial keys for the same connection ID, kept for the raw side.
fn raw_keys() -> &'static (rq::Keys, rq::Keys) {
    use std::sync::OnceLock;
    static KEYS: OnceLock<(rq::Keys, rq::Keys)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let suite = match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
            rustls::SupportedCipherSuite::Tls13(t) => t.quic_suite().unwrap(),
            rustls::SupportedCipherSuite::Tls12(_) => unreachable!(),
        };
        (
            suite.keys(&[7; 8], rustls::Side::Client, rq::Version::V1),
            suite.keys(&[7; 8], rustls::Side::Server, rq::Version::V1),
        )
    })
}

fn raw_seal(payload: &mut [u8], header: &[u8]) -> [u8; 16] {
    let tag = raw_keys()
        .0
        .local
        .packet
        .encrypt_in_place(1, header, payload)
        .unwrap();
    tag.as_ref().try_into().unwrap()
}

fn raw_mask(sample: &[u8], first: &mut u8, pn: &mut [u8; 4]) {
    raw_keys()
        .0
        .local
        .header
        .encrypt_in_place(sample, first, pn)
        .unwrap();
}

fn raw_open(packet: &mut [u8], header: &[u8]) -> usize {
    raw_keys()
        .1
        .remote
        .packet
        .decrypt_in_place(1, header, packet)
        .unwrap()
        .len()
}
