//! Handshakes, records, and `accept`, each for tls-net and for rustls's
//! unbuffered connection driven directly with the same configuration
//! (PLAN section 9: `handshake_full`, `handshake_resumed`, `step_record`,
//! `encrypt_record`, `accept`, `custody`).
//!
//! ```text
//! cargo bench --bench session --features rustls-escape-hatch
//! ```

mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use common::{Direct, Drive, Pipe, client, data, receive, records, server};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tls_net::{HandshakeKind, KeySource, TlsServer};

fn handshakes(c: &mut Criterion) {
    let mut g = c.benchmark_group("handshake_full");
    let (srv, cli) = (server(), client(0));
    let mut pipe = Pipe::default();
    g.bench_function("tls-net", |b| {
        b.iter(|| {
            let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
            pipe.handshake(&mut s, &mut c);
            black_box(s.info().unwrap().kind)
        });
    });
    g.bench_function("rustls-unbuffered", |b| {
        b.iter(|| {
            let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
            pipe.handshake(&mut s, &mut c);
        });
    });
    g.finish();

    let mut g = c.benchmark_group("handshake_resumed");
    let (srv, cli) = (server(), client(64));
    {
        let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
        pipe.handshake(&mut s, &mut c);
        let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
        pipe.handshake(&mut s, &mut c);
        assert_eq!(s.info().unwrap().kind, HandshakeKind::Resumed);
    }
    g.bench_function("tls-net", |b| {
        b.iter(|| {
            let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
            pipe.handshake(&mut s, &mut c);
            black_box(s.info().unwrap().kind)
        });
    });
    let (srv, cli) = (server(), client(64));
    {
        let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
        pipe.handshake(&mut s, &mut c);
    }
    g.bench_function("rustls-unbuffered", |b| {
        b.iter(|| {
            let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
            pipe.handshake(&mut s, &mut c);
        });
    });
    g.finish();
}

/// A handshaken pair of each kind.
fn pairs() -> (
    (tls_net::ServerSession, tls_net::ClientSession),
    (impl Drive, impl Drive),
) {
    let (srv, cli) = (server(), client(0));
    let mut pipe = Pipe::default();
    let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
    pipe.handshake(&mut s, &mut c);
    let (mut ds, mut dc) = (Direct::server(&srv), Direct::client(&cli));
    pipe.handshake(&mut ds, &mut dc);
    ((s, c), (ds, dc))
}

/// Records per batch: fresh records are needed for every receive.
const BATCH: usize = 256;

fn timed_receive(iters: u64, size: usize, from: &mut dyn Drive, to: &mut dyn Drive) -> Duration {
    let (mut wire, mut out) = (Vec::new(), vec![0; 64 * 1024]);
    let mut total = Duration::ZERO;
    let mut left = iters as usize;
    while left > 0 {
        let n = left.min(BATCH);
        records(from, size, n, &mut wire);
        let start = Instant::now();
        black_box(receive(to, &mut wire, &mut out));
        total += start.elapsed();
        left -= n;
    }
    total
}

fn timed_send(iters: u64, size: usize, from: &mut dyn Drive) -> Duration {
    let plain = vec![0x5a; size];
    let mut out = vec![0; size + 1024];
    let start = Instant::now();
    for _ in 0..iters {
        black_box(from.send(&plain, &mut out));
    }
    start.elapsed()
}

fn record_paths(c: &mut Criterion) {
    for size in [1024usize, 16 * 1024] {
        let mut g = c.benchmark_group("step_record");
        g.throughput(Throughput::Bytes(size as u64));
        let ((mut s, mut cl), (mut ds, mut dc)) = pairs();
        g.bench_with_input(BenchmarkId::new("tls-net", size), &size, |b, &size| {
            b.iter_custom(|iters| timed_receive(iters, size, &mut cl, &mut s));
        });
        g.bench_with_input(
            BenchmarkId::new("rustls-unbuffered", size),
            &size,
            |b, &size| {
                b.iter_custom(|iters| timed_receive(iters, size, &mut dc, &mut ds));
            },
        );
        g.finish();

        // The copy rustls 0.23 forces on received plaintext (D-035), for reference.
        let mut g = c.benchmark_group("memcpy");
        g.throughput(Throughput::Bytes(size as u64));
        let (src, mut dst) = (vec![1u8; size], vec![0u8; size]);
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| dst.copy_from_slice(black_box(&src)));
        });
        g.finish();

        let mut g = c.benchmark_group("encrypt_record");
        g.throughput(Throughput::Bytes(size as u64));
        // A fresh pair per sample keeps every run far from the AEAD key limits.
        g.bench_with_input(BenchmarkId::new("tls-net", size), &size, |b, &size| {
            b.iter_custom(|iters| timed_send(iters, size, &mut pairs().0.0));
        });
        g.bench_with_input(
            BenchmarkId::new("rustls-unbuffered", size),
            &size,
            |b, &size| {
                b.iter_custom(|iters| timed_send(iters, size, &mut pairs().1.0));
            },
        );
        g.finish();
    }
}

fn accept(c: &mut Criterion) {
    let mut g = c.benchmark_group("accept");
    let srv = server();
    g.bench_function("TlsServer::accept", |b| {
        b.iter(|| black_box(srv.accept().unwrap()))
    });
    let mut reader = srv.worker_acceptor();
    g.bench_function("WorkerAcceptor::accept", |b| {
        b.iter(|| black_box(reader.accept().unwrap()))
    });
    g.finish();
}

fn custody(c: &mut Criterion) {
    use key_vault::{KeyVaultBuilder, RawKey};
    use std::sync::Arc;
    use tls_net::KeyCustody;
    let mut g = c.benchmark_group("custody");
    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let handle = vault
        .register("site", RawKey::new(data("site.key.der")))
        .unwrap();
    let cli = client(0);
    let mut pipe = Pipe::default();
    for (label, custody) in [
        ("resident", KeyCustody::Resident),
        ("per-signature", KeyCustody::PerSignature),
    ] {
        let srv = TlsServer::builder()
            .certificate(
                &data("site.pem"),
                KeySource::Vault {
                    vault: Arc::clone(&vault),
                    handle,
                    custody,
                },
            )
            .unwrap()
            .build()
            .unwrap();
        g.bench_function(label, |b| {
            b.iter(|| {
                let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
                pipe.handshake(&mut s, &mut c);
            });
        });
    }
    g.finish();
}

criterion_group!(benches, handshakes, record_paths, accept, custody);
criterion_main!(benches);
