//! Configuration paths (PLAN section 9: `reload`, `ticket_seal_open`,
//! `sni_lookup`).
//!
//! ```text
//! cargo bench --bench config --features rustls-escape-hatch
//! RUSTFLAGS="--cfg tls_net_bench" cargo bench --bench config --features rustls-escape-hatch   # with sni_lookup
//! ```

mod common;

use std::hint::black_box;
use std::time::Duration;

use common::data;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustls::server::ProducesTickets;
use tls_net::{KeySource, ServerBuilder, TicketMode, TicketSeed, TlsServer};

/// A builder with `n` entries, each the wildcard certificate under its own name.
fn hundred(n: usize, chain: &[u8], key: &[u8]) -> ServerBuilder {
    let mut b = TlsServer::builder()
        .certificate(chain, KeySource::Pem(key))
        .unwrap();
    for i in 0..n {
        let name = format!("h{i}.example.test");
        b = b
            .certificate_for(&[name.as_str()], chain, KeySource::Pem(key))
            .unwrap();
    }
    b
}

fn reload(c: &mut Criterion) {
    let (chain, key) = (data("site.pem"), data("site.key"));
    let mut g = c.benchmark_group("reload");
    g.sample_size(20).measurement_time(Duration::from_secs(10));
    g.bench_function(BenchmarkId::new("build", 100), |b| {
        b.iter(|| hundred(100, &chain, &key).build().unwrap());
    });
    let server = common::server();
    let handle = server.reload_handle();
    g.bench_function(BenchmarkId::new("publish", 100), |b| {
        b.iter(|| handle.publish(hundred(100, &chain, &key)).unwrap());
    });
    g.finish();
}

fn tickets(c: &mut Criterion) {
    let mut g = c.benchmark_group("ticket_seal_open");
    // About the size of a TLS 1.3 session value rustls stores in a ticket.
    let plain = vec![0x42u8; 160];
    let ring = |mode: TicketMode| {
        let s = TlsServer::builder()
            .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
            .unwrap()
            .tickets(mode, 2)
            .build()
            .unwrap();
        std::sync::Arc::clone(&s.as_rustls_configs()[0].ticketer)
    };
    let period = Duration::from_secs(3600);
    let rings: [(&str, std::sync::Arc<dyn ProducesTickets>); 3] = [
        ("tls-net-ephemeral", ring(TicketMode::Ephemeral { period })),
        (
            "tls-net-ratchet",
            ring(TicketMode::Ratchet {
                seed: TicketSeed::Random,
                period,
            }),
        ),
        (
            "rustls-ticketer",
            rustls::crypto::aws_lc_rs::Ticketer::new().unwrap(),
        ),
    ];
    // What the rings are built on: crypt-io's XChaCha20-Poly1305 and its key source.
    let key = [7u8; 32];
    let crypt = crypt_io::Crypt::xchacha20_poly1305();
    g.bench_function(BenchmarkId::new("seal", "crypt-io-xchacha20"), |b| {
        b.iter(|| {
            crypt
                .encrypt_with_aad(&key, black_box(&plain), b"aad")
                .unwrap()
        })
    });
    let sealed = crypt.encrypt_with_aad(&key, &plain, b"aad").unwrap();
    g.bench_function(BenchmarkId::new("open", "crypt-io-xchacha20"), |b| {
        b.iter(|| {
            crypt
                .decrypt_with_aad(&key, black_box(&sealed), b"aad")
                .unwrap()
        })
    });
    g.bench_function("crypt-io-generate_key", |b| {
        b.iter(|| crypt_io::generate_key().unwrap())
    });
    for (label, t) in rings {
        g.bench_function(BenchmarkId::new("seal", label), |b| {
            b.iter(|| t.encrypt(black_box(&plain)).unwrap())
        });
        let sealed = t.encrypt(&plain).unwrap();
        g.bench_function(BenchmarkId::new("open", label), |b| {
            b.iter(|| t.decrypt(black_box(&sealed)).unwrap())
        });
    }
    g.finish();
}

#[cfg(tls_net_bench)]
fn sni(c: &mut Criterion) {
    let mut g = c.benchmark_group("sni_lookup");
    let names: Vec<String> = (0..10_000)
        .map(|i| format!("host-{i:05}.tenant.example.test"))
        .collect();
    let mut all = names.clone();
    all.push("*.wild.example.test".into());
    let key = data("site.key.der");
    let table = tls_net::bench::Sni::new(&all, &key);
    g.bench_function(BenchmarkId::new("exact", 10_000), |b| {
        b.iter(|| table.lookup(black_box("Host-04711.Tenant.Example.Test")));
    });
    g.bench_function(BenchmarkId::new("wildcard", 10_000), |b| {
        b.iter(|| table.lookup(black_box("api.wild.example.test")));
    });
    g.bench_function(BenchmarkId::new("miss", 10_000), |b| {
        b.iter(|| table.lookup(black_box("nothing.example.org")));
    });
    let swap = tls_net::bench::Swap::new();
    g.bench_function("snapshot_publish", |b| {
        let mut v = 0;
        b.iter(|| {
            v += 1;
            swap.publish(v)
        });
    });
    g.bench_function("snapshot_load", |b| b.iter(|| swap.load()));
    g.finish();
}

#[cfg(not(tls_net_bench))]
fn sni(_: &mut Criterion) {
    eprintln!("sni_lookup and snapshot need RUSTFLAGS=\"--cfg tls_net_bench\"");
}

criterion_group!(benches, reload, tickets, sni);
criterion_main!(benches);
