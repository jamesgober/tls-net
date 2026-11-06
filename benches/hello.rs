//! ClientHello parsing and fingerprints on a real hello (PLAN section 9:
//! `hello_parse`, `ja4`). The hello is the one tls-net's client sends: TLS
//! 1.3 and 1.2, an X25519MLKEM768 key share, SNI, and ALPN, about 1.5 KiB.
//!
//! ```text
//! cargo bench --bench hello
//! ```

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tls_net::{
    Alpn, ClientBuilder, Event, HelloLimits, HelloParse, HelloParser, Ja4, TrustAnchors, ja3_string,
};

fn real_hello() -> Vec<u8> {
    let client = ClientBuilder::new()
        .trust(
            TrustAnchors::from_pem(
                &std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ca.pem")).unwrap(),
            )
            .unwrap(),
        )
        .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
        .build()
        .unwrap();
    let mut session = client.connect("www.example.test").unwrap();
    let mut out = vec![0; 64 * 1024];
    let p = session.step(&mut [], &mut out).unwrap();
    assert!(matches!(p.event, Event::Transmit));
    out.truncate(p.written);
    out
}

fn hello(c: &mut Criterion) {
    let bytes = real_hello();
    let limits = HelloLimits::new();
    let mut g = c.benchmark_group("hello");
    g.throughput(Throughput::Bytes(bytes.len() as u64));
    g.bench_function("hello_parse", |b| {
        b.iter(
            || match HelloParser::parse(black_box(&bytes), &limits).unwrap() {
                HelloParse::Complete { length, .. } => length,
                _ => unreachable!(),
            },
        );
    });
    let HelloParse::Complete { view, .. } = HelloParser::parse(&bytes, &limits).unwrap() else {
        unreachable!()
    };
    g.bench_function("ja4", |b| b.iter(|| Ja4::compute(black_box(&view))));
    g.bench_function("parse_and_ja4", |b| {
        b.iter(
            || match HelloParser::parse(black_box(&bytes), &limits).unwrap() {
                HelloParse::Complete { view, .. } => Ja4::compute(&view),
                _ => unreachable!(),
            },
        );
    });
    let mut s = String::with_capacity(512);
    g.bench_function("ja3_string", |b| {
        b.iter(|| {
            ja3_string(black_box(&view), &mut s);
            s.len()
        });
    });
    g.finish();
    eprintln!("hello size: {} bytes", bytes.len());
}

criterion_group!(benches, hello);
criterion_main!(benches);
