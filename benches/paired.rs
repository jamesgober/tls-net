//! tls-net against rustls's unbuffered connection, measured in alternation:
//! each round times one tls-net operation and one rustls operation back to
//! back, so load that drifts over the run (a shared machine) hits both
//! sides alike. Prints the median of each and the ratio. This is the check
//! for PLAN section 9's "within 3% of rustls unbuffered".
//!
//! ```text
//! cargo bench --bench paired --features rustls-escape-hatch
//! ```

mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use common::{Direct, Drive, Pipe, client, receive, records, server};

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

fn main() {
    let rounds: usize = std::env::var("PAIRED_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let mut pipe = Pipe::default();

    for (label, resumption) in [("handshake_full", 0), ("handshake_resumed", 64)] {
        let (srv, cli) = (server(), client(resumption));
        let (dsrv, dcli) = (server(), client(resumption));
        let (mut a, mut b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
        for i in 0..rounds + 50 {
            let t = Instant::now();
            let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
            pipe.handshake(&mut s, &mut c);
            let ta = t.elapsed();
            let t = Instant::now();
            let (mut s, mut c) = (Direct::server(&dsrv), Direct::client(&dcli));
            pipe.handshake(&mut s, &mut c);
            let tb = t.elapsed();
            if i >= 50 {
                a.push(ta);
                b.push(tb);
            }
        }
        report(label, &mut a, &mut b);
    }

    // The full handshake with tls-net on one side only: which side's layer
    // costs what.
    for side in ["server", "client"] {
        let (srv, cli) = (server(), client(0));
        let (mut a, mut b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
        for i in 0..rounds + 50 {
            let t = Instant::now();
            if side == "server" {
                let (mut s, mut c) = (srv.accept().unwrap(), Direct::client(&cli));
                pipe.handshake(&mut s, &mut c);
            } else {
                let (mut s, mut c) = (Direct::server(&srv), cli.connect("localhost").unwrap());
                pipe.handshake(&mut s, &mut c);
            }
            let ta = t.elapsed();
            let t = Instant::now();
            let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
            pipe.handshake(&mut s, &mut c);
            let tb = t.elapsed();
            if i >= 50 {
                a.push(ta);
                b.push(tb);
            }
        }
        report(&format!("handshake_full/{side} only"), &mut a, &mut b);
    }

    for size in [1024usize, 16 * 1024] {
        let (srv, cli) = (server(), client(0));
        let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
        pipe.handshake(&mut s, &mut c);
        let (mut ds, mut dc) = (Direct::server(&srv), Direct::client(&cli));
        pipe.handshake(&mut ds, &mut dc);
        let (mut wire, mut out) = (Vec::new(), vec![0; 64 * 1024]);
        let batch = 64;
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for _ in 0..rounds / 4 {
            records(&mut c, size, batch, &mut wire);
            let t = Instant::now();
            black_box(receive(&mut s, &mut wire, &mut out));
            a.push(t.elapsed() / batch as u32);
            records(&mut dc, size, batch, &mut wire);
            let t = Instant::now();
            black_box(receive(&mut ds, &mut wire, &mut out));
            b.push(t.elapsed() / batch as u32);
        }
        report(&format!("step_record/{size}"), &mut a, &mut b);

        let plain = vec![0x5a; size];
        let mut sink = vec![0; size + 1024];
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for _ in 0..rounds / 4 {
            let t = Instant::now();
            for _ in 0..batch {
                black_box(s.send(&plain, &mut sink));
            }
            a.push(t.elapsed() / batch as u32);
            let t = Instant::now();
            for _ in 0..batch {
                black_box(ds.send(&plain, &mut sink));
            }
            b.push(t.elapsed() / batch as u32);
        }
        report(&format!("encrypt_record/{size}"), &mut a, &mut b);
    }
}
