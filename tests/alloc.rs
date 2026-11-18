//! NFR-1: tls-net's own code allocates nothing on the established record path.
//!
//! rustls 0.23 allocates one `Vec` per record in each direction (D-035):
//! `encrypt` builds each record in a `Vec` before copying it out, and a
//! received record is copied into an owned `Vec`. The test counts every
//! allocation on this thread while records flow, and checks that the total
//! is exactly rustls's one per record each way, so tls-net adds none.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use common::{End, data, pump};
use tls_net::{Event, KeySource, TlsClient, TlsServer, TrustAnchors};

struct Counting;

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|c| {
            if let Some(n) = c.get() {
                c.set(Some(n + 1));
            }
        });
        // SAFETY: forwarding the caller's layout to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn counting<R>(f: impl FnOnce() -> R) -> (R, usize) {
    COUNT.with(|c| c.set(Some(0)));
    let r = f();
    let n = COUNT.with(|c| c.replace(None)).unwrap_or(0);
    (r, n)
}

#[test]
fn test_established_path_allocates_only_rustls_record_buffers() {
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap();
    let client = TlsClient::builder()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .build()
        .unwrap();
    let (mut srv, mut cli) = (
        server.accept().unwrap(),
        client.connect("localhost").unwrap(),
    );
    let (mut s, mut c) = (End::new(usize::MAX), End::new(usize::MAX));
    pump(&mut srv, &mut s, &mut cli, &mut c);
    assert!(s.complete && c.complete);

    const RECORDS: usize = 100;
    let payload = vec![0x42u8; 16_384];
    let mut wire = vec![0u8; RECORDS * (16_384 + 64)];
    let mut out = vec![0u8; 64 * 1024];

    // Warm up: rustls's plaintext queue allocates its buffer on first use.
    let n = cli.encrypt(&payload, &mut wire).unwrap();
    let p = srv.step(&mut wire[..n], &mut out).unwrap();
    assert!(matches!(p.event, Event::Data(d) if d.len() == payload.len()));

    // Client side: encrypt RECORDS full records.
    let (len, encrypt_allocs) = counting(|| {
        let mut len = 0;
        for _ in 0..RECORDS {
            len += cli.encrypt(&payload, &mut wire[len..]).unwrap();
        }
        len
    });

    // Server side: decrypt them, one `Data` per step.
    let (got, step_allocs) = counting(|| {
        let mut input = &mut wire[..len];
        let mut got = 0;
        loop {
            let p = srv.step(input, &mut out).unwrap();
            let consumed = p.consumed;
            match p.event {
                Event::Data(d) => got += d.len(),
                Event::NeedInput => break,
                other => panic!("{other:?}"),
            }
            input = &mut input[consumed..];
        }
        got
    });

    assert_eq!(got, RECORDS * payload.len());
    assert_eq!(
        encrypt_allocs, RECORDS,
        "encrypt: rustls builds one Vec per record; tls-net adds none"
    );
    assert_eq!(
        step_allocs, RECORDS,
        "step: rustls copies one Vec per record; tls-net adds none"
    );
}

#[test]
fn test_accept_and_hello_parse_do_not_allocate_in_tls_net() {
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap();
    // accept: one Arc clone per slot, no allocation. Warm up first: on macOS
    // the standard library allocates a mutex's pthread object on first lock.
    drop(server.accept().unwrap());
    let (session, n) = counting(|| server.accept().unwrap());
    assert_eq!(n, 0);
    drop(session);
    let client = TlsClient::builder()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .build()
        .unwrap();
    let mut cli = client.connect("localhost").unwrap();
    let mut out = vec![0u8; 64 * 1024];
    let p = cli.step(&mut [], &mut out).unwrap();
    let hello = out[..p.written].to_vec();
    let limits = tls_net::HelloLimits::new();
    let (parsed, n) = counting(|| {
        let r = tls_net::parse_client_hello(&hello, &limits).unwrap();
        matches!(r, tls_net::HelloParse::Complete { .. })
    });
    assert!(parsed);
    assert_eq!(n, 0, "the ClientHello parser allocates nothing");
    let (name, n) = counting(|| tls_net::normalize_server_name("WWW.Example.COM."));
    assert!(name.is_some());
    assert_eq!(n, 0, "SNI normalisation allocates nothing");
}

#[test]
fn test_t27_half_open_session_allocates_nothing() {
    // A connection that sent one byte of its ClientHello holds its session
    // and nothing on the heap: 10,000 such connections cost 10,000 times the
    // session's inline size, flat (T-27).
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap();
    drop(server.accept().unwrap());
    let mut out = vec![0u8; 64 * 1024];
    let ((), n) = counting(|| {
        for _ in 0..1_000 {
            let mut s = server.accept().unwrap();
            let mut first = [22u8];
            let p = s.step(&mut first, &mut out).unwrap();
            assert!(matches!(p.event, tls_net::Event::NeedInput));
            drop(s);
        }
    });
    assert_eq!(n, 0, "accept plus a one-byte step allocated");
    assert!(std::mem::size_of::<tls_net::ServerSession>() < 2048);
}
