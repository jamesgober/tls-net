//! NFR-21 in one process: certificate reloads, ticket key rotations, and full
//! and resumed handshakes hold no heap once they are over.
//!
//! The soak (`perf/soak.sh`) watches RSS, which also moves with the
//! allocator's arenas and fragmentation. This test counts live heap bytes
//! instead: after a warm-up, rounds of reload, rotation, and handshakes must
//! leave the live total where it started. It is the only test in this binary,
//! so no other test allocates while it measures.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering::Relaxed};

use common::{End, data, pump};
use tls_net::{ClientBuilder, HandshakeKind, KeySource, TlsClient, TlsServer, TrustAnchors};

struct Live;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Live {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding the caller's layout to the system allocator.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(size(layout), Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(size(layout), Relaxed);
        // SAFETY: `ptr` came from `System.alloc` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// A layout's size never exceeds `isize::MAX`.
fn size(layout: Layout) -> isize {
    isize::try_from(layout.size()).unwrap_or(isize::MAX)
}

#[global_allocator]
static GLOBAL: Live = Live;

/// One round: a reload, a rotation every tenth round, one handshake that
/// resumes when the client holds a ticket and one that cannot (a fresh
/// client). Returns how many handshakes resumed.
fn round(server: &TlsServer, client: &TlsClient, i: usize) -> usize {
    server
        .reload_from_pem(&data("site.pem"), &data("site.key"))
        .unwrap();
    if i % 10 == 0 {
        server.ticket_keys().unwrap().rotate_now().unwrap();
    }
    let fresh = ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .build()
        .unwrap();
    let mut resumed = 0;
    for c in [client, &fresh] {
        let (mut srv, mut cli) = (server.accept().unwrap(), c.connect("localhost").unwrap());
        let (mut s, mut e) = (End::new(usize::MAX), End::new(usize::MAX));
        pump(&mut srv, &mut s, &mut cli, &mut e);
        assert!(s.complete && e.complete, "{:?} {:?}", s.error, e.error);
        // TLS 1.3 tickets arrive after the handshake; let the client read them.
        pump(&mut srv, &mut s, &mut cli, &mut e);
        if srv.info().unwrap().kind == HandshakeKind::Resumed {
            resumed += 1;
        }
    }
    resumed
}

#[test]
fn test_nfr21_reloads_rotations_and_handshakes_hold_no_heap() {
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .build()
        .unwrap();
    let client = ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .build()
        .unwrap();
    // Warm-up: the client's ticket cache fills and lazily built state
    // (provider tables, the reload path) is in place.
    for i in 0..40 {
        round(&server, &client, i);
    }
    let start = LIVE.load(Relaxed);
    let mut resumed = 0;
    for i in 0..200 {
        resumed += round(&server, &client, i);
    }
    let grown = LIVE.load(Relaxed) - start;
    assert!(resumed >= 150, "only {resumed} of 200 resumed");
    // 200 reloads, 20 rotations, 400 handshakes: a leak of even 8 bytes per
    // round shows. The margin covers buffers whose capacity settles.
    assert!(grown < 1024, "live heap grew {grown} bytes over 200 rounds");
}
