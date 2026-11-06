//! Memory per idle connection and allocations per record, for tls-net and
//! for rustls's unbuffered connection driven directly (PLAN section 9).
//! Counts through a wrapping global allocator; prints a table.
//!
//! ```text
//! cargo bench --bench memory --features rustls-escape-hatch
//! ```

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering::Relaxed};

use common::{Direct, Drive, Pipe, client, receive, records, server};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        LIVE.fetch_add(layout.size() as isize, Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        LIVE.fetch_add(new_size as isize - layout.size() as isize, Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const CONNS: usize = 500;
const RECORDS: usize = 2_000;

fn main() {
    let (srv, cli) = (server(), client(0));
    let mut pipe = Pipe::default();
    // Warm up lazily initialised state in both stacks.
    for _ in 0..4 {
        let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
        pipe.handshake(&mut s, &mut c);
        let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
        pipe.handshake(&mut s, &mut c);
    }

    // Memory per idle server connection after the handshake (client sides
    // dropped): heap bytes, plus the connection value itself.
    let mut kept = Vec::with_capacity(CONNS);
    let before = LIVE.load(Relaxed);
    for _ in 0..CONNS {
        let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
        pipe.handshake(&mut s, &mut c);
        kept.push(s);
    }
    let tls_net_heap = (LIVE.load(Relaxed) - before) as usize / CONNS;
    drop(kept);
    let mut kept = Vec::with_capacity(CONNS);
    let before = LIVE.load(Relaxed);
    for _ in 0..CONNS {
        let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
        pipe.handshake(&mut s, &mut c);
        s.release_app();
        kept.push(s.conn);
    }
    let direct_heap = (LIVE.load(Relaxed) - before) as usize / CONNS;
    drop(kept);
    let tls_net_inline = std::mem::size_of::<tls_net::ServerSession>();
    let direct_inline = std::mem::size_of::<rustls::server::UnbufferedServerConnection>();
    println!("idle server connection after the handshake, bytes:");
    println!(
        "  {:<18}  {:>6} heap  {:>6} inline  {:>6} total",
        "tls-net",
        tls_net_heap,
        tls_net_inline,
        tls_net_heap + tls_net_inline
    );
    println!(
        "  {:<18}  {:>6} heap  {:>6} inline  {:>6} total",
        "rustls-unbuffered",
        direct_heap,
        direct_inline,
        direct_heap + direct_inline
    );

    // Allocations per record, each direction.
    let mut wire = Vec::with_capacity(RECORDS * 17 * 1024);
    let mut out = vec![0; 64 * 1024];
    for size in [1024usize, 16 * 1024] {
        let mut row = |label: &str, from: &mut dyn Drive, to: &mut dyn Drive| {
            records(from, size, 16, &mut wire);
            receive(to, &mut wire, &mut out);
            let a = ALLOCS.load(Relaxed);
            records(from, size, RECORDS, &mut wire);
            let sent = ALLOCS.load(Relaxed) - a;
            let a = ALLOCS.load(Relaxed);
            receive(to, &mut wire, &mut out);
            let recv = ALLOCS.load(Relaxed) - a;
            println!(
                "  {label:<18}  {size:>6} B  send {:>5.2}  receive {:>5.2}",
                sent as f64 / RECORDS as f64,
                recv as f64 / RECORDS as f64
            );
        };
        if size == 1024 {
            println!("allocations per record (the bench's own buffers are preallocated):");
        }
        let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
        pipe.handshake(&mut s, &mut c);
        row("tls-net", &mut c, &mut s);
        let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
        pipe.handshake(&mut s, &mut c);
        row("rustls-unbuffered", &mut c, &mut s);
    }
}
