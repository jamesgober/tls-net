//! Loopback comparison of TLS server stacks (docs/PERFORMANCE.md).
//!
//! ```text
//! perf server <tls-net|tls-net-shared|tokio-rustls|tokio-openssl> <addr> <workers>
//! perf load <handshakes|bulk> <addr> <threads> <seconds> [x25519]
//! perf inmem <tls-net|rustls|server|client> <full|resumed> <seconds>
//! perf inmem hello x <rounds>
//! ```
//!
//! `perf/ab.sh` runs the interleaved comparison. `PERF_PROFILE=<path>` (Linux)
//! writes folded CPU stacks of a server run (in `inmem` runs pprof's unwinder
//! has crashed inside aws-lc's assembly, so use it on servers). `inmem` drives
//! in-memory handshakes through the benches' driver (`server` and `client`
//! put tls-net on that side only); `inmem hello` times the server's first
//! step on one ClientHello against rustls's.
//!
//! Every server answers `GET /` with a short response and closes, and answers
//! `GET /bulk` with 16 KiB writes until the client goes away. The load
//! generator is the same for every server: blocking rustls clients, no
//! resumption, one request per connection (`handshakes`) or one stream per
//! thread (`bulk`). `x25519` limits the client to X25519, the group every
//! stack here supports (OpenSSL 3.0 has no ML-KEM).
//! `PERF_EARLY_REQUEST=1` sends the request in the same flight as the
//! client's Finished, as browsers and curl do, so a server can answer it in
//! the send that carries its tickets.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
const CHUNK: usize = 16 * 1024;
/// `GET /keep`: a 32 KiB page on a connection that stays open.
const KEEP_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 32768\r\n\r\n";
const KEEP_BODY: usize = 32 * 1024;

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") => {
            let workers: usize = args[3].parse().unwrap();
            profile();
            match args[1].as_str() {
                "tls-net" => tls_net_server(&args[2], workers, false),
                "tls-net-shared" => tls_net_server(&args[2], workers, true),
                "tokio-rustls" => tokio_server(&args[2], workers, Stack::Rustls),
                "tokio-openssl" => tokio_server(&args[2], workers, Stack::OpenSsl),
                other => panic!("unknown stack {other}"),
            }
        }
        Some("inmem") => {
            profile();
            inmem::run(&args[1], &args[2], args[3].parse().unwrap());
        }
        Some("once") => match one_request(&args[1], &client_config(false)) {
            Ok(_) => println!("ok"),
            Err(e) => println!("error: {e:?}"),
        },
        Some("idle") => idle(
            &args[1],
            args[2].parse().unwrap(),
            args[3].parse().unwrap(),
            args.get(4).is_some_and(|a| a == "warm"),
        ),
        Some("load") => {
            let x25519 = args.get(5).is_some_and(|a| a == "x25519");
            load(&args[1], &args[2], args[3].parse().unwrap(), args[4].parse().unwrap(), x25519);
        }
        _ => eprintln!("usage: see the source"),
    }
}

/// `PERF_PROFILE=<path>`: samples the server's CPU from 2 s after start for
/// `PERF_PROFILE_SECS` (default 10) and writes folded stacks to the path.
fn profile() {
    let Some(path) = std::env::var_os("PERF_PROFILE") else { return };
    #[cfg(target_os = "linux")]
    std::thread::spawn(move || {
        use std::fmt::Write as _;
        let secs = std::env::var("PERF_PROFILE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(10);
        std::thread::sleep(Duration::from_secs(2));
        let guard = pprof::ProfilerGuardBuilder::default().frequency(499).build().unwrap();
        std::thread::sleep(Duration::from_secs(secs));
        let report = guard.report().build().unwrap();
        let mut out = String::new();
        for (frames, count) in &report.data {
            let mut first = true;
            for symbols in frames.frames.iter().rev() {
                for s in symbols.iter().rev() {
                    out.push_str(if first { "" } else { ";" });
                    first = false;
                    out.push_str(&s.name().replace(';', ":"));
                }
            }
            let _ = writeln!(out, " {count}");
        }
        std::fs::write(&path, out).unwrap();
        eprintln!("profile written");
    });
    #[cfg(not(target_os = "linux"))]
    let _ = path;
}

// ---------------------------------------------------------------------------
// In-memory handshakes, for profiles of tls-net against rustls direct

#[path = "../../benches/common/mod.rs"]
#[allow(clippy::all)]
mod common;

mod inmem {
    use super::common::{Direct, Pipe, client, server};
    use std::time::{Duration, Instant};

    /// `inmem hello x <rounds>`: the server's first step on one ClientHello,
    /// tls-net and rustls alternating; prints the medians.
    fn hello(rounds: usize) {
        use super::common::Drive;
        let (srv, cli) = (server(), client(0));
        let mut c = Direct::client(&cli);
        let (mut hello, mut out) = (vec![0u8; 4096], vec![0u8; 64 * 1024]);
        let (_, n, _) = c.drive(&mut [], &mut hello);
        hello.truncate(n);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for _ in 0..rounds {
            let mut input = hello.clone();
            let t = Instant::now();
            let mut s = srv.accept().unwrap();
            std::hint::black_box(s.drive(&mut input, &mut out));
            a.push(t.elapsed());
            drop(s);
            let mut input = hello.clone();
            let t = Instant::now();
            let mut s = Direct::server(&srv);
            std::hint::black_box(s.drive(&mut input, &mut out));
            b.push(t.elapsed());
        }
        a.sort();
        b.sort();
        let (ma, mb) = (a[rounds / 2], b[rounds / 2]);
        println!("first server step: tls-net {ma:?} rustls {mb:?} difference {:?}", ma.saturating_sub(mb));
    }

    /// `inmem <tls-net|rustls> <full|resumed> <seconds>`: handshakes in a loop.
    pub fn run(stack: &str, kind: &str, secs: u64) {
        if stack == "hello" {
            return hello(usize::try_from(secs).unwrap());
        }
        let resumption = if kind == "resumed" { 64 } else { 0 };
        let (srv, cli) = (server(), client(resumption));
        let mut pipe = Pipe::default();
        let (start, mut n) = (Instant::now(), 0u64);
        while start.elapsed() < Duration::from_secs(secs) {
            // `server` and `client` put tls-net on that side only.
            match stack {
                "tls-net" => {
                    let (mut s, mut c) = (srv.accept().unwrap(), cli.connect("localhost").unwrap());
                    pipe.handshake(&mut s, &mut c);
                }
                "server" => {
                    let (mut s, mut c) = (srv.accept().unwrap(), Direct::client(&cli));
                    pipe.handshake(&mut s, &mut c);
                }
                "client" => {
                    let (mut s, mut c) = (Direct::server(&srv), cli.connect("localhost").unwrap());
                    pipe.handshake(&mut s, &mut c);
                }
                _ => {
                    let (mut s, mut c) = (Direct::server(&srv), Direct::client(&cli));
                    pipe.handshake(&mut s, &mut c);
                }
            }
            n += 1;
        }
        println!("{stack} {kind}: {:.0} handshakes/s", n as f64 / start.elapsed().as_secs_f64());
    }
}

// ---------------------------------------------------------------------------
// tls-net on net-io's reactor

mod tls_net_app {
    use net_io::{CloseReason, ConnectionInfo, Input, Session, SessionContext, Step};

    #[derive(Default)]
    pub struct App {
        bulk: bool,
        /// The response did not fit the output budget yet.
        pending: bool,
    }

    static FILL: [u8; super::CHUNK] = [b'a'; super::CHUNK];

    impl App {
        /// The response, or a wait for room in the output budget.
        fn respond(pending: &mut bool, cx: &mut SessionContext<'_>) -> Step {
            // A failed push here means the worker's buffer budget is spent;
            // waiting with `Write` would spin, so the connection is dropped.
            *pending = false;
            if cx.output().push(super::RESPONSE).is_err() {
                return Step::Abort;
            }
            Step::Close
        }

        fn fill(cx: &mut SessionContext<'_>) -> Step {
            while cx.output().push(&FILL).is_ok() {}
            Step::Write
        }
    }

    impl Session for App {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            if self.bulk {
                let n = input.bytes().len();
                input.consume(n);
                return Step::Read;
            }
            let bytes = input.bytes();
            let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                return Step::Read;
            };
            let bulk = bytes.starts_with(b"GET /bulk");
            let keep = bytes.starts_with(b"GET /keep");
            input.consume(end + 4);
            if bulk {
                self.bulk = true;
                return App::fill(cx);
            }
            if keep {
                // Header and page fit the 64 KiB output budget.
                if cx.output().push(super::KEEP_HEAD).is_err()
                    || cx.output().push(&FILL).is_err()
                    || cx.output().push(&FILL).is_err()
                {
                    return Step::Abort;
                }
                return Step::Write;
            }
            App::respond(&mut self.pending, cx)
        }

        fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
            if self.bulk {
                App::fill(cx)
            } else if self.pending {
                App::respond(&mut self.pending, cx)
            } else {
                Step::Read
            }
        }

        fn on_close(&mut self, info: &ConnectionInfo, reason: CloseReason) {
            use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
            static SHOWN: AtomicU32 = AtomicU32::new(0);
            if !matches!(reason, CloseReason::SessionClosed)
                && std::env::var_os("PERF_STATS").is_some()
                && SHOWN.fetch_add(1, Relaxed) < 5
            {
                eprintln!("close {reason:?} tls {:?}", info.tls.as_ref().map(|t| t.version()));
            }
        }
    }
}

/// `shared` (`tls-net-shared`): one listener shared by the workers and
/// net-io's default linger, the setup net-io 0.6.2 tunes for (D-174, D-177).
fn tls_net_server(addr: &str, workers: usize, shared: bool) {
    use net_io::{
        AllowAll, ConnectionInfo, DriverKind, Limits, ListenOptions, ListenerSpec, PrefixPolicy,
        ServerBuilder,
    };
    // All load comes from 127.0.0.1: lift the per-source cap (256 by
    // default) and the connection cap, which the tokio servers do not have.
    let mut limits = Limits::reactor_defaults()
        .to_builder()
        .max_connections(9_000)
        .max_per_listener(9_000)
        .max_per_source(9_000, PrefixPolicy::DEFAULT);
    if !shared {
        // The tokio servers close without a linger; match them unless asked.
        let linger = std::env::var_os("PERF_LINGER").is_some();
        limits = limits.graceful_linger(
            if linger { Duration::from_secs(2) } else { Duration::ZERO },
            if linger { 64 * 1024 } else { 0 },
        );
    }
    let limits = limits.build().unwrap();
    let mut builder = tls_net::TlsServer::builder()
        .certificate(&data("site.pem"), tls_net::KeySource::Pem(&data("site.key")))
        .unwrap()
        // The fixtures sit on shared mounts with open permissions.
        .allow_group_readable_key(true);
    if let Some(m) = env_secs("PERF_TICKET_MINUTES") {
        let period = Duration::from_secs(m * 60);
        builder = builder.tickets(tls_net::TicketMode::Ephemeral { period }, 2);
    }
    let tls = builder.build().unwrap();
    soak_threads(&tls);
    let server = ServerBuilder::new()
        // One reuse-port socket per worker (Linux): with one shared listener
        // net-io 0.6.0 hands most short connections to a single worker.
        .listener(if !shared && std::env::var_os("PERF_SINGLE_LISTENER").is_none() {
            ListenerSpec::tcp_with(addr, ListenOptions::new().per_worker(true)).tls(true)
        } else {
            ListenerSpec::tcp(addr).tls(true)
        })
        .driver(DriverKind::Reactor)
        .workers(u16::try_from(workers).unwrap())
        .limits(limits)
        .sessions(|_: &ConnectionInfo| tls_net_app::App::default())
        .tls(tls)
        .gate(AllowAll)
        .build()
        .unwrap();
    server.open_door().unwrap();
    eprintln!("tls-net on net-io reactor, {workers} workers, {addr}");
    if std::env::var_os("PERF_STATS").is_some() {
        let handle = server.handle();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(3));
            let st = handle.stats();
            eprintln!("stats {st:?}");
            for (cause, n) in st.refusals() {
                eprintln!("  refused {cause:?}: {n}");
            }
            for (reason, n) in st.closes() {
                eprintln!("  closed {reason:?}: {n}");
            }
        });
    }
    let _ = server.wait_for_stop();
}

fn env_secs(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// Soak options (perf/soak.sh, NFR-21): `PERF_RELOAD_SECS` reloads the
/// certificate from its files that often; `PERF_RSS_SECS` prints the
/// process's resident memory and tls-net's counters that often.
fn soak_threads(tls: &tls_net::TlsServer) {
    if let Some(secs) = env_secs("PERF_RELOAD_SECS") {
        let tls = tls.clone();
        std::thread::spawn(move || {
            let dir = format!("{}/../tests/data", env!("CARGO_MANIFEST_DIR"));
            loop {
                std::thread::sleep(Duration::from_secs(secs));
                if let Err(e) = tls.reload_from_files(format!("{dir}/site.pem"), format!("{dir}/site.key")) {
                    eprintln!("reload failed: {e}");
                }
            }
        });
    }
    if let Some(secs) = env_secs("PERF_RSS_SECS") {
        let tls = tls.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(secs));
            let rss = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS")).map(|l| l.split_whitespace().nth(1).unwrap_or("0").to_owned()))
                .unwrap_or_default();
            let st = tls.stats();
            eprintln!(
                "rss_kib {rss} full {} resumed {} failed {} tickets {} rejected {} version {}",
                st.handshakes_full, st.handshakes_resumed, st.handshakes_failed, st.tickets_issued, st.tickets_rejected, st.snapshot_version
            );
        });
    }
}

// ---------------------------------------------------------------------------
// tokio with tokio-rustls or tokio-openssl

#[derive(Clone, Copy)]
enum Stack {
    Rustls,
    OpenSsl,
}

async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Small, like the reactor's: an idle connection should not hold 16 KiB.
    let mut buf = [0u8; 512];
    let mut req = Vec::new();
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
        if req.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    if req.starts_with(b"GET /bulk") {
        let chunk = vec![b'a'; CHUNK];
        while s.write_all(&chunk).await.is_ok() {}
        return;
    }
    if req.starts_with(b"GET /keep") {
        let page = vec![b'k'; KEEP_BODY];
        if s.write_all(KEEP_HEAD).await.is_err() || s.write_all(&page).await.is_err() {
            return;
        }
        drop(page);
        // Idle until the client goes away.
        while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        return;
    }
    let _ = s.write_all(RESPONSE).await;
    let _ = s.shutdown().await;
}

fn tokio_server(addr: &str, workers: usize, stack: Stack) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        match stack {
            Stack::Rustls => {
                let acceptor = tokio_rustls::TlsAcceptor::from(rustls_server_config());
                eprintln!("tokio + tokio-rustls, {workers} workers, {addr}");
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let _ = tcp.set_nodelay(true);
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            serve(tls).await;
                        }
                    });
                }
            }
            Stack::OpenSsl => {
                let acceptor = Arc::new(openssl_acceptor());
                eprintln!("tokio + tokio-openssl ({}), {workers} workers, {addr}", openssl::version::version());
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let _ = tcp.set_nodelay(true);
                    let acceptor = Arc::clone(&acceptor);
                    tokio::spawn(async move {
                        let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
                        if std::pin::Pin::new(&mut tls).accept().await.is_ok() {
                            serve(tls).await;
                        }
                    });
                }
            }
        }
    });
}

/// rustls's defaults with stateless tickets, two per handshake, as tls-net sends.
fn rustls_server_config() -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&data("site.pem")).map(Result::unwrap).collect();
    let key = PrivateKeyDer::from_pem_slice(&data("site.key")).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().unwrap();
    config.send_tls13_tickets = 2;
    Arc::new(config)
}

fn openssl_acceptor() -> openssl::ssl::SslAcceptor {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    let dir = format!("{}/../tests/data", env!("CARGO_MANIFEST_DIR"));
    b.set_certificate_chain_file(format!("{dir}/site.pem")).unwrap();
    b.set_private_key_file(format!("{dir}/site.key"), SslFiletype::PEM).unwrap();
    b.check_private_key().unwrap();
    b.build()
}

// ---------------------------------------------------------------------------
// The load generator

fn client_config(x25519: bool) -> Arc<rustls::ClientConfig> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&data("ca.pem")) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if x25519 {
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

/// One request on a new connection; `Ok(true)` when the handshake resumed.
fn one_request(addr: &str, config: &Arc<rustls::ClientConfig>) -> Result<bool, std::io::Error> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true)?;
    let conn = rustls::ClientConnection::new(Arc::clone(config), "localhost".try_into().unwrap())
        .map_err(std::io::Error::other)?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    if std::env::var_os("PERF_EARLY_REQUEST").is_some_and(|v| !v.is_empty()) {
        // As browsers and curl do: the request leaves with Finished.
        s.conn.writer().write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")?;
        while s.conn.is_handshaking() || s.conn.wants_write() {
            s.conn.complete_io(&mut s.sock)?;
        }
    } else {
        s.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")?;
    }
    let t = Instant::now();
    let mut got = Vec::with_capacity(RESPONSE.len());
    let mut buf = [0u8; 256];
    while got.len() < RESPONSE.len() {
        match s.read(&mut buf)? {
            0 => break,
            n => got.extend_from_slice(&buf[..n]),
        }
    }
    if std::env::var_os("PERF_TIME").is_some() {
        eprintln!("response after {:?}", t.elapsed());
    }
    if got != RESPONSE {
        return Err(std::io::Error::other("short response"));
    }
    Ok(s.conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed))
}

fn bulk(addr: &str, config: &Arc<rustls::ClientConfig>, stop: &AtomicBool, bytes: &AtomicU64) -> Result<(), std::io::Error> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true)?;
    let conn = rustls::ClientConnection::new(Arc::clone(config), "localhost".try_into().unwrap())
        .map_err(std::io::Error::other)?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    s.write_all(b"GET /bulk HTTP/1.1\r\nhost: localhost\r\n\r\n")?;
    let mut buf = vec![0u8; 64 * 1024];
    while !stop.load(Relaxed) {
        match s.read(&mut buf)? {
            0 => break,
            n => {
                bytes.fetch_add(n as u64, Relaxed);
            }
        }
    }
    Ok(())
}

/// `idle <addr> <connections> <seconds> [warm]`: opens connections, completes
/// each handshake, and holds them; prints `open N` when all are up. `warm`
/// fetches `GET /keep` (a 32 KiB page) on each first, so the server has
/// carried traffic on the connection before it goes idle.
fn idle(addr: &str, n: usize, seconds: u64, warm: bool) {
    let config = client_config(true);
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        let mut tcp = match TcpStream::connect(addr) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("connect: {e}");
                break;
            }
        };
        let mut conn = rustls::ClientConnection::new(Arc::clone(&config), "localhost".try_into().unwrap()).unwrap();
        // Until the handshake is done and the client's Finished is sent.
        while conn.is_handshaking() || conn.wants_write() {
            if conn.complete_io(&mut tcp).is_err() {
                break;
            }
        }
        if warm {
            let mut s = rustls::Stream::new(&mut conn, &mut tcp);
            let mut buf = [0u8; 4096];
            let (want, mut got) = (KEEP_HEAD.len() + KEEP_BODY, 0);
            if s.write_all(b"GET /keep HTTP/1.1\r\nhost: localhost\r\n\r\n").is_ok() {
                while got < want {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Err(e) => {
                            eprintln!("warm read: {e}");
                            break;
                        }
                        Ok(k) => got += k,
                    }
                }
                if got < want {
                    eprintln!("warm: {got} of {want} bytes");
                }
            }
        }
        held.push((conn, tcp));
    }
    println!("open {}", held.len());
    std::thread::sleep(Duration::from_secs(seconds));
}

fn load(mode: &str, addr: &str, threads: usize, seconds: u64, x25519: bool) {
    let config = client_config(x25519);
    let stop = Arc::new(AtomicBool::new(false));
    let (done, errors) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    // `mixed`: every other thread resumes (its own ticket store), the rest
    // make full handshakes.
    let mixed = mode == "mixed";
    let handshakes = mode == "handshakes" || mixed;
    let resumed = Arc::new(AtomicU64::new(0));
    let mut joins = Vec::new();
    for i in 0..threads {
        let config = if mixed && i % 2 == 1 {
            let mut c = (*config).clone();
            c.resumption = rustls::client::Resumption::in_memory_sessions(64);
            Arc::new(c)
        } else {
            Arc::clone(&config)
        };
        let resumed = Arc::clone(&resumed);
        let (config, stop, done, errors, addr) = (
            config,
            Arc::clone(&stop),
            Arc::clone(&done),
            Arc::clone(&errors),
            addr.to_string(),
        );
        joins.push(std::thread::spawn(move || {
            if handshakes {
                while !stop.load(Relaxed) {
                    match one_request(&addr, &config) {
                        Ok(r) => {
                            if r {
                                resumed.fetch_add(1, Relaxed);
                            }
                            done.fetch_add(1, Relaxed)
                        }
                        Err(e) => {
                            if errors.fetch_add(1, Relaxed) < 3 {
                                eprintln!("client error: {e:?}");
                            }
                            0
                        }
                    };
                }
            } else if bulk(&addr, &config, &stop, &done).is_err() {
                errors.fetch_add(1, Relaxed);
            }
        }));
    }
    // One second of warm-up, then the measured window.
    std::thread::sleep(Duration::from_secs(1));
    let (start, at_start) = (Instant::now(), done.load(Relaxed));
    std::thread::sleep(Duration::from_secs(seconds));
    let (elapsed, at_end) = (start.elapsed().as_secs_f64(), done.load(Relaxed));
    stop.store(true, Relaxed);
    for j in joins {
        let _ = j.join();
    }
    let rate = (at_end - at_start) as f64 / elapsed;
    if mixed {
        println!(
            "handshakes/s {rate:.0} total {at_end} resumed {} errors {}",
            resumed.load(Relaxed),
            errors.load(Relaxed)
        );
    } else if handshakes {
        println!("handshakes/s {rate:.0} errors {}", errors.load(Relaxed));
    } else {
        println!("MB/s {:.0} errors {}", rate / 1e6, errors.load(Relaxed));
    }
}
