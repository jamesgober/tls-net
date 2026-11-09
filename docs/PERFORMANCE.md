# tls-net - Performance

What tls-net costs on top of rustls, how the end-to-end path (net-io's reactor plus tls-net) compares with tokio plus tokio-rustls and tokio plus tokio-openssl, how each number was measured, and what is still open. Targets: [`../dev/PLAN.md`](../dev/PLAN.md) section 9. Decisions: D-096 to D-105.

---

## Contents

- [Summary](#summary)
- [Hardware and software](#hardware-and-software)
- [Method](#method)
- [tls-net against rustls](#tls-net-against-rustls)
- [End to end](#end-to-end)
- [Open gaps](#open-gaps)
- [Running the measurements](#running-the-measurements)

---

## Summary

| Metric | Target | Measured | Status |
|---|---|---|---|
| overhead per `step` record | under 100 ns plus the D-035 copy | +32 ns (1 KiB), +210 ns (16 KiB, one extra 16 KiB copy) | met |
| overhead per `encrypt` record | under 50 ns | +11 ns (1 KiB), +10 ns (16 KiB) | met |
| allocations per record, tls-net code | 0 | 0 (1.00 per record each way, the same as rustls alone) | met |
| full handshake, in memory, one core | within 3% of rustls | 1.022 (Linux), 1.007 (Windows) | met |
| resumed handshake, in memory, one core | within 3% of rustls | 1.025 (Linux), 1.007 (Windows) | met |
| loopback handshakes, 8 cores | 1.2x tokio-rustls in rate and in CPU per handshake | rate 1.45x, CPU 0.96x | open (net-io) |
| loopback bulk, 16 KiB writes | 1.2x tokio-rustls in rate and in CPU per byte | rate 1.23x, CPU 1.20x | met |
| memory per idle connection, tls-net's part | rustls plus under 512 bytes | rustls plus 257 bytes | met |
| memory per idle connection, end to end | 30% below tokio-rustls | 25.8 KB against 11.4 KB | open (net-io) |
| ClientHello parse plus JA4 (1.5 KiB hello) | under 1.5 µs | 0.82 µs | met |
| SNI lookup, 10,000 names | under 100 ns | 75 ns exact, 101 ns wildcard, 90 ns miss | met (wildcard at the limit) |
| `accept()` / `ServerReader::accept` | under 60 ns / under 20 ns | 61 ns / 37 ns | at target / missed (D-102) |
| reload build of 100 certificates / swap | under 10 ms / under 1 µs | 1.74 ms / 25 ns | met |
| ticket seal / open | under 2 µs each | 1.6 µs / 1.5 µs | met |
| per-signature custody | at least 70% of resident | about 100% | met |

"Linux" is WSL2. There is no bare-metal Linux machine in this project yet (see [Hardware and software](#hardware-and-software)).

---

## Hardware and software

| | |
|---|---|
| CPU | AMD Ryzen 9 9950X3D, 16 cores, 32 threads, two CCDs (CPUs 0 to 15 and 16 to 31 in WSL's numbering; SMT siblings are adjacent) |
| Memory | 64 GiB |
| Windows | Windows 11 Pro 10.0.26200, Rust 1.95.0 |
| Linux | WSL2, kernel 6.6.87.2-microsoft-standard-WSL2, clock source TSC, Rust 1.99.0 |
| TLS | rustls 0.23.46, aws-lc-rs 1.19.0; tokio-rustls 0.26; OpenSSL 3.0.13 with tokio-openssl 0.6 |
| net-io | 0.6.1 |
| Build | release profile: `opt-level = 3`, fat LTO, one codegen unit |

The machine is shared with other build and soak work. During these measurements its load average moved between about 110 and 500 on 32 threads. The method is built for that (next section), and every figure below names the load it was taken under where it matters. The spec's reference platform is Linux on bare metal with 60-second runs; until one is available, the numbers here are WSL2 and Windows numbers and are labelled so.

---

## Method

**Same configurations (D-098).** tls-net is compared with rustls's unbuffered connection built from tls-net's own rustls configurations, taken through the `rustls-escape-hatch` feature: identical suites, groups, certificate resolver, and ticketer. Both are driven by the same in-memory driver (`benches/common`), which copies received plaintext into an application buffer once, as an application would. The only difference left is tls-net's session layer.

**Paired rounds.** `benches/paired.rs` times one tls-net operation and one rustls operation back to back in each round, for thousands of rounds, and compares medians. Load that drifts during the run reaches both sides alike, so the ratio holds on a busy machine where criterion's absolute times do not. This is the check for the "within 3%" and "per record" targets, and the regression check between versions: a ratio that moves by more than 5% blocks the change.

**Criterion** (`benches/session.rs`, `hello.rs`, `config.rs`) gives absolute times for the parts tls-net owns. Absolute times are only comparable within one session on one machine: compare a change with `--save-baseline` before and `--baseline` after, back to back. `cfg(tls_net_bench)` exposes the crate-private SNI table and configuration cell to these benches only (D-097).

**Memory** (`benches/memory.rs`): a counting global allocator measures heap bytes held by an idle connection after its handshake, the inline size of the session, and allocations per record each way.

**End to end** (`perf/`, D-099, D-103): a separate workspace that is never published and never a dependency of tls-net. tokio and OpenSSL appear only there.

- Servers: tls-net on net-io's reactor (8 workers, one reuse-port listener per worker, no graceful linger, connection and per-source caps lifted to 9,000, since all load comes from one address), tokio with tokio-rustls (8 worker threads, aws-lc, the rustls `Ticketer`, two tickets per handshake as tls-net sends), and tokio with tokio-openssl (`mozilla_intermediate_v5`). The certificate is the same ECDSA P-256 key everywhere. Every server answers `GET /` with a short response and closes, and `GET /bulk` with 16 KiB writes until the client leaves.
- Placement: servers on one thread of each of 8 physical cores of the first CCD (CPUs 0, 2, ..., 14), the load generator on the second CCD (CPUs 16 to 31).
- Load generator: blocking rustls clients, X25519 (the group all three stacks share; OpenSSL 3.0 has no ML-KEM), no resumption; 64 threads making one request per connection for handshakes, 8 connections streaming for bulk.
- Interleaving: all servers run at once (an idle server costs nothing), and the generator visits each in turn for a 3-second window, 9 rounds, rotating the order. Each stack gets the same load from the rest of the machine.
- Reported: the median rate over the rounds, and the median server CPU time per operation (user plus system from `/proc`). The rate depends on the client's concurrency and the machine; CPU per operation sets what 8 cores can do at saturation. D-105 requires both to clear 1.2x.
- Profiles: `PERF_PROFILE` samples a server's CPU with pprof's signal timer and writes folded stacks. Within one process the shares are useful; sample counts are not comparable between processes, since signal sampling loses samples unevenly.

---

## tls-net against rustls

### Paired (medians)

Linux: WSL2, one core (`taskset -c 6`), 3,000 rounds, load about 120. Windows: 4,000 rounds.

| Operation | Linux tls-net | Linux rustls | Linux ratio | Windows ratio |
|---|---|---|---|---|
| full handshake | 442.2 µs | 432.7 µs | 1.022 | 1.007 |
| resumed handshake | 255.6 µs | 249.4 µs | 1.025 | 1.007 |
| full handshake, tls-net server only | 429.6 µs | 421.6 µs | 1.019 | |
| full handshake, tls-net client only | 435.0 µs | 429.1 µs | 1.014 | |
| `step`, 1 KiB record | 349 ns | 317 ns | 1.101 | 1.064 |
| `step`, 16 KiB record | 1.82 µs | 1.61 µs | 1.132 | 1.033 |
| `encrypt`, 1 KiB record | 338 ns | 327 ns | 1.034 | 0.994 |
| `encrypt`, 16 KiB record | 1.62 µs | 1.61 µs | 1.002 | 1.000 |

- Handshakes: the server's first step (hello parse, JA4, SNI lookup) costs 1.6 to 2.5 µs more than rustls's; the client side's share fell when the peer identity became lazy (D-104). Windows shows less overhead than Linux, where the crypto itself is faster, so the fixed cost is a larger share.
- `step` at 16 KiB: tls-net bounces each record's plaintext through the output buffer back into the input (D-035), one 16 KiB copy more than the driver's single copy; the measured difference is about that one copy. rustls 0.24's in-place reads remove it (0.9).

### Criterion (Windows, lightest load of the run)

| Bench | Time |
|---|---|
| `hello/hello_parse` (1,491-byte hello) | 283 ns |
| `hello/ja4` | 398 ns |
| `hello/parse_and_ja4` | 816 ns |
| `hello/ja3_string` | 400 ns |
| `sni_lookup` exact / wildcard / miss, 10,000 names | 75 / 101 / 90 ns |
| snapshot publish / load | 25 / 17 ns |
| `reload` build / publish, 100 certificates | 1.74 / 1.75 ms |
| ticket seal / open, ephemeral ring | 1.89 / 1.52 µs |
| ticket seal / open, ratchet ring | 1.63 / 1.46 µs |
| ticket seal / open, rustls `Ticketer` (aws-lc) | 0.71 / 0.32 µs |
| `TlsServer::accept` / `ServerReader::accept` | 61 / 37 ns |
| `custody` resident / per-signature (full handshake) | 301 / 292 µs |

Tickets: 1.4 to 1.5 µs of each operation is crypt-io's XChaCha20-Poly1305; the rest is the ring and the header (D-100). A full handshake seals two tickets, about 1 µs more than rustls's `Ticketer`, or 0.3% of a handshake.

### Memory (Linux)

| | heap | inline | total |
|---|---|---|---|
| idle tls-net server session after the handshake | 1,074 B | 1,336 B | 2,410 B |
| idle rustls unbuffered server connection | 1,065 B | 1,088 B | 2,153 B |

tls-net adds 257 bytes per idle connection (D-096, D-104). Records allocate once each way in rustls 0.23 and never in tls-net's code.

---

## End to end

Interleaved, 9 rounds of 3 seconds, net-io 0.6.1, load about 130.

| Stack | Handshakes/s | Server CPU per handshake | Bulk MB/s (8 connections) | Server CPU per GB |
|---|---|---|---|---|
| tls-net on net-io reactor | 2,517 | 617 µs | 2,072 | 1,062 ms |
| tokio + tokio-rustls | 1,739 | 589 µs | 1,680 | 1,278 ms |
| tokio + tokio-openssl | 1,333 | 1,417 µs | 1,716 | 1,363 ms |

- Bulk: 1.23x tokio-rustls's rate and 17% less CPU per byte (1.20x as much work per CPU second).
- Handshakes: 1.45x the rate, the reactor's shorter turnaround. CPU per handshake is 5% above tokio-rustls's, so at saturation the two would be about even. The same run at load 500 gave 0.88x the rate; the rate is a property of the client and the machine as much as of the server, which is why D-105 counts CPU too.
- Both stacks send exactly four data segments per connection (flight, tickets, response, close_notify; counted from the client's `TCP_INFO`). Within the reactor's profile, send syscalls are about 25% of a handshake's CPU and accept, poll, and epoll about 8%.

### net-io 0.6.2

Same method, net-io 0.6.2, load about 530 (the soak and six fuzz targets had just ended; other work kept the machine busy). `tls-net-shared` is one listener shared by the workers with net-io's default linger, the setup 0.6.2's placement fix is for (net-io D-174, D-177); `tls-net` is the per-worker setup above.

| Stack | Handshakes/s | Server CPU per handshake | Bulk MB/s (8 connections) | Server CPU per GB |
|---|---|---|---|---|
| tls-net, per-worker listeners | 506 | 1,099 µs | 265 | 3,422 ms |
| tls-net, one shared listener | 503 | 1,051 µs | 287 | 3,434 ms |
| tokio + tokio-rustls | 540 | 832 µs | 222 | 3,556 ms |
| tokio + tokio-openssl | 353 | 1,774 µs | 204 | 4,179 ms |

- The shared listener now matches the per-worker setup (rate within 1%, CPU within 5%, inside the run's spread): 0.6.2 no longer piles short connections onto one worker.
- At this load tls-net's CPU per handshake is 0.76x to 0.79x tokio-rustls's, against 0.96x at load 130. Not profiled at this load; the likely cause is the reactor's per-connection syscalls (above), which a contended machine makes dearer. The 1.0 gate is judged at the lower load or on bare metal, and on net-io 0.8 (D-180).
- Bulk holds its lead: 1.2x to 1.3x the rate, about the same CPU per byte.

### Idle connections

`perf/idle.sh`: the client completes N handshakes and holds the connections; server RSS before and after. `WARM=1` fetches a 32 KiB page on each connection first.

| Stack | Cold: open, bytes each | Warm: open, bytes each |
|---|---|---|
| tls-net on net-io 0.6.1 | 4,096, 25,792 | 3,288, 102,051 |
| tls-net on net-io 0.6.2 | 9,000, 9,991 | 9,000, 39,322 |
| tls-net on net-io 0.7.0 | 9,000, 8,971 | 9,000, 42,030 |
| tokio + tokio-rustls | 9,000, 11,418 | 9,000, 11,651 |
| tokio + tokio-openssl | 9,000, 15,816 | 9,000, 15,816 |

net-io 0.6.1 keeps two 64 KiB buffers per TLS connection for its whole life, which also caps the reactor at 4,096 TLS connections under its default 512 MiB buffer budget (connection 4,097 closes with `Limit(Connections)`). On 0.6.2 all 9,000 connections open, and a connection that has never carried data costs 13% less than tokio-rustls's; one that has carried a page still keeps 3.4x as much, the buffers net-io 0.7.0 gives back while a connection is idle (net-io D-181). tokio-rustls's 0.6.2-run figures (11,447 cold, 11,563 warm) match the table's. On 0.7.0 a cold connection costs 22% less than tokio-rustls's (11,447 in the same run). The warm figure did not move: on the reactor's TLS path a session waiting for input never reached the call that gives the buffers back, so they stayed (net-io D-200, fixed in net-io 0.7.1). A counting allocator shows tls-net's own session holding 96 bytes more after a 32 KiB page each way, so the rest is net-io's buffers.

---

## Open gaps

| Gap | Where | Plan |
|---|---|---|
| CPU per handshake 0.96x tokio-rustls (target 1.2x) | net-io reactor | Send the tickets, the first response, and close_notify together when one turn produces them (four sends per connection to two), and accept on the worker when listeners are per worker. Reported to net-io with profiles; re-measured on each net-io release |
| idle memory after traffic 3.6x tokio-rustls on net-io 0.7.0 (target 0.7x; cold connections already 0.78x) | net-io reactor | net-io 0.7.0 gives TLS buffers back while a connection is idle (net-io D-181), but its reactor skipped that for a session waiting for input (net-io D-200); the fix is in net-io 0.7.1, which tls-net 0.7.1 accepts. Re-measured on 0.7.1 |
| `ServerReader::accept` 37 ns (target 20 ns) | tls-net | Four atomic operations are left, the capacity gate's and the snapshot's reference count; going lower would give up the server-wide handshake bound (D-102). Accepted |
| D-035 copy, one extra copy per received record | rustls 0.23 | rustls 0.24's in-place reads (0.9) |
| bare-metal Linux numbers | hardware | Re-run `perf/` and the paired bench on bare-metal Linux when one is available |

The first row is scheduled in net-io 0.8 (net-io D-180); the second is fixed in net-io 0.7.0 (net-io D-181) and is re-measured there. They are part of the 1.0 gate (D-106): 1.0 does not ship until both are met.

---

## Running the measurements

```bash
cargo bench --bench paired --features rustls-escape-hatch
```

```bash
RUSTFLAGS="--cfg tls_net_bench" cargo bench --features rustls-escape-hatch
```

```bash
bash perf/ab.sh handshakes 9 3
```

```bash
bash perf/ab.sh bulk 9 3
```

```bash
bash perf/idle.sh 9000
```

```bash
WARM=1 bash perf/idle.sh 9000
```

`PAIRED_ROUNDS` sets the paired bench's rounds (default 3,000). `SERVER_CPUS`, `CLIENT_CPUS`, `THREADS`, and `BULK_THREADS` adjust `perf/ab.sh`. `perf/` needs Linux, `taskset`, `bc`, and the OpenSSL development package.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>
