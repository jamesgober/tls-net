# tls-net - 1.0 readiness

> **Draft, as of 0.10.0 (2026-11-11).** What 1.0 needs, item by item: what is met, with the evidence, and what is open, with who closes it. 1.0 ships only on James's explicit go (ROADMAP 1.0); this file becomes the 1.0 audit record then. Design and reasons: [`../dev/PLAN.md`](../dev/PLAN.md); the gate: [`../dev/ROADMAP.md`](../dev/ROADMAP.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

---

## Contents

- [Verdict](#verdict)
- [Definition of done](#definition-of-done)
- [The 1.0 gate](#the-10-gate)
- [Performance targets](#performance-targets)
- [Security](#security)
- [API](#api)
- [Open work before 1.0](#open-work-before-10)
- [Decisions for James](#decisions-for-james)

---

## Verdict

**Not ready.** Three gate items are open, and none of them is in tls-net's code:

1. **CPU per handshake end to end:** 0.96x tokio-rustls against a 1.2x target. The cost is in net-io's reactor, and the fix is scheduled for net-io 0.8 (D-106).
2. **Production use:** direct mode of the first site and smtp-net have not yet used the API end to end in production (DIRECTIVES section 3, item 10).
3. **24-hour NFR-21 soak:** it has run for 6 hours; the 24-hour run is a 1.0 gate item (D-108).

Everything else tls-net owns is met or is listed under [Open work before 1.0](#open-work-before-10) with a plan.

---

## Definition of done

DIRECTIVES section 3, checked at 0.9.1.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Clean on Linux, macOS, Windows, stable and 1.85 | met | CI `Test` matrix (six jobs), every PR since 0.1 |
| 2 | fmt, clippy `-D warnings` (all targets, all and no default features), tests, `cargo doc -D warnings` | met | CI; local gates before every push. `fips` builds in its own Linux job (it needs CMake and Go) |
| 3 | `cargo audit` and `cargo deny check` | met | CI `Security (audit + deny)` |
| 4 | No `unwrap`, `expect`, `todo!`, `dbg!`, or printing in shipping code | met | clippy with `unwrap_used`, `expect_used`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`, `print_stderr`, and `panic` on the library, all features: clean at 0.9.1 |
| 5 | A Tier-1 API headlines the docs | met | `README.md`, `docs/API.md` "Tier 1" |
| 6 | Standards cases whole and split at every byte; a property test per invariant; a fuzz target per parser or decoder; an attack test per threat | met, one gap | T-1 to T-30 each have an attack test (`docs/SECURITY.md`); `tests/properties.rs`; seven fuzz targets. The seventh, `import_sealed`, was added at 0.9.1 (the testing plan listed it, but it had not been written); its 24-hour run is open |
| 7 | Hot-path changes carry benchmarks; no regression over 5% | open | the re-tune against the 0.6 baselines is a 0.9.x item; it needs a quiet machine |
| 8 | `README.md`, `docs/API.md`, `CHANGELOG.md`, release notes | met | updated each release; `docs/release/` |
| 9 | Decision log for every design decision | met | `dev/PLAN.md` D-001 to D-142 |
| 10 | Direct mode of the first site and smtp-net have used the API end to end; an adversarial review with every finding fixed test-first | half met | review: 0.9.0, 2 high, 2 medium, 9 low, all fixed test-first (D-125 to D-137). Production use: open, see [Decisions for James](#decisions-for-james) |

---

## The 1.0 gate

ROADMAP 1.0.

| Item | Status | Notes |
|---|---|---|
| Full audit recorded here | draft | this file |
| Every end-to-end target of PLAN section 9, including the two carried from 0.6 (D-106) | one open | idle memory met on net-io 0.7.1 (0.50x tokio-rustls, D-123); CPU per handshake open (0.96x, target 1.2x), waiting on net-io 0.8 |
| Production use (DIRECTIVES 3, item 10): two weeks on staging for direct mode; RC builds in production for smtp-net | open | serve-net is on tls-net 0.7.1 and has been asked to move to 0.9; smtp-net pins 0.5 |
| API frozen until 2.0 | from 1.0 | 0.10.0 changed the API after the simplicity audit (James: the API may be simplified before 1.0); it is frozen again at the 1.0 release |
| 24-hour NFR-21 soak (D-108) | open | 6 hours run at 0.7 with no live-heap growth (`docs/SECURITY.md`); the 24-hour run needs a machine that stays up and quiet for a day |

---

## Performance targets

The full table with measured values is in `docs/PERFORMANCE.md`, "Summary". The targets that are not plainly met:

| Target | Measured | Status |
|---|---|---|
| Loopback handshakes, CPU per handshake, 1.2x tokio-rustls | 0.96x (rate 1.45x) | open, net-io 0.8 (coalesced sends, accept on the worker) |
| `ServerReader::accept` under 20 ns | 37 ns | accepted (D-102): the remaining cost is the server-wide handshake bound, which stays |
| SNI wildcard lookup under 100 ns | 101 ns | at the limit; re-measured in the 0.9.x re-tune |
| One extra copy per received record (D-035) | 210 ns per 16 KiB record | goes away with rustls 0.24's in-place reads; not a 1.0 blocker |

All numbers were measured on Windows and on WSL2. There are no bare-metal Linux numbers yet (see [Decisions for James](#decisions-for-james)).

---

## Security

- **Threats:** T-1 to T-30 each have a defence, an attack test, and a stated cost (`docs/SECURITY.md`).
- **Fuzzing:** six targets ran 24 hours each at 0.7 with one finding, fixed (D-111). The seventh (`import_sealed`, 0.9.1) is open.
- **Conformance:** testssl.sh and tlsfuzzer run weekly in CI. One finding was fixed (D-110).
- **Miri and loom:** both run in CI.
- **Adversarial review:** done at 0.9.0 with three independent reviewers, and every finding was fixed test-first.
- **Dependencies:** rustls is the only third-party runtime dependency. Cryptography goes through crypt-io. At 0.9.1 every dependency is on its newest stable release: rustls 0.23.46, aws-lc-rs 1.19.0, ring 0.17.14, webpki-roots 1.0.11, rustls-platform-verifier 0.7.1, crypt-io 1.5.0, key-vault 1.1.0, net-io 0.7.1.
- **Unsafe code:** `#![forbid(unsafe_code)]`.
- **Still to do before 1.0:** re-run the security review over the 0.9.x changes (threat table, attack tests, footprint, audit, deny). This is a 0.9.x item.

---

## API

- **Documented:** every public item is in `docs/API.md`, and every item there exists (D-138). Since 0.10.0 every example in it and in the README compiles as a doctest, so the two cannot drift apart.
- **Changed at 0.10.0:** the simplicity audit below. Renames and removals are mapped in `docs/MIGRATION-0.10.md`. Before that, 0.9.1 fixed `alert()` to report the alerts rustls sends for certificate refusals (D-139).
- **Waiting for rustls 0.24:** the exporters and channel binding (RFC 9266) are documented and will be added in a 1.x minor when rustls 0.24 is stable (D-124). Only 0.24.0-dev.2 exists today. Adding them is additive and does not break 1.0.
- **After 1.0 (P3, ROADMAP):** early data, kTLS hand-over, QUIC, raw public keys, client-side ECH, certificate compression, the Windows key file ACL check, and dynamic record sizing.

### Simplicity audit (0.10)

Checked against the bar for the API: Tier 1 calls with no builder cover about 80% of uses and work with plain `?`; a newcomer can read the names without the docs; there is one way to do each thing; `docs/API.md` lists every public item with compiled examples. The usage evidence is the two dependents (serve-net, smtp-net) and tls-net's own tests.

| # | Finding | Evidence | Fix (0.10.0) |
|---|---|---|---|
| S-1 | Tier 1 stopped at the session: a client or server built in one line could not be used over a socket without a hand-written `step` loop | three copies of that loop: serve-net's test client (about 80 lines), smtp-net's TLS layer (about 300 lines, with the input minimum hard-coded as `18_437`), and tls-net's own test helper | `TlsStream` over any blocking `Read + Write`: `client.connect_stream("example.com", tcp)?` and `server.accept_stream(tcp)?`; `TlsStream::client` and `TlsStream::server` take a session made another way (`connect_to`, STARTTLS) |
| S-2 | Three `TlsServer` methods repeated fields of `stats()`, and `server.version()` read as the TLS version when it is the configuration's reload count | `handshakes_in_progress`, `sni_disagreements`, `version` | removed; `stats()` is the one way; `ServerStats::snapshot_version` is `config_version` |
| S-3 | `ServerReader` and `TlsServer::reader()` read as something that reads data; the type is a per-worker accept handle | the rustdoc had to say so | `WorkerAcceptor` and `TlsServer::worker_acceptor()` |
| S-4 | `HelloParser`, a unit struct holding one function, and `HelloParse`, its result, were named one letter apart | `HelloParser::parse(input, &limits)` | a function, `parse_client_hello(input, &limits)`; `HelloParser` removed |
| S-5 | `INCOMING_MIN` and `OUTGOING_MIN` did not say what they size | smtp-net hard-codes `18_437` rather than use the constant | `MIN_INPUT_BUFFER` and `MIN_OUTPUT_BUFFER`, named after `step`'s `input` and `output` |
| S-6 | Two ways to get each builder: `TlsServer::builder()` and `ServerBuilder::new()` (and `Default`), the same for the client | serve-net's test uses one of each | `TlsServer::builder()` and `TlsClient::builder()` only |
| S-7 | `docs/API.md` was not in the house format, and none of its 85 code blocks was compiled, so they could drift from the build | its status line still said 0.9.0 | the house format (header, navigation, nested contents), and every example compiled as a doctest with the README |

Kept, with reasons:

- **Tier 1 configuration.** `server_from_pem`, `server_from_files`, `client()`, and `client_with_ca_pem` already build a server or client in one line with plain `?`, and on net-io a server is one more line (`.tls(tls)`).
- **`start_after_plaintext` beside `connect`.** It refuses plaintext an attacker injected before the upgrade (STARTTLS injection), which `connect` cannot know about.
- **`reload_from_pem` and `reload_from_files` beside `ReloadHandle::publish`.** The first two swap one certificate (Tier 1); `publish` swaps a whole configuration (Tier 2).
- **`certificate`, `certificate_for`, `certificate_der`.** Three different inputs: PEM as the default, PEM for named hosts, and DER.
- **Domain abbreviations** (ALPN, SNI, CRL, OCSP, DER, PEM, JA4, SPKI). These are the words the RFCs and operators use. Spelling them out would make the API harder to match against the standards.
- **One error type.** `TlsError`, with stable codes and a retry category; no rustls type is public.

---

## Open work before 1.0

Technical items tls-net closes itself, in 0.9.x:

| Item | Plan |
|---|---|
| The back-channel test failure seen once in CI on PR 9 | It is most likely the server refusing a valid peer: a TLS 1.3 client learns of a refusal as a reset on its first write. The test now prints the server's events, the socket error, and the alert when one arrives (D-139), so the next failure names the cause. It stays open until explained (ROADMAP 0.9.x) |
| `import_sealed` fuzz target, 24 hours | Run with `fuzz/run-24h.sh` |
| The edge-case list of PLAN section 10 (59 groups) | Not in the repository. It will be written out as a checklist next to the tests and checked off against them |
| Performance re-tune against the 0.6 baselines; the SNI wildcard lookup | `perf/` and criterion on a quiet machine. The shared build machine has been under heavy load from other work |
| Security review re-run | Over the 0.9.x changes |
| `docs/ARCHITECTURE.md` | Required by 1.0 and not written yet; the design lives in `dev/PLAN.md` section 6 and is to be condensed into it |
| CPU per handshake on net-io 0.8 | Measure with `perf/` when net-io 0.8 is released |
| 24-hour soak | `perf/soak.sh` for 24 hours on a machine that stays up |

---

## Decisions for James

1. **Production use, and who starts it.** 1.0 needs the first site's direct mode on staging for two weeks and smtp-net RC builds in production. The two weeks cannot start until serve-net is on tls-net 0.9: it is on 0.7.1, and a peer can make the `close()` panic fixed in 0.9.0 happen through it. smtp-net pins 0.5. **Recommendation:** move both to `tls-net = "0.9"` now and start the two-week clock. Nothing in 0.9.x changes the API they use.
2. **Whether 1.0 waits for net-io 0.8.** The CPU-per-handshake target (1.2x tokio-rustls) is open at 0.96x, and the fix is in net-io's reactor, not in tls-net (D-106). **Recommendation:** wait, as D-106 recorded. The handshake rate is already 1.45x, but the target was set for CPU, and net-io 0.8 is scheduled to fix it.
3. **Bare-metal Linux.** Every Linux number so far is from WSL2. **Recommendation:** not a 1.0 blocker. If a bare-metal Linux machine (or a short-term cloud host) is available, the `perf/` and paired benchmarks should run there once before 1.0, so the published numbers are not WSL-only.
4. **The rustls issue.** D-111's root cause is in rustls 0.23's unbuffered API: after a fatal error it keeps reading input, and each bad record queues another fatal alert. tls-net guards against this. Reporting it upstream is a public filing, so it is your call. **Recommendation:** file it. An upstream fix would let tls-net's guard go, and other users of the unbuffered API have the same exposure.
