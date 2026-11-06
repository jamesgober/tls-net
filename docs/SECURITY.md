# tls-net - Security

> The threat model, every threat with its defence, its test, and its cost; where tls-net is deliberately stricter than the RFCs; and the 0.7 hardening record (threat audit, fuzz campaign, soak, conformance runs, Miri). Every threat T-1 to T-28 has an attack test. Design and reasons: [`../dev/PLAN.md`](../dev/PLAN.md) section 8 and the decision log.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

---

## Contents

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Threat model](#threat-model)
- [Threats, defences, tests, costs](#threats-defences-tests-costs)
- [Hardening record (0.7)](#hardening-record-07)
- [Where tls-net is stricter than the RFCs](#where-tls-net-is-stricter-than-the-rfcs)
- [What tls-net does not defend against](#what-tls-net-does-not-defend-against)

---

## Reporting a vulnerability

Email **me@jamesgober.com** with "tls-net security" in the subject. Please include the version, a description of the issue, and a way to reproduce it. Do not open a public issue for a vulnerability.

You will get an answer within three working days. A confirmed issue gets a fixed release, a GitHub security advisory, and a credit in the release notes if you want one.

tls-net is pre-1.0: fixes go into the newest release only.

A flaw in the TLS protocol implementation or the cryptography belongs to rustls or to the provider (aws-lc-rs, ring); tls-net forwards such reports and ships the fixed version promptly.

---

## Threat model

**Assets:** the confidentiality and integrity of the traffic; the server's private keys and ticket keys; the identity a session reports (SNI, peer certificate, ALPN), which other components act on; the server's CPU and memory.

**Attackers:** any network peer, on either side, who controls every byte it sends, can open many connections, replay recorded traffic, present any certificate, and measure timing; a party in the path who can rewrite or drop bytes; another crate in the same process that installs a process-wide rustls provider.

**Trust boundary:** every byte given to `step` is hostile. Configuration (certificates, keys, policies, limits) is trusted to mean what the operator wants, but it is validated at load so a weak or broken configuration is refused rather than served. The attacker does not control configuration files or process memory; a reader of process memory defeats key custody, as key-vault's own documentation says.

**Out of scope here, in place elsewhere:** the TLS state machine and the cryptography (rustls and its provider), connection limits and deadlines (net-io), rates and bans (bouncer-io), `Host` against SNI (the HTTP layer).

---

## Threats, defences, tests, costs

Costs are per handshake or per record unless stated; measured values are from `docs/PERFORMANCE.md`, estimates are marked [est.]. Every test below runs in CI on Linux, macOS, and Windows unless noted.

| Id | Threat | Defence | Test | Cost |
|---|---|---|---|---|
| T-1 | Version downgrade to TLS 1.1 or lower, or from 1.3 to 1.2 | rustls has nothing below TLS 1.2; `Version` has two variants; clients check RFC 8446's downgrade sentinel | `tests/attacks.rs` (`test_t1_*`: a TLS 1.1-only hello gets `protocol_version`; `supported_versions` stripped in transit is refused by the client); `tests/interop.rs` (OpenSSL TLS 1.1) | 0 |
| T-2 | TLS 1.3 to 1.2 downgrade on internal channels | `Policy::internal` and `Policy::modern` are TLS 1.3 only | `tests/extended.rs` (`test_t2_t4_*`: a TLS 1.2-only peer against an internal listener gets `NoCommonVersion`); `tests/handshake.rs`, `tests/interop.rs` (modern listener) | 0 |
| T-3 | Weak suites or key exchange | AEAD with ECDHE only; the policy enums cannot name anything else; empty lists refused | `tests/attacks.rs` (`test_t3_*`: a CBC and 3DES-only hello gets `handshake_failure`; policies cannot name weak suites) | 0 |
| T-4 | Post-quantum stripping | the TLS 1.3 transcript covers the negotiation; internal listeners accept only X25519MLKEM768 | `tests/attacks.rs` (`test_t4_*`: groups reordered in transit fail both sides); `tests/extended.rs` (internal listener refuses X25519-only and P-256-only peers) | ML-KEM-768 adds about 2.3 KiB per handshake and [est. tens of µs] CPU |
| T-5 | STARTTLS stripping and injection | `start_after_plaintext` refuses any byte after the `220` reply; smtp-net requires TLS | `tests/attacks.rs`, `tests/complete.rs` (`220 ready\r\n250 injected\r\n` in one segment gives `StartTlsInjection`, unit and over TCP) | 0 |
| T-6 | Wrong or misissued server certificate | rustls-webpki path validation and name check; optional CRLs; pins | `tests/handshake.rs` (wrong name, unknown root); `tests/attacks.rs` (`test_t6_*`: expired, self-signed, revoked by CRL against a CRL-free control) | rustls's [est. tens to hundreds of µs per chain] |
| T-6b | Pin bypass by a verifier that skips signature checks | the pinned verifier calls rustls's signature verification; constant-time pin comparison | `tests/extended.rs` (`test_t6b_*`: the pinned certificate signed with another key is refused) | one signature verification, as without pinning |
| T-7 | Renegotiation and the triple handshake | rustls does not renegotiate; extended master secret required for TLS 1.2 | `tests/attacks.rs` (`test_t7_*`: a TLS 1.2 client without EMS is refused). A renegotiation attempt cannot be produced against tls-net: tlsfuzzer's renegotiation script sends no EMS and is refused first; rustls has no renegotiation code to reach | 0 |
| T-8 | Private key leakage through logs, errors, dumps, freed memory | key-vault custody; PEM and DER buffers wiped; no key or ticket secret in any `Debug` or `Display`; key file permission check (Unix); key log absent by default and refused with FIPS | `tests/complete.rs` (`test_t8_*`: the `Debug` of every type that can hold key material, and the key errors' `Display`, scanned for the test key and a known ticket seed, raw, hex, and listed); `src/pem.rs` (a world-readable key file is refused) | vault access 34 to 157 ns; per-signature custody about the same handshake rate as resident keys |
| T-9 | Weak or wrong server configuration shipped | validation at load (key strength, signature algorithm, key match, chain order, expiry, purpose, names); reload refuses rather than degrades | `tests/attacks.rs` (`test_t9_*`: RSA-1024, SHA-1, mismatched key, reversed chain, expired, client-only purpose, P-521, wrong name: each its named error) | build time only |
| T-10 | 0-RTT replay | no early data: tickets carry `max_early_data_size` 0 | `tests/extended.rs` (`test_t10_*`: a rustls client with early data enabled resumes and has no 0-RTT window; data sent after the handshake arrives once) | 0 |
| T-11 | Resumption linkability and ticket-key compromise | `psk_dhe_ke` only; two-epoch ring; the ratchet cannot recompute old keys; per-client ticket stores | `src/tickets.rs` (epoch e-2 refused; a ratchet ticket unreadable after two rotations even with the current key); `tests/attacks.rs` (`test_t11_*`: two clients never resume with each other's tickets) | seal 1.6 µs, open 1.5 µs; 49 bytes per ticket |
| T-12 | Ticket forgery or tampering | XChaCha20-Poly1305 tag checked before use; version and epoch in the associated data; open never panics | `src/tickets.rs` (bit flips at every position, every truncation, 4,000 seeded random tickets); fuzz target `ticket_open` | as T-11 |
| T-13 | Handshake CPU exhaustion | capacity cap checked in `accept` before any parsing; bouncer-io rates; ECDSA preferred; resumption; net-io's handshake deadline | `tests/attacks.rs` (`test_t13_*`: refused at the cap before any parse); `tests/net_io.rs` (`test_t13_*`: a stalled handshake's slot comes back at net-io's deadline) | `accept` 61 ns |
| T-14 | ClientHello parser abuse | lengths checked against what remains; counts checked before iterating; 16 KiB, 4-record, and list budgets; linear time; after a failure rustls never reads further input (D-111) | `src/hello.rs` (every budget at n-1, n, n+1); `tests/properties.rs`; `tests/attacks.rs` (`test_t14_*`: malformed hellos, junk after a failure); fuzz targets `hello_parse`, `session_step_server`, `session_step_client` | parse 0.28 µs, parse plus JA4 0.82 µs for a 1.5 KiB hello |
| T-15 | Cross-protocol attacks (ALPACA) | strict ALPN; `AlpnPolicy::Required` on internal listeners; unknown SNI refused without a default | `tests/handshake.rs` (an HTTP ALPN against an SMTP-only listener); `tests/extended.rs` (unconfigured SNI on a back-channel listener) | 0 |
| T-16 | Domain fronting | the session reports the normalised SNI; the HTTP layer compares it with `Host` | `tests/extended.rs` (`test_t16_*`) | 0 |
| T-17 | Truncation | `close_notify` tracked; EOF without it is `Unclean` | `tests/handshake.rs` (`test_unclean_eof_is_reported_t17`) | 0 |
| T-18 | Certificate expiry outage | proportional warning thresholds; expiry events; reload refuses expired certificates | `src/expiry.rs` (warn at `not_after - lifetime/3`); `tests/attacks.rs` (`test_t18_*`: an expired certificate in a reload is refused and the old one is still served) | report under 1 µs per entry |
| T-19 | Half-written files during reload | key match check; reload is all or nothing | `tests/extended.rs` (`test_reload_keeps_handshakes_in_progress_t19`: new chain with old key refused, old certificate served, handshakes in flight across both a good and a refused reload complete) | as a reload (1.74 ms for 100 certificates) |
| T-20 | Log or terminal injection through SNI or ALPN | SNI validated as LDH ASCII, anything else treated as absent; events carry SNI only in normalised form and ALPN only as configured names | `tests/attacks.rs` (`test_t20_*`: control bytes in SNI treated as absent; no event holds a raw control byte with every hello sampled) | part of the hello parse |
| T-21 | Timing side channels in tls-net's code | constant-time pin and secret comparisons; AEAD for tickets | `src/verify.rs` (`test_t21_*`, opt-in statistical timing test, Linux CI) | negligible |
| T-22 | Client certificate abuse (huge chains) | chain length and size budgets; handshake byte budget; rustls's 64 KiB handshake message limit; webpki path limits | `tests/attacks.rs` (`test_t22_*`: a 50-certificate chain and a 1 MiB certificate refused, against a control that passes); `tests/extended.rs`, `tests/handshake.rs` (budgets on both sides) | 0 |
| T-23 | Supply chain | small pinned tree; `cargo audit` and `cargo deny` in CI; banned crates; lockfile review | CI `Security (audit + deny)`; `tests/complete.rs` (`test_t23_*`: no banned crate in the tree; fails on CI if `cargo tree` cannot run) | build time |
| T-24 | Stolen hand-off export | sealed with XChaCha20-Poly1305 under a wrap key; older than one epoch refused; wiped on drop | `tests/complete.rs` (wrong wrap key, tampering at every byte, truncation); `src/tickets.rs` (an export two epochs old refused, one epoch old taken) | microseconds per restart |
| T-25 | SNI probing of hosted names | `UnknownName::Refuse` gives the same alert for every unknown name; the lookup is two hash lookups | `tests/attacks.rs` (`test_t25_*`: 1,000 probes get identical bytes; refusal time near a hosted wildcard equals that elsewhere, opt-in timing test, Linux CI) | 0 |
| T-26 | Legacy attack classes (BEAST, POODLE, Lucky13, CRIME, FREAK, Logjam, Raccoon, ROBOT, Sweet32, Heartbleed, DROWN) | the features they need do not exist in rustls | testssl.sh vulnerability checks in the conformance workflow (weekly): every one "not vulnerable" | 0 |
| T-27 | Memory exhaustion through half-open handshakes | capacity cap; handshake byte budget; no rustls connection until a whole hello has arrived; net-io's buffer limits and deadline | `tests/complete.rs` (`test_t27_*`: 10,000 one-byte half-open connections); `tests/alloc.rs` (`test_t27_*`: `accept` plus a one-byte `step` allocates nothing) | the session's inline size, under 2 KiB, per half-open connection |
| T-28 | Process-wide provider confusion | tls-net never reads or installs the process default | `tests/provider.rs` (`test_t28_*`: after another crate installs a secp384r1-only default, tls-net still negotiates X25519MLKEM768) | 0 |

---

## Hardening record (0.7)

**Threat audit.** Every row above was checked against the threat table's planned tests in `dev/PLAN.md` and against the test code: the cited test exists, and its assertions attack what the row describes. The audit found 20 rows with a part of the planned test missing or weaker than described, for example T-1 had no downgrade-sentinel case, T-10 never checked that the client actually resumed, T-12's "random tickets" were two fixed inputs, and T-22 used a short chain under a small budget instead of a 50-certificate chain. Each gap now has a test; the planned wording was corrected where the test checks something more precise.

**Defects found and fixed in 0.7:**

- **D-110, found by tlsfuzzer.** The ClientHello parser accepted only record versions `0x0301` to `0x0303`, so a hello in a `0x0300` record (tlsfuzzer, older stacks) was refused with no alert before rustls saw it. RFC 5246 appendix E.1 requires a server to accept any `{03,XX}`; rustls does. Now accepted. No security effect: the record version never selects the protocol.
- **D-111, found by the session fuzz targets.** After a rustls error, tls-net called rustls again to collect the alert; with nothing queued, rustls read the next record, and a second malformed record made it queue a second fatal alert. That trips a `debug_assert!` in rustls, a panic in any debug build of an application from bytes a peer sends; release builds were not affected beyond an unsent second alert. Now rustls is called after a failure only while it holds queued records. Regression tests replay the fuzzers' inputs on both sides.

**Fuzz campaign.** Six targets, seeded with 18 real ClientHellos (Chromium, Windows Schannel, OpenSSL, curl, wget, Python, rustls) and 7 real server flights (`fuzz/seeds/`, D-108), each run for 24 hours at low priority on WSL2 with AddressSanitizer and debug assertions (`fuzz/run-24h.sh`).

<!-- campaign table: filled when the runs end -->

**Soak.** `perf/soak.sh` (NFR-21): tls-net on net-io's reactor, 8 workers, 32 client threads making mixed full and resumed handshakes, a certificate reload every 60 seconds, a 10-minute ticket epoch.

<!-- soak result: filled when the run ends -->

**Conformance.** `.github/workflows/conformance.yml`, weekly and on demand (D-109):

- testssl.sh 3.2.4 against the example server: no finding of severity HIGH or CRITICAL beyond the test certificate's own (a private CA, a validity to 2099 so fixtures never expire, no CRL or OCSP URI). Every vulnerability check (Heartbleed, CCS injection, Ticketbleed, ROBOT, renegotiation, CRIME, BREACH, POODLE, SWEET32, FREAK, DROWN, LOGJAM, BEAST, Winshock) reports "not vulnerable".

<!-- tlsfuzzer classification: filled from the dual-server run -->

**Miri.** The library tests that need no crypto provider (parsers, PEM intake, SNI, fingerprints, tickets, snapshot, expiry, errors: 66 tests) run under Miri in CI with no undefined behaviour reported (D-112). The providers are C and assembly, which Miri cannot execute.

**loom.** The capacity gate, the configuration snapshot, and the ticket ring are model-checked with loom in CI (NFR-20), including the 0.6 change to the capacity slot (D-102).

---

## Where tls-net is stricter than the RFCs

| Behaviour | RFC | tls-net | Why |
|---|---|---|---|
| A ClientHello that its parser cannot read whole (bad lengths, duplicate extensions, over a budget) | an alert, usually `decode_error` | refused before rustls, with no alert | a scanner learns nothing about the server, and the refusal costs no rustls state (D-014). `HelloLimits::refuse_malformed(false)` hands such hellos to rustls instead |
| ClientHello size | up to 2^24 bytes in one handshake message | 16 KiB by default, in at most 4 records | bounds memory and CPU per half-open connection (T-14, T-27); real hellos are under 2 KiB, post-quantum ones included |
| Lists in the ClientHello | no limit | budgets for cipher suites, extensions, ALPN names, groups, signature algorithms, key shares | linear work per hello with a small constant; each budget is configurable |
| TLS 1.2 without extended master secret | allowed | refused | closes the triple-handshake class (T-7) |

---

## What tls-net does not defend against

- A reader of process memory: keys in memory can be read; key-vault limits how long and where they sit, not whether a privileged attacker can read them.
- Traffic analysis: record sizes and timing are visible; tls-net does not pad records.
- Bugs in rustls or the provider: tls-net pins and audits them, ships fixes promptly, and keeps its own code thin so the attack surface it adds is small.
- Denial of service by volume: tls-net bounds per-connection cost; volume belongs to net-io's limits and bouncer-io's rates.
