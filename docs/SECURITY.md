# tls-net - Security

> The threat model, every threat with its defence, its test, and its cost; where tls-net is deliberately stricter than the RFCs; and the 0.7 hardening record (threat audit, fuzz campaign, soak, conformance runs, Miri). Every threat T-1 to T-30 has an attack test. Design and reasons: [`../dev/PLAN.md`](../dev/PLAN.md) section 8 and the decision log.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

---

## Contents

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Threat model](#threat-model)
- [Threats, defences, tests, costs](#threats-defences-tests-costs)
- [Hardening record (0.7)](#hardening-record-07)
- [Adversarial review (0.9)](#adversarial-review-09)
- [Independent review (0.9.1)](#independent-review-091)
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

**Out of scope here, in place elsewhere:** the TLS state machine and the cryptography (rustls and its provider), connection limits and deadlines (net-io), rates and bans (bouncer-io). The HTTP layer checks each request's `Host` with the `HostScope` tls-net gives it (T-31).

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
| T-8 | Private key leakage through logs, errors, dumps, freed memory | key-vault custody; tls-net's PEM and DER buffers wiped, and a key file's buffer never reallocated (the PEM decoder's own scratch is not wiped, D-135); no key or ticket secret in any `Debug` or `Display`; key file permission check (Unix); key log absent by default and refused with FIPS | `tests/complete.rs` (`test_t8_*`: the `Debug` of every type that can hold key material, and the key errors' `Display`, scanned for the test key and a known ticket seed, raw, hex, and listed); `src/pem.rs` (a world-readable key file is refused) | vault access 34 to 157 ns; per-signature custody about the same handshake rate as resident keys |
| T-9 | Weak or wrong server configuration shipped | validation at load (key strength, signature algorithm, key match, chain order, expiry, purpose, names); reload refuses rather than degrades | `tests/attacks.rs` (`test_t9_*`: RSA-1024, SHA-1, mismatched key, reversed chain, expired, client-only purpose, P-521, wrong name: each its named error) | build time only |
| T-10 | 0-RTT replay | no early data: tickets carry `max_early_data_size` 0 | `tests/extended.rs` (`test_t10_*`: a rustls client with early data enabled resumes and has no 0-RTT window; data sent after the handshake arrives once) | 0 |
| T-11 | Resumption linkability and ticket-key compromise | `psk_dhe_ke` only; two-epoch ring; the ratchet cannot recompute old keys; per-client ticket stores | `src/tickets.rs` (epoch e-2 refused; a ratchet ticket unreadable after two rotations even with the current key); `tests/attacks.rs` (`test_t11_*`: two clients never resume with each other's tickets) | seal 1.6 µs, open 1.5 µs; 49 bytes per ticket |
| T-12 | Ticket forgery or tampering | XChaCha20-Poly1305 tag checked before use; version and epoch in the associated data; open never panics | `src/tickets.rs` (bit flips at every position, every truncation, 4,000 seeded random tickets); fuzz target `ticket_open` | as T-11 |
| T-13 | Handshake CPU exhaustion | capacity cap checked in `accept` before any parsing; bouncer-io rates; ECDSA preferred; resumption; net-io's handshake deadline | `tests/attacks.rs` (`test_t13_*`: refused at the cap before any parse); `tests/net_io.rs` (`test_t13_*`: a stalled handshake's slot comes back at net-io's deadline) | `accept` 61 ns |
| T-14 | ClientHello parser abuse | lengths checked against what remains; counts checked before iterating; 16 KiB, 4-record, and list budgets; linear time; after a failure rustls never reads further input (D-111) | `src/hello.rs` (every budget at n-1, n, n+1); `tests/properties.rs`; `tests/attacks.rs` (`test_t14_*`: malformed hellos, junk after a failure); fuzz targets `hello_parse`, `session_step_server`, `session_step_client` | parse 0.28 µs, parse plus JA4 0.82 µs for a 1.5 KiB hello |
| T-15 | Cross-protocol attacks (ALPACA) | strict ALPN; `AlpnPolicy::Required` on internal listeners; unknown SNI refused without a default | `tests/handshake.rs` (an HTTP ALPN against an SMTP-only listener); `tests/extended.rs` (unconfigured SNI on a back-channel listener) | 0 |
| T-16 | Domain fronting | the session reports the normalised SNI; the HTTP layer checks `Host` against the connection's `HostScope` (T-31) | `tests/extended.rs` (`test_t16_*`) | 0 |
| T-17 | Truncation | `close_notify` tracked; EOF without it is `Unclean`; `TlsStream` turns it into an `UnexpectedEof` error, never `Ok(0)` | `tests/handshake.rs` (`test_unclean_eof_is_reported_t17`); `tests/stream.rs` (`test_stream_truncation_without_close_notify_is_an_error`) | 0 |
| T-18 | Certificate expiry outage | proportional warning thresholds; expiry events; reload refuses expired certificates | `src/expiry.rs` (warn at `not_after - lifetime/3`); `tests/attacks.rs` (`test_t18_*`: an expired certificate in a reload is refused and the old one is still served) | report under 1 µs per entry |
| T-19 | Half-written files during reload | key match check; reload is all or nothing | `tests/extended.rs` (`test_reload_keeps_handshakes_in_progress_t19`: new chain with old key refused, old certificate served, handshakes in flight across both a good and a refused reload complete) | as a reload (1.74 ms for 100 certificates) |
| T-20 | Log or terminal injection through SNI or ALPN | SNI validated as LDH ASCII, anything else treated as absent; events carry SNI only in normalised form and ALPN only as configured names | `tests/attacks.rs` (`test_t20_*`: control bytes in SNI treated as absent; no event holds a raw control byte with every hello sampled) | part of the hello parse |
| T-21 | Timing side channels in tls-net's code | constant-time pin and secret comparisons; AEAD for tickets | `src/verify.rs` (`test_t21_*`, opt-in statistical timing test, Linux CI) | negligible |
| T-22 | Client certificate abuse (huge chains) | chain length and size budgets; handshake byte budget; rustls's 64 KiB handshake message limit; webpki path limits | `tests/attacks.rs` (`test_t22_*`: a 50-certificate chain and a 1 MiB certificate refused, against a control that passes); `tests/extended.rs`, `tests/handshake.rs` (budgets on both sides) | 0 |
| T-23 | Supply chain | small pinned tree; `cargo audit` and `cargo deny` in CI; banned crates; lockfile review | CI `Security (audit + deny)`; `tests/complete.rs` (`test_t23_*`: no banned crate in the tree; fails on CI if `cargo tree` cannot run) | build time |
| T-24 | Stolen hand-off export | sealed with XChaCha20-Poly1305 under a wrap key; older than one epoch refused; wiped on drop | `tests/complete.rs` (wrong wrap key, tampering at every byte, truncation); `src/tickets.rs` (an export two epochs old refused, one epoch old taken); fuzz target `import_sealed` (0.9.1, D-140) | microseconds per restart |
| T-25 | SNI probing of hosted names | `UnknownName::Refuse` gives the same alert for every unknown name; the lookup is two hash lookups | `tests/attacks.rs` (`test_t25_*`: 1,000 probes get identical bytes; refusal time near a hosted wildcard equals that elsewhere, opt-in timing test, Linux CI) | 0 |
| T-26 | Legacy attack classes (BEAST, POODLE, Lucky13, CRIME, FREAK, Logjam, Raccoon, ROBOT, Sweet32, Heartbleed, DROWN) | the features they need do not exist in rustls | testssl.sh vulnerability checks in the conformance workflow (weekly): every one "not vulnerable" | 0 |
| T-27 | Memory exhaustion through half-open handshakes | capacity cap; handshake byte budget; no rustls connection until a whole hello has arrived; net-io's buffer limits and deadline | `tests/complete.rs` (`test_t27_*`: 10,000 one-byte half-open connections); `tests/alloc.rs` (`test_t27_*`: `accept` plus a one-byte `step` allocates nothing) | the session's inline size, under 2 KiB, per half-open connection |
| T-28 | Process-wide provider confusion | tls-net never reads or installs the process default | `tests/provider.rs` (`test_t28_*`: after another crate installs a secp384r1-only default, tls-net still negotiates X25519MLKEM768) | 0 |
| T-29 | A post-handshake message split over records to crash the session | while rustls holds part of a message, `encrypt` and `close` wait for `step` instead of calling rustls on an empty buffer (D-126) | `tests/attacks.rs` (`test_t29_*`: a ticket in 64-byte records; `encrypt` and `close` return `WrongState`, then work once the rest arrives) | one header check per `step` |
| T-30 | Resumption past a client-authentication change, or past the client certificate's expiry | tickets and cached sessions are bound to the group's client-auth rules; a resumed handshake is refused without a required certificate or with an expired one (D-125) | `tests/attacks.rs` (`test_t30_*`: required auth published after an anonymous session, with tickets and with the cache; a removed pin); `src/server.rs` (`test_resumed_client_certificate_checked_for_expiry`) | 32 bytes more associated data per ticket; 1 to 2 µs per resumed handshake with a client certificate (estimate) |
| T-31 | A host policy skipped: a client sends no SNI, or another name the same certificate covers, gets the default group's rules (no client certificate), then sends a request for the protected host | `TlsServer::host_scope` and `HostScope::permits`, which the HTTP layer calls for every request's `Host` and answers `421` when it is `false`; `HostPolicy`'s docs make the check a requirement (D-143) | `tests/hosts.rs` (no SNI and a sibling SNI complete without a certificate, and their scopes refuse the admin host; the admin SNI needs a certificate; `Host` values parsed strictly; a reload that adds a policy); fuzz target `host_value` | one lock per connection [est. 60 ns], under 100 ns per request [est.] |

---

## Hardening record (0.7)

**Threat audit.** Every row above was checked against the threat table's planned tests in `dev/PLAN.md` and against the test code: the cited test exists, and its assertions attack what the row describes. The audit found 20 rows with a part of the planned test missing or weaker than described, for example T-1 had no downgrade-sentinel case, T-10 never checked that the client actually resumed, T-12's "random tickets" were two fixed inputs, and T-22 used a short chain under a small budget instead of a 50-certificate chain. Each gap now has a test; the planned wording was corrected where the test checks something more precise.

**Defects found and fixed in 0.7:**

- **D-110, found by tlsfuzzer.** The ClientHello parser accepted only record versions `0x0301` to `0x0303`, so a hello in a `0x0300` record (tlsfuzzer, older stacks) was refused with no alert before rustls saw it. RFC 5246 appendix E.1 requires a server to accept any `{03,XX}`; rustls does. Now accepted. No security effect: the record version never selects the protocol.
- **D-111, found by the session fuzz targets.** After a rustls error, tls-net called rustls again to collect the alert; with nothing queued, rustls read the next record, and a second malformed record made it queue a second fatal alert. That trips a `debug_assert!` in rustls, a panic in any debug build of an application from bytes a peer sends; release builds were not affected beyond an unsent second alert. Now rustls is called after a failure only while it holds queued records. Regression tests replay the fuzzers' inputs on both sides.

**Fuzz campaign.** Six targets at 0.7 (a seventh, `import_sealed`, was added at 0.9.1 and is in its 24-hour run), seeded with 18 real ClientHellos (Chromium, Windows Schannel, OpenSSL, curl, wget, Python, rustls) and 7 real server flights (`fuzz/seeds/`, D-108), each run for 24 hours at low priority on WSL2 with AddressSanitizer and debug assertions (`fuzz/run-24h.sh`).

| Target | Input | Hours | Executions | Coverage (edges) | Corpus | Findings |
|---|---|---|---|---|---|---|
| `hello_parse` | the ClientHello parser | 24.1 | 231,376,252 | 1,287 | 521 | none |
| `session_step_server` | ciphertext into a server session, in chunks | 24.0 | 64,755,461 | 7,322 | 3,338 | D-111 |
| `pem_intake` | PEM and DER key and certificate intake | 24.1 | 95,356,950 | 1,094 | 3,787 | none |
| `der_fields` | the DER field reader | 24.3 | 3,613,674,429 | 645 | 386 | none |
| `ticket_open` | arbitrary bytes as a session ticket; none may open | 24.1 | 996,060,126 | 549 | 43 | none |
| `session_step_client` | server flights into a client session, in chunks | 24.6 | 58,823,032 | 6,513 | 2,593 | none |
| `import_sealed` (0.9.1) | arbitrary bytes as a ticket-key hand-off; none may import, and sealed as an export's plaintext only the two export layouts import | first run 0.17 (24-hour run started 2026-11-10) | 4,571,209 | 767 | 59 | none |

The first runs started on 2026-11-06. The session targets found D-111 within hours; from `2b7c1c8`, which has the fix, `hello_parse`, both session targets, and `pem_intake` started again from their corpora and ran the 24 hours above. libFuzzer measures each input on the wall clock, which WSL steps, so the first campaign also wrote 61 timeout artifacts: every one replays cleanly in at most 17 ms of CPU. The same steps stopped `der_fields` after 5.4 hours and `ticket_open` after 3.3, and left one `session_step_client` job blocked inside libFuzzer's own alarm handler after 11.75 hours. Those three continued from their corpora with libFuzzer's timeout off and a progress watchdog that turns a real hang into a crash artifact (D-115). A signal from outside this repository stopped all three 1.8 hours later; they resumed from the same corpora on the same code and finished their 24 hours (D-117). Their rows add the segments: `der_fields` 5.4 + 1.8 + 17.1 hours, `ticket_open` 3.3 + 1.8 + 19.0, `session_step_client` 11.75 + 1.8 + 11.1. With the timeout off, the watchdog never fired and no target wrote an artifact.

**Soak.** `perf/soak.sh` (NFR-21): tls-net on net-io's reactor, 8 workers, 32 client threads making mixed full and resumed handshakes, a certificate reload every 60 seconds, a 10-minute ticket epoch.

6 hours on WSL2 at load averages around 400, net-io 0.6.1, rustls 0.23.46:

| Measure | Result |
|---|---|
| handshakes | 21,361,611 (10,142,969 full, 11,218,674 resumed), about 990 per second |
| handshakes failed by the server | 0 |
| certificate reloads / refused | 359 / 0 |
| ticket epochs | 36; 42,723,286 tickets issued, 0 rejected |
| server RSS | 25.9 MB after 10 minutes, 30.0 MB at the end, unchanged for the last 80 minutes |

RSS rose 4.1 MB over the first four and a half hours, more slowly each hour, then stopped: the allocator's arenas settling across 8 workers and the reload thread, not a leak. A leak scales with the work: 359 reloads or 21 million handshakes leave a slope that does not flatten. `tests/leak.rs` checks the same work against live heap bytes, which arenas do not move: after a warm-up, 200 rounds of a reload, a ticket rotation every tenth round, and a resumed and a full handshake leave the live heap exactly where it started (a leak of 8 bytes per handshake fails it at 3,200 bytes). The 24-hour soak belongs to the 1.0 gate (D-108).

**Conformance.** `.github/workflows/conformance.yml`, weekly and on demand (D-109):

- testssl.sh 3.2.4 against the example server: no finding of severity HIGH or CRITICAL beyond the test certificate's own (a private CA, a validity to 2099 so fixtures never expire, no CRL or OCSP URI). Every vulnerability check (Heartbleed, CCS injection, Ticketbleed, ROBOT, renegotiation, CRIME, BREACH, POODLE, SWEET32, FREAK, DROWN, LOGJAM, BEAST, Winshock) reports "not vulnerable".

- tlsfuzzer (commit `5eebc44`) against the example server with an ECDSA and with an RSA certificate, TLS 1.2 scripts with ECDHE, extended master secret, and an AEAD suite where they take those options. Ten script runs pass in full and fail the job if they regress: the TLS 1.3 conversation (both certificates), invalid cipher suites, no cipher suites, HelloRetryRequest, ChangeCipherSpec handling, SSL 2 hellos refused (both), the TLS 1.2 conversation, and zero-length records. Every other script runs as a report (`tests/conformance/tlsfuzzer.txt` gives the reason per script), and the server's own log of each run accounts for every failing case:
  - **tls-net's hello strictness (D-014):** a ClientHello tls-net cannot read whole, or one over a budget (16 KiB, 64 extensions, list budgets), is refused before rustls with no alert, where tlsfuzzer expects `decode_error` or `illegal_parameter`. RFC 8446 section 6.2 makes the alert a SHOULD; see the table below.
  - **rustls's choices:** another alert than the one tlsfuzzer expects (for example `decrypt_error` for `decode_error`, `bad_record_mac` for `record_overflow`), a nonsense `legacy_version` accepted beside `supported_versions`, no tickets to a client that offers no `psk_key_exchange_modes`, two tickets per handshake where a script expects one.
  - **Features rustls does not have:** TLS 1.1 and below, static RSA key exchange, CBC suites, FFDHE, x448, brainpool curves, `psk_ke`, SHA-1 signatures, renegotiation, heartbeat, compression.
  - **Scripts that cannot run here:** renegotiation and one ECDSA script send no extended master secret, which tls-net requires for TLS 1.2 (T-7); one needs a server that asks for client certificates.

  One tls-net defect came out of these runs and is fixed (D-110).

**Miri.** The library tests that need no crypto provider (parsers, PEM intake, SNI, fingerprints, tickets, snapshot, expiry, errors: 66 tests) run under Miri in CI with no undefined behaviour reported (D-112). The providers are C and assembly, which Miri cannot execute.

**loom.** The capacity gate, the configuration snapshot, and the ticket ring are model-checked with loom in CI (NFR-20), including the 0.6 change to the capacity slot (D-102).

---

## Adversarial review (0.9)

Three reviewers read the source with no access to the author's notes, each over one area: the code that takes bytes from the network (sessions, the net-io seam, the hello parser); tickets, verifiers, and certificate and key intake; and server and client configuration (reload, the handshake gate, SNI, policies, observers). Each finding was reproduced with a test that fails on 0.8.0 before it was fixed, except where noted.

| Finding | Severity | Fix |
|---|---|---|
| A peer could make `encrypt` or `close` panic, in release builds too, by sending one valid record holding part of a post-handshake message (a ticket or key update): rustls kept the part in the caller's input and was then called on an empty buffer. net-io calls `close` on every graceful close | high | D-126, T-29 |
| Resumption skipped client authentication: rustls does not ask for a certificate on resumption, so after a publish that required client certificates, dropped a pin, or added a CRL, old sessions still resumed; and an identity carried in tickets never expired | high | D-125, T-30 |
| `refuse_malformed(false)`, which a peer reaches by going over a budget, also skipped the hello hook, host groups, and a required ALPN; and a second hello after a HelloRetryRequest could drop ALPN (no available client does this and still completes, so that path is covered by the completion check without a test of its own) | medium | D-127 |
| A ticket-key export from another period, or from a clock running ahead, froze key rotation | medium | D-130 |
| `HelloLimits` fields assigned directly could index past the parser's fixed arrays | low | D-128 |
| `close` into a short buffer lost close_notify; records queued by `step` could be lost by `encrypt`; a hello over several records asked net-io for one record's room | low | D-129 |
| `Policy::internal()` let anonymous clients in; CRLs without anchors were never checked | low | D-131 |
| `publish` ignored a new `max_in_progress`; the SNI counter reset on reload; setting only the gate cut the client-auth budget | low | D-132 |
| Pinned client identities never resumed, and failed with platform anchors | low | D-133 |
| A verified client certificate with one name tls-net could not read got no identity | low | D-134 |
| A key read from a FIFO left unwiped copies in freed memory; the PEM decoder's scratch was described as wiped | low | D-135 |
| `reload_from_*` made a `certificate_for` entry the default | low | D-136 |
| OCSP staples went to every certificate for a name, not the one they are for | low | D-137 |

What held, in the reviewers' words condensed: offsets and budgets in the session and the parser; data never handed out before completion or after a failure; the ticket construction (fresh nonces, bound epochs, only two epochs open, nothing printed); constant-time pin comparison over the full SPKI; the verified end-entity as the only source of a peer identity; reload built completely before the swap; the capacity gate released on every path; SNI normalisation and one-label wildcards; presets that cannot weaken; STARTTLS leftovers refused; nothing secret or unescaped in events and errors.

---

## Independent review (0.9.1)

One reviewer read 0.9.1 (`5e31545`) end to end, with reproductions for each finding, and found no critical issue. Every finding is fixed in 0.10.0, each with a regression test.

| Finding | Severity | Fix |
|---|---|---|
| A host policy's client authentication was skipped by a client that sent no SNI, or another name the same certificate covers: the handshake ran under the default group's rules, and nothing let the HTTP layer see that the session had not met the protected host's rules | high | D-143, T-31 |
| A certificate living under 2 days was `Critical` from issue (and one under 7 days `Warn`), the opposite of OPERATIONS.md | medium | D-144 |
| A client's CRLs were accepted without anchors and never applied on a pinned connection without a chain check | low | D-145 |
| An established session kept the configuration it was accepted under, private keys included, alive after a reload | low | D-146 |
| `LoadLimits` and `HandshakeLimits` fields assigned directly bypassed their ranges (a 256 MiB buffer for a 241-byte key; no handshake budget) | low | D-147 |
| Load settings given after `certificate` were skipped at startup and applied at reload, so a renewal of the same files could be refused | low | D-148 |
| The peer identity made lazy in D-104 was built at every completion by the completion counters | low | D-149 |
| Notes: `Policy::versions` on a preset kept its suites (D-150); a ticket opened for up to two periods against an advertised one (D-151); an ALPN name over 32 bytes reached net-io as no ALPN (D-152); `peer` can be `None` under `ClientAuth::required` when the verified certificate cannot be read (documented, and `peer_verified` added, D-143); four documentation errors | note | as listed |

Recorded, not changed: `TlsServer::accept`, the only accept net-io can call, takes one uncontended lock per connection (about 60 ns against a handshake of 300 to 450 µs); a lock-free cell without `unsafe` is an open item in `dev/ROADMAP.md`.

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
