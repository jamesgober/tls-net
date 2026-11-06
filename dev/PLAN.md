# tls-net - Project Plan

> The design, requirements, threat model, and decision record for `tls-net`. A living document: every design decision, idea, or open question about tls-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on. The public API itself is in [`../docs/API.md`](../docs/API.md).
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md) &rarr; [`../docs/API.md`](../docs/API.md).
>
> **Status:** `0.5.0`, feature complete. Facts about rustls were checked against the rustls 0.23.46 source. Numbers that were not measured are marked [est.]; numbers that are goals are marked [target].

---

## Contents

1. [Purpose](#1-purpose)
2. [Why we do not write TLS](#2-why-we-do-not-write-tls)
3. [Position in the stack](#3-position-in-the-stack)
4. [Scope](#4-scope)
5. [Requirements](#5-requirements)
6. [Design](#6-design)
7. [Features and dependencies](#7-features-and-dependencies)
8. [Threats](#8-threats)
9. [Performance targets](#9-performance-targets)
10. [Testing plan](#10-testing-plan)
11. [Defence ideas](#11-defence-ideas)
12. [Open questions](#12-open-questions)
13. [Decision log](#13-decision-log)

---

## 1. Purpose

tls-net gives the stack TLS without the stack writing TLS. It is an adapter between rustls and net-io:

- **rustls** does the protocol and the cryptography: handshake, record protection, certificate path validation (through rustls-webpki).
- **tls-net** drives rustls's sans-IO "unbuffered" connection API in the shape net-io's drivers need, loads and validates certificates and keys, keeps private keys and ticket keys in key-vault, selects certificates by SNI, reloads them without dropping a connection, enforces a TLS policy (versions, suites, groups, ALPN, client certificates, budgets), parses the raw ClientHello once for fingerprinting (JA4, JA3) and hands the result to the connection gate, and maps every failure to an error category.

| Role | Who | What tls-net provides |
|---|---|---|
| public server | serve-net direct mode | HTTPS on :443, SNI, ALPN `h2` and `http/1.1`, tickets, hot reload, fingerprints |
| internal server | the service back-channel, admin listeners | mutual TLS, pinned CA or pinned peer key, TLS 1.3 only, post-quantum key exchange required |
| outbound client | fetch-net, smtp-net (465 and STARTTLS on 587), proxy-net, dns-net later | server verification that cannot be turned off, SNI, ALPN, resumption, client certificates |
| internal client | back-channel dialer, cluster transport | client certificate from key-vault, pinned server identity |

## 2. Why we do not write TLS

TLS safety does not come from implementing the protocol; it comes from years of audits, constant-time cryptography, defences against timing and padding side channels, and a long history of attacks already fixed. A home-made TLS would be the weakest link in a stack built around security. rustls is memory-safe Rust, audited, and widely deployed. It is one of the few third-party crates this stack accepts, and tls-net keeps it behind its own types so net-io and everything above stay free of it.

tls-net is also:

- not a socket library (it never reads or writes a socket; net-io does);
- not an async adapter (no tokio, no futures, no `AsyncRead`);
- not a certificate authority or ACME client (issuing and renewal belong to a separate crate, `cert-net`);
- not a ban engine (it produces fingerprints and facts; bouncer-io decides, sentinel-sec scores);
- not an X.509 library (its small DER reader extracts fields for reports and identity mapping; trust decisions are rustls-webpki's).

## 3. Position in the stack

```
 inbound
 net-io accept -> bouncer-io door (address) -> PROXY header (trusted) -> door (real peer)
   -> tls-net: ClientHello parse -> fingerprint hook (bouncer-io) -> rustls handshake
   -> protocol engine (http-net, h2-net, ws-net, smtp-net, back-channel codec)
   -> inspection, authentication, authorization -> handlers
 outbound
   handlers -> egress check (net-io) -> tls-net encrypt -> net-io write
```

| Crate | Uses | Since |
|---|---|---|
| serve-net | server sessions through the net-io seam, reload, fingerprint hook | 0.3 |
| h2-net | ALPN `h2` result | 0.3 |
| smtp-net | client sessions, `start_after_plaintext` for STARTTLS | 0.3 |
| fetch-net, proxy-net | client sessions, ALPN, resumption, per-upstream clients | 0.3 |
| the service back-channel | mutual TLS, `PeerIdentity` | 0.4 |
| cert-net | `ReloadHandle` to publish renewed certificates | 0.4 |
| bouncer-io, sentinel-sec | `Fingerprint`, `ClientHelloView`, events | 0.4 |

| tls-net uses | Kind | Why |
|---|---|---|
| `rustls` | third party, recorded exception | the TLS implementation |
| `rustls-pki-types`, `rustls-webpki` | third party, already rustls dependencies | DER wrappers, PEM parser, path validation, CRLs |
| `aws-lc-rs` (default) or `ring` (feature) | third party, rustls crypto provider | cryptography |
| `webpki-roots` | third party (data) | Mozilla root program bundle for clients |
| `net-io` | first party, feature `net-io` | the TLS seam traits |
| `crypt-io` | first party | XChaCha20-Poly1305 for tickets, HKDF-SHA256 for the ticket ratchet, SHA-256 for JA4 and SPKI pins |
| `key-vault` | first party, feature `key-vault` | custody of private keys and ticket keys |

## 4. Scope

### 4.1 In scope

| Piece | Detail | Grades |
|---|---|---|
| sans-IO sessions | server and client sessions over rustls's unbuffered API; caller-owned input and output buffers | P0 |
| net-io adapter | net-io's `TlsAcceptor` and `TlsSession` (feature `net-io`) | P0 |
| policy | versions, cipher suites, key exchange groups including X25519MLKEM768, extended master secret, server suite order, fragment size, presets | P0-P2 |
| certificates and keys | PEM and DER loading with size budgets; chain, key, validity, name, algorithm, and EKU checks | P0 |
| key custody | resident keys or per-signature keys from key-vault | P1-P2 |
| SNI | exact and single-label wildcard names, several certificates, explicit default or refusal, per-host policy | P0-P2 |
| ALPN | server preference order, strict refusal on mismatch, ALPN required on internal listeners | P0-P1 |
| client certificates | none, optional, required; trust anchors per listener; CRLs; SPKI pins; `PeerIdentity` | P0-P2 |
| hot reload | build, validate, swap; zero failed handshakes; expiry reporting | P0-P1 |
| resumption | stateless tickets under a key ring (ephemeral, ratchet with hand-off, derived); stateful cache for TLS 1.2 session IDs | P1-P2 |
| ClientHello capture | bounded zero-copy parser, `ClientHelloView`, JA4, JA4_r, JA4_o, JA3 string, optional JA3 MD5 | P1-P3 |
| client trust | Mozilla roots, custom anchors, optional platform verifier, pins, CRLs | P0-P2 |
| STARTTLS helper | client start after a plaintext phase with injection refusal | P0 |
| exporters | RFC 5705 keying material export, RFC 9266 `tls-exporter` channel binding | P2 |
| OCSP stapling | static staples supplied by the operator or cert-net | P2 |
| errors and events | `TlsError` with codes and categories, `TlsObserver` events | P0-P1 |
| FIPS | `fips` feature over aws-lc-rs | P2 |

### 4.2 Out of scope, and where it lives

| Not in tls-net | Lives in | Reason |
|---|---|---|
| TLS protocol, record layer, cryptography | rustls and its provider | we do not write TLS |
| sockets, timeouts, the handshake deadline | net-io | sans-IO; net-io owns time and descriptors |
| ban decisions, per-prefix handshake rates | bouncer-io | policy is the gate's |
| risk scoring from fingerprints | sentinel-sec | detection is sentinel's |
| ACME, renewal, development certificates | cert-net | issuing needs X.509 encoding and signing |
| fetching OCSP responses or CRLs | cert-net with fetch-net | tls-net does no I/O |
| DANE, MTA-STS | smtp-net with dns-net (later) | needs DNSSEC and HTTP |
| HTTP semantics of early data (`425 Too Early`) | http-net, web-net | tls-net only reports early data |
| Host header versus SNI (domain fronting) | web-net | tls-net exposes the normalised SNI |
| kernel TLS offload | P3 after 1.0; socket calls in net-io | needs OS calls and a different record path |
| QUIC handshake integration | quic-net (later) | not scheduled |
| certificate transparency enforcement | not done (D-018) | rustls removed SCT checks; browsers enforce CT |
| renegotiation, SSL 3.0, TLS 1.0, 1.1, CBC, RC4, static RSA, finite-field DHE | nowhere | rustls does not implement them; RFC 8996 deprecated TLS 1.0 and 1.1 |
| server-side encrypted ClientHello | not in rustls 0.23 | revisit when rustls ships it |
| certificate compression (RFC 8879) | P3 | needs third-party compression crates |

## 5. Requirements

Each requirement is testable; the test that proves it is named in the test file that covers it, and the 1.0 audit maps every one.

### 5.1 Functional

**Sessions and the seam**

- **FR-1** A server session takes ciphertext in a caller-owned buffer and returns how many bytes to discard, decrypted plaintext as a slice of that buffer, and ciphertext written into a caller-owned output buffer. It never reads or writes a socket and never keeps a reference to either buffer between calls.
- **FR-2** A client session does the same, started for a given server identity.
- **FR-3** `step` refuses to call rustls when the output buffer has less free space than `OUTGOING_MIN` (18,437 bytes, one maximum TLS record), because rustls loses a pending handshake chunk that cannot be encoded (D-035).
- **FR-4** After the handshake, `encrypt` turns plaintext into TLS records in the output buffer (all records or none) and `close` writes a `close_notify` alert.
- **FR-5** End of stream without a received `close_notify` is reported as an unclean close, never as a clean one.
- **FR-6** With feature `net-io`, the server implements net-io's `TlsAcceptor` and both sessions implement `TlsSession`.

**Policy**

- **FR-7** The policy fixes the allowed versions (TLS 1.2 and TLS 1.3 only; nothing lower is representable), cipher suites, key exchange groups, the extended master secret requirement for TLS 1.2, and whether the server's suite order wins.
- **FR-8** Building a configuration from an inconsistent policy (no suite for an allowed version, no group, a group the provider lacks, post-quantum required with `ring`) fails with a named error; it never falls back.
- **FR-9** Presets: `compatible` (TLS 1.2 and 1.3, server default), `modern` (TLS 1.3 only), `internal` (TLS 1.3 only, X25519MLKEM768 only), `fips` (feature `fips`).
- **FR-10** No handshake completes below the configured minimum version or outside the configured suite and group lists.

**Certificates and keys**

- **FR-11** Chains and keys load from PEM bytes, DER bytes, or files, with a size budget checked before the bytes are read into memory.
- **FR-12** Accepted key forms: PKCS#8, PKCS#1 RSA, SEC1 EC. Encrypted PKCS#8 is refused with an error that says so. A key file with more than one key is refused.
- **FR-13** Load-time checks: the chain is non-empty; the key matches the end-entity certificate; the end-entity certificate is inside its validity window (skew default 5 minutes); configured names are covered by its SANs; RSA at least 2048 bits, ECDSA P-256 or P-384, Ed25519; the certificate is not SHA-1 signed; the EKU, if present, permits `serverAuth` (server) or `clientAuth` (client certificate); the chain is in issuing order.
- **FR-14** Private key bytes held by tls-net are wiped after use; key material never appears in `Debug`, `Display`, errors, events, or logs.
- **FR-15** Keys may come from key-vault (feature `key-vault`) in two custody modes: resident (parsed once into the provider) or per-signature (fetched and parsed inside the vault's scoped callback for every signature).

**SNI and ALPN**

- **FR-16** A server holds any number of certificates, each for one or more exact names or single-label wildcards (`*.example.com` matches `a.example.com`, not `a.b.example.com` and not `example.com`).
- **FR-17** SNI is normalised (ASCII lowercase, one trailing dot removed) before lookup; SNI that is not a valid DNS name in A-label form, or that is an IP literal, is treated as absent.
- **FR-18** A ClientHello without SNI, or with an unknown name, gets the configured default certificate, or is refused with an `unrecognized_name` alert when there is no default.
- **FR-19** One ECDSA and one RSA certificate for the same name are allowed; the ECDSA one is chosen when the client's signature schemes allow it.
- **FR-20** ALPN: the server selects the first protocol in its own list that the client offered; an offer with no overlap is refused with `no_application_protocol`; a listener with `AlpnPolicy::Required` also refuses a ClientHello without ALPN.
- **FR-21** Per-host policy: a host name may carry its own ALPN list, client-certificate requirement, and policy, chosen from the parsed SNI before the rustls connection is created.

**Client certificates and identity**

- **FR-22** Server-side client authentication: none, optional, required, pinned; each with its own trust anchors and optional CRLs.
- **FR-23** SPKI pins (SHA-256 of the SubjectPublicKeyInfo) are checked in addition to, never instead of, handshake signature verification.
- **FR-24** After the handshake a `PeerIdentity` is available: SPKI SHA-256, end-entity DER, SANs, serial, validity window.

**Client side**

- **FR-25** Server certificate verification is always on. There is no API in tls-net that disables it, in any feature.
- **FR-26** Trust anchors: Mozilla roots (default), custom anchors from PEM or DER, the platform verifier (feature `platform-verifier`), and pinned server keys.
- **FR-27** The server name used for verification is the one the caller passes, never one taken from connection data.
- **FR-28** `start_after_plaintext` begins a client handshake after a plaintext phase and refuses when any plaintext byte arrived after the upgrade reply (STARTTLS injection).
- **FR-29** Client resumption is per `TlsClient`; separate clients never share tickets.

**Hot reload**

- **FR-30** `ReloadHandle::publish` replaces certificates, keys, policy, and per-host settings as one unit after full validation; a failure leaves the old state in force and returns the reason.
- **FR-31** Handshakes in progress finish with the configuration they started with; new sessions use the new one; no handshake fails because of a reload.
- **FR-32** Ticket keys and the stateful session cache survive a reload.
- **FR-33** `expiry_report` lists every loaded certificate with days remaining and a state (`ok`, `warn`, `critical`, `expired`).

**Resumption**

- **FR-34** TLS 1.3 and TLS 1.2 stateless tickets, sealed with XChaCha20-Poly1305 under a key from a key ring, with rotation and the previous key still accepted.
- **FR-35** Key ring modes: ephemeral (random per process), ratchet (forward-only HKDF chain with sealed export and import for a socket hand-off), derived (from a root shared by a cluster).
- **FR-36** Tickets per full handshake configurable (default 2); a ticket that fails to open leads to a full handshake, never an error.
- **FR-37** 0-RTT is refused unless the server was built with `dangerous_enable_early_data`, which requires stateful single-use resumption (P3, after 1.0).

**ClientHello capture**

- **FR-38** The server parses the ClientHello from the input buffer before rustls sees it, without copying, within budgets (total bytes, records, list counts), across record boundaries.
- **FR-39** From the parse: `ClientHelloView` (fields and extension order), `Ja4` (36 characters), JA4_r and JA4_o strings, the JA3 string, and with feature `ja3-md5` the JA3 MD5 digest.
- **FR-40** A hook receives the view and fingerprint before the handshake continues and may refuse the connection.
- **FR-41** A ClientHello the parser rejects as malformed or over budget is refused (fail closed) by default.

**Other**

- **FR-42** `export_keying_material(out, label, context)` and `channel_binding()` after the handshake.
- **FR-43** OCSP staples may be attached per certificate and replaced by reload.
- **FR-44** Every error has a code in namespace `TLS`, a category, an action, and a public message that reveals nothing about keys or configuration.
- **FR-45** Events for handshake completed, handshake failed, hello captured, hello refused, reload applied, reload refused, certificate expiring, ticket key rotated, handshake capacity reached.
- **FR-46** A per-server cap on handshakes in progress; above it, new sessions are refused before any parse.
- **FR-47** Handshake byte budgets per session (inbound bytes before the handshake completes; peer chain length and size).
- **FR-48** `is_fips()` on server and client reports whether the configuration runs in FIPS mode.
- **FR-49** On Unix, loading a private key from a file refuses a file readable by group or others (`mode & 0o077 != 0`) unless the builder explicitly allows it; the refusal names the file and the mode. On Windows the check is an ACL inspection graded P3; until it ships, `docs/PLATFORM-NOTES.md` says the check does not run there.
- **FR-50** tls-net never watches files and never runs a timer; reloads happen only when the caller publishes.

### 5.2 Non-functional

- **NFR-1** No allocation in tls-net code on the established-connection record path (`step` with application data, `encrypt`), proved with a counting allocator. rustls 0.23 allocates one `Vec` per record in each direction on that path (D-035); that is measured and reported, not claimed away.
- **NFR-2** Plaintext is delivered as a slice of the caller's input buffer. With rustls 0.23 this costs one copy per record inside tls-net (D-035); tls-net copies nothing else.
- **NFR-3** ClientHello parse plus JA4 under 1.5 µs for a 2 KiB hello on the reference machine [target].
- **NFR-4** SNI lookup under 100 ns with 10,000 names, no allocation [target].
- **NFR-5** tls-net's own overhead per record (excluding rustls) under 100 ns, plus the plaintext copy of D-035 [target]; handshake rate within 3% of raw rustls unbuffered on the same machine [target].
- **NFR-6** End-to-end (net-io plus tls-net) handshakes per second and bulk throughput at least 20% above tokio plus tokio-rustls at the same rustls version, provider, suite, group, and key type, on Linux [target].
- **NFR-7** Memory per idle established connection added by tls-net: under 512 bytes beyond the rustls connection object [target].
- **NFR-8** Reload of 100 certificates builds in under 10 ms and swaps in under 1 µs [target]; zero failed handshakes during reload under load.
- **NFR-9** Zero CPU when idle: no timers, no file watching, no background threads. Ticket key rotation is checked lazily on ticket operations.
- **NFR-10** All memory bounded by configuration: per-session budgets, session cache capacity, ticket ring size (at most three keys), certificate count.
- **NFR-11** No panics in library code. rustls calls that panic by contract (for example `ServerConfig::builder_with_protocol_versions`) are never used; the fallible equivalents are.
- **NFR-12** `#![forbid(unsafe_code)]` in tls-net.
- **NFR-13** `Send` for sessions; `Send + Sync` for `TlsServer`, `TlsClient`, `ReloadHandle`; checked at compile time.
- **NFR-14** No rustls type in tls-net's public API (except behind `rustls-escape-hatch`, outside semver), so a rustls upgrade is not a tls-net major change.
- **NFR-15** Deterministic: the same configuration and the same ClientHello bytes give the same fingerprint, certificate choice, and ALPN on every platform.
- **NFR-16** Linux, macOS, Windows in CI on stable and 1.85.
- **NFR-17** Every parser (ClientHello, DER field reader, PEM size gate) has a fuzz target and a property test "never panics, never exceeds budget".
- **NFR-18** Every threat in section 8 has an attack test that must fail to get through.
- **NFR-19** Constant-time comparison for SPKI pins and any secret-derived value; ticket opening is AEAD (tag checked before plaintext is released).
- **NFR-20** Handshake capacity, reload snapshot, and key ring primitives are tested with `loom`.
- **NFR-21** Soak: mixed full and resumed handshakes with a reload every 60 seconds and a ticket rotation every 10 minutes; no memory growth, no handshake failed by tls-net (24 hours before 1.0).
- **NFR-22** cargo-deny and cargo-audit clean; every third-party crate in the tree listed in `docs/SECURITY.md` with its reason.
- **NFR-23** Public API documented with runnable examples; `docs/API.md` complete.
- **NFR-24** A rustls security release can be adopted by a tls-net patch release within 48 hours of publication [target].

## 6. Design

### 6.1 Module map

```
src/
  lib.rs          crate docs, Tier 1 functions, re-exports, VERSION
  error.rs        TlsError (#[non_exhaustive]), ErrorCategory, Action, codes TLS-nnnn
  provider.rs     provider selection by feature; never a process default (D-043)
  policy.rs       Policy, Version, CipherSuite, Group, SignatureScheme, presets, validation
  pem.rs          size-gated PEM and DER intake over rustls-pki-types; key form checks
  der.rs          bounded DER reader: X.509 fields for reports and identity (never for trust)
  certs.rs        CertificateEntry: chain, key, names, validity, OCSP staple; load-time checks
  custody.rs      KeySource, KeyCustody, VaultSigningKey (feature key-vault)
  sni.rs          SniTable: exact and wildcard names, default entry, host groups
  snapshot.rs     Snapshot<T> and Reader<T>: versioned publish and read, loom-tested
  server.rs       TlsServer, ServerBuilder, ReloadHandle, HostPolicy, capacity gate
  client.rs       TlsClient, ClientBuilder, TrustAnchors, ServerIdentity, STARTTLS helper
  verify.rs       pinned verifiers (SPKI pins plus real signature checks), CRL wiring
  session.rs      ServerSession, ClientSession: the step loop over rustls unbuffered
  hello/          parse.rs (ClientHelloView), ja4.rs, ja3.rs (MD5 behind ja3-md5)
  tickets.rs      TicketKeyRing (ephemeral, ratchet, derived), implements rustls ProducesTickets
  identity.rs     PeerIdentity, HandshakeInfo
  observe.rs      TlsObserver, TlsEvent
  seam.rs         net-io seam implementation (feature net-io)
  escape.rs       rustls access (feature rustls-escape-hatch, outside semver)
```

Modules are private; public items are re-exported at the crate root.

### 6.2 Server data flow

```
 net-io read completes -> ServerSession::step(input, output)
   state Hello:
     HelloParser::parse(input)               budgets checked first; zero copy
       Incomplete -> NeedInput (nothing consumed)
       Invalid    -> Err(HelloMalformed)     fail closed (D-013)
       Complete(view, len)
         -> Fingerprint (only the kinds enabled)
         -> hook(view, fingerprint) -> Refuse -> Err(Refused), no alert (D-014)
         -> normalised SNI -> host group -> Arc<rustls::ServerConfig> for that group
            unknown and no default -> 7-byte unrecognized_name alert, Err(UnknownServerName) (D-031)
         -> rustls UnbufferedServerConnection::new(config) -> state Handshake
   state Handshake / Established:
     loop process_tls_records(input[consumed..]) and map each rustls state (table 6.3)
```

### 6.3 The step loop over rustls's unbuffered API

Verified against `rustls-0.23.46/src/conn/unbuffered.rs` and `src/common_state.rs`:

| rustls `ConnectionState` | What tls-net does | `Event` returned |
|---|---|---|
| `EncodeTlsData` | `encode(&mut output[written..])`. `step` checked `output.len() - written >= OUTGOING_MIN` before calling rustls at all (FR-3), so `encode` cannot fail for size and the chunk rustls holds cannot be lost | none yet; loop |
| `TransmitTlsData` | `done()` at once: the bytes belong to the caller's output buffer, which the driver sends in full | `Transmit` |
| `BlockedHandshake` | nothing until more ciphertext arrives; records how many bytes rustls holds unconsumed (for `input_capacity_required`) | `NeedInput` |
| `WriteTraffic` | first time: fill `HandshakeInfo`, release the capacity slot | `HandshakeComplete` once, then `NeedInput` when idle |
| `ReadTraffic` | `next_record()` returns an owned chunk (rustls 0.23 copies every received record into a `Vec`, D-035). While that chunk lives, rustls holds the whole input borrow, so tls-net copies it into the spare output first and then to the end of the bytes this call discards (D-063); the slice lies in the caller's input | `Data(payload)` |
| `ReadEarlyData` | only reachable when early data is enabled (P3) | `EarlyData(payload)` |
| `PeerClosed` | records the clean close | `PeerClosed` |
| `Closed` | terminal | `Closed` |
| `Err(e)` | maps the rustls error (6.15); rustls queues the alert, and the next `process_tls_records` call hands it out as `EncodeTlsData`, so tls-net encodes it into `output` | `Transmit` with the alert, then `Err(TlsError)` on the next call (D-051) |

**Discard rule.** rustls requires `discard` bytes to be removed from the front of the input before `process_tls_records` runs again. Inside one `step`, tls-net passes `&mut input[consumed..]` to each call and adds each discard to `consumed`; the caller removes `consumed` bytes after handling the event. Because a `Data` slice points into the same buffer, the driver hands the payload to the engine first and compacts afterwards; the borrow checker enforces it.

**Buffer minimums.** `OUTGOING_MIN = INCOMING_MIN = 18,437` bytes: rustls's maximum wire record (16,384 + 2,048 + 5-byte header). During the handshake rustls coalesces a handshake message that spans records in place inside the caller's buffer (V-1, D-029); messages up to 65,535 bytes are allowed by rustls, and the session's handshake byte budget bounds the total. `input_capacity_required()` reports `max(INCOMING_MIN, held + 1)` during the handshake, where `held` is what rustls kept unconsumed at the last `NeedInput`, so net-io grows its read buffer only when a peer really sends a large message.

**Outbound.** `encrypt(plaintext, output)` makes one rustls `WriteTraffic::encrypt` call: rustls fragments, checks the whole size first, and writes all records or none (`InsufficientSize` maps to `TlsError::OutputFull` with the required size). rustls refreshes TLS 1.3 traffic keys before the AEAD limit by itself; under TLS 1.2 the limit surfaces as `EncryptExhausted`, mapped to `KeyUsageExhausted` (close and reconnect). `close(output)` calls `queue_close_notify`.

**Session state machine:**

```
 Hello --parse ok, hook allows--> Handshake --WriteTraffic--> Established --PeerClosed--> HalfClosed
   |                                  |                           |                          |
   +- refused / malformed -+          +- error -+                 +- close() -> Closing -----+-> Closed
                           v                    v
                         Failed (terminal; carries the error code; later calls return Err(SessionFailed))
```

A client session starts in `Handshake` (it writes the ClientHello first). Calls in the wrong state return `WrongState` and do not touch rustls.

### 6.4 The net-io seam

net-io owns the traits (published since net-io 0.4.0, unchanged through 0.6): `TlsAcceptor { type Session; fn session(&self, &ConnectionInfo) }` and `TlsSession { step, encrypt, close, on_transport_closed, info, input_capacity_required }`, with `TlsProgress`, `TlsEvent`, `TlsCloseKind`, `TlsInfo`, and `net_io::TlsError { kind: TlsFailure, code: u16, alert: Option<u8> }`. tls-net's `seam.rs` maps its own types onto them: no extra state, no allocation (net-io boxes the session once per connection). `tls_net::TlsError::code()` is the `u16` that crosses the seam; a hook refusal maps to `TlsFailure::HelloRefused`, capacity to `Capacity`, `OutputFull` and `WrongState` to their own kinds, protocol violations by the peer to `Protocol`, every other handshake failure to `Handshake`.

Order (fixed by net-io): accept, admission, PROXY header, readmission; `TlsAcceptor::session` (capacity gate; refuse before reading); `step` under net-io's handshake deadline until `HandshakeComplete`; `info()` fills `ConnectionInfo::tls`; on the way out, net-io's egress check runs on the plaintext before `encrypt`.

net-io's read loop checks that a `Data` slice lies inside the input it passed and copies it once into the reader's buffer. net-io's write path calls `encrypt` with at most 16 KiB of plaintext and at least 2 KiB of spare room beyond it; with the default fragment size one TLS 1.3 record adds 22 bytes. A `max_fragment_size` below 512 bytes can need more than 2 KiB of overhead for 16 KiB of plaintext; such policies are refused for sessions driven through the net-io adapter (D-049).

### 6.5 Certificates and keys: loading and validation

Order of checks for every certificate entry (stop at the first failure; each has its own error):

1. **Size gate.** File length from metadata before reading; chain at most `max_chain_file_bytes` (default 1 MiB), key at most `max_key_file_bytes` (default 64 KiB); the read is bounded by the same limit in case the file grows. For byte input, the slice length.
2. **Key file permissions** (Unix, FR-49).
3. **PEM decode** through `rustls_pki_types::pem::PemObject`. The key buffer is held in a wiping buffer and wiped after decode. tls-net scans PEM labels first so `ENCRYPTED PRIVATE KEY` is reported as `EncryptedPrivateKey`, not "no key". Zero keys is `NoPrivateKey`, more than one is `MultiplePrivateKeys`. Zero certificates is `NoCertificate`; more than `max_chain_len` (default 10) is `ChainTooLong`.
4. **Key load** through the provider's `KeyProvider::load_private_key`; unsupported algorithms are `UnsupportedKeyType`.
5. **Key match** (`CertifiedKey::keys_match`): mismatch is `KeyMismatch`. This also catches a half-written pair during reload.
6. **Fields** from the end-entity certificate by the DER reader: validity, SANs, key algorithm and size, EKU, signature algorithm.
7. **Validity**: `not_before <= now + skew` and `now < not_after`, else `CertificateNotYetValid` or `CertificateExpired`.
8. **Name coverage**: every configured name matches a SAN dNSName (RFC 9525: one leftmost `*` label only); CN is never used. Else `NameNotCovered`.
9. **Algorithm policy**: RSA at least 2048 bits; ECDSA P-256 or P-384; Ed25519; not SHA-1 signed. Else `WeakKey` or `WeakSignatureAlgorithm`.
10. **EKU**: if present, must include `serverAuth` (or `clientAuth` for client certificates). Absent EKU is accepted (RFC 5280).
11. **Chain order** (default on): each certificate's issuer DN equals the next one's subject DN; else `ChainOrder`.
12. **OCSP staple** (if given): at most 16 KiB and a DER SEQUENCE; a stale staple is dropped with a warning event, never served.

The DER reader is used only for these facts and for `PeerIdentity`; whether a peer's chain is trusted is decided by rustls-webpki.

### 6.6 Key custody (key-vault)

key-vault keeps keys in page-locked, dump-excluded, zero-on-drop memory and hands bytes out only inside a scoped callback (measured by key-vault at 34 to 157 ns per call for 16 to 256 byte keys without page protection). A vault normalises keys with BLAKE3 by default, which turns a private key into a 32-byte digest; a vault for TLS keys must be built with normalisation off. tls-net does not trust the configuration: if the bytes from the callback do not parse as a key, the error is `VaultKeyUnusable` with the help text "build the vault with normalize_with_blake3(false)".

| Custody | How | Protects | Cost per full handshake |
|---|---|---|---|
| `Resident` (default) | at build or reload the DER exists only inside the vault callback; the provider parses it once | the DER form in memory, dumps, swap; the parsed key stays in provider memory for the life of the entry | none beyond rustls |
| `PerSignature` | a `SigningKey` whose signer fetches, parses, signs, and drops the key each time | no parsed key between handshakes | one key parse per signature: ECDSA P-256 [est. 10 to 30 µs], RSA-2048 [est. 50 to 150 µs]; measured at 0.6 |

When the provider frees a parsed key, AWS-LC wipes the allocation (`OPENSSL_free` calls `OPENSSL_cleanse` on every allocation of its default allocator, checked in aws-lc-sys 0.47.0 `crypto/mem.c`). ring does not wipe key memory on drop (no `Drop` impl clears key types in ring 0.17.14). Recorded in `docs/SECURITY.md` (D-030).

### 6.7 SNI table, host groups, snapshot, reload

**SniTable.** A hash map of exact names and one of wildcard suffixes (`*.example.com` stored as `example.com`), lowercase ASCII keys, built once per snapshot. Lookup: exact; then strip the first label and look up the wildcard map; then the default entry or refusal. At most two hash lookups, no allocation.

**Host groups.** Each distinct `HostPolicy` (plus the default) forms a group with its own `Arc<rustls::ServerConfig>` per snapshot. The session picks the group from its own parse of the SNI. Each group's rustls certificate resolver resolves only names that belong to its group, using the same normalisation function on rustls's view of the SNI, and uses the client's signature schemes to choose ECDSA or RSA. If tls-net's parse and rustls's parse ever disagreed, the worst outcome is a refusal, never a certificate from one group with another group's policy (D-032); each disagreement is counted (D-064).

**Snapshot.** `TlsServer` holds `Snapshot<ServerState>`: an `AtomicU64` version plus a mutex-guarded `Arc<ServerState>` touched only on publish and on a reader's refresh. `TlsServer::accept` takes one atomic load and an `Arc` clone [est. 20 to 40 ns]; a per-worker `ServerReader` takes one atomic load and a lock only after a publish [est. 1 ns steady state].

**Reload.** `ReloadHandle::publish(ServerBuilder)` builds a complete new state (every entry validated), then swaps. Validation happens entirely before the swap; failure returns `ReloadRefused` and the old state is untouched. The ticket key ring and session cache are carried by `Arc`. Handshakes already running hold the `Arc<ServerConfig>` they started with. Only the caller triggers a reload (FR-50).

**Expiry.** `expiry_report(now)`: `warn` below max(7 days, lifetime / 3), `critical` below max(2 days, lifetime / 10), `expired` after `not_after`. Proportional thresholds keep 47-day certificates (the CA/Browser Forum maximum from 2029-03-15) from warning right after issuance.

### 6.8 Resumption and the ticket key ring

Verified rustls behaviour (0.23.46): the default server ticketer produces no tickets, so TLS 1.3 resumption is stateful through a 256-entry cache by default; stateful TLS 1.3 resumption is single use; early data is accepted only with the ticketer disabled; provider ticketers rotate every 6 hours with random keys; clients offer only `psk_dhe_ke`.

tls-net's `TicketKeyRing` implements `ProducesTickets`. Ticket format version 1:

```
 0      1             9                          33                           n-16       n
 +------+-------------+--------------------------+----------------------------+----------+
 | 0x01 | epoch (u64) | nonce (24 bytes, random) | ciphertext of rustls value | tag (16) |
 +------+-------------+--------------------------+----------------------------+----------+
 AEAD: XChaCha20-Poly1305 (crypt-io), key = ring key for `epoch`, AAD = first 9 bytes
```

Overhead 49 bytes per ticket. A random 192-bit nonce needs no coordination between processes or hosts. Unknown version, unknown epoch, or a failed tag gives `None` (full handshake), counted in `ServerStats::tickets_rejected`.

**Ring.** At most three keys: current epoch `e`, previous `e-1` (still accepted), and the next during rotation. Epoch length `period` (default 6 hours). A ticket sealed at epoch `e` opens until the ring reaches `e+2`, so its real maximum age is under `2 * period`. Rotation is checked lazily on seal and open against `SystemTime::now()`; there is no timer. If the wall clock moves back, the ring does not move back; if it jumps forward more than `max_ratchet_steps` (default 1,000) epochs, the ring reseeds and emits `TicketKeyRotated { reseeded: true }`.

| Mode | Next key | Ticket forward secrecy | Survives restart | Across hosts |
|---|---|---|---|---|
| `Ephemeral` | random per epoch | old keys erased after 2 epochs | no | no |
| `Ratchet` (single host) | `K(e+1) = HKDF-SHA256(ikm = K(e), info = "tls-net ticket ratchet v1" + be64(e+1))`, then `K(e-1)` erased | old keys unrecoverable after 2 epochs, even with the current key | yes, through sealed export and import | no |
| `Derived` (clusters) | `K(e) = HKDF-SHA256(ikm = root, info = "tls-net ticket derive v1" + be64(e))` | only while the operator rotates `root` | yes | yes, with the same root and synchronised clocks |

**Hand-off.** The old process calls `export_sealed(wrap_key)`: `version + epoch + XChaCha20-Poly1305(wrap_key, K(e) + K(e-1))`; the new process calls `import_sealed`. tls-net never writes the export to disk. Without hand-off every returning client does a full handshake after a restart (about 3.1 times the CPU of a resumed one [est. from rustls's published 2,357 full and 7,249 resumed handshakes per second per core]).

**Stateful cache** for TLS 1.2 clients that resume by session ID: `session_cache(capacity)`, default 1,024 entries [target], [est. 200 to 400 bytes per entry]. Capacity 0 disables it.

**Client side.** Resumption store per `TlsClient` (default 256 sessions); separate clients never share tickets (FR-29).

### 6.9 Policy and defaults

| Setting | `compatible` (server default) | `modern` | `internal` | client default |
|---|---|---|---|---|
| versions | TLS 1.3, TLS 1.2 | TLS 1.3 | TLS 1.3 | TLS 1.3, TLS 1.2 |
| TLS 1.3 suites (order) | AES_256_GCM_SHA384, AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256 | same | same | same |
| TLS 1.2 suites | ECDHE_ECDSA and ECDHE_RSA with AES_256_GCM, AES_128_GCM, CHACHA20_POLY1305 | none | none | same six |
| groups | X25519MLKEM768, X25519, secp256r1, secp384r1 | same | X25519MLKEM768 only | same as compatible |
| extended master secret (TLS 1.2) | required | n/a | n/a | required |
| server suite order wins | yes | yes | yes | n/a |
| tickets per handshake | 2 | 2 | 0 | n/a |
| 0-RTT | off | off | off | off |
| unknown SNI | default certificate if configured | same | refuse | n/a |
| client certificates | none | none | required, pinned CA or pinned SPKI | sent when configured |

The client chooses the key exchange group: rustls 0.23.46 walks the client's `supported_groups` in the client's order and picks the first the server supports (`server/hs.rs`), sending a HelloRetryRequest when there is no key share for it. On `internal` listeners the provider's group list is restricted to X25519MLKEM768, so a peer that cannot do it fails with `NoCommonGroup`. With the `ring` provider (no ML-KEM group) `internal` and `require_post_quantum(true)` fail to build (`PostQuantumUnavailable`).

TLS 1.2 stays on public listeners (D-011): RFC 9325 still allows TLS 1.2 with AEAD suites and forward secrecy. Everything weak in TLS 1.2 is absent by construction (rustls has no CBC, static RSA, finite-field DHE, compression, or renegotiation); extended master secret is required.

### 6.10 ClientHello parsing and fingerprints

`HelloParser::parse(input, limits)` reads TLS records of content type 22 from the start of `input`, treats their payloads as one stream without copying (a fixed array of up to `max_records` payload ranges, default 4), and parses one `client_hello`:

- Record header: type 22, legacy version `0x03XX` (any minor version, D-110), length 1 to 16,384; anything else is `NotTls` (for example an HTTP request on 443, or an SSLv2-compatible hello) or `BadRecord`.
- Handshake type 1; length at most `max_hello_bytes` (default 16 KiB). The total needed is known after 9 bytes, so `Incomplete { needed }` is exact.
- Body: legacy version, random, session id (0 to 32), cipher suites (even length, count at most `max_ciphers`, default 512), compression methods (must contain 0), extensions (length must match; count at most `max_extensions`, default 64; duplicates are `DuplicateExtension`).
- Extension views: `server_name` (one `host_name`, at most 255 bytes), ALPN (at most 32 names of 1 to 255 bytes), `supported_groups`, `ec_point_formats`, `signature_algorithms`, `supported_versions`, `key_share` (groups only), `pre_shared_key` (presence; must be last), `early_data`, `encrypted_client_hello`, `compress_certificate`, `padding`. Unknown extensions are kept as `(type, data)` for fingerprints.
- Every length is checked against the remaining input before use, every count against its limit before iteration, all arithmetic checked. Linear in the hello length.

| Fingerprint | Definition | Output | Grade |
|---|---|---|---|
| JA4 | FoxIO JA4 technical details: `t` + version + `d`/`i` + 2-digit cipher count + 2-digit extension count (GREASE excluded, capped at 99) + first and last alphanumeric characters of the first ALPN value; `_`; first 12 hex of SHA-256 over the sorted cipher list; `_`; first 12 hex of SHA-256 over the sorted extensions (without GREASE, SNI, ALPN) `_` the signature algorithms in order | `Ja4`: 36 ASCII bytes, `Copy` | P1 |
| JA4_r, JA4_o | the unhashed sorted lists; the original-order variant | caller `String` | P2 |
| JA3 string | `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`, decimal, `-` joined, GREASE ignored | caller `String` | P2 |
| JA3 MD5 | MD5 of the JA3 string, used as a label only | `[u8; 32]` hex, feature `ja3-md5` | P3 |

Sorting uses fixed stack arrays sized by the parse limits; SHA-256 is crypt-io's. JA3 changes on almost every Chrome connection (Chrome permutes its extension order), so JA4 is the primary fingerprint. JA4 (TLS client) is BSD 3-Clause; other JA4+ methods are under the FoxIO License 1.1 and are not implemented (D-016).

The hook `HelloHook::on_client_hello(&self, &HelloContext) -> HelloVerdict` runs synchronously inside `step`; it must be a lookup, never I/O.

### 6.11 Client side

- **Trust anchors**: `TrustAnchors::mozilla()` (webpki-roots, default; the same roots on every platform), `from_pem`, `from_der`, `platform()` (feature `platform-verifier`: Windows and macOS use the OS verifier with revocation; Linux uses the system bundle with no revocation).
- **Verification**: rustls `WebPkiServerVerifier` built with the explicit provider, optional CRLs. rustls checks the name against the identity the caller gave. There is no "accept any certificate" path.
- **Pinning** (`ServerIdentity::Pinned`): with `require_chain: true`, normal verification first and then the end-entity SPKI SHA-256 must equal a pin (constant-time compare). With `require_chain: false` (a self-issued third-party certificate), a pinned verifier accepts a chain whose end-entity SPKI matches a pin without a CA, but still verifies the handshake signatures with `rustls::crypto::verify_tls12_signature` / `verify_tls13_signature` and still checks the validity window. A verifier that returns "signature valid" without checking lets anyone who copies the public certificate through; attack test T-6b keeps that bug out.
- **STARTTLS**: the SMTP client reads the `220` reply with its own parser, then calls `start_after_plaintext(server_name, leftover)`; non-empty `leftover` is `StartTlsInjection`.

### 6.12 Mutual TLS and PeerIdentity

`ClientAuth::Required` builds `WebPkiClientVerifier` with the explicit provider; `Optional` adds `allow_unauthenticated()`; `Pinned` adds the SPKI pin rule. CA name hints are sent by default; `hide_ca_names()` clears them. Peer chain budgets: at most 5 certificates of at most 16 KiB each for client certificates (10 of 32 KiB for server certificates seen by a client). `PeerIdentity { spki_sha256, end_entity, dns_names, ip_addresses, uri_names, serial, not_before, not_after }` is built once at handshake completion, only when the peer sent a certificate.

### 6.13 Handshake capacity and budgets

| Budget | Default | Checked | Error |
|---|---|---|---|
| handshakes in progress per server | 1,024 [target] | atomic increment in `accept`, before any byte is parsed; released on completion, failure, or drop | `HandshakeCapacity` |
| ClientHello bytes | 16 KiB | after the 9-byte prefix | `HelloTooLarge` |
| ClientHello records | 4 | per record header | `HelloTooFragmented` |
| ciphers / extensions / ALPN names / groups / signature algorithms / key shares | 512 / 64 / 32 / 64 / 64 / 8 | before iterating each list | `HelloOverBudget { what }` |
| inbound handshake bytes, server | 32 KiB, or 96 KiB with client auth | summed per `step` until `HandshakeComplete` | `HandshakeTooLarge` |
| inbound handshake bytes, client | 128 KiB | same | `HandshakeTooLarge` |
| peer chain length / certificate size | client certificates 5 / 16 KiB; server certificates 10 / 32 KiB | before identity extraction | `PeerChainTooLarge` |
| handshake deadline | net-io (default 10 s public, 5 s recommended internal) | net-io | net-io |

CPU per full handshake is about 0.42 ms per core for rustls (1 / 2,357 per second, rustls.dev/perf 2026-03-07) [est.; key type not stated]; 1,024 concurrent handshakes is about 0.43 CPU-seconds of queued work, bounded by the deadline.

### 6.14 Events

`TlsObserver::on_event(&self, &TlsEvent<'_>)`, default no-op; one observer per server or client. Emitting allocates nothing; borrowed fields are valid during the call only. SNI and ALPN in events are sanitised (printable ASCII; other bytes as `\xNN`). Events: `HandshakeCompleted`, `HandshakeFailed`, `HelloCaptured` (sampled), `HelloRefused`, `ReloadApplied`, `ReloadRefused`, `CertificateExpiring`, `TicketKeyRotated`, `HandshakeCapacityReached` (at most once per second per server).

### 6.15 Errors

`TlsError` is `#[non_exhaustive]`. Each variant has a code (shown `TLS-nnnn`, a `u16`), a category, an action, and a public message. `TLS-0000` is the generic code. Until the error-suite definitions crate is published, tls-net exposes `code()`, `category()` (its own `#[non_exhaustive]` `ErrorCategory`), `action()`, and `public_message()`; a later minor release implements the suite's trait instead. The full table is in `docs/API.md` ("Errors").

rustls error mapping: `InvalidCertificate(_)` to `PeerCertificateInvalid(CertificateProblem)`; `NoCertificatesPresented` to `PeerCertificateRequired`; `PeerIncompatible(_)` to the matching `NoCommon*`; `NoApplicationProtocol` to `NoApplicationProtocol`; `AlertReceived(a)` to `AlertReceived`; `DecryptError` to `DecryptFailed`; `PeerMisbehaved(_)` and `InvalidMessage(_)` to `PeerMisbehaved`; `InconsistentKeys(_)` to `KeyMismatch`; everything else to `Other`. Private detail stays out of `Display`; `Debug` prints only fields that are safe.

### 6.16 Lessons from older code

| Pattern seen before | Why it is wrong | tls-net |
|---|---|---|
| installing a process-default crypto provider and ignoring the result | global state; another crate can change it | explicit provider per configuration (D-043) |
| errors carrying a `String` from rustls | not actionable, may leak detail | typed variants with codes and categories |
| a pinning verifier that returns "signature valid" without checking, and compares hashes with `==` | anyone holding the public certificate passes; timing leak | pins on top of real verification, constant-time compare, test T-6b |
| `rustls-pemfile` | archived (RUSTSEC-2025-0134) | rustls-pki-types `PemObject` |
| ALPN `h2, http/1.1` on every listener | cross-protocol confusion | ALPN set per listener and per host |

## 7. Features and dependencies

### 7.1 Features

| Feature | Default | Effect | Ships |
|---|---|---|---|
| `aws-lc` | on | rustls `aws_lc_rs` and `prefer-post-quantum`; X25519MLKEM768 | 0.3 |
| `ring` | off | rustls `ring`; no ML-KEM groups; post-quantum policies fail to build | 0.3 |
| `fips` | off | rustls `fips` over aws-lc-rs; `Policy::fips()`; build fails unless `is_fips()` is true (D-042) | 0.5 |
| `prebuilt-nasm` | off | pass-through to aws-lc-rs for Windows x86-64 without NASM | 0.2 |
| `webpki-roots` | on | bundled Mozilla roots | 0.3 |
| `platform-verifier` | off | OS trust store through rustls-platform-verifier | 0.5 |
| `key-vault` | on | `KeySource::Vault`, ticket keys in key-vault | 0.4 |
| `net-io` | off until 0.3, then on | the seam implementation | 0.3 |
| `ja3-md5` | off | JA3 MD5 digest (in-house MD5, label only) | 0.5 |
| `rustls-escape-hatch` | off | raw rustls configuration access; outside semver | 0.5 |
| `dangerous-keylog` | off | NSS key log output for debugging; refused together with FIPS (D-040) | 0.5 |

With both `aws-lc` and `ring` on, aws-lc-rs is used and `provider_name()` says so. With `--no-default-features` there is no provider and every constructor returns `TlsError::NoProvider` (tested, so the mode is not dead code).

### 7.2 Footprint

Resolved with `cargo tree` on 2026-11-04 for the default features: rustls 0.23.46, rustls-pki-types 1.15.1, rustls-webpki 0.103.16, untrusted 0.9.0, subtle 2.6.1, zeroize 1.9.1, once_cell 1.21.4, aws-lc-rs 1.19.0, aws-lc-sys 0.47.0 (C and assembly), webpki-roots 1.0.11 (CDLA-Permissive-2.0, data); first party crypt-io 1.2.2 (with the RustCrypto chacha20poly1305, sha2, hkdf crates and mod-rand) and key-vault 1.1.0 (with blake3, getrandom 0.2, zeroize, and the platform crates libc or windows-sys). Build-only: cc and its helpers for aws-lc-sys. With `ring` instead: ring 0.17.14 (C and assembly) replaces aws-lc-rs and aws-lc-sys.

How the exception is contained:

1. Only tls-net depends on rustls. Every other crate depends on tls-net's types.
2. No rustls type appears in the public API (NFR-14).
3. rustls default features are off: no `log`, no compression features, no process-default provider.
4. `deny.toml` bans `openssl`, `openssl-sys`, `native-tls`, `tokio`, `async-std`, and `rustls-pemfile`; `CDLA-Permissive-2.0` is allowed for `webpki-roots` only (D-041).
5. Every lockfile change in the rustls tree is reviewed in the pull request; `cargo audit` runs in CI.
6. The provider is chosen at build time and passed explicitly to every configuration (D-043).

**Windows builds.** aws-lc-sys 0.47 needs a C compiler; on x86-64 it uses NASM when found and otherwise falls back to its prebuilt NASM objects (checked on 2026-11-04 on a machine without NASM, D-042). `prebuilt-nasm` forces the prebuilt objects. FIPS builds need CMake and Go (and on Windows NASM, Ninja, and clang).

## 8. Threats

The attacker controls every byte from the network, can open many connections, replay recorded traffic, present any certificate, and observe timing. The attacker does not control configuration files or process memory (a memory reader defeats key-vault, as its documentation states).

| Id | Threat | Defence | Attack test (must fail to get through) | Cost |
|---|---|---|---|---|
| T-1 | Version downgrade to TLS 1.0/1.1 or SSL | rustls implements neither; `Version` has two variants; rustls clients check the TLS 1.3 downgrade sentinel | a ClientHello offering only TLS 1.1 gets `protocol_version`; a server forced to TLS 1.2 while the client supports 1.3 with the sentinel set is refused | 0 |
| T-2 | TLS 1.3 to 1.2 downgrade on internal channels | `Policy::internal` is TLS 1.3 only | a TLS 1.2-only client against an internal listener gets `NoCommonVersion` | 0 |
| T-3 | Weak suites or key exchange | AEAD with ECDHE only; enums cannot name others; empty lists refused | a ClientHello offering only `TLS_RSA_WITH_AES_128_CBC_SHA` gets `handshake_failure` | 0 |
| T-4 | Post-quantum stripping | TLS 1.3 transcript covers the negotiation; internal listeners accept only X25519MLKEM768 | rewriting the ClientHello groups in transit fails the Finished check; an internal listener refuses an X25519-only client | ML-KEM-768 adds about 2.3 KiB per handshake and [est. tens of µs] CPU; measured at 0.6 |
| T-5 | STARTTLS stripping and injection | smtp-net requires TLS; `start_after_plaintext` refuses any byte after the `220` reply | `220 ready\r\n250 injected\r\n` in one segment gives `StartTlsInjection` | 0 |
| T-6 | Wrong or misissued server certificate | rustls-webpki path validation; name check; optional CRLs; pins | wrong name, expired, self-signed, unknown root, revoked (CRL): each refused | rustls's [est. tens to hundreds of µs per chain] |
| T-6b | Pin bypass by a verifier that skips signature checks | pinned verifier calls rustls's signature verification; constant-time compare | a server presenting the pinned certificate but signing with another key is refused | one signature verification, as without pinning |
| T-7 | Renegotiation and triple handshake | rustls does not renegotiate; EMS required for TLS 1.2 | a TLS 1.2 client without EMS is refused. A mid-connection ClientHello cannot be sent through any client here: tlsfuzzer's `test-renegotiation-disabled.py` has no EMS option, so tls-net refuses its first handshake (D-113); the defence is that rustls has no renegotiation code | 0 |
| T-8 | Private key leakage through logs, errors, dumps, freed memory | key-vault custody; wiped PEM and DER buffers; no key in `Debug`/`Display`/errors; key file permission check; key log refused with FIPS and absent by default | the `Debug` of every public type that can hold key material (key sources, builders, servers, sessions, ticket modes, ring handles, sealed exports) and the `Display` of the key errors are scanned for windows of the test key and of a known ticket seed, raw, hex, and listed; a world-readable key file is refused | vault access 34 to 157 ns; per-signature custody [est. 10 to 150 µs] per handshake |
| T-9 | Weak or wrong server configuration shipped | load-time validation (6.5); reload refuses rather than degrades | RSA-1024 key, SHA-1 signed certificate, wrong-name certificate, mismatched key, reversed chain: each produces its named error | build time only |
| T-10 | 0-RTT replay | off; enabling needs a `dangerous_` method (P3) and stateful single-use resumption | early data to a default server is rejected and never reaches the application | 0 |
| T-11 | Resumption linkability and ticket-key compromise | `psk_dhe_ke` only; two-epoch ring; ratchet erases old keys; per-client stores; internal listeners send no tickets | a ticket from epoch e-2 is rejected; a ratchet ticket cannot be opened after two rotations even with the current key; two clients never reuse each other's tickets | seal or open [target under 2 µs]; 49 bytes per ticket |
| T-12 | Ticket forgery or tampering | AEAD tag checked before use; version and epoch in the AAD; open never panics | bit flips at every position, 4,000 seeded random tickets of every length up to 400 bytes, truncated tickets: all fail; the `ticket_open` fuzz target | as T-11 |
| T-13 | Handshake CPU exhaustion | capacity cap; bouncer-io handshake rates; ECDSA preferred; resumption; net-io deadline | a ClientHello flood above the cap is refused before parsing [target under 1 µs per refusal]; a stalled handshake releases its slot at the deadline | one atomic per session |
| T-14 | ClientHello parser abuse | lengths checked against remaining input; counts before iteration; 16 KiB and 4-record limits; linear time | fuzz target `hello_parse`; property test never panics, never reads past the input; fixtures for each budget at n-1, n, n+1 | parse under 1.5 µs for 2 KiB [target] |
| T-15 | Cross-protocol attacks (ALPACA) | strict ALPN; `AlpnPolicy::Required` on internal listeners; unknown SNI refused without a default | an HTTP ALPN against an SMTP-only listener is refused; an unconfigured SNI on a back-channel listener is refused | 0 |
| T-16 | Domain fronting | tls-net exposes the normalised SNI; web-net compares it with `Host` | tls-net tests that `info().server_name` equals the normalised SNI | 0 |
| T-17 | Truncation | `close_notify` tracked; EOF without it is `Unclean` | a TCP FIN mid-stream gives `Unclean` and `UncleanClose` | 0 |
| T-18 | Certificate expiry outage | proportional thresholds, events, reload refuses expired certificates | clock past `not_after - lifetime/3` gives `warn`; an expired certificate in a reload is refused | report under 1 µs per entry [target] |
| T-19 | Half-written files during reload | key match check; reload is all or nothing | new chain with old key: refused, old certificate still served, no failed handshake | as a reload |
| T-20 | Log or terminal injection through SNI or ALPN | SNI validated as LDH ASCII; event fields sanitised | SNI with `\r\n`, NUL, ANSI escapes is treated as absent; no event (with every hello sampled) holds a raw control byte | under 50 ns [target] |
| T-21 | Timing side channels in tls-net's code | constant-time pin and secret comparisons; AEAD for tickets | statistical timing test of the pin comparison (Linux CI) | negligible |
| T-22 | Client certificate abuse (huge chains) | chain length and size budgets; handshake byte budget; webpki path limits | a 50-certificate chain and a 1 MiB certificate are refused | 0 |
| T-23 | Supply chain | small pinned tree, `cargo audit`, `cargo deny`, bans, lockfile review, FIPS option | CI fails on an advisory; a test that the tree has no banned crate | build time |
| T-24 | Stolen hand-off export | sealed with XChaCha20-Poly1305 under a wrap key; local channel only; wiped on drop | wrong wrap key, tampered export, export older than one epoch: each refused | microseconds per restart |
| T-25 | SNI probing of hosted names | `UnknownName::Refuse` gives the same alert for every unknown name; lookup is two hash lookups | 1,000 probes: identical alert; refusing names under a hosted wildcard's domain takes as long as refusing unrelated names (opt-in timing test, as T-21) | 0 |
| T-26 | Legacy attack classes (BEAST, POODLE, Lucky13, CRIME, FREAK, Logjam, Raccoon, ROBOT, Sweet32) | the features they need do not exist in rustls | testssl.sh vulnerability section clean (weekly job) | 0 |
| T-27 | Memory exhaustion through half-open handshakes | capacity cap, handshake byte budget, net-io buffer limits and deadline | 10,000 connections sending one byte of ClientHello: memory flat at the cap times per-session size | per-session state [est. a few KiB in rustls] |
| T-28 | Process-wide provider confusion | tls-net never reads or installs the process default | build a server after installing a different process default (secp384r1 only); `provider_name()` is unchanged and the handshake still negotiates X25519MLKEM768 | 0 |

## 9. Performance targets

rustls 0.23.37 with aws-lc-rs 1.16 on x86_64 (rustls.dev/perf, 2026-03-07), per core: full handshakes 2,357/s, resumed 7,249/s, sent 7,421 MB/s, received 7,333 MB/s; in-memory connections, so an upper bound without network costs.

| Metric | Target | Compared with |
|---|---|---|
| tls-net overhead per `step` record | under 100 ns plus the D-035 copy [target] | rustls unbuffered called directly |
| tls-net overhead per `encrypt` record | under 50 ns [target] | same |
| allocations per established record, tls-net code | 0 (counting allocator) | n/a |
| allocations per established record, end to end | reported (rustls 0.23: one per record each way) | tokio-rustls (reported) |
| full and resumed handshake rate, in memory, one core | within 3% of rustls unbuffered [target] | rustls |
| loopback HTTPS handshakes per second (net-io reactor, 8 cores) | at least 1.2 times tokio plus tokio-rustls [target] | tokio-rustls 0.26.6 |
| loopback bulk throughput, 16 KiB writes | at least 1.2 times tokio plus tokio-rustls [target] | same |
| memory per idle TLS connection (excluding net-io buffers) | rustls state plus under 512 bytes [target] | tokio-rustls |
| ClientHello parse plus JA4, 2 KiB | under 1.5 µs [target] | the `ja4` crate as a reference point |
| SNI lookup, 10,000 names | under 100 ns [target] | rustls `ResolvesServerCertUsingSni` |
| `accept()` / `ServerReader::accept` | under 60 ns / under 20 ns [target] | n/a |
| reload build of 100 ECDSA certificates / swap | under 10 ms / under 1 µs [target] | n/a |
| ticket seal / open | under 2 µs each [target] | rustls provider ticketer |
| per-signature custody, ECDSA P-256 | at least 70% of the resident full handshake rate [target] | resident |

Benchmarks (criterion, `benches/`): `hello_parse`, `ja4`, `sni_lookup`, `step_record`, `encrypt_record`, `handshake_full`, `handshake_resumed`, `ticket_seal_open`, `reload`, `accept`, `custody`. The end-to-end comparison runs in a separate, unpublished harness (tokio appears only there, never in tls-net's own manifest). Method and hardware go into `docs/PERFORMANCE.md`; a regression over 5% blocks the change. Measured values and the status of each target: `docs/PERFORMANCE.md`, "Summary" (0.6, D-105).

## 10. Testing plan

| Layer | Content |
|---|---|
| unit | every function, every `Ok` and `Err` path; names `test_<subject>_<condition>_<expected>` |
| integration (`tests/`) | server against client over an in-memory pipe and over `std::net` loopback; every preset; every client-auth mode; reload under load; ticket modes; hand-off between two servers; STARTTLS with a scripted SMTP peer; the net-io adapter on a real net-io server |
| interoperability | OpenSSL `s_client` and curl, Go `crypto/tls`, rustls examples; servers: OpenSSL `s_server`, Go; post-quantum interop with OpenSSL 3.5 and Go 1.24+ |
| conformance | tlsfuzzer server scripts; testssl.sh scan of the example server (weekly CI) |
| property | hello parser never panics and never exceeds budgets; `step` fed one byte at a time equals `step` fed at once; ticket round trip; tampered tickets fail; SNI normalisation idempotent; JA4 invariant under extension and cipher permutation |
| fuzz | `hello_parse`, `der_fields`, `pem_intake`, `ticket_open`, `session_step_server`, `session_step_client`, `import_sealed`; corpus kept outside the repository |
| allocation | counting allocator: established `step` and `encrypt`, `ServerReader::accept`, SNI lookup, `Ja4::compute`, hello parse |
| loom / Miri | snapshot, capacity gate, ticket ring; Miri on the parser, DER reader, SNI table, ring bookkeeping |
| attack | one per threat T-1 to T-28, in `tests/attacks/` |
| known answers | JA4 and JA3 against the published examples; RFC 9266 exporter values against another implementation; MD5 against RFC 1321 |

The full edge-case list (59 groups: parser, sessions and buffers, certificates and keys, SNI and reload, tickets, client side, concurrency) is kept with the tests and checked off in the 1.0 audit.

## 11. Defence ideas

At least one new idea per version, as hypothesis, method, and expected cost.

| Version | Hypothesis | Method | Expected cost |
|---|---|---|---|
| 0.2 | A difference between tls-net's parse of the ClientHello and rustls's (SNI) is an attack signal, because honest clients produce one unambiguous hello | the group resolver checks rustls's normalised SNI against the session's group and counts every disagreement (shipped in 0.3, D-064; exposed in `ServerStats` at 0.5) | one hash lookup per handshake, already paid |
| 0.3 | Refusing ClientHellos with GREASE in impossible positions (GREASE as the only cipher) catches crude fingerprint spoofers | count; report to sentinel-sec in shadow mode before enforcing | under 50 ns per hello [target] |
| 0.4 | A per-fingerprint full-handshake budget in bouncer-io (not per IP) slows distributed handshake floods from one tool | tls-net emits JA4 on `HandshakeCompleted`; bouncer keeps a bounded sketch | one lookup per handshake |
| 0.5 | Comparing JA4 with the User-Agent family at the web layer flags clients lying about being browsers | hand JA4 to web-net through `ConnectionInfo`; sentinel scores mismatches | one table lookup per request |
| 0.6 | Sending fewer tickets (1) to fingerprints that never resume saves CPU and bytes | per-fingerprint resumption rate in stats | none |
| 0.7 | Rotating ticket keys on a security event limits the damage of a suspected compromise | `TicketKeyRingHandle::rotate_now()` wired to the urgent control line | one full-handshake wave |
| 0.8 | Short-lived internal certificates (hours) from the platform CA make CRLs unnecessary inside the platform | cert-net issues; tls-net reloads | a reload every few hours |
| 0.9 | Constant-shape refusals (same alert, same timing) for every policy refusal reduce probing value | measure timing distributions of refusal paths | 0 |

## 12. Open questions

None blocks a pre-1.0 release. James decides 1.0 (DIRECTIVES section 3, item 10 needs production use of direct mode and smtp-net).

| Id | Question | Status |
|---|---|---|
| Q-1 | rustls 0.24 (providers in separate crates, new input buffering, split mode): does it deliver plaintext in place, so the D-035 copy goes away? | checked when 0.24 is released as stable, at the latest in 0.9 (D-007) |
| Q-2 | Windows key file ACL check (FR-49 counterpart) | P3 after 1.0 through a first-party Windows security crate (D-028) |
| Q-3 | Ticket ring keys in key-vault (rotated on advance) instead of tls-net's wiped buffers? | measured at 0.6 against the seal and open targets (D-070) |

## 13. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Never write our own TLS; rustls behind a thin adapter | security first; TLS is the accepted third-party exception |
| D-002 | 2026-10-13 | tls-net is separate from net-io | net-io stays dependency-free |
| D-003 | 2026-10-13 | 0-RTT off by default | early data can be replayed |
| D-004 | 2026-11-04 | Crypto provider: aws-lc-rs by default, ring as a non-default feature (supersedes the 0.1 recommendation of ring) | ring's provider has only X25519, P-256, P-384 (no ML-KEM), so post-quantum key exchange, required on internal listeners, is impossible with it; aws-lc-rs carries the FIPS 140-3 path and rustls's benchmark lead; crypt-io's signing work uses aws-lc-rs too, so the tree has one backend. Windows cost: a C compiler; NASM optional (D-042) |
| D-005 | 2026-11-04 | Client roots: bundled Mozilla roots (webpki-roots) by default; OS store through rustls-platform-verifier as a non-default feature (supersedes the 0.1 recommendation) | the same answer on every platform (determinism); one data crate instead of six platform crates; the platform verifier behaves differently per OS (no revocation on Linux). Cost: root updates need a tls-net release (checked in every release) |
| D-006 | 2026-11-04 | The first crates.io publish is 0.2.0 (0.1.0 was never published) | O-3 said yes to claiming the name; the release routine publishes every version from 0.2.0 on |
| D-007 | 2026-11-04 | Build on rustls 0.23 now; move to 0.24 when it is stable, at the latest in 0.9 | 0.23 is the stable line; no rustls type is public, so the move is internal |
| D-008 | 2026-11-04 | PEM through rustls-pki-types `PemObject`, with tls-net's size gate, label scan, and key counting around it | already in the tree, maintained by the rustls team; an in-house PEM parser would be a second parser to fuzz for no smaller footprint |
| D-009 | 2026-11-04 | Default key custody with key-vault: resident | per-signature costs a key parse per full handshake and still leaves the key in provider memory during the signature; offered for low-rate, high-value keys |
| D-010 | 2026-11-04 | Ticket modes: ratchet with hand-off for single-host deployments, derived only for clusters (root rotated by the operator), ephemeral for Tier 1 | ratchet keeps ticket forward secrecy to two epochs and survives restarts; derived trades forward secrecy for coordination-free clusters, documented as such |
| D-011 | 2026-11-04 | TLS 1.2 on public listeners by default (`compatible`), EMS required, AEAD only; internal listeners TLS 1.3 only | RFC 9325 still allows it; some clients and crawlers lack TLS 1.3; operators switch to `modern` from `HandshakeCompleted` statistics |
| D-012 | 2026-11-04 | Ticket AEAD, JA4 and SPKI hashing, HKDF through crypt-io (XChaCha20-Poly1305, SHA-256, HKDF-SHA256) | random 192-bit nonces need no coordination across processes; reusing the rustls record encrypter would need a shared nonce counter, where one mistake reuses nonces |
| D-013 | 2026-11-04 | A ClientHello tls-net's parser rejects is refused (fail closed), counted, and evented; `refuse_malformed = false` exists for emergencies | fuzzing plus differential tests against rustls keep false refusals at zero |
| D-014 | 2026-11-04 | Hook refusals close without an alert; protocol failures send the alert rustls chooses | a scanner learns nothing; costs nothing |
| D-015 | 2026-11-04 | Unknown SNI with a default certificate: serve the default on public listeners; refuse on internal listeners (`internal` sets `UnknownName::Refuse`) | clients without SNI exist on the public internet; internal peers always send it |
| D-016 | 2026-11-04 | JA4 and the JA3 string by default; JA3 MD5 behind `ja3-md5` with an in-house MD5 used only as a label; no JA4S, JA4H, JA4X | other JA4+ methods are under the FoxIO License 1.1, not BSD, and belong to other layers |
| D-017 | 2026-11-04 | X.509 field extraction with an in-house bounded DER reader that never makes a trust decision; fuzzed and differential-tested against rustls-webpki | a third-party X.509 parser adds several crates for reporting fields |
| D-018 | 2026-11-04 | No certificate transparency (SCT) checks on the client | rustls removed SCT verification; tls-net clients talk to known relays, APIs, and internal peers, where pinning or a private CA is stronger |
| D-019 | 2026-11-04 | OCSP: static staples only, fetched by cert-net | tls-net does no I/O; Let's Encrypt ended OCSP in 2025, so many certificates have no responder |
| D-020 | 2026-11-04 | kTLS offload is P3 after 1.0 | the socket calls need unsafe code in net-io; the benefit must be measured first |
| D-021 | 2026-11-04 | key-vault is a default feature | servers should keep ticket keys and private keys in the vault; tiny tools can turn it off |
| D-022 | 2026-11-04 | Default handshake capacity per server: 1,024, revisited at 0.6 from measurements | roughly what a modest server finishes within one deadline window [est.] |
| D-023 | 2026-11-04 | Implement net-io's published seam (`TlsAcceptor`, `TlsSession` with `on_transport_closed` and `input_capacity_required`, `net_io::TlsError` with a `u16` code) instead of the names sketched before net-io's design lock; tls-net's own Tier 3 sessions keep `on_eof` and map to it | net-io owns the traits and locked them at its 0.2; the in-place seam was adopted by both crates |
| D-024 | 2026-11-04 | No `no_std` core until a consumer exists; keep the session and parser independent of `std` where it costs nothing | file loading, `SystemTime`, and key-vault need `std` |
| D-025 | 2026-11-04 | rustls 0.24 split mode (read and write halves on two threads) is evaluated at the 0.24 move and adopted only with a measured gain | no number yet |
| D-026 | 2026-11-04 | rustls `logging` feature off; tls-net reports through `TlsObserver` | no `log` crate in the tree |
| D-027 | 2026-11-04 | Certificate compression (RFC 8879) off, P3 | needs third-party compression crates; saves a few KiB per full handshake |
| D-028 | 2026-11-04 | Windows key file ACL check is P3, through a first-party Windows security crate when one exists | keeps tls-net `forbid(unsafe_code)`; documented in `docs/PLATFORM-NOTES.md` |
| D-029 | 2026-11-04 | V-1 answered: rustls 0.23.46 coalesces a handshake message spanning records in place in the caller's buffer (`msgs/deframer/handshake.rs`, messages up to 65,535 bytes). `INCOMING_MIN` stays 18,437; `input_capacity_required()` reports `max(INCOMING_MIN, held + 1)` during the handshake | net-io grows its read buffer only when a peer sends a large message; the handshake byte budget bounds the total; asking for 96 or 128 KiB up front would make net-io refuse every connection with its 64 KiB default |
| D-030 | 2026-11-04 | V-2 answered: AWS-LC wipes every allocation on free (`OPENSSL_free` calls `OPENSSL_cleanse`); ring does not wipe key memory on drop | completes the custody statement in `docs/SECURITY.md`; one more reason aws-lc-rs is the default |
| D-031 | 2026-11-04 | V-3 answered: when a rustls resolver returns `None`, rustls sends `access_denied`. tls-net decides unknown names itself from its own parse, before the rustls connection exists, and writes the 7-byte plaintext fatal `unrecognized_name` alert (`15 03 03 00 02 02 70`) | RFC 6066 names that alert for this case; T-25 needs the same alert for every unknown name; a constant alert record is not TLS implementation |
| D-032 | 2026-11-04 | V-4 answered with host groups: the session picks the group from its own parse; each group's rustls resolver resolves only its own names, with the same normalisation function applied to rustls's SNI (rustls lowercases a validated `DnsName`; IP literals and invalid names are absent). After the handshake the two views are compared (idea 0.2) | a parser difference can only cause a refusal, never a certificate with another host's policy |
| D-033 | 2026-11-04 | V-5 answered: rustls refuses RSA PKCS#1 v1.5 and SHA-1 schemes for TLS 1.3 handshake signatures (`SignatureScheme::supported_in_tls13`); `SignatureScheme` keeps the PKCS#1 variants because TLS 1.2 and certificate signatures still use them | matches RFC 9846; tested at 0.3 |
| D-034 | 2026-11-04 | V-6: no behaviour depends on browser key shares; the post-quantum share on public listeners is measured from `HandshakeCompleted` events at 0.8 | a measurement beats a claim about browser defaults |
| D-035 | 2026-11-04 | rustls 0.23.46's unbuffered API does not deliver plaintext in place: `ReadTraffic::next_record` pops an owned `Vec` (one allocation and one copy per received record, `common_state.rs` `take_received_plaintext`), and `WriteTraffic::encrypt` builds each record in a `Vec` before copying it out. tls-net copies the plaintext into the consumed region of the caller's input so `Data` stays a slice of that buffer, as net-io's seam requires. NFR-1 and NFR-2 are restated: tls-net's own code allocates nothing on the record path; the extra copy and rustls's allocations are measured and reported | a seam that returned rustls's own chunk would tie its lifetime to the session, not the buffer; the copy costs [est. 0.3 to 1 µs per 16 KiB record] against [est. 2 to 3 µs] for AEAD on the same record. Q-1 checks whether rustls 0.24 removes it |
| D-036 | 2026-11-04 | The net-io adapter moves from 0.5 to 0.3, and the net-io requirement is `>= 0.4, < 0.7` (the seam is identical across those releases; CI compiles against the lowest and the newest) | net-io published the seam in 0.4.0 and is at 0.6; serve-net's real-TLS tests wait only for tls-net; a range lets consumers on any of those net-io releases use tls-net |
| D-037 | 2026-11-04 | The ClientHello parser moves from 0.4 to 0.3 (JA4 and JA3 stay in 0.4) | the server session's `Hello` state, the unknown-name refusal (D-031), and host groups (D-032) need it; it is the hardest new code, so it goes first |
| D-038 | 2026-11-04 | `start_after_plaintext` moves from 0.5 to 0.3 | it is a check on one slice; smtp-net is being built now |
| D-039 | 2026-11-04 | Roadmap stages that need production deployment (two weeks on a staging host, production mail, RC builds in production) are gates on 1.0 owned by James, not exits of 0.8 or 0.9; 0.8 instead requires the consumers' integration in this repository's tests and examples, and 0.9.x is a polish series (gaps, performance re-tune, security review, readiness note) | a library release cannot wait on a deployment it does not control; DIRECTIVES section 3 item 10 already makes production use a 1.0 condition |
| D-040 | 2026-11-04 | `dangerous-keylog` and FIPS are refused together at configuration build time (`PolicyInvalid`), not with a compile error | `--all-features` must compile (CI, docs.rs); a runtime refusal at build time is just as hard to miss |
| D-041 | 2026-11-04 | `deny.toml` bans openssl, openssl-sys, native-tls, tokio, async-std, rustls-pemfile; allows CDLA-Permissive-2.0 for webpki-roots only; checks only the supported targets (Linux, Windows, macOS on x86-64 and aarch64) | contains the exception; platform-verifier's Android and wasm32 crates are never built for supported targets |
| D-042 | 2026-11-04 | No NASM install in CI: aws-lc-sys 0.47 falls back to prebuilt NASM objects on Windows x86-64 (checked on a machine without NASM, stable and 1.85). FIPS is a separate Linux CI job; when `fips` ships (0.5), the gate's "all features" is the full list minus `fips` on Windows and macOS, and docs.rs lists features explicitly | a FIPS build needs CMake and Go (plus NASM and Ninja on Windows); forcing that on every runner adds cost for no coverage |
| D-043 | 2026-11-04 | tls-net never calls `CryptoProvider::install_default` and never uses `ServerConfig::builder()` / `ClientConfig::builder()`; every configuration uses `builder_with_provider` and the fallible version setters | no global mutable state; another crate cannot change tls-net's provider (T-28) |
| D-044 | 2026-11-04 | Error codes are `u16` (`TLS-nnnn`) | net-io's seam carries a `u16`; four decimal digits fit |
| D-045 | 2026-11-04 | The ClientHello is parsed twice (tls-net, then rustls) | rustls offers no access to its own parse before the connection exists; tls-net's parse is [target under 1.5 µs] against [est. 420 µs] for a full handshake |
| D-046 | 2026-11-04 | Public items are re-exported at the crate root; modules stay private | one import path per item; modules can be reorganised without breaking users |
| D-047 | 2026-11-04 | `encrypt` makes one rustls call for the whole plaintext; rustls checks the full size and writes all records or none | matches net-io's "all records or none" contract without tls-net computing record sizes |
| D-048 | 2026-11-04 | The 0.2 design lock is approved under James's delegation of pre-1.0 technical calls; 1.0, product, and visibility calls stay with him | recorded so the approval is traceable |
| D-049 | 2026-11-04 | A policy with `max_fragment_size` below 512 bytes is refused for sessions driven through the net-io adapter | net-io leaves 2 KiB of room beyond 16 KiB of plaintext per `encrypt`; 32 records of 512 bytes need 704 bytes, smaller fragments can exceed 2 KiB and would fail every write |
| D-050 | 2026-11-04 | API additions over the spec sketch, written into `docs/API.md`: `ServerBuilder::certificate_der`, `load_limits` and `LoadLimits` (intake budgets were fixed numbers), `hello_sampling`, `HostPolicy::alpn_policy`, `HelloContext::server_name`, `HelloRefusal`, `TlsError::{alert, required, public_message}`, `Session::error_code`, `default_provider_name()`, `normalize_server_name`, `BadAnchor` and `WrongPurpose` variants, `ServerStats::{tls12_handshakes, post_quantum_handshakes}`, `HandshakeLimits` setters with ranges, `KeyLogSink`, `RevocationPolicy` as a bit set | each fills a gap found while writing the reference: a budget with no setter, a fact an operator needs to decide when TLS 1.2 can go, a value the hook would otherwise recompute |
| D-051 | 2026-11-04 | A session failure that has an alert to send is reported as `Ok(Transmit)` with the alert in `output` and the session already `Failed`; the next `step` returns the error | net-io closes on `Err` without sending its output buffer, and the seam's error carries only the alert code; reporting the alert as an ordinary transmit makes every driver send it with no extra API |
| D-052 | 2026-11-04 | `export_keying_material` and `channel_binding` wait for rustls 0.24: the 0.23.46 unbuffered connections expose no exporter (only the buffered `ConnectionCommon` does), and tls-net must not derive keys itself. Moved from 0.4 to the rustls 0.24 adoption (at the latest 0.9), recorded in `ROADMAP.md` | implementing the TLS key schedule here would be writing TLS (D-001); buffered connections would undo the seam (D-023) |
| D-053 | 2026-11-04 | Hello parse failures close without an alert, like hook refusals | the peer has not shown it speaks TLS; an alert would teach a scanner which parser rule fired |
| D-054 | 2026-11-04 | A DER private key's form (PKCS#8, PKCS#1, SEC1) is detected from its structure by tls-net's DER reader | one rule, read from the ASN.1 structure, the same for every input |
| D-055 | 2026-11-04 | When the private key does not match the first certificate but matches a later one, the error is `ChainOrder { position: 0 }`, not `KeyMismatch` | a reversed chain is a common operator mistake; the specific error says what to fix |
| D-056 | 2026-11-04 | Groups a preset lists but the provider lacks (X25519MLKEM768 with `ring`) are skipped; groups the caller names explicitly, and post-quantum requirements, must exist or the build fails | `compatible` must work with every provider; FR-8 forbids falling back only from what the caller asked for |
| D-057 | 2026-11-04 | `Policy::max_fragment_size` is the plaintext bytes per record; rustls's field counts the 5-byte header, so tls-net passes the value plus 5 | one meaning in tls-net's API, checked against rustls `msgs/fragmenter.rs` |
| D-058 | 2026-11-04 | Interop (OpenSSL `s_client`, curl) and public-site tests are opt-in by environment variable (`TLS_NET_INTEROP`, `TLS_NET_NETWORK`) and run in a Linux CI job | they need external binaries and the internet; the default test run stays hermetic |
| D-059 | 2026-11-04 | The allocation test counts the steady state after one warm-up record: rustls's plaintext queue allocates its buffer on first use | measures the per-record cost, which is what NFR-1 is about |
| D-060 | 2026-11-04 | Fuzz corpus seeding with real ClientHellos (browsers, curl, Go, OpenSSL) moves to 0.7; 0.3 ships the five targets, built in CI and run for two minutes each without findings | random bytes reach the parser's deeper paths slowly; seeding belongs with the 24-hour runs |
| D-061 | 2026-11-04 | `TlsError` has no `alert()`; the sessions do (`ServerSession::alert`, `ClientSession::alert`) | the alert belongs to the connection that sent or received it |
| D-062 | 2026-11-04 | `ClientHelloView` gains `extension_types`, `extension_count`, `has_server_name`, `normalized_server_name`, and `has_alpn`; `point_formats` is an iterator; `server_name`, `alpn`, and `extensions` return only data that sits in one record | a zero-copy view over several records cannot lend a slice that crosses a record boundary; the typed accessors read across boundaries |
| D-063 | 2026-11-04 | Received plaintext travels rustls chunk, spare output, then input (two copies by tls-net) | `ReadTraffic` holds the borrow of the whole input until it is dropped, and dropping it drops the chunk; the output has at least `OUTGOING_MIN` free, more than any record. Cost [est. 0.5 to 1.5 µs per 16 KiB record], measured at 0.6; removed if rustls 0.24 delivers in place (Q-1) |
| D-064 | 2026-11-04 | rustls 0.23.46's unbuffered server connection has no `server_name()` accessor, so defence idea 0.2 runs inside the group resolver: rustls's SNI is normalised and checked against the session's group, and each disagreement is counted | the check runs before the certificate is chosen, earlier than a comparison after the handshake |
| D-065 | 2026-11-04 | `TlsServer::handshakes_in_progress()` is public | operators and tests need the gate's state without waiting for `ServerStats` (0.5) |
| D-066 | 2026-11-04 | When application data (or `close_notify`) arrives in the same flight as the peer's Finished, rustls hands it out before it reports the handshake complete. The session reports `HandshakeComplete` first and keeps the plaintext at the front of the unconsumed input (it reports that many bytes fewer as consumed); the next `step` hands it out as `Data` before rustls runs again | net-io refuses plaintext before `HandshakeComplete`, and clients such as curl send their first request with their Finished; found by the CI interop job, now covered by an in-memory test and a net-io test |
| D-067 | 2026-11-04 | `ClientAuth` is a struct with constructors (`none`, `optional`, `required`, `pinned`) and modifiers (`with_crls`, `hide_ca_names`), not an enum | CRLs and CA-name hiding apply to several modes; an enum would repeat the fields in each variant |
| D-068 | 2026-11-04 | `ServerBuilder` defaults: stateless tickets in `Ephemeral` mode with 6-hour epochs and 2 tickets per handshake (off for `Policy::internal()`), session cache of 1,024 entries | the same as rustls's own provider ticketer, with tls-net's AEAD; internal peers reconnect rarely and keep no ticket state to steal |
| D-069 | 2026-11-04 | key-vault is used with `std`, `mlock`, `zeroize`, and `fragment-standard` (its defaults minus the decoy) | turning key-vault's default features off had dropped page locking and wiping, the properties custody relies on |
| D-070 | 2026-11-04 | Ticket ring keys live in tls-net's wiped buffers; the ratchet seed or the derived root may come from key-vault (`TicketSeed::Vault`) | a vault access per ticket seal and open adds a callback per handshake and the AEAD key schedule copies the key anyway; revisited with measurements at 0.6 (Q-3) |
| D-071 | 2026-11-04 | OCSP staples are checked when given (`ocsp_staple`): at most 16 KiB, a successful response, status good, `thisUpdate` not in the future, `nextUpdate` not past; a failing staple is an error at that call (and so refuses a reload) rather than being dropped silently | until events exist (0.5) a dropped staple would be invisible; refusing at the call tells the operator at once |
| D-072 | 2026-11-04 | `HelloLimits::max_ciphers` ranges 1 to 1,024 (default 512) | the fingerprint sorts ciphers in a stack array of that size (2 KiB), so JA4 stays exact and allocation-free |
| D-073 | 2026-11-04 | A `TlsClient` without anchors builds, with a verifier that refuses every certificate; only `ServerIdentity::Pinned { require_chain: false }` can connect with it, and that mode does not check the name | back-channel peers pinned by key alone have no CA; the name of a self-issued certificate proves nothing the pin does not |
| D-074 | 2026-11-04 | A pinned connection clones the client's rustls configuration once and replaces its verifier; the resumption store stays shared | rustls keeps the verifier in the configuration; [est. a few µs and a handful of allocations per pinned connect], paid by back-channel dialers that connect rarely |
| D-075 | 2026-11-04 | A host group with `AlpnPolicy::Required` refuses a ClientHello without ALPN with tls-net's own 7-byte `no_application_protocol` alert, before rustls runs | rustls only refuses an ALPN mismatch, not an absent extension; the same constant-alert approach as D-031 |
| D-076 | 2026-11-04 | Host policy names must be covered by a certificate; a covered name moves into the host's group (a wildcard-covered name gets an exact entry in that group) | a host policy for a name no certificate serves is a configuration mistake; the move keeps the group check of D-032 exact |
| D-077 | 2026-11-04 | Public helpers `spki_sha256(der)` and `certificate_der_from_pem(pem)` | operators compute pins from certificate files; without the helpers they would need another X.509 tool |
| D-078 | 2026-11-04 | `reload_from_pem` and `reload_from_files` work for servers with one certificate and no host policy; others use `ReloadHandle::publish`. The settings of the last publish become the template for later Tier 1 reloads | a Tier 1 reload replaces "the" certificate; with several the intent is ambiguous |
| D-079 | 2026-11-04 | `TlsServer::version()`, `TlsServer::sni_disagreements()`, and `ServerSession::fingerprint()` are public | the reload version and the parser-differential count (idea 0.2) are operator facts; the fingerprint is useful before the handshake completes |
| D-080 | 2026-11-04 | loom runs under `cfg(tls_net_loom)` through a `sync` module that swaps in loom's types for the snapshot, the capacity gate, and the ticket ring; a CI job runs the models | the same code is checked that ships; the cfg name avoids clashing with dependencies that read `cfg(loom)` |
| D-081 | 2026-11-04 | The reload-under-load test in the default suite runs 200 handshakes on four threads with a reload every 2 ms; the 10-minute run at 1,000 handshakes per second moves to the soak job of 0.7 | a 10-minute test does not belong in every CI run; the property (zero failed handshakes) is the same |
| D-082 | 2026-11-04 | T-10 is tested through what tls-net offers: its tickets carry `max_early_data_size` 0, so a resuming client with early data enabled gets no 0-RTT window at all | refusing to open the window is stronger than rejecting early records after they arrive |
| D-083 | 2026-11-04 | `days_remaining` is whole days rounded down while valid and rounded up (negative) after expiry | a report never shows 0 days for a certificate with hours left that has already expired |
| D-084 | 2026-11-04 | `Policy::fips()` exists in every build; building a server or client with it outside a `fips` build returns `FipsUnavailable`. Feature `fips` uses rustls's `default_fips_provider()` with tls-net's suite and group filters on top; `is_fips()` reports rustls's own `fips()` of every built configuration. The gate's full feature list is every feature but `fips`, which a Linux CI job builds and tests alone | configuration code compiles the same in every build and the mistake is caught at build time, not at compile time; a FIPS build needs CMake and Go, which only one job pays for (D-042) |
| D-085 | 2026-11-04 | Only `Ratchet` ticket rings export and import sealed keys; `Ephemeral` and `Derived` return `PolicyInvalid`. The export is the current and previous keys sealed with XChaCha20-Poly1305 under a 32-byte wrap key, with version, mode, and epoch as associated data; an import older than the importer's previous epoch is refused | an ephemeral ring has nothing worth keeping; derived processes already share their root, so an export would only widen where key bytes travel. Cost: 91 bytes on the hand-off channel, one AEAD seal and open per restart |
| D-086 | 2026-11-04 | `TicketKeyRingHandle::rotate_now` ships in 0.5 (planned for 0.7): it replaces the current key with a random one and drops the previous key without changing the epoch; refused for `Derived` rings | an operator who suspects a key leak needs it the day hand-off ships, not two releases later; every outstanding ticket then needs a full handshake, which is the point. Cost: one random key and one write lock |
| D-087 | 2026-11-04 | `HandshakeCapacityReached` is emitted at most once per second per server; `ServerStats::capacity_refusals` counts every refusal | under a flood the event would otherwise cost an observer call per refused connection, which is the work the cap exists to shed. Cost per refusal: one relaxed atomic add, and with an observer one monotonic clock read [est. 20 to 30 ns] and one relaxed load; one compare-exchange per second |
| D-088 | 2026-11-04 | `post_quantum_handshakes` counts every completed handshake whose group is a post-quantum hybrid, resumptions included | a TLS 1.3 resumption with `psk_dhe_ke` runs the key exchange again, so its forward secrecy depends on the group just like a full handshake |
| D-089 | 2026-11-04 | Clients take an observer too and emit `HandshakeCompleted` and `HandshakeFailed`; `ClientBuilder::dangerous_key_log` exists beside the server's, refused with FIPS in the same way (D-040) | outbound connections (smtp-net, fetch-net) need the same failure visibility; debugging a handshake is as often needed on the client side |
| D-090 | 2026-11-04 | `TlsEvent::HandshakeCompleted` reports `peer_certificate` (the design said `client_certificate`) and `HandshakeFailed` has no `alert_from_peer` | one field name serves both sides; whether the alert came from the peer is already in the code (`TLS-0041` is `AlertReceived`) |
| D-091 | 2026-11-04 | `ServerStats` includes `sni_disagreements`; the observer gets SNI only in normalised form and ALPN only as a configured name, so events need no escaping | the D-064 count belongs with the other counters; values from the network never reach an observer unchecked (T-20) |
| D-092 | 2026-11-04 | T-21 is an opt-in statistical test (`TLS_NET_TIMING=1`, release build, Linux CI): the median time to refuse a pin differing in its first byte and one differing in its last byte must be within 25 percent | shared runners are noisy, so the test uses medians of interleaved rounds; it guards against a regression to an early-exit comparison, not against every side channel |
| D-093 | 2026-11-04 | The platform verifier is tested against public sites on all three operating systems in the stable CI matrix (opt-in network step), and the cross-process hand-off test re-runs the test binary as the new process | the exit criteria need both on real systems; re-running the test binary needs no extra crate or helper program |
| D-094 | 2026-11-04 | `deny.toml` allows the OpenSSL license for `aws-lc-fips-sys` only; the security CI job runs `cargo deny` with every feature but `fips` and once more with `fips` | the FIPS module's license is `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`; it is only in the tree when a user enables `fips`, and the OpenSSL license's attribution clause then applies to their distribution (`docs/PLATFORM-NOTES.md` says so). The exception is scoped to that crate so nothing else can bring the license in |
| D-095 | 2026-11-04 | In a `fips` build the policy keeps only the suites and groups rustls reports as FIPS-approved (`fips()`), so every preset still builds: ChaCha20 suites and X25519 drop out, X25519MLKEM768 (ML-KEM first) stays. A suite or group the caller names explicitly that is not approved is an error, as with any unavailable item | the FIPS CI job showed presets naming ChaCha20 failed to build; skipping preset items mirrors how ring builds skip ML-KEM (`groups_explicit`), and filtering on rustls's own flag keeps `is_fips()` true for every configuration a FIPS build makes. Cost: one boolean check per item at configuration build |
| D-096 | 2026-11-06 | `ServerSession` keeps the normalised SNI as `Box<str>` and the peer identity as `Box<PeerIdentity>` (both were inline) | measured: tls-net's addition to an idle server connection fell from 656 to 257 bytes (rustls's own 2,153), under the 512-byte target. Cost: one allocation of the name's length per handshake with SNI and one per mutual-TLS handshake, on the handshake path only; no security effect |
| D-097 | 2026-11-06 | Benchmarks use criterion 0.7 with default features off (no rayon, no plots; its MSRV 1.80 fits 1.85). The SNI table and the configuration cell are timed through a `#[doc(hidden)] pub mod bench` that exists only under `--cfg tls_net_bench` | REPS requires criterion; those two types are crate-private and have no public path that times them alone; the cfg keeps them out of every normal build |
| D-098 | 2026-11-06 | tls-net is compared with rustls's unbuffered connection built from the same rustls configurations (taken through the escape hatch) and driven by the same in-memory driver; a paired bench alternates the two each round and compares medians | identical suites, groups, ticketer, and resolver leave only tls-net's session layer as the difference; alternation keeps a shared machine's drifting load from favouring either side |
| D-099 | 2026-11-06 | The end-to-end comparison is `perf/`, a separate unpublished workspace (tokio, tokio-rustls, tokio-openssl, OpenSSL). The server gets 8 workers on 8 physical cores of one CCD, the load generator the other CCD; net-io runs with one reuse-port listener per worker, no graceful linger, and the per-source cap lifted, so it does what the tokio servers do | tokio and OpenSSL never enter tls-net's tree (deny bans them); with one shared listener net-io 0.6.0 handed most short connections to one worker, and its 2 s linger held closed connections until the connection cap refused new ones. Both were reported to net-io |
| D-100 | 2026-11-06 | Ticket seal makes one allocation (`encrypt_with_aad_into` into a buffer with room for the header) and takes the ring lock once when the ring is current; open takes it once. XChaCha20-Poly1305 through crypt-io stays. Q-3: ring keys stay in tls-net's wiped buffers | measured seal 1.6 µs and open 1.5 µs for a 160-byte session, under the 2 µs target; 1.4 to 1.5 µs of that is crypt-io's cipher (aws-lc's AES-GCM ticketer: 0.7 and 0.3 µs), noted for crypt-io. key-vault access would add 34 to 157 ns per operation to keys that are already wiped and rotated, for no gain in what an attacker with memory access can read |
| D-101 | 2026-11-06 | The SNI table keeps the standard library's keyed hash | measured lookups of 75 to 100 ns among 10,000 names, including normalisation; an unkeyed hash would save tens of nanoseconds per handshake (under 0.01% of one) and give up keyed hashing on lookup keys an attacker chooses |

| D-102 | 2026-11-06 | The handshake slot holds no reference of its own: the capacity gate lives in the server's lifetime state, every snapshot carries an `Arc` to it, and the session gives its slot back through that `Arc` (on release or drop). `ServerReader::accept` stays above its 20 ns target | removes one `Arc` increment and decrement per session: `TlsServer::accept` 67 to 61 ns, `ServerReader::accept` 41 to 37 ns (Windows, loaded machine). What is left is four atomic read-modify-writes, the gate's increment and decrement and the snapshot's reference count, about 6 to 9 ns each on this CPU; 20 ns would need a per-worker gate that no longer bounds handshakes across the server (FR-46), a security loss for 17 ns in a handshake of about 400 µs (0.004%). No security effect from the change itself; the loom model of the gate is updated |
| D-103 | 2026-11-06 | The end-to-end comparison is interleaved (`perf/ab.sh`): every server runs at once on the same 8 cores, the load generator visits each in turn for short windows, and the result is the median rate and the median server CPU time per operation (from `/proc`) over the rounds. CPU profiles come from signal sampling inside the server (`PERF_PROFILE`, pprof in the harness only). This replaces running one stack after another | this machine is shared, and its load moved between about 30 and 500 during 0.6; run one after another, two stacks saw different machines. Interleaving gives every stack the same load, and CPU per operation does not depend on how much CPU the server was given. Section 11.4 of the spec asks for bare-metal Linux and 60-second runs; there is no bare-metal Linux here (WSL2 only), so these numbers are WSL numbers and say so |
| D-104 | 2026-11-06 | `PeerIdentity` is built on the first `info()` after the handshake (a `OnceCell` in each session), no longer at completion. The chain budgets (`max_peer_chain_len`, `max_peer_cert_bytes`) are still checked at completion, and `HandshakeCompleted.peer_certificate` now reports whether the peer sent a certificate | a client always gets the server's certificate, and building its identity (a DER parse, a SHA-256 of the key, copies of the certificate and its names) cost every handshake whether or not the application read it. Measured on Linux (paired, one core): tls-net's client-side overhead over rustls went from 1.6% to 1.4% of a full handshake; the first server step costs 1.6 to 2.5 µs more than rustls's (hello parse, JA4, SNI lookup). Cost: 8 bytes per session for the cell. No security effect: the certificate is the one rustls verified, and the identity is derived from it the same way, only later |
| D-105 | 2026-11-06 | 0.6 stays open until the end-to-end targets are met, as spec section 11.1 requires. Each target counts as met only when both the rate at the harness's client concurrency and the server's CPU time per operation are at least 1.2 times better than tokio-rustls's; memory per idle connection must be at least 30% below tokio-rustls's. Measured on net-io 0.6.1 (WSL2, interleaved, load about 130): bulk is met (1.23x rate, 1.20x CPU per byte); handshakes reach 1.45x the rate but 0.96x the CPU per handshake; idle memory is 25.8 KB per connection against tokio-rustls's 11.4 KB (102 KB after traffic), and the reactor stops at 4,096 TLS connections | the closed-loop rate alone depends on the client generator and the machine's load (0.88x at load 500, 1.45x at load 130), while CPU per operation sets capacity at saturation, so both are required. tls-net's own layer costs 1.4 to 1.9% of a handshake over rustls (paired) and nothing per record beyond the D-035 copy; the remaining gaps sit in net-io's reactor: four sends per connection where two would do, the accept thread's hand-off, and TLS buffers held for a connection's whole life. Each was reported to net-io with measurements and a proposal. If net-io 0.7.0 publishes while 0.6 is open, the seam range widens in a 0.5.x patch release (standing item) |
| D-106 | 2026-11-06 | 0.6.0 is released with the end-to-end handshake-CPU and idle-memory targets open; both become items of the 1.0 gate (ROADMAP 0.9.x and 1.0) and are measured with `perf/` on the net-io release that carries the fixes. This replaces D-105's "0.6 stays open" | everything tls-net owns in 0.6 is met and measured; the two open gaps are inside net-io's reactor, and net-io has scheduled the fixes for its 0.8 (net-io D-180) after its 0.7 hardening review. Holding 0.6 open until then would stall tls-net's 0.7 hardening (fuzzing, soak, attack tests), which does not depend on them. The targets are not dropped: 1.0 cannot ship without them, and docs/PERFORMANCE.md states each open gap with its numbers |
| D-107 | 2026-11-06 | Correction to D-106: net-io returns idle TLS buffers to the pool in its 0.7.0 (net-io D-181), not 0.8. The idle-memory target is re-measured on net-io 0.7.0 when the seam range widens; the handshake-CPU target still waits on net-io 0.8 (net-io D-180) | net-io's answer after the 0.6.0 release |
| D-108 | 2026-11-06 | Fuzz seeds are committed in `fuzz/seeds/`: 18 ClientHellos captured from real clients (Chromium, Windows Schannel through curl and .NET, OpenSSL 3.0 in ten configurations, curl, wget, Python, rustls) and 7 server first flights (OpenSSL TLS 1.3 and 1.2, tls-net, rustls). `fuzz/run-24h.sh` merges them into each target's corpus (behind a chunk-size byte for the server session target), adds the test certificates and system roots for the DER and PEM targets, and runs every target for 24 hours at low priority. The NFR-21 soak is `perf/soak.sh`: mixed full and resumed handshakes on the net-io reactor, a reload every 60 seconds, a 10-minute ephemeral ticket epoch; 6 hours in 0.7, 24 hours in 0.9.x | D-060 asked for browsers, curl, Go, and OpenSSL: Go, Firefox, and Safari are not available on this machine and are added when they are. Captures are of each client's first flight only (the listener closes without answering), so they hold no secrets. The 24-hour soak belongs to the 1.0 gate (NFR-21 says "before 1.0"); 0.7 runs long enough to show any growth trend on this shared machine |
| D-109 | 2026-11-06 | testssl.sh (tag v3.2.4) and tlsfuzzer (commit 5eebc44, tlslite-ng 0.9.0b2) run in `.github/workflows/conformance.yml` against `examples/https_server_blocking` weekly, on demand, and when their files change, never on this machine. testssl.sh fails the job on any HIGH or CRITICAL finding except the test CA's trust findings; tlsfuzzer runs the scripts in `tests/conformance/tlsfuzzer.txt`, each marked `pass` (must pass) or `report` (logged, with the reason it cannot pass) | pinned versions keep results reproducible; running them only on GitHub's runners keeps code fetched from the network off the development machine. The list starts with every applicable script in report mode, and each moves to `pass` once a run shows it passing, so a later regression fails the job |
| D-110 | 2026-11-06 | The ClientHello parser accepts any `{03,XX}` record version (was `0x0301` to `0x0303`) | found by tlsfuzzer: its first record carries `0x0300`, as older stacks do, and tls-net refused every such hello with `BadRecord` and no alert, before rustls saw it. RFC 5246 appendix E.1 requires a server to accept any `{03,XX}` on a ClientHello, RFC 8446 section 5.1 says the field is ignored, and rustls accepts it. No security effect: the record version never selects the protocol version (that is `supported_versions` or `legacy_version`), and rustls has no SSL 3.0 to negotiate. Cost: none (one shift instead of a range check) |
| D-111 | 2026-11-06 | After a failure, `step` calls rustls again only while `CommonState::wants_write()` says records are queued (the alert, and anything queued before it), then fails; it never lets rustls read further input | found by the `session_step_client` fuzz target within two executions (one byte `0xd3` where the server's first flight belongs) and, after a first narrower fix, by both session targets (a ChangeCipherSpec before the ServerHello followed by a malformed record; a hello followed by bad records). rustls 0.23's unbuffered connection hands out queued records before it reads input, but with nothing queued it deframes the next record even after a failure, and a deframing error queues a fatal alert whether one was sent or not. That trips rustls's `debug_assert!(!sent_fatal_alert)` (a panic in any debug build of an application, from bytes a peer sends) and in release builds queues a second alert that was never sent. Server and client sessions were both affected; regression tests `test_t14_*_d111` panic without the fix. Passing an empty input instead is not possible: rustls's handshake deframer keeps positions in the caller's buffer and panics on a shorter one. Cost: one length check per call after a failure |
| D-112 | 2026-11-06 | Miri runs in CI on the library tests that need no crypto provider (`cargo miri test --lib --no-default-features`, isolation off so fixtures can be read): the ClientHello and DER parsers, PEM intake, SNI, fingerprints, tickets, the snapshot, expiry, errors | the providers are C and assembly, which Miri cannot execute; everything tls-net itself parses runs under it. Locally: 66 tests, no undefined behaviour reported, about 18 minutes on a loaded machine |
| D-113 | 2026-11-06 | The tlsfuzzer gate is the set of scripts that pass in full (`pass` in `tests/conformance/tlsfuzzer.txt`); every other script runs as `report` with the reason it cannot pass, in four categories: tls-net's hello strictness (D-014), rustls's alert choices or rules, features rustls does not have, and scripts that assume RSA. Scripts run against an ECDSA and an RSA server, and TLS 1.2 scripts with ECDHE, EMS, and an AEAD suite where they take those options. tls-net keeps refusing unreadable or over-budget hellos without an alert | the per-script server errors show every remaining failure falls in those categories (D-110 was the one tls-net defect, now fixed). RFC 8446 section 6.2 makes sending an alert on an error a SHOULD; tls-net's no-alert refusal of hellos it cannot parse is a deliberate choice (a scanner learns nothing, no rustls state is spent) and stays. A `pass` script that fails fails the job, so a regression in what passes today is caught |
| D-114 | 2026-11-06 | NFR-21 "no memory growth" is judged on live heap bytes, not RSS alone: `tests/leak.rs` counts live bytes with a global allocator and requires 200 rounds of reload, rotation, and full and resumed handshakes to leave the total where it started (under 1 KiB of margin; measured 0). The soak's RSS curve is reported beside it | the 6-hour soak's RSS rose 4.1 MB and then held flat for its last 80 minutes, which is allocator arenas settling across threads, but RSS cannot tell that from a slow leak. Live bytes can, in seconds, in every CI run: an 8-byte leak per handshake fails the test. Cost: one test binary, about 3 seconds in debug |
