# tls-net - Project Plan

> The design, strategy, and decision record for `tls-net`. A living document: every design decision, idea, or open question about tls-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

---

## 1. Purpose

tls-net gives net-io TLS. It is a thin adapter: rustls implements TLS, and tls-net connects it to net-io's sans-IO TLS seam, loads and reloads certificates, and applies a policy.

## 2. Why we do not write TLS

TLS safety does not come from implementing the protocol; it comes from years of audits, constant-time cryptography, defences against timing and padding side channels, and a long history of attacks already fixed. A home-made TLS would be the weakest link in a stack built around security. rustls is memory-safe Rust, audited, and widely deployed. It is one of the few third-party crates this stack accepts, and tls-net keeps it behind a seam so net-io and everything above stay free of it.

## 3. Scope

| Piece | Detail |
|---|---|
| the adapter | implements net-io's TLS seam over rustls's sans-IO connection API (ciphertext in, plaintext out, and the reverse) |
| server configuration | certificate chains and keys, SNI with several certificates, ALPN (`http/1.1`, `h2` later), optional client certificates |
| client configuration | for smtp-net, outbound HTTP, and service-to-service calls; server verification on by default |
| certificates | PEM loading; hot reload (new handshakes use the new certificate, open connections keep theirs) |
| ClientHello capture | the raw ClientHello bytes (captured by net-io) and the parsed summary (SNI, ALPN, cipher suites, extensions) handed to bouncer-io for fingerprinting |
| policy | minimum TLS 1.2, TLS 1.3 preferred, cipher allowlist, 0-RTT off (replay risk), session tickets with key rotation; shaped by shield-sec |
| OCSP stapling | when the certificate provides a responder |

## 4. Out of scope

- The TLS protocol and cryptography (rustls).
- Automatic certificates (ACME, Let's Encrypt): a separate crate later, since `acme-net` is taken on crates.io (name open).
- Kernel TLS offload: parking lot.

## 5. Threats

| Threat | Defence |
|---|---|
| protocol downgrade | minimum version and cipher policy |
| replay of early data | 0-RTT disabled |
| certificate expiry outage | expiry reported to health and the error core well ahead; hot reload |
| key theft | keys loaded into key-vault, zeroized; file permissions checked at boot (shield-sec) |
| client impersonation (admin plane) | optional client certificates |

## 6. Architecture

```
src/
  lib.rs      crate docs, Tier-1 entry points
  seam.rs     net-io TLS seam implementation
  server.rs   server configuration, SNI resolver, reload
  client.rs   client configuration, roots
  certs.rs    PEM loading, chains, keys
  hello.rs    ClientHello summary for fingerprinting
  policy.rs   TLS policy
  error.rs    TlsError (#[non_exhaustive])
```

## 7. Dependencies

`rustls` (accepted exception) and `net-io`; `key-vault` for keys. Everything else first-party.

## 8. Testing

Handshakes between tls-net server and client over loopback; SNI selection; reload under load with no failed handshakes; policy refusal of TLS 1.0/1.1 and weak ciphers; interop checks against common clients in CI.

## 9. Open decisions

| Id | Question | Recommendation |
|---|---|---|
| O-1 | rustls crypto provider: `aws-lc-rs` (default; C and assembly, needs CMake on Windows) or `ring` (C and assembly, simpler build)? | `ring` for build simplicity; revisit if FIPS is ever required |
| O-2 | Client root certificates: bundled Mozilla roots or the operating system's store? | the operating system's store, with bundled roots as a fallback feature |
| O-3 | Publish `0.1.0` to crates.io to claim the name? | yes |

## 10. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Never write our own TLS; rustls behind a thin adapter | security first; TLS is the accepted third-party exception |
| D-002 | 2026-10-13 | tls-net is separate from net-io | net-io stays dependency-free |
| D-003 | 2026-10-13 | 0-RTT off by default | early data can be replayed |
