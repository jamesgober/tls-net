<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>OPERATIONS</b>
</h1>

> Running a tls-net server: deploying certificates, reloading them, watching expiry, choosing a ticket mode and keeping resumption across restarts, choosing a policy, and deciding from the server's own counters when TLS 1.2 can be turned off. API details are in [`API.md`](./API.md), platform differences in [`PLATFORM-NOTES.md`](./PLATFORM-NOTES.md), the threat model in [`SECURITY.md`](./SECURITY.md).

---

## Certificate deployment

| Item | What tls-net expects |
|---|---|
| Chain file | PEM, end-entity certificate first, then the intermediates in order. Leave the root out: clients have it, and a root in the file is sent in every handshake like the rest of the chain. A chain that does not link up, or a key that does not match the end-entity certificate, is refused at load (`TLS-0010` to `TLS-0020`) |
| Key file | PEM: PKCS#8, PKCS#1 (RSA), or SEC1 (EC). On Unix the file must have no group or other permission bits (`0600` or `0400`), else `KeyFilePermissions` (`TLS-0012`); `ServerBuilder::allow_group_readable_key(true)` lifts the check where a group must read it. Windows has no check yet: restrict the file to the service account |
| Key in a vault | `KeySource::Vault` (feature `key-vault`) keeps the private key out of the process's ordinary memory; signing goes through the vault |
| Key types | ECDSA P-256 and P-384, Ed25519, RSA 2048 bits or more. An ECDSA and an RSA certificate for the same names can be loaded together; tls-net serves whichever the client supports, preferring ECDSA |
| Several sites | The first `certificate` call is the default; later calls add certificates named by their SANs (`certificate_for` names them explicitly). Names are matched exactly, then by one `*.` wildcard label |
| Unknown names | `UnknownName::UseDefault` (the default when a default certificate exists) serves the default; `Refuse` answers with an `unrecognized_name` alert before any certificate is sent, which hides which names the host serves. `Policy::internal()` refuses |

Check a new certificate before it goes live by loading it in a staging build: every check that runs at reload runs at `build`.

---

## Reloading certificates

tls-net runs no timer and installs no signal handler; the application decides when to reload, usually on SIGHUP or when a file watcher sees a renewed certificate.

| Server built with | Reload with |
|---|---|
| One certificate (`server_from_files`, or a builder with one `certificate`) | `TlsServer::reload_from_files(chain, key)` or `reload_from_pem` |
| Several certificates, or settings that change | `TlsServer::reload_handle().publish(builder)`, with a builder made the same way as at startup |

What a reload guarantees:

- The new configuration is built and checked completely before anything changes. On any failure the old configuration stays, the call returns `ReloadRefused` (`TLS-0021`) with the cause as its source, and observers get `ReloadRefused`.
- Handshakes already running finish with the configuration they started with; new handshakes get the new one from the next `accept`.
- Ticket keys and the session cache carry over, so clients keep resuming across a reload. The ticket mode is fixed for the server's lifetime.
- Resumption is bound to each host group's client-authentication rules (mode, anchors, pins, CRLs). A publish that changes them ends resumption for that group: each of its clients makes one full handshake, and a session made under the old rules never resumes under the new ones (D-125). Publishing new CRLs therefore takes effect for resumed clients at once, at the cost of one full handshake each.
- A certificate added with `certificate_for` keeps its names through `reload_from_*`; it does not become the default (D-136).
- `HandshakeLimits::max_in_progress` follows each publish: publish 0 to drain, a higher value to let a spike through (D-132).
- `publish` returns the new version, the number of certificates, and how many of them are already in `Warn` or worse; log all three. An expired or not-yet-valid certificate is refused (`TLS-0017`); one that is only close to expiry loads, since refusing it would leave the older one in place, and `expiring` says so.

Cost: building 100 ECDSA certificates takes about 2 ms; the swap about 25 ns (`docs/PERFORMANCE.md`).

---

## Expiry

`TlsServer::expiry_report(now)` lists every loaded certificate with its days remaining and a state. Call it from the health check; `now` is a parameter so the caller controls time.

| State | When |
|---|---|
| `Ok` | more than both thresholds remain |
| `Warn` | less than the longer of 7 days and a third of the certificate's lifetime, but at most half the lifetime |
| `Critical` | less than the longer of 2 days and a tenth of its lifetime, but at most a fifth of the lifetime |
| `Expired` | at or after `not_after` |

The thresholds scale with the lifetime, so a certificate is `Ok` when it is issued however short its life: a 90-day certificate warns at 30 days and is critical at 9, a 15-day one at 7 days and 2, a 6-hour internal one at 3 hours and 72 minutes. Every entry in `Warn` or worse is also sent to the observer as `CertificateExpiring`. Alert on `Warn`, page on `Critical`. tls-net still serves an expired certificate if nothing replaced it; clients will refuse it.

---

## Session tickets

Resumption saves a full handshake's signature and most of its CPU. Tickets are sealed with XChaCha20-Poly1305 under keys from a ring that advances every `period`. A ticket opens for one `period` after it was issued, the lifetime clients are told; the previous epoch's key is kept so a ticket issued late in an epoch still opens early in the next. Five minutes of clock difference between servers that share keys is allowed.

| Mode | Use when | Restart behaviour |
|---|---|---|
| `Ephemeral { period }` (default, 6 hours) | one process, or restarts are rare | keys are lost at restart; clients make one full handshake again |
| `Ratchet { seed, period }` | restarts hand the listening socket to a new process | the old process exports the ring sealed under a wrap key (`ticket_keys().export_sealed`), the new one imports it (`import_sealed`), and clients keep resuming |
| `Derived { root, period }` | several hosts behind one name should accept each other's tickets | every host derives the same keys from the shared root; anyone with the root can derive every past key, so rotate the root |
| `Off` | resumption is not wanted | stateful session cache only |

Hand-off across a restart with `Ratchet`:

1. The new process starts and receives the listening sockets.
2. The old process calls `export_sealed(&wrap_key)` and sends the bytes over a local socket. The export is sealed and authenticated; tls-net never writes it to disk.
3. The new process calls `import_sealed(&wrap_key, bytes)`. An export more than one epoch older or newer than the new process's clock, from another mode or ticket period, under another wrap key, or altered in any byte is refused (T-24). Keep the period the same across a hand-off; an export from tls-net 0.8 or older is refused by 0.9, so that one restart costs each client a full handshake.
4. The old process drains and exits.

The wrap key must reach both processes outside this path, for example from key-vault or a file readable only by the service account.

If a ticket key may have leaked, call `ticket_keys().rotate_now()`: the current key is replaced and the previous one dropped, so every outstanding ticket needs a full handshake. `tickets(mode, 0)` stops issuing tickets while still accepting valid ones until the ring moves on.

---

## Choosing a policy

| Preset | Versions | TLS 1.2 suites | Groups | For |
|---|---|---|---|---|
| `Policy::compatible()` (server default) | TLS 1.3, TLS 1.2 | ECDHE with AES-GCM or ChaCha20, extended master secret required | X25519MLKEM768, X25519, P-256, P-384 | public listeners |
| `Policy::modern()` | TLS 1.3 | none | same | public listeners whose clients all speak TLS 1.3 |
| `Policy::internal()` | TLS 1.3 | none | X25519MLKEM768 only | service-to-service links; `build` requires `ClientAuth::required` or `pinned` (D-131); no tickets |
| `Policy::fips()` | TLS 1.3, TLS 1.2 | AES-GCM only | P-256, P-384, ML-KEM hybrids from the FIPS module | builds with feature `fips` |

Nothing weaker than these can be configured: rustls has no CBC, static RSA, finite-field DHE, compression, or renegotiation, and tls-net's enums name nothing outside the presets. Start public listeners on `compatible`, then move to `modern` when the counters below say it is safe.

---

## When TLS 1.2 can be turned off

`TlsServer::stats()` reads lock-free counters:

| Counter | Meaning |
|---|---|
| `handshakes_full`, `handshakes_resumed` | completed handshakes |
| `tls12_handshakes` | completed handshakes that used TLS 1.2 |
| `post_quantum_handshakes` | completed handshakes on X25519MLKEM768 |
| `handshakes_failed` | handshakes that ended in an error |
| `capacity_refusals`, `hello_refusals` | sessions refused before rustls: the handshake limit, or a ClientHello that was malformed, over budget, or refused by a hook |
| `tickets_issued`, `tickets_rejected` | tickets sent; tickets that did not open (expired, rotated, or forged) |

The share of TLS 1.2 is `tls12_handshakes / (handshakes_full + handshakes_resumed)`. Sample it over a full business cycle, at least a week, since some clients (monitoring, payment terminals, old embedded devices) connect only at certain times. To find out which clients they are, set an observer and look at `HandshakeCompleted` events with `version: Version::Tls12`. The `server_name` and the `fingerprint` (JA4 by default, `ServerBuilder::fingerprints`) identify a client family without logging anyone's address.

When the share is zero, or every remaining client is known and can be upgraded:

1. Switch the listener to `Policy::modern()` with a `publish`.
2. Watch `handshakes_failed` and the `HandshakeFailed` events. A client that only speaks TLS 1.2 now fails with `TLS-0035` (no common version).
3. If the failures matter, `publish` the `compatible` builder again: the change and its rollback are both reloads, with no restart.

---

## Watching a server

| Signal | Likely cause | Action |
|---|---|---|
| `capacity_refusals` rising, `HandshakeCapacityReached` events | more handshakes at once than `HandshakeLimits::max_in_progress` (default 1,024): a load spike or a handshake flood | if the load is real, raise the limit; for a flood, rate-limit by source in front of tls-net |
| `hello_refusals` rising | scanners, a protocol mismatch (HTTP on the TLS port), or a hook refusing a fingerprint | check `HelloRefused` reasons |
| `tickets_rejected` high after a restart | an `Ephemeral` ring was lost, or a hand-off was skipped | expected once per restart without `Ratchet` |
| `handshakes_failed` with `TLS-0037` to `TLS-0040` on a client | the peer's certificate is invalid, missing, revoked, or matches no pin | not retryable against the same peer |
| `ReloadRefused` | a new certificate failed a load check | the old one is still served; read the source error |

Every error has a stable code (`TLS-0001` onwards), a category, and a suggested action (`TlsError::category`, `TlsError::action`); the table is in [`API.md`](./API.md#error-codes). Events never contain key material or client addresses, and `server_name` and `alpn` are normalised before they are emitted, so they are safe to log as they are (T-20).
