# tls-net &mdash; API Reference

> Every public item in `tls-net`, with signatures, behaviour, errors, cost, and examples.
> **Status: `0.8.0`.** This document is the binding API for `0.3.0` to `1.0.0`. Each item shows the version that ships it and its grade (P0 required, P1 expected, P2 high value, P3 after 1.0). Items marked `0.5.0` or earlier are in the current release (0.6.0, 0.7.x, and 0.8.0 added no API). Design and reasons: [`../dev/PLAN.md`](../dev/PLAN.md); schedule: [`../dev/ROADMAP.md`](../dev/ROADMAP.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Overview](#overview)
  - [Tiers](#tiers)
  - [Conventions](#conventions)
  - [Quick start](#quick-start)
- [Tier 1](#tier-1)
  - [`VERSION`](#version)
  - [`server_from_pem`](#server_from_pem)
  - [`server_from_files`](#server_from_files)
  - [`client`](#client)
  - [`client_with_ca_pem`](#client_with_ca_pem)
  - [`TlsServer::accept`](#tlsserveraccept)
  - [`TlsServer::reload_from_pem` / `reload_from_files`](#tlsserverreload_from_pem--reload_from_files)
  - [`TlsServer::expiry_report`](#tlsserverexpiry_report)
  - [`TlsClient::connect`](#tlsclientconnect)
  - [`TlsClient::start_after_plaintext`](#tlsclientstart_after_plaintext)
- [Server configuration](#server-configuration)
  - [`TlsServer`](#tlsserver)
  - [`ServerBuilder`](#serverbuilder)
  - [`KeySource` and `KeyCustody`](#keysource-and-keycustody)
  - [`UnknownName`](#unknownname)
  - [`Alpn` and `AlpnPolicy`](#alpn-and-alpnpolicy)
  - [`HostPolicy`](#hostpolicy)
  - [`ClientAuth`](#clientauth)
  - [`HandshakeLimits`](#handshakelimits)
  - [`HelloLimits`](#hellolimits)
  - [`LoadLimits`](#loadlimits)
- [Policy](#policy)
  - [`Policy`](#policy-1)
  - [`Version`, `CipherSuite`, `Group`, `SignatureScheme`](#version-ciphersuite-group-signaturescheme)
  - [`PolicySummary`](#policysummary)
- [Client configuration](#client-configuration)
  - [`TlsClient`](#tlsclient)
  - [`ClientBuilder`](#clientbuilder)
  - [`TrustAnchors`](#trustanchors)
  - [`ServerIdentity` and `DnsName`](#serveridentity-and-dnsname)
  - [`Crls` and `RevocationPolicy`](#crls-and-revocationpolicy)
- [Reload and expiry](#reload-and-expiry)
  - [`ReloadHandle` and `ReloadOutcome`](#reloadhandle-and-reloadoutcome)
  - [`ExpiryReport`, `CertificateInfo`, `ExpiryState`, `KeyType`](#expiryreport-certificateinfo-expirystate-keytype)
- [Session resumption](#session-resumption)
  - [`TicketMode` and `TicketSeed`](#ticketmode-and-ticketseed)
  - [`TicketKeyRingHandle` and `SealedTicketKeys`](#ticketkeyringhandle-and-sealedticketkeys)
- [Handshake results](#handshake-results)
  - [`HandshakeInfo` and `HandshakeKind`](#handshakeinfo-and-handshakekind)
  - [`PeerIdentity`](#peeridentity)
  - [Exporters and channel binding](#exporters-and-channel-binding)
- [Observation](#observation)
  - [`TlsObserver` and `TlsEvent`](#tlsobserver-and-tlsevent)
  - [`ServerStats`](#serverstats)
  - [`provider_name` and `is_fips`](#provider_name-and-is_fips)
- [Sessions (Tier 3)](#sessions-tier-3)
  - [Buffer constants](#buffer-constants)
  - [`ServerSession` and `ClientSession`](#serversession-and-clientsession)
  - [`Progress`, `Event`, `CloseKind`, `SessionState`](#progress-event-closekind-sessionstate)
  - [Driving a session](#driving-a-session)
  - [`ServerReader`](#serverreader)
- [ClientHello and fingerprints (Tier 3)](#clienthello-and-fingerprints-tier-3)
  - [`HelloParser` and `HelloParse`](#helloparser-and-helloparse)
  - [`ClientHelloView`](#clienthelloview)
  - [`Ja4`, `ja4_raw`, `ja4_original`](#ja4-ja4_raw-ja4_original)
  - [`ja3_string` and `ja3_md5`](#ja3_string-and-ja3_md5)
  - [`Fingerprint` and `FingerprintKinds`](#fingerprint-and-fingerprintkinds)
  - [`HelloHook`, `HelloContext`, `HelloVerdict`, `RefuseReason`](#hellohook-hellocontext-helloverdict-refusereason)
- [net-io seam](#net-io-seam)
- [Escape hatch](#escape-hatch)
- [Errors](#errors)
  - [`TlsError`](#tlserror)
  - [`ErrorCategory` and `Action`](#errorcategory-and-action)
  - [`CertificateProblem`](#certificateproblem)
  - [Error codes](#error-codes)
- [Features](#features)
- [After 1.0](#after-10)
- [Use cases](#use-cases)
  - [Public HTTPS server on net-io](#public-https-server-on-net-io)
  - [SNI with several certificates](#sni-with-several-certificates)
  - [Reload on a signal](#reload-on-a-signal)
  - [Back-channel with mutual TLS](#back-channel-with-mutual-tls)
  - [SMTP submission with STARTTLS](#smtp-submission-with-starttls)
  - [Outbound HTTPS client](#outbound-https-client)
  - [Fingerprint hook](#fingerprint-hook)

---

## Overview

tls-net is a thin adapter over rustls. It never opens or reads a socket: a session takes ciphertext from a buffer the caller owns and writes ciphertext into another buffer the caller owns. With feature `net-io` the server and its sessions plug straight into a net-io server.

### Tiers

| Tier | For | Items |
|---|---|---|
| 1 | about 80% of uses: one call, no builder | `server_from_pem`, `server_from_files`, `client`, `client_with_ca_pem`, `accept`, `connect`, `start_after_plaintext`, `reload_from_*`, `expiry_report` |
| 2 | the next 15%: builders and configuration | `ServerBuilder`, `ClientBuilder`, `Policy`, `ClientAuth`, `HostPolicy`, `TrustAnchors`, `ServerIdentity`, `ReloadHandle`, `TicketMode`, observers |
| 3 | drivers and other libraries | sessions and their events, `ServerReader`, the ClientHello parser, fingerprints, the hook, the net-io seam |

### Conventions

- Every public enum and every struct with public fields is `#[non_exhaustive]`.
- Every constructor and builder method whose result must not be dropped is `#[must_use]`.
- Every public item is re-exported at the crate root: `use tls_net::{TlsServer, Policy};`.
- No rustls type appears in the public API (except behind `rustls-escape-hatch`, outside semver).
- `TlsServer`, `TlsClient`, `ReloadHandle`, `TrustAnchors`, `Policy` are `Clone + Send + Sync`; sessions are `Send`, not `Sync`.
- Fallible calls return `Result<_, TlsError>`; the `# Errors` section of each item lists the codes.
- "Cost" is tls-net's own work unless it says otherwise. [est.] marks an estimate, [target] a goal; both are replaced by measurements at 0.6.

### Quick start

```rust
// Server: certificate files from the operator, default policy, ALPN http/1.1.
let server = tls_net::server_from_files("/etc/tls/site.pem", "/etc/tls/site.key")?;
let mut session = server.accept()?;          // one per accepted connection

// Client: Mozilla roots, server verification always on.
let client = tls_net::client()?;
let mut session = client.connect("example.com")?;
# Ok::<(), tls_net::TlsError>(())
```

With net-io (feature `net-io`), a `TlsServer` is the listener's TLS acceptor:

```rust
let tls = tls_net::server_from_files("/etc/tls/site.pem", "/etc/tls/site.key")?;
let server = net_io::ServerBuilder::new()
    .listener(net_io::ListenerSpec::tcp("0.0.0.0:443").tls(true))
    .tls(tls)
    .handler(|conn| { /* plaintext in, plaintext out */ Ok(()) })
    .gate(net_io::AllowAll)
    .build()?;
```

---

## Tier 1

### `VERSION`

P0, `0.1.0`.

```rust
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

The crate version, from Cargo at build time.

```rust
println!("tls-net {}", tls_net::VERSION);
```

### `server_from_pem`

P0, `0.3.0`.

```rust
pub fn server_from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<TlsServer, TlsError>;
```

A server with `Policy::compatible()`, the chain and key as the default certificate (served for any SNI and for none), ALPN `http/1.1` only, stateless tickets in `TicketMode::Ephemeral { period: 6 h }` (session cache only until `0.4.0`), and default budgets. Every load-time check runs (PLAN 6.5); the certificate's names come from its SANs. The key buffer tls-net decodes is wiped after use.

**Parameters.** `chain_pem`: one or more `CERTIFICATE` blocks, end-entity first. `key_pem`: exactly one `PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY` block.

**Errors.** `TLS-0001` (no provider in this build), `TLS-0011` (input over the size budget), `TLS-0013` to `TLS-0019` (malformed PEM, no or several keys, encrypted key, weak or unsupported key, key mismatch, not valid now, chain too long or misordered).

**Cost.** Dominated by key parsing in the provider [est. under 1 ms for ECDSA P-256, a few ms for RSA-2048]; tls-net's own work under 50 µs for a 3-certificate chain [target]. Build time only.

```rust
let chain = std::fs::read("site.pem")?;
let key = std::fs::read("site.key")?;
let server = tls_net::server_from_pem(&chain, &key)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `server_from_files`

P0, `0.3.0`.

```rust
pub fn server_from_files(chain: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<TlsServer, TlsError>;
```

As `server_from_pem`, reading the files first. The size of each file is checked from its metadata before it is read (chain 1 MiB, key 64 KiB), and the read is bounded by the same limit. On Unix a key file readable by group or others is refused (FR-49).

**Errors.** As `server_from_pem`, plus `TLS-0010` (file cannot be read), `TLS-0012` (key file permissions; the error names the file and the mode).

```rust
let server = tls_net::server_from_files("/etc/tls/site.pem", "/etc/tls/site.key")?;
# Ok::<(), tls_net::TlsError>(())
```

### `client`

P0, `0.3.0`.

```rust
pub fn client() -> Result<TlsClient, TlsError>;
```

A client with the Mozilla roots (feature `webpki-roots`), the client default policy (PLAN 6.9), resumption on (256 sessions), no client certificate, no ALPN. Verification is always on.

**Errors.** `TLS-0001`; `TLS-0002` (`PolicyInvalid { reason: "no trust anchors" }`) without the `webpki-roots` feature.

**Cost.** Builds the root store once [est. under 1 ms]. Keep the client and reuse it; it holds the resumption store.

```rust
let client = tls_net::client()?;
# Ok::<(), tls_net::TlsError>(())
```

### `client_with_ca_pem`

P0, `0.3.0`.

```rust
pub fn client_with_ca_pem(ca_pem: &[u8]) -> Result<TlsClient, TlsError>;
```

A client that trusts only the given CA certificates (a private CA, an internal relay). Mozilla roots are not added.

**Errors.** `TLS-0001`, `TLS-0013` (malformed PEM), `TLS-0014` (`NoCertificate`), `TLS-0015` (a CA certificate rustls-webpki cannot use as an anchor).

```rust
let client = tls_net::client_with_ca_pem(&std::fs::read("internal-ca.pem")?)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `TlsServer::accept`

P0, `0.3.0`.

```rust
impl TlsServer {
    pub fn accept(&self) -> Result<ServerSession, TlsError>;
}
```

A session in state `Hello`, bound to the current configuration snapshot. It takes a handshake capacity slot first (FR-46); the slot is released when the handshake completes, fails, or the session is dropped. The rustls connection is created later, inside `step`, once the SNI is known.

**Errors.** `TLS-0030` (`HandshakeCapacity`) at the limit; the server also emits `HandshakeCapacityReached`, at most once per second.

**Cost.** One atomic increment and one snapshot read [target under 60 ns]; no allocation in tls-net.

```rust
let mut session = server.accept()?;
session.set_tag(connection_id);   // echoed in events
# Ok::<(), tls_net::TlsError>(())
```

### `TlsServer::reload_from_pem` / `reload_from_files`

P0, `0.4.0`.

```rust
impl TlsServer {
    pub fn reload_from_pem(&self, chain_pem: &[u8], key_pem: &[u8]) -> Result<(), TlsError>;
    pub fn reload_from_files(&self, chain: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<(), TlsError>;
}
```

For servers built with Tier 1: replaces the single certificate, keeping policy, ALPN, tickets, and the session cache. Everything is validated before the swap; on failure the old certificate stays and the call returns `ReloadRefused` with the cause as `source()`. Handshakes already running finish with the certificate they started with.

**Errors.** `TLS-0021` (`ReloadRefused`; the source carries the load error); `TLS-0002` when the server was built with `ServerBuilder` and several certificates (use `ReloadHandle::publish`).

**Cost.** As building, plus the swap [target under 1 µs].

```rust
server.reload_from_files("/etc/tls/site.pem", "/etc/tls/site.key")?;
# Ok::<(), tls_net::TlsError>(())
```

### `TlsServer::expiry_report`

P1, `0.4.0`.

```rust
impl TlsServer {
    pub fn expiry_report(&self, now: SystemTime) -> ExpiryReport;
}
```

Every loaded certificate with its days remaining and an `ExpiryState`. Never fails. `now` is a parameter so the caller (the health check) controls time; tls-net runs no timer. Each entry in `Warn` or worse is also sent to the observer as `CertificateExpiring`.

**Cost.** Linear in entries; one `Vec` for the report [target under 1 µs per entry].

```rust
let report = server.expiry_report(std::time::SystemTime::now());
if report.worst >= tls_net::ExpiryState::Warn { /* raise a health warning */ }
```

### `TlsClient::connect`

P0, `0.3.0`.

```rust
impl TlsClient {
    pub fn connect(&self, server_name: &str) -> Result<ClientSession, TlsError>;
}
```

A client session for `server_name`: a DNS name in A-label form or an IP address literal (then no SNI is sent, RFC 6066, and the certificate must carry the IP in a SAN). The name is used for verification exactly as given (FR-27). The first `step` writes the ClientHello.

**Errors.** `TLS-0018` (`InvalidName`: empty, U-label, or not a DNS name or IP).

**Cost.** rustls client connection creation [est. a few µs].

```rust
let mut session = client.connect("smtp.example.com")?;
# Ok::<(), tls_net::TlsError>(())
```

### `TlsClient::start_after_plaintext`

P0, `0.3.0`.

```rust
impl TlsClient {
    pub fn start_after_plaintext(&self, server_name: &str, leftover: &[u8]) -> Result<ClientSession, TlsError>;
}
```

STARTTLS upgrade. `leftover` is every byte the protocol parser received after the end of the upgrade reply (`220` for SMTP). It must be empty; otherwise no session is created and the error is `StartTlsInjection` (the response-injection class: an attacker who can inject plaintext before the handshake would have it treated as if it came over TLS). Implicit TLS (port 465) uses `connect`.

**Errors.** `TLS-0045` (`StartTlsInjection`), `TLS-0018`.

```rust
// After reading "220 2.0.0 Ready to start TLS\r\n" with the SMTP parser:
let mut session = client.start_after_plaintext("smtp.example.com", parser.leftover())?;
# Ok::<(), tls_net::TlsError>(())
```

---

## Server configuration

### `TlsServer`

P0, `0.3.0`.

```rust
#[derive(Clone)]
pub struct TlsServer { /* one Arc */ }

impl TlsServer {
    pub fn builder() -> ServerBuilder;                       // P0 0.3
    pub fn accept(&self) -> Result<ServerSession, TlsError>; // P0 0.3
    pub fn reader(&self) -> ServerReader;                    // P1 0.4
    pub fn reload_handle(&self) -> ReloadHandle;             // P0 0.4
    pub fn reload_from_pem(&self, chain_pem: &[u8], key_pem: &[u8]) -> Result<(), TlsError>;                // P0 0.4
    pub fn reload_from_files(&self, chain: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<(), TlsError>; // P0 0.4
    pub fn expiry_report(&self, now: SystemTime) -> ExpiryReport;  // P1 0.4
    pub fn version(&self) -> u64;                                  // P1 0.4 (D-079)
    pub fn sni_disagreements(&self) -> u64;                        // P2 0.4 (D-079)
    pub fn ticket_keys(&self) -> Option<TicketKeyRingHandle>;      // P2 0.5
    pub fn stats(&self) -> ServerStats;                            // P1 0.5
    pub fn provider_name(&self) -> &'static str;                   // P1 0.3
    pub fn handshakes_in_progress(&self) -> u32;                   // P1 0.3 (D-065)
    pub fn is_fips(&self) -> bool;                                 // P2 0.5
}
```

Cloning is one `Arc` increment; clones share the snapshot, capacity gate, ticket ring, and statistics. `Debug` prints the snapshot version, entry count, and provider, never key material.

### `ServerBuilder`

P0, `0.3.0` (methods marked otherwise ship later).

```rust
#[must_use]
pub struct ServerBuilder { /* private */ }

impl ServerBuilder {
    pub fn certificate(self, chain_pem: &[u8], key: KeySource<'_>) -> Result<Self, TlsError>;                       // P0 0.3
    pub fn certificate_for(self, names: &[&str], chain_pem: &[u8], key: KeySource<'_>) -> Result<Self, TlsError>;  // P0 0.3
    pub fn certificate_der(self, chain_der: &[&[u8]], key: KeySource<'_>) -> Result<Self, TlsError>;               // P1 0.3
    pub fn unknown_name(self, behaviour: UnknownName) -> Self;                                                      // P0 0.3
    pub fn alpn(self, protocols: &[Alpn]) -> Self;                                                                  // P0 0.3
    pub fn policy(self, policy: Policy) -> Self;                                                                    // P0 0.3
    pub fn limits(self, limits: HandshakeLimits) -> Self;                                                           // P0 0.3
    pub fn load_limits(self, limits: LoadLimits) -> Self;                                                           // P1 0.3
    pub fn alpn_policy(self, policy: AlpnPolicy) -> Self;                                                           // P1 0.4
    pub fn hello_limits(self, limits: HelloLimits) -> Self;                                                         // P1 0.4
    pub fn client_auth(self, auth: ClientAuth) -> Self;                                                             // P0 0.4
    pub fn host(self, names: &[&str], policy: HostPolicy) -> Result<Self, TlsError>;                               // P2 0.4
    pub fn tickets(self, mode: TicketMode, per_handshake: u8) -> Self;                                              // P1 0.4
    pub fn session_cache(self, capacity: usize) -> Self;                                                            // P1 0.4
    pub fn ocsp_staple(self, name: &str, staple_der: &[u8]) -> Result<Self, TlsError>;                             // P2 0.4
    pub fn hello_hook(self, hook: Arc<dyn HelloHook>) -> Self;                                                      // P1 0.4
    pub fn fingerprints(self, kinds: FingerprintKinds) -> Self;                                                     // P1 0.4
    pub fn allow_group_readable_key(self, allow: bool) -> Self;                                                     // P2 0.4
    pub fn validity_skew(self, skew: Duration) -> Self;                                                             // P2 0.4
    pub fn observer(self, observer: Arc<dyn TlsObserver>) -> Self;                                                  // P1 0.5
    pub fn hello_sampling(self, one_in: u32) -> Self;                                                               // P1 0.5
    #[cfg(feature = "dangerous-keylog")]
    pub fn dangerous_key_log(self, sink: Arc<dyn KeyLogSink>) -> Self;                                              // P3 0.5
    pub fn build(self) -> Result<TlsServer, TlsError>;                                                              // P0 0.3
}
```

**Behaviour.** Methods that parse return `Result` at once, so an error points at the call that caused it. `certificate` registers the default entry (names from its SANs); the first `certificate` call is the default. `certificate_for` registers an entry for explicit names, each of which must be covered by the certificate. `build` checks the cross-field rules:

- at least one certificate;
- names unique across entries, except one ECDSA plus one RSA entry per name (FR-19);
- `UnknownName::UseDefault` needs a default entry; without one, `Refuse` is used (documented, not an error);
- the policy is consistent with the provider (FR-8);
- ALPN names unique;
- `ClientAuth::required` and `optional` anchors non-empty;
- with feature `net-io`, `max_fragment_size` at least 512 (D-049);
- `dangerous_key_log` together with a FIPS configuration is refused (D-040).

With feature `dangerous-keylog`, `KeyLogSink` receives NSS key log lines (for Wireshark while debugging); never enable it in production:

```rust
#[cfg(feature = "dangerous-keylog")]
pub trait KeyLogSink: Send + Sync + 'static {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
}
```

**Errors.** `TLS-0001` to `TLS-0019`, as raised by each step.

**Cost.** Build time only.

```rust
use tls_net::{Alpn, KeySource, Policy, TlsServer};

let server = TlsServer::builder()
    .certificate(&chain, KeySource::Pem(&key))?
    .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
    .policy(Policy::modern())
    .build()?;
# Ok::<(), tls_net::TlsError>(())
```

### `KeySource` and `KeyCustody`

`Pem`, `Der`, `File` P0 `0.3.0`; `Vault` and `Resident` P1 `0.4.0`; `PerSignature` P2 `0.4.0`.

```rust
#[non_exhaustive]
#[derive(Clone)]
pub enum KeySource<'a> {
    Pem(&'a [u8]),
    Der(&'a [u8]),
    File(&'a Path),
    #[cfg(feature = "key-vault")]
    Vault { vault: Arc<key_vault::KeyVault>, handle: key_vault::KeyHandle, custody: KeyCustody },
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KeyCustody { #[default] Resident, PerSignature }
```

`KeySource` borrows; key bytes are never copied into a long-lived tls-net buffer, and every buffer tls-net decodes into is wiped. `Debug` prints only the variant name and, for files, the path.

- `Pem`: one key block (PKCS#8, PKCS#1 RSA, or SEC1 EC). `ENCRYPTED PRIVATE KEY` is refused with `EncryptedPrivateKey`.
- `Der`: PKCS#8, PKCS#1, or SEC1 DER; the form is detected.
- `File`: size gate, Unix permission check, then as `Pem`.
- `Vault`: the key bytes exist only inside key-vault's scoped callback. The vault must be built with `normalize_with_blake3(false)`; if the bytes do not parse as a key the error is `VaultKeyUnusable` with that help text.
- `KeyCustody::Resident` parses the key once into the provider. `PerSignature` fetches and parses it for every signature [est. 10 to 30 µs for ECDSA P-256, 50 to 150 µs for RSA-2048 per full handshake].

```rust
let builder = TlsServer::builder()
    .certificate(&chain, KeySource::File(Path::new("/etc/tls/site.key")))?;
# Ok::<(), tls_net::TlsError>(())
```

### `UnknownName`

P0, `0.3.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownName { UseDefault, Refuse }
```

What a ClientHello without SNI, or with a name no entry covers, gets. `UseDefault` serves the default entry. `Refuse` writes a fatal `unrecognized_name` alert (the same 7 bytes for every name, T-25) and fails the session with `UnknownServerName` (`TLS-0034`). Default: `UseDefault` when a default entry exists, else `Refuse`. `Policy::internal()` servers default to `Refuse`.

### `Alpn` and `AlpnPolicy`

`Alpn` P0 `0.3.0`; `AlpnPolicy` P1 `0.4.0`.

```rust
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Alpn { /* 1..=255 bytes */ }

impl Alpn {
    pub const HTTP_1_1: Alpn;      // "http/1.1"
    pub const H2: Alpn;            // "h2"
    pub fn new(bytes: &[u8]) -> Result<Alpn, TlsError>;   // 1..=255 bytes, else PolicyInvalid
    pub fn as_bytes(&self) -> &[u8];
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AlpnPolicy { #[default] Optional, Required }
```

The server picks the first protocol in its own list that the client offered (server preference). A client that offered ALPN with no overlap is refused with `no_application_protocol` (`TLS-0036`). With `AlpnPolicy::Required`, a ClientHello without ALPN is refused too (T-15, cross-protocol attacks). A server with no ALPN list ignores the extension.

```rust
let smtp_only = Alpn::new(b"smtp")?;
let back_channel = Alpn::new(b"svc-bc/1")?;
# Ok::<(), tls_net::TlsError>(())
```

### `HostPolicy`

P2, `0.4.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Default)]
pub struct HostPolicy {
    pub alpn: Option<Vec<Alpn>>,
    pub alpn_policy: Option<AlpnPolicy>,
    pub client_auth: Option<ClientAuth>,
    pub policy: Option<Policy>,
}
impl HostPolicy {
    pub fn new() -> Self;
    pub fn alpn(self, protocols: &[Alpn]) -> Self;
    pub fn alpn_policy(self, policy: AlpnPolicy) -> Self;
    pub fn client_auth(self, auth: ClientAuth) -> Self;
    pub fn policy(self, policy: Policy) -> Self;
}
```

Overrides for the named hosts; unset fields inherit the server's. The session picks the host from its own parse of the SNI before the rustls connection exists, and each host group's certificate resolver only resolves names of that group (D-032). A host policy that names a group the provider lacks fails `build`.

```rust
let server = TlsServer::builder()
    .certificate(&wildcard_chain, KeySource::Pem(&wildcard_key))?
    .host(&["admin.example.com"], HostPolicy::new()
        .alpn(&[Alpn::H2])
        .client_auth(ClientAuth::required(admin_ca)))?
    .build()?;
# Ok::<(), tls_net::TlsError>(())
```

### `ClientAuth`

`None` P0 `0.3.0`; `Required` P0, `Optional` and `Pinned` P1, `hide_ca_names` P2, all `0.4.0`.

```rust
#[derive(Clone, Debug, Default)]
pub struct ClientAuth { /* private (D-067) */ }
impl ClientAuth {
    pub fn none() -> Self;
    pub fn optional(anchors: TrustAnchors) -> Self;
    pub fn required(anchors: TrustAnchors) -> Self;
    pub fn pinned(anchors: Option<TrustAnchors>, pins: &[[u8; 32]]) -> Self;
    pub fn with_crls(self, crls: Crls, policy: RevocationPolicy) -> Self;
    pub fn hide_ca_names(self) -> Self;
    pub fn is_required(&self) -> bool;
}
pub fn spki_sha256(certificate_der: &[u8]) -> Result<[u8; 32], TlsError>;          // a pin from a certificate
pub fn certificate_der_from_pem(pem: &[u8]) -> Result<Vec<Vec<u8>>, TlsError>;
```

- `required` verifies the client chain against `anchors` (rustls-webpki), with optional CRLs; no certificate is `PeerCertificateRequired` (`TLS-0038`).
- `optional` also allows a client without a certificate; `HandshakeInfo::peer` is then `None`, and upper layers must treat that as anonymous.
- `pinned` requires the end-entity SPKI SHA-256 to equal one of the pins (constant-time compare). With `anchors`, the chain is verified first. Without anchors, a self-issued certificate is accepted only when its SPKI matches a pin, and the handshake signature and validity window are still verified (T-6b).
- CA name hints are sent by default; `hide_ca_names()` clears them when the CA names are themselves sensitive.

Peer chain budgets come from `HandshakeLimits` (default 5 certificates of at most 16 KiB).

### `HandshakeLimits`

P0, `0.3.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeLimits {
    pub max_in_progress: u32,       // server: 1,024
    pub max_handshake_bytes: u32,   // server 32 KiB, 96 KiB with client auth; client 128 KiB
    pub max_peer_chain_len: u8,     // 5 for client certificates, 10 for server certificates
    pub max_peer_cert_bytes: u32,   // 16 KiB / 32 KiB
}
impl HandshakeLimits {
    pub fn server() -> Self;
    pub fn client() -> Self;
    pub fn max_in_progress(self, n: u32) -> Result<Self, TlsError>;      // 0 refuses every session (allowed, for drains)
    pub fn max_handshake_bytes(self, n: u32) -> Result<Self, TlsError>;  // 4 KiB ..= 1 MiB
    pub fn max_peer_chain_len(self, n: u8) -> Result<Self, TlsError>;    // 1 ..= 16
    pub fn max_peer_cert_bytes(self, n: u32) -> Result<Self, TlsError>;  // 1 KiB ..= 64 KiB
}
impl Default for HandshakeLimits { /* server() */ }
```

When `max_handshake_bytes` is left at its default and the server has client authentication, the 96 KiB default applies. Out-of-range setters return `PolicyInvalid`.

### `HelloLimits`

P1, `0.4.0` (the parser runs with the defaults from `0.3.0`).

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloLimits {
    pub max_hello_bytes: u32,           // 16 KiB
    pub max_records: u8,                // 4
    pub max_ciphers: u16,               // 512
    pub max_extensions: u8,             // 64
    pub max_alpn: u8,                   // 32
    pub max_groups: u8,                 // 64
    pub max_signature_algorithms: u8,   // 64
    pub max_key_shares: u8,             // 8
    pub refuse_malformed: bool,         // true (D-013)
}
impl HelloLimits {
    pub fn new() -> Self;
    pub fn max_hello_bytes(self, n: u32) -> Result<Self, TlsError>;   // 512 ..= 65,535
    pub fn max_records(self, n: u8) -> Result<Self, TlsError>;        // 1 ..= 16
    pub fn max_ciphers(self, n: u16) -> Result<Self, TlsError>;       // 1 ..= 1,024 (D-072)
    pub fn max_extensions(self, n: u8) -> Result<Self, TlsError>;     // 1 ..= 128
    pub fn max_alpn(self, n: u8) -> Result<Self, TlsError>;           // 1 ..= 64
    pub fn max_groups(self, n: u8) -> Result<Self, TlsError>;         // 1 ..= 128
    pub fn max_signature_algorithms(self, n: u8) -> Result<Self, TlsError>; // 1 ..= 128
    pub fn max_key_shares(self, n: u8) -> Result<Self, TlsError>;     // 1 ..= 16
    pub fn refuse_malformed(self, on: bool) -> Self;
}
impl Default for HelloLimits { /* new() */ }
```

`refuse_malformed(false)` lets a hello tls-net cannot parse continue to rustls without a fingerprint (for an emergency only; counted). The stack arrays used for JA4 sorting are sized for the maximum of each range, so raising a limit never allocates.

### `LoadLimits`

P1, `0.3.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadLimits {
    pub max_chain_file_bytes: u32,   // 1 MiB
    pub max_key_file_bytes: u32,     // 64 KiB
    pub max_chain_len: u8,           // 10
    pub check_chain_order: bool,     // true
}
impl LoadLimits { pub fn new() -> Self; /* setters with ranges as above, each returning Result */ }
impl Default for LoadLimits { /* new() */ }
```

Budgets for certificate and key intake (PLAN 6.5, checks 1, 3, and 11).

---

## Policy

### `Policy`

P0, `0.3.0` (methods marked otherwise ship later).

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy { /* private */ }

impl Policy {
    pub fn compatible() -> Policy;                                                    // P0 0.3
    pub fn modern() -> Policy;                                                        // P0 0.3
    pub fn internal() -> Policy;                                                      // P1 0.4
    pub fn fips() -> Policy;                                                          // P2 0.5 (D-084)
    pub fn client_default() -> Policy;                                                // P0 0.3
    pub fn versions(self, versions: &[Version]) -> Result<Policy, TlsError>;          // P1 0.3
    pub fn cipher_suites(self, suites: &[CipherSuite]) -> Result<Policy, TlsError>;   // P1 0.3
    pub fn groups(self, groups: &[Group]) -> Result<Policy, TlsError>;                // P1 0.3
    pub fn require_extended_master_secret(self, on: bool) -> Policy;                 // P1 0.3
    pub fn server_order(self, on: bool) -> Policy;                                    // P1 0.3
    pub fn require_post_quantum(self, on: bool) -> Policy;                            // P1 0.4
    pub fn max_fragment_size(self, bytes: Option<u16>) -> Result<Policy, TlsError>;   // P2 0.4
    pub fn summary(&self) -> PolicySummary;                                           // P2 0.5
}
impl Default for Policy { /* compatible() */ }
```

The presets are in PLAN 6.9. Setters validate their own argument: empty lists, duplicates, and `max_fragment_size` below 32 or above 16,384 are `PolicyInvalid`. Lists keep their order (the server's preference). Cross-checks against the provider happen at `build` (FR-8): no suite for an allowed version, a group the provider lacks, post-quantum required with `ring` (`PostQuantumUnavailable`), a FIPS policy outside FIPS mode (`FipsUnavailable`). `Policy::fips()` exists in every build so configuration code compiles the same way everywhere; only a build with feature `fips` can use it (D-084). It allows TLS 1.3 and TLS 1.2 with AES-GCM suites, P-256 and P-384, and the ML-KEM hybrids the FIPS module offers. In a `fips` build every preset leaves out what rustls does not report as approved (ChaCha20, X25519), so `is_fips()` holds for every configuration; naming such an item explicitly is `PolicyInvalid` (D-095). Nothing weaker than these enums can be named, so a weak configuration cannot be written.

```rust
// TLS 1.3 only, ChaCha20 first for clients without AES hardware.
let policy = tls_net::Policy::modern().cipher_suites(&[
    tls_net::CipherSuite::Tls13ChaCha20Poly1305Sha256,
    tls_net::CipherSuite::Tls13Aes256GcmSha384,
    tls_net::CipherSuite::Tls13Aes128GcmSha256,
])?;
# Ok::<(), tls_net::TlsError>(())
```

### `Version`, `CipherSuite`, `Group`, `SignatureScheme`

P0, `0.3.0`.

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Version { Tls12, Tls13 }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    Tls13Aes256GcmSha384, Tls13Aes128GcmSha256, Tls13ChaCha20Poly1305Sha256,
    EcdheEcdsaAes256GcmSha384, EcdheEcdsaAes128GcmSha256, EcdheEcdsaChaCha20Poly1305Sha256,
    EcdheRsaAes256GcmSha384, EcdheRsaAes128GcmSha256, EcdheRsaChaCha20Poly1305Sha256,
}

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group { X25519MlKem768, Secp256r1MlKem768, X25519, Secp256r1, Secp384r1 }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    EcdsaP256Sha256, EcdsaP384Sha384, Ed25519,
    RsaPssSha256, RsaPssSha384, RsaPssSha512,
    RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512,
}
```

Each has `wire(self) -> u16` (the IANA code point) and `from_wire(u16) -> Option<Self>`, and `CipherSuite::version(self) -> Version`. `Secp256r1MlKem768` exists on aws-lc-rs and is in no preset. RSA PKCS#1 v1.5 schemes are used only for TLS 1.2 and certificate signatures; rustls refuses them for TLS 1.3 handshake signatures (D-033).

### `PolicySummary`

P2, `0.5.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySummary {
    pub versions: Vec<Version>, pub cipher_suites: Vec<CipherSuite>, pub groups: Vec<Group>,
    pub extended_master_secret: bool, pub server_order: bool, pub post_quantum_required: bool,
    pub max_fragment_size: Option<u16>, pub fips: bool,
}
impl fmt::Display for PolicySummary { /* one line for logs and audits */ }
```

---

## Client configuration

### `TlsClient`

P0, `0.3.0`.

```rust
#[derive(Clone)]
pub struct TlsClient { /* one Arc */ }

impl TlsClient {
    pub fn builder() -> ClientBuilder;                                                        // P0 0.3
    pub fn connect(&self, server_name: &str) -> Result<ClientSession, TlsError>;              // P0 0.3
    pub fn connect_to(&self, identity: &ServerIdentity) -> Result<ClientSession, TlsError>;   // P0 0.3
    pub fn start_after_plaintext(&self, server_name: &str, leftover: &[u8]) -> Result<ClientSession, TlsError>; // P0 0.3
    pub fn provider_name(&self) -> &'static str;                                              // P1 0.3
    pub fn is_fips(&self) -> bool;                                                            // P2 0.5
}
```

Clones share the resumption store. Separate `TlsClient` values (built separately) never share tickets (FR-29); that is how a proxy keeps tenants unlinkable to upstreams.

### `ClientBuilder`

P0, `0.3.0` (methods marked otherwise ship later).

```rust
#[must_use]
pub struct ClientBuilder { /* private */ }

impl ClientBuilder {
    pub fn trust(self, anchors: TrustAnchors) -> Self;                                                 // P0 0.3
    pub fn policy(self, policy: Policy) -> Self;                                                       // P0 0.3
    pub fn alpn(self, protocols: &[Alpn]) -> Self;                                                     // P0 0.3
    pub fn resumption(self, sessions: usize) -> Self;                                                  // P1 0.3 (0 disables)
    pub fn send_sni(self, on: bool) -> Self;                                                           // P2 0.3 (default on)
    pub fn limits(self, limits: HandshakeLimits) -> Self;                                              // P0 0.3
    pub fn client_certificate(self, chain_pem: &[u8], key: KeySource<'_>) -> Result<Self, TlsError>;  // P0 0.4
    pub fn crls(self, crls: Crls, policy: RevocationPolicy) -> Self;                                   // P2 0.4
    pub fn observer(self, observer: Arc<dyn TlsObserver>) -> Self;                                     // P1 0.5
    #[cfg(feature = "dangerous-keylog")]
    pub fn dangerous_key_log(self, sink: Arc<dyn KeyLogSink>) -> Self;                                 // P3 0.5
    pub fn build(self) -> Result<TlsClient, TlsError>;                                                 // P0 0.3
}
```

A client without anchors can only connect to `ServerIdentity::Pinned { require_chain: false, .. }`; `connect` and other identities return `PolicyInvalid { reason: "no trust anchors" }`. There is no method that disables verification, in any feature (FR-25). Client certificates get the same load-time checks as server certificates, with `clientAuth` in place of `serverAuth`.

```rust
let client = TlsClient::builder()
    .trust(TrustAnchors::mozilla())
    .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
    .build()?;
# Ok::<(), tls_net::TlsError>(())
```

### `TrustAnchors`

P0, `0.3.0` (`platform` P2 `0.5.0`).

```rust
#[derive(Clone)]
pub struct TrustAnchors { /* private, shared */ }

impl TrustAnchors {
    #[cfg(feature = "webpki-roots")] pub fn mozilla() -> TrustAnchors;      // P0 0.3
    pub fn from_pem(pem: &[u8]) -> Result<TrustAnchors, TlsError>;          // P0 0.3
    pub fn from_der(certs: &[&[u8]]) -> Result<TrustAnchors, TlsError>;     // P1 0.3
    #[cfg(feature = "platform-verifier")] pub fn platform() -> TrustAnchors; // P2 0.5
    pub fn len(&self) -> usize;                                             // P1 0.3
    pub fn is_empty(&self) -> bool;                                         // P1 0.3
}
```

`mozilla()` is the Mozilla root program bundle shipped in webpki-roots: the same roots on every platform. Roots change only with a tls-net release; every release checks for a newer webpki-roots. `platform()` uses the operating system's verifier: Windows and macOS check revocation, Linux uses the system bundle without revocation. `len()` of `platform()` is 0 (the OS holds the roots).

**Errors.** `TLS-0013`, `TLS-0014` (`NoCertificate`), `TLS-0015` (an anchor rustls-webpki cannot use).

### `ServerIdentity` and `DnsName`

`Dns`, `Ip` P0 `0.3.0`; `Pinned` P1 `0.4.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerIdentity {
    Dns(DnsName),
    Ip(IpAddr),
    Pinned { name: DnsName, spki_sha256: Vec<[u8; 32]>, require_chain: bool },
}
impl ServerIdentity { pub fn parse(s: &str) -> Result<ServerIdentity, TlsError>; }   // DNS name or IP literal

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DnsName { /* validated A-label, lowercase, no trailing dot */ }
impl DnsName {
    pub fn new(s: &str) -> Result<DnsName, TlsError>;
    pub fn as_str(&self) -> &str;
}
```

`Pinned { require_chain: true }` verifies the chain against the client's anchors, then requires the end-entity SPKI SHA-256 to equal a pin. `require_chain: false` accepts a self-issued certificate whose SPKI matches a pin, still verifying the handshake signature and the validity window. Pins are compared in constant time. The `name` is sent as SNI and, with `require_chain: true`, checked against the certificate.

**Errors.** `TLS-0018` (`InvalidName`), `TLS-0002` (no pins).

### `Crls` and `RevocationPolicy`

P2, `0.4.0`.

```rust
#[derive(Clone)]
pub struct Crls { /* private */ }
impl Crls {
    pub fn from_pem(pem: &[u8]) -> Result<Crls, TlsError>;
    pub fn from_der(der: &[&[u8]]) -> Result<Crls, TlsError>;
    pub fn len(&self) -> usize;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RevocationPolicy { /* bit set */ }
impl RevocationPolicy {
    pub const END_ENTITY_ONLY: Self;       // check only the leaf
    pub const ALLOW_UNKNOWN_STATUS: Self;  // a certificate no CRL covers passes
    pub const ENFORCE_EXPIRY: Self;        // an expired CRL fails
    pub const fn union(self, other: Self) -> Self;
    pub const fn contains(self, other: Self) -> bool;
}
```

The default (empty set) checks the whole chain, refuses unknown status, and does not enforce CRL expiry (rustls-webpki's defaults). Fetching CRLs is cert-net's job; tls-net only loads them. A revoked peer is `PeerCertificateRevoked` (`TLS-0039`).

---

## Reload and expiry

### `ReloadHandle` and `ReloadOutcome`

P0, `0.4.0`.

```rust
#[derive(Clone)]
pub struct ReloadHandle { /* private */ }
impl ReloadHandle {
    pub fn publish(&self, next: ServerBuilder) -> Result<ReloadOutcome, TlsError>;
    pub fn version(&self) -> u64;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReloadOutcome { pub version: u64, pub entries: usize, pub expiring: usize }
```

`publish` builds and validates `next` completely, carries the ticket key ring and the session cache over (FR-32), swaps, and emits `ReloadApplied`. Handshakes already running finish with the configuration they started with (FR-31). The ticket mode and the observer in `next` are ignored: they belong to the server's lifetime, not to one snapshot. Concurrent `publish` calls are serialised; the later one wins and both return their own outcome.

**Errors.** `TLS-0021` (`ReloadRefused`, the cause as `source()`); the old state stays in force and `ReloadRefused` is emitted.

**Cost.** The build [target under 10 ms for 100 ECDSA certificates] plus the swap [target under 1 µs].

```rust
let handle = server.reload_handle();
let outcome = handle.publish(build_from_config(&new_config)?)?;
log_reload(outcome.version, outcome.entries);
# Ok::<(), tls_net::TlsError>(())
```

### `ExpiryReport`, `CertificateInfo`, `ExpiryState`, `KeyType`

P1, `0.4.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ExpiryReport { pub entries: Vec<CertificateInfo>, pub worst: ExpiryState }

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CertificateInfo {
    pub names: Vec<String>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub days_remaining: i64,          // negative after expiry
    pub state: ExpiryState,
    pub key_type: KeyType,
    pub spki_sha256: [u8; 32],
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExpiryState { Ok, Warn, Critical, Expired }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType { EcdsaP256, EcdsaP384, Ed25519, Rsa { bits: u16 } }
```

Thresholds: `Warn` below max(7 days, lifetime / 3), `Critical` below max(2 days, lifetime / 10), `Expired` at or after `not_after`. Proportional thresholds keep short-lived certificates from warning right after issuance.

---

## Session resumption

### `TicketMode` and `TicketSeed`

P1, `0.4.0` (`Derived` P2).

```rust
#[non_exhaustive]
#[derive(Clone)]
pub enum TicketMode {
    Off,                                              // stateful cache only
    Ephemeral { period: Duration },                   // random keys per process
    Ratchet { seed: TicketSeed, period: Duration },   // forward-only chain; sealed export and import
    Derived { root: TicketSeed, period: Duration },   // shared root for a cluster
}

#[non_exhaustive]
#[derive(Clone)]
pub enum TicketSeed {
    Random,
    Bytes(Arc<Zeroizing<[u8; 32]>>),   // see TicketSeed::from_bytes
    #[cfg(feature = "key-vault")]
    Vault { vault: Arc<key_vault::KeyVault>, handle: key_vault::KeyHandle },
}
impl TicketSeed { pub fn from_bytes(bytes: [u8; 32]) -> TicketSeed; }
```

`period` from 1 minute to 24 hours, else `PolicyInvalid`. Default for Tier 1: `Ephemeral { period: 6 h }`. Recommended for a single host that restarts with a socket hand-off: `Ratchet` (D-010). `Derived` gives clusters shared tickets, and anyone with the root can derive every past key, so rotate the root. `tickets(mode, per_handshake)`: `per_handshake` 0 to 8 (default 2); 0 stops issuing tickets while still accepting valid ones until the ring advances. Ticket format, ring, and costs: PLAN 6.8.

```rust
let server = TlsServer::builder()
    .certificate(&chain, KeySource::Pem(&key))?
    .tickets(TicketMode::Ratchet { seed: TicketSeed::Random, period: Duration::from_secs(6 * 3600) }, 2)
    .build()?;
# Ok::<(), tls_net::TlsError>(())
```

### `TicketKeyRingHandle` and `SealedTicketKeys`

P2, `0.5.0`.

```rust
#[derive(Clone)]
pub struct TicketKeyRingHandle { /* private */ }
impl TicketKeyRingHandle {
    pub fn export_sealed(&self, wrap_key: &[u8; 32]) -> Result<SealedTicketKeys, TlsError>;
    pub fn import_sealed(&self, wrap_key: &[u8; 32], sealed: &[u8]) -> Result<(), TlsError>;
    pub fn epoch(&self) -> u64;
    pub fn rotate_now(&self) -> Result<u64, TlsError>;     // P2 0.5 (D-086)
}

pub struct SealedTicketKeys { /* wipes on drop */ }
impl SealedTicketKeys { pub fn as_bytes(&self) -> &[u8]; }
```

For restarts that hand the listening sockets to a new process: the old process exports, the new one imports, and resumption survives. Only `Ratchet` rings export and import; `Ephemeral` has nothing worth keeping and `Derived` processes already share their root, so both return `PolicyInvalid` (D-085). `TlsServer::ticket_keys()` returns the handle, `None` when tickets are off. `import_sealed` refuses an export older than the importer's epoch minus one, a mode mismatch, a wrong wrap key, and any tampering (T-24). The export is AEAD-sealed, so it is safe on a local socket; tls-net never writes it to disk. `rotate_now` replaces the current key with a random one and drops the previous key, so every outstanding ticket needs a full handshake (for a suspected key compromise); it returns the epoch and is refused for `Derived` rings, whose keys come from the shared root (D-086). Cost: an export is 10 bytes of header plus 65 bytes sealed plus a 16-byte tag; import and export take the ring's write lock once (about a microsecond, an estimate).

---

## Handshake results

### `HandshakeInfo` and `HandshakeKind`

P0, `0.3.0` (`peer` and `fingerprint` P1, `0.4.0`).

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct HandshakeInfo<'s> {
    pub version: Version,
    pub cipher_suite: CipherSuite,
    pub group: Option<Group>,                    // None for a TLS 1.2 resumption
    pub alpn: Option<&'s [u8]>,
    pub server_name: Option<&'s str>,            // normalised SNI (server side) or the name used (client side)
    pub kind: HandshakeKind,
    pub peer: Option<&'s PeerIdentity>,
    pub fingerprint: Option<&'s Fingerprint>,    // server side, when enabled
    pub early_data_accepted: bool,               // always false before early data (P3) exists
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeKind { Full, FullWithHelloRetry, Resumed }
```

`ServerSession::info()` and `ClientSession::info()` return `None` before `HandshakeComplete`. The server's certificate resolver checks rustls's view of the SNI against the session's host group before a certificate is chosen; a disagreement refuses the handshake and is counted (D-064). `peer` and `fingerprint` arrive in `0.4.0`.

### `PeerIdentity`

P1, `0.4.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub spki_sha256: [u8; 32],
    pub end_entity: Arc<[u8]>,       // DER
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub uri_names: Vec<String>,
    pub serial: Vec<u8>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}
```

Built once when the handshake completes, only when the peer sent a certificate (one allocation for its vectors). Map `spki_sha256` (survives re-issuance with the same key) or a URI SAN to a service principal; tls-net does not know principals.

### Exporters and channel binding

P2, with the rustls 0.24 adoption (at the latest `0.9.0`): rustls 0.23's unbuffered connections expose no exporter (D-052).

```rust
impl ServerSession {   // and ClientSession
    pub fn export_keying_material(&self, out: &mut [u8], label: &[u8], context: Option<&[u8]>) -> Result<(), TlsError>;
    pub fn channel_binding(&self) -> Result<[u8; 32], TlsError>;
}
```

`export_keying_material` is RFC 5705 / TLS 1.3 exporters. `channel_binding` is RFC 9266 `tls-exporter` (label `EXPORTER-Channel-Binding`, empty context, 32 bytes); under TLS 1.2 it needs extended master secret (always required by tls-net's policies). Both return `WrongState` before the handshake completes. Cost: one HKDF expand inside rustls.

---

## Observation

### `TlsObserver` and `TlsEvent`

P1, `0.5.0`.

```rust
pub trait TlsObserver: Send + Sync + 'static {
    fn on_event(&self, event: &TlsEvent<'_>) { let _ = event; }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum TlsEvent<'a> {
    HandshakeCompleted { tag: u64, version: Version, cipher_suite: CipherSuite, group: Option<Group>,
        alpn: Option<&'a [u8]>, server_name: Option<&'a str>, kind: HandshakeKind,
        duration: Duration, peer_certificate: bool, fingerprint: Option<&'a Fingerprint> },
    HandshakeFailed { tag: u64, code: u16, alert: Option<u8>, stage: SessionState },
    HelloCaptured { tag: u64, view: &'a ClientHelloView<'a>, fingerprint: &'a Fingerprint },
    HelloRefused { tag: u64, reason: HelloRefusal },
    ReloadApplied { version: u64, entries: usize },
    ReloadRefused { version: u64, code: u16 },
    CertificateExpiring { names: &'a [String], not_after: SystemTime, state: ExpiryState },
    TicketKeyRotated { epoch: u64, reseeded: bool },
    HandshakeCapacityReached { in_progress: u32, limit: u32 },
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloRefusal { Hook(RefuseReason), Malformed, OverBudget, UnknownName, AlpnRequired }
```

One observer per server or client, set at build. Events are delivered synchronously on the thread that caused them; emitting allocates nothing; borrowed fields are valid during the call only. `server_name` is the normalised SNI (letters, digits, `-`, `.`) and `alpn` is one of the configured names, so both are safe to log as they are (T-20). `HandshakeCapacityReached` is emitted at most once per second however many sessions are refused (D-087); the counter in `ServerStats` still counts each one. Clients emit `HandshakeCompleted` and `HandshakeFailed` only. `HelloCaptured` is sampled: `ServerBuilder::hello_sampling(one_in: u32)` (default 0 = off). `duration` is from the first `step` call to completion (tls-net reads `Instant::now()` twice per handshake).

```rust
struct Log;
impl tls_net::TlsObserver for Log {
    fn on_event(&self, event: &tls_net::TlsEvent<'_>) {
        if let tls_net::TlsEvent::HandshakeFailed { code, .. } = event {
            eprintln!("handshake failed: TLS-{code:04}");
        }
    }
}
```

### `ServerStats`

P1, `0.5.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStats {
    pub handshakes_full: u64, pub handshakes_resumed: u64, pub handshakes_failed: u64,
    pub in_progress: u32, pub capacity_refusals: u64, pub hello_refusals: u64,
    pub tickets_issued: u64, pub tickets_rejected: u64, pub snapshot_version: u64,
    pub tls12_handshakes: u64, pub post_quantum_handshakes: u64, pub sni_disagreements: u64,
}
```

Relaxed atomic counters, padded so counter groups sit on separate cache lines; `stats()` reads them without locking. `tls12_handshakes` and `post_quantum_handshakes` tell an operator when TLS 1.2 can be turned off and how many clients use X25519MLKEM768. A TLS 1.3 resumption still runs a key exchange, so it counts as post-quantum when the group is a hybrid (D-088). `sni_disagreements` counts D-064 refusals. Cost of the counters: one relaxed atomic add per event, no lock; an observer call is one virtual call with nothing allocated.

### `provider_name` and `is_fips`

`provider_name` P1 `0.3.0`; `is_fips` P2 `0.5.0`.

```rust
impl TlsServer { pub fn provider_name(&self) -> &'static str; pub fn is_fips(&self) -> bool; }
impl TlsClient { pub fn provider_name(&self) -> &'static str; pub fn is_fips(&self) -> bool; }
pub fn default_provider_name() -> Option<&'static str>;      // P1 0.3: the provider this build uses
```

`provider_name()` is `"aws-lc-rs"`, `"aws-lc-rs (FIPS)"`, or `"ring"`. `default_provider_name()` is `None` in a build with no provider. Installing a process-default rustls provider elsewhere never changes these (T-28).

---

## Sessions (Tier 3)

### Buffer constants

P0, `0.3.0`.

```rust
pub const MAX_RECORD_PAYLOAD: usize = 16_384;   // TLS plaintext record maximum
pub const OUTGOING_MIN: usize = 18_437;         // one maximum wire record (rustls MAX_WIRE_SIZE)
pub const INCOMING_MIN: usize = 18_437;         // one maximum wire record
```

### `ServerSession` and `ClientSession`

P0, `0.3.0`.

```rust
pub struct ServerSession { /* private */ }   // Send, not Sync
pub struct ClientSession { /* private */ }   // Send, not Sync

impl ServerSession {   // ClientSession has the same methods
    pub fn step<'i>(&mut self, input: &'i mut [u8], output: &mut [u8]) -> Result<Progress<'i>, TlsError>;
    pub fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError>;
    pub fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError>;
    pub fn on_eof(&mut self) -> CloseKind;
    pub fn state(&self) -> SessionState;
    pub fn info(&self) -> Option<HandshakeInfo<'_>>;
    pub fn input_capacity_required(&self) -> usize;
    pub fn set_tag(&mut self, tag: u64);        // opaque id echoed in events (for example a connection id)
    pub fn error_code(&self) -> Option<u16>;    // the code that failed the session, once Failed
    pub fn alert(&self) -> Option<u8>;          // the TLS alert sent or received when it failed (D-061)
}
impl ServerSession {
    pub fn fingerprint(&self) -> Option<&Fingerprint>;   // P1 0.4, once the ClientHello is parsed (D-079)
}
```

**`step`.** `input` holds ciphertext received and not yet consumed; `output` is free space for records to send.

1. In `Failed`: `Err(SessionFailed)`; in `Closed`: `Ok(Closed)`; nothing is touched.
2. If `output.len() < OUTGOING_MIN`: `Ok(OutputFull)` with nothing consumed, before any rustls call (FR-3).
3. Server in `Hello`: parse the ClientHello from `input`. `Incomplete`: `NeedInput`, nothing consumed. Malformed or over budget: the session fails (`TLS-0031` / `TLS-0032`). Complete: hook, host group, then the rustls connection is created and rustls reads the same bytes (the parser consumes nothing).
4. Run rustls until a state that needs the caller. At most one `Data` per call, so the borrow of `input` stays simple; call again for more.
5. `consumed` counts every byte rustls discarded; the handshake byte budget is checked before returning.

A failure with an alert to send (rustls's alert, or tls-net's `unrecognized_name`) is reported as `Ok(Transmit)` with the alert in `output` and the session already `Failed`; the next call returns the error. A driver that sends every `Transmit` and calls `step` again therefore sends the alert without knowing about it. A hook refusal sends nothing (D-014).

**`encrypt`.** Only in `Established` or `HalfClosed`. Turns all of `plaintext` into records in `output`, or writes nothing and returns `OutputFull` (the error's `required()` says how many bytes are needed). Empty plaintext writes nothing and returns `Ok(0)`. One TLS 1.3 record adds 22 bytes (5 header, 1 content type, 16 tag) to at most `MAX_RECORD_PAYLOAD` bytes of plaintext (smaller with `max_fragment_size`).

**`close`.** Writes `close_notify`; afterwards `encrypt` is `WrongState`, and the session is `Closing` (or `Closed` if the peer already closed). A second `close` writes nothing and returns `Ok(0)`.

**`on_eof`.** The transport ended. `Clean` if `close_notify` was received; otherwise `Unclean`, and the session becomes `Failed` with `UncleanClose` (`TLS-0043`, T-17).

**`input_capacity_required`.** `INCOMING_MIN` once established; during the handshake, `max(INCOMING_MIN, held + 1)` where `held` is what rustls kept unconsumed at the last `NeedInput` (a handshake message being assembled in place, D-029).

**Errors.** Every code from `TLS-0030` to `TLS-0050` can end a session; see [Error codes](#error-codes).

**Cost.** tls-net's own work per record under 100 ns [target], plus the plaintext copy of D-035 [est. 0.3 to 1 µs per 16 KiB record]; no allocation in tls-net code once established (NFR-1). rustls 0.23 allocates one `Vec` per record each way.

### `Progress`, `Event`, `CloseKind`, `SessionState`

P0, `0.3.0`.

```rust
#[must_use]
#[non_exhaustive]
#[derive(Debug)]
pub struct Progress<'i> { pub consumed: usize, pub written: usize, pub event: Event<'i> }

#[non_exhaustive]
#[derive(Debug)]
pub enum Event<'i> {
    NeedInput,          // read more ciphertext, append it after the unconsumed bytes, call step again
    Transmit,           // `written` bytes at the start of `output` must be sent, all of them
    HandshakeComplete,  // once; info() is now Some
    Data(&'i [u8]),     // plaintext, a slice of `input`, valid while Progress lives; call step again
    EarlyData(&'i [u8]),// P3, only with dangerous_enable_early_data
    OutputFull,         // fewer than OUTGOING_MIN bytes free in `output`; flush and call again
    PeerClosed,         // close_notify received; the plaintext stream ended cleanly
    Closed,             // both directions closed
}

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseKind { Clean, Unclean }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState { Hello, Handshake, Established, HalfClosed, Closing, Closed, Failed }
```

`written` can be non-zero with any event (for example a handshake flight and `HandshakeComplete` in one call); send `written` bytes whenever it is non-zero. `consumed` bytes must be removed from the front of `input` before the next `step`, after the `Data` slice has been used.

### Driving a session

The loop a blocking driver runs (net-io does the same inside its adapter):

```rust
use std::io::{Read, Write};
use tls_net::{Event, OUTGOING_MIN};

fn serve(mut sock: std::net::TcpStream, mut session: tls_net::ServerSession) -> Result<(), Box<dyn std::error::Error>> {
    let mut inbuf = vec![0u8; 64 * 1024];
    let mut filled = 0;
    let mut outbuf = vec![0u8; 64 * 1024];
    loop {
        let p = session.step(&mut inbuf[..filled], &mut outbuf)?;
        let (consumed, written) = (p.consumed, p.written);
        match p.event {
            Event::Data(plain) => handle_plaintext(plain),   // use it before compacting
            Event::NeedInput => {}
            Event::PeerClosed | Event::Closed => break,
            _ => {}
        }
        if written > 0 { sock.write_all(&outbuf[..written])?; }
        inbuf.copy_within(consumed..filled, 0);
        filled -= consumed;
        if matches!(session.state(), tls_net::SessionState::Closed) { break; }
        if written == 0 && consumed == 0 {
            if filled == inbuf.len() { inbuf.resize(session.input_capacity_required().max(filled + 1), 0); }
            let n = sock.read(&mut inbuf[filled..])?;
            if n == 0 { let _ = session.on_eof(); break; }
            filled += n;
        }
    }
    Ok(())
}
# fn handle_plaintext(_: &[u8]) {}
```

### `ServerReader`

P1, `0.4.0`.

```rust
impl TlsServer { pub fn reader(&self) -> ServerReader; }
pub struct ServerReader { /* private */ }   // Send, not Sync
impl ServerReader { pub fn accept(&mut self) -> Result<ServerSession, TlsError>; }
```

A per-worker handle: one atomic load per `accept`, and a lock only after a reload [target under 20 ns]. Semantics as `TlsServer::accept`.

---

## ClientHello and fingerprints (Tier 3)

### `HelloParser` and `HelloParse`

P1, `0.4.0` (used inside server sessions from `0.3.0`).

```rust
pub struct HelloParser;
impl HelloParser {
    pub fn parse<'a>(input: &'a [u8], limits: &HelloLimits) -> Result<HelloParse<'a>, TlsError>;
}
#[non_exhaustive]
#[derive(Debug)]
pub enum HelloParse<'a> {
    Incomplete { needed: usize },                          // total bytes needed, exact after 9 bytes
    Complete { view: ClientHelloView<'a>, length: usize }, // `length` = bytes of the records holding the hello
}
```

Bounded, zero-copy, linear in the hello length; every budget checked before the work it guards (PLAN 6.10). Errors: `NotTls`, `BadRecord`, `HelloMalformed`, `DuplicateExtension` (`TLS-0031`); `HelloTooLarge`, `HelloTooFragmented`, `HelloOverBudget { what }` (`TLS-0032`).

**Cost.** Under 1 µs for a 2 KiB hello [target]; no allocation.

```rust
match tls_net::HelloParser::parse(&buf[..filled], &tls_net::HelloLimits::default())? {
    tls_net::HelloParse::Incomplete { needed } => { /* read until `needed` bytes */ }
    tls_net::HelloParse::Complete { view, .. } => println!("sni {:?}", view.server_name()),
    _ => {}
}
# Ok::<(), tls_net::TlsError>(())
```

### `ClientHelloView`

P1, `0.4.0`.

```rust
#[derive(Clone, Copy)]
pub struct ClientHelloView<'a> { /* borrowed ranges */ }
impl<'a> ClientHelloView<'a> {
    pub fn record_version(&self) -> u16;
    pub fn legacy_version(&self) -> u16;
    pub fn supported_versions(&self) -> impl Iterator<Item = u16> + 'a;
    pub fn cipher_suites(&self) -> impl Iterator<Item = u16> + 'a;          // wire order, GREASE included
    pub fn extension_types(&self) -> impl Iterator<Item = u16> + 'a;        // wire order, across records
    pub fn extension_count(&self) -> usize;
    pub fn extensions(&self) -> impl Iterator<Item = (u16, &'a [u8])> + 'a; // wire order; data empty if it crosses a record
    pub fn server_name(&self) -> Option<&'a str>;                           // validated LDH ASCII, as sent, one record
    pub fn has_server_name(&self) -> bool;
    pub fn normalized_server_name(&self) -> Option<NormalizedName>;         // FR-17, across records
    pub fn server_name_raw(&self) -> Option<&'a [u8]>;                      // P2: bytes as sent, for forensics
    pub fn alpn(&self) -> impl Iterator<Item = &'a [u8]> + 'a;              // names inside one record
    pub fn has_alpn(&self) -> bool;
    pub fn groups(&self) -> impl Iterator<Item = u16> + 'a;
    pub fn point_formats(&self) -> impl Iterator<Item = u8> + 'a;
    pub fn signature_algorithms(&self) -> impl Iterator<Item = u16> + 'a;
    pub fn key_share_groups(&self) -> impl Iterator<Item = u16> + 'a;
    pub fn has_pre_shared_key(&self) -> bool;
    pub fn has_early_data(&self) -> bool;
    pub fn has_encrypted_client_hello(&self) -> bool;
    pub fn session_id_len(&self) -> u8;
    pub fn padding_len(&self) -> Option<u16>;
    pub fn raw(&self) -> Option<&'a [u8]>;   // the handshake message, when it sits in one record
}
pub fn is_grease(value: u16) -> bool;        // RFC 8701: 0x0A0A, 0x1A1A, ... 0xFAFA
pub fn normalize_server_name(name: &str) -> Option<NormalizedName>;   // the FR-17 rule, also used on rustls's view
```

`Debug` prints the counts and the sanitised SNI and ALPN, never raw bytes. `server_name()` is `None` for an IP literal, an invalid name, or a name with any byte outside letters, digits, `-`, and `.` (T-20).

### `Ja4`, `ja4_raw`, `ja4_original`

`Ja4` P1, the others P2; all `0.4.0`.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ja4([u8; 36]);
impl Ja4 {
    pub fn compute(view: &ClientHelloView<'_>) -> Ja4;
    pub fn as_str(&self) -> &str;
}
impl fmt::Display for Ja4 { /* as_str */ }
pub fn ja4_raw(view: &ClientHelloView<'_>, out: &mut String);       // JA4_r
pub fn ja4_original(view: &ClientHelloView<'_>, out: &mut String);  // JA4_ro
```

Follows the FoxIO JA4 definition (PLAN 6.10). `compute` never fails: missing pieces have defined encodings. Deterministic across platforms (NFR-15) and invariant under cipher and extension permutation.

**Cost.** Under 600 ns [target]: two SHA-256 over short strings and two sorts in stack arrays.

```rust
let ja4 = tls_net::Ja4::compute(&view);
assert_eq!(ja4.as_str().len(), 36);
```

### `ja3_string` and `ja3_md5`

`ja3_string` P2 `0.4.0`; `ja3_md5` P3 `0.5.0` behind `ja3-md5`.

```rust
pub fn ja3_string(view: &ClientHelloView<'_>, out: &mut String);
#[cfg(feature = "ja3-md5")] pub fn ja3_md5(view: &ClientHelloView<'_>) -> [u8; 32];   // lowercase hex
```

The Salesforce JA3 string (decimal values, `-` joined, GREASE ignored). JA3 changes on most Chrome connections (Chrome permutes extensions); it is kept for existing intelligence feeds. MD5 here is a label, not security; the in-house MD5 is tested against RFC 1321.

### `Fingerprint` and `FingerprintKinds`

P1, `0.4.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Fingerprint { pub ja4: Option<Ja4>, pub ja3_md5: Option<[u8; 32]> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FingerprintKinds(u8);
impl FingerprintKinds {
    pub const NONE: Self;
    pub const JA4: Self;                                  // default
    pub const JA3_MD5: Self;                              // needs feature ja3-md5
    pub const fn union(self, other: Self) -> Self;
    pub const fn contains(self, other: Self) -> bool;
}
```

`ServerBuilder::fingerprints(kinds)` chooses what is computed for every hello; `NONE` skips the work when nothing consumes it.

### `HelloHook`, `HelloContext`, `HelloVerdict`, `RefuseReason`

P1, `0.4.0`.

```rust
pub trait HelloHook: Send + Sync + 'static {
    fn on_client_hello(&self, ctx: &HelloContext<'_>) -> HelloVerdict;
}

#[non_exhaustive]
pub struct HelloContext<'a> {
    pub view: &'a ClientHelloView<'a>,
    pub fingerprint: &'a Fingerprint,
    pub server_name: Option<&'a str>,   // normalised
    pub tag: u64,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloVerdict { Continue, Refuse(RefuseReason) }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefuseReason { Banned, Fingerprint, Policy, Other(&'static str) }
```

Runs synchronously inside `step`, after the parse and before the rustls connection exists. It must be a lookup, never I/O (bouncer-io budgets one lookup). `Refuse` fails the session with `Refused(reason)` (`TLS-0033`), sends no alert (D-014), and maps to net-io's `TlsFailure::HelloRefused` (closed with `CloseReason::HelloRefused`).

---

## net-io seam

P0, `0.3.0`, feature `net-io`.

```rust
impl net_io::TlsAcceptor for TlsServer { type Session = ServerSession; }   // session() = accept()
impl net_io::TlsSession for ServerSession { /* step, encrypt, close, on_transport_closed, info, input_capacity_required */ }
impl net_io::TlsSession for ClientSession { /* same */ }
impl From<&TlsError> for net_io::TlsError { /* kind, code, alert */ }
```

Type conversions only: no extra state, no allocation. Works with net-io `>= 0.7, < 0.8` (D-036, D-122; tls-net 0.7.x accepts `>= 0.4`). Mapping:

| tls-net | net-io |
|---|---|
| `Event::NeedInput`, `Transmit`, `HandshakeComplete`, `Data`, `OutputFull`, `PeerClosed`, `Closed` | the `TlsEvent` of the same name |
| `on_eof()` | `on_transport_closed()` |
| `info()` | `TlsInfo::new(sni, alpn, version code, suite code)` (ALPN over 32 bytes is reported as absent), with `with_peer_spki_sha256` when the peer sent a certificate tls-net verified (0.8.0) |
| `Refused` | `TlsFailure::HelloRefused` |
| `HandshakeCapacity` | `TlsFailure::Capacity` |
| `OutputFull` | `TlsFailure::OutputFull` |
| `WrongState`, `SessionFailed` | `TlsFailure::State` |
| `PeerMisbehaved`, `DecryptFailed`, `HelloMalformed`, `NotTls`, `BadRecord`, `DuplicateExtension`, budgets | `TlsFailure::Protocol` |
| everything else | `TlsFailure::Handshake` |

`net_io::TlsError::code` is `TlsError::code()`; `alert` is the alert sent or received.

---

## Escape hatch

P2, `0.5.0`, feature `rustls-escape-hatch`. **Outside semver**: may change in any release.

```rust
impl TlsServer { pub fn as_rustls_configs(&self) -> Vec<Arc<rustls::ServerConfig>>; }
impl TlsClient { pub fn as_rustls_config(&self) -> Arc<rustls::ClientConfig>; }
```

Read-only access to the built configurations, for debugging and for wiring rustls-only integrations.

---

## Errors

### `TlsError`

P0, `0.3.0`.

```rust
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsError { /* one variant per row of the table below */ }

impl TlsError {
    pub fn code(&self) -> u16;                       // TLS-nnnn
    pub fn category(&self) -> ErrorCategory;
    pub fn action(&self) -> Action;
    pub fn public_message(&self) -> &'static str;    // safe to show a remote client or end user
    pub fn required(&self) -> Option<usize>;         // OutputFull only: bytes needed
}
impl fmt::Display for TlsError { /* "TLS-0016: private key does not match the certificate" */ }
impl std::error::Error for TlsError { /* source() for ReloadRefused */ }
```

`Display` is the operator message: it may name a file, a configured name, or a number, never key material and never bytes received from the network (SNI in a message is sanitised). `public_message()` is what a remote party may see. `Debug` prints the same safe fields.

### `ErrorCategory` and `Action`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    InvalidArgument, FailedPrecondition, NotFound, PermissionDenied, Unauthenticated,
    ResourceExhausted, Unavailable, Aborted, Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action { None, FixConfig, Retry, RetryIdempotent, RetryWithoutEarlyData, Operator }
```

`category()` gives the retry rule of the error suite (for example `ResourceExhausted` may be retried later, `InvalidArgument` never). When the error-suite definitions crate is published, a minor release implements its trait as well.

### `CertificateProblem`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateProblem {
    Expired, NotYetValid, UnknownIssuer, BadSignature, NameMismatch, Revoked,
    UnhandledCriticalExtension, InvalidPurpose, Other,
}
```

Carried by `PeerCertificateInvalid`.

### Error codes

| Code | Variant | Category | Action | Public message |
|---|---|---|---|---|
| TLS-0000 | `Other` | Internal | Operator | Secure connection failed |
| TLS-0001 | `NoProvider` | FailedPrecondition | FixConfig | TLS is not available in this build |
| TLS-0002 | `PolicyInvalid { reason }` | InvalidArgument | FixConfig | TLS configuration is invalid |
| TLS-0003 | `PostQuantumUnavailable` | FailedPrecondition | FixConfig | TLS configuration is invalid |
| TLS-0004 | `FipsUnavailable` | FailedPrecondition | FixConfig | TLS configuration is invalid |
| TLS-0010 | `Io { path, kind }` | Unavailable | Retry | Certificate files could not be read |
| TLS-0011 | `FileTooLarge { path, limit }` | InvalidArgument | FixConfig | Certificate files could not be read |
| TLS-0012 | `KeyFilePermissions { path, mode }` | FailedPrecondition | FixConfig | Certificate files could not be read |
| TLS-0013 | `PemInvalid { what }` | InvalidArgument | FixConfig | Certificate or key is malformed |
| TLS-0014 | `NoCertificate`, `NoPrivateKey`, `MultiplePrivateKeys`, `EncryptedPrivateKey` | InvalidArgument | FixConfig | Certificate or key is malformed |
| TLS-0015 | `UnsupportedKeyType`, `WeakKey { bits }`, `WeakSignatureAlgorithm`, `BadAnchor` | InvalidArgument | FixConfig | Certificate or key is not allowed |
| TLS-0016 | `KeyMismatch` | InvalidArgument | FixConfig | Certificate or key is not allowed |
| TLS-0017 | `CertificateExpired { not_after }`, `CertificateNotYetValid { not_before }`, `WrongPurpose` | FailedPrecondition | FixConfig | Certificate is not valid now |
| TLS-0018 | `NameNotCovered { name }`, `DuplicateName { name }`, `InvalidName { name }` | InvalidArgument | FixConfig | Certificate does not cover the configured names |
| TLS-0019 | `ChainTooLong { len, limit }`, `ChainOrder { position }` | InvalidArgument | FixConfig | Certificate does not cover the configured names |
| TLS-0020 | `VaultKeyUnusable`, `Vault { kind }` | FailedPrecondition | FixConfig | Key store error |
| TLS-0021 | `ReloadRefused { source }` | FailedPrecondition | FixConfig | New certificates were refused; the old ones are still in use |
| TLS-0030 | `HandshakeCapacity` | ResourceExhausted | Retry | Server is busy |
| TLS-0031 | `HelloMalformed`, `NotTls`, `BadRecord`, `DuplicateExtension` | InvalidArgument | None | Secure connection failed |
| TLS-0032 | `HelloTooLarge`, `HelloTooFragmented`, `HelloOverBudget { what }`, `HandshakeTooLarge`, `PeerChainTooLarge` | ResourceExhausted | None | Secure connection failed |
| TLS-0033 | `Refused(RefuseReason)` | PermissionDenied | None | Secure connection failed |
| TLS-0034 | `UnknownServerName` | NotFound | None | Secure connection failed |
| TLS-0035 | `NoCommonVersion`, `NoCommonCipherSuite`, `NoCommonGroup`, `NoCommonSignatureScheme`, `ExtendedMasterSecretRequired` | FailedPrecondition | None | Client and server have no TLS settings in common |
| TLS-0036 | `NoApplicationProtocol` | FailedPrecondition | None | Client and server have no TLS settings in common |
| TLS-0037 | `PeerCertificateInvalid(CertificateProblem)` | Unauthenticated | None | Certificate was not accepted |
| TLS-0038 | `PeerCertificateRequired` | Unauthenticated | None | Certificate was not accepted |
| TLS-0039 | `PeerCertificateRevoked` | Unauthenticated | None | Certificate was not accepted |
| TLS-0040 | `PinMismatch` | Unauthenticated | Operator | Certificate was not accepted |
| TLS-0041 | `AlertReceived { alert }` | Aborted | Retry | Secure connection failed |
| TLS-0042 | `DecryptFailed`, `PeerMisbehaved` | Aborted | None | Secure connection failed |
| TLS-0043 | `UncleanClose` | Unavailable | RetryIdempotent | Connection closed early |
| TLS-0044 | `KeyUsageExhausted` | Aborted | Retry | Connection closed early |
| TLS-0045 | `StartTlsInjection` | PermissionDenied | Operator | Mail server sent unexpected data |
| TLS-0046 | `EarlyDataRefused` | FailedPrecondition | RetryWithoutEarlyData | Secure connection failed |
| TLS-0050 | `OutputFull { required }`, `WrongState`, `SessionFailed` | FailedPrecondition | None | Secure connection failed |

No variant holds key bytes. `Debug` and `Display` of every variant are scanned in the tests for key material (T-8).

---

## Features

| Feature | Default | Effect |
|---|---|---|
| `aws-lc` | on | aws-lc-rs provider with X25519MLKEM768 |
| `ring` | off | ring provider (no post-quantum groups); with `aws-lc` also on, aws-lc-rs is used |
| `fips` | off | FIPS 140-3 mode over aws-lc-rs (`0.5.0`; needs CMake and Go to build) |
| `prebuilt-nasm` | off | Windows x86-64 without NASM: prebuilt NASM objects for aws-lc-sys |
| `webpki-roots` | on | `TrustAnchors::mozilla()` |
| `platform-verifier` | off | `TrustAnchors::platform()` |
| `key-vault` | on | `KeySource::Vault`, `TicketSeed::Vault` |
| `net-io` | on from `0.3.0` | the net-io seam |
| `ja3-md5` | off | `ja3_md5`, `FingerprintKinds::JA3_MD5` |
| `rustls-escape-hatch` | off | raw rustls configurations, outside semver |
| `dangerous-keylog` | off | `ServerBuilder::dangerous_key_log`; never in production; refused with FIPS |

Without a provider feature every constructor returns `NoProvider` (`TLS-0001`).

---

## After 1.0

Designed for, not scheduled before 1.0 (P3):

| Item | Sketch | Constraint |
|---|---|---|
| early data (0-RTT) | `ServerBuilder::dangerous_enable_early_data(max_bytes: u32)`; forces `TicketMode::Off`; `Event::EarlyData`; `HandshakeInfo::early_data_accepted` | single-use storage in one process does not stop replay across processes; HTTP `425 Too Early` handling first |
| kTLS | `ServerSession::into_kernel(self) -> Result<KernelSecrets, TlsError>` | Linux only; the socket calls belong in net-io |
| QUIC | a wrapper over rustls's QUIC interface for quic-net | quic-net is not scheduled |
| raw public keys | `ServerBuilder::raw_public_key(key)` (RFC 7250) | for back-channel peers without X.509 |
| client ECH | `ClientBuilder::ech(config_list)` (RFC 9849) | needs DNS HTTPS records |
| certificate compression | RFC 8879 | third-party compression crates |
| Windows key ACL check | FR-49 counterpart | a first-party Windows security crate |
| dynamic record sizing | small first records after idle, 16 KiB under bulk | measured benefit first |

---

## Use cases

### Public HTTPS server on net-io

```rust
use tls_net::{Alpn, KeySource, Policy, TlsServer};

let tls = TlsServer::builder()
    .certificate(&std::fs::read("/etc/tls/site.pem")?, KeySource::File("/etc/tls/site.key".as_ref()))?
    .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
    .policy(Policy::compatible())
    .build()?;

let server = net_io::ServerBuilder::new()
    .listener(net_io::ListenerSpec::tcp("0.0.0.0:443").tls(true))
    .tls(tls.clone())
    .sessions(my_http_factory)      // the protocol engine is chosen by ConnectionInfo::tls ALPN
    .gate(my_gate)
    .build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### SNI with several certificates

```rust
let server = TlsServer::builder()
    .certificate(&main_chain, KeySource::Pem(&main_key))?                         // default: SANs of main_chain
    .certificate_for(&["api.example.com"], &api_chain, KeySource::Pem(&api_key))?
    .certificate_for(&["*.shop.example.com"], &shop_chain, KeySource::Pem(&shop_key))?
    .certificate_for(&["api.example.com"], &api_rsa_chain, KeySource::Pem(&api_rsa_key))? // RSA twin for old clients
    .unknown_name(UnknownName::Refuse)
    .build()?;
# Ok::<(), tls_net::TlsError>(())
```

### Reload on a signal

tls-net runs no timer and watches no file. The service kernel turns a signal (or cert-net's renewal) into a call:

```rust
let handle = server.reload_handle();
// on SIGHUP, in the control thread:
match handle.publish(builder_from_config(&config)?) {
    Ok(outcome) => notify_reloaded(outcome.version),
    Err(e) => report(e),   // the old certificates are still in use
}
# Ok::<(), tls_net::TlsError>(())
```

### Back-channel with mutual TLS

```rust
let ca = TrustAnchors::from_pem(&platform_ca_pem)?;
let back_channel = Alpn::new(b"svc-bc/1")?;

let server = TlsServer::builder()
    .certificate(&node_chain, KeySource::Vault { vault: vault.clone(), handle: node_key, custody: KeyCustody::Resident })?
    .policy(Policy::internal())
    .alpn(&[back_channel.clone()])
    .alpn_policy(AlpnPolicy::Required)
    .client_auth(ClientAuth::required(ca.clone()))
    .tickets(TicketMode::Off, 0)
    .build()?;

let client = TlsClient::builder()
    .trust(ca)
    .policy(Policy::internal())
    .alpn(&[back_channel])
    .client_certificate(&node_chain, KeySource::Vault { vault, handle: node_key, custody: KeyCustody::Resident })?
    .build()?;
let session = client.connect("node-2.internal")?;
// after HandshakeComplete on the server: map info().peer.spki_sha256 to a service principal
# Ok::<(), tls_net::TlsError>(())
```

### SMTP submission with STARTTLS

```rust
let client = tls_net::client()?;                      // Mozilla roots, verification on
// EHLO, STARTTLS, read "220 Ready" with the SMTP parser, then:
let mut session = client.start_after_plaintext("smtp.example.com", smtp.leftover())?;
// any byte after the 220 line was refused above (StartTlsInjection)
# Ok::<(), tls_net::TlsError>(())
```

### Outbound HTTPS client

```rust
let client = TlsClient::builder()
    .trust(TrustAnchors::mozilla())
    .alpn(&[Alpn::H2, Alpn::HTTP_1_1])
    .resumption(256)
    .build()?;
let mut session = client.connect("api.example.com")?;
// drive with step/encrypt; info().alpn says whether to speak h2
# Ok::<(), tls_net::TlsError>(())
```

### Fingerprint hook

```rust
struct Door { banned: std::collections::HashSet<tls_net::Ja4> }
impl tls_net::HelloHook for Door {
    fn on_client_hello(&self, ctx: &tls_net::HelloContext<'_>) -> tls_net::HelloVerdict {
        match ctx.fingerprint.ja4 {
            Some(ja4) if self.banned.contains(&ja4) => tls_net::HelloVerdict::Refuse(tls_net::RefuseReason::Fingerprint),
            _ => tls_net::HelloVerdict::Continue,
        }
    }
}
let server = TlsServer::builder()
    .certificate(&chain, KeySource::Pem(&key))?
    .hello_hook(std::sync::Arc::new(Door { banned }))
    .fingerprints(FingerprintKinds::JA4)
    .build()?;
# Ok::<(), tls_net::TlsError>(())
```
