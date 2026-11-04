<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>tls-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.5.0] - 2026-11-04

Feature complete: observation, FIPS, the platform verifier, ticket key
hand-off across restarts, and the remaining debugging and fingerprint options.

### Added

- Observation: `TlsObserver`, `TlsEvent` (handshake completed and failed,
  hello captured and refused, reload applied and refused, certificate
  expiring, ticket key rotated, capacity reached), `HelloRefusal`;
  `ServerBuilder::{observer, hello_sampling}` and `ClientBuilder::observer`.
- `TlsServer::stats()` and `ServerStats`: lock-free counters for full,
  resumed, and failed handshakes, refusals, tickets, TLS 1.2 and post-quantum
  handshakes, and SNI disagreements.
- FIPS 140-3: feature `fips`, `Policy::fips()`, `TlsServer::is_fips()`,
  `TlsClient::is_fips()`; a Linux CI job builds and tests it.
- `TrustAnchors::platform()` (feature `platform-verifier`), tested against
  public sites on Linux, macOS, and Windows.
- Ticket key hand-off: `TlsServer::ticket_keys()`, `TicketKeyRingHandle::{epoch,
  export_sealed, import_sealed, rotate_now}`, `SealedTicketKeys`; tested
  between two processes.
- `Policy::summary()` and `PolicySummary` for logs and audits.
- `ja3_md5` and `FingerprintKinds::JA3_MD5` (feature `ja3-md5`), with MD5
  checked against RFC 1321.
- `TlsServer::as_rustls_configs` and `TlsClient::as_rustls_config` (feature
  `rustls-escape-hatch`, outside semver).
- `ServerBuilder::dangerous_key_log`, `ClientBuilder::dangerous_key_log`, and
  `KeyLogSink` (feature `dangerous-keylog`); refused with FIPS.
- `docs/PLATFORM-NOTES.md`.
- Attack tests T-8 (no key bytes in any `Debug` or `Display`), T-21 (opt-in
  pin comparison timing), T-23 (no banned crate in the tree), T-24 (sealed
  keys refused when wrong, tampered, or old), T-27 (half-open handshakes).
- STARTTLS tests against a scripted relay and a public relay.

### Changed

- `Fingerprint` has a `ja3_md5` field (always `None` without the feature).

## [0.4.0] - 2026-11-04

Extended: mutual TLS, pinned identities, host policies, hot reload, session
tickets, fingerprints, key-vault custody, expiry reports, and OCSP staples.

### Added

- Mutual TLS: `ClientAuth::{none, optional, required, pinned}` with
  `with_crls` and `hide_ca_names`; `ClientBuilder::client_certificate`;
  `PeerIdentity` in `HandshakeInfo::peer` on both sides.
- Pins: `ServerIdentity::Pinned { name, spki_sha256, require_chain }` and
  `ClientAuth::pinned`, on top of real handshake signature checks (T-6b);
  `spki_sha256`, `certificate_der_from_pem`.
- CRLs: `Crls::{from_pem, from_der}`, `RevocationPolicy`, `ClientBuilder::crls`.
- Host policies: `ServerBuilder::host(names, HostPolicy)` with their own ALPN,
  `AlpnPolicy::Required`, client authentication, and policy.
- Reload: `TlsServer::{reload_from_pem, reload_from_files, reload_handle,
  reader, version}`, `ReloadHandle::publish`, `ReloadOutcome`, `ServerReader`.
  Ticket keys and the session cache survive a reload.
- Session tickets under a key ring: `TicketMode::{Off, Ephemeral, Ratchet,
  Derived}`, `TicketSeed`, `ServerBuilder::{tickets, session_cache}`;
  XChaCha20-Poly1305 tickets with lazy rotation.
- Fingerprints and the hook: `Ja4`, `ja4_raw`, `ja4_original`, `ja3_string`,
  `Fingerprint`, `FingerprintKinds`, `HelloHook`, `HelloContext`,
  `HelloVerdict`; `ServerBuilder::{hello_hook, fingerprints, hello_limits}`;
  `ServerSession::fingerprint`.
- Key-vault custody: `KeySource::Vault` with `KeyCustody::{Resident,
  PerSignature}`.
- `TlsServer::expiry_report`, `ExpiryReport`, `CertificateInfo`, `ExpiryState`,
  `KeyType`; `ServerBuilder::ocsp_staple`; `allow_group_readable_key`,
  `validity_skew`; `TlsServer::sni_disagreements`.
- loom models (snapshot, capacity gate, ticket ring) and a CI job; fuzz target
  `ticket_open`; JA4 known-answer test against FoxIO's published example.

### Changed

- `KeySource` is `Clone`, not `Copy` (the vault variant holds an `Arc`).
- `HelloLimits::max_ciphers` accepts 1 to 1,024 (D-072).
- key-vault is built with page locking and wiping on (D-069).

## [0.3.0] - 2026-11-04

Core. tls-net serves and connects over TLS 1.3 and TLS 1.2 through rustls's
sans-IO API, and plugs into net-io as its TLS engine.

### Added

- Tier 1: `server_from_pem`, `server_from_files`, `client`, `client_with_ca_pem`,
  `TlsServer::accept`, `TlsClient::connect`, `TlsClient::start_after_plaintext`
  (STARTTLS with injection refusal).
- `ServerBuilder` (`certificate`, `certificate_for`, `certificate_der`,
  `unknown_name`, `alpn`, `policy`, `limits`, `load_limits`) and `ClientBuilder`
  (`trust`, `policy`, `alpn`, `resumption`, `send_sni`, `limits`).
- `Policy` with the presets `compatible`, `modern`, `internal`, `client_default`;
  `Version`, `CipherSuite`, `Group`, `SignatureScheme` with wire codes.
- `ServerSession` and `ClientSession`: `step`, `encrypt`, `close`, `on_eof`,
  `info`, `input_capacity_required`, `set_tag`, `error_code`, `alert`; `Progress`,
  `Event`, `CloseKind`, `SessionState`, `OUTGOING_MIN`, `INCOMING_MIN`,
  `MAX_RECORD_PAYLOAD`.
- Certificate loading with every check: size gate, Unix key file permissions,
  PEM labels (encrypted keys named), one key only, key match, validity with skew,
  SAN name coverage (RFC 9525 wildcards), key size and type, SHA-1 refusal, EKU,
  chain order. `KeySource::{Pem, Der, File}`, `LoadLimits`.
- SNI: exact and single-label wildcard names, ECDSA and RSA certificates for one
  name, default certificate or a 7-byte `unrecognized_name` refusal that is the
  same for every name; `normalize_server_name`.
- ClientHello parser: `HelloParser`, `HelloParse`, `ClientHelloView`,
  `HelloLimits`, `is_grease`; zero-copy across up to 16 records, every budget
  checked before work.
- Handshake budgets (`HandshakeLimits`): capacity gate per server, inbound
  handshake bytes, peer chain length and size.
- `TlsError` with codes `TLS-0000` to `TLS-0050`, `ErrorCategory`, `Action`,
  `public_message`; `CertificateProblem`, `RefuseReason`.
- `TrustAnchors::{mozilla, from_pem, from_der}`, `ServerIdentity::{Dns, Ip}`,
  `DnsName`, `HandshakeInfo`, `HandshakeKind`, `default_provider_name`.
- The net-io adapter (feature `net-io`, now on by default): `TlsServer` is a
  `net_io::TlsAcceptor`, both sessions are `net_io::TlsSession`, for net-io
  0.4 to 0.6.
- Examples `https_server_blocking` and `https_get`; tests for every load-time
  check, attack tests for T-1, T-2, T-3, T-5, T-6, T-7, T-9, T-13, T-14, T-17,
  T-20, T-22, T-25, T-28, a counting-allocator test, property tests, an
  end-to-end net-io test, opt-in interop tests against OpenSSL and curl and
  public sites, and five fuzz targets.

### Changed

- The ClientHello parser, the net-io adapter, and the STARTTLS helper shipped in
  this release instead of 0.4 and 0.5 (D-036 to D-038).
- Exporters and channel binding move to the rustls 0.24 adoption: rustls 0.23's
  unbuffered connections have no exporter (D-052).
- Application data that arrives in the same flight as the peer's Finished is
  delivered after `HandshakeComplete`, never before (D-066).

## [0.2.0] - 2026-11-04

Design lock. The public API from `0.3.0` to `1.0.0` is written down; no TLS code
ships yet. This is the first release on crates.io.

### Added

- `docs/API.md`: every public item by tier and grade, with signatures, errors and
  their codes, cost targets, and examples per use case.
- `dev/PLAN.md`: requirements FR-1 to FR-50 and NFR-1 to NFR-24, design (the step
  loop over rustls's unbuffered API, certificate checks, SNI host groups, reload,
  the ticket key ring, ClientHello parsing and fingerprints), threats T-1 to T-28
  with defences, tests, and costs, performance targets, and decisions D-004 to
  D-051.
- Cargo features, each wired to its dependency: `aws-lc` (default), `ring`,
  `prebuilt-nasm`, `webpki-roots` (default), `platform-verifier`, `key-vault`
  (default), `net-io`, `ja3-md5`, `rustls-escape-hatch`, `dangerous-keylog`.
- Dependencies: rustls 0.23.46 (default features off), aws-lc-rs, webpki-roots,
  rustls-platform-verifier, crypt-io 1.2.2, key-vault 1.1, net-io (0.4 to 0.6).

### Changed

- Crypto provider decision: aws-lc-rs by default, ring as a feature (was ring),
  because ring has no post-quantum key exchange group (D-004).
- Client roots decision: bundled Mozilla roots by default, the OS store as a
  feature (was the OS store first) (D-005).
- `dev/ROADMAP.md` follows the specification: 0.3 core, 0.4 extended, 0.5 feature
  complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta, a 0.9.x polish
  series, then 1.0. The ClientHello parser, the net-io adapter, and the STARTTLS
  helper move to 0.3 (D-036 to D-038).
- `deny.toml` bans openssl, openssl-sys, native-tls, tokio, async-std, and
  rustls-pemfile; allows CDLA-Permissive-2.0 for webpki-roots only; checks the
  supported targets only.

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/tls-net/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/jamesgober/tls-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/tls-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/tls-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/tls-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/tls-net/releases/tag/v0.1.0
