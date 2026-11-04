# tls-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md). Public API by version: [`../docs/API.md`](../docs/API.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: every public item written in `docs/API.md` with signatures, errors, and version; every open decision answered and logged; verification items V-1 to V-6 answered against rustls 0.23.46; seam shape matched to net-io's published seam; `deny.toml` updated; every planned feature declared and wired to its dependency; CI builds the full tree on Linux, macOS, Windows, stable and 1.85.
- [x] `docs/API.md`: the whole public API 0.3 to 1.0, by tier and grade.
- [x] Decisions D-004 to D-049 in `PLAN.md` (open decisions O-1 to O-25, V-1 to V-6, and what the rustls source showed).
- [x] Features declared: `aws-lc`, `ring`, `prebuilt-nasm`, `webpki-roots`, `platform-verifier`, `key-vault`, `net-io`, `ja3-md5`, `rustls-escape-hatch`, `dangerous-keylog` (`fips` waits for 0.5, D-042).
- [x] `deny.toml`: bans, CDLA exception for webpki-roots, supported targets.
- [x] First crates.io publish (D-006).

## v0.3.0 - Core
Exit: a tls-net server serves HTTPS to curl and OpenSSL `s_client` over the loopback harness with SNI (several certificates), ALPN, `compatible` and `modern`; the tls-net client completes handshakes to public sites with Mozilla roots and to a private CA; every load-time check of PLAN 6.5 has a test; error mapping complete for the implemented paths; a counting allocator proves zero allocations in tls-net code on the established path; a real net-io server carries HTTPS through the adapter.
- [x] Policy, presets, enums, provider selection, `NoProvider` mode.
- [x] PEM and DER intake, DER field reader, certificate entries with all checks.
- [x] ClientHello parser with budgets (moved from 0.4, D-037).
- [x] SNI table, unknown-name refusal, host groups (one group until 0.4).
- [x] `ServerSession`, `ClientSession`: the step loop, the D-035 copy, budgets, capacity gate.
- [x] Tier 1: `server_from_pem`, `server_from_files`, `client`, `client_with_ca_pem`, `accept`, `connect`, `connect_to`.
- [x] `start_after_plaintext` (moved from 0.5, D-038).
- [x] net-io adapter behind `net-io` (moved from 0.5, D-036); compile check against net-io 0.4.0 and the newest.
- [x] Attack tests for T-1, T-2, T-3, T-5, T-6, T-7, T-9, T-13, T-14, T-17, T-20, T-22 (client side), T-25, T-28.
- [x] Fuzz targets `hello_parse`, `der_fields`, `pem_intake`, `session_step_server`, `session_step_client` (built in CI; two minutes each without findings, D-060).
- [x] Interop: OpenSSL 3.0 and 3.5 `s_client` (TLS 1.3 with X25519MLKEM768, X25519, P-256, P-384; TLS 1.2), curl; public sites with the Mozilla roots (D-058).

## v0.4.0 - Extended
Exit: mutual TLS end to end (pinned CA and pinned SPKI with signature checks; T-6b passes); reload under load with zero failed handshakes (1,000 handshakes per second, a reload every second, 10 minutes); ticket ring in all three modes with resumption across a reload; JA4 and JA3 with known-answer tests; the hook refuses by fingerprint; key-vault custody in both modes; expiry report; OCSP static staple; exporters and channel binding.
- [x] Tier 1: `reload_from_pem`, `reload_from_files`, `expiry_report`.
- [x] Tier 2: `client_auth`, `ClientAuth` (struct, D-067), `HostPolicy`, `AlpnPolicy`, `hello_limits`, `tickets`, `TicketMode::*`, `session_cache`, `ocsp_staple`, `Crls`, `RevocationPolicy`, `ServerIdentity::Pinned`, `ReloadHandle`, `ExpiryReport`, `PeerIdentity`, `KeySource::Vault`, `KeyCustody::*`, `ClientBuilder::{client_certificate, crls}`; tests for `Policy::internal`, `require_post_quantum`, `max_fragment_size`.
- Moved: `export_keying_material` and `channel_binding` to the rustls 0.24 adoption, at the latest 0.9 (D-052: rustls 0.23's unbuffered API has no exporter).
- [x] Tier 3: `ServerReader`, `ClientHelloView` accessors, `HelloHook`, `Fingerprint`, `Ja4` (FoxIO known answer), `ja4_raw`, `ja4_original`, `ja3_string`.
- [x] loom tests for the snapshot, capacity gate, and ticket ring (D-080).
- [x] Attack tests T-4, T-6b, T-10, T-11, T-12, T-15, T-16, T-18, T-19, T-22 (server side); T-2 and T-7 since 0.3.
- [x] Fuzz target `ticket_open`.
- Moved: the 10-minute reload-under-load run at 1,000 handshakes per second to the 0.7 soak (D-081); the default suite runs a scaled version.

## v0.5.0 - Feature complete
Exit: smtp-net-shaped STARTTLS and implicit TLS flows against a scripted relay and an external relay with verification; outbound HTTPS from a client; hand-off export and import between two processes keeps resumption; observer events and stats; FIPS build passes `is_fips()` in a Linux CI job; platform verifier on all three OSes; every P0, P1, P2 item shipped or moved with a recorded reason.
- [x] Tier 2: `observer` (server and client, D-089), `TlsObserver`, `TlsEvent`, `ServerStats`, `is_fips`, `Policy::fips` (D-084), `TrustAnchors::platform`, `Policy::summary`.
- [x] Tier 3: `TicketKeyRingHandle::{export_sealed, import_sealed, epoch}` (Ratchet only, D-085), `ja3_md5`, escape hatch, `dangerous-keylog`.
- [x] `TicketKeyRingHandle::rotate_now` (moved from 0.7, D-086).
- [x] `docs/PLATFORM-NOTES.md`.
- [x] Attack tests T-8, T-21 (opt-in timing, D-092), T-23, T-24, T-27.
- [x] Hand-off between two processes and the platform verifier on all three operating systems (D-093); STARTTLS against a scripted relay and a public relay.

## Standing: net-io releases
When net-io publishes a release outside the seam range (`>= 0.4, < 0.7` today, D-036), read its changelog for seam changes and ship a tls-net patch release that widens the range (or adapts the seam) without waiting for the next milestone, so serve-net and smtp-net can move with net-io. The `net-io-range` CI job keeps checking the lowest release of the range.

## v0.6.0 - Optimisation
Exit: every bench of PLAN section 9 with committed baselines; the end-to-end comparison against tokio plus tokio-rustls published; the 20% target met, or the gap explained with a plan, and 0.6 does not close until it is met; per-signature custody cost measured; `docs/PERFORMANCE.md` written.
- [ ] No new API; internal changes only.

## v0.7.0 - Hardening
Exit: every fuzz target seeded with real ClientHellos (D-060) and run for 24 hours without an open finding; attack tests T-1 to T-28 green; tlsfuzzer server scripts and testssl.sh clean for the supported features (weekly CI job); soak of NFR-21 without memory growth; Miri and loom green; `docs/SECURITY.md` written.
- [ ] No new API.

## v0.8.0 - Alpha
Exit (D-039): the consumers' shapes run in this repository against real binaries: a serve-net-style net-io server in direct mode, a back-channel pair with mutual TLS, an smtp-net-style STARTTLS client against a local MTA; interop with curl, OpenSSL, and Go in CI; `docs/OPERATIONS.md` written; every finding fixed test-first.
- [ ] API changes only from findings, each logged.

## v0.9.0 - Beta
Exit: rustls 0.24 (or the next stable line) adopted if released (D-007), with exporters and channel binding (D-052); adversarial review in a dedicated session with every finding fixed test-first; API review against `docs/API.md`; `docs/OPERATIONS.md` and `docs/PLATFORM-NOTES.md` complete. API frozen at 0.9.0.

## v0.9.x - Pre-1.0 polish
Exit: a 1.0 readiness note (`docs/STABILITY-1.0.md` draft) that lists, item by item, what is met and what still needs James.
- [ ] Revisit every gap and every deferred item in this file and in `PLAN.md`; close each or record why it waits for after 1.0.
- [ ] Re-tune handshake and throughput performance against the 0.6 baselines; no regression over 5%.
- [ ] Re-run the security review (threat table, attack tests, dependency footprint, `cargo audit`, `cargo deny`).
- [ ] Check webpki-roots, rustls, and the provider for newer releases.

## v1.0.0 - Stable (James's explicit go)
- [ ] Full audit recorded in `docs/STABILITY-1.0.md` (API, docs, tests, benchmarks, security).
- [ ] DIRECTIVES section 3 item 10: direct mode of the first site and smtp-net have used the API end to end in production (two weeks on staging for direct mode; RC builds in production).
- [ ] API frozen until 2.0.

## After 1.0 (P3)
Early data (0-RTT), kTLS secrets hand-over, QUIC wrapper, raw public keys (RFC 7250), client-side ECH (RFC 9849), certificate compression (RFC 8879), Windows key file ACL check, dynamic record sizing. Each moves into a 1.x minor with a reason.
