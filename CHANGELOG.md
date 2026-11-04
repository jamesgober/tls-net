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

[Unreleased]: https://github.com/jamesgober/tls-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/tls-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/tls-net/releases/tag/v0.1.0
