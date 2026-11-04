<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>tls-net</b>
    <br>
    <sub><sup>TLS ADAPTER</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/tls-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/tls-net"></a>
    <a href="https://crates.io/crates/tls-net"><img alt="Downloads" src="https://img.shields.io/crates/d/tls-net?color=%230099ff"></a>
    <a href="https://docs.rs/tls-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/tls-net"></a>
    <a href="https://github.com/jamesgober/tls-net/actions"><img alt="CI" src="https://github.com/jamesgober/tls-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>tls-net</strong> gives net-io TLS without net-io depending on a TLS library. It is a thin adapter: rustls does the cryptography and the protocol, and tls-net connects it to net-io's sans-IO TLS seam, loads certificates, and applies the policy.
    </p>
    <p>
        We do not write TLS. TLS safety comes from years of audits, constant-time code, and side-channel work; a home-made implementation would be the weakest link in a security-first stack. rustls is memory-safe and audited, and it is one of the few third-party crates the stack accepts.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: extended (<code>0.4.0</code>).</strong> Server and client sessions, policies, certificate checks, SNI with host policies, ALPN, mutual TLS with pins, hot reload, session tickets, JA4 fingerprints with a hook, key-vault custody, the STARTTLS helper, and the net-io adapter work and are tested against OpenSSL and curl. Observability, FIPS, and the platform verifier arrive in <code>0.5.0</code> (<a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>).
    </blockquote>
</div>

<hr>
<br>

## Features

- **Sans-IO sessions** over rustls's unbuffered API: ciphertext in a buffer you own, plaintext out as a slice of that buffer, records written into another buffer you own. No sockets, no async runtime.
- **net-io adapter** (feature `net-io`): a `TlsServer` is a net-io `TlsAcceptor`.
- **Policy** that cannot express anything weak: TLS 1.2 and 1.3 only, AEAD suites with ECDHE only, X25519MLKEM768 post-quantum key exchange first; presets `compatible`, `modern`, `internal`.
- **Certificates checked before use**: key match, validity window, name coverage, key size, signature algorithm, EKU, chain order; files size-gated and, on Unix, permission-checked.
- **SNI** with several certificates, single-label wildcards, a default or a refusal, and per-host policy.
- **Hot reload** that validates everything before the swap; handshakes in progress keep their configuration.
- **Client verification that cannot be turned off**, Mozilla roots by default, private CAs, SPKI pins that still check handshake signatures.
- **ClientHello capture** with a bounded zero-copy parser, JA4 and JA3 fingerprints, and a hook for the connection gate.
- **Session tickets** under a rotating key ring (ephemeral, ratchet with a sealed hand-off across restarts, or derived for clusters).
- **Errors** with stable codes (`TLS-nnnn`), categories, and messages that never carry key material.

## Installation

```toml
[dependencies]
tls-net = "0.4"
```

The default crypto provider is aws-lc-rs, which builds C and assembly code: you need a C compiler (on Windows, Visual Studio Build Tools or clang). On Windows x86-64, NASM is used when it is on `PATH`; otherwise aws-lc-sys uses its prebuilt objects (feature `prebuilt-nasm` forces them). The `ring` feature selects the ring provider instead, without post-quantum key exchange.

## Quick start

Tier 1: one call each. The full API, including the session loop a driver runs, is in [`docs/API.md`](./docs/API.md).

```rust
// Server: certificate files from the operator, default policy, ALPN http/1.1.
let server = tls_net::server_from_files("/etc/tls/site.pem", "/etc/tls/site.key")?;
let mut session = server.accept()?;     // one per accepted connection; drive with step()

// Client: Mozilla roots, server verification always on.
let client = tls_net::client()?;
let mut session = client.connect("example.com")?;
```

## Documentation

- [`docs/API.md`](./docs/API.md): every public item with signatures, errors, cost, and examples.
- [`dev/PLAN.md`](./dev/PLAN.md): requirements, design, threat model, and the decision log.
- [`dev/ROADMAP.md`](./dev/ROADMAP.md): versions and their exit criteria.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
