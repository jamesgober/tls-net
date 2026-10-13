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
        <strong>Status: scaffold (<code>0.1.0</code>).</strong> No functional code yet. The design is written down in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a> and the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>; the public API is locked in <code>0.2.0</code>.
    </blockquote>
</div>

<hr>
<br>

## Scope

The adapter over the sans-IO API of rustls, server and client configurations, certificate and key loading (PEM), hot reload without dropping connections, SNI with several certificates, ALPN, optional client certificates, ClientHello capture for fingerprinting, and a TLS policy object (minimum version, cipher suites). Automatic certificates (ACME) are planned separately.

See [`dev/PLAN.md`](./dev/PLAN.md) for the full scope, what is deliberately left to other crates, and the decision log.

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
