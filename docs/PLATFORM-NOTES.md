# tls-net - Platform notes

What differs between Linux, macOS, and Windows, and what each build needs. CI runs the test suite on all three with Rust stable and 1.85.

---

## Building

| Build | Linux | macOS | Windows |
|---|---|---|---|
| default (`aws-lc`) | a C compiler (gcc or clang) | Xcode command line tools | Visual Studio Build Tools or clang |
| `prebuilt-nasm` | no effect | no effect | x86-64: use aws-lc-sys's prebuilt NASM objects even when NASM is installed |
| `ring` | a C compiler | Xcode command line tools | Visual Studio Build Tools or clang |
| `fips` | CMake and Go as well | CMake and Go as well | CMake, Go, NASM, Ninja, and clang as well |

**aws-lc-rs.** The default provider builds C and assembly code through aws-lc-sys. On Windows x86-64, NASM is used when it is on `PATH`; without it, aws-lc-sys falls back to its prebuilt objects, so a plain Visual Studio install is enough. `prebuilt-nasm` makes that choice explicit for reproducible builds.

**FIPS.** Feature `fips` builds aws-lc-rs's FIPS 140-3 module (aws-lc-fips-sys), which needs CMake and Go on every platform. It is tested in a Linux CI job only; the other jobs build every feature except `fips`. In a `fips` build, `TlsServer::is_fips()` and `TlsClient::is_fips()` report what rustls reports for the built configuration, and `Policy::fips()` restricts suites and groups to the approved ones. Outside a `fips` build, `Policy::fips()` still compiles and building with it returns `FipsUnavailable` (`TLS-0004`). Whether a deployment counts as FIPS-validated depends on the module's certificate and the operating environment; tls-net only selects the module and checks rustls's own flag. The FIPS module's crate (aws-lc-fips-sys) is licensed `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`; the OpenSSL license asks for an attribution notice in products that include it, so a distribution built with `fips` must carry that notice. Builds without `fips` do not include the crate.

**Cross-compiling.** aws-lc-sys needs a C cross toolchain for the target. When that is not available, `ring` is the simpler provider (no post-quantum key exchange).

---

## Private key file permissions

| Platform | Check |
|---|---|
| Linux, macOS, other Unix | a key file with any group or other permission bit (`mode & 0o077`) is refused with `KeyFilePermissions` (`TLS-0012`); `0600` and `0400` pass. `ServerBuilder::allow_group_readable_key(true)` turns the check off for deployments where a group must read the key |
| Windows | no check. An ACL check is planned after 1.0 through a first-party Windows security crate (PLAN Q-2). Restrict the key file with NTFS permissions to the service account, or keep the key in key-vault (`KeySource::Vault`) |

The check reads the metadata of the open file, so a file swapped after the check is not read instead. Cost: one `fstat` per key file at load and reload.

---

## Trust anchors

| Anchors | Linux | macOS | Windows |
|---|---|---|---|
| `TrustAnchors::mozilla()` (feature `webpki-roots`) | the Mozilla bundle compiled into the binary | same | same |
| `TrustAnchors::platform()` (feature `platform-verifier`) | the system bundle (`/etc/ssl/certs` and friends); no revocation check | Security framework with the system and user keychains; revocation as the OS does it | CryptoAPI with the system store; revocation as the OS does it |
| `from_pem`, `from_der` | the given certificates | same | same |

`mozilla()` gives the same answer on every machine and changes only with a tls-net release. `platform()` follows the operating system, including roots an administrator added (useful inside a company network) and roots an administrator removed; the result can differ between two machines. On Linux, `platform()` does not check revocation, so `mozilla()` with `ClientBuilder::crls` is the stricter choice there.

The platform verifier can block on the operating system (for example a revocation fetch on Windows or macOS) during certificate verification. Drive sessions that use it from a thread that may block, not from a readiness loop that serves other connections. `mozilla()` and private anchors never block.

---

## Clocks

Certificate validity, expiry reports, and ticket key rotation read the system clock (`SystemTime`). A ticket ring never moves back: after a clock step backwards it keeps its current key until the clock passes the epoch again. A `Ratchet` ring that would have to step forward more than 1,000 periods (a large clock jump, or a process that slept that long) draws a new random key instead of running the chain (`TicketKeyRotated { reseeded: true }`); outstanding tickets then need a full handshake. Handshake durations in events use the monotonic clock (`Instant`).
