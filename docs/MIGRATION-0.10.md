# tls-net - Migrating to 0.10

> 0.10.0 simplified the API after an audit of how it is used (the simplicity audit in [`STABILITY-1.0.md`](./STABILITY-1.0.md), D-141, D-142), and fixed the findings of a review of 0.9.1 (D-143 to D-152). Most code needs no change: Tier 1, the builders, policies, sessions, and errors are as they were. This page lists every rename and removal, every behaviour that changed, and what is new. A server with host policies needs the `Host` check below.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

---

## Renamed or removed

| 0.9 | 0.10 | Why |
|---|---|---|
| `ClientBuilder::new()`, `ClientBuilder::default()` | `TlsClient::builder()` | one way to start a builder |
| `ServerBuilder::new()`, `ServerBuilder::default()` | `TlsServer::builder()` | the same |
| `TlsServer::handshakes_in_progress()` | `server.stats().in_progress` | `stats()` already carried it |
| `TlsServer::sni_disagreements()` | `server.stats().sni_disagreements` | the same |
| `TlsServer::version()` | `server.stats().config_version` | the same; `version()` read as the TLS version |
| `ServerStats::snapshot_version` | `ServerStats::config_version` | the number counts configurations |
| `TlsServer::reader()`, `ServerReader` | `TlsServer::worker_acceptor()`, `WorkerAcceptor` | it accepts sessions; it does not read data |
| `HelloParser::parse(input, &limits)` | `parse_client_hello(input, &limits)` | a unit struct held one function |
| `INCOMING_MIN`, `OUTGOING_MIN` | `MIN_INPUT_BUFFER`, `MIN_OUTPUT_BUFFER` | named after `step`'s `input` and `output` |
| `HandshakeLimits::max_in_progress(n)?` | `HandshakeLimits::max_in_progress(n)` | it could not fail; drop the `?` or `.unwrap()` |

The values are unchanged: both buffer minimums are still 18,437 bytes.

## New

- `TlsClient::connect_stream(name, io)` and `TlsServer::accept_stream(io)` run a session over any blocking `Read + Write` and return a `TlsStream`, which reads and writes plaintext. For a session made another way (`connect_to`, `start_after_plaintext`, `WorkerAcceptor::accept`) there are `TlsStream::client(session, io)` and `TlsStream::server(session, io)`.
- `TlsError::Transport { kind }` (`TLS-0047`): the transport under a `TlsStream` failed. It is in the same category as `UncleanClose`: unavailable, retry idempotent requests.

## Servers with host policies: check `Host`

A `HostPolicy` applies its rules by the SNI the client sends. A client that sends another name the certificate covers, or none, gets the default group's rules and can then ask for the protected host. The HTTP layer must check every request (D-143, T-31):

```rust,ignore
// Once per connection, after the handshake:
let scope = server.host_scope(info.server_name);   // or net-io's tls_info.sni()
// For every request:
if !scope.permits(host_header) {
    return respond(421); // Misdirected Request
}
```

A server without host policies can make the same call; `permits` is then `true` for every name the server serves.

## Behaviour that changed

| What | 0.9 | 0.10 |
|---|---|---|
| Expiry state of a short-lived certificate | under 2 days: `Critical` from issue; under 7 days: `Warn` from issue | `Ok` at issue; `Warn` below half to a third of the lifetime, `Critical` below a fifth to a tenth (D-144) |
| `crls` on a client without `trust` | accepted, never applied | `build` fails with `PolicyInvalid` (D-145) |
| A pinned identity without `require_chain` on a client with CRLs | connected without a CRL check | `connect_to` fails with `PolicyInvalid`; set `require_chain: true` (D-145) |
| `load_limits`, `validity_skew`, `allow_group_readable_key` after `certificate` | ignored at startup, applied at reload | applied at `build` too (D-148) |
| A `LoadLimits` or `HandshakeLimits` field set outside the setter's range | used as set | clamped to the range (D-147) |
| `Policy::modern().versions(&[Tls13, Tls12])` | failed at `build` | builds with the TLS 1.2 suites (D-150) |
| Session tickets | opened for up to two periods | open for one period after issue; 0.9 tickets are refused once after the upgrade (D-151) |
| An ALPN name over 32 bytes with feature `net-io` | reported to net-io as no ALPN | refused at `build` (D-152) |
| `HandshakeInfo` | | new field `peer_verified` (the struct is `#[non_exhaustive]`, so nothing breaks) |

## Replacing a hand-written session loop

Code that drove `step` over a `TcpStream` itself can usually drop the loop:

```rust,ignore
// 0.9: a session, two buffers, and a loop around step, encrypt, and on_eof.
let session = client.connect("example.com")?;
// ... about 80 lines ...

// 0.10:
let mut tls = client.connect_stream("example.com", tcp)?;
tls.write_all(request)?;
tls.read_to_end(&mut response)?;
```

`read` returns `Ok(0)` only after the peer's `close_notify`; a connection that ends without it is an `UnexpectedEof` error carrying `TlsError::UncleanClose`. A loop that treated a bare EOF as the end of the stream had a truncation hole (T-17); `TlsStream` closes it.

Code with its own non-blocking transport, deadlines, or event loop keeps driving `step`: that API is unchanged apart from the buffer constants' names.

## Dependents

- **serve-net** (tests only): `ClientBuilder::new()` becomes `TlsClient::builder()`. With host policies, or for defence in depth, check each request's `Host` with a `HostScope` and answer `421`.
- **smtp-net**: no rename touches it. Its TLS layer hard-codes `18_437`; that is `tls_net::MIN_INPUT_BUFFER`.
