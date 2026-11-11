# tls-net - Migrating to 0.10

> 0.10.0 simplified the API after an audit of how it is used (the simplicity audit in [`STABILITY-1.0.md`](./STABILITY-1.0.md), D-141, D-142). Most code needs no change: Tier 1, the builders, policies, sessions, and errors are as they were. This page lists every rename and removal, and the one new way to use a session.

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

The values are unchanged: both buffer minimums are still 18,437 bytes.

## New

- `TlsClient::connect_stream(name, io)` and `TlsServer::accept_stream(io)` run a session over any blocking `Read + Write` and return a `TlsStream`, which reads and writes plaintext. For a session made another way (`connect_to`, `start_after_plaintext`, `WorkerAcceptor::accept`) there are `TlsStream::client(session, io)` and `TlsStream::server(session, io)`.
- `TlsError::Transport { kind }` (`TLS-0047`): the transport under a `TlsStream` failed. It is in the same category as `UncleanClose`: unavailable, retry idempotent requests.

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

- **serve-net** (tests only): `ClientBuilder::new()` becomes `TlsClient::builder()`.
- **smtp-net**: no rename touches it. Its TLS layer hard-codes `18_437`; that is `tls_net::MIN_INPUT_BUFFER`.
