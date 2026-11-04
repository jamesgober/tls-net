//! A small HTTPS server over `std::net`, one thread per connection, driving
//! tls-net sessions by hand. It answers every request with a short page.
//!
//! ```text
//! cargo run --example https_server_blocking -- 127.0.0.1:8443 tests/data/site.pem tests/data/site.key
//! curl --cacert tests/data/ca.pem --resolve localhost:8443:127.0.0.1 https://localhost:8443/
//! ```
//!
//! On Unix the key file must not be readable by group or others (`chmod 600`).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use tls_net::{Alpn, Event, KeySource, ServerSession, TlsServer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8443".into());
    let chain = args
        .next()
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/site.pem").into());
    let key = args
        .next()
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/site.key").into());

    let server = TlsServer::builder()
        .certificate(
            &std::fs::read(&chain)?,
            KeySource::Pem(&std::fs::read(&key)?),
        )?
        .alpn(&[Alpn::HTTP_1_1])
        .build()?;
    let server = Arc::new(server);
    let listener = TcpListener::bind(&addr)?;
    eprintln!("listening on https://{}", listener.local_addr()?);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            if let Ok(session) = server.accept() {
                if let Err(e) = serve(stream, session) {
                    eprintln!("connection ended: {e}");
                }
            }
        });
    }
    Ok(())
}

/// The driver loop: read ciphertext, step, send what the session wrote,
/// hand plaintext to the application.
fn serve(
    mut sock: TcpStream,
    mut session: ServerSession,
) -> Result<(), Box<dyn std::error::Error>> {
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut inbuf = vec![0u8; 64 * 1024];
    let mut filled = 0;
    let mut outbuf = vec![0u8; 64 * 1024];
    let mut request = Vec::new();
    loop {
        let p = session.step(&mut inbuf[..filled], &mut outbuf)?;
        let (consumed, written) = (p.consumed, p.written);
        let mut need_input = false;
        let mut done = false;
        match p.event {
            Event::Data(plain) => request.extend_from_slice(plain),
            Event::NeedInput => need_input = true,
            Event::PeerClosed | Event::Closed => done = true,
            _ => {}
        }
        if written > 0 {
            sock.write_all(&outbuf[..written])?;
        }
        inbuf.copy_within(consumed..filled, 0);
        filled -= consumed;
        if done {
            return Ok(());
        }
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            let body = b"hello from tls-net\n";
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut reply = head.into_bytes();
            reply.extend_from_slice(body);
            let n = session.encrypt(&reply, &mut outbuf)?;
            sock.write_all(&outbuf[..n])?;
            let n = session.close(&mut outbuf)?;
            sock.write_all(&outbuf[..n])?;
            return Ok(());
        }
        if need_input && written == 0 && consumed == 0 {
            if filled == inbuf.len() {
                inbuf.resize(session.input_capacity_required().max(filled + 1), 0);
            }
            let n = sock.read(&mut inbuf[filled..])?;
            if n == 0 {
                session.on_eof();
                return Ok(());
            }
            filled += n;
        }
    }
}
