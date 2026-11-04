//! Fetches `https://<host>/` with the Mozilla roots and prints the status
//! line and the negotiated parameters.
//!
//! ```text
//! cargo run --example https_get -- www.rust-lang.org
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;

use tls_net::{Alpn, ClientBuilder, Event, TrustAnchors};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "www.rust-lang.org".into());
    let client = ClientBuilder::new()
        .trust(TrustAnchors::mozilla())
        .alpn(&[Alpn::HTTP_1_1])
        .build()?;
    let mut session = client.connect(&host)?;
    let mut sock = TcpStream::connect((host.as_str(), 443))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    let mut inbuf = vec![0u8; 64 * 1024];
    let mut filled = 0;
    let mut outbuf = vec![0u8; 64 * 1024];
    let mut sent_request = false;
    let mut response = Vec::new();
    loop {
        let p = session.step(&mut inbuf[..filled], &mut outbuf)?;
        let (consumed, written) = (p.consumed, p.written);
        let mut need_input = false;
        let mut done = false;
        match p.event {
            Event::HandshakeComplete => {
                if let Some(info) = session.info() {
                    println!(
                        "{:?} {:?} {:?}",
                        info.version, info.cipher_suite, info.group
                    );
                }
            }
            Event::Data(plain) => response.extend_from_slice(plain),
            Event::NeedInput => need_input = true,
            Event::PeerClosed | Event::Closed => done = true,
            _ => {}
        }
        if written > 0 {
            sock.write_all(&outbuf[..written])?;
        }
        inbuf.copy_within(consumed..filled, 0);
        filled -= consumed;
        if !sent_request && session.info().is_some() {
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            let n = session.encrypt(req.as_bytes(), &mut outbuf)?;
            sock.write_all(&outbuf[..n])?;
            sent_request = true;
        }
        if response.windows(2).any(|w| w == b"\r\n") || done {
            break;
        }
        if need_input && written == 0 && consumed == 0 {
            let n = sock.read(&mut inbuf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
    }
    let line = response.split(|&b| b == b'\n').next().unwrap_or_default();
    println!("{}", String::from_utf8_lossy(line).trim_end());
    Ok(())
}
