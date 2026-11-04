//! Ticket key hand-off between two processes: the old process seals its keys,
//! the new one imports them, and a client resumes against the new process.
//! The test binary re-runs itself as the new process.

#![cfg(any(feature = "aws-lc", feature = "ring"))]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{TcpClient, data, spawn_https};
use tls_net::{
    ClientBuilder, HandshakeKind, KeySource, TicketMode, TicketSeed, TlsServer, TrustAnchors,
};

const WRAP: [u8; 32] = [0x5a; 32];

fn server() -> TlsServer {
    TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .tickets(
            TicketMode::Ratchet {
                seed: TicketSeed::Random,
                period: Duration::from_secs(3600),
            },
            2,
        )
        .session_cache(0)
        .build()
        .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The new process: imports the sealed keys from stdin, serves, prints its port.
#[test]
fn test_handoff_child() {
    if std::env::var_os("TLS_NET_HANDOFF_CHILD").is_none() {
        return;
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    let server = server();
    server
        .ticket_keys()
        .unwrap()
        .import_sealed(&WRAP, &unhex(line.trim()))
        .unwrap();
    let addr = spawn_https(server);
    println!("PORT {}", addr.port());
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(20));
}

#[test]
fn test_handoff_across_processes_keeps_resumption() {
    let old = server();
    let addr = spawn_https(old.clone());
    let client = ClientBuilder::new()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .build()
        .unwrap();
    // A first connection to the old process leaves a ticket in the client.
    {
        let sock = std::net::TcpStream::connect(addr).unwrap();
        let mut c = TcpClient::new(sock, client.connect("localhost").unwrap());
        c.handshake().unwrap();
        c.write(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let _ = c.read(19);
    }
    let sealed = old.ticket_keys().unwrap().export_sealed(&WRAP).unwrap();

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "test_handoff_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("TLS_NET_HANDOFF_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", hex(sealed.as_bytes())).unwrap();
    let mut port = None;
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        // libtest may print the test name on the same line.
        if let Some(at) = line.find("PORT ") {
            port = Some(line[at + 5..].trim().parse::<u16>().unwrap());
            break;
        }
    }
    let port = port.expect("the child printed its port");
    let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut c = TcpClient::new(sock, client.connect("localhost").unwrap());
    c.handshake().unwrap();
    let kind = c.session.info().unwrap().kind;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        kind,
        HandshakeKind::Resumed,
        "the new process opened the old process's ticket"
    );
}
