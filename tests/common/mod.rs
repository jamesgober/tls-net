//! Shared helpers: fixtures and an in-memory pipe between two sessions.

#![allow(dead_code)]

use tls_net::{ClientSession, Event, Progress, ServerSession, SessionState, TlsError};

pub fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Either session kind.
pub trait Side {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError>;
    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError>;
    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError>;
    fn state(&self) -> SessionState;
}

macro_rules! side {
    ($t:ty) => {
        impl Side for $t {
            fn step<'i>(
                &mut self,
                input: &'i mut [u8],
                output: &mut [u8],
            ) -> Result<Progress<'i>, TlsError> {
                <$t>::step(self, input, output)
            }
            fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
                <$t>::encrypt(self, plaintext, output)
            }
            fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
                <$t>::close(self, output)
            }
            fn state(&self) -> SessionState {
                <$t>::state(self)
            }
        }
    };
}
side!(ServerSession);
side!(ClientSession);

/// One end of the pipe.
pub struct End {
    /// Bytes received from the peer and not yet consumed.
    pub inbox: Vec<u8>,
    /// How much of `inbox` the session may see (for byte-at-a-time tests).
    pub visible: usize,
    pub chunk: usize,
    pub out: Vec<u8>,
    pub received: Vec<u8>,
    pub complete: bool,
    pub peer_closed: bool,
    pub error: Option<TlsError>,
    pub steps: usize,
}

impl End {
    pub fn new(chunk: usize) -> Self {
        End {
            inbox: Vec::new(),
            visible: 0,
            chunk,
            out: vec![0; 64 * 1024],
            received: Vec::new(),
            complete: false,
            peer_closed: false,
            error: None,
            steps: 0,
        }
    }

    /// Steps until the session needs more input than is visible. Returns
    /// whether anything happened. Bytes to send go to `peer`.
    pub fn run(&mut self, side: &mut dyn Side, peer: &mut Vec<u8>) -> bool {
        let mut any = false;
        loop {
            if self.error.is_some() || self.steps > 1_000_000 {
                return any;
            }
            self.visible = self.visible.min(self.inbox.len());
            if self.visible == 0 && !self.inbox.is_empty() {
                self.visible = self.chunk.min(self.inbox.len());
            }
            self.steps += 1;
            let visible = self.visible;
            let r = side.step(&mut self.inbox[..visible], &mut self.out);
            let (consumed, written, event) = match r {
                Ok(p) => {
                    let ev = match p.event {
                        Event::Data(d) => {
                            self.received.extend_from_slice(d);
                            "data"
                        }
                        Event::HandshakeComplete => "complete",
                        Event::NeedInput => "need",
                        Event::Transmit => "transmit",
                        Event::PeerClosed => "peer_closed",
                        Event::Closed => "closed",
                        Event::OutputFull => "full",
                        _ => "other",
                    };
                    (p.consumed, p.written, ev)
                }
                Err(e) => {
                    self.error = Some(e);
                    return true;
                }
            };
            peer.extend_from_slice(&self.out[..written]);
            self.inbox.drain(..consumed);
            self.visible -= consumed;
            match event {
                "complete" => self.complete = true,
                "peer_closed" => self.peer_closed = true,
                _ => {}
            }
            if consumed > 0 || written > 0 || event != "need" {
                any = true;
            }
            if event == "closed" || event == "full" {
                return any;
            }
            if event == "need" && consumed == 0 && written == 0 {
                if self.visible < self.inbox.len() {
                    self.visible = (self.visible + self.chunk).min(self.inbox.len());
                    continue;
                }
                return any;
            }
        }
    }
}

/// Runs both sides until neither makes progress.
pub fn pump(server: &mut ServerSession, s: &mut End, client: &mut ClientSession, c: &mut End) {
    for _ in 0..100_000 {
        let mut to_server = Vec::new();
        let mut to_client = Vec::new();
        let a = c.run(client, &mut to_server);
        s.inbox.extend(to_server);
        let b = s.run(server, &mut to_client);
        c.inbox.extend(to_client);
        if !a && !b {
            return;
        }
    }
    panic!("pump did not settle");
}

/// Sends `data` from one side in `encrypt` calls of at most `chunk` bytes.
pub fn send(side: &mut dyn Side, data: &[u8], chunk: usize, peer: &mut Vec<u8>) {
    let mut out = vec![0; 64 * 1024];
    for part in data.chunks(chunk) {
        let n = side.encrypt(part, &mut out).unwrap();
        peer.extend_from_slice(&out[..n]);
    }
}

/// A blocking client over a real socket: the loop from `docs/API.md`.
pub struct TcpClient {
    pub sock: std::net::TcpStream,
    pub session: ClientSession,
    inbuf: Vec<u8>,
    filled: usize,
    out: Vec<u8>,
}

/// A socket error as the session sees it, with what the socket said kept
/// on stderr: a reset, a timeout, and a refused write all end as
/// `UncleanClose`, and a failing test should say which.
fn socket_error(op: &str, e: &std::io::Error) -> TlsError {
    eprintln!("socket {op}: {:?} {e}", e.kind());
    TlsError::UncleanClose
}

impl TcpClient {
    pub fn new(sock: std::net::TcpStream, session: ClientSession) -> Self {
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        TcpClient {
            sock,
            session,
            inbuf: vec![0; 64 * 1024],
            filled: 0,
            out: vec![0; 64 * 1024],
        }
    }

    /// Steps once; reads from the socket when the session needs input.
    /// Returns plaintext if any arrived, `Ok(None)` for other progress.
    fn turn(&mut self) -> Result<Option<Vec<u8>>, TlsError> {
        use std::io::{Read, Write};
        let p = self
            .session
            .step(&mut self.inbuf[..self.filled], &mut self.out)?;
        let (consumed, written) = (p.consumed, p.written);
        let mut data = None;
        let mut need = false;
        match p.event {
            Event::Data(d) => data = Some(d.to_vec()),
            Event::NeedInput => need = true,
            Event::PeerClosed | Event::Closed => data = Some(Vec::new()),
            _ => {}
        }
        if written > 0 {
            self.sock
                .write_all(&self.out[..written])
                .map_err(|e| socket_error("write", &e))?;
        }
        self.inbuf.copy_within(consumed..self.filled, 0);
        self.filled -= consumed;
        if need && written == 0 && consumed == 0 {
            if self.filled == self.inbuf.len() {
                let want = self.session.input_capacity_required().max(self.filled + 1);
                self.inbuf.resize(want, 0);
            }
            let n = self
                .sock
                .read(&mut self.inbuf[self.filled..])
                .map_err(|e| socket_error("read", &e))?;
            if n == 0 {
                let eof = self.session.on_eof();
                eprintln!("socket closed by the peer: on_eof {eof:?}");
                return Err(TlsError::UncleanClose);
            }
            self.filled += n;
        }
        Ok(data)
    }

    pub fn handshake(&mut self) -> Result<(), TlsError> {
        while self.session.info().is_none() {
            self.turn()?;
        }
        Ok(())
    }

    /// Plaintext until at least `n` bytes or the peer closes.
    pub fn read(&mut self, n: usize) -> Result<Vec<u8>, TlsError> {
        let mut got = Vec::new();
        while got.len() < n {
            match self.turn()? {
                Some(d) if d.is_empty() => break,
                Some(d) => got.extend(d),
                None => {}
            }
        }
        Ok(got)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), TlsError> {
        use std::io::Write;
        for part in data.chunks(16_384) {
            let n = self.session.encrypt(part, &mut self.out)?;
            if let Err(e) = self.sock.write_all(&self.out[..n]) {
                let _ = socket_error("write", &e);
                return Err(self.refusal());
            }
        }
        Ok(())
    }

    /// Why the peer reset the connection, when it said so first. A TLS 1.3
    /// client finishes its handshake before the server checks its
    /// certificate, so a refused client learns it on its first write: the
    /// server's alert came first and, on Linux, can still be read after the
    /// reset (Windows discards it).
    fn refusal(&mut self) -> TlsError {
        for _ in 0..16 {
            match self.turn() {
                Err(e) => return e,
                Ok(Some(d)) if d.is_empty() => break,
                Ok(_) => {}
            }
        }
        TlsError::UncleanClose
    }
}

/// Serves HTTPS on an ephemeral loopback port, one thread per connection,
/// answering every request with `hello from tls-net`.
pub fn spawn_https(server: tls_net::TlsServer) -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let Ok(session) = server.accept() else {
                continue;
            };
            std::thread::spawn(move || {
                let _ = serve_one(stream, session);
            });
        }
    });
    addr
}

fn serve_one(mut sock: std::net::TcpStream, mut session: ServerSession) -> std::io::Result<()> {
    use std::io::{Read, Write};
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let (mut inbuf, mut filled, mut out, mut request) =
        (vec![0u8; 64 * 1024], 0, vec![0u8; 64 * 1024], Vec::new());
    loop {
        let Ok(p) = session.step(&mut inbuf[..filled], &mut out) else {
            return Ok(());
        };
        let (consumed, written) = (p.consumed, p.written);
        let need = matches!(p.event, Event::NeedInput);
        let done = matches!(p.event, Event::PeerClosed | Event::Closed);
        if let Event::Data(d) = p.event {
            request.extend_from_slice(d);
        }
        if written > 0 {
            sock.write_all(&out[..written])?;
        }
        inbuf.copy_within(consumed..filled, 0);
        filled -= consumed;
        if done {
            return Ok(());
        }
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\nhello from tls-net\n";
            if let Ok(n) = session.encrypt(reply, &mut out) {
                sock.write_all(&out[..n])?;
            }
            if let Ok(n) = session.close(&mut out) {
                sock.write_all(&out[..n])?;
            }
            return Ok(());
        }
        if need && written == 0 && consumed == 0 {
            let n = sock.read(&mut inbuf[filled..])?;
            if n == 0 {
                return Ok(());
            }
            filled += n;
        }
    }
}

/// Builds raw ClientHello records for attack tests.
pub struct RawHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl RawHello {
    /// A TLS 1.2-shaped hello with groups, point formats, signature
    /// algorithms, and extended master secret.
    pub fn tls12(ciphers: &[u16]) -> Self {
        RawHello {
            legacy_version: 0x0303,
            ciphers: ciphers.to_vec(),
            extensions: vec![
                (10, vec![0, 4, 0, 0x1d, 0, 0x17]),
                (11, vec![1, 0]),
                (13, vec![0, 6, 4, 3, 8, 4, 4, 1]),
                (23, vec![]),
            ],
        }
    }

    pub fn sni(mut self, name: &[u8]) -> Self {
        let mut d = Vec::new();
        d.extend(u16::try_from(name.len() + 3).unwrap().to_be_bytes());
        d.push(0);
        d.extend(u16::try_from(name.len()).unwrap().to_be_bytes());
        d.extend(name);
        self.extensions.push((0, d));
        self
    }

    pub fn record(&self) -> Vec<u8> {
        let mut b = self.legacy_version.to_be_bytes().to_vec();
        b.extend([9u8; 32]);
        b.push(0);
        b.extend(u16::try_from(self.ciphers.len() * 2).unwrap().to_be_bytes());
        for c in &self.ciphers {
            b.extend(c.to_be_bytes());
        }
        b.extend([1, 0]);
        let mut ext = Vec::new();
        for (t, d) in &self.extensions {
            ext.extend(t.to_be_bytes());
            ext.extend(u16::try_from(d.len()).unwrap().to_be_bytes());
            ext.extend(d);
        }
        b.extend(u16::try_from(ext.len()).unwrap().to_be_bytes());
        b.extend(ext);
        let mut msg = vec![1];
        msg.extend(&u32::try_from(b.len()).unwrap().to_be_bytes()[1..]);
        msg.extend(b);
        let mut rec = vec![22, 3, 1];
        rec.extend(u16::try_from(msg.len()).unwrap().to_be_bytes());
        rec.extend(msg);
        rec
    }
}

/// Feeds `hello` to a fresh server session; returns the bytes it sent and
/// its final error.
pub fn refuse(server: &tls_net::TlsServer, hello: &[u8]) -> (Vec<u8>, Option<TlsError>) {
    let mut s = server.accept().unwrap();
    let mut input = hello.to_vec();
    let mut out = vec![0u8; 64 * 1024];
    let mut sent = Vec::new();
    for _ in 0..4 {
        match s.step(&mut input, &mut out) {
            Ok(p) => {
                let (c, w) = (p.consumed, p.written);
                sent.extend_from_slice(&out[..w]);
                input.drain(..c);
            }
            Err(e) => return (sent, Some(e)),
        }
    }
    (sent, None)
}

impl TcpClient {
    /// Completes the handshake and sends `first` in the same write as the
    /// client's Finished, as curl does.
    pub fn handshake_with_early_request(&mut self, first: &[u8]) -> Result<(), TlsError> {
        use std::io::{Read, Write};
        loop {
            let p = self
                .session
                .step(&mut self.inbuf[..self.filled], &mut self.out)?;
            let (consumed, mut written) = (p.consumed, p.written);
            let complete = matches!(p.event, Event::HandshakeComplete);
            let need = matches!(p.event, Event::NeedInput);
            if complete {
                written += self.session.encrypt(first, &mut self.out[written..])?;
            }
            if written > 0 {
                self.sock
                    .write_all(&self.out[..written])
                    .map_err(|_| TlsError::UncleanClose)?;
            }
            self.inbuf.copy_within(consumed..self.filled, 0);
            self.filled -= consumed;
            if complete {
                return Ok(());
            }
            if need && written == 0 && consumed == 0 {
                let n = self
                    .sock
                    .read(&mut self.inbuf[self.filled..])
                    .map_err(|_| TlsError::UncleanClose)?;
                if n == 0 {
                    return Err(TlsError::UncleanClose);
                }
                self.filled += n;
            }
        }
    }
}
