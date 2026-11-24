//! A small HTTP/1.1 server over `silica.net.Tcp`, the first program on the
//! network stack's TCP (spec/MILESTONES.md, M4's exit test).
//!
//! `GET /<n>` answers `n` bytes (at most 16 MiB) whose byte `i` is
//! `i % 251`, so a client checks a body without being sent its hash;
//! `GET /quit` answers, and the server ends (status 0) once the client
//! has closed that connection, so the answer is never lost with the
//! server's memory. Connections are kept alive between requests (HTTP/1.1)
//! unless the request says `Connection: close` or is HTTP/1.0.
#![no_std]
#![no_main]

use silica_net::tcp::{Read, Stream, Tcp};
use silica_rt::alloc::format;
use silica_rt::alloc::vec::Vec;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

const PORT: u16 = 80;
/// The largest body asked for.
const MOST: u64 = 16 << 20;
/// The longest request head kept (method, path, version, headers).
const HEAD: usize = 8192;

struct Conn {
    s: Stream,
    /// What arrived and is not yet a whole request.
    input: Vec<u8>,
    /// The answer being sent: its head, then `body` bytes of the pattern.
    head: Vec<u8>,
    head_sent: usize,
    body: u64,
    body_sent: u64,
    /// Close once the answer is sent; the peer has finished sending.
    close_after: bool,
    peer_done: bool,
    finished: bool,
    /// This connection asked the server to end.
    quit: bool,
}

fn main(_info: &'static ProcessInfo) -> i64 {
    // On its events: the stack is its need 0 (bit 0), so a restart of the
    // stack is seen and its listener set up again; its own bits from 32.
    let mut tcp = match Tcp::on(silica_rt::sys::Cap(slots::FIRST_GRANT), 22, slots::EVENTS, 32, 1) {
        Ok(t) => t,
        Err(e) => {
            println!("ERROR: httpd: no TCP: {e:?}");
            return 1;
        }
    };
    let listener = match tcp.listen(PORT, 64) {
        Ok(l) => l,
        Err(e) => {
            println!("ERROR: httpd: cannot listen on port {PORT}: {e:?}");
            return 1;
        }
    };
    println!("httpd: listening on port {PORT}");
    let mut conns: Vec<Conn> = Vec::new();
    let mut buf = [0u8; 16384];
    let mut served = 0u64;
    loop {
        let mut progress = false;
        loop {
            match tcp.accept(listener) {
                Ok(Some(s)) => {
                    progress = true;
                    conns.push(Conn {
                        s,
                        input: Vec::new(),
                        head: Vec::new(),
                        head_sent: 0,
                        body: 0,
                        body_sent: 0,
                        close_after: false,
                        peer_done: false,
                        finished: false,
                        quit: false,
                    });
                }
                Ok(None) => break,
                // Every block in use: the waiting ones wait.
                Err(silica_net::tcp::Failure::NoRoom) => break,
                Err(e) => {
                    println!("ERROR: httpd: accept: {e:?}");
                    return 1;
                }
            }
        }
        for c in conns.iter_mut() {
            progress |= step(c, &mut buf, &mut served);
        }
        // Done with: the answer sent and finished, and the peer done too.
        let mut i = 0;
        while i < conns.len() {
            let c = &conns[i];
            if c.finished && c.peer_done {
                let c = conns.swap_remove(i);
                let quit = c.quit;
                let _ = tcp.close(c.s);
                if quit {
                    println!("httpd: {served} answers; asked to end");
                    return 0;
                }
                progress = true;
            } else {
                i += 1;
            }
        }
        if progress {
            continue;
        }
        // Nothing moved: say what each connection waits for, then wait.
        let mut may_sleep = true;
        for c in conns.iter_mut() {
            if !c.peer_done && !c.s.sleep_read() {
                may_sleep = false;
            }
            if sending(c) && !c.s.sleep_write() {
                may_sleep = false;
            }
        }
        if may_sleep {
            let _ = tcp.wait(None);
        }
    }
}

/// The connection failed (reset by the peer, or the stack started again):
/// nothing more is sent or read, and it is let go of.
fn failed(c: &mut Conn) -> bool {
    c.head.clear();
    c.head_sent = 0;
    c.body = 0;
    c.body_sent = 0;
    c.finished = true;
    c.peer_done = true;
    true
}

fn sending(c: &Conn) -> bool {
    c.head_sent < c.head.len() || c.body_sent < c.body
}

/// Read, answer and send for one connection; whether anything moved.
fn step(c: &mut Conn, buf: &mut [u8], served: &mut u64) -> bool {
    let mut progress = false;
    // Send what is being sent.
    while sending(c) {
        if c.head_sent < c.head.len() {
            let Ok(n) = c.s.write(&c.head[c.head_sent..]) else { return failed(c) };
            if n == 0 {
                return progress;
            }
            c.head_sent += n;
            progress = true;
            continue;
        }
        let at = c.body_sent;
        let want = (c.body - at).min(buf.len() as u64) as usize;
        for (k, b) in buf[..want].iter_mut().enumerate() {
            *b = ((at + k as u64) % 251) as u8;
        }
        let Ok(n) = c.s.write(&buf[..want]) else { return failed(c) };
        if n == 0 {
            return progress;
        }
        c.body_sent += n as u64;
        progress = true;
    }
    if c.close_after && !c.finished {
        c.s.finish();
        c.finished = true;
        progress = true;
    }
    // Read, and answer the next whole request.
    if !c.peer_done {
        match c.s.read(buf) {
            Ok(Read::Bytes(n)) => {
                c.input.extend_from_slice(&buf[..n]);
                progress = true;
            }
            Ok(Read::Empty) => {}
            Ok(Read::Closed(_)) | Err(_) => {
                c.peer_done = true;
                if !c.finished && !sending(c) {
                    c.s.finish();
                    c.finished = true;
                }
                progress = true;
            }
        }
    }
    if !sending(c)
        && !c.finished
        && let Some(end) = c.input.windows(4).position(|w| w == b"\r\n\r\n")
    {
        let request: Vec<u8> = c.input.drain(..end + 4).collect();
        answer(c, &request);
        *served += 1;
        // A line now and then: how far a test's load got (and when to act).
        if (*served).is_multiple_of(1000) {
            println!("httpd: {served} answers");
        }
        progress = true;
    } else if c.input.len() > HEAD {
        // A head longer than any client sends: answered and closed.
        c.input.clear();
        respond(c, 431, 0, true);
        progress = true;
    }
    progress
}

fn answer(c: &mut Conn, request: &[u8]) {
    let text = core::str::from_utf8(request).unwrap_or("");
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, path, version) = (first.next().unwrap_or(""), first.next().unwrap_or(""), first.next().unwrap_or(""));
    let mut close = version != "HTTP/1.1";
    for h in lines {
        if let Some((name, value)) = h.split_once(':')
            && name.trim().eq_ignore_ascii_case("connection")
        {
            close = value.trim().eq_ignore_ascii_case("close");
        }
    }
    if method != "GET" {
        return respond(c, 405, 0, true);
    }
    if path == "/quit" {
        c.quit = true;
        return respond(c, 200, 0, true);
    }
    match path.strip_prefix('/').and_then(|n| n.parse::<u64>().ok()) {
        Some(n) if n <= MOST => respond(c, 200, n, close),
        _ => respond(c, 404, 0, close),
    }
}

fn respond(c: &mut Conn, status: u16, body: u64, close: bool) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Request Header Fields Too Large",
    };
    let connection = if close { "close" } else { "keep-alive" };
    c.head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {body}\r\nContent-Type: application/octet-stream\r\nConnection: {connection}\r\n\r\n"
    )
    .into_bytes();
    c.head_sent = 0;
    c.body = body;
    c.body_sent = 0;
    c.close_after = close;
}
