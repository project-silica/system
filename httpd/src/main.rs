//! A small HTTP/1.1 server over `silica.net.Tcp`, the first program on the
//! network stack's TCP (spec/MILESTONES.md, M4's exit test).
//!
//! `GET /<n>` answers `n` bytes (at most 16 MiB) whose byte `i` is
//! `i % 251`, so a client checks a body without being sent its hash;
//! `GET /quit` answers, and the server ends (status 0) once the client
//! has closed that connection, so the answer is never lost with the
//! server's memory, where the command line allows it (`httpd.quit=allowed`,
//! for a test that ends the server so); elsewhere it is answered 404, as
//! any other path, and said once. Connections are kept alive between
//! requests (HTTP/1.1) unless the request says `Connection: close` or is
//! HTTP/1.0, and let go of after a minute with nothing to read or send.
#![no_std]
#![no_main]

use silica_net::tcp::{Read, Stream, Tcp};
use silica_rt::alloc::format;
use silica_rt::alloc::vec::Vec;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

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
    /// When something was last read or sent: a connection idle for
    /// [`IDLE`] is closed (one that never sends again kept its place, and
    /// the stack's, for good).
    last: u64,
}

/// How long a connection may be idle.
const IDLE: u64 = 60_000_000_000;

/// Whether a refused `GET /quit` has been said.
static QUIT_REFUSED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn main(_info: &'static ProcessInfo) -> i64 {
    // On its events: the stack is its need 0 (bit 0), so a restart of the
    // stack is seen and its listener set up again; its own bits from 32.
    // 8 MiB lent: 128 connections (one for every 64 KiB, the stack's rule),
    // accepted, waiting to be, and let go of but not yet ended.
    let mut tcp = match Tcp::on(silica_rt::sys::Cap(slots::FIRST_GRANT), 23, slots::EVENTS, 32, 1) {
        Ok(t) => t,
        Err(e) => {
            println!("ERROR: httpd: no TCP: {e:?}");
            return 1;
        }
    };
    // On the port its declaration was given (`listen=<port>`).
    let (listener, port) = match tcp.listen(64) {
        Ok(l) => l,
        Err(e) => {
            println!("ERROR: httpd: cannot listen on the port it was given: {e:?}");
            return 1;
        }
    };
    println!("httpd: listening on port {port}");
    let quit_allowed = silica_rt::option("quit") == Some("allowed");
    let mut conns: Vec<Conn> = Vec::new();
    let mut buf = [0u8; 16384];
    // The body's bytes from any offset, as one slice: the pattern repeats
    // every 251 bytes. Computing them per write cost a division a byte,
    // spent again on every wake-up that found the stream with little room
    // (a reader paced to 50 MB/s kept a processor 74% busy, 2026-11-24).
    let pattern: Vec<u8> = (0..251 + buf.len()).map(|i| (i % 251) as u8).collect();
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
                        last: silica_rt::clock().now(),
                    });
                }
                Ok(None) => break,
                // Every block in use, or the stack short of room for one more:
                // the waiting ones wait, and are taken when this program next
                // looks (a refusal is a moment's shortage, not an end).
                Err(silica_net::tcp::Failure::NoRoom | silica_net::tcp::Failure::Refused(silica_net::tcp::Error::NoRoom)) => break,
                Err(e) => {
                    println!("ERROR: httpd: accept: {e:?}");
                    return 1;
                }
            }
        }
        let now = silica_rt::clock().now();
        for c in conns.iter_mut() {
            if step(c, &mut buf, &pattern, &mut served, quit_allowed) {
                c.last = now;
                progress = true;
            } else if now >= c.last + IDLE && !c.finished {
                // Idle for a minute: let go of, as a failed one is.
                progress |= failed(c);
            }
        }
        // Done with: the answer sent and finished. The stack sends the rest
        // and ends the connection, which stays this program's to pay for
        // until then and gives its place when this program needs it: a
        // peer that never reads its answer, or never finishes, holds
        // nothing here (before, each such connection kept its block for
        // good, and 64 of them shut the server). The one that asked the
        // server to end is kept until its peer has finished, so that the
        // answer is not lost with the server.
        let mut i = 0;
        while i < conns.len() {
            let c = &conns[i];
            if c.finished && (c.peer_done || !c.quit) {
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
            let next = conns.iter().filter(|c| !c.finished).map(|c| c.last + IDLE).min();
            let _ = tcp.wait(next);
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
fn step(c: &mut Conn, buf: &mut [u8], pattern: &[u8], served: &mut u64, quit_allowed: bool) -> bool {
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
        let from = (at % 251) as usize;
        let want = (c.body - at).min((pattern.len() - from) as u64) as usize;
        let Ok(n) = c.s.write(&pattern[from..from + want]) else { return failed(c) };
        if n == 0 {
            return progress;
        }
        c.body_sent += n as u64;
        progress = true;
    }
    // The answer is sent: end this side if asked to, or if the peer ended
    // its side while the answer was going out (it asks nothing more; before,
    // such a connection was kept for good).
    let more = c.input.windows(4).any(|w| w == b"\r\n\r\n");
    if !c.finished && (c.close_after || (c.peer_done && !more)) {
        c.s.finish();
        c.finished = true;
        progress = true;
    }
    // Read, and answer the next whole request. Not past a head's length
    // while an answer goes out: a pipelining client waits its turn.
    if !c.peer_done && (!sending(c) || c.input.len() <= HEAD) {
        match c.s.read(buf) {
            Ok(Read::Bytes(n)) => {
                if !c.finished {
                    c.input.extend_from_slice(&buf[..n]);
                }
                progress = true;
            }
            Ok(Read::Empty) => {}
            Ok(Read::Closed(_)) | Err(_) => {
                c.peer_done = true;
                progress = true;
            }
        }
    }
    if sending(c) || c.finished {
        return progress;
    }
    if let Some(end) = c.input.windows(4).position(|w| w == b"\r\n\r\n") {
        let request: Vec<u8> = c.input.drain(..end + 4).collect();
        answer(c, &request, quit_allowed);
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
    } else if c.peer_done {
        // FIN follows all the peer's requests, including those already in
        // input. Finish only after the last complete request was answered.
        c.s.finish();
        c.finished = true;
        progress = true;
    }
    progress
}

fn answer(c: &mut Conn, request: &[u8], quit_allowed: bool) {
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
    // Only where the boot options allow it (a test that ends the server
    // through it): otherwise any peer could stop the service.
    if path == "/quit" && quit_allowed {
        c.quit = true;
        return respond(c, 200, 0, true);
    }
    if path == "/quit" && !QUIT_REFUSED.swap(true, core::sync::atomic::Ordering::Relaxed) {
        // Said once: a peer asking again and again writes nothing more.
        println!("httpd: GET /quit refused: httpd.quit is not allowed on this machine");
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
