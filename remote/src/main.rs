//! The remote management service (component D21): an owner on another
//! machine inspects, steers and updates this one.
//!
//! It listens on TCP port 22 (`silica.remote.Session`'s page is the wire;
//! `silica_remote` the framing) and answers only owners: a connection's
//! first message is a Noise IK handshake whose initiator key must be one
//! of the owners the machine was given (the boot archive's `remote.owners`),
//! sealed to this machine's key (`remote.key`). Anyone else is closed on
//! without an answer and said in the log. After the handshake every call
//! a session makes is the same IDL request a program here would make, and
//! goes on to the provider unchanged: channel 1 is the service manager
//! (`silica.system.Manager`), channel 2 the log (`silica.log.Reader`).
//! The service holds a capability to each, badged as itself; what a
//! session may do is exactly what this service may, and a request that
//! needs a capability is refused by its provider, which sees none. The
//! providers check every request as they check a local one: nothing a
//! session sends is trusted here beyond its framing.
//!
//! The log names who did what: every session's start and end with its
//! owner's name and address, and every call that changes the system
//! (stop, start, restart, update, revert, shutdown).
//!
//! Without a key or an owner, it says so and ends: remote management is
//! off on a machine that was not provisioned for it.
#![no_std]
#![no_main]

use silica_crypto::noise::{self, Keypair, Responder, Transport};
use silica_idl_rt::{CapList, Transport as _, TransportError};
use silica_net::tcp::{Read, Stream, Tcp};
use silica_protocols::remote::session;
use silica_protocols::system::manager;
use silica_remote::{Frames, MAX_FRAME, MAX_MESSAGE, PORT, PROLOGUE, Status, TAG};
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::sys::{self, Cap, Rights};
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

/// Grants, in the order the declaration's needs and files give them.
const TCP: u64 = slots::FIRST_GRANT;
const MANAGER: u64 = slots::FIRST_GRANT + 1;
const LOG: u64 = slots::FIRST_GRANT + 2;
const KEY_FILE: u64 = slots::FIRST_GRANT + 3;
const OWNERS_FILE: u64 = slots::FIRST_GRANT + 4;

/// The protocols a session carries, on channels 1 and 2.
const PROTOCOLS: [&str; 2] = [manager::NAME, silica_protocols::log::reader::NAME];
/// Sessions at once; a connection past them is closed at once.
const MAX_SESSIONS: usize = 8;
/// A connection that has not finished its handshake in this long is closed.
const HANDSHAKE: u64 = 10_000_000_000;
/// A session nothing arrived on for this long is closed.
const IDLE: u64 = 3_600_000_000_000;

enum State {
    /// Waiting for the owner's handshake message.
    Handshake,
    Open(Transport),
}

struct Session {
    s: Stream,
    id: u64,
    peer: String,
    /// The owner, once the handshake named one.
    owner: Option<usize>,
    state: State,
    /// What arrived and is not yet a whole message.
    input: Vec<u8>,
    /// What is to be sent, from `sent` on.
    output: Vec<u8>,
    sent: usize,
    /// When it was accepted, and when something last arrived.
    since: u64,
    last: u64,
    calls: u64,
    /// Closing: nothing more is read; it ends once its output is sent.
    closing: bool,
    done: bool,
}

/// What the service holds for every session.
struct Machine {
    key: Keypair,
    owners: Vec<([u8; 32], String)>,
    manager: Channel,
    log: Channel,
    /// The session whose program is being staged with the service manager:
    /// the service manager keeps one per caller, and every session calls as
    /// this service, so two sessions sending programs at once would mix
    /// them. The second is refused until the first's `update` is answered or
    /// its session ends.
    stager: Option<u64>,
}

fn main(_info: &'static ProcessInfo) -> i64 {
    let key = match read_file(KEY_FILE).as_deref().and_then(silica_remote::parse_key) {
        Some(k) => Keypair::new(k),
        None => {
            println!("remote: no machine key (the boot archive's remote.key): remote management is off");
            return 0;
        }
    };
    let mut owners = Vec::new();
    if let Some(text) = read_file(OWNERS_FILE) {
        for o in silica_remote::owners(&text) {
            match o {
                Ok((k, name)) => owners.push((k, String::from(name))),
                Err(silica_remote::BadLine(n)) => {
                    println!("ERROR: remote: line {n} of remote.owners is not a key and a name; remote management is off");
                    return 1;
                }
            }
        }
    }
    if owners.is_empty() {
        println!("remote: no owners (the boot archive's remote.owners): remote management is off");
        return 0;
    }
    let mut tcp = match Tcp::on(Cap(TCP), 20, slots::EVENTS, 32, 1) {
        Ok(t) => t,
        Err(e) => {
            println!("ERROR: remote: no TCP: {e:?}");
            return 1;
        }
    };
    let listener = match tcp.listen(PORT, 8) {
        Ok(l) => l,
        Err(e) => {
            println!("ERROR: remote: cannot listen on port {PORT}: {e:?}");
            return 1;
        }
    };
    println!(
        "remote: listening on port {PORT} for {} owner{}; this machine's key is {}",
        owners.len(),
        if owners.len() == 1 { "" } else { "s" },
        core::str::from_utf8(&silica_remote::key_text(&key.public)).unwrap_or("?")
    );
    let mut m = Machine { key, owners, manager: Channel::new(Cap(MANAGER)), log: Channel::new(Cap(LOG)), stager: None };
    let mut sessions: Vec<Session> = Vec::new();
    let mut next_id = 1u64;
    loop {
        let now = silica_rt::clock().now();
        let mut progress = false;
        loop {
            match tcp.accept(listener) {
                Ok(Some(s)) => {
                    progress = true;
                    let peer = s.peer.as_ref().map(|p| address(p.address, p.port)).unwrap_or_default();
                    let mut session = Session {
                        s,
                        id: next_id,
                        peer,
                        owner: None,
                        state: State::Handshake,
                        input: Vec::new(),
                        output: Vec::new(),
                        sent: 0,
                        since: now,
                        last: now,
                        calls: 0,
                        closing: false,
                        done: false,
                    };
                    next_id += 1;
                    if sessions.len() >= MAX_SESSIONS {
                        println!("remote: a connection from {} closed: {MAX_SESSIONS} sessions are open", session.peer);
                        session.close();
                    }
                    sessions.push(session);
                }
                Ok(None) => break,
                Err(silica_net::tcp::Failure::NoRoom) => break,
                Err(e) => {
                    println!("ERROR: remote: accept: {e:?}");
                    return 1;
                }
            }
        }
        for s in sessions.iter_mut() {
            progress |= s.step(&mut m, now);
        }
        // Ended: closed and sent, or broken.
        let mut i = 0;
        while i < sessions.len() {
            if sessions[i].done {
                let s = sessions.swap_remove(i);
                if m.stager == Some(s.id) {
                    m.stager = None;
                }
                if let Some(o) = s.owner {
                    println!("remote: {}'s session from {} ended after {} calls", m.owners[o].1, s.peer, s.calls);
                }
                let _ = tcp.close(s.s);
                progress = true;
            } else {
                i += 1;
            }
        }
        if progress {
            continue;
        }
        // Nothing moved: each session says what it waits for, then wait
        // until the first deadline.
        let mut may_sleep = true;
        let mut deadline = u64::MAX;
        for s in sessions.iter_mut() {
            if !s.closing && !s.s.sleep_read() {
                may_sleep = false;
            }
            if s.sent < s.output.len() && !s.s.sleep_write() {
                may_sleep = false;
            }
            deadline = deadline.min(s.deadline());
        }
        if may_sleep {
            let _ = tcp.wait((deadline != u64::MAX).then_some(deadline));
        }
    }
}

impl Session {
    fn deadline(&self) -> u64 {
        match self.state {
            State::Handshake => self.since + HANDSHAKE,
            State::Open(_) => self.last + IDLE,
        }
    }

    /// Send what is pending, then end.
    fn close(&mut self) {
        self.closing = true;
        self.input.clear();
    }

    /// Send, read and answer; whether anything moved.
    fn step(&mut self, m: &mut Machine, now: u64) -> bool {
        let mut progress = false;
        while self.sent < self.output.len() {
            match self.s.write(&self.output[self.sent..]) {
                Ok(0) => break,
                Ok(n) => {
                    self.sent += n;
                    progress = true;
                }
                Err(_) => {
                    self.done = true;
                    return true;
                }
            }
        }
        if self.sent == self.output.len() {
            self.output.clear();
            self.sent = 0;
            if self.closing && !self.done {
                self.s.finish();
                self.done = true;
                return true;
            }
        }
        if self.closing {
            return progress;
        }
        if now >= self.deadline() {
            match self.owner {
                Some(o) => println!("remote: {}'s session from {} closed: nothing for an hour", m.owners[o].1, self.peer),
                None => println!("remote: a connection from {} closed: no handshake within 10 s", self.peer),
            }
            self.close();
            return true;
        }
        // Read only while no answer waits to be sent: a peer that does not
        // read its answers is not served more.
        if self.output.is_empty() {
            let mut buf = [0u8; 4096];
            let room = (2 + MAX_FRAME).saturating_sub(self.input.len()).min(buf.len());
            match self.s.read(&mut buf[..room]) {
                Ok(Read::Bytes(n)) => {
                    self.input.extend_from_slice(&buf[..n]);
                    self.last = now;
                    progress = true;
                }
                Ok(Read::Empty) => {}
                Ok(Read::Closed(_)) | Err(_) => {
                    self.close();
                    return true;
                }
            }
        }
        // One whole message at a time: the owner waits for each answer.
        if self.output.is_empty() {
            match Frames::next(&self.input) {
                Ok(None) => {}
                Ok(Some((range, used))) => {
                    let mut frame = [0u8; MAX_FRAME];
                    let n = range.len();
                    frame[..n].copy_from_slice(&self.input[range]);
                    self.input.drain(..used);
                    self.message(m, &mut frame[..n]);
                    progress = true;
                }
                Err(silica_remote::BadLength(n)) => {
                    println!("remote: a connection from {} closed: a message of {n} bytes is not this protocol's", self.peer);
                    self.close();
                    progress = true;
                }
            }
        }
        progress
    }

    /// One whole message from the peer.
    fn message(&mut self, m: &mut Machine, frame: &mut [u8]) {
        match &mut self.state {
            State::Handshake => self.handshake(m, frame),
            State::Open(t) => {
                let Ok(n) = t.open(frame) else {
                    println!("remote: {}'s session from {} closed: a message did not open", self.who(m), self.peer);
                    return self.close();
                };
                let mut answer = [0u8; MAX_FRAME];
                let Some(len) = self.call(m, &frame[..n], &mut answer) else {
                    println!("remote: {}'s session from {} closed: a message is not a call", self.who(m), self.peer);
                    return self.close();
                };
                let State::Open(t) = &mut self.state else { return };
                if t.seal(&mut answer[..len + TAG]).is_err() {
                    return self.close();
                }
                self.send(&answer[..len + TAG]);
            }
        }
    }

    fn who<'m>(&self, m: &'m Machine) -> &'m str {
        self.owner.map_or("?", |o| m.owners[o].1.as_str())
    }

    fn send(&mut self, frame: &[u8]) {
        self.output.extend_from_slice(&Frames::length(frame.len()));
        self.output.extend_from_slice(frame);
    }

    fn handshake(&mut self, m: &mut Machine, frame: &mut [u8]) {
        let (r, payload) = match Responder::read(PROLOGUE, &m.key, frame) {
            Ok(r) => r,
            Err(e) => {
                println!("remote: a connection from {} closed: its handshake did not open ({e:?})", self.peer);
                return self.close();
            }
        };
        let Some(o) = m.owners.iter().position(|(k, _)| silica_crypto::equal(k, r.peer())) else {
            println!(
                "remote: a connection from {} closed: its key {} is no owner's",
                self.peer,
                core::str::from_utf8(&silica_remote::key_text(r.peer())).unwrap_or("?")
            );
            return self.close();
        };
        if payload != 0 {
            println!("remote: a connection from {} closed: its handshake carries a payload", self.peer);
            return self.close();
        }
        let mut e = [0u8; 32];
        silica_rt::random::fill(&mut e);
        let mut out = [0u8; noise::SECOND];
        match r.answer(e, &[], &mut out) {
            Ok((t, n)) => {
                self.send(&out[..n]);
                self.state = State::Open(t);
                self.owner = Some(o);
                println!("remote: {} connected from {}", m.owners[o].1, self.peer);
            }
            Err(e) => {
                println!("remote: a connection from {} closed: {e:?}", self.peer);
                self.close();
            }
        }
    }

    /// Answer the call in `plain` into `answer` (channel, status, reply);
    /// the answer's length, or `None` for a plaintext that is no call.
    fn call(&mut self, m: &mut Machine, plain: &[u8], answer: &mut [u8; MAX_FRAME]) -> Option<usize> {
        let (channel, request) = silica_remote::call(plain)?;
        if request.len() > MAX_MESSAGE {
            return None;
        }
        self.calls += 1;
        answer[0] = channel;
        let reply = &mut answer[2..2 + MAX_MESSAGE];
        let mut caps = CapList::new();
        let (status, n) = match channel {
            silica_remote::SESSION => (Status::Reply, session::dispatch(&mut SessionServer, request, CapList::new(), reply, &mut caps)),
            1 => {
                let ordinal = silica_idl_rt::request_ordinal(request).unwrap_or(0);
                if let Some(what) = changes(ordinal) {
                    let name = name_in(request).unwrap_or("?");
                    println!("remote: {} asks the service manager to {what} {name}", self.who(m));
                }
                let staging = ordinal == manager::StageRequest::ORDINAL || ordinal == manager::UpdateRequest::ORDINAL;
                if staging && m.stager.is_some_and(|s| s != self.id) {
                    // Another session is sending a program: refused, as
                    // the service manager would refuse what it cannot do.
                    let n = silica_idl_rt::encode_error_reply(reply, &mut caps, ordinal, manager::VERSION, &manager::Error::Refused)
                        .unwrap_or(0);
                    (Status::Reply, n)
                } else {
                    if staging {
                        m.stager = (ordinal == manager::StageRequest::ORDINAL).then_some(self.id);
                    }
                    forward(&mut m.manager, request, reply)
                }
            }
            2 => forward(&mut m.log, request, reply),
            _ => (Status::NoChannel, 0),
        };
        answer[1] = status as u8;
        Some(2 + n)
    }
}

/// Make the call `request` through `to`, its reply into `reply`.
fn forward(to: &mut Channel, request: &[u8], reply: &mut [u8]) -> (Status, usize) {
    let n = request.len();
    reply[..n].copy_from_slice(request);
    let mut caps = CapList::new();
    match to.call(reply, n, CapList::new(), &mut caps) {
        // A capability in a reply has nowhere to go: dropping it lets it go.
        Ok(m) => (Status::Reply, m),
        Err(TransportError::Revoked) => (Status::Revoked, 0),
        Err(_) => (Status::PeerGone, 0),
    }
}

/// The verb of a service manager call that changes the system, for the log.
fn changes(ordinal: u32) -> Option<&'static str> {
    Some(match ordinal {
        manager::StopRequest::ORDINAL => "stop",
        manager::StartRequest::ORDINAL => "start",
        manager::RestartRequest::ORDINAL => "restart",
        manager::UpdateRequest::ORDINAL => "update",
        manager::RevertRequest::ORDINAL => "revert",
        manager::ShutdownRequest::ORDINAL => "shut down",
        _ => return None,
    })
}

/// The service a call names: each of those methods' first parameter is the
/// service's name (`shutdown`'s is not, and names nothing).
fn name_in(request: &[u8]) -> Option<&str> {
    let ordinal = silica_idl_rt::request_ordinal(request).ok()?;
    macro_rules! named {
        ($($t:ident),*) => {
            $(if ordinal == manager::$t::ORDINAL {
                return silica_idl_rt::decode_request::<Handle, manager::$t<'_>>(request, CapList::new(), ordinal).ok().map(|r| r.name);
            })*
        };
    }
    named!(StopRequest, StartRequest, RestartRequest, UpdateRequest, RevertRequest);
    (ordinal == manager::ShutdownRequest::ORDINAL).then_some("the machine")
}

struct SessionServer;

impl session::Server<Handle> for SessionServer {
    fn protocols<'a>(&'a mut self) -> session::ProtocolsReply<'a, Handle> {
        session::ProtocolsReply { names: silica_idl_rt::Array::new(&PROTOCOLS) }
    }
}

/// A file the service manager gave in `slot` (`files=`): its text, up to
/// the first zero byte, or `None` for an empty slot or a file that is not
/// text.
fn read_file(slot: u64) -> Option<String> {
    let info = sys::inspect_slot(slots::SPACE, slot).ok()??;
    let region = silica_rt::mem::peer(Cap(slot), info.bits, Rights::READ).ok()?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 256];
    for at in (0..region.len()).step_by(chunk.len()) {
        region.read_bytes(at, &mut chunk);
        match chunk.iter().position(|b| *b == 0) {
            Some(end) => {
                bytes.extend_from_slice(&chunk[..end]);
                break;
            }
            None => bytes.extend_from_slice(&chunk),
        }
    }
    String::from_utf8(bytes).ok()
}

fn address(a: u32, port: u16) -> String {
    let [x, y, z, w] = a.to_be_bytes();
    silica_rt::alloc::format!("{x}.{y}.{z}.{w}:{port}")
}
