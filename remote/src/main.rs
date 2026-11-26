//! The remote management service (component D21): an owner on another
//! machine inspects, steers and updates this one.
//!
//! It listens on TCP port 22 (`silica.remote.Session`'s page is the wire;
//! `silica_remote` the framing) and answers only owners: a connection's
//! first message is a Noise IK handshake whose initiator key must be one
//! of the owners the machine was given (the boot archive's `remote.owners`),
//! sealed to this machine's key (`remote.key`), and made later than every
//! first message taken from that owner before (`silica_remote::stamp`;
//! the newest time of each kept across this service's restarts in its kept
//! page), so a recorded one sent again is refused at once. Anyone else is
//! closed on without an answer and said in the log. A connection is an
//! owner's session only once its first sealed message opens: until then
//! (10 s at most) it holds one of eight places, two from any one address:
//! a connection that has not given an owner's handshake in its first
//! second gives its place to newer ones, the oldest first, and one an
//! owner's handshake was answered on never does (`make_room`). A session
//! is closed when no whole message has come for an hour
//! (or what that owner's line of `remote.owners` says: `idle=<seconds>`); bytes that
//! make no message keep nothing open.
//!
//! After the handshake every call a session makes is the same IDL request
//! a program here would make, and goes on to the provider unchanged:
//! channel 1 is the service manager (`silica.system.Manager`), channel 2
//! the log (`silica.log.Reader`). The service holds a capability to each,
//! badged as itself and scoped to what owners may do through it; each
//! owner may do what its line of `remote.owners` says (`observe`,
//! `control`, `update`, `power`, joined with `+`; all four when it says
//! none), and a call beyond it is refused here and said in the log. The
//! providers check every request as they check a local one: nothing a
//! session sends is trusted here beyond its framing. A program an owner
//! sends (`send`, a piece a call) is held here, in this service's own
//! memory, one for each owner, until that owner's `update`: the service
//! manager then lends memory for it (`program`), this service writes the
//! program there and passes the `update` on. The service manager holds
//! nothing an owner sent before that, and no owner waits for another.
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
use silica_protocols::scope;
use silica_protocols::system::manager;
use silica_remote::{Frames, MAX_FRAME, MAX_MESSAGE, PROLOGUE, Status, TAG};
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
/// Owners' sessions at once; a connection past them is closed at once.
const MAX_SESSIONS: usize = 8;
/// Connections not yet proven an owner's (no handshake, or one answered
/// that no authenticated message has followed) at once, and from one
/// address: a new one past them takes the place of the oldest, so nobody
/// who is not an owner can keep the owners out (eight idle connections
/// every ten seconds did, and so did a recorded handshake replayed).
const MAX_UNPROVEN: usize = 8;
const MAX_UNPROVEN_FROM_ONE: usize = 2;
/// A connection not proven an owner's in this long is closed.
const HANDSHAKE: u64 = 10_000_000_000;
/// How far behind this machine's clock an owner's first message may be
/// made (its clock may lag): older is a recording.
const STAMP_WINDOW: u64 = 300_000_000_000;
/// How long a new connection has to give an owner's handshake before a
/// newer one may take its place.
const GRACE: u64 = 1_000_000_000;
/// A session no whole message arrived on for this long is closed, unless
/// its owner's line of `remote.owners` sets another (`idle=<seconds>`): the
/// bound on a peer is given where the peer is named.
const IDLE: u64 = 3_600_000_000_000;

enum State {
    /// Waiting for the owner's handshake message.
    Handshake,
    Open(Transport),
}

struct Session {
    s: Stream,
    peer: String,
    /// The owner, once the handshake named one.
    owner: Option<usize>,
    /// The address it comes from.
    from: u32,
    /// An authenticated message has come since the handshake: the peer
    /// holds the handshake's keys, and is the owner (a first handshake
    /// message recorded and replayed is answered, but its sender cannot
    /// read the answer nor send one message that opens).
    proven: bool,
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
    /// Each owner's key, name, what of the service manager it may use
    /// (`silica_protocols::scope`), and how long its sessions may stay
    /// without a whole message ([`IDLE`], or its line's `idle=`).
    owners: Vec<([u8; 32], String, u64, u64)>,
    manager: Channel,
    log: Channel,
    /// The program each owner is sending (`send`), held here until that
    /// owner's `update` takes it or its last session ends: at most
    /// [`MAX_PROGRAM`] bytes an owner, and no more than this service's own
    /// memory holds.
    sending: Vec<silica_remote::Sending>,
    /// The time of the newest first message taken from each owner
    /// (`silica_remote::stamp`), kept in the page the service manager keeps
    /// across this service's restarts (`keep`): one taken before a restart
    /// is no more taken after it.
    newest: Vec<u64>,
    keep: Option<silica_rt::mmio::Mmio>,
}

/// The keep page: this word, the number of owners, then each one's newest
/// time. Another program (an update) is given a fresh page, and the times
/// start again from zero.
const KEPT: u64 = u64::from_be_bytes(*b"rmtnewst");

impl Machine {
    /// The newest times kept for `owners` owners, or zeros.
    fn kept(keep: Option<&silica_rt::mmio::Mmio>, owners: usize) -> Vec<u64> {
        match keep {
            Some(k) if k.read64(0) == KEPT && k.read64(8) == owners as u64 => {
                (0..owners).map(|o| if 16 + 8 * o + 8 <= k.len() { k.read64(16 + 8 * o) } else { 0 }).collect()
            }
            _ => silica_rt::alloc::vec![0; owners],
        }
    }

    /// A first message of owner `o` made at `made` was taken.
    fn took(&mut self, o: usize, made: u64) {
        self.newest[o] = made;
        if let Some(k) = &self.keep
            && 16 + 8 * o + 8 <= k.len()
        {
            k.write64(0, KEPT);
            k.write64(8, self.newest.len() as u64);
            k.write64(16 + 8 * o, made);
        }
    }
}

fn main(_info: &'static ProcessInfo) -> i64 {
    // The key's text is as secret as the key (`read_key` wipes it).
    let key = match read_key(KEY_FILE) {
        Some(mut k) => {
            let pair = Keypair::new(k);
            silica_crypto::wipe(&mut k);
            pair
        }
        None => {
            println!("remote: no machine key (the boot archive's remote.key): remote management is off");
            return 0;
        }
    };
    let mut owners = Vec::new();
    if let Some(text) = read_file(OWNERS_FILE) {
        for o in silica_remote::owners(&text) {
            match o {
                Ok((k, name, spec, idle)) => {
                    let all = scope::SYSTEM_OBSERVE | scope::SYSTEM_CONTROL | scope::SYSTEM_UPDATE | scope::SYSTEM_POWER;
                    let Ok(may) = spec.map_or(Ok(all), |s| scope::parse(manager::NAME, s)) else {
                        println!(
                            "ERROR: remote: {name} in remote.owners is given a scope the service manager does not have; remote management is off"
                        );
                        return 1;
                    };
                    owners.push((k, String::from(name), may & all, idle.map_or(IDLE, |s| s.saturating_mul(1_000_000_000))));
                }
                Err(silica_remote::BadLine(n)) => {
                    println!(
                        "ERROR: remote: line {n} of remote.owners is not an owner (a key, a name, then its scopes and idle=<seconds> if any); remote management is off"
                    );
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
    // On the port its declaration was given (`listen=<port>`).
    let (listener, port) = match tcp.listen() {
        Ok(l) => l,
        Err(e) => {
            println!("ERROR: remote: cannot listen on the port it was given: {e:?}");
            return 1;
        }
    };
    println!(
        "remote: listening on port {port} for {} owner{}; this machine's key is {}",
        owners.len(),
        if owners.len() == 1 { "" } else { "s" },
        core::str::from_utf8(&silica_remote::key_text(&key.public)).unwrap_or("?")
    );
    // No request loop of the runtime's: it serves from here.
    silica_rt::serving();
    // A page of 4 KiB, read and written one access at a time.
    let keep = silica_rt::mem::peer(slots::KEEP, 12, Rights(Rights::READ.0 | Rights::WRITE.0)).ok();
    let newest = Machine::kept(keep.as_ref(), owners.len());
    let sending = owners.iter().map(|_| silica_remote::Sending::default()).collect();
    let mut m = Machine { key, owners, manager: Channel::new(Cap(MANAGER)), log: Channel::new(Cap(LOG)), sending, newest, keep };
    let mut sessions: Vec<Session> = Vec::new();
    loop {
        let now = silica_rt::clock().now();
        let mut progress = false;
        loop {
            match tcp.accept(listener) {
                Ok(Some(s)) => {
                    progress = true;
                    let peer = s.peer.as_ref().map(|p| address(p.address, p.port)).unwrap_or_default();
                    let from = s.peer.as_ref().map_or(0, |p| p.address);
                    let mut session = Session {
                        s,
                        peer,
                        owner: None,
                        from,
                        proven: false,
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
                    if sessions.iter().filter(|s| s.proven && !s.closing).count() >= MAX_SESSIONS {
                        println!("remote: a connection from {} closed: {MAX_SESSIONS} sessions are open", session.peer);
                        session.close();
                    }
                    sessions.push(session);
                }
                Ok(None) => break,
                // Out of room, here or in the stack: the waiting ones wait.
                Err(silica_net::tcp::Failure::NoRoom | silica_net::tcp::Failure::Refused(silica_net::tcp::Error::NoRoom)) => break,
                Err(e) => {
                    println!("ERROR: remote: accept: {e:?}");
                    return 1;
                }
            }
        }
        for s in sessions.iter_mut() {
            progress |= s.step(&mut m, now);
        }
        progress |= make_room(&mut sessions, now);
        // Ended: closed and sent, or broken.
        let mut i = 0;
        while i < sessions.len() {
            if sessions[i].done {
                let s = sessions.swap_remove(i);
                if let Some(o) = s.owner {
                    println!("remote: {}'s session from {} ended after {} calls", m.owners[o].1, s.peer, s.calls);
                    // What the owner was sending goes with its last session.
                    if !sessions.iter().any(|other| other.owner == Some(o)) {
                        m.sending[o] = silica_remote::Sending::default();
                    }
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
            deadline = deadline.min(s.deadline(&m));
            // A stranger past its second may be closed for room (`make_room`).
            if !s.proven && matches!(s.state, State::Handshake) && s.since + GRACE > now {
                deadline = deadline.min(s.since + GRACE);
            }
        }
        if may_sleep {
            let _ = tcp.wait((deadline != u64::MAX).then_some(deadline));
        }
    }
}

/// Keep the connections not yet proven an owner's within their room, once
/// every one has been read: a connection that has given no owner's
/// handshake (a stranger, so far) and has had [`GRACE`] to give one gives
/// its place, the oldest first, while its address has more than
/// [`MAX_UNPROVEN_FROM_ONE`] such or all together more than
/// [`MAX_UNPROVEN`]. Younger ones wait their second (the stack bounds how
/// many there are), so a stream of newcomers cannot push out an owner's
/// connection before its first message is read; one whose owner's
/// handshake was answered (a fresh one: a replay is refused, `stamp`) is
/// the owner's, a round trip from proving it, and is never closed for room.
/// Whether any was closed.
fn make_room(sessions: &mut [Session], now: u64) -> bool {
    let stranger = |s: &Session| !s.proven && !s.closing && matches!(s.state, State::Handshake) && now >= s.since + GRACE;
    let mut closed = false;
    loop {
        let waiting = sessions.iter().filter(|s| !s.proven && !s.closing).count();
        let crowded = sessions
            .iter()
            .filter(|s| stranger(s))
            .map(|s| s.from)
            .find(|&a| sessions.iter().filter(|s| stranger(s) && s.from == a).count() > MAX_UNPROVEN_FROM_ONE);
        if crowded.is_none() && waiting <= MAX_UNPROVEN {
            return closed;
        }
        let Some(oldest) = sessions.iter_mut().filter(|s| stranger(s) && crowded.is_none_or(|a| s.from == a)).min_by_key(|s| s.since)
        else {
            return closed;
        };
        println!("remote: a connection from {} closed: newer ones need its place", oldest.peer);
        oldest.close();
        closed = true;
    }
}

impl Session {
    /// How long this session may stay without a whole message: its owner's.
    fn idle(&self, m: &Machine) -> u64 {
        self.owner.map_or(IDLE, |o| m.owners[o].3)
    }

    fn deadline(&self, m: &Machine) -> u64 {
        if self.proven { self.last.saturating_add(self.idle(m)) } else { self.since + HANDSHAKE }
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
        if now >= self.deadline(m) {
            if self.proven {
                println!("remote: {}'s session from {} closed: no message for {} s", self.who(m), self.peer, self.idle(m) / 1_000_000_000);
            } else {
                println!("remote: a connection from {} closed: no owner proven within 10 s", self.peer);
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
                    // Bytes alone keep nothing open: only a whole message that
                    // opens does (`message`).
                    self.input.extend_from_slice(&buf[..n]);
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
                    self.message(m, &mut frame[..n], now);
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
    fn message(&mut self, m: &mut Machine, frame: &mut [u8], now: u64) {
        match &mut self.state {
            State::Handshake => self.handshake(m, frame),
            State::Open(t) => {
                let Ok(n) = t.open(frame) else {
                    println!("remote: {}'s session from {} closed: a message did not open", self.who(m), self.peer);
                    return self.close();
                };
                self.last = now;
                if !self.proven {
                    self.proven = true;
                    println!("remote: {} connected from {}", self.who(m), self.peer);
                }
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
        let Some(o) = m.owners.iter().position(|(k, ..)| silica_crypto::equal(k, r.peer())) else {
            println!(
                "remote: a connection from {} closed: its key {} is no owner's",
                self.peer,
                core::str::from_utf8(&silica_remote::key_text(r.peer())).unwrap_or("?")
            );
            return self.close();
        };
        // Made after every first message taken from this owner: one seen
        // before, by anyone who saw it pass, opens nothing (`stamp`).
        let Some(made) = silica_remote::stamp_of(&frame[..payload]) else {
            println!("remote: a connection from {} closed: its handshake carries no time", self.peer);
            return self.close();
        };
        if made <= m.newest[o] {
            println!(
                "remote: a connection from {} closed: a handshake of {} made no later than the last taken from them (replayed, or their clock went back)",
                self.peer, m.owners[o].1
            );
            return self.close();
        }
        // Made long before this machine's clock: a recording, even when the
        // newest times were lost (the kept page is empty after a boot and
        // after this service's program changes), as long as the machine
        // knows the time. An owner's clock may lag it by `STAMP_WINDOW`.
        if let Some(wall) = silica_rt::time::now()
            && made.saturating_add(STAMP_WINDOW) < wall.ns
        {
            println!(
                "remote: a connection from {} closed: a handshake of {} made {} s before this machine's clock (replayed, or their clock is behind)",
                self.peer,
                m.owners[o].1,
                (wall.ns - made) / 1_000_000_000
            );
            return self.close();
        }
        m.took(o, made);
        let mut e = [0u8; 32];
        silica_rt::random::fill(&mut e);
        let mut out = [0u8; noise::SECOND];
        match r.answer(e, &[], &mut out) {
            Ok((t, n)) => {
                self.send(&out[..n]);
                // Not connected yet: whoever sent this first message may have
                // recorded it; the owner proves itself with its next.
                self.state = State::Open(t);
                self.owner = Some(o);
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
            silica_remote::SESSION => {
                let mut none = silica_remote::Sending::default();
                let (may, program) = match self.owner {
                    Some(o) => (m.owners[o].2, &mut m.sending[o]),
                    None => (0, &mut none),
                };
                (Status::Reply, session::dispatch(&mut SessionServer { may, program }, request, CapList::new(), reply, &mut caps))
            }
            1 => {
                let ordinal = silica_idl_rt::request_ordinal(request).unwrap_or(0);
                let may = self.owner.map_or(0, |o| m.owners[o].2);
                let refuse = |reply: &mut [u8], caps: &mut CapList<Handle>| {
                    silica_idl_rt::encode_error_reply(reply, caps, ordinal, manager::VERSION, &manager::Error::Refused).unwrap_or(0)
                };
                if scope_of(ordinal).is_none_or(|need| may & need != need) {
                    // Not what this owner may do (`remote.owners`), or not a
                    // call the remote service makes for anyone (`add_log`).
                    println!("remote: {} may not make call {ordinal} of the service manager", self.who(m));
                    let n = refuse(reply, &mut caps);
                    answer[1] = Status::Reply as u8;
                    return Some(2 + n);
                }
                if let Some(what) = changes(ordinal) {
                    let name = name_in(request).unwrap_or("?");
                    println!("remote: {} asks the service manager to {what} {name}", self.who(m));
                }
                // An update runs what this owner sent: written into memory
                // the service manager lends for it, in this one turn, so no
                // other session's update comes between the two calls. What
                // was sent is let go of whatever the answer.
                let lent = match self.owner {
                    Some(o) if ordinal == manager::UpdateRequest::ORDINAL => {
                        let program = core::mem::take(&mut m.sending[o]);
                        lend_program(&program, request)
                    }
                    _ => Ok(()),
                };
                match lent {
                    Ok(()) => forward(&mut m.manager, request, reply),
                    Err(e) => {
                        (Status::Reply, silica_idl_rt::encode_error_reply(reply, &mut caps, ordinal, manager::VERSION, &e).unwrap_or(0))
                    }
                }
            }
            // The log is what `observe` lets an owner see.
            2 if self.owner.is_some_and(|o| m.owners[o].2 & scope::SYSTEM_OBSERVE != 0) => forward(&mut m.log, request, reply),
            2 => (Status::Revoked, 0),
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

/// What an owner must be given to make the service manager call
/// `ordinal` (`remote.owners`); `None` for a call no owner makes through
/// this service.
fn scope_of(ordinal: u32) -> Option<u64> {
    Some(match ordinal {
        manager::ListRequest::ORDINAL | manager::DescribeRequest::ORDINAL | manager::MemoryRequest::ORDINAL => scope::SYSTEM_OBSERVE,
        manager::StartRequest::ORDINAL | manager::StopRequest::ORDINAL | manager::RestartRequest::ORDINAL => scope::SYSTEM_CONTROL,
        manager::StageRequest::ORDINAL | manager::UpdateRequest::ORDINAL | manager::RevertRequest::ORDINAL => scope::SYSTEM_UPDATE,
        manager::ShutdownRequest::ORDINAL => scope::SYSTEM_POWER,
        _ => return None,
    })
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

/// The largest program an owner sends: the largest the service manager
/// runs a service on.
const MAX_PROGRAM: u64 = 16 << 20;
/// What this service keeps of its own memory for its sessions and its
/// answers: a program an owner sends is given none of the last of it.
const RESERVE: u64 = 1 << 20;

/// Write the first bytes of `program` (as many as the `update` in
/// `request` names) into memory the service manager lends for them
/// (`program`), for the `update` that follows to run. `too_large` when the
/// owner sent fewer; a request that is no `update` is the service
/// manager's to refuse.
fn lend_program(program: &silica_remote::Sending, request: &[u8]) -> Result<(), manager::Error> {
    let ordinal = manager::UpdateRequest::ORDINAL;
    let Ok(update) = silica_idl_rt::decode_request::<Handle, manager::UpdateRequest<'_>>(request, CapList::new(), ordinal) else {
        return Ok(());
    };
    let length = usize::try_from(update.length).map_err(|_| manager::Error::TooLarge)?;
    let parts = program.parts(length).ok_or(manager::Error::TooLarge)?;
    let mut system = manager::Client::<Channel, Handle>::from(Channel::new(Cap(MANAGER)));
    let memory = match system.program(update.length) {
        Ok(r) => r.memory,
        Err(silica_idl_rt::CallError::Error(e)) => return Err(e),
        Err(_) => return Err(manager::Error::Refused),
    };
    let bits = sys::inspect_slot(slots::SPACE, memory.cap().0).ok().flatten().ok_or(manager::Error::Refused)?.bits;
    let lent =
        silica_rt::mem::Lent::map(memory.cap(), bits, Rights(Rights::READ.0 | Rights::WRITE.0)).map_err(|_| manager::Error::Refused)?;
    if lent.region().len() < length {
        return Err(manager::Error::Refused);
    }
    for (at, part) in parts {
        lent.region().write_bytes(at, part);
    }
    Ok(())
}

/// A session's own calls: `may` is what its owner may do, `program` what
/// that owner is sending.
struct SessionServer<'a> {
    may: u64,
    program: &'a mut silica_remote::Sending,
}

impl session::Server<Handle> for SessionServer<'_> {
    fn protocols<'a>(&'a mut self) -> session::ProtocolsReply<'a, Handle> {
        session::ProtocolsReply { names: silica_idl_rt::Array::new(&PROTOCOLS) }
    }

    fn send(&mut self, at: u64, data: &[u8]) -> Result<session::SendReply, session::Error> {
        if self.may & scope::SYSTEM_UPDATE == 0 {
            return Err(session::Error::NotAllowed);
        }
        if at == 0 {
            // Another program: the last one's memory goes first.
            *self.program = silica_remote::Sending::default();
        }
        // Held in this service's own memory (its declaration's), down to
        // what it keeps for itself: never in the service manager's.
        if at.saturating_add(data.len() as u64) > self.program.room() as u64 && silica_rt::mem::available() < RESERVE {
            return Err(session::Error::NoRoom);
        }
        match self.program.write(at, data, MAX_PROGRAM) {
            Ok(()) => Ok(session::SendReply {}),
            Err(silica_remote::NotKept::TooLarge) => Err(session::Error::TooLarge),
            Err(silica_remote::NotKept::NoRoom) => Err(session::Error::NoRoom),
        }
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
/// The machine's key from the file in `slot` (`remote.key`): its 64
/// hexadecimal digits, read into a buffer of this function's that is wiped
/// before it returns, the file's mapping let go of with it. (The text was
/// read into a growing string before, every copy of it left behind.)
fn read_key(slot: u64) -> Option<[u8; 32]> {
    let info = sys::inspect_slot(slots::SPACE, slot).ok()??;
    let lent = silica_rt::mem::Lent::map(Cap(slot), info.bits, Rights::READ).ok()?;
    let region = lent.region();
    let mut text = [0u8; 128];
    let n = text.len().min(region.len());
    region.read_bytes(0, &mut text[..n]);
    let end = text[..n].iter().position(|b| *b == 0).unwrap_or(n);
    let key = core::str::from_utf8(&text[..end]).ok().and_then(silica_remote::parse_key);
    silica_crypto::wipe(&mut text);
    drop(lent);
    key
}
