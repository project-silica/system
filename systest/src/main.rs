//! A root task that tests what programs can do to each other (the M2 exit
//! test's process-level items). It starts `stress` in its roles and prints
//! one `TEST <name> PASS` or `ERROR: systest: <name>: ...` line per test,
//! then `SYSTEST OK` when every test passed.
#![no_std]
#![no_main]

use libsys::root::RootInfo;
use libsys::{self as sys, Cap, Error, MsgInfo, ObjectType, Rights, Wait};
use silica_formats::ramdisk;
use silica_proc::root::{self, Root, finish};
use silica_proc::{Child, Grant, Program, report, spawn};
use silica_rt::ipc::{free_slot, release_slot};
use silica_rt::mem::Object;
use silica_rt::{EXIT_LABEL, print, println};

// The roles of `stress` (its first argument).
const SERVER: u64 = 0;
const CLIENT: u64 = 1;
const REVOKER: u64 = 2;
const HOG: u64 = 3;
const ONE_CALL: u64 = 4;
const TIME_WRITER: u64 = 5;
const TIME_READER: u64 = 6;

const SECOND: u64 = 1_000_000_000;
const SEND: Rights = Rights(Rights::WRITE.0 | Rights::GRANT.0);

struct Tests {
    root: Root,
    stress: &'static [u8],
    next_id: u64,
    /// What the running test has made, taken back when it ends.
    children: [Option<Child>; 16],
    caps: [Option<Cap>; 16],
    objects: [Option<Object>; 8],
    /// How long this machine took for a million round trips on one
    /// processor (0 until that test has run): its pace, which the limits
    /// on the tests after it follow ([`Tests::patience`]).
    pace: u64,
}

/// The pace the limits are sized for: a million round trips on one
/// processor took 14.4 s emulating aarch64 on the reference host
/// (2026-11-24), far less under KVM, where the limits stay as written. On a
/// hosted runner the same took 44 s, and the tests across processors up to
/// 31 times their time here: a limit that does not follow the machine fails
/// a slow run as if it were a hung one.
const REFERENCE_PACE_NS: u64 = 15 * SECOND;

/// How often a wait says it is still waiting (the harness ends a guest that
/// says nothing for a minute: `tools/qemu.sh --quiet`).
const SAY_NS: u64 = 10 * SECOND;

type Outcome = Result<(), &'static str>;

impl Tests {
    /// Start `stress` in `role` on processor `cpu` (modulo how many there
    /// are). Returns the program and the badge its exit report will carry.
    fn start(&mut self, role: u64, args: [u64; 2], cpu: u64, grants: &[Grant]) -> Result<(&Child, u64), &'static str> {
        self.start_with(role, [args[0], args[1], 0], cpu, grants)
    }

    /// [`Tests::start`] with a third argument (a client's: where its
    /// progress notification is among its grants).
    fn start_with(&mut self, role: u64, args: [u64; 3], cpu: u64, grants: &[Grant]) -> Result<(&Child, u64), &'static str> {
        self.next_id += 1;
        let place = self.children.iter_mut().find(|c| c.is_none()).ok_or("a test starts too many programs")?;
        let prog = Program {
            grants,
            args: [role, args[0], args[1], args[2], 0, 0, 0, 0],
            cpu: (cpu % self.root.parent.cpus) as usize,
            ..Program::new(self.stress, self.next_id)
        };
        let child = spawn(&self.root.parent, &prog).map_err(|e| {
            println!("systest:   spawn failed: {e:?}");
            "cannot start a program"
        })?;
        Ok((place.insert(child), self.next_id))
    }

    /// A limit written for the reference pace, for this machine's: longer
    /// in proportion where the machine is slower, never shorter.
    fn patience(&self, within: u64) -> u64 {
        // (In 128 bits: two times in nanoseconds multiplied pass 2^64.)
        let scaled = u128::from(within) * u128::from(self.pace.max(REFERENCE_PACE_NS)) / u128::from(REFERENCE_PACE_NS);
        u64::try_from(scaled).unwrap_or(u64::MAX)
    }

    /// The next exit report, as (badge, status), within `within` at the
    /// reference pace ([`Tests::patience`]), saying every [`SAY_NS`] that
    /// it still waits.
    fn next_exit(&self, within: u64) -> Result<(u64, i64), &'static str> {
        self.next_exit_watching(within, None)
    }

    /// [`Tests::next_exit`], where the programs signal `progress` as they
    /// get somewhere: then `within` is the longest without progress, not
    /// the longest in all, and a slow machine is told from a stuck one.
    fn next_exit_watching(&self, within: u64, progress: Option<Cap>) -> Result<(u64, i64), &'static str> {
        let limit = self.patience(within);
        let began = silica_rt::clock().now();
        let (mut moved, mut said, mut signals) = (began, began, 0u64);
        let m = loop {
            let now = silica_rt::clock().now();
            // Said every SAY_NS whatever woke it (progress wakes it often).
            if now - said >= SAY_NS {
                println!(
                    "systest:   waiting for its programs: {} s, the last progress {} s ago ({signals} signals; the limit {} s without)",
                    (now - began) / SECOND,
                    (now - moved) / SECOND,
                    limit / SECOND
                );
                said = now;
            }
            if now >= moved + limit {
                break None;
            }
            let until = (moved + limit).min(said + SAY_NS);
            let got = match progress {
                Some(p) => sys::recv_listening(self.root.parent.exit, p, Wait::Until(until)),
                None => sys::recv(self.root.parent.exit, Wait::Until(until)),
            };
            match got {
                Ok(m) if m.signals().is_some() => {
                    moved = silica_rt::clock().now();
                    signals += 1;
                }
                Ok(m) => break Some(m),
                Err(Error::Timeout) => {}
                Err(_) => break None,
            }
        };
        let Some(m) = m else {
            // Say where everyone is: the owner's first question.
            for c in self.children.iter().flatten() {
                match sys::inspect_thread(c.thread()) {
                    Ok(t) => println!(
                        "systest:   a program's thread: state {} on processor {}, ip {:#x}, waits on {:#x}",
                        t.state, t.cpu, t.ip, t.waits_on
                    ),
                    Err(e) => println!("systest:   a program's thread cannot be inspected: {e:?}"),
                }
            }
            return Err("a program did not finish in time (the lines above say where each one is)");
        };
        if m.info.label() != EXIT_LABEL {
            return Err("something other than an exit report arrived on the exit endpoint");
        }
        Ok((m.badge, m.words[0] as i64))
    }

    /// Keep `cap` (in a slot from the allocator) until the test ends.
    fn keep(&mut self, cap: Cap) -> Result<Cap, &'static str> {
        *self.caps.iter_mut().find(|c| c.is_none()).ok_or("a test makes too many capabilities")? = Some(cap);
        Ok(cap)
    }

    fn endpoint(&mut self) -> Result<Cap, &'static str> {
        self.object(ObjectType::Endpoint, 0)
    }

    fn notification(&mut self) -> Result<Cap, &'static str> {
        self.object(ObjectType::Notification, 0)
    }

    /// An object of type `ty` for the running test, destroyed when it ends.
    fn object(&mut self, ty: ObjectType, bits: u8) -> Result<Cap, &'static str> {
        let object = Object::new(ty, bits).map_err(|_| "cannot create a test object")?;
        let cap = object.cap();
        *self.objects.iter_mut().find(|o| o.is_none()).ok_or("a test makes too many objects")? = Some(object);
        Ok(cap)
    }

    /// End the programs and delete the capabilities the test made, however it ended.
    fn clean(&mut self) -> Outcome {
        let mut result = Ok(());
        for c in self.children.iter_mut().filter_map(Option::take) {
            if c.destroy().is_err() {
                result = Err("cannot take back a program's memory");
            }
        }
        // Newest first: a capability derived from an earlier one goes before it.
        for cap in self.caps.iter_mut().rev().filter_map(Option::take) {
            // SAFETY: made by the test that has ended; nothing else uses it.
            // (Deleting an empty slot is not an error.)
            #[allow(unsafe_code)]
            if unsafe { sys::cap_delete(cap) }.is_err() {
                result = Err("cannot delete a test's capability");
            }
            release_slot(cap.0);
        }
        for object in self.objects.iter_mut().filter_map(Option::take) {
            // SAFETY: made by the test that has ended; nothing else uses it.
            #[allow(unsafe_code)]
            unsafe {
                object.destroy()
            };
        }
        result
    }

    /// `pairs` clients each exchange `count` round trips with a server of
    /// their own; pair `i` runs on processors `cpus(i)`.
    fn round_trips(&mut self, pairs: u64, count: u64, cpus: impl Fn(u64) -> (u64, u64)) -> Outcome {
        let mut clients = [0u64; 8];
        // The clients signal it as they go (every 4096 round trips): the
        // limit is on a stretch without progress, not on the whole run. On
        // an emulated machine with fewer host processors than it has, a
        // round trip across processors waits for the host to schedule both
        // (four pairs on eight emulated processors, two host ones: over
        // eleven times one pair's time, 2026-11-24).
        let progress = self.notification()?;
        for i in 0..pairs {
            let ep = self.endpoint()?;
            let (server_cpu, client_cpu) = cpus(i);
            self.start(SERVER, [0, 0], server_cpu, &[Grant::lend(ep, Rights::READ)])?;
            let grants = [Grant::badged(ep, SEND, 1), Grant::lend(progress, Rights::WRITE)];
            (_, clients[i as usize]) = self.start_with(CLIENT, [count, 0, 1], client_cpu, &grants)?;
        }
        // Clients finish in any order.
        for _ in 0..pairs {
            let (who, status) = self.next_exit_watching(120 * SECOND, Some(progress))?;
            if !clients[..pairs as usize].contains(&who) {
                return Err("a server exited");
            }
            if status != 0 {
                return Err("a client lost or miscounted a round trip (its line above says which)");
            }
        }
        Ok(())
    }

    /// Round trips while the root task keeps moving both programs between
    /// processors: a move is invisible to the thread moved, even in the
    /// middle of a call, so the client loses and repeats nothing.
    fn moved_mid_call(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        let cpus = self.root.parent.cpus;
        let server = self.start(SERVER, [0, 0], 1, &[Grant::lend(ep, Rights::READ)])?.0.thread();
        let (client, id) = self.start(CLIENT, [200_000, 0], 2, &[Grant::badged(ep, SEND, 1)])?;
        let client = client.thread();
        let (start, mut moves) = (silica_rt::clock().now(), 0u64);
        let (limit, mut said) = (self.patience(120 * SECOND), start);
        loop {
            match sys::recv(self.root.parent.exit, Wait::Until(silica_rt::clock().now() + 50_000)) {
                Ok(m) if m.badge == id && m.words[0] == 0 => break,
                Ok(m) => {
                    println!("systest:   exit report from {} (client {id}, server {}): status {}", m.badge, id - 1, m.words[0] as i64);
                    return Err("the client lost or repeated a round trip, or the server exited (a line above says which)");
                }
                Err(Error::Timeout) => {}
                Err(_) => return Err("cannot receive exit reports"),
            }
            let now = silica_rt::clock().now();
            if now - start > limit {
                println!("systest:   the pair was moved {moves} times in {} s", limit / SECOND);
                return Err("the round trips did not finish in time (120 s at the reference pace)");
            }
            if now - said >= SAY_NS {
                println!("systest:   moving the pair: {moves} moves, {} s", (now - start) / SECOND);
                said = now;
            }
            moves += 1;
            for (thread, k) in [(client, 0), (server, 3)] {
                sys::thread_set_cpu(thread, ((moves + k) % cpus) as usize).map_err(|_| "cannot move a running program")?;
            }
        }
        println!("systest: the pair was moved {moves} times during its round trips");
        if moves < 10 { Err("the pair finished before it was moved often enough to test anything") } else { Ok(()) }
    }

    /// A million round trips while a third program takes the client's
    /// capability away and gives it back every 200 microseconds.
    fn revoke_and_regrant(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        self.start(SERVER, [0, 0], 1, &[Grant::lend(ep, Rights::READ)])?;
        let (client, id) = self.start(CLIENT, [1_000_000, 1], 2, &[])?;
        // The revoker's source is its own child of the endpoint, so revoking
        // it touches only what the revoker granted.
        let source = Grant::lend(ep, SEND);
        let space = Grant::lend(client.space(), Rights::ALL);
        self.start(REVOKER, [200_000, 0], 3, &[source, space])?;
        match self.next_exit(300 * SECOND)? {
            (who, 0) if who == id => Ok(()),
            (who, _) if who == id => Err("the client lost a round trip or was never revoked (its line above says which)"),
            _ => Err("the server or the revoker exited"),
        }
    }

    /// Create a 256-slot capability table and use its last slot. The block
    /// holding it must account for the size of each slot.
    fn object_storage(&mut self) -> Outcome {
        let space = Object::new(ObjectType::CapSpace, 8).map_err(|_| "cannot allocate a 256-slot CapSpace")?;
        let endpoint = self.endpoint()?;
        let copied = sys::cap_derive(space.cap(), 255, endpoint, Rights::READ, 0);
        // SAFETY: this table holds only the derived endpoint and nobody uses it.
        #[allow(unsafe_code)]
        unsafe {
            space.destroy()
        };
        copied.map_err(|_| "cannot use the last slot of the allocated CapSpace")
    }

    fn abandoned_time_page(&mut self) -> Outcome {
        let page = self.object(ObjectType::Frame, 12)?;
        let (_, writer) = self.start(TIME_WRITER, [0, 0], 0, &[Grant::lend(page, Rights(Rights::READ.0 | Rights::WRITE.0))])?;
        if self.next_exit(SECOND)? != (writer, 0) {
            return Err("writer failed before leaving the time page mid-update");
        }
        let (_, reader) = self.start(TIME_READER, [0, 0], 0, &[Grant::lend(page, Rights::READ)])?;
        if self.next_exit(SECOND)? != (reader, 0) {
            return Err("reader accepted an unfinished time update");
        }
        Ok(())
    }

    /// A program that uses up its memory gets an error; a pair running
    /// beside it is not affected, and the memory comes back with the program.
    fn exhaustion(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        self.start(SERVER, [0, 0], 1, &[Grant::lend(ep, Rights::READ)])?;
        let (_, client) = self.start(CLIENT, [200_000, 0], 2, &[Grant::badged(ep, SEND, 1)])?;
        let (_, hog) = self.start(HOG, [0, 0], 3, &[])?;
        for _ in 0..2 {
            match self.next_exit(60 * SECOND)? {
                (who, 0) if who == client || who == hog => {}
                (who, _) if who == hog => return Err("the program that ran out of memory did not get NoMemory"),
                _ => return Err("the pair beside the program that ran out of memory failed"),
            }
        }
        self.clean()?;
        // All of it is back: three more start and fill their memory again.
        for _ in 0..3 {
            self.start(HOG, [0, 0], 0, &[])?;
        }
        for _ in 0..3 {
            if self.next_exit(60 * SECOND)?.1 != 0 {
                return Err("after the memory came back, a program could not use it");
            }
        }
        Ok(())
    }

    /// The owner's view of a running program: every capability it holds and
    /// every thread with its state. A server waiting on an endpoint granted
    /// with a badge is listed holding that endpoint in its first grant slot
    /// and receiving on the very object the slot names.
    fn the_debug_console_lists_every_thread_and_capability(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        let (server, _) = self.start(SERVER, [0, 0], 1, &[Grant::lend(ep, Rights::READ)])?;
        let (thread, space) = (server.thread(), server.space());
        let until = silica_rt::clock().now() + 10 * SECOND;
        while sys::inspect_thread(thread).map(|t| t.state) != Ok(sys::THREAD_RECEIVING) {
            if silica_rt::clock().now() > until {
                return Err("the server never waited on its endpoint");
            }
            sys::yield_now();
        }
        let mut text = Text::new();
        let (caps, threads) = report(&mut text, "server", space).map_err(|_| "the report could not read the server")?;
        print!("{}", text.as_str());
        let ep_id = sys::inspect_slot(self.root.parent.space, ep.0).ok().flatten().ok_or("the endpoint is gone")?.object;
        let grant =
            sys::inspect_slot(space, silica_rt::slots::FIRST_GRANT).ok().flatten().ok_or("the server's first grant slot is empty")?;
        if grant.ty != ObjectType::Endpoint || grant.object != ep_id {
            return Err("the server's first grant is not the endpoint it was given");
        }
        let want_slot = format_args!("  slot {}: Endpoint rights r--- ", silica_rt::slots::FIRST_GRANT);
        let mut line = Text::new();
        let _ = core::fmt::Write::write_fmt(&mut line, want_slot);
        if !text.as_str().contains(line.as_str()) {
            return Err("the report does not list the granted endpoint with its rights");
        }
        let mut waiting = Text::new();
        let _ = core::fmt::Write::write_fmt(&mut waiting, format_args!("receiving on processor 1, at "));
        if threads != 1 || caps < 7 || !text.as_str().contains(waiting.as_str()) {
            return Err("the report does not show the one thread, receiving, with every capability");
        }
        let mut on = Text::new();
        let _ = core::fmt::Write::write_fmt(&mut on, format_args!("waiting on {ep_id:#x}"));
        if !text.as_str().contains(on.as_str()) {
            return Err("the report does not say which object the thread waits on");
        }
        Ok(())
    }

    /// A capability revoked in the middle of a call fails the call on both
    /// sides: the caller gets `Gone`, the server's reply `NoCaller`.
    fn revoked_mid_call(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        // The client's capability is derived from this one, not from `ep`
        // itself, so it can be revoked while this task keeps receiving.
        let lent = self.keep(Cap(free_slot().ok_or("the root CapSpace is full")?))?;
        sys::cap_derive(self.root.parent.space, lent.0, ep, SEND, 5).map_err(|_| "cannot derive the capability to lend")?;
        let (_, id) = self.start(ONE_CALL, [0, 0], 1, &[Grant::lend(lent, SEND)])?;
        let m = sys::recv(ep, Wait::Until(silica_rt::clock().now() + 10 * SECOND)).map_err(|_| "the call did not arrive")?;
        if (m.badge, m.words[0]) != (5, 41) {
            return Err("the call arrived with the wrong badge or word");
        }
        // The call is held, unanswered. Its capability goes.
        // SAFETY: the only capability derived from `lent` is the client's.
        #[allow(unsafe_code)]
        unsafe { sys::cap_revoke(lent) }.map_err(|_| "cannot revoke the lent capability")?;
        if self.next_exit(10 * SECOND)? != (id, Error::Gone as i64) {
            return Err("the caller's call did not fail with Gone");
        }
        if sys::reply(MsgInfo::new(0, 1), [42, 0, 0, 0]) != Err(Error::NoCaller) {
            return Err("the server's reply did not fail with NoCaller");
        }
        Ok(())
    }
}

/// Program entry, called by libsys's `_start`.
// SAFETY: the one definition of the symbol `_start` calls.
#[unsafe(no_mangle)]
extern "C" fn silica_main(info: &'static RootInfo, s0: u64, s1: u64, s2: u64, s3: u64) -> ! {
    // The boot secret: the four words after the record (libsys::root::secret).
    let secret = [s0, s1, s2, s3];
    let root = match root::start(info, secret) {
        Ok(r) => r,
        Err(e) => {
            println!("ERROR: systest: {e}");
            finish(false)
        }
    };
    let Some(stress) = ramdisk::find(root.archive, "stress") else {
        println!("ERROR: systest: the ramdisk has no program named stress");
        finish(false)
    };
    let cpus = root.parent.cpus;
    let mut t = Tests { root, stress, next_id: 0, children: [const { None }; 16], caps: [None; 16], objects: [const { None }; 8], pace: 0 };
    let mut failed = false;
    type Test = fn(&mut Tests) -> Outcome;
    let tests: [(&str, Test); 10] = [
        ("runtime_allocates_capspace_storage", Tests::object_storage),
        ("time_reader_survives_its_writer", Tests::abandoned_time_page),
        ("a_million_round_trips_on_one_processor", |t| t.round_trips(1, 1_000_000, |_| (1, 1))),
        ("a_million_round_trips_across_processors", |t| t.round_trips(1, 1_000_000, |_| (1, 2))),
        ("four_pairs_on_eight_processors", |t| t.round_trips(4, 250_000, |i| (2 * i, 2 * i + 1))),
        ("a_million_round_trips_while_the_capability_is_revoked_and_regranted", Tests::revoke_and_regrant),
        ("programs_moved_between_processors_mid_call_lose_nothing", Tests::moved_mid_call),
        ("running_out_of_memory_is_an_error_to_that_program_only", Tests::exhaustion),
        ("a_capability_revoked_mid_call_fails_the_call_on_both_sides", Tests::revoked_mid_call),
        ("the_debug_console_lists_every_thread_and_capability", Tests::the_debug_console_lists_every_thread_and_capability),
    ];
    println!("systest: {cpus} processors, {} tests", tests.len());
    for (name, test) in tests {
        let began = silica_rt::clock().now();
        // Whatever the test made is taken back before the next one starts.
        let outcome = test(&mut t).and(t.clean()).or_else(|e| t.clean().and(Err(e)).or(Err(e)));
        let took = silica_rt::clock().now() - began;
        if name == "a_million_round_trips_on_one_processor" && outcome.is_ok() {
            t.pace = took;
        }
        match outcome {
            Ok(()) => println!("TEST {name} PASS ({} ms)", took / 1_000_000),
            Err(why) => {
                println!("ERROR: systest: {name}: {why}");
                failed = true;
            }
        }
    }
    if failed {
        finish(false);
    }
    println!("SYSTEST OK");
    finish(true)
}

/// Text written with `write!` into a fixed buffer (the test has no heap).
struct Text {
    buf: [u8; 4096],
    len: usize,
}

impl Text {
    fn new() -> Text {
        Text { buf: [0; 4096], len: 0 }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl core::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}
