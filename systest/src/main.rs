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
use silica_proc::{Child, Grant, spawn};
use silica_rt::ipc::{free_slot, release_slot};
use silica_rt::mem::Object;
use silica_rt::{EXIT_LABEL, println};

// The roles of `stress` (its first argument).
const SERVER: u64 = 0;
const CLIENT: u64 = 1;
const REVOKER: u64 = 2;
const HOG: u64 = 3;
const ONE_CALL: u64 = 4;

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
}

type Outcome = Result<(), &'static str>;

impl Tests {
    /// Start `stress` in `role` on processor `cpu` (modulo how many there
    /// are). Returns the program and the badge its exit report will carry.
    fn start(&mut self, role: u64, args: [u64; 2], cpu: u64, grants: &[Grant]) -> Result<(&Child, u64), &'static str> {
        self.next_id += 1;
        let place = self.children.iter_mut().find(|c| c.is_none()).ok_or("a test starts too many programs")?;
        let child =
            spawn(&self.root.parent, self.stress, 22, self.next_id, grants, [role, args[0], args[1], 0, 0, 0, 0, 0]).map_err(|e| {
                println!("systest:   spawn failed: {e:?}");
                "cannot start a program"
            })?;
        let child = place.insert(child);
        child.place((cpu % self.root.parent.cpus) as usize).map_err(|_| "cannot place a program on its processor")?;
        Ok((child, self.next_id))
    }

    /// The next exit report, as (badge, status).
    fn next_exit(&self, within: u64) -> Result<(u64, i64), &'static str> {
        let Ok(m) = sys::recv(self.root.parent.exit, Wait::Until(silica_rt::clock().now() + within)) else {
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
        let object = Object::new(ObjectType::Endpoint, 0).map_err(|_| "cannot create an endpoint")?;
        let cap = object.cap();
        *self.objects.iter_mut().find(|o| o.is_none()).ok_or("a test makes too many endpoints")? = Some(object);
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
        for i in 0..pairs {
            let ep = self.endpoint()?;
            let (server_cpu, client_cpu) = cpus(i);
            self.start(SERVER, [0, 0], server_cpu, &[Grant { cap: ep, rights: Rights::READ, badge: 0 }])?;
            (_, clients[i as usize]) = self.start(CLIENT, [count, 0], client_cpu, &[Grant { cap: ep, rights: SEND, badge: 1 }])?;
        }
        // Clients finish in any order.
        for _ in 0..pairs {
            let (who, status) = self.next_exit(120 * SECOND)?;
            if !clients[..pairs as usize].contains(&who) {
                return Err("a server exited");
            }
            if status != 0 {
                return Err("a client lost or miscounted a round trip (its line above says which)");
            }
        }
        Ok(())
    }

    /// A million round trips while a third program takes the client's
    /// capability away and gives it back every 200 microseconds.
    fn revoke_and_regrant(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        self.start(SERVER, [0, 0], 1, &[Grant { cap: ep, rights: Rights::READ, badge: 0 }])?;
        let (client, id) = self.start(CLIENT, [1_000_000, 1], 2, &[])?;
        // The revoker's source is its own child of the endpoint, so revoking
        // it touches only what the revoker granted.
        let source = Grant { cap: ep, rights: SEND, badge: 0 };
        let space = Grant { cap: client.space(), rights: Rights::ALL, badge: 0 };
        self.start(REVOKER, [200_000, 0], 3, &[source, space])?;
        match self.next_exit(300 * SECOND)? {
            (who, 0) if who == id => Ok(()),
            (who, _) if who == id => Err("the client lost a round trip or was never revoked (its line above says which)"),
            _ => Err("the server or the revoker exited"),
        }
    }

    /// A program that uses up its memory gets an error; a pair running
    /// beside it is not affected, and the memory comes back with the program.
    fn exhaustion(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        self.start(SERVER, [0, 0], 1, &[Grant { cap: ep, rights: Rights::READ, badge: 0 }])?;
        let (_, client) = self.start(CLIENT, [200_000, 0], 2, &[Grant { cap: ep, rights: SEND, badge: 1 }])?;
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

    /// A capability revoked in the middle of a call fails the call on both
    /// sides: the caller gets `Gone`, the server's reply `NoCaller`.
    fn revoked_mid_call(&mut self) -> Outcome {
        let ep = self.endpoint()?;
        // The client's capability is derived from this one, not from `ep`
        // itself, so it can be revoked while this task keeps receiving.
        let lent = self.keep(Cap(free_slot().ok_or("the root CapSpace is full")?))?;
        sys::cap_derive(self.root.parent.space, lent.0, ep, SEND, 5).map_err(|_| "cannot derive the capability to lend")?;
        let (_, id) = self.start(ONE_CALL, [0, 0], 1, &[Grant { cap: lent, rights: SEND, badge: 0 }])?;
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
extern "C" fn silica_main(info: &'static RootInfo) -> ! {
    let root = match root::start(info) {
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
    let mut t = Tests { root, stress, next_id: 0, children: [const { None }; 16], caps: [None; 16], objects: [const { None }; 8] };
    let mut failed = false;
    type Test = fn(&mut Tests) -> Outcome;
    let tests: [(&str, Test); 6] = [
        ("a_million_round_trips_on_one_processor", |t| t.round_trips(1, 1_000_000, |_| (1, 1))),
        ("a_million_round_trips_across_processors", |t| t.round_trips(1, 1_000_000, |_| (1, 2))),
        ("four_pairs_on_eight_processors", |t| t.round_trips(4, 250_000, |i| (2 * i, 2 * i + 1))),
        ("a_million_round_trips_while_the_capability_is_revoked_and_regranted", Tests::revoke_and_regrant),
        ("running_out_of_memory_is_an_error_to_that_program_only", Tests::exhaustion),
        ("a_capability_revoked_mid_call_fails_the_call_on_both_sides", Tests::revoked_mid_call),
    ];
    println!("systest: {cpus} processors, {} tests", tests.len());
    for (name, test) in tests {
        let began = silica_rt::clock().now();
        // Whatever the test made is taken back before the next one starts.
        let outcome = test(&mut t).and(t.clean()).or_else(|e| t.clean().and(Err(e)).or(Err(e)));
        match outcome {
            Ok(()) => println!("TEST {name} PASS ({} ms)", (silica_rt::clock().now() - began) / 1_000_000),
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
