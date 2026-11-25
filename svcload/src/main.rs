//! Services killed under their clients' load (`spec/MILESTONES.md` M3:
//! every restartable component is killed under load and recovers inside its
//! deadline with nothing leaked).
//!
//! Each service that declares `restart=always` is restarted [`ROUNDS`] times
//! through `silica.system.Manager`'s `restart` (an abrupt end: its memory
//! and capabilities taken away at once, as a fault would), [`EVERY_NS`]
//! apart, while its clients use it:
//!
//! - `partitions`: this program keeps [`DEPTH`] reads in flight on a
//!   partition it opened (they go to the disk's driver, and must all
//!   succeed) and asks for the partition list between them;
//! - `logd`: this program writes numbered lines to its log the whole time;
//!   the harness checks that every one reached the console, and this
//!   program that the new log service has a line written after the restart;
//! - `console`: the shell is always in the middle of a call to it (waiting
//!   for a line), and this program asks it its size;
//! - `shell`: the console is always in the middle of answering it;
//! - `devmgr`: every driver is its child and ends with it, so the reads in
//!   flight on the partition lose their driver each time; the disk's
//!   client reconnects through it and sends them again.
//!
//! A recovery is the time from asking for the restart to the first call the
//! new instance answers; each must be under [`RECOVERY_NS`]. After all of
//! them, the shell has failed no time (a client that recovers does not end),
//! and the service manager can give out exactly as much memory as before
//! (`silica.system.Manager`'s `memory`): nothing leaked. Prints `SVCLOAD OK`.
#![no_std]
#![no_main]

use silica_block::client::{Disk, Error as DiskError};
use silica_block::{Op, Request};
use silica_protocols::console::terminal;
use silica_protocols::log::reader as log;
use silica_protocols::system::manager as system;
use silica_rt::alloc::format;
use silica_rt::alloc::string::String;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

/// Restarts of each service, and how far apart.
const ROUNDS: u32 = 10;
const EVERY_NS: u64 = 200_000_000;
/// The longest a recovery may take.
const RECOVERY_NS: u64 = 250_000_000;
/// Reads in flight on the partition.
const DEPTH: u64 = 16;
/// How often a numbered line is written while `logd` is restarted.
const LINE_NS: u64 = 5_000_000;

fn grant(n: u64) -> Cap {
    Cap(slots::FIRST_GRANT + n)
}

fn now() -> u64 {
    silica_rt::clock().now()
}

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => {
            println!("SVCLOAD OK");
            0
        }
        Err(e) => {
            println!("ERROR: svcload: {e}");
            1
        }
    }
}

struct Load {
    system: system::Client<Channel, Handle>,
    /// The slowest recovery of the service being restarted.
    slowest: u64,
}

impl Load {
    /// Restart `name`, then call `probe` until it answers: the recovery.
    fn restart(&mut self, name: &str, mut probe: impl FnMut() -> bool) -> Result<(), String> {
        let start = now();
        self.system.restart(name).map_err(|e| format!("restarting {name}: {e:?}"))?;
        let restarted = now() - start;
        while !probe() {
            if now() - start > RECOVERY_NS {
                break;
            }
            silica_rt::sys::yield_now();
        }
        // A probe that answers, but late, is as slow as one that does not.
        let took = now() - start;
        if took > RECOVERY_NS {
            return Err(format!(
                "{name} took {} ms to answer after its restart (the restart itself {} ms); the deadline is {} ms",
                took / 1_000_000,
                restarted / 1_000_000,
                RECOVERY_NS / 1_000_000
            ));
        }
        self.slowest = self.slowest.max(took);
        Ok(())
    }

    fn said(&mut self, name: &str) {
        println!("svcload: {name} restarted {ROUNDS} times under load; slowest recovery {} us", self.slowest / 1000);
        self.slowest = 0;
    }
}

/// This program's capability to the service manager carries `observe` and
/// `control` only (its declaration): everything else the protocol has is
/// refused, and the capability cannot be given more. Before (the 2026-11-24
/// audit), every holder could replace any service's program, turn the
/// machine off or take log slots: this check would have turned it off.
fn scopes_hold(system: &mut system::Client<Channel, Handle>) -> Result<(), String> {
    let refused = |what: &str, r: Result<(), system::Error>| match r {
        Err(system::Error::Refused) => Ok(()),
        other => Err(format!("{what} with observe+control+logs only: {other:?}, not refused")),
    };
    refused("stage", system.stage(0, b"\x7fELF").map(|_| ()).map_err(err))?;
    refused("update", system.update("httpd", 4).map(|_| ()).map_err(err))?;
    refused("revert", system.revert("httpd").map(|_| ()).map_err(err))?;
    refused("shutdown", system.shutdown(false).map(|_| ()).map_err(err))?;
    // The scopes are in the capability's badge, which the service manager
    // chose: a holder cannot derive itself one with more.
    let slot = silica_rt::ipc::free_slot().ok_or("no slot")?;
    let all = silica_protocols::scope::of(u64::MAX) << silica_protocols::scope::SHIFT;
    if silica_rt::sys::cap_derive(slots::SPACE, slot, grant(0), silica_rt::sys::Rights::WRITE, (1 << 32) | all).is_ok() {
        return Err(String::from("a capability to the service manager was given a badge of every scope by its holder"));
    }
    silica_rt::ipc::release_slot(slot);
    println!("svcload: the service manager refuses stage, update, revert and shutdown to a holder of observe+control+logs");
    Ok(())
}

/// One service asks for logs until it is refused: it gets at most half the
/// machine's (32 of 64), so the device manager restarted afterwards (the
/// `devmgr` round) still gets its drivers' logs. Before (the 2026-11-24
/// audit), the 64 were first come first served and never given back: one
/// holder could leave every later driver and service without a log.
fn logs_bounded(system: &mut system::Client<Channel, Handle>) -> Result<(), String> {
    let mut rings = silica_rt::alloc::vec::Vec::new();
    let mut given = 0;
    for n in 0..40 {
        let ring = Memory::new(silica_rt::log::BITS).map_err(|e| format!("no memory for a ring: {e:?}"))?;
        let lent = Handle::new(Cap(silica_rt::ipc::free_slot().ok_or("no slot")?));
        silica_rt::sys::cap_derive(slots::SPACE, lent.cap().0, ring.frame(), silica_rt::sys::Rights(3), 0)
            .map_err(|e| format!("deriving a ring: {e:?}"))?;
        match system.add_log(&format!("flood{n}"), lent) {
            Ok(_) => given += 1,
            Err(silica_idl_rt::CallError::Error(system::Error::Refused)) => break,
            Err(e) => return Err(format!("add_log {n}: {e:?}")),
        }
        rings.push(ring);
    }
    if given > 32 {
        return Err(format!("one service was given {given} logs, more than half of the machine's 64"));
    }
    println!("svcload: one service is given {given} logs and refused the next");
    // The rings stay this program's while it runs (their places stay taken).
    core::mem::forget(rings);
    Ok(())
}

/// A call's error, transport failures included, as the method's.
fn err(e: silica_idl_rt::CallError<system::Error>) -> system::Error {
    match e {
        silica_idl_rt::CallError::Error(e) => e,
        silica_idl_rt::CallError::Transport(_) => system::Error::Unknown(u32::MAX),
    }
}

fn run() -> Result<(), String> {
    let mut load = Load { system: system::Client::from(Channel::new(grant(0))), slowest: 0 };
    scopes_hold(&mut load.system)?;
    // What the service manager can give out and what its running services
    // hold: a service that ends by itself meanwhile (the remote service on
    // a machine without its keys, at boot) moves memory from one to the
    // other, and only a leak changes the sum.
    let total = |m: system::MemoryReply| m.free + m.held;
    let before = total(load.system.memory().map_err(|e| format!("memory: {e:?}"))?);
    logs_bounded(&mut load.system)?;
    partitions(&mut load)?;
    devmgr(&mut load)?;
    logd(&mut load)?;
    console(&mut load)?;
    shell(&mut load)?;
    // Every instance ended has given its memory back for the next.
    let after = total(load.system.memory().map_err(|e| format!("memory: {e:?}"))?);
    if after != before {
        return Err(format!("the service manager could give out or had given {before} bytes before the restarts and {after} after"));
    }
    let listed = load.system.list().map_err(|e| format!("list: {e:?}"))?;
    for s in listed.services.iter() {
        if s.failures != 0 {
            return Err(format!("{} failed {} times while the services under it restarted", s.name, s.failures));
        }
    }
    Ok(())
}

/// Reads of the partition's first blocks, [`DEPTH`] at a time, each sent
/// again as it completes.
struct Reads {
    disk: Disk,
    _buffer: Memory,
    done: u64,
}

impl Reads {
    fn new() -> Result<Reads, String> {
        let mut parts = silica_block::partitions::Client::<Channel, Handle>::from(Channel::new(grant(1)));
        let id = parts.list().map_err(|e| format!("partitions: {e:?}"))?.partitions.iter().next().map(|p| p.id);
        let id = id.ok_or("the disk has no partition to read")?;
        let mut disk = Disk::open_partition(grant(1), id).map_err(|e| format!("opening partition {id:#x}: {e:?}"))?;
        let buffer = Memory::new(16).map_err(|_| "no memory for the reads")?;
        disk.add_memory(0, &buffer, true).map_err(|e| format!("registering memory: {e:?}"))?;
        let mut reads = Reads { disk, _buffer: buffer, done: 0 };
        for tag in 0..DEPTH {
            reads.send(tag)?;
        }
        reads.disk.kick();
        Ok(reads)
    }

    fn send(&mut self, tag: u64) -> Result<(), String> {
        let r = Request { op: Op::Read, memory: 0, block: tag, offset: (tag * 512) as u32, blocks: 1, tag };
        self.disk.submit(&r).map_err(|e| format!("a read could not be sent: {e:?}"))
    }

    /// Take what completed and send it again.
    fn pump(&mut self) -> Result<(), String> {
        let mut sent = false;
        while let Some(c) = self.disk.poll().map_err(|e| format!("reading the partition: {e:?}"))? {
            c.status.map_err(|e| format!("a read of the partition failed: {e:?}"))?;
            self.done += 1;
            self.send(c.tag)?;
            sent = true;
        }
        if sent {
            self.disk.kick();
        }
        Ok(())
    }

    fn finish(mut self) -> Result<u64, String> {
        let deadline = now() + 5_000_000_000;
        while self.disk.in_progress() > 0 {
            match self.disk.wait(Some(deadline)) {
                Ok(c) => c.status.map_err(|e| format!("a read of the partition failed: {e:?}"))?,
                Err(DiskError::Timeout) => return Err(String::from("reads of the partition never finished")),
                Err(e) => return Err(format!("reading the partition: {e:?}")),
            }
            self.done += 1;
        }
        Ok(self.done)
    }
}

fn partitions(load: &mut Load) -> Result<(), String> {
    // Partitions is need 1 in this service's declaration. Check what an
    // existing client is told when the owner stops and starts its provider.
    let restarted = || silica_rt::sys::recv(slots::EVENTS, silica_rt::sys::Wait::Poll).is_ok_and(|m| m.badge & (1 << 1) != 0);
    load.system.stop("partitions").map_err(|e| format!("stopping partitions: {e:?}"))?;
    let _ = restarted();
    load.system.start("partitions").map_err(|e| format!("starting partitions: {e:?}"))?;
    if !restarted() {
        return Err(String::from("starting partitions did not notify its client"));
    }
    load.system.start("partitions").map_err(|e| format!("starting running partitions: {e:?}"))?;
    if restarted() {
        return Err(String::from("starting running partitions reported a second instance"));
    }
    let mut reads = Reads::new()?;
    let mut parts = silica_block::partitions::Client::<Channel, Handle>::from(Channel::new(grant(1)));
    for _ in 0..ROUNDS {
        let until = now() + EVERY_NS;
        while now() < until {
            reads.pump()?;
            parts.list().map_err(|e| format!("partitions, between restarts: {e:?}"))?;
        }
        let mut failed = None;
        load.restart("partitions", || {
            if let Err(e) = reads.pump() {
                failed = Some(e);
                return true;
            }
            parts.list().is_ok_and(|r| !r.partitions.is_empty())
        })?;
        if let Some(e) = failed {
            return Err(format!("{e} while the partitions service restarted"));
        }
    }
    let done = reads.finish()?;
    load.said("partitions");
    println!("svcload: {done} reads of the partition, every one completed");
    Ok(())
}

fn devmgr(load: &mut Load) -> Result<(), String> {
    use silica_protocols::device::manager as devices;
    let mut reads = Reads::new()?;
    let mut manager = devices::Client::<Channel, Handle>::from(Channel::new(grant(4)));
    for _ in 0..ROUNDS {
        let until = now() + EVERY_NS;
        while now() < until {
            reads.pump()?;
        }
        // What the old driver finished is taken first: a read counted
        // after the restart is one the new driver did.
        reads.pump()?;
        let mut failed = None;
        let before = reads.done;
        load.restart("devmgr", || {
            if let Err(e) = reads.pump() {
                failed = Some(e);
                return true;
            }
            reads.done > before && manager.list(devices::Class::Block).is_ok_and(|r| !r.devices.is_empty())
        })?;
        if let Some(e) = failed {
            return Err(format!("{e} while the device manager restarted"));
        }
    }
    let done = reads.finish()?;
    load.said("devmgr");
    println!("svcload: {done} reads of the partition across the device manager's restarts, every one completed");
    Ok(())
}

fn logd(load: &mut Load) -> Result<(), String> {
    let mut reader = log::Client::<Channel, Handle>::from(Channel::new(grant(2)));
    let mut line = 0u64;
    for round in 0..ROUNDS {
        let until = now() + EVERY_NS;
        while now() < until {
            println!("svcload: line {line}");
            line += 1;
            let next = now() + LINE_NS;
            while now() < next {
                silica_rt::sys::yield_now();
            }
        }
        // A line written after the restart, which the new instance must have.
        let mark = format!("svcload: after restart {round}");
        let expected = format!("?{mark}");
        let mut written = false;
        load.restart("logd", || {
            if !written {
                // The next line must remain readable through the log
                // protocol even if the preceding record is malformed.
                silica_rt::log::write(&[0xff]);
                println!("{mark}");
                written = true;
            }
            reader.read("svcload", 0).is_ok_and(|r| r.text.contains(expected.as_str()))
        })?;
    }
    load.said("logd");
    println!("svcload: {line} numbered lines written");
    Ok(())
}

fn console(load: &mut Load) -> Result<(), String> {
    let mut term = terminal::Client::<Channel, Handle>::from(Channel::new(grant(3)));
    let second = term.read_line().map_err(|e| format!("console: second reader: {e:?}"))?;
    if !second.busy || !second.line.is_empty() {
        return Err(format!("console: a second reader received a line while the shell was waiting: {:?}", second.line));
    }
    for _ in 0..ROUNDS {
        let until = now() + EVERY_NS;
        while now() < until {
            term.size().map_err(|e| format!("console, between restarts: {e:?}"))?;
        }
        load.restart("console", || term.size().is_ok())?;
    }
    load.said("console");
    Ok(())
}

fn shell(load: &mut Load) -> Result<(), String> {
    for _ in 0..ROUNDS {
        let until = now() + EVERY_NS;
        while now() < until {
            silica_rt::sys::yield_now();
        }
        let mut system = system::Client::<Channel, Handle>::from(Channel::new(grant(0)));
        load.restart("shell", || {
            system.list().is_ok_and(|r| r.services.iter().any(|s| s.name == "shell" && s.state == system::State::Running))
        })?;
    }
    load.said("shell");
    Ok(())
}
