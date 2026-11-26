//! The root task and service manager (components D01, D02).
//!
//! The kernel starts this one program and gives it every capability there
//! is. It starts the system as the boot archive's `services` list declares
//! it (`manifest`): each service with the memory and capabilities it is
//! meant to have and no more, providers before what needs them, every
//! provided protocol's endpoint made and kept here so that clients'
//! capabilities to it outlive the service's instances. It takes back the
//! memory of every program that ends and starts again the services that
//! ask to be (`restart=always`).
//!
//! It provides `silica.system.Manager` on the endpoint its programs report
//! their exits on (callers' badges are from 2^32 up, programs' below):
//! the services and what they do, stopping and starting one, and turning
//! the machine off in order (`shutdown`: services stopped last-started
//! first, then the power). It makes the log's rings: one per service, and
//! one per program a service asks for (`add_log`), which the log service
//! finds in its directory (`silica_rt::log::directory`).
//!
//! The kernel command line chooses what is checked at boot (`checks=`, a
//! comma list; default `programs,block`): `programs` runs the round trips
//! everything rests on (a program's memory comes back, two programs talk
//! through a protocol), `spawn` measures starting a program, and every
//! other name runs the services declared
//! `start=check:<name>`, which must end with status 0. When checks ran, the
//! machine is turned off when they are done (`halt=reboot`: reset);
//! without them the system stays up. `off=` (a comma list of service
//! names) keeps those boot services from starting, as if stopped: what an
//! owner does to boot without a service (and what a driver's own check
//! does to have its device to itself); `start <name>` starts one later.
//! `bench` on the command line prints
//! `BENCH DONE` when the checks are done (`tools/bench.sh` reads up to it).
#![no_std]
#![no_main]

mod manifest;

use core::sync::atomic::{AtomicU64, Ordering};
use libsys::root::{KIND_DEVICE, KIND_FIRMWARE, RootInfo, SLOT_DEVICES, SLOT_FIRST_UNTYPED, SLOT_INFO, SLOT_IRQS};
use libsys::{self as sys, ObjectType, Rights, Wait};
use manifest::{Cpu, Service, Start};
use silica_formats::ramdisk;
use silica_proc::root::{self, Root, finish};
use silica_proc::{Child, FAULT_BADGE, Grant, Program, Restarts, spawn};
use silica_protocols::device::manager as devices;
use silica_protocols::scope;
use silica_protocols::system::manager;
use silica_protocols::watchdog::device as watchdog;
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle, Listener};
use silica_rt::log::directory;
use silica_rt::mem::Object;
use silica_rt::{EXIT_LABEL, PROBE_LABEL, UNANSWERED_LABEL, println};

macro_rules! fail {
    ($($a:tt)*) => {{
        flush_log();
        silica_rt::print!("ERROR: init: ");
        println!($($a)*);
        finish(false)
    }};
}

/// The log service's notification, badged [`FLUSH`], and the notification it
/// answers a flush on (0: no log service).
static FLUSH_TO: AtomicU64 = AtomicU64::new(0);
static FLUSHED: AtomicU64 = AtomicU64::new(0);
/// The bit of the log's notification that asks it to flush (`logd`).
const FLUSH: u64 = 2;
/// The bit of the log's notification that says logs were added (`add_log`).
const ADDED: u64 = 4;
/// The most logs services give their programs (`add_log`), half of them at
/// most to any one service.
const MAX_LOGS: usize = 64;

/// Whether the ring `h` names is still there: one whose maker ended is gone,
/// and every capability derived from it with it.
fn alive(h: &Handle) -> bool {
    matches!(sys::inspect_slot(sys::Cap(libsys::root::SLOT_CAPSPACE), h.cap().0), Ok(Some(_)))
}

/// The longest init waits for the log service to answer a flush.
const FLUSH_WAIT: u64 = 2_000_000_000;

/// Have the log service put everything its rings hold on the console before
/// what init says next: a failure, a check's verdict, `BOOT OK`, and the
/// machine turning off, after which nothing in a ring would reach the
/// console. Init waits for the answer, which normally comes at once, at
/// most [`FLUSH_WAIT`] so that a log service that hangs cannot hang
/// shutdown; if it does not come, init says so, so that missing lines are
/// never missing silently. (200 ms was too short: on a loaded host half of
/// 48 boots of the entropy check lost a service's last lines at power-off,
/// 2026-11-23.)
fn flush_log() {
    let (to, done) = (FLUSH_TO.load(Ordering::Relaxed), FLUSHED.load(Ordering::Relaxed));
    if to == 0 {
        return;
    }
    // A late answer to an earlier flush is not this one's.
    let _ = sys::recv(sys::Cap(done), Wait::Poll);
    if sys::signal(sys::Cap(to)).is_ok() && sys::recv(sys::Cap(done), Wait::Until(silica_rt::clock().now() + FLUSH_WAIT)).is_err() {
        println!("init: the log service did not put its text on the console within 2 s: services' last lines may be missing");
    }
}

const SECOND: u64 = 1_000_000_000;
/// Badges of consumers' capabilities to a provider start here.
const CONSUMERS: u64 = 1 << 32;
/// Service `i` runs with the program identifier `SERVICE_IDS + i`.
const SERVICE_IDS: u64 = 1000;
/// How long a provider has to answer the service manager's probe after a
/// client reported it unanswered (`Manager::unanswered`): its runtime
/// answers from its request loop, so only a provider that takes no calls
/// at all, for longer than a driver is given (`DRIVER_CALL_LIMIT`), misses it.
const PROBE_LIMIT: u64 = 2 * SECOND;
/// How long after it answered a probe a provider is not asked again.
const PROBE_QUIET: u64 = 5 * SECOND;
/// The status `after` is given for a provider ended because it stopped
/// answering (no program exits with it).
const HUNG: i64 = i64::MIN + 1;
/// How long an updated service's new program is on trial: failing within
/// it puts the program before it back (`update`).
const TRIAL: u64 = 10 * SECOND;
/// How long a service asked to end as the machine turns off has to exit
/// (`Manager::end_in_order`): longer than the device manager gives its
/// drivers.
const END_WAIT: u64 = 10 * SECOND;
/// The largest program `update` takes, and the most all callers may have
/// staged at once.
const MAX_PROGRAM: u64 = 16 << 20;
const MAX_STAGED: usize = 32 << 20;

/// A service and what it is now.
struct Running {
    child: Option<Child>,
    /// What it was given outright, to take back before it goes: each as
    /// the slot in its CapSpace and the slot in this one it came from
    /// (a machine service's device memory and firmware tables).
    given: Vec<(u64, u64)>,
    /// How many times it was started: what its seed is derived for.
    starts: u64,
    /// When it failed and when it is started again (`restart=always`).
    restarts: Restarts,
    /// When it last answered the service manager's probe (`unanswered`).
    answered_at: u64,
    /// Stopped by the owner: not started again until asked.
    stopped: bool,
    /// The program it runs, when an `update` gave it one; `None`: the boot
    /// archive's.
    program: Option<Vec<u8>>,
    /// An update on trial: the program to go back to if the new one fails
    /// (`None` inside: the archive's), and when the trial ends (0: the new
    /// program has not started yet; the trial starts when it does).
    trial: Option<(Option<Vec<u8>>, u64)>,
    /// The BLAKE2s-256 of its program, once asked for (`list`).
    hash: Option<&'static [u8; 32]>,
    /// The boot archive's files it is given (`files=`), each in a frame of
    /// its own made once.
    files: Vec<Option<silica_rt::mem::Memory>>,
}

/// The machine's hardware watchdog (`silica.watchdog.Device`), which the
/// service manager alone pets, from its own loop: when it stops (the
/// service manager or the kernel hung) the machine is reset. The device
/// manager says when one appears (`watch`, on `note`), so nothing polls; a
/// machine without one wakes nothing for it.
#[derive(Default)]
struct Watchdog {
    /// The device manager, called with the watchdog's scope, which no
    /// declaration can name (`silica_protocols::scope::DEVICE_WATCHDOG`).
    devices: Option<devices::Client<Channel, Handle>>,
    /// What the device manager signals when a watchdog comes or goes.
    note: Option<Object>,
    /// The watchdog's driver, once found.
    driver: Option<watchdog::Client<Channel, Handle>>,
    /// When to pet it next (monotonic ns), and how often.
    next: u64,
    every: u64,
    /// Whether the absence of one was said.
    said_none: bool,
    /// When to ask the device manager again (0: not), how long the wait
    /// after that one is, and since when it has been asked.
    retry: u64,
    wait: u64,
    since: u64,
}

struct Manager {
    root: Root,
    info: &'static RootInfo,
    services: Vec<Service>,
    /// The endpoint of each service that provides a protocol.
    endpoints: Vec<Option<Object>>,
    running: Vec<Running>,
    /// Each service's own notification (`slots::EVENTS`), the same object
    /// for every start of it, and a capability to signal it for each of
    /// its needs (badge bit `n`: the provider of need `n` started again).
    events: Vec<(Object, Vec<Handle>)>,
    /// The page each service that `keeps` is given at every start.
    kept: Vec<Option<Object>>,
    /// Each service's group (`libsys::sched_group`), the same for every
    /// start of it: its threads share one share of its processor however
    /// many it makes, and the programs it starts are in it too.
    groups: Vec<Object>,
    /// The time page (`silica_rt::time`), set from the firmware's clock.
    time: silica_rt::mem::Memory,
    /// Each service's options: the boot command line's
    /// `<service>.<key>=<value>` words, as `<key>=<value>`.
    options: Vec<Vec<u8>>,
    /// The order services were started in, for stopping them in reverse.
    order: Vec<usize>,
    /// The processor each service runs on (`place`).
    placed: Vec<usize>,
    /// What `list` answers with, rebuilt for each call.
    listed: Vec<manager::Service<'static>>,
    /// What `describe` answers with.
    described: String,
    /// The badge of the call being answered.
    caller: u64,
    /// The program each caller is sending (`stage`), by its badge.
    staged: Vec<(u64, Vec<u8>)>,
    /// Every program hash `list` has shown, each kept once: what a
    /// service's `hash` points at (a reply borrows it). One per distinct
    /// program the system ran, 32 bytes each.
    hashes: Vec<&'static [u8; 32]>,
    /// The log: the service that provides it, its notification, what it
    /// answers flushes on, and a ring per service (`silica_rt::log`).
    log: Option<LogSetup>,
    /// The machine's hardware watchdog, once the device manager has it.
    dog: Watchdog,
}

struct LogSetup {
    service: usize,
    note: Object,
    flushed: Object,
    rings: Vec<Option<Object>>,
    /// The note, badged [`ADDED`].
    added: sys::Cap,
    /// The logs services gave their programs (`add_log`): the source's
    /// name and the ring.
    given: Vec<(String, Handle)>,
    /// The ring directory (`silica_rt::log::directory`): entry `i` names
    /// service `i`'s ring, entry `services + k` the `k`th given one.
    directory: silica_rt::mem::Memory,
}

/// The value of `key=` on the command line.
fn option(cmdline: &'static [u8], key: &str) -> Option<&'static [u8]> {
    cmdline.split(|b| b.is_ascii_whitespace()).find_map(|w| w.strip_prefix(key.as_bytes())?.strip_prefix(b"="))
}

impl Manager {
    /// The capabilities service `i` starts with, and its arguments.
    fn grants(&self, i: usize) -> Result<(Vec<Grant>, [u64; 8]), &'static str> {
        let s = &self.services[i];
        let mut grants = Vec::new();
        let mut args = [0u64; 8];
        // First, when it provides a protocol: its own endpoint, to receive
        // on (and to give its children a way to report, as the device
        // manager does).
        if let Some(ep) = &self.endpoints[i] {
            grants.push(Grant::lend(ep.cap(), Rights::ALL));
        }
        // Then what it needs, a capability badged for it to each provider.
        for (n, need) in s.needs.iter().enumerate() {
            let ep = if *need == manifest::ROOT_PROTOCOL {
                self.root.parent.exit
            } else {
                let p = self.services.iter().position(|p| p.provides == Some(*need)).ok_or("a need with no provider")?;
                self.endpoints[p].as_ref().ok_or("a provider without an endpoint")?.cap()
            };
            let scopes = s.scopes.get(n).copied().unwrap_or(0) << silica_protocols::scope::SHIFT;
            grants.push(Grant::badged(ep, Rights(Rights::WRITE.0 | Rights::GRANT.0), CONSUMERS | scopes | i as u64));
        }
        // The archive's files it is given, read-only, after its needs.
        for f in &self.running[i].files {
            grants.push(match f {
                Some(m) => Grant::lend(m.frame(), Rights::READ),
                None => Grant::none(),
            });
        }
        if let Some(log) = self.log.as_ref().filter(|l| l.service == i) {
            // The notification, the flush's answer, the directory, then a
            // slot for each ring the directory can name (`log_slot`): the
            // services' and those given so far; `add_log` fills the rest.
            debug_assert_eq!(grants.len() as u64, self.log_grants());
            grants.push(Grant::lend(log.note.cap(), Rights::ALL));
            grants.push(Grant::lend(log.flushed.cap(), Rights::WRITE));
            grants.push(Grant::lend(log.directory.frame(), Rights::READ));
            let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
            for r in &log.rings {
                grants.push(match r {
                    Some(f) => Grant::lend(f.cap(), rw),
                    None => Grant::none(),
                });
            }
            for k in 0..MAX_LOGS {
                grants.push(match log.given.get(k) {
                    Some((_, ring)) if alive(ring) => Grant::lend(ring.cap(), rw),
                    _ => Grant::none(),
                });
            }
            args[0] = (log.rings.len() + MAX_LOGS) as u64;
        }
        if s.machine {
            let info = self.info;
            grants.push(Grant::lend(sys::Cap(SLOT_INFO), Rights::READ));
            grants.push(Grant::lend(sys::Cap(SLOT_DEVICES), Rights::ALL));
            grants.push(Grant::lend(sys::Cap(SLOT_IRQS), Rights::ALL));
            // The I/O ports, on a machine that has them (x86_64).
            let has_ports = matches!(sys::inspect_slot(sys::Cap(libsys::root::SLOT_CAPSPACE), self.root.ports.0), Ok(Some(_)));
            grants.push(if has_ports { Grant::lend(self.root.ports, Rights::ALL) } else { Grant::none() });
            grants.extend(self.root.ramdisk.iter().map(|f| Grant::lend(*f, Rights::READ)));
            // Device registers and the firmware's memory (its tables), given outright.
            let untyped = &info.untyped[..info.untyped_count as usize];
            let device = untyped.iter().enumerate().filter(|(_, d)| d.kind == KIND_DEVICE || d.kind == KIND_FIRMWARE);
            let before = grants.len();
            grants.extend(device.map(|(n, _)| Grant::give(sys::Cap(SLOT_FIRST_UNTYPED + n as u64))));
            args[0] = self.root.ramdisk.len() as u64;
            args[1] = (grants.len() - before) as u64;
        }
        if s.seed {
            // A secret of its own for this start (`silica_proc::seed`).
            let seed = silica_proc::seed(&self.root.secret, s.name, self.running[i].starts);
            for (k, word) in seed.as_chunks::<8>().0.iter().enumerate() {
                args[4 + k] = u64::from_le_bytes(*word);
            }
            args[3] = self.info.entropy_sources;
        }
        Ok((grants, args))
    }

    /// How many grants the log service has before its notification: its
    /// endpoint and its needs (`grants`).
    fn log_grants(&self) -> u64 {
        let l = self.log.as_ref().map_or(0, |l| l.service);
        self.endpoints[l].is_some() as u64 + self.services[l].needs.len() as u64
    }

    /// The slot of the log service's CapSpace that holds the ring of
    /// directory entry `entry` (`grants`: grant `n` lands in
    /// `FIRST_GRANT + n`).
    fn log_slot(&self, entry: usize) -> u64 {
        silica_rt::slots::FIRST_GRANT + self.log_grants() + 3 + entry as u64
    }

    /// Create and record the running instance of service `i`.
    fn spawn(&mut self, i: usize) -> Result<(), &'static str> {
        let s = &self.services[i];
        let image = match &self.running[i].program {
            Some(p) => p.as_slice(),
            None => ramdisk::find(self.root.archive, s.program).ok_or("its program is not in the boot archive")?,
        };
        let (grants, args) = self.grants(i)?;
        let log = self.log.as_ref().and_then(|l| Some((l.rings.get(i)?.as_ref()?.cap(), l.note.cap())));
        // Nothing a last instance was told is news to this one.
        let events = self.events[i].0.cap();
        let _ = sys::recv(events, Wait::Poll);
        let program = Program {
            grants: &grants,
            args,
            log,
            events: Some(events),
            keep: self.kept[i].as_ref().map(|p| p.cap()),
            group: Some(self.groups[i].cap()),
            time: Some((self.time.frame(), self.services[i].sets_time)),
            options: &self.options[i],
            mem_bits: s.memory,
            space_bits: if s.machine { 13 } else { 10 },
            aspace_bits: 18,
            cpu: self.placed[i],
            isolated: s.secrets,
            ..Program::new(image, SERVICE_IDS + i as u64)
        };
        let child = spawn(&self.root.parent, &program).map_err(|e| {
            println!("init: cannot start {}: {e:?} (2^{} bytes asked, {} bytes free)", s.name, s.memory, silica_rt::mem::available());
            "it could not be started"
        })?;
        self.running[i].starts += 1;
        self.running[i].restarts.started(silica_rt::clock().now());
        // An update's trial runs from its program's first start.
        if let Some((_, until @ 0)) = &mut self.running[i].trial {
            *until = silica_rt::clock().now() + TRIAL;
        }
        // What was given outright, by the slot it lands in (`silica_proc`
        // puts grant `n` at `FIRST_GRANT + n`).
        self.running[i].given =
            grants.iter().enumerate().filter(|(_, g)| g.give).map(|(n, g)| (silica_rt::slots::FIRST_GRANT + n as u64, g.cap.0)).collect();
        self.running[i].child = Some(child);
        Ok(())
    }

    /// End service `i`'s program `child`. What it was given outright is
    /// taken back first, and emptied of everything made from it (frames of
    /// device registers in the device manager and its drivers), for the
    /// next instance; then its memory comes back.
    fn end(&mut self, i: usize, child: Child) {
        let name = self.services[i].name;
        let given = core::mem::take(&mut self.running[i].given);
        for &(at, slot) in &given {
            if child.take_back(at, slot).is_err() {
                println!("ERROR: init: cannot take back what {name} was given (its slot {at})");
            }
        }
        if child.destroy().is_err() {
            println!("ERROR: init: cannot take back the memory of {name}");
        }
        for &(_, slot) in &given {
            // SAFETY: init uses nothing made from the memory it gave: the
            // frames made from it were the service's and its children's.
            #[allow(unsafe_code)]
            let _ = unsafe { sys::cap_revoke(sys::Cap(slot)) };
        }
    }

    /// A message on the exit endpoint about a service: it ended (`EXIT_LABEL`)
    /// or faulted (`FAULT_BADGE`). Returns the service and its status
    /// (`None`: a fault), or `None` for a message about nothing of ours or
    /// a fault on memory a peer took back, which is answered.
    fn ended(&mut self, m: &sys::Message) -> Option<(usize, Option<i64>)> {
        let fault = m.badge & FAULT_BADGE != 0;
        let i = (m.badge & !FAULT_BADGE).checked_sub(SERVICE_IDS)? as usize;
        if i >= self.services.len() || self.running[i].child.is_none() || (!fault && m.info.label() != EXIT_LABEL) {
            return None;
        }
        // Memory a peer lent it and took back: it carries on, on zeros.
        if fault && self.running[i].child.as_mut().is_some_and(|c| c.answer_peer_fault(m)) {
            return None;
        }
        let child = self.running[i].child.take()?;
        self.end(i, child);
        Some((i, if fault { None } else { Some(m.words[0] as i64) }))
    }

    /// Publish a new instance to its running consumers once spawn succeeds.
    fn start(&mut self, p: usize) -> Result<(), &'static str> {
        self.spawn(p)?;
        let Some(protocol) = self.services[p].provides else { return Ok(()) };
        for (c, s) in self.services.iter().enumerate() {
            if c == p || self.running[c].child.is_none() {
                continue;
            }
            if let Some(n) = s.needs.iter().position(|need| *need == protocol)
                && let Some(note) = self.events[c].1.get(n)
            {
                let _ = sys::signal(note.cap());
            }
        }
        Ok(())
    }

    /// Service `i` ended with `status` (`None`: it faulted): say so, and
    /// start it again if it asks to be.
    fn after(&mut self, i: usize, status: Option<i64>) {
        let name = self.services[i].name;
        match status {
            Some(0) => println!("init: {name} ended"),
            Some(HUNG) => println!("init: {name} was ended: it stopped answering"),
            Some(s) => println!("init: {name} ended with status {s}"),
            None => println!("init: {name} faulted"),
        }
        if status != Some(0) && self.on_trial(i) && !self.running[i].stopped {
            println!("init: {name}'s new program failed within {} s of its update; it is started on the program before it", TRIAL / SECOND);
            self.undo_update(i);
            self.start_again(i, " on the program before its update");
            return;
        }
        if status == Some(silica_rt::EXIT_AGAIN)
            && !self.running[i].stopped
            && self.running[i].restarts.may_start_again(silica_rt::clock().now())
        {
            // It asked to be started again: a start, not a failure.
            self.start_again(i, "");
            return;
        }
        if status == Some(0) || !self.services[i].restart || self.running[i].stopped {
            return;
        }
        let now = silica_rt::clock().now();
        let due = self.running[i].restarts.failed(now);
        if due > now {
            let r = self.running[i].restarts;
            println!("init: {name} has failed {} times in a row; it is started again in {} ms", r.streak, (due - now) / 1_000_000);
            return;
        }
        self.start_again(i, "");
    }

    /// Start service `i` again after a failure; one that cannot be started
    /// is tried again later, as if it had failed again.
    fn start_again(&mut self, i: usize, how: &str) {
        let name = self.services[i].name;
        match self.start(i) {
            Ok(()) => println!("init: {name} started again{how}"),
            Err(e) => {
                let now = silica_rt::clock().now();
                let due = self.running[i].restarts.failed(now);
                println!("ERROR: init: {name}: {e}; tried again in {} ms", (due - now) / 1_000_000);
            }
        }
    }

    /// Start the services whose restart is due; returns when the next one
    /// is (`None`: none waits).
    fn restart_due(&mut self) -> Option<u64> {
        let now = silica_rt::clock().now();
        for i in 0..self.services.len() {
            let r = &self.running[i];
            if r.restarts.due != 0 && r.restarts.due <= now && r.child.is_none() && !r.stopped {
                self.start_again(i, "");
            }
        }
        self.running.iter().filter(|r| r.restarts.due != 0 && r.child.is_none() && !r.stopped).map(|r| r.restarts.due).min()
    }

    /// Take one message from the endpoint: a call of `silica.system.Manager`
    /// is answered, a service's end looked after. Returns the end of a
    /// service the caller is waiting for (`watch`), or `Err` at the deadline.
    /// Ask the device manager to say when a watchdog comes, and take the one
    /// there is now. The capability carries the watchdog's scope, which only
    /// this program can give (no declaration names it).
    fn watch_watchdog(&mut self) {
        let Some(p) = self.services.iter().position(|s| s.provides == Some("silica.device.Manager")) else { return };
        let Some(ep) = self.endpoints[p].as_ref().map(Object::cap) else { return };
        let badge = (CONSUMERS + self.services.len() as u64) | (scope::DEVICE_WATCHDOG << scope::SHIFT);
        let Some(slot) = silica_rt::ipc::free_slot() else { return };
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), slot, ep, Rights(Rights::WRITE.0 | Rights::GRANT.0), badge).is_err() {
            silica_rt::ipc::release_slot(slot);
            return;
        }
        let Ok(note) = Object::new(ObjectType::Notification, 0) else { return };
        // The device manager parses what devices say: a call to it has a
        // time limit, as every call to something trusted less does.
        self.dog.devices = Some(devices::Client::from(Channel::within(sys::Cap(slot), silica_rt::ipc::DRIVER_CALL_LIMIT)));
        self.dog.note = Some(note);
        self.dog.since = silica_rt::clock().now();
        self.dog.wait = SECOND / 2;
        self.try_watch();
    }

    /// Ask the device manager to signal the watchdog's notification when a
    /// watchdog comes or goes. It may still be bringing its drivers up and
    /// not answer in time: asked again later (half a second, then twice as
    /// long each time, up to 8 s, for a minute), so nothing waits on it and
    /// nothing polls once it has answered.
    fn try_watch(&mut self) {
        self.dog.retry = 0;
        let (Some(devs), Some(note)) = (self.dog.devices.as_mut(), self.dog.note.as_ref()) else { return };
        let Some(to) = silica_rt::ipc::free_slot() else { return };
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, note.cap(), Rights::WRITE, 1).is_err() {
            silica_rt::ipc::release_slot(to);
            return;
        }
        // The capability moves with the call, and is released if it fails.
        match devs.watch(devices::Class::Watchdog, Handle::new(sys::Cap(to))) {
            Ok(_) => self.find_watchdog(),
            Err(e) => {
                let now = silica_rt::clock().now();
                if now - self.dog.since > 60 * SECOND {
                    println!("init: the device manager did not say whether there is a watchdog within a minute ({e:?}): none is petted");
                    return;
                }
                self.dog.retry = now + self.dog.wait;
                self.dog.wait = (self.dog.wait * 2).min(8 * SECOND);
            }
        }
    }

    /// Take the watchdog the device manager has, if any, say what it is,
    /// and pet it.
    fn find_watchdog(&mut self) {
        let Some(devs) = self.dog.devices.as_mut() else { return };
        let id = match devs.list(devices::Class::Watchdog, 0) {
            Ok(r) => r.devices.iter().next().map(|d| d.id),
            Err(e) => {
                println!("init: the device manager did not list watchdogs: {e:?}");
                return;
            }
        };
        let Some(id) = id else {
            self.dog.driver = None;
            if !self.dog.said_none {
                println!("init: this machine has no hardware watchdog: a hung machine is not reset");
                self.dog.said_none = true;
            }
            return;
        };
        let Ok(opened) = devs.open(id, None) else { return };
        let mut driver = watchdog::Client::from(Channel::within(opened.driver.cap(), silica_rt::ipc::DRIVER_CALL_LIMIT));
        core::mem::forget(opened.driver);
        let Ok(info) = driver.info() else { return };
        if info.reset_last_boot {
            println!("init: the last boot was reset by the watchdog");
        }
        // A pet at a third of its timeout: two may be late and the machine
        // still stands.
        self.dog.every = (info.timeout_ms as u64 * 1_000_000 / 3).max(1_000_000);
        println!(
            "init: the watchdog resets this machine {} s after the last pet; petted every {} s",
            info.timeout_ms / 1000,
            self.dog.every / SECOND
        );
        self.dog.driver = Some(driver);
        self.dog.next = 0;
        self.pet_watchdog();
    }

    /// Pet the watchdog if it is due; when it next is (`None`: no watchdog).
    fn pet_watchdog(&mut self) -> Option<u64> {
        let driver = self.dog.driver.as_mut()?;
        let now = silica_rt::clock().now();
        if now >= self.dog.next {
            if driver.pet().is_err() {
                // Its driver ended: the device manager starts another and
                // says so (the watch), and that one is taken then.
                self.dog.driver = None;
                return None;
            }
            self.dog.next = now + self.dog.every;
        }
        Some(self.dog.next)
    }

    /// The watchdog's chores that are due: asking the device manager again,
    /// petting. When the next one is (`None`: none).
    fn tend_watchdog(&mut self) -> Option<u64> {
        if self.dog.retry != 0 && silica_rt::clock().now() >= self.dog.retry {
            self.try_watch();
        }
        let retry = (self.dog.retry != 0).then_some(self.dog.retry);
        match (self.pet_watchdog(), retry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn step(&mut self, listener: &mut Listener, wait: Wait, watch: Option<usize>) -> Result<Option<(usize, Option<i64>)>, ()> {
        // The wait ends for the watchdog's pet too, and hears the device
        // manager say a watchdog came.
        let pet = self.tend_watchdog();
        let until = match (wait, pet) {
            (Wait::Until(t), Some(p)) => Wait::Until(t.min(p)),
            (Wait::Forever, Some(p)) => Wait::Until(p),
            (w, _) => w,
        };
        let got = match self.dog.note.as_ref() {
            Some(note) => listener.recv_listening(note.cap(), until),
            None => listener.recv(until),
        };
        let m = match got {
            Ok(m) => m,
            // The pet's time, not the caller's deadline: nothing ended.
            Err(_) if matches!(wait, Wait::Forever) || matches!(wait, Wait::Until(t) if silica_rt::clock().now() < t) => {
                self.tend_watchdog();
                return Ok(None);
            }
            Err(_) => return Err(()),
        };
        if m.info == sys::MsgInfo::NOTIFIED {
            self.find_watchdog();
            return Ok(None);
        }
        if m.badge >= CONSUMERS && m.badge & FAULT_BADGE == 0 {
            self.caller = m.badge;
            listener.answer(&m, |request, caps, reply, reply_caps| manager::dispatch(self, request, caps, reply, reply_caps));
            return Ok(None);
        }
        // A service whose time-limited call to a provider it needs went
        // unanswered: ask the provider ourselves.
        if m.badge & FAULT_BADGE == 0
            && m.info.label() == UNANSWERED_LABEL
            && let Some(i) = m.badge.checked_sub(SERVICE_IDS).map(|i| i as usize).filter(|i| *i < self.services.len())
        {
            self.unanswered(i, m.words[0]);
            return Ok(None);
        }
        match self.ended(&m) {
            Some((j, status)) if Some(j) == watch => Ok(Some((j, status))),
            Some((j, status)) => {
                self.after(j, status);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Service `i` waited past its limit for need `need`'s provider: ask the
    /// provider itself, once, within [`PROBE_LIMIT`] (its runtime answers
    /// from its request loop, whatever its protocol); one that does not
    /// answer either has hung without ending, and is ended and started
    /// again as a failure (the restart backoff applies). A provider that
    /// answered is not asked again for [`PROBE_QUIET`], so reports cannot
    /// keep the service manager busy. Nothing happens without a report.
    fn unanswered(&mut self, i: usize, need: u64) {
        let Some(protocol) = usize::try_from(need).ok().and_then(|n| self.services[i].needs.get(n)).copied() else { return };
        let Some(p) = self.services.iter().position(|s| s.provides == Some(protocol)) else { return };
        let Some(endpoint) = self.endpoints[p].as_ref().map(Object::cap) else { return };
        let now = silica_rt::clock().now();
        if self.running[p].child.is_none() || now < self.running[p].answered_at.saturating_add(PROBE_QUIET) {
            return;
        }
        match sys::call_within(endpoint, sys::MsgInfo::new(PROBE_LABEL, 0), [0; 4], PROBE_LIMIT) {
            Ok(_) => self.running[p].answered_at = silica_rt::clock().now(),
            Err(sys::Error::Timeout) => {
                let (name, by) = (self.services[p].name, self.services[i].name);
                println!("init: {name} did not answer within {} ms after {by} waited for it", PROBE_LIMIT / 1_000_000);
                if let Some(child) = self.running[p].child.take() {
                    self.end(p, child);
                    self.after(p, Some(HUNG));
                }
            }
            Err(_) => {}
        }
    }

    /// Ask service `i` to end ([`silica_rt::END`] on its events notification)
    /// and wait up to [`END_WAIT`] for it to exit; the caller then stops it
    /// (what is left of it, or all of it if it did not exit). For shutdown
    /// only: a call that arrives meanwhile is not answered (the machine is
    /// going down), and another service's exit is left for its own stop.
    fn end_in_order(&mut self, i: usize) {
        let name = self.services[i].name;
        let slot = silica_rt::ipc::free_slot();
        let asked = slot.is_some_and(|s| {
            let made = sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), s, self.events[i].0.cap(), Rights::WRITE, silica_rt::END);
            let ok = made.and_then(|()| sys::signal(sys::Cap(s))).is_ok();
            // SAFETY: made here for this one signal.
            #[allow(unsafe_code)]
            let _ = unsafe { sys::cap_delete(sys::Cap(s)) };
            silica_rt::ipc::release_slot(s);
            ok
        });
        if !asked {
            println!("init: cannot ask {name} to end; it is ended where it stands");
            return;
        }
        let id = SERVICE_IDS + i as u64;
        let deadline = silica_rt::clock().now() + END_WAIT;
        while let Ok(m) = sys::recv(self.root.parent.exit, Wait::Until(deadline)) {
            if m.badge & !FAULT_BADGE != id {
                continue;
            }
            if m.badge & FAULT_BADGE == 0 && m.info.label() == EXIT_LABEL && m.words[0] == 0 {
                println!("init: {name} ended in order");
            } else {
                println!("init: {name} did not end in order");
            }
            return;
        }
        println!("init: {name} did not end within {} s; it is ended where it stands", END_WAIT / SECOND);
    }

    /// Stop service `i` at once, as if it had failed, but for good.
    fn stop(&mut self, i: usize) -> bool {
        self.running[i].stopped = true;
        self.running[i].restarts.cancel();
        match self.running[i].child.take() {
            Some(child) => {
                self.end(i, child);
                true
            }
            None => false,
        }
    }

    /// Whether service `i` runs an update still on trial. A trial that is
    /// over is ended here, and the program it kept to go back to let go.
    fn on_trial(&mut self, i: usize) -> bool {
        match self.running[i].trial {
            Some((_, until)) if until == 0 || silica_rt::clock().now() < until => true,
            Some(_) => {
                self.running[i].trial = None;
                false
            }
            None => false,
        }
    }

    /// Put back the program service `i` ran before its update on trial.
    fn undo_update(&mut self, i: usize) {
        if let Some((before, _)) = self.running[i].trial.take() {
            self.running[i].program = before;
            self.running[i].hash = None;
            self.fresh_keep(i);
        }
    }

    /// Service `i` runs another program from its next start: the page it
    /// keeps across restarts starts empty, so nothing a program wrote there
    /// is read by one installed in its place (a compromised instance's
    /// data trusted by its replacement). The old page goes at once: each
    /// caller ends the running instance next.
    fn fresh_keep(&mut self, i: usize) {
        if self.kept[i].is_some() {
            match Object::new(ObjectType::Frame, 12) {
                Ok(page) => {
                    println!("init: {}'s kept page starts empty for its new program", self.services[i].name);
                    if let Some(old) = self.kept[i].replace(page) {
                        // SAFETY: init never maps it; the instance that has
                        // it is ended before the next starts (each caller ends
                        // it next), and reads zeros meanwhile.
                        #[allow(unsafe_code)]
                        unsafe {
                            old.destroy()
                        };
                    }
                }
                Err(_) => println!("ERROR: init: no memory to give {} an empty page; it keeps the old one", self.services[i].name),
            }
        }
    }

    /// The hash of the program service `i` runs (or will), computed once.
    fn hash(&mut self, i: usize) -> &'static [u8; 32] {
        if let Some(h) = self.running[i].hash {
            return h;
        }
        let image = match &self.running[i].program {
            Some(p) => p.as_slice(),
            None => ramdisk::find(self.root.archive, self.services[i].program).unwrap_or(&[]),
        };
        let h = silica_formats::blake2s::Blake2s::new().update(image).finish();
        let h = match self.hashes.iter().find(|k| ***k == h) {
            Some(k) => *k,
            None => {
                let k: &'static [u8; 32] = silica_rt::alloc::boxed::Box::leak(silica_rt::alloc::boxed::Box::new(h));
                self.hashes.push(k);
                k
            }
        };
        self.running[i].hash = Some(h);
        h
    }

    fn find(&self, name: &str) -> Result<usize, manager::Error> {
        self.services.iter().position(|s| s.name == name).ok_or(manager::Error::NoSuchService)
    }

    /// Wait for service `i` to end, looking after the others meanwhile.
    fn wait_for(&mut self, listener: &mut Listener, i: usize, within: u64) -> Result<i64, &'static str> {
        let deadline = silica_rt::clock().now() + within;
        loop {
            match self.step(listener, Wait::Until(deadline), Some(i)) {
                Ok(Some((_, status))) => return status.ok_or("it faulted"),
                Ok(None) => {}
                Err(()) => return Err("it did not finish in time"),
            }
        }
    }
}

impl Manager {
    /// Whether the current caller's capability carries `want`
    /// (`silica_protocols::scope`): `refused` when it does not.
    fn may(&self, want: u64) -> Result<(), manager::Error> {
        if scope::has(self.caller, want) { Ok(()) } else { Err(manager::Error::Refused) }
    }

    /// The service the current caller is (its capability's badge holds its
    /// number below the scopes).
    fn calling(&self) -> Option<&Service> {
        (self.caller & CONSUMERS != 0).then_some(self.caller & 0xFFFF_FFFF).and_then(|i| self.services.get(i as usize))
    }
}

impl manager::Server<Handle> for Manager {
    fn list<'a>(&'a mut self, from: u32) -> manager::ListReply<'a, Handle> {
        self.listed.clear();
        // Nothing to a caller not given `observe`.
        if self.may(scope::SYSTEM_OBSERVE).is_err() {
            return manager::ListReply { services: silica_idl_rt::Array::new(&self.listed), next: 0 };
        }
        for i in 0..self.services.len() {
            let program = self.hash(i);
            let _ = self.on_trial(i);
            let (s, r) = (&self.services[i], &self.running[i]);
            let state = if r.child.is_some() {
                manager::State::Running
            } else if s.restart && r.restarts.due != 0 && !r.stopped {
                // Failed, and waiting to be started again.
                manager::State::Failed
            } else {
                manager::State::Stopped
            };
            self.listed.push(manager::Service {
                name: s.name,
                state,
                failures: r.restarts.total,
                provides: s.provides.unwrap_or(""),
                program,
                updated: r.program.is_some(),
            });
        }
        // The part asked for, of every service made above.
        let all = core::mem::take(&mut self.listed);
        let listed = &mut self.listed;
        let next = silica_protocols::paging::part(
            all,
            from,
            |s| {
                use silica_protocols::paging::{record, text};
                record(text(s.name.len()) + 4 + 4 + text(s.provides.len()) + text(s.program.len()) + 1)
            },
            |s| listed.push(s),
        );
        manager::ListReply { services: silica_idl_rt::Array::new(&self.listed), next }
    }

    fn stop(&mut self, name: &str) -> Result<manager::StopReply, manager::Error> {
        self.may(scope::SYSTEM_CONTROL)?;
        let i = self.services.iter().position(|s| s.name == name).ok_or(manager::Error::NoSuchService)?;
        if self.services[i].machine || self.running[i].child.is_none() {
            return Err(manager::Error::Refused);
        }
        self.stop(i);
        println!("init: {name} stopped, as asked");
        Ok(manager::StopReply {})
    }

    fn restart(&mut self, name: &str) -> Result<manager::RestartReply, manager::Error> {
        self.may(scope::SYSTEM_CONTROL)?;
        let i = self.services.iter().position(|s| s.name == name).ok_or(manager::Error::NoSuchService)?;
        let child = self.running[i].child.take().ok_or(manager::Error::Refused)?;
        self.end(i, child);
        Manager::start(self, i).map_err(|_| manager::Error::Refused)?;
        println!("init: {name} restarted, as asked");
        Ok(manager::RestartReply {})
    }

    fn memory(&mut self) -> manager::MemoryReply {
        if self.may(scope::SYSTEM_OBSERVE).is_err() {
            return manager::MemoryReply { free: 0, held: 0 };
        }
        let held = self.services.iter().zip(&self.running).filter(|(_, r)| r.child.is_some()).map(|(s, _)| 1u64 << s.memory).sum();
        manager::MemoryReply { free: silica_rt::mem::available(), held }
    }

    fn start(&mut self, name: &str) -> Result<manager::StartReply, manager::Error> {
        self.may(scope::SYSTEM_CONTROL)?;
        let i = self.services.iter().position(|s| s.name == name).ok_or(manager::Error::NoSuchService)?;
        if self.running[i].child.is_none() {
            self.running[i].stopped = false;
            Manager::start(self, i).map_err(|_| manager::Error::Refused)?;
            println!("init: {name} started, as asked");
        }
        Ok(manager::StartReply {})
    }

    fn describe<'a>(&'a mut self, name: &str, from: u32) -> Result<manager::DescribeReply<'a>, manager::Error> {
        self.may(scope::SYSTEM_OBSERVE)?;
        let i = self.services.iter().position(|s| s.name == name).ok_or(manager::Error::NoSuchService)?;
        let child = self.running[i].child.as_ref().ok_or(manager::Error::Refused)?;
        let mut all = String::new();
        silica_proc::report(&mut all, self.services[i].name, child.space()).map_err(|_| manager::Error::Refused)?;
        // Whole lines from `from`, as many as fit a message.
        self.described.clear();
        let mut next = 0;
        for (n, line) in all.lines().enumerate().skip(from as usize) {
            if self.described.len() + line.len() + 1 > 3000 {
                next = n as u32;
                break;
            }
            self.described.push_str(line);
            self.described.push('\n');
        }
        Ok(manager::DescribeReply { text: &self.described, next })
    }

    fn shutdown(&mut self, reboot: bool) -> Result<manager::ShutdownReply, manager::Error> {
        self.may(scope::SYSTEM_POWER)?;
        flush_log();
        println!("init: shutting down{}", if reboot { " to reset" } else { "" });
        let caller = (self.caller & CONSUMERS != 0).then_some(self.caller & 0xFFFF_FFFF);
        for &i in self.order.clone().iter().rev() {
            // A service with something to finish (`ends`: the device
            // manager, its disks' caches) is asked to end and given a while;
            // not the one whose call this is, which cannot answer while it
            // waits for it (it ends what it must before it calls).
            if self.services[i].ends && self.running[i].child.is_some() && caller != Some(i as u64) {
                self.end_in_order(i);
            }
            // What the services said as they ended reaches the console
            // before the log goes.
            if self.log.as_ref().is_some_and(|l| l.service == i) {
                flush_log();
            }
            if self.stop(i) {
                println!("init: {} stopped", self.services[i].name);
            }
        }
        let power = sys::Cap(libsys::root::SLOT_POWER);
        let why = if reboot { sys::reboot(power, 0) } else { sys::power_off(power, 0) };
        println!("ERROR: init: the machine cannot be turned off: {why:?}");
        Err(manager::Error::Refused)
    }

    fn stage(&mut self, at: u64, data: &[u8]) -> Result<manager::StageReply, manager::Error> {
        self.may(scope::SYSTEM_UPDATE)?;
        let end = at.checked_add(data.len() as u64).filter(|e| *e <= MAX_PROGRAM).ok_or(manager::Error::TooLarge)?;
        let caller = self.caller;
        let k = match self.staged.iter().position(|(c, _)| *c == caller) {
            Some(k) => k,
            None => {
                self.staged.push((caller, Vec::new()));
                self.staged.len() - 1
            }
        };
        if at == 0 {
            self.staged[k].1.clear();
        }
        let others: usize = self.staged.iter().filter(|(c, _)| *c != caller).map(|(_, p)| p.len()).sum();
        let program = &mut self.staged[k].1;
        // In order: a piece starts where the last one ended, or earlier.
        if at > program.len() as u64 || others + end as usize > MAX_STAGED {
            return Err(manager::Error::TooLarge);
        }
        let (at, end) = (at as usize, end as usize);
        if end > program.len() {
            program.try_reserve(end - program.len()).map_err(|_| manager::Error::Refused)?;
            program.resize(end, 0);
        }
        program[at..end].copy_from_slice(data);
        Ok(manager::StageReply {})
    }

    fn update(&mut self, name: &str, length: u64) -> Result<manager::UpdateReply, manager::Error> {
        self.may(scope::SYSTEM_UPDATE)?;
        let i = self.find(name)?;
        let caller = self.caller;
        let k = self.staged.iter().position(|(c, _)| *c == caller).ok_or(manager::Error::TooLarge)?;
        let (_, mut program) = self.staged.swap_remove(k);
        if length > program.len() as u64 {
            return Err(manager::Error::TooLarge);
        }
        program.truncate(length as usize);
        program.shrink_to_fit();
        if let Err(e) = silica_proc::check_image(&program) {
            println!("init: the program sent to update {name} is not one this machine runs: {e:?}");
            return Err(manager::Error::NotAProgram);
        }
        // What it runs now is what to go back to (an earlier update's trial,
        // if one is still on, ends here: its program is the one now kept).
        let before = self.running[i].program.take();
        self.running[i].program = Some(program);
        self.running[i].trial = Some((before, 0));
        self.running[i].hash = None;
        self.fresh_keep(i);
        let hash = self.hash(i);
        println!(
            "init: {name} has a new program, {length} bytes, BLAKE2s {}, until the next reboot (an update is not kept on disk yet)",
            Hex(&hash[..8])
        );
        let Some(child) = self.running[i].child.take() else { return Ok(manager::UpdateReply {}) };
        self.end(i, child);
        if let Err(e) = Manager::start(self, i) {
            println!("init: {name}'s new program could not be started ({e}); it is started on the program before it");
            self.undo_update(i);
            if let Err(e) = Manager::start(self, i) {
                println!("ERROR: init: {name}: {e}");
            }
            return Err(manager::Error::Refused);
        }
        println!("init: {name} started on its new program");
        Ok(manager::UpdateReply {})
    }

    fn revert(&mut self, name: &str) -> Result<manager::RevertReply, manager::Error> {
        self.may(scope::SYSTEM_UPDATE)?;
        let i = self.find(name)?;
        if self.running[i].program.is_none() {
            return Ok(manager::RevertReply {});
        }
        self.running[i].program = None;
        self.running[i].trial = None;
        self.running[i].hash = None;
        self.fresh_keep(i);
        println!("init: {name} runs its program from the boot archive again, as asked");
        if let Some(child) = self.running[i].child.take() {
            self.end(i, child);
            Manager::start(self, i).map_err(|_| manager::Error::Refused)?;
        }
        Ok(manager::RevertReply {})
    }

    fn add_log(&mut self, name: &str, ring: Handle) -> Result<manager::AddLogReply<Handle>, manager::Error> {
        self.may(scope::SYSTEM_LOGS)?;
        let caller: &'static str = self.calling().ok_or(manager::Error::Refused)?.name;
        let source = silica_rt::alloc::format!("{caller}/{name}");
        let log = self.log.as_mut().ok_or(manager::Error::Refused)?;
        // A name given before keeps its place only while its ring lives: a
        // ring that is gone (the service that made it restarted, its
        // memory with it) is replaced by the new one, and the log service
        // reads on from it under the same source.
        let again = log.given.iter().position(|(n, _)| *n == source);
        if again.is_some_and(|k| alive(&log.given[k].1)) {
            return Err(manager::Error::Exists);
        }
        // A ring of the size every log's writer and reader assume.
        let fits = matches!(sys::inspect_slot(sys::Cap(libsys::root::SLOT_CAPSPACE), ring.cap().0),
            Ok(Some(i)) if i.ty == ObjectType::Frame && i.bits == silica_rt::log::BITS);
        if !fits || name.is_empty() || name.len() > 64 || source.len() > directory::NAME {
            return Err(manager::Error::Refused);
        }
        // One service has at most half the logs, so no one service can take
        // them all; and a log whose ring is gone (its maker ended for good)
        // gives its place to the next new one, anyone's.
        let mine = log.given.iter().filter(|(n, r)| n.strip_prefix(caller).is_some_and(|n| n.starts_with('/')) && alive(r)).count();
        let reuse = match again {
            Some(_) => None,
            None if mine >= MAX_LOGS / 2 => return Err(manager::Error::Refused),
            None if log.given.len() < MAX_LOGS => None,
            None => Some(log.given.iter().position(|(_, r)| !alive(r)).ok_or(manager::Error::Refused)?),
        };
        let to = silica_rt::ipc::free_slot().ok_or(manager::Error::Refused)?;
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, log.note.cap(), Rights::WRITE, 0).is_err() {
            silica_rt::ipc::release_slot(to);
            return Err(manager::Error::Refused);
        }
        let k = match (again, reuse) {
            (Some(k), _) => {
                log.given[k].1 = ring;
                k
            }
            (None, Some(k)) => {
                log.given[k] = (source, ring);
                k
            }
            (None, None) => {
                log.given.push((source, ring));
                log.given.len() - 1
            }
        };
        // Into the log service's own slot for it, if it runs (one started
        // later is given it with the others: `grants`), then named in the
        // directory: the log service never asks the service manager
        // (`silica_rt::log::directory`). The slot of a ring that is gone
        // emptied when it went, with every capability derived from it.
        let entry = self.services.len() + k;
        let slot = self.log_slot(entry);
        let log = self.log.as_ref().ok_or(manager::Error::Refused)?;
        if let Some(child) = &self.running[log.service].child
            && let Err(e) = sys::cap_derive(child.space(), slot, log.given[k].1.cap(), Rights(Rights::READ.0 | Rights::WRITE.0), 0)
        {
            println!("init: cannot give the log service the ring of {}: {e:?}", log.given[k].0);
        }
        directory::publish(&log.directory.shared(), entry, log.given[k].0.as_bytes());
        let _ = sys::signal(log.added);
        Ok(manager::AddLogReply { wake: Handle::new(sys::Cap(to)) })
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
        Err(e) => fail!("{e}"),
    };
    // Faults of the services are reported where their exits are.
    // The wall clock, from the firmware's (the machine's real-time clock,
    // read by the loader), in the time page every program can read.
    let time = silica_rt::mem::Memory::new(12).unwrap_or_else(|_| fail!("no memory for the time page"));
    let [wall_secs, wall_at] = info.wall_clock;
    if wall_secs != 0 {
        silica_rt::time::set(&time.shared(), wall_secs * 1_000_000_000, wall_at, silica_rt::time::Source::Firmware);
        println!("init: the wall clock is {} (the firmware's)", silica_rt::time::Civil::from_unix(wall_secs));
    } else {
        println!("init: the firmware gave no wall clock; it is unknown until a time server sets it");
    }
    let root = Root { parent: silica_proc::Parent { fault: root.parent.exit, time: time.frame(), ..root.parent }, ..root };
    let cmdline: &'static [u8] = &info.cmdline[..(info.cmdline_len as usize).min(info.cmdline.len())];
    let checks: Vec<&[u8]> =
        option(cmdline, "checks").unwrap_or(b"programs,block").split(|b| *b == b',').filter(|c| !c.is_empty()).collect();

    if checks.contains(&&b"programs"[..]) {
        program_checks(&root);
    }
    if checks.contains(&&b"spawn"[..]) {
        spawn_bench(&root);
    }

    let Some(list) = ramdisk::find(root.archive, "services").and_then(|b| core::str::from_utf8(b).ok()) else {
        fail!("the boot archive has no services list")
    };
    let services = match manifest::parse(list) {
        Ok(s) => s,
        Err(e) => fail!("the services list: {e}"),
    };
    let order = match manifest::order(&services) {
        Ok(o) => o,
        Err(e) => fail!("the services list: {e}"),
    };
    let mut endpoints = Vec::new();
    for s in &services {
        endpoints.push(match s.provides {
            Some(_) => match Object::new(ObjectType::Endpoint, 0) {
                Ok(ep) => Some(ep),
                Err(_) => fail!("no memory for {}'s endpoint", s.name),
            },
            None => None,
        });
    }
    // The boot archive's files services are given (`files=`), each copied
    // once into a frame of its own: lent read-only at every start, so no
    // instance can change what the next is given.
    let running = services
        .iter()
        .map(|s| Running {
            child: None,
            given: Vec::new(),
            starts: 0,
            restarts: Restarts::default(),
            answered_at: 0,
            stopped: false,
            program: None,
            trial: None,
            hash: None,
            files: s.files.iter().map(|f| file_frame(root.archive, s.name, f)).collect(),
        })
        .collect();
    // Each service's events, and a capability per need to tell it.
    let mut events = Vec::new();
    for s in &services {
        let note = Object::new(ObjectType::Notification, 0).unwrap_or_else(|_| fail!("no memory for {}'s events", s.name));
        let mut needs = Vec::new();
        for n in 0..s.needs.len().min(31) {
            let to = silica_rt::ipc::free_slot().unwrap_or_else(|| fail!("no slot for {}'s events", s.name));
            if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, note.cap(), Rights::WRITE, 1 << n).is_err() {
                fail!("cannot make {}'s events", s.name);
            }
            needs.push(Handle::new(sys::Cap(to)));
        }
        events.push((note, needs));
    }
    // The pages services keep across their restarts: zero at boot (a new
    // frame is).
    let kept = services
        .iter()
        .map(|s| s.keeps.then(|| Object::new(ObjectType::Frame, 12).unwrap_or_else(|_| fail!("no memory for {}'s page", s.name))))
        .collect();
    // Where each service runs (its declaration's `cpu=`, or processor 0).
    let placed = place(&services, root.parent.cpus as usize);
    // A group for each service, on the processor it runs on: a program
    // that makes many threads takes one share, not one a thread (the
    // remediation of the 2026-11-24 audit).
    let groups = services
        .iter()
        .zip(&placed)
        .map(|(s, &cpu)| {
            let g = Object::new(ObjectType::SchedContext, 0).unwrap_or_else(|_| fail!("no memory for {}'s group", s.name));
            if let Err(e) = sys::sched_group(g.cap(), libsys::SCHED_DEFAULT_WEIGHT, cpu, sys::Cap(libsys::root::SLOT_SCHED)) {
                fail!("cannot make {}'s group: {e:?}", s.name);
            }
            g
        })
        .collect();
    // The log, when a service provides it: a ring for every other service,
    // made before anything starts; the log starts first.
    let mut order = order;
    let log = match services.iter().position(|s| s.provides == Some("silica.log.Reader")) {
        None => None,
        Some(l) => {
            let object = |ty, bits| Object::new(ty, bits).unwrap_or_else(|_| fail!("no memory for the log"));
            let note = object(ObjectType::Notification, 0);
            let flushed = object(ObjectType::Notification, 0);
            let rings = (0..services.len()).map(|i| (i != l).then(|| object(ObjectType::Frame, silica_rt::log::BITS))).collect();
            order.retain(|&i| i != l);
            order.insert(0, l);
            if services.len() + MAX_LOGS > directory::ENTRIES {
                fail!("more services than the log's directory names");
            }
            let directory = silica_rt::mem::Memory::new(directory::BITS).unwrap_or_else(|_| fail!("no memory for the log"));
            for (i, s) in services.iter().enumerate() {
                if i != l {
                    directory::publish(&directory.shared(), i, s.name.as_bytes());
                }
            }
            Some(LogSetup { service: l, note, flushed, rings, added: sys::Cap(0), given: Vec::new(), directory })
        }
    };
    // Each service's options, from the boot command line.
    let options: Vec<Vec<u8>> = services
        .iter()
        .map(|s| {
            let prefix = silica_rt::alloc::format!("{}.", s.name);
            let words: Vec<&[u8]> = cmdline.split(|b| b.is_ascii_whitespace()).filter_map(|w| w.strip_prefix(prefix.as_bytes())).collect();
            let o = words.join(&b' ');
            if o.len() > silica_rt::OPTIONS_MAX {
                println!("ERROR: init: {}'s options are longer than {} bytes; it is given none", s.name, silica_rt::OPTIONS_MAX);
                return Vec::new();
            }
            o
        })
        .collect();
    let mut m = Manager {
        placed,
        root,
        info,
        services,
        endpoints,
        running,
        events,
        kept,
        groups,
        time,
        options,
        order: order.clone(),
        listed: Vec::new(),
        described: String::new(),
        caller: 0,
        staged: Vec::new(),
        hashes: Vec::new(),
        log,
        dog: Watchdog::default(),
    };
    if let Some(l) = &m.log {
        let to = silica_rt::ipc::free_slot().unwrap_or_else(|| fail!("no slot for the log"));
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, l.note.cap(), Rights::WRITE, FLUSH).is_err() {
            fail!("cannot make the log's flush capability");
        }
        FLUSH_TO.store(to, Ordering::Relaxed);
        FLUSHED.store(l.flushed.cap().0, Ordering::Relaxed);
    }
    if let Some(l) = m.log.as_mut() {
        let to = silica_rt::ipc::free_slot().unwrap_or_else(|| fail!("no slot for the log"));
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, l.note.cap(), Rights::WRITE, ADDED).is_err() {
            fail!("cannot make the log's capability for added logs");
        }
        l.added = sys::Cap(to);
    }
    let mut listener = Listener::new(m.root.parent.exit);

    // The system, in order, but for what the command line keeps off.
    let off: Vec<&[u8]> = option(cmdline, "off").unwrap_or(b"").split(|b| *b == b',').filter(|c| !c.is_empty()).collect();
    for o in &off {
        if !m.services.iter().any(|s| s.name.as_bytes() == *o) {
            fail!("off= names {}, which no service is declared for", core::str::from_utf8(o).unwrap_or("?"));
        }
    }
    for &i in &order {
        if m.services[i].start != Start::Boot {
            continue;
        }
        if off.contains(&m.services[i].name.as_bytes()) {
            m.running[i].stopped = true;
            println!("init: {} is off, as the command line asks", m.services[i].name);
            continue;
        }
        // Boot order puts providers before consumers, so none needs a
        // notification for this initial instance.
        if let Err(e) = m.spawn(i) {
            fail!("{}: {e}", m.services[i].name);
        }
    }
    // The machine's watchdog, petted from here on.
    m.watch_watchdog();
    // `checks=watchdog`: once the watchdog is petted, stop petting it and
    // answering anyone, as a hung service manager would: the watchdog must
    // reset the machine, and the next boot hears it did.
    if checks.contains(&&b"watchdog"[..]) {
        let until = silica_rt::clock().now() + 60 * SECOND;
        while m.dog.driver.is_none() && silica_rt::clock().now() < until {
            let _ = m.step(&mut listener, Wait::Until(until), None);
        }
        if m.dog.driver.is_none() {
            fail!("checks=watchdog: no watchdog came within 60 s");
        }
        flush_log();
        println!("init: no more pets and no more answers, as checks=watchdog asks: the watchdog must reset the machine");
        let Ok(never) = Object::new(ObjectType::Notification, 0) else { fail!("no memory") };
        loop {
            let _ = sys::recv(never.cap(), Wait::Forever);
        }
    }
    // The checks the command line asks for, in its order.
    let mut checked = false;
    for c in checks.iter().filter(|c| **c != b"programs" && **c != b"spawn" && **c != b"watchdog") {
        let mut any = false;
        for &i in &order {
            if !matches!(m.services[i].start, Start::Check(n) if n.as_bytes() == *c) {
                continue;
            }
            any = true;
            let name = m.services[i].name;
            if let Err(e) = m.start(i) {
                fail!("{name}: {e}");
            }
            let ended = m.wait_for(&mut listener, i, 120 * SECOND);
            flush_log();
            match ended {
                Ok(0) => println!("init: {name} passed"),
                Ok(s) => fail!("{name} ended with status {s}"),
                Err(e) => fail!("{name}: {e}"),
            }
        }
        if !any {
            fail!("checks= names {}, which no service is declared for", core::str::from_utf8(c).unwrap_or("?"));
        }
        checked = true;
    }
    if checked || checks.contains(&&b"programs"[..]) || checks.contains(&&b"spawn"[..]) {
        flush_log();
        if option(cmdline, "bench").is_some() || cmdline.split(|b| b.is_ascii_whitespace()).any(|w| w == b"bench") {
            println!("BENCH DONE");
        }
        println!("BOOT OK");
        if cmdline.split(|b| b.is_ascii_whitespace()).any(|w| w == b"halt=reboot") {
            let why = sys::reboot(sys::Cap(libsys::root::SLOT_POWER), 0);
            fail!("the machine cannot be reset: {why:?}");
        }
        finish(true)
    }
    // No checks: the system stays up, and its services are looked after.
    flush_log();
    println!("BOOT OK");
    let mut next = None;
    loop {
        let wait = next.map_or(Wait::Forever, Wait::Until);
        let _ = m.step(&mut listener, wait, None);
        next = m.restart_due();
    }
}

/// The round trips everything rests on: a program runs in its own address
/// space and CapSpace, reports its exit, and its memory comes back; two
/// programs call each other through a protocol.
/// `checks=spawn`: how long a program takes from its parent's `spawn` to
/// its own first line of code (`hello` asked to answer with the time it
/// started), over [`SPAWNS`] programs started and taken down one after
/// another, before any service runs. Prints `BENCH spawn` (median) and
/// `BENCH spawn_p99`, in nanoseconds; the Linux baseline measures fork or
/// vfork and exec of a static program to its `main` the same way
/// (os/bench/linux/init.c).
fn spawn_bench(root: &Root) {
    const SPAWNS: usize = 2000;
    const WARMUP: usize = 200;
    let parent = &root.parent;
    let Some(image) = ramdisk::find(root.archive, "hello") else { fail!("the ramdisk has no program named hello") };
    let clock = silica_rt::clock();
    let mut took = Vec::with_capacity(SPAWNS);
    for n in 0..SPAWNS + WARMUP {
        let id = 100;
        let start = clock.now();
        let child = match spawn(parent, &Program { args: [0, 1, 0, 0, 0, 0, 0, 0], ..Program::new(image, id) }) {
            Ok(c) => c,
            Err(e) => fail!("cannot start hello: {e:?}"),
        };
        let Ok(m) = sys::recv(parent.exit, Wait::Until(clock.now() + 5 * SECOND)) else {
            fail!("hello did not report its exit within 5 s")
        };
        if m.info.label() != EXIT_LABEL || m.badge != id || m.words[0] < start {
            fail!("hello's exit message is not the time it started");
        }
        if n >= WARMUP {
            took.push(m.words[0] - start);
        }
        if child.destroy().is_err() {
            fail!("cannot take back hello's memory");
        }
    }
    took.sort_unstable();
    println!("BENCH spawn {} ns", took[SPAWNS / 2]);
    println!("BENCH spawn_p99 {} ns", took[SPAWNS - SPAWNS / 100 - 1]);
}

fn program_checks(root: &Root) {
    let (parent, archive) = (&root.parent, root.archive);
    let Some(image) = ramdisk::find(archive, "hello") else { fail!("the ramdisk has no program named hello") };
    // Twice: the second start must find all of the first one's memory back.
    for round in 0..2u64 {
        let child = match spawn(parent, &Program { args: [7 + round, 0, 0, 0, 0, 0, 0, 0], ..Program::new(image, 100 + round) }) {
            Ok(c) => c,
            Err(e) => fail!("cannot start hello: {e:?}"),
        };
        let Ok(m) = sys::recv(parent.exit, Wait::Until(silica_rt::clock().now() + 5 * SECOND)) else {
            fail!("hello did not report its exit within 5 s")
        };
        if m.info.label() != EXIT_LABEL || m.badge != 100 + round || m.words[0] != 7 + round {
            fail!("hello's exit message is not what it was started to send");
        }
        if child.destroy().is_err() {
            fail!("cannot take back hello's memory");
        }
        println!("init: hello (id {}) exited with status {}; its memory is back", m.badge, m.words[0]);
    }
    // Every program has a random number generator of its own, seeded by its
    // parent: three programs started alike give three different numbers
    // (one started without a seed would end with an error), none of them
    // this program's own.
    let mut drawn = [silica_rt::random::u64(), 0, 0, 0];
    for (n, slot) in drawn.iter_mut().enumerate().skip(1) {
        let id = 110 + n as u64;
        let child = match spawn(parent, &Program { args: [0, 2, 0, 0, 0, 0, 0, 0], ..Program::new(image, id) }) {
            Ok(c) => c,
            Err(e) => fail!("cannot start hello: {e:?}"),
        };
        let Ok(m) = sys::recv(parent.exit, Wait::Until(silica_rt::clock().now() + 5 * SECOND)) else {
            fail!("hello did not report its exit within 5 s")
        };
        if m.info.label() != EXIT_LABEL || m.badge != id {
            fail!("hello's exit message is not its random number");
        }
        *slot = m.words[0];
        if child.destroy().is_err() {
            fail!("cannot take back hello's memory");
        }
    }
    if (0..4).any(|i| (i + 1..4).any(|j| drawn[i] == drawn[j])) {
        fail!("two programs' random number generators gave the same number: {drawn:x?}");
    }
    println!("init: three programs' random number generators and this one's gave four different numbers");
    // Two programs that talk: a provider of the sample.Echo protocol and a
    // client of it, connected by one endpoint. The provider may only
    // receive on it; the client may only send (and pass capabilities).
    // The first pair is the runtime's own; the second was written from the
    // published documentation alone and is kept exactly as it first built.
    for (n, (server_name, client_name)) in [("echo-server", "echo-client"), ("trial-server", "trial-client")].into_iter().enumerate() {
        let id = 200 + 2 * n as u64;
        let (Some(server_image), Some(client_image)) = (ramdisk::find(archive, server_name), ramdisk::find(archive, client_name)) else {
            fail!("the ramdisk lacks {server_name} or {client_name}")
        };
        let Ok(endpoint_object) = Object::new(ObjectType::Endpoint, 0) else { fail!("cannot create an endpoint for the echo programs") };
        let endpoint = endpoint_object.cap();
        let receive = Grant::lend(endpoint, Rights::READ);
        let send = Grant::badged(endpoint, Rights(Rights::WRITE.0 | Rights::GRANT.0), 7);
        let server = spawn(parent, &Program { grants: &[receive], ..Program::new(server_image, id) });
        let client = spawn(parent, &Program { grants: &[send], ..Program::new(client_image, id + 1) });
        let (Ok(server), Ok(client)) = (server, client) else { fail!("cannot start {server_name} and {client_name}") };
        let Ok(m) = sys::recv(parent.exit, Wait::Until(silica_rt::clock().now() + 10 * SECOND)) else {
            fail!("{client_name} did not finish within 10 s")
        };
        if m.badge != id + 1 || m.words[0] != 0 {
            fail!("program {} of the pair {server_name}, {client_name} exited with status {}", m.badge, m.words[0] as i64);
        }
        if client.destroy().is_err() || server.destroy().is_err() {
            fail!("cannot take back the echo programs' memory");
        }
        // SAFETY: the endpoint was made for this pair, which is gone.
        #[allow(unsafe_code)]
        unsafe {
            endpoint_object.destroy()
        };
        println!("init: {client_name} and {server_name} talked over sample.Echo; both are gone and their memory is back");
    }
}

/// The boot archive's file `name` in a frame of its own for service
/// `service` (`files=`): the smallest power of two that holds it, at least
/// a page, zeros after it. `None`, said in the log, when the archive has no
/// such file: the service finds that grant's slot empty.
fn file_frame(archive: &'static [u8], service: &str, name: &str) -> Option<silica_rt::mem::Memory> {
    let Some(bytes) = ramdisk::find(archive, name) else {
        println!("init: {service} is to be given the file {name}, which the boot archive does not have");
        return None;
    };
    let bits = (bytes.len().max(1).next_power_of_two().trailing_zeros() as u8).max(12);
    let m = silica_rt::mem::Memory::new(bits).unwrap_or_else(|_| fail!("no memory for {service}'s file {name}"));
    m.shared().write_bytes(0, bytes);
    Some(m)
}

/// Bytes as hexadecimal digits.
struct Hex<'a>(&'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// The processor each of `services` runs on (`cpu=`, manifest.rs;
/// `silica_proc::place`), saying so of one declared for a processor this
/// machine does not have, which runs on processor 0.
fn place(services: &[Service], cpus: usize) -> Vec<usize> {
    let wanted: Vec<silica_proc::Placement> = services
        .iter()
        .map(|s| match s.cpu {
            Cpu::Fixed(n) => silica_proc::Placement::Fixed(n),
            Cpu::Any => silica_proc::Placement::Any,
        })
        .collect();
    let placed = silica_proc::place(&wanted, cpus);
    for (s, (_, missing)) in services.iter().zip(&placed) {
        if *missing {
            println!("init: {} is declared for a processor this machine does not have ({cpus}); it runs on processor 0", s.name);
        }
    }
    placed.into_iter().map(|(c, _)| c).collect()
}
