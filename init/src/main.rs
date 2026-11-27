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
//! The machine is turned off only when a holder of the `power` scope asks
//! (`shutdown`).
//!
//! The boot command line is not a service's to read on a machine's image
//! (spec/ARCHITECTURE.md, invariant 10): nothing signs it, and whoever last
//! wrote the boot volume wrote it. So only a test image's init gives a
//! service the line's `<service>.<word>` words as its options and obeys
//! `off=` (a comma list of boot services kept from starting, as if
//! stopped; `start <name>` starts one later). A machine's init gives
//! services no options from it, starts every boot service, and says which
//! words it did not obey. (Before, any image obeyed them: the network
//! stack's address, router, name servers and time server, and any service
//! kept off, the device manager and the log among them, were whoever
//! wrote the disk's to choose: the 2026-11-26 review, H2.)
//!
//! A test image's init (the `harness` feature, which no image a machine
//! runs is built with) also obeys `checks=` (a comma list; default
//! `programs,block`): `programs` runs the round trips everything rests on
//! (a program's memory comes back, two programs talk through a protocol),
//! `spawn` measures starting a program, `watchdog` stops petting, and every
//! other name runs the services declared `start=check:<name>`, which must
//! end with status 0. When checks ran, the machine is turned off when they
//! are done (`halt=reboot`: reset), and `bench` prints `BENCH DONE` first
//! (`tools/bench.sh` reads up to it). A failure there turns the machine off
//! with a status the harness reads; without the feature, an init that
//! cannot start the system says why and stands still.
#![no_std]
#![no_main]

mod manifest;

use libsys::root::{KIND_DEVICE, KIND_FIRMWARE, RootInfo, SLOT_DEVICES, SLOT_FIRST_UNTYPED, SLOT_INFO, SLOT_IRQS};
use libsys::{self as sys, ObjectType, Rights, Wait};
use manifest::{Cpu, Service, Start};
use silica_formats::ramdisk;
#[cfg(feature = "harness")]
use silica_proc::root::finish;
use silica_proc::root::{self, Root};
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
use silica_rt::{AGAIN_LABEL, EXIT_LABEL, println};

/// Init cannot go on: say why and stop ([`halt`]). For what fails before
/// any service runs; later, [`Manager::fail`] puts the services' last
/// lines on the console first.
macro_rules! fail {
    ($($a:tt)*) => {{
        silica_rt::print!("ERROR: init: ");
        println!($($a)*);
        halt(false)
    }};
}

/// As [`fail!`], once services run: `$m` is the [`Manager`].
macro_rules! fail_with {
    ($m:expr, $($a:tt)*) => {{
        $m.last_words();
        silica_rt::print!("ERROR: init: ");
        println!($($a)*);
        halt(false)
    }};
}

/// The end of this boot. A test image's init turns the machine off, telling
/// the harness whether everything passed. On a machine, init never turns
/// the power off by itself: one that cannot start the system has said why
/// and stands still (nothing pets the watchdog, where there is one).
fn halt(ok: bool) -> ! {
    #[cfg(feature = "harness")]
    finish(ok);
    #[cfg(not(feature = "harness"))]
    {
        let _ = ok;
        println!("init: the system cannot start; this machine stands still until it is reset");
        loop {
            let _ = sys::thread_suspend(sys::Cap(libsys::root::SLOT_THREAD));
        }
    }
}

/// The bit of the log's notification that says logs were added (`add_log`).
const ADDED: u64 = 4;

/// Whether the ring `h` names is still there: one whose maker ended is gone,
/// and every capability derived from it with it.
fn alive(h: &Handle) -> bool {
    matches!(sys::inspect_slot(sys::Cap(libsys::root::SLOT_CAPSPACE), h.cap().0), Ok(Some(_)))
}

const SECOND: u64 = 1_000_000_000;
/// Badges of consumers' capabilities to a provider start here.
const CONSUMERS: u64 = 1 << 32;
/// Service `i` runs with the program identifier `SERVICE_IDS + i`.
const SERVICE_IDS: u64 = 1000;

/// The bit of the watchdog's notification service `i`'s program under an
/// update's trial signals when it serves (`silica_rt::serving`): 1 + `i`,
/// bit 0 being the device manager's word on the watchdog. The services list
/// holds at most 63 services (`manifest::parse`), so every one has a bit.
fn serving_bit(i: usize) -> u64 {
    1u64.checked_shl(1 + i as u32).unwrap_or(0)
}
/// How long a service asked to end as the machine turns off has to exit
/// (`Manager::end_in_order`): longer than the device manager gives its
/// drivers. Its exit is what is waited for; this is how long a service that
/// never exits is waited for before it is ended where it stands.
const END_WAIT: u64 = 10 * SECOND;
/// The largest program `update` takes.
const MAX_PROGRAM: u64 = 16 << 20;

/// How a service's program ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// It exited with this status (0: it finished).
    Status(i64),
    /// It faulted.
    Fault,
    /// It ended asking to be started again (`silica_rt::AGAIN_LABEL`).
    Again,
}

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
    /// Stopped by the owner: not started again until asked.
    stopped: bool,
    /// The program it runs, when an `update` gave it one; `None`: the boot
    /// archive's.
    program: Option<Vec<u8>>,
    /// An update on trial: the program to go back to (`None` inside: the
    /// archive's) if the new one ends badly before it has served. The new
    /// program says when it serves (`silica_rt::serving`, a signal on its
    /// bit of the watchdog's notification: `serving_bit`), which ends
    /// the trial.
    trial: Option<Option<Vec<u8>>>,
    /// The BLAKE2s-256 of its program, once asked for (`list`).
    hash: Option<&'static [u8; 32]>,
    /// The boot archive's files it is given (`files=`), each in a frame of
    /// its own made once.
    files: Vec<Option<silica_rt::mem::Memory>>,
}

/// The machine's hardware watchdog (`silica.watchdog.Device`), which the
/// service manager alone pets, from its own loop: when it stops (the
/// service manager or the kernel hung) the machine is reset.
///
/// The device manager says when its watchdog's driver changes by signalling
/// `note`, through a capability it is given at each of its starts (among a
/// machine service's grants): the kernel keeps the signal until the service
/// manager listens, so nothing is asked for, nothing is asked again and
/// nothing polls; a machine without one wakes nothing for it. (Before, the
/// service manager called the device manager to be told, with a time limit,
/// again after a wait that doubled, and gave up after a minute; and a
/// device manager started again had never been asked, so the watchdog of
/// its new driver went unpetted and reset the machine.)
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
    /// Each service's scheduling context (`libsys::sched_fair`: one share
    /// of the processor it is placed on), the same for every start of
    /// it: its threads take that one share however many it makes, and
    /// the programs it starts run on it too.
    sched: Vec<Object>,
    /// The page the program before a service's new one kept (`fresh_keep`),
    /// and whether an instance was started with it: the new program's
    /// first instance is given it read-only, as its last grant, and it goes
    /// when that instance has.
    left: Vec<Option<(Object, bool)>>,
    /// The time page (`silica_rt::time`), set from the firmware's clock.
    time: silica_rt::mem::Memory,
    /// Each service's options: the boot command line's
    /// `<service>.<key>=<value>` words, as `<key>=<value>`.
    options: Vec<Vec<u8>>,
    /// The order services were started in, for stopping them in reverse.
    order: Vec<usize>,
    /// What `list` answers with, rebuilt for each call.
    listed: Vec<manager::Service<'static>>,
    /// What `describe` answers with.
    described: String,
    /// The badge of the call being answered.
    caller: u64,
    /// The memory each calling service was lent to write a program into
    /// (`program`), with its size in bits: one a service, the service
    /// manager's own frame, taken back by `update`, by the next `program`
    /// and when the service ends.
    lent: Vec<(u64, u8, Object)>,
    /// Every program hash `list` has shown, each kept once: what a
    /// service's `hash` points at (a reply borrows it). One per distinct
    /// program the system ran, 32 bytes each.
    hashes: Vec<&'static [u8; 32]>,
    /// The log: the service that provides it (whose events notification
    /// its writers signal), a ring per service (`silica_rt::log`), and the
    /// places for the logs services give their programs.
    log: Option<LogSetup>,
    /// The machine's hardware watchdog, once the device manager has it.
    dog: Watchdog,
}

struct LogSetup {
    service: usize,
    rings: Vec<Option<Object>>,
    /// The log service's notification, badged [`ADDED`].
    added: sys::Cap,
    /// The logs services gave their programs (`add_log`): the source's
    /// name and the ring. Each service has the places its declaration
    /// gives it (`logs=`), from `first[service]` on: a service fills its
    /// own and no other's.
    given: Vec<Option<(String, Handle)>>,
    first: Vec<usize>,
    /// The ring directory (`silica_rt::log::directory`): entry `i` names
    /// service `i`'s ring, entry `services + k` the given one in place `k`.
    directory: silica_rt::mem::Memory,
}

/// The value of `key=` on the command line.
#[cfg(feature = "harness")]
fn option(cmdline: &'static [u8], key: &str) -> Option<&'static [u8]> {
    cmdline.split(|b| b.is_ascii_whitespace()).find_map(|w| w.strip_prefix(key.as_bytes())?.strip_prefix(b"="))
}

/// A machine's image: say which words of the command line, a service's
/// options or `off=`, this init does not obey (shown inertly: the line is
/// whoever wrote the boot volume's).
#[cfg(not(feature = "harness"))]
fn not_obeyed(cmdline: &'static [u8], services: &[Service]) {
    let words: Vec<&str> = cmdline
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| {
            w.starts_with(b"off=")
                || services.iter().any(|s| w.strip_prefix(s.name.as_bytes()).is_some_and(|rest| rest.first() == Some(&b'.')))
        })
        .map(|w| core::str::from_utf8(w).unwrap_or("(not text)"))
        .collect();
    if !words.is_empty() {
        let shown = words.join(" ");
        println!("init: the boot command line configures no service on this image; not obeyed: {}", silica_rt::text::printable(&shown));
    }
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
            // The notification its writers signal (its own events, where it
            // is also asked to end), the directory, then a slot for each
            // ring the directory can name (`log_slot`): the services' and
            // those given so far; `add_log` fills the rest.
            debug_assert_eq!(grants.len() as u64, self.log_grants());
            grants.push(Grant::lend(self.events[i].0.cap(), Rights::ALL));
            grants.push(Grant::lend(log.directory.frame(), Rights::READ));
            let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
            for r in &log.rings {
                grants.push(match r {
                    Some(f) => Grant::lend(f.cap(), rw),
                    None => Grant::none(),
                });
            }
            for place in &log.given {
                grants.push(match place {
                    Some((_, ring)) if alive(ring) => Grant::lend(ring.cap(), rw),
                    _ => Grant::none(),
                });
            }
            args[0] = (log.rings.len() + log.given.len()) as u64;
        }
        if s.machine {
            let info = self.info;
            grants.push(Grant::lend(sys::Cap(SLOT_INFO), Rights::READ));
            grants.push(Grant::lend(sys::Cap(SLOT_DEVICES), Rights::ALL));
            grants.push(Grant::lend(sys::Cap(SLOT_IRQS), Rights::ALL));
            // The I/O ports, on a machine that has them (x86_64).
            let has_ports = matches!(sys::inspect_slot(sys::Cap(libsys::root::SLOT_CAPSPACE), self.root.ports.0), Ok(Some(_)));
            grants.push(if has_ports { Grant::lend(self.root.ports, Rights::ALL) } else { Grant::none() });
            // What it signals when the watchdog's driver changes: the
            // watchdog's notification, to signal and nothing else.
            grants.push(self.dog.note.as_ref().map_or(Grant::none(), |n| Grant::badged(n.cap(), Rights::WRITE, 1)));
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
        if s.keeps {
            // Last: the page the program before this one left (`fresh_keep`),
            // for its first instance, read-only.
            grants.push(match &self.left[i] {
                Some((page, false)) => Grant::lend(page.cap(), Rights::READ),
                _ => Grant::none(),
            });
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
        silica_rt::slots::FIRST_GRANT + self.log_grants() + 2 + entry as u64
    }

    /// Create and record the running instance of service `i`.
    fn spawn(&mut self, i: usize) -> Result<(), &'static str> {
        let s = &self.services[i];
        let image = match &self.running[i].program {
            Some(p) => p.as_slice(),
            None => ramdisk::find(self.root.archive, s.program).ok_or("its program is not in the boot archive")?,
        };
        // The page of the program before this one was the last instance's
        // to read: that instance has ended, and the page goes.
        if let Some((page, true)) = self.left[i].take_if(|(_, given)| *given) {
            // SAFETY: init never maps it, and the one instance that had
            // it has ended.
            #[allow(unsafe_code)]
            unsafe {
                page.destroy()
            };
        }
        let (grants, args) = self.grants(i)?;
        let log = self.log.as_ref().and_then(|l| Some((l.rings.get(i)?.as_ref()?.cap(), self.events[l.service].0.cap())));
        // Nothing a last instance was told is news to this one.
        let events = self.events[i].0.cap();
        let _ = sys::recv(events, Wait::Poll);
        let program = Program {
            grants: &grants,
            args,
            log,
            events: Some(events),
            keep: self.kept[i].as_ref().map(|p| p.cap()),
            sched: Some(self.sched[i].cap()),
            time: Some((self.time.frame(), self.services[i].sets_time)),
            options: &self.options[i],
            mem_bits: s.memory,
            space_bits: if s.machine { 13 } else { 10 },
            aspace_bits: 18,
            isolated: s.secrets,
            // A program an update installed says when it serves, by a signal
            // on bit 1 + i of the notification this program listens on beside
            // its endpoint (bit 0 is the device manager's watchdog news): its
            // trial's end.
            says_serving: self.running[i].trial.as_ref().and(self.dog.note.as_ref()).map(|n| (n.cap(), serving_bit(i))),
            ..Program::new(image, SERVICE_IDS + i as u64)
        };
        let child = spawn(&self.root.parent, &program).map_err(|e| {
            println!("init: cannot start {}: {e:?} (2^{} bytes asked, {} bytes free)", s.name, s.memory, silica_rt::mem::available());
            "it could not be started"
        })?;
        self.running[i].starts += 1;
        if let Some((_, given)) = &mut self.left[i] {
            *given = true;
        }
        self.running[i].restarts.started(silica_rt::clock().now());
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
        self.take_lent(i as u64);
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

    /// The service whose call this is, as what `program` lends to: a
    /// declared service (`refused` for any other caller).
    fn borrower(&self) -> Result<u64, manager::Error> {
        (self.caller & CONSUMERS != 0).then_some(self.caller & 0xFFFF_FFFF).ok_or(manager::Error::Refused)
    }

    /// Take back the memory service `caller` was lent for a program
    /// (`program`), if any: its borrower's capability goes with the frame.
    fn take_lent(&mut self, caller: u64) {
        while let Some(k) = self.lent.iter().position(|(c, _, _)| *c == caller) {
            let (_, _, frame) = self.lent.swap_remove(k);
            // SAFETY: never mapped here outside `copy_out`.
            #[allow(unsafe_code)]
            unsafe {
                frame.destroy()
            };
        }
    }

    /// A message on the exit endpoint about a service: it ended (`EXIT_LABEL`,
    /// or `AGAIN_LABEL`) or faulted (`FAULT_BADGE`). Returns the service and
    /// how it ended, or `None` for a message about nothing of ours, one that
    /// says nothing this program acts on, or a fault on memory a peer took
    /// back, which is answered.
    fn ended(&mut self, m: &sys::Message) -> Option<(usize, End)> {
        let fault = m.badge & FAULT_BADGE != 0;
        let i = (m.badge & !FAULT_BADGE).checked_sub(SERVICE_IDS)? as usize;
        if i >= self.services.len() || self.running[i].child.is_none() {
            return None;
        }
        let how = match m.info.label() {
            _ if fault => End::Fault,
            EXIT_LABEL => End::Status(m.words[0] as i64),
            AGAIN_LABEL => End::Again,
            // Whatever else a program tells its parent changes nothing.
            _ => return None,
        };
        // Memory a peer lent it and took back: it carries on, on zeros.
        if fault && self.running[i].child.as_mut().is_some_and(|c| c.answer_peer_fault(m)) {
            return None;
        }
        let child = self.running[i].child.take()?;
        self.end(i, child);
        Some((i, how))
    }

    /// Service `i`'s program says it serves (its bit, `serving_bit`): if an update
    /// installed it, the update's trial is over and the program before it
    /// is let go.
    fn serves(&mut self, i: usize) {
        if self.running[i].child.is_some() && self.running[i].trial.take().is_some() {
            println!("init: {}'s new program serves; it is kept", self.services[i].name);
        }
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

    /// Say how service `i` ended.
    fn say_end(&self, i: usize, how: End) {
        let name = self.services[i].name;
        match how {
            End::Status(0) => println!("init: {name} ended"),
            End::Status(s) => println!("init: {name} ended with status {s}"),
            End::Fault => println!("init: {name} faulted"),
            End::Again => println!("init: {name} ended asking to be started again, which only a driver's device needs: a failure"),
        }
    }

    /// Service `i` ended (`how`): say so, and start it again if it asks to be.
    fn after(&mut self, i: usize, how: End) {
        let name = self.services[i].name;
        self.say_end(i, how);
        let failed = how != End::Status(0);
        if failed && self.running[i].trial.is_some() && !self.running[i].stopped {
            println!("init: {name}'s new program failed before it served; it is started on the program before it");
            self.undo_update(i);
            self.start_again(i, " on the program before its update");
            return;
        }
        if !failed || !self.services[i].restart || self.running[i].stopped {
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
    /// Make the capability the watchdog is taken through: the device
    /// manager's, with the watchdog's scope, which only this program can
    /// give (no declaration names it). Nothing is asked here: the device
    /// manager signals `dog.note` when it has a watchdog's driver (and once
    /// when it starts, so a machine without one is said to have none), and
    /// `find_watchdog` takes it then.
    fn watch_watchdog(&mut self) {
        let Some(p) = self.services.iter().position(|s| s.provides == Some("silica.device.Manager")) else { return };
        let Some(ep) = self.endpoints[p].as_ref().map(Object::cap) else { return };
        let badge = (CONSUMERS + self.services.len() as u64) | (scope::DEVICE_WATCHDOG << scope::SHIFT);
        let Some(slot) = silica_rt::ipc::free_slot() else { return };
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), slot, ep, Rights(Rights::WRITE.0 | Rights::GRANT.0), badge).is_err() {
            silica_rt::ipc::release_slot(slot);
            return;
        }
        // The device manager parses what devices say: a call to it has a
        // time limit, as every call to something trusted less does.
        self.dog.devices = Some(devices::Client::from(Channel::within(sys::Cap(slot), silica_rt::ipc::DRIVER_CALL_LIMIT)));
    }

    /// The device manager signalled: take the watchdog it has, if any, say
    /// what it is, and pet it. The device manager signals from its own
    /// loop, as it turns to listen, and again each time it does until it
    /// has seen its watchdog taken: a call here that it does not answer in
    /// time (it went on to something long) is made again at its next
    /// signal, not after a wait of this program's choosing.
    fn find_watchdog(&mut self) {
        // The driver held still answers: the signal was for nothing new.
        if self.dog.driver.as_mut().is_some_and(|d| d.pet().is_ok()) {
            return;
        }
        self.dog.driver = None;
        let Some(devs) = self.dog.devices.as_mut() else { return };
        let id = match devs.list(devices::Class::Watchdog, 0) {
            Ok(r) => r.devices.iter().next().map(|d| d.id),
            Err(e) => {
                println!("init: the device manager did not list watchdogs ({e:?}); asked again when it next says it has one");
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
        let opened = match devs.open(id, None) {
            Ok(o) => o,
            Err(e) => {
                println!(
                    "init: the device manager did not hand over the watchdog's driver ({e:?}); asked again when it next says it has one"
                );
                return;
            }
        };
        let mut driver = watchdog::Client::from(Channel::within(opened.driver.cap(), silica_rt::ipc::DRIVER_CALL_LIMIT));
        core::mem::forget(opened.driver);
        let info = match driver.info() {
            Ok(i) => i,
            Err(e) => {
                // The watchdog runs from the moment its device was found:
                // unpetted, it resets the machine, which is the answer to a
                // watchdog nobody can reach.
                println!(
                    "ERROR: init: the watchdog's driver did not say what it is ({e:?}): nothing pets the watchdog, which resets this machine"
                );
                return;
            }
        };
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

    /// The watchdog's one chore: its pet, when due. When the next one is
    /// (`None`: no watchdog, and nothing to wake for).
    fn tend_watchdog(&mut self) -> Option<u64> {
        self.pet_watchdog()
    }

    fn step(&mut self, listener: &mut Listener, wait: Wait, watch: Option<usize>) -> Result<Option<(usize, End)>, ()> {
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
            // Programs on trial that serve now (their bits), then the
            // device manager's word on the watchdog (bit 0).
            for i in 0..self.services.len().min(63) {
                if m.badge & serving_bit(i) != 0 {
                    self.serves(i);
                }
            }
            if m.badge & 1 != 0 {
                self.find_watchdog();
            }
            return Ok(None);
        }
        if m.badge >= CONSUMERS && m.badge & FAULT_BADGE == 0 {
            self.caller = m.badge;
            listener.answer(&m, |request, caps, reply, reply_caps| manager::dispatch(self, request, caps, reply, reply_caps));
            return Ok(None);
        }
        match self.ended(&m) {
            Some((j, how)) if Some(j) == watch => Ok(Some((j, how))),
            Some((j, how)) => {
                self.after(j, how);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Ask service `i` to end ([`silica_rt::END`] on its events notification)
    /// and wait for its exit, which the kernel delivers; the caller then
    /// stops it (what is left of it). For the machine going down only.
    /// What the wait hears meanwhile is looked after as ever, but for
    /// starting anything again: a fault of this service or another on memory
    /// a peer took back is answered (the log service reads rings whose
    /// writers have ended), another service that ends is taken back and
    /// said. A call that arrives is not answered (the machine is going
    /// down). A service that never exits is waited for [`END_WAIT`], said to
    /// have failed to end, and ended where it stands.
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
                if let Some((j, how)) = self.ended(&m) {
                    self.say_end(j, how);
                }
                continue;
            }
            let fault = m.badge & FAULT_BADGE != 0;
            if fault && self.running[i].child.as_mut().is_some_and(|c| c.answer_peer_fault(&m)) {
                continue;
            }
            if !fault && m.info.label() != EXIT_LABEL {
                continue;
            }
            if !fault && m.words[0] == 0 {
                println!("init: {name} ended in order");
            } else {
                println!("init: {name} did not end in order");
            }
            return;
        }
        println!("init: {name} did not end within {} s; it is ended where it stands", END_WAIT / SECOND);
    }

    /// Before init says its last words on this boot (a failure, the checks'
    /// verdict): the log service, if it runs, is asked to end, so every
    /// service's text is on the console first; then it is taken back.
    fn last_words(&mut self) {
        if let Some(l) = self.log.as_ref().map(|l| l.service)
            && self.running[l].child.is_some()
        {
            self.end_in_order(l);
            self.stop(l);
        }
    }

    /// Whether service `i` gave a program of its own a log whose ring is
    /// still there (`add_log`).
    fn gave_logs(&self, i: usize) -> bool {
        self.log
            .as_ref()
            .is_some_and(|l| l.given[l.first[i]..l.first[i] + self.services[i].logs as usize].iter().flatten().any(|(_, ring)| alive(ring)))
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

    /// Put back the program service `i` ran before its update on trial.
    fn undo_update(&mut self, i: usize) {
        if let Some(before) = self.running[i].trial.take() {
            self.running[i].program = before;
            self.running[i].hash = None;
            self.fresh_keep(i);
        }
    }

    /// Service `i` runs another program from its next start: the page it
    /// keeps across restarts starts empty, so nothing a program wrote there
    /// is taken for its own by one installed in its place (a compromised
    /// instance's data trusted by its replacement). The old page is handed
    /// to the new program's first instance read-only, as its last grant:
    /// another program's bytes, from which it takes what it would believe
    /// of a stranger (the network stack: which peers to tell that their
    /// connections are gone, as after it was killed, and nothing else).
    /// A page left by the program before and never handed over (the new
    /// program never started) stays the one handed over: what replaces it
    /// here was nobody's yet.
    fn fresh_keep(&mut self, i: usize) {
        if self.kept[i].is_some() {
            match Object::new(ObjectType::Frame, 12) {
                Ok(page) => {
                    println!("init: {}'s kept page starts empty for its new program", self.services[i].name);
                    if let Some(old) = self.kept[i].replace(page) {
                        let stale = match &self.left[i] {
                            Some((_, false)) => Some(old),
                            _ => self.left[i].replace((old, false)).map(|(page, _)| page),
                        };
                        if let Some(stale) = stale {
                            // SAFETY: init never maps it, and no instance
                            // has it: one never started on it, or the one
                            // that read it is ended by each caller next,
                            // and reads zeros meanwhile.
                            #[allow(unsafe_code)]
                            unsafe {
                                stale.destroy()
                            };
                        }
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

    /// Wait for service `i` (a check) to end, looking after the others
    /// meanwhile: its exit is what is waited for, `within` how long a check
    /// that never ends is given before the boot is failed.
    #[cfg(feature = "harness")]
    fn wait_for(&mut self, listener: &mut Listener, i: usize, within: u64) -> Result<i64, &'static str> {
        let deadline = silica_rt::clock().now() + within;
        loop {
            match self.step(listener, Wait::Until(deadline), Some(i)) {
                Ok(Some((_, End::Status(status)))) => return Ok(status),
                Ok(Some((_, End::Fault))) => return Err("it faulted"),
                Ok(Some((_, End::Again))) => return Err("it ended asking to be started again"),
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
        println!("init: shutting down{}", if reboot { " to reset" } else { "" });
        let caller = (self.caller & CONSUMERS != 0).then_some(self.caller & 0xFFFF_FFFF);
        let log = self.log.as_ref().map(|l| l.service);
        // Taken back only once the log service has ended.
        let mut later = Vec::new();
        for &i in self.order.clone().iter().rev() {
            if Some(i) == log {
                continue;
            }
            // A service with something to finish (`ends`: the device
            // manager, its disks' caches) is asked to end and its exit
            // waited for; not the one whose call this is, which cannot
            // answer while it waits for it (it ends what it must before it
            // calls).
            if self.services[i].ends && self.running[i].child.is_some() && caller != Some(i as u64) {
                self.end_in_order(i);
            }
            // The logs it gave its programs are rings in its own memory: it
            // keeps that until the log service has read them (it runs no
            // more: it has ended in order, or waits for this call's answer).
            if self.gave_logs(i) {
                later.push(i);
                continue;
            }
            if self.stop(i) {
                println!("init: {} stopped", self.services[i].name);
            }
        }
        // The log service, last: every ring is still whole, so what the
        // services said as they ended reaches the console before it goes,
        // and its exit says that it has.
        if let Some(l) = log
            && self.services[l].ends
            && self.running[l].child.is_some()
            && caller != Some(l as u64)
        {
            self.end_in_order(l);
        }
        for i in later.into_iter().chain(log) {
            if self.stop(i) {
                println!("init: {} stopped", self.services[i].name);
            }
        }
        let power = sys::Cap(libsys::root::SLOT_POWER);
        let why = if reboot { sys::reboot(power, 0) } else { sys::power_off(power, 0) };
        println!("ERROR: init: the machine cannot be turned off: {why:?}");
        Err(manager::Error::Refused)
    }

    fn stage(&mut self, _at: u64, _data: &[u8]) -> Result<manager::StageReply, manager::Error> {
        // Retired: nothing a caller sends is kept here before `update`.
        self.may(scope::SYSTEM_UPDATE)?;
        Err(manager::Error::Refused)
    }

    fn program(&mut self, bytes: u64) -> Result<manager::ProgramReply<Handle>, manager::Error> {
        self.may(scope::SYSTEM_UPDATE)?;
        if bytes > MAX_PROGRAM {
            return Err(manager::Error::TooLarge);
        }
        let caller = self.borrower()?;
        self.take_lent(caller);
        let bits = (bytes.max(1 << 12).next_power_of_two().trailing_zeros()) as u8;
        // The service manager's own frame, never mapped here while its
        // borrower holds it: `update` reads it once the bytes are asked for.
        let frame = Object::new(ObjectType::Frame, bits).map_err(|_| manager::Error::Refused)?;
        let lend = silica_rt::ipc::free_slot().ok_or(manager::Error::Refused).and_then(|slot| {
            sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), slot, frame.cap(), Rights(Rights::READ.0 | Rights::WRITE.0), 0)
                .map(|()| Handle::new(sys::Cap(slot)))
                .map_err(|_| {
                    silica_rt::ipc::release_slot(slot);
                    manager::Error::Refused
                })
        });
        match lend {
            Ok(memory) => {
                self.lent.push((caller, bits, frame));
                Ok(manager::ProgramReply { memory })
            }
            Err(e) => {
                // SAFETY: just made, never mapped, lent to nobody.
                #[allow(unsafe_code)]
                unsafe {
                    frame.destroy()
                };
                Err(e)
            }
        }
    }

    fn update(&mut self, name: &str, length: u64) -> Result<manager::UpdateReply, manager::Error> {
        self.may(scope::SYSTEM_UPDATE)?;
        // The memory the caller was lent, the service manager's own again:
        // destroyed with the capability its borrower holds once its first
        // `length` bytes are copied, so what is checked and run is what was
        // read, whatever the borrower writes meanwhile.
        let caller = self.borrower()?;
        let k = self.lent.iter().position(|(c, _, _)| *c == caller).ok_or(manager::Error::TooLarge)?;
        let (_, bits, frame) = self.lent.swap_remove(k);
        let program = copy_out(&frame, bits, length);
        // SAFETY: mapped only inside `copy_out`, which unmapped it.
        #[allow(unsafe_code)]
        unsafe {
            frame.destroy()
        };
        let i = self.find(name)?;
        let program = program?;
        if let Err(e) = silica_proc::check_image(&program) {
            println!("init: the program sent to update {name} is not one this machine runs: {e:?}");
            return Err(manager::Error::NotAProgram);
        }
        // What it runs now is what to go back to (an earlier update's trial,
        // if one is still on, ends here: its program is the one now kept).
        let before = self.running[i].program.take();
        self.running[i].program = Some(program);
        self.running[i].trial = Some(before);
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
        let c = (self.caller & 0xFFFF_FFFF) as usize;
        let (caller, allowed): (&'static str, usize) = self.calling().map(|s| (s.name, s.logs as usize)).ok_or(manager::Error::Refused)?;
        let source = silica_rt::alloc::format!("{caller}/{name}");
        let notify = self.log.as_ref().map(|l| self.events[l.service].0.cap()).ok_or(manager::Error::Refused)?;
        let log = self.log.as_mut().ok_or(manager::Error::Refused)?;
        // The caller's own places, as many as its declaration says (`logs=`):
        // no service takes another's, whatever it asks for.
        let mine = log.first[c]..log.first[c] + allowed;
        // A name given before keeps its place only while its ring lives: a
        // ring that is gone (the service that made it restarted, its
        // memory with it) is replaced by the new one, and the log service
        // reads on from it under the same source.
        let again = mine.clone().find(|k| log.given[*k].as_ref().is_some_and(|(n, _)| *n == source));
        if again.is_some_and(|k| log.given[k].as_ref().is_some_and(|(_, r)| alive(r))) {
            return Err(manager::Error::Exists);
        }
        // A ring of the size every log's writer and reader assume.
        let fits = matches!(sys::inspect_slot(sys::Cap(libsys::root::SLOT_CAPSPACE), ring.cap().0),
            Ok(Some(i)) if i.ty == ObjectType::Frame && i.bits == silica_rt::log::BITS);
        if !fits || name.is_empty() || name.len() > 64 || source.len() > directory::NAME {
            return Err(manager::Error::Refused);
        }
        // Its place again, else one of its own never used, else one whose
        // ring is gone (its maker ended for good); with none, the service
        // has every log its declaration gives it.
        let free = |want_empty: bool| mine.clone().find(|k| log.given[*k].as_ref().map_or(want_empty, |(_, r)| !want_empty && !alive(r)));
        let Some(k) = again.or_else(|| free(true)).or_else(|| free(false)) else {
            println!("init: {caller} asked for another log; it has the {allowed} its declaration gives it (logs=)");
            return Err(manager::Error::Refused);
        };
        let to = silica_rt::ipc::free_slot().ok_or(manager::Error::Refused)?;
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, notify, Rights::WRITE, 0).is_err() {
            silica_rt::ipc::release_slot(to);
            return Err(manager::Error::Refused);
        }
        log.given[k] = Some((source, ring));
        // Into the log service's own slot for it, if it runs (one started
        // later is given it with the others: `grants`), then named in the
        // directory: the log service never asks the service manager
        // (`silica_rt::log::directory`). The slot of a ring that is gone
        // emptied when it went, with every capability derived from it.
        let entry = self.services.len() + k;
        let slot = self.log_slot(entry);
        let log = self.log.as_ref().ok_or(manager::Error::Refused)?;
        if let Some((source, ring)) = &log.given[k] {
            if let Some(child) = &self.running[log.service].child
                && let Err(e) = sys::cap_derive(child.space(), slot, ring.cap(), Rights(Rights::READ.0 | Rights::WRITE.0), 0)
            {
                println!("init: cannot give the log service the ring of {source}: {e:?}");
            }
            directory::publish(&log.directory.shared(), entry, source.as_bytes());
        }
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
    say_last_panic(info);
    let cmdline: &'static [u8] = &info.cmdline[..(info.cmdline_len as usize).min(info.cmdline.len())];
    #[cfg(feature = "harness")]
    let checks: Vec<&[u8]> =
        option(cmdline, "checks").unwrap_or(b"programs,block").split(|b| *b == b',').filter(|c| !c.is_empty()).collect();
    #[cfg(feature = "harness")]
    {
        if checks.contains(&&b"programs"[..]) {
            program_checks(&root);
        }
        if checks.contains(&&b"spawn"[..]) {
            spawn_bench(&root);
        }
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
    let kept: Vec<Option<Object>> = services
        .iter()
        .map(|s| s.keeps.then(|| Object::new(ObjectType::Frame, 12).unwrap_or_else(|_| fail!("no memory for {}'s page", s.name))))
        .collect();
    // Where each service runs (its declaration's `cpu=`, or processor 0).
    let placed = place(&services, root.parent.cpus as usize);
    // Time for each service: one share of the processor it runs on
    // (processor time is a capability, and the service manager holds
    // every processor's). A program that makes many threads takes that
    // one share, not one a thread (the 2026-11-24 audit).
    let sched = services
        .iter()
        .zip(&placed)
        .map(|(s, &cpu)| {
            let g = Object::new(ObjectType::SchedContext, 0).unwrap_or_else(|_| fail!("no memory for {}'s scheduling context", s.name));
            if let Err(e) = sys::sched_fair(g.cap(), libsys::SCHED_DEFAULT_WEIGHT, cpu, sys::Cap(libsys::root::SLOT_SCHED)) {
                fail!("cannot give {} a share of processor {cpu}: {e:?}", s.name);
            }
            g
        })
        .collect();
    // The log, when a service provides it: a ring for every other service,
    // made before anything starts, and a place for every log the services'
    // declarations let them give their programs (`logs=`); the log starts
    // first. Its writers signal the log service's own events notification.
    let mut order = order;
    let log = match services.iter().position(|s| s.provides == Some("silica.log.Reader")) {
        None => None,
        Some(l) => {
            let object = |ty, bits| Object::new(ty, bits).unwrap_or_else(|_| fail!("no memory for the log"));
            let rings = (0..services.len()).map(|i| (i != l).then(|| object(ObjectType::Frame, silica_rt::log::BITS))).collect();
            order.retain(|&i| i != l);
            order.insert(0, l);
            let mut first = Vec::new();
            let mut places = 0;
            for s in &services {
                first.push(places);
                places += s.logs as usize;
            }
            if services.len() + places > directory::ENTRIES {
                fail!(
                    "the services and the {places} logs their declarations give them (logs=) are more than the {} the log's directory names",
                    directory::ENTRIES
                );
            }
            let directory = silica_rt::mem::Memory::new(directory::BITS).unwrap_or_else(|_| fail!("no memory for the log"));
            for (i, s) in services.iter().enumerate() {
                if i != l {
                    directory::publish(&directory.shared(), i, s.name.as_bytes());
                }
            }
            let to = silica_rt::ipc::free_slot().unwrap_or_else(|| fail!("no slot for the log"));
            if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, events[l].0.cap(), Rights::WRITE, ADDED).is_err() {
                fail!("cannot make the log's capability for added logs");
            }
            Some(LogSetup { service: l, rings, added: sys::Cap(to), given: (0..places).map(|_| None).collect(), first, directory })
        }
    };
    // Each service's options, from the boot command line: a test image's
    // alone (the module's documentation says why).
    #[cfg(not(feature = "harness"))]
    let options: Vec<Vec<u8>> = {
        not_obeyed(cmdline, &services);
        services.iter().map(|_| Vec::new()).collect()
    };
    #[cfg(feature = "harness")]
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
        root,
        info,
        services,
        endpoints,
        running,
        events,
        left: kept.iter().map(|_| None).collect(),
        kept,
        sched,
        time,
        options,
        order: order.clone(),
        listed: Vec::new(),
        described: String::new(),
        caller: 0,
        lent: Vec::new(),
        hashes: Vec::new(),
        log,
        // The watchdog's notification exists before the device manager is
        // started: it is among that program's grants.
        dog: Watchdog { note: Object::new(ObjectType::Notification, 0).ok(), ..Watchdog::default() },
    };
    let mut listener = Listener::new(m.root.parent.exit);

    // The system, in order, but for what a test image's command line keeps off.
    #[cfg(feature = "harness")]
    let off: Vec<&[u8]> = option(cmdline, "off").unwrap_or(b"").split(|b| *b == b',').filter(|c| !c.is_empty()).collect();
    #[cfg(not(feature = "harness"))]
    let off: Vec<&[u8]> = Vec::new();
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
            fail_with!(m, "{}: {e}", m.services[i].name);
        }
    }
    // The machine's watchdog, petted from here on.
    m.watch_watchdog();
    #[cfg(feature = "harness")]
    run_checks(&mut m, &mut listener, &checks, &order, cmdline);
    // The system stays up, and its services are looked after.
    println!("BOOT OK");
    let mut next = None;
    loop {
        let wait = next.map_or(Wait::Forever, Wait::Until);
        let _ = m.step(&mut listener, wait, None);
        next = m.restart_due();
    }
}

/// The last boot's end, when the kernel kept its record across the reset
/// (`RootInfo::last_panic`: the console's last lines, the panic and its
/// backtrace): said here, so the owner reading this boot's log learns that
/// the machine reset itself and why. The record is the last boot's bytes,
/// whatever was on its console: shown as text, obeyed by no terminal.
fn say_last_panic(info: &RootInfo) {
    let record = &info.last_panic[..(info.last_panic_len as usize).min(info.last_panic.len())];
    if record.is_empty() {
        return;
    }
    println!("init: the last boot ended in a kernel panic and the machine reset itself; the kernel's record of it:");
    for line in String::from_utf8_lossy(record).lines().filter(|l| !l.trim().is_empty()) {
        // In pieces a line of the console holds whole.
        let mut rest = line;
        while !rest.is_empty() {
            let cut = (0..=rest.len().min(160)).rev().find(|n| rest.is_char_boundary(*n)).unwrap_or(rest.len());
            let (piece, more) = rest.split_at(cut.max(1).min(rest.len()));
            println!("init: | {}", silica_rt::text::printable(piece));
            rest = more;
        }
    }
    println!("init: end of the last boot's panic record");
}

/// What a test image's command line asks for once the system is up
/// (`checks=`). Returns when it asked for nothing that ends the boot: the
/// system then stays up.
#[cfg(feature = "harness")]
fn run_checks(m: &mut Manager, listener: &mut Listener, checks: &[&[u8]], order: &[usize], cmdline: &'static [u8]) {
    // `checks=watchdog`: once the watchdog is petted, stop petting it and
    // answering anyone, as a hung service manager would: the watchdog must
    // reset the machine, and the next boot hears it did.
    if checks.contains(&&b"watchdog"[..]) {
        let until = silica_rt::clock().now() + 60 * SECOND;
        while m.dog.driver.is_none() && silica_rt::clock().now() < until {
            let _ = m.step(listener, Wait::Until(until), None);
        }
        if m.dog.driver.is_none() {
            fail_with!(m, "checks=watchdog: no watchdog came within 60 s");
        }
        m.last_words();
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
        for &i in order {
            if !matches!(m.services[i].start, Start::Check(n) if n.as_bytes() == *c) {
                continue;
            }
            any = true;
            let name = m.services[i].name;
            if let Err(e) = m.start(i) {
                fail_with!(m, "{name}: {e}");
            }
            match m.wait_for(listener, i, 120 * SECOND) {
                Ok(0) => println!("init: {name} passed"),
                Ok(s) => fail_with!(m, "{name} ended with status {s}"),
                Err(e) => fail_with!(m, "{name}: {e}"),
            }
        }
        if !any {
            fail_with!(m, "checks= names {}, which no service is declared for", core::str::from_utf8(c).unwrap_or("?"));
        }
        checked = true;
    }
    if checked || checks.contains(&&b"programs"[..]) || checks.contains(&&b"spawn"[..]) {
        // Every service's text on the console before the verdict.
        m.last_words();
        if option(cmdline, "bench").is_some() || cmdline.split(|b| b.is_ascii_whitespace()).any(|w| w == b"bench") {
            println!("BENCH DONE");
        }
        println!("BOOT OK");
        if cmdline.split(|b| b.is_ascii_whitespace()).any(|w| w == b"halt=reboot") {
            let why = sys::reboot(sys::Cap(libsys::root::SLOT_POWER), 0);
            fail!("the machine cannot be reset: {why:?}");
        }
        halt(true)
    }
}

/// `checks=spawn`: how long a program takes from its parent's `spawn` to
/// its own first line of code (`hello` asked to answer with the time it
/// started), over [`SPAWNS`] programs started and taken down one after
/// another, before any service runs. Prints `BENCH spawn` (median) and
/// `BENCH spawn_p99`, in nanoseconds; the Linux baseline measures fork or
/// vfork and exec of a static program to its `main` the same way
/// (os/bench/linux/init.c).
#[cfg(feature = "harness")]
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

/// `checks=programs`: the round trips everything rests on: a program runs
/// in its own address space and CapSpace, reports its exit, and its memory
/// comes back; two programs call each other through a protocol.
#[cfg(feature = "harness")]
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

/// The first `length` bytes of `frame` (the service manager's own, of
/// `2^bits` bytes), copied once: `too_large` past its end, `refused` with
/// no memory for the copy. Mapped for the copy alone, at addresses the next
/// copy of that size takes again.
fn copy_out(frame: &Object, bits: u8, length: u64) -> Result<Vec<u8>, manager::Error> {
    if length > 1 << bits {
        return Err(manager::Error::TooLarge);
    }
    let map = silica_rt::mem::Lent::map(frame.cap(), bits, Rights::READ).map_err(|_| manager::Error::Refused)?;
    let mut program = Vec::new();
    program.try_reserve_exact(length as usize).map_err(|_| manager::Error::Refused)?;
    program.resize(length as usize, 0);
    map.region().read_bytes(0, &mut program);
    Ok(program)
}
