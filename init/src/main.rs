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
//! first, then the power).
//!
//! The kernel command line chooses what is checked at boot (`checks=`, a
//! comma list; default `programs,block`): `programs` runs the round trips
//! everything rests on (a program's memory comes back, two programs talk
//! through a protocol), and every other name runs the services declared
//! `start=check:<name>`, which must end with status 0. When checks ran, the
//! machine is turned off when they are done (`halt=reboot`: reset);
//! without them the system stays up. `bench` on the command line prints
//! `BENCH DONE` when the checks are done (`tools/bench.sh` reads up to it).
#![no_std]
#![no_main]

mod manifest;

use core::sync::atomic::{AtomicU64, Ordering};
use libsys::root::{KIND_DEVICE, KIND_FIRMWARE, RootInfo, SLOT_DEVICES, SLOT_FIRST_UNTYPED, SLOT_INFO, SLOT_IRQS};
use libsys::{self as sys, ObjectType, Rights, Wait};
use manifest::{Service, Start};
use silica_formats::ramdisk;
use silica_proc::root::{self, Root, finish};
use silica_proc::{Child, FAULT_BADGE, Grant, Program, spawn};
use silica_protocols::system::manager;
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Handle, Listener};
use silica_rt::mem::Object;
use silica_rt::{EXIT_LABEL, println};

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

/// Have the log service put everything its rings hold on the console before
/// what init says next, waiting at most 200 ms: init never waits on a
/// service for long.
fn flush_log() {
    let (to, done) = (FLUSH_TO.load(Ordering::Relaxed), FLUSHED.load(Ordering::Relaxed));
    if to == 0 {
        return;
    }
    // A late answer to an earlier flush is not this one's.
    let _ = sys::recv(sys::Cap(done), Wait::Poll);
    if sys::signal(sys::Cap(to)).is_ok() {
        let _ = sys::recv(sys::Cap(done), Wait::Until(silica_rt::clock().now() + 200_000_000));
    }
}

const SECOND: u64 = 1_000_000_000;
/// Badges of consumers' capabilities to a provider start here.
const CONSUMERS: u64 = 1 << 32;
/// Service `i` runs with the program identifier `SERVICE_IDS + i`.
const SERVICE_IDS: u64 = 1000;
/// How often a failing service is started again.
const MAX_RESTARTS: u32 = 3;

/// A service and what it is now.
struct Running {
    child: Option<Child>,
    failures: u32,
    /// Stopped by the owner: not started again until asked.
    stopped: bool,
}

struct Manager {
    root: Root,
    info: &'static RootInfo,
    services: Vec<Service>,
    /// The endpoint of each service that provides a protocol.
    endpoints: Vec<Option<Object>>,
    running: Vec<Running>,
    /// The order services were started in, for stopping them in reverse.
    order: Vec<usize>,
    /// What `list` answers with, rebuilt for each call.
    listed: Vec<manager::Service<'static>>,
    /// What `describe` answers with.
    described: String,
    /// The log: the service that provides it, its notification, what it
    /// answers flushes on, and a ring per service (`silica_rt::log`).
    log: Option<LogSetup>,
}

struct LogSetup {
    service: usize,
    note: Object,
    flushed: Object,
    rings: Vec<Option<Object>>,
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
        for need in &s.needs {
            let ep = if *need == manifest::ROOT_PROTOCOL {
                self.root.parent.exit
            } else {
                let p = self.services.iter().position(|p| p.provides == Some(*need)).ok_or("a need with no provider")?;
                self.endpoints[p].as_ref().ok_or("a provider without an endpoint")?.cap()
            };
            grants.push(Grant::badged(ep, Rights(Rights::WRITE.0 | Rights::GRANT.0), CONSUMERS + i as u64));
        }
        if let Some(log) = self.log.as_ref().filter(|l| l.service == i) {
            grants.push(Grant::lend(log.note.cap(), Rights::ALL));
            grants.push(Grant::lend(log.flushed.cap(), Rights::WRITE));
            for r in &log.rings {
                grants.push(match r {
                    Some(f) => Grant::lend(f.cap(), Rights(Rights::READ.0 | Rights::WRITE.0)),
                    None => Grant::none(),
                });
            }
            args[0] = log.rings.len() as u64;
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
        Ok((grants, args))
    }

    /// Start service `i`.
    fn start(&mut self, i: usize) -> Result<(), &'static str> {
        let s = &self.services[i];
        let image = ramdisk::find(self.root.archive, s.program).ok_or("its program is not in the boot archive")?;
        let (grants, args) = self.grants(i)?;
        let log = self.log.as_ref().and_then(|l| Some((l.rings.get(i)?.as_ref()?.cap(), l.note.cap())));
        let program = Program {
            grants: &grants,
            args,
            log,
            mem_bits: s.memory,
            space_bits: if s.machine { 13 } else { 10 },
            aspace_bits: 18,
            ..Program::new(image, SERVICE_IDS + i as u64)
        };
        let child = spawn(&self.root.parent, &program).map_err(|e| {
            println!("init: cannot start {}: {e:?}", s.name);
            "it could not be started"
        })?;
        self.running[i].child = Some(child);
        Ok(())
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
        if child.destroy().is_err() {
            println!("ERROR: init: cannot take back the memory of {}", self.services[i].name);
        }
        Some((i, if fault { None } else { Some(m.words[0] as i64) }))
    }

    /// Service `i` ended with `status` (`None`: it faulted): say so, and
    /// start it again if it asks to be.
    fn after(&mut self, i: usize, status: Option<i64>) {
        let name = self.services[i].name;
        match status {
            Some(0) => println!("init: {name} ended"),
            Some(s) => println!("init: {name} ended with status {s}"),
            None => println!("init: {name} faulted"),
        }
        if status == Some(0) || !self.services[i].restart || self.running[i].stopped {
            return;
        }
        self.running[i].failures += 1;
        if self.running[i].failures > MAX_RESTARTS {
            println!("ERROR: init: {name} failed {MAX_RESTARTS} times; it is not started again");
        } else if let Err(e) = self.start(i) {
            println!("ERROR: init: {name}: {e}");
        } else {
            println!("init: {name} started again");
        }
    }

    /// Take one message from the endpoint: a call of `silica.system.Manager`
    /// is answered, a service's end looked after. Returns the end of a
    /// service the caller is waiting for (`watch`), or `Err` at the deadline.
    fn step(&mut self, listener: &mut Listener, wait: Wait, watch: Option<usize>) -> Result<Option<(usize, Option<i64>)>, ()> {
        let m = listener.recv(wait).map_err(|_| ())?;
        if m.badge >= CONSUMERS && m.badge & FAULT_BADGE == 0 {
            listener.answer(&m, |request, caps, reply, reply_caps| manager::dispatch(self, request, caps, reply, reply_caps));
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

    /// Stop service `i` at once, as if it had failed, but for good.
    fn stop(&mut self, i: usize) -> bool {
        self.running[i].stopped = true;
        match self.running[i].child.take() {
            Some(child) => {
                if child.destroy().is_err() {
                    println!("ERROR: init: cannot take back the memory of {}", self.services[i].name);
                }
                true
            }
            None => false,
        }
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

impl manager::Server<Handle> for Manager {
    fn list<'a>(&'a mut self) -> manager::ListReply<'a, Handle> {
        self.listed.clear();
        for (i, s) in self.services.iter().enumerate() {
            let r = &self.running[i];
            let state = if r.child.is_some() {
                manager::State::Running
            } else if s.restart && r.failures > MAX_RESTARTS {
                manager::State::Failed
            } else {
                manager::State::Stopped
            };
            self.listed.push(manager::Service { name: s.name, state, failures: r.failures, provides: s.provides.unwrap_or("") });
        }
        manager::ListReply { services: silica_idl_rt::Array::new(&self.listed) }
    }

    fn stop(&mut self, name: &str) -> Result<manager::StopReply, manager::Error> {
        let i = self.services.iter().position(|s| s.name == name).ok_or(manager::Error::NoSuchService)?;
        if self.services[i].machine || self.running[i].child.is_none() {
            return Err(manager::Error::Refused);
        }
        self.stop(i);
        println!("init: {name} stopped, as asked");
        Ok(manager::StopReply {})
    }

    fn start(&mut self, name: &str) -> Result<manager::StartReply, manager::Error> {
        let i = self.services.iter().position(|s| s.name == name).ok_or(manager::Error::NoSuchService)?;
        if self.running[i].child.is_none() {
            self.running[i].stopped = false;
            Manager::start(self, i).map_err(|_| manager::Error::Refused)?;
            println!("init: {name} started, as asked");
        }
        Ok(manager::StartReply {})
    }

    fn describe<'a>(&'a mut self, name: &str, from: u32) -> Result<manager::DescribeReply<'a>, manager::Error> {
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
        flush_log();
        println!("init: shutting down{}", if reboot { " to reset" } else { "" });
        for &i in self.order.clone().iter().rev() {
            if self.stop(i) {
                println!("init: {} stopped", self.services[i].name);
            }
        }
        let power = sys::Cap(libsys::root::SLOT_POWER);
        let why = if reboot { sys::reboot(power, 0) } else { sys::power_off(power, 0) };
        println!("ERROR: init: the machine cannot be turned off: {why:?}");
        Err(manager::Error::Refused)
    }
}

/// Program entry, called by libsys's `_start`.
// SAFETY: the one definition of the symbol `_start` calls.
#[unsafe(no_mangle)]
extern "C" fn silica_main(info: &'static RootInfo) -> ! {
    let root = match root::start(info) {
        Ok(r) => r,
        Err(e) => fail!("{e}"),
    };
    // Faults of the services are reported where their exits are.
    let root = Root { parent: silica_proc::Parent { fault: root.parent.exit, ..root.parent }, ..root };
    let cmdline: &'static [u8] = &info.cmdline[..(info.cmdline_len as usize).min(info.cmdline.len())];
    let checks: Vec<&[u8]> =
        option(cmdline, "checks").unwrap_or(b"programs,block").split(|b| *b == b',').filter(|c| !c.is_empty()).collect();

    if checks.contains(&&b"programs"[..]) {
        program_checks(&root);
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
    let running = services.iter().map(|_| Running { child: None, failures: 0, stopped: false }).collect();
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
            Some(LogSetup { service: l, note, flushed, rings })
        }
    };
    let mut m =
        Manager { root, info, services, endpoints, running, order: order.clone(), listed: Vec::new(), described: String::new(), log };
    if let Some(l) = &m.log {
        let to = silica_rt::ipc::free_slot().unwrap_or_else(|| fail!("no slot for the log"));
        if sys::cap_derive(sys::Cap(libsys::root::SLOT_CAPSPACE), to, l.note.cap(), Rights::WRITE, FLUSH).is_err() {
            fail!("cannot make the log's flush capability");
        }
        FLUSH_TO.store(to, Ordering::Relaxed);
        FLUSHED.store(l.flushed.cap().0, Ordering::Relaxed);
    }
    let mut listener = Listener::new(m.root.parent.exit);

    // The system, in order.
    for &i in &order {
        if m.services[i].start == Start::Boot
            && let Err(e) = m.start(i)
        {
            fail!("{}: {e}", m.services[i].name);
        }
    }
    // The checks the command line asks for, in its order.
    let mut checked = false;
    for c in checks.iter().filter(|c| **c != b"programs") {
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
    if checked || checks.contains(&&b"programs"[..]) {
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
    loop {
        let _ = m.step(&mut listener, Wait::Forever, None);
    }
}

/// The round trips everything rests on: a program runs in its own address
/// space and CapSpace, reports its exit, and its memory comes back; two
/// programs call each other through a protocol.
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
