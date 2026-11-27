//! The device manager (component D15).
//!
//! It is given the description of the machine and every device capability
//! there is: all device memory, every device identity, every interrupt
//! line. It finds the devices (PCI functions, through the configuration
//! space the firmware's MCFG table points at), and for each one it has a
//! driver for it starts that driver as a program of its own holding that
//! device and nothing else: its registers, its identity, its interrupt
//! lines (`silica_driver` documents what a driver finds when it starts).
//!
//! What a driver may do to its device is decided here, before it runs: the
//! device manager switches on memory decoding, bus mastering and MSI-X in
//! configuration space, and the driver gets configuration space read-only,
//! so no driver can move its device's registers onto another's.
//!
//! A driver reads memory its clients lend it (the rings of a block
//! connection), which a client can take back at any moment. A page fault
//! there is the client's doing, not the driver's: it is answered with a
//! page of zeros (up to [`silica_proc::ZERO_PAGES`] in one run of a driver), which the
//! driver reads as a broken ring and closes that connection. No client can
//! crash a driver by taking its memory back.
//!
//! A driver that faults or ends with a failure is taken down, its device
//! is silenced (no bus mastering; the kernel has already cut it off from
//! memory, which happens when the driver's device address space goes), and
//! the driver is started again (at once the first time, then backing off,
//! never for good: `silica_proc::Restarts`); the driver is told how many
//! times it has been started. Which program drives a device is said by the
//! boot archive's `drivers` list and by nothing else: the list is part of
//! the archive the kernel checked, and no word of the boot command line
//! reaches this program's choice (before, `driver=<ids>=<program>` there
//! gave any program in the archive a device's authority).
//!
//! In a test image only (the `harness` feature, which a machine's image is
//! never built with), the device manager's own option
//! `inject=<driver>:<fault>@<n>` (`devmgr.inject=...` to the service
//! manager) has the first run of `<driver>` commit a device's fault at its
//! `n`th request (`silica_driver::inject`).
//!
//! It provides `silica.device.Manager`: a program that uses devices (the
//! block server, a filesystem, the network stack) lists the devices of a
//! class and opens the driver of one. When a driver ends, every capability
//! to it that was handed out stops working (its endpoint is destroyed), so a
//! client of a driver that was started again finds out on its next call
//! and opens the new one.
//!
//! One endpoint carries everything the device manager hears, each kind by
//! its badge: a client's calls (badges from [`CLIENTS`] up; whoever starts
//! the device manager hands those out), and its drivers' exit reports and
//! faults (each driver's identifier, below that).
//!
//! The machine's ACPI fixed events are its too: the power button asks the
//! service manager to shut the system down (`silica.system.Manager`).
//!
//! Started by the service manager (its service is declared `machine`) with,
//! as grants: 0 its endpoint (to receive on, and to give drivers their way
//! to report), 1 the service manager's (`silica.system.Manager`), 2 the
//! frame of the kernel's `RootInfo` (read-only), 3 the device identities,
//! 4 the interrupt lines, 5 the I/O ports (or nothing), 6 a capability that
//! signals the service manager's watchdog notification (how it is told
//! that the watchdog's driver changed: `Manager::tell_watchdog`), then
//! `args[0]` frames (one, or none): the drivers' archive, read-only (the
//! drivers list and the programs it names, nothing else of the boot
//! archive: `map_archive`), then `args[1]` Untyped capabilities, given
//! outright: the machine's device memory and the firmware's memory (where
//! its ACPI tables are), in `RootInfo` order.
#![no_std]
#![no_main]

mod phys;
mod power;

use devmgr::hotplug;
use libsys::root::{KIND_DEVICE, KIND_FIRMWARE, ROOT_MAGIC, RootInfo};
use libsys::{self as sys, Cap, ObjectType, Rights, Wait};
use phys::DeviceMemory;
use silica_driver::pci::{self, Config};
use silica_formats::{acpi, ramdisk};
use silica_proc::{Child, FAULT_BADGE, Grant, Parent, Program, Restarts, spawn};
use silica_rt::alloc::collections::BTreeMap;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle, Listener, free_slot, release_slot};
use silica_rt::mem::{self, Object, OwnedObject};
use silica_rt::mmio::Mmio;
use silica_rt::{EXIT_LABEL, ProcessInfo, println, slots};

use silica_protocols::device::{PciAddress, manager};
use silica_protocols::{paging, scope};

silica_rt::main!(main);

const RW: Rights = Rights(Rights::READ.0 | Rights::WRITE.0);
const GRANT_ENDPOINT: u64 = 0;
const GRANT_SYSTEM: u64 = 1;
const GRANT_INFO: u64 = 2;
const GRANT_DEVICES: u64 = 3;
const GRANT_IRQS: u64 = 4;
const GRANT_PORTS: u64 = 5;
const GRANT_WATCHDOG: u64 = 6;
const GRANT_FIRST_RAMDISK: u64 = 7;
/// Badges of the capabilities clients call through start here (and stay
/// below `silica_proc::FAULT_BADGE`); below are the drivers'.
pub const CLIENTS: u64 = 1 << 32;
/// Interrupt lines one device gets at most.
const LINES_PER_DEVICE: u32 = 8;

fn granted(n: u64) -> Cap {
    Cap(slots::FIRST_GRANT + n)
}

/// A PCI function found on the machine.
struct Function {
    /// Segment, bus, device, function, as the kernel takes a device identity.
    id: u32,
    config: Config,
    /// The frame of its configuration space.
    config_frame: Cap,
    vendor: u16,
    device: u16,
    class: (u8, u8, u8),
    bars: [Option<pci::Bar>; 6],
    vectors: u16,
    /// Its interrupt lines (first, count), once a driver was started for it.
    lines: Option<(u32, u32)>,
    /// How many times a driver has been started for it.
    starts: u32,
    /// Its driver's failures (faulted, or ended with a failure; an owner's
    /// restart is not one) and when it is started again
    /// (`silica_proc::Restarts`), and the driver waiting to be.
    restarts: Restarts,
    waiting: Option<&'static str>,
    /// Its drivers' log (`silica.system.Manager`'s `add_log`): the ring and
    /// what its writer signals, made when its first driver starts and
    /// handed to every one after it.
    log: Option<(Object, Handle)>,
}

/// A driver that is running.
struct Running<'a> {
    name: &'a str,
    /// The identifier its exit report and its faults carry.
    id: u64,
    function: usize,
    child: Child,
    /// The endpoint its clients call it on.
    service: Object,
    /// The driver's events notification (`slots::EVENTS` in it): what
    /// the device manager asks it to end on ([`silica_rt::END`]).
    events: OwnedObject,
    /// What clients asked to have signalled when this driver ends.
    gone: Vec<(u64, Handle)>,
    /// A client was given it (`open`) since it started: one that then ends
    /// asking to be started again (`silica_rt::AGAIN_LABEL`) is, at once; one
    /// nobody opened is not (it could keep the device manager starting it).
    opened: bool,
}

struct Manager {
    info: &'static RootInfo,
    memory: DeviceMemory,
    /// Pages of firmware tables mapped so far, by physical page address.
    tables: BTreeMap<u64, usize>,
    archive: &'static [u8],
    parent: Parent,
    functions: Vec<Function>,
    running: Vec<Running<'static>>,
    /// Interrupt lines given back (first, count): a device that left gives
    /// its back, and the next device is given them before new ones (before,
    /// every arrival took new lines and none came back, so a slot worked
    /// for as many insertions as the machine had lines).
    free_lines: Vec<(u32, u32)>,
    /// The next interrupt line to hand out.
    next_line: u32,
    next_id: u64,
    /// What `list` answers with, rebuilt for each call.
    listing: Vec<manager::Device<'static>>,
    /// What `describe` answers with, one part of it.
    described: silica_rt::alloc::string::String,
    /// Badges of driver capabilities handed out, so each client is told apart.
    next_client: u64,
    /// Hot-plug capable ports, with the configuration space base (ECAM)
    /// and segment of the buses behind them.
    /// (Each with the segment's last bus.)
    ports: Vec<(hotplug::Port, u64, u16, u8)>,
    /// Every bridge found: its segment and the buses behind it, to judge
    /// a hot-plug port's own (`hotplug::buses_valid`).
    bridges: Vec<(u32, u8, u8)>,
    /// Slots a device arrived in, waiting for their link (its deadline)
    /// or for the 100 ms a device has after its link comes up: the port,
    /// when to give up or go on, and whether the link is up. The device
    /// manager serves meanwhile; before, it spun here for up to 1.1 s.
    settling: Vec<(usize, u64, bool)>,
    /// Devices that arrived in and departed from slots, for the log.
    arrivals: u64,
    departures: u64,
    /// The longest the device manager went without listening, in
    /// nanoseconds: what a client or a fault report may have waited.
    longest_turn: u64,
    /// The archive's drivers, by what they drive.
    table: Vec<(Match, &'static str)>,
    /// The configuration writes each driver's declaration asks for, made
    /// before it starts (`drivers`).
    writes: Vec<(&'static str, Vec<ConfigWrite>)>,
    /// The drivers the archive's list says do no DMA (`nodma`).
    no_dma: Vec<&'static str>,
    /// Every configuration space mapped, by function identity.
    configs: BTreeMap<u32, (Config, Cap)>,
    /// What clients asked to have signalled when a device of a class gains
    /// or loses its driver (`watch`).
    watchers: Vec<(u64, manager::Class, Handle)>,
    /// The service manager has not been seen to act on the watchdog as it
    /// now is (`tell_watchdog`): true from the start, so a machine without
    /// a watchdog is said to have none, and again whenever a watchdog's
    /// driver starts or ends.
    watchdog_news: bool,
    /// It was told of that news, and this program has done nothing since
    /// but answer it: not told again until it has.
    watchdog_told: bool,
    /// The badge of the call being answered: whose capability, and its
    /// scopes (`silica_protocols::scope`).
    caller: u64,
}

/// The scope a caller needs for devices of `class`.
fn scope_of(class: manager::Class) -> u64 {
    match class {
        manager::Class::Block => scope::DEVICE_BLOCK,
        manager::Class::Network => scope::DEVICE_NETWORK,
        manager::Class::Display => scope::DEVICE_DISPLAY,
        manager::Class::Port => scope::DEVICE_PORT,
        manager::Class::Input => scope::DEVICE_INPUT,
        manager::Class::Entropy => scope::DEVICE_ENTROPY,
        manager::Class::Watchdog => scope::DEVICE_WATCHDOG,
        _ => 0,
    }
}

/// A function as found, its BARs probed.
fn function_of(id: u32, config: Config, config_frame: Cap) -> Function {
    let mut bars = [None; 6];
    let mut i = 0;
    while i < 6 {
        let wide = config.bar_address(i).is_some_and(|(_, wide)| wide);
        bars[i] = config.probe_bar(i);
        i += if wide { 2 } else { 1 };
    }
    Function {
        id,
        config,
        config_frame,
        vendor: config.vendor(),
        device: config.device(),
        class: config.class(),
        bars,
        vectors: config.msix().map_or(0, |m| m.vectors),
        lines: None,
        starts: 0,
        restarts: Restarts::default(),
        waiting: None,
        log: None,
    }
}

/// The class of a function, from its PCI class code, or for a device no
/// class code describes, from what its specification says it is (a
/// virtio entropy device reports "other").
fn class_of(f: &Function) -> Option<manager::Class> {
    match (f.class.0, f.vendor, f.device) {
        (0x01, ..) => Some(manager::Class::Block),
        (0x02, ..) => Some(manager::Class::Network),
        (0x03, ..) => Some(manager::Class::Display),
        (0x07, ..) => Some(manager::Class::Port),
        (0x09, ..) => Some(manager::Class::Input),
        (_, 0x1AF4, 0x1044) => Some(manager::Class::Entropy),
        // Intel's 6300ESB watchdog (class "other system peripheral").
        (_, 0x8086, 0x25AB) => Some(manager::Class::Watchdog),
        _ => None,
    }
}

impl manager::Server<Handle> for Manager {
    fn list<'a>(&'a mut self, class: manager::Class, from: u32) -> manager::ListReply<'a, Handle> {
        self.listing.clear();
        if scope_of(class) == 0 || !scope::has(self.caller, scope_of(class)) {
            return manager::ListReply { devices: silica_idl_rt::Array::new(&self.listing), next: 0 };
        }
        let functions = &self.functions;
        let of_class = self.running.iter().map(|r| (&functions[r.function], r.name)).filter(|(f, _)| class_of(f) == Some(class));
        // The service manager asked what watchdog there is, and there is
        // none: it knows (`tell_watchdog`).
        if class == manager::Class::Watchdog && of_class.clone().next().is_none() {
            self.watchdog_news = false;
        }
        let listing = &mut self.listing;
        let next = paging::part(
            of_class,
            from,
            |(_, driver)| paging::record(4 + 4 + paging::text(driver.len())),
            |(f, driver)| listing.push(manager::Device { id: f.id, class, driver }),
        );
        manager::ListReply { devices: silica_idl_rt::Array::new(&self.listing), next }
    }

    fn open(&mut self, id: u32, gone: Option<Handle>) -> Result<manager::OpenReply<Handle>, manager::Error> {
        let (functions, caller) = (&self.functions, self.caller);
        let r = self.running.iter_mut().find(|r| functions[r.function].id == id).ok_or(manager::Error::NoSuchDevice)?;
        let class = class_of(&functions[r.function]);
        if !class.is_some_and(|c| scope_of(c) != 0 && scope::has(caller, scope_of(c))) {
            return Err(manager::Error::Refused);
        }
        let slot = free_slot().ok_or(manager::Error::NoRoom)?;
        self.next_client += 1;
        let rights = Rights(Rights::WRITE.0 | Rights::GRANT.0);
        if sys::cap_derive(slots::SPACE, slot, r.service.cap(), rights, self.next_client).is_err() {
            release_slot(slot);
            return Err(manager::Error::NoRoom);
        }
        if let Some(g) = gone {
            // Kept until the driver ends, one for each caller: a caller's
            // later notice (its reconnecting) replaces its earlier one.
            r.gone.retain(|(c, _)| *c != caller);
            r.gone.push((caller, g));
        }
        r.opened = true;
        if class == Some(manager::Class::Watchdog) {
            // The service manager takes the watchdog's driver: it knows
            // (`tell_watchdog`).
            self.watchdog_news = false;
        }
        Ok(manager::OpenReply { driver: Handle::new(Cap(slot)) })
    }

    fn restart(&mut self, id: u32) -> Result<manager::RestartReply, manager::Error> {
        if !scope::has(self.caller, scope::DEVICE_CONTROL) {
            return Err(manager::Error::Refused);
        }
        let at = self.running.iter().position(|r| self.functions[r.function].id == id).ok_or(manager::Error::NoSuchDevice)?;
        let r = self.running.remove(at);
        let (driver, function) = (r.name, r.function);
        println!("devmgr: restarting {driver} for {}, as asked", PciAddress(id));
        if !self.stop(r) {
            println!("ERROR: devmgr: cannot take back the memory of {driver}");
        }
        self.start(function, driver).map_err(|e| {
            println!("ERROR: devmgr: {} is not driven: {e}", PciAddress(id));
            manager::Error::NoSuchDevice
        })?;
        Ok(manager::RestartReply {})
    }

    fn watch(&mut self, class: manager::Class, changed: Handle) -> manager::WatchReply {
        if scope_of(class) != 0 && scope::has(self.caller, scope_of(class)) {
            let caller = self.caller;
            self.watchers.retain(|(c, k, _)| (*c, *k) != (caller, class));
            self.watchers.push((caller, class, changed));
        }
        manager::WatchReply {}
    }

    fn describe<'a>(&'a mut self, id: u32, from: u32) -> Result<manager::DescribeReply<'a>, manager::Error> {
        if !scope::has(self.caller, scope::DEVICE_CONTROL) {
            return Err(manager::Error::Refused);
        }
        let functions = &self.functions;
        let r = self.running.iter().find(|r| functions[r.function].id == id).ok_or(manager::Error::NoSuchDevice)?;
        let name = silica_rt::alloc::format!("{}@{}", r.name, PciAddress(id));
        let mut all = silica_rt::alloc::string::String::new();
        silica_proc::report(&mut all, &name, r.child.space()).map_err(|_| manager::Error::NoSuchDevice)?;
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
}

/// The fault this program's `inject=<driver>:<fault>@<n>` options ask
/// `driver` to commit, as `silica_driver::inject::Fault::plan` makes it (0:
/// none). Test images only: a machine's device manager has no such option.
#[cfg(feature = "harness")]
fn inject_plan(driver: &str) -> u32 {
    for choice in silica_rt::options().split_ascii_whitespace().filter_map(|w| w.strip_prefix("inject=")) {
        let Some((name, rest)) = choice.split_once(':') else { continue };
        if name != driver {
            continue;
        }
        let (fault, n) = match rest.split_once('@') {
            Some((fault, n)) => (fault, n.parse().unwrap_or(1)),
            None => (rest, 1),
        };
        match silica_driver::inject::Fault::named(fault.as_bytes()) {
            Some(f) => return f.plan(n),
            None => println!("devmgr: inject: no fault named {fault}"),
        }
    }
    0
}

/// What a driver says it drives: a line of the boot archive's `drivers`
/// entry, which the image build collects from every driver crate's
/// `[package.metadata.silica] drivers = [...]`:
///
/// ```text
/// pci <vendor>:<device> <program>      # four hexadecimal digits each
/// class <class>.<subclass>.<interface> <program>   # two each: any device of that kind
/// ```
#[derive(Clone, Copy, Debug)]
enum Match {
    Id(u16, u16),
    Class(u8, u8, u8),
}

/// The drivers the boot archive offers, in its order.
fn drivers(archive: &'static [u8]) -> Vec<(Match, &'static str)> {
    driver_lines(archive).into_iter().map(|(m, program, _)| (m, program)).collect()
}

/// The driver programs the archive's driver list says do no DMA (`nodma`,
/// from a driver's declaration `dma = false`): their devices are left
/// without bus mastering, and they start where DMA cannot be confined.
/// Only from lines the list's reader takes, and only for an exact device
/// identity (`pci <vendor>:<device>`): a class matches devices whose
/// registers can do anything (a display class takes in GPUs whose register
/// window mirrors configuration space, where a driver could turn bus
/// mastering on).
fn no_dma_drivers(archive: &'static [u8]) -> Vec<&'static str> {
    driver_lines(archive).into_iter().filter(|(_, _, no_dma)| *no_dma).map(|(_, program, _)| program).collect()
}

/// The lines of the archive's driver list: a match, its program, and
/// whether it says `nodma`. A line it cannot read is said and skipped.
fn driver_lines(archive: &'static [u8]) -> Vec<(Match, &'static str, bool)> {
    let mut table = Vec::new();
    let Some(text) = ramdisk::find(archive, "drivers").and_then(|b| core::str::from_utf8(b).ok()) else { return table };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match driver_line(line) {
            Some(entry) => table.push(entry),
            None => println!("devmgr: the archive's driver list has a line it cannot read: {line}"),
        }
    }
    table
}

/// One line of the driver list: `pci <vendor>:<device>` or `class
/// <class>.<subclass>.<interface>`, the program, then its configuration
/// writes (`config=`) and `nodma`, each at most once and nothing else;
/// `nodma` only with an exact device identity.
fn driver_line(line: &'static str) -> Option<(Match, &'static str, bool)> {
    let hex16 = |s: &str| u16::from_str_radix(s, 16).ok().filter(|_| s.len() == 4);
    let hex8 = |s: &str| u8::from_str_radix(s, 16).ok().filter(|_| s.len() == 2);
    let mut w = line.split_ascii_whitespace();
    let m = match (w.next()?, w.next()?) {
        ("pci", id) => id.split_once(':').and_then(|(v, d)| Some(Match::Id(hex16(v)?, hex16(d)?)))?,
        ("class", c) => {
            let mut p = c.split('.');
            Match::Class(hex8(p.next()?)?, hex8(p.next()?)?, hex8(p.next()?)?)
        }
        _ => return None,
    };
    let program = w.next()?;
    let rest: Vec<&str> = w.collect();
    let configs = rest.iter().filter(|x| x.starts_with("config=")).count();
    let no_dma = rest.iter().filter(|x| **x == "nodma").count();
    if configs + no_dma != rest.len() || configs > 1 || no_dma > 1 || (no_dma == 1 && !matches!(m, Match::Id(..))) {
        return None;
    }
    Some((m, program, no_dma == 1))
}

/// A write to a device's configuration space that its driver's declaration
/// asks for (`config = ["<offset>:<bytes>:<value>", ...]`, hexadecimal):
/// a device that is set up through registers of its own configuration
/// space, which drivers may only read (the watchdog's enable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConfigWrite {
    offset: u16,
    bytes: u8,
    value: u32,
}

/// The writes the archive's driver list declares, by driver program (the
/// list's `config=<offset>:<bytes>:<value>,...` word).
fn config_writes(archive: &'static [u8]) -> Vec<(&'static str, Vec<ConfigWrite>)> {
    let mut all = Vec::new();
    let Some(text) = ramdisk::find(archive, "drivers").and_then(|b| core::str::from_utf8(b).ok()) else { return all };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut w = line.split_ascii_whitespace().skip(2);
        let Some(program) = w.next() else { continue };
        let Some(spec) = w.find_map(|c| c.strip_prefix("config=")) else { continue };
        let writes: Option<Vec<ConfigWrite>> = spec
            .split(',')
            .map(|one| {
                let mut p = one.split(':');
                let offset = u16::from_str_radix(p.next()?, 16).ok()?;
                let bytes = u8::from_str_radix(p.next()?, 16).ok()?;
                let value = u32::from_str_radix(p.next()?, 16).ok()?;
                p.next().is_none().then_some(ConfigWrite { offset, bytes, value })
            })
            .collect();
        match writes {
            Some(writes) => all.push((program, writes)),
            None => println!("devmgr: the archive's driver list declares writes it cannot read: {line}"),
        }
    }
    all
}

/// Whether `w` may be made to a device whose capabilities are `caps`
/// (offset and identifier): only the device's own registers, after the
/// standard header and outside every capability structure, at a width the
/// bus has and aligned to it. A declaration can never move a BAR, turn on
/// bus mastering or change a message interrupt: those stay the device
/// manager's.
fn write_allowed(w: ConfigWrite, caps: &[(u8, usize)]) -> bool {
    let (at, n) = (w.offset as usize, w.bytes as usize);
    let length = |id: u8| match id {
        0x01 => 8,  // power management
        0x05 => 24, // MSI
        0x10 => 60, // PCI Express
        0x11 => 12, // MSI-X
        _ => 16,
    };
    matches!(n, 1 | 2 | 4)
        && at.is_multiple_of(n)
        && at >= 0x40
        && at + n <= 0x100
        && caps.iter().all(|&(id, cap)| at + n <= cap || at >= cap + length(id))
}

/// The driver for a function: the first in the archive's list that names
/// its identifiers, else the first that names its class.
fn driver_for(f: &Function, table: &[(Match, &'static str)]) -> Option<&'static str> {
    let by_id = table.iter().find(|(m, _)| matches!(m, Match::Id(v, d) if (*v, *d) == (f.vendor, f.device)));
    let by_class = || table.iter().find(|(m, _)| matches!(m, Match::Class(c, s, p) if (*c, *s, *p) == f.class));
    by_id.or_else(by_class).map(|(_, program)| *program)
}

impl Manager {
    /// Read firmware memory (ACPI tables), mapping its pages as they are needed.
    fn read(&mut self, at: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let (page, off) = ((at + done as u64) & !0xFFF, ((at + done as u64) & 0xFFF) as usize);
            let mapped = match self.tables.get(&page) {
                Some(m) => *m,
                None => {
                    let Ok(m) = self.memory.frame(page, 12).and_then(|f| mem::map(f, 12, Rights::READ)) else { return false };
                    self.tables.insert(page, m);
                    m
                }
            };
            let n = (4096 - off).min(buf.len() - done);
            // SAFETY: a page of firmware tables mapped read-only above and
            // never unmapped; nothing writes it.
            #[allow(unsafe_code)]
            let src = unsafe { core::slice::from_raw_parts((mapped + off) as *const u8, n) };
            buf[done..done + n].copy_from_slice(src);
            done += n;
        }
        true
    }

    /// The configuration space of the function `id`, mapped writable, with
    /// its frame; `None` when the page cannot be had.
    fn config_space(&mut self, ecam: u64, id: u32) -> Option<(Config, Cap)> {
        // Mapped once: a frame maps in one place, and a slot is looked at
        // again when a device arrives in it.
        if let Some(c) = self.configs.get(&id) {
            return Some(*c);
        }
        let frame = self.memory.frame(ecam + ((id as u64 & 0xFFFF) << 12), 12).ok()?;
        let at = mem::map(frame, 12, RW).ok()?;
        // SAFETY: the function's configuration space, just mapped, for as
        // long as the device manager runs.
        #[allow(unsafe_code)]
        let space = unsafe { Mmio::new(at, 4096) };
        self.configs.insert(id, (Config::new(space), frame));
        Some((Config::new(space), frame))
    }

    /// Let every hot-plug port interrupt: its MSI-X entry 0 signals `sender`.
    fn arm_ports(&mut self, sender: Cap) {
        for k in 0..self.ports.len() {
            let (id, config) = (self.ports[k].0.id, self.ports[k].0.config);
            let armed = (|| {
                let msix = config.msix().ok_or("it has no MSI-X")?;
                let bar = config.probe_bar(msix.bar as usize).ok_or("its MSI-X table is in no BAR")?;
                let frame = self.memory.frame(bar.base, bar.bits.max(12)).map_err(|_| "its MSI-X table is not in device memory")?;
                let at = mem::map(frame, bar.bits.max(12), RW).map_err(|_| "its MSI-X table cannot be mapped")?;
                // SAFETY: the port's own BAR, just mapped, for as long as the
                // device manager runs; nothing else uses it (ports have no driver).
                #[allow(unsafe_code)]
                let table = unsafe { Mmio::new(at, 1 << bar.bits.max(12)) };
                let entry = table.part(msix.offset as usize, 16).ok_or("its MSI-X table lies outside its BAR")?;
                if self.next_line as u64 >= sys::IRQ_LINES {
                    return Err("no interrupt lines are left");
                }
                let line = self.next_line;
                let (address, data) = sys::irq_bind_msi(granted(GRANT_IRQS), line, sender, granted(GRANT_DEVICES), id)
                    .map_err(|_| "its interrupt cannot be bound")?;
                self.next_line += 1;
                entry.write32(12, 1);
                entry.write32(0, address as u32);
                entry.write32(4, (address >> 32) as u32);
                entry.write32(8, data as u32);
                entry.write32(12, 0);
                self.ports[k].0.arm();
                Ok(())
            })();
            match armed {
                Ok(()) => println!("devmgr: {} takes devices while the system runs", PciAddress(id)),
                Err(e) => println!("devmgr: {} could take devices while the system runs, but {e}", PciAddress(id)),
            }
        }
    }

    /// A slot's interrupt: devices that arrived get addresses and drivers,
    /// devices taken out lose theirs, a device swapped for another between
    /// two looks is both.
    fn slots_changed(&mut self) {
        for k in 0..self.ports.len() {
            match self.ports[k].0.changed() {
                Some(hotplug::Change::Arrived) => self.arrived(k),
                Some(hotplug::Change::Leaving) => self.left(k, false),
                Some(hotplug::Change::Left) => self.left(k, true),
                Some(hotplug::Change::Replaced) => {
                    println!("devmgr: {}: its device was taken out and one put in since it was last asked", PciAddress(self.ports[k].0.id));
                    self.forget_slot(k);
                    self.arrived(k);
                }
                None => {}
            }
        }
    }

    /// A device arrived in slot `k`: its power on, and then a wait for its
    /// link (at most a second) and the 100 ms PCI Express gives a device
    /// after its link comes up before it must answer configuration requests.
    /// The wait is the main loop's (`slots_due`): the device manager serves
    /// its clients and hears its drivers' faults meanwhile.
    fn arrived(&mut self, k: usize) {
        self.settling.retain(|s| s.0 != k);
        self.ports[k].0.power(true);
        self.arrivals += 1;
        self.settling.push((k, silica_rt::clock().now() + 1_000_000_000, false));
    }

    /// Slots waiting for their link or their 100 ms: go on with those that
    /// are ready; returns when to look again.
    fn slots_due(&mut self) -> Option<u64> {
        let now = silica_rt::clock().now();
        let mut ready = Vec::new();
        let mut next: Option<u64> = None;
        let ports = &self.ports;
        self.settling.retain_mut(|(k, until, linked)| {
            if !*linked {
                if ports[*k].0.link_up() {
                    *linked = true;
                    *until = now + 100_000_000;
                } else if now > *until {
                    println!("devmgr: {}: a device arrived, but its link never came up", PciAddress(ports[*k].0.id));
                    return false;
                } else {
                    // The port's interrupt says when the link comes up (it
                    // turns this loop, which asks here again): nothing looks
                    // meanwhile, and the second PCI Express gives a link is
                    // the wait's only other end. A port that could not be
                    // armed, or reports no link changes, sends none: its
                    // link is looked at every 5 ms within that second.
                    let look = if ports[*k].0.link_interrupt { *until + 1 } else { (now + 5_000_000).min(*until + 1) };
                    next = Some(next.map_or(look, |n| n.min(look)));
                    return true;
                }
            }
            if now >= *until {
                ready.push(*k);
                return false;
            }
            next = Some(next.map_or(*until, |n| n.min(*until)));
            true
        });
        for k in ready {
            self.found(k);
        }
        next
    }

    /// The device in slot `k` answers now: give each of its functions
    /// addresses and a driver.
    fn found(&mut self, k: usize) {
        let arrival = self.arrivals;
        let (bus, ecam, segment) = (self.ports[k].0.secondary, self.ports[k].1, self.ports[k].2);
        for dev in 0..32u32 {
            let mut functions = 1;
            let mut function = 0;
            while function < functions {
                let id = (segment as u32) << 16 | (bus as u32) << 8 | dev << 3 | function;
                function += 1;
                let Some((config, frame)) = self.config_space(ecam, id) else { continue };
                if config.vendor() == pci::NO_DEVICE {
                    continue;
                }
                if function == 1 && config.multifunction() {
                    functions = 8;
                }
                // A function still known with a driver running (a slot
                // whose departure was never seen): the driver ends before
                // its record is the new device's (before, the record was
                // overwritten under the running driver).
                if let Some(index) = self.functions.iter().position(|g| g.id == id) {
                    self.forget_function(index);
                }
                if let Err((bar, bits, memory, prefetchable)) = self.ports[k].0.place(&config) {
                    println!(
                        "devmgr: {}: its BAR {bar} (2^{bits} bytes) does not fit the port's windows (memory {memory:x?}, prefetchable {prefetchable:x?}); left alone",
                        PciAddress(id)
                    );
                    continue;
                }
                // Nothing masters the bus until a driver that does DMA is
                // started for it (`silence_found`).
                silence_found(&config);
                let f = function_of(id, config, frame);
                let index = match self.functions.iter().position(|g| g.id == id) {
                    Some(i) => {
                        self.functions[i] = f;
                        i
                    }
                    None => {
                        self.functions.push(f);
                        self.functions.len() - 1
                    }
                };
                let f = &self.functions[index];
                let driver = driver_for(f, &self.table);
                println!(
                    "devmgr: {} {:04x}:{:04x} class {:02x}.{:02x}.{:02x} arrived: {}",
                    PciAddress(id),
                    f.vendor,
                    f.device,
                    f.class.0,
                    f.class.1,
                    f.class.2,
                    driver.unwrap_or("no driver")
                );
                if let Some(d) = driver
                    && let Err(e) = self.start(index, d)
                {
                    println!("ERROR: devmgr: {} is not driven: {e}", PciAddress(id));
                }
                let lines = self.functions[index].lines;
                println!(
                    "devmgr: {}: arrival {arrival} in the slot, {}, {} lines free, longest turn {} ms",
                    PciAddress(self.ports[k].0.id),
                    match lines {
                        Some((first, n)) => silica_rt::alloc::format!("interrupt lines {first} to {}", first + n - 1),
                        None => silica_rt::alloc::string::String::from("no interrupt lines"),
                    },
                    self.lines_free(),
                    self.longest_turn / 1_000_000
                );
            }
        }
    }

    /// How many interrupt lines the device manager can still give.
    fn lines_free(&self) -> u64 {
        (sys::IRQ_LINES - self.next_line as u64) + self.free_lines.iter().map(|(_, n)| *n as u64).sum::<u64>()
    }

    /// Function `index` is gone (or about to be found again): its driver
    /// ends, and what it was given comes back: its interrupt lines (for the
    /// next device) and its registers' frames (a device laid out otherwise
    /// may come next).
    fn forget_function(&mut self, index: usize) {
        while let Some(at) = self.running.iter().position(|r| r.function == index) {
            let r = self.running.remove(at);
            let (driver, id) = (r.name, self.functions[index].id);
            if !self.stop(r) {
                println!("ERROR: devmgr: cannot take back the memory of {driver}");
            }
            println!("devmgr: {} was taken out; {driver} ended", PciAddress(id));
        }
        let f = &mut self.functions[index];
        // Nothing is started again for a device that is gone.
        f.waiting = None;
        if let Some(lines) = f.lines.take() {
            self.free_lines.push(lines);
        }
        let bars = f.bars;
        for bar in bars.iter().flatten() {
            // SAFETY: its driver has ended (above), and the device manager
            // maps no device's registers but the ports' own.
            #[allow(unsafe_code)]
            unsafe {
                self.memory.release(bar.base, bar.bits)
            };
        }
        self.functions[index].bars = [None; 6];
    }

    /// Every function behind slot `k` is gone.
    fn forget_slot(&mut self, k: usize) {
        self.settling.retain(|s| s.0 != k);
        let (first, last) = (self.ports[k].0.secondary, self.ports[k].0.subordinate);
        let segment = self.ports[k].2;
        for index in 0..self.functions.len() {
            if PciAddress(self.functions[index].id).on_buses(segment, first..=last) {
                self.forget_function(index);
            }
        }
        self.ports[k].0.empty();
    }

    /// The device in slot `k` is leaving (someone pressed its button: it is
    /// still there, and is let go of and its power switched off) or `gone`.
    fn left(&mut self, k: usize, gone: bool) {
        self.forget_slot(k);
        if gone {
            self.departures += 1;
            println!(
                "devmgr: {}: departure {} from the slot, {} lines free, longest turn {} ms",
                PciAddress(self.ports[k].0.id),
                self.departures,
                self.lines_free(),
                self.longest_turn / 1_000_000
            );
        }
        self.ports[k].0.power(false);
    }

    /// Start a driver for function `index` again after a failure; one that
    /// cannot be started is tried again later, as if it had failed again.
    fn start_again(&mut self, index: usize, driver: &'static str) {
        let device = PciAddress(self.functions[index].id);
        match self.start(index, driver) {
            Ok(()) => println!("devmgr: {driver} for {device} started again"),
            Err(e) => {
                let now = silica_rt::clock().now();
                let due = self.functions[index].restarts.failed(now);
                self.functions[index].waiting = Some(driver);
                println!("ERROR: devmgr: {device} is not driven: {e}; tried again in {} ms", (due - now) / 1_000_000);
            }
        }
    }

    /// Start the drivers whose restart is due; returns when the next one is.
    fn restart_due(&mut self) -> Option<u64> {
        let now = silica_rt::clock().now();
        for index in 0..self.functions.len() {
            let f = &self.functions[index];
            if let Some(driver) = f.waiting
                && f.restarts.due <= now
            {
                self.functions[index].waiting = None;
                self.start_again(index, driver);
            }
        }
        self.functions.iter().filter(|f| f.waiting.is_some()).map(|f| f.restarts.due).min()
    }

    /// Find every function on `bus` and behind its bridges.
    fn scan(&mut self, ecam: u64, segment: u16, bus: u8, last_bus: u8, depth: u8) {
        for dev in 0..32u32 {
            let mut functions = 1;
            let mut function = 0;
            while function < functions {
                let id = (segment as u32) << 16 | (bus as u32) << 8 | dev << 3 | function;
                function += 1;
                let Some((config, config_frame)) = self.config_space(ecam, id) else { continue };
                if config.vendor() == pci::NO_DEVICE {
                    continue;
                }
                if function == 1 && config.multifunction() {
                    functions = 8;
                }
                if config.header() == 1 {
                    // A bridge: the firmware numbered the bus behind it.
                    let behind = config.secondary_bus();
                    let r = config.registers();
                    self.bridges.push((id, r.read8(0x19), r.read8(0x1A)));
                    if behind > bus && behind <= last_bus && depth < 16 {
                        self.scan(ecam, segment, behind, last_bus, depth + 1);
                    }
                    if let Some(port) = hotplug::Port::of(id, config) {
                        self.ports.push((port, ecam, segment, last_bus));
                    }
                }
                silence_found(&config);
                self.functions.push(function_of(id, config, config_frame));
            }
        }
    }

    /// Find the machine's PCI functions.
    fn enumerate(&mut self) -> Result<(), &'static str> {
        let rsdp = self.info.rsdp;
        let mut read = |a: u64, b: &mut [u8]| self.read(a, b);
        let (mcfg, len) = acpi::find_table(&mut read, rsdp, b"MCFG").ok_or("the firmware has no MCFG table: no PCI configuration space")?;
        // After the header and 8 reserved bytes: 16 bytes per segment.
        for i in 0..(len as u64).saturating_sub(44) / 16 {
            let mut e = [0u8; 16];
            if !self.read(mcfg + 44 + i * 16, &mut e) {
                return Err("the MCFG table cannot be read");
            }
            let base = u64::from_le_bytes([e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]]);
            let (segment, first, last) = (u16::from_le_bytes([e[8], e[9]]), e[10], e[11]);
            // The table gives the address of bus 0 even when the segment starts later.
            self.scan(base, segment, first, last, 0);
        }
        // A port is trusted with the buses behind it only when they are its
        // own (`hotplug::buses_valid`): a device found on another's would
        // be given addresses out of this port's windows.
        let bridges = core::mem::take(&mut self.bridges);
        self.ports.retain(|(p, _, segment, last)| {
            let bus = (p.id >> 8) as u8;
            let others: Vec<(u8, u8)> =
                bridges.iter().filter(|(b, _, _)| *b >> 16 == *segment as u32 && *b != p.id).map(|(_, sec, sub)| (*sec, *sub)).collect();
            let ok = hotplug::buses_valid(bus, p.secondary, p.subordinate, *last, &others);
            if !ok {
                println!(
                    "devmgr: {} says the buses behind it are {} to {}, which are not its own; it takes no devices",
                    PciAddress(p.id),
                    p.secondary,
                    p.subordinate
                );
            }
            ok
        });
        self.bridges = bridges;
        Ok(())
    }

    /// Start the driver `driver` for function number `index`. Whatever
    /// keeps it from starting, its device is left silenced ([`silence`]):
    /// no bus mastering, no message interrupts.
    fn start(&mut self, index: usize, driver: &'static str) -> Result<(), &'static str> {
        let config = self.functions[index].config;
        let r = self.start_driver(index, driver);
        if r.is_err() {
            silence(&config);
        }
        r
    }

    fn start_driver(&mut self, index: usize, driver: &'static str) -> Result<(), &'static str> {
        // Whether the kernel confines this device's DMA, asked of the
        // kernel for this device: attaching it to no address space succeeds
        // only for a device an IOMMU unit the kernel drives translates (on a
        // machine without one, on a segment no driven unit covers, or outside
        // every driven unit's scopes, it is `Unsupported`). A driver that
        // does no DMA (`nodma` in the driver list, exact device identities
        // only) needs no confinement: its device is left without bus
        // mastering, which drivers cannot turn on (configuration space is
        // the device manager's to write).
        let dma = !self.no_dma.contains(&driver);
        let attached = dma.then(|| sys::device_attach(granted(GRANT_DEVICES), self.functions[index].id, Cap::NONE));
        // A machine's image starts no driver it cannot confine: one that is
        // not is trusted with all of memory, and a promise of confinement
        // that is not kept is refused by name, not logged and broken
        // (spec/ARCHITECTURE.md, invariant 7; the 2026-11-26 review, N5). A
        // test image runs it unconfined and says so: the same image on a
        // machine without an IOMMU (`unconfined`).
        #[cfg(not(feature = "harness"))]
        match attached {
            Some(Err(sys::Error::Unsupported)) => {
                return Err("its DMA cannot be confined on this machine, and only a test image trusts a driver with all of memory");
            }
            Some(Err(e)) => {
                println!("devmgr: the kernel did not say whether {} can be confined: {e:?}", PciAddress(self.functions[index].id));
                return Err("the kernel did not say whether its DMA can be confined");
            }
            _ => {}
        }
        #[cfg(feature = "harness")]
        let _ = attached;
        let f = &self.functions[index];
        let image = ramdisk::find(self.archive, driver).ok_or("its driver is not in the boot archive")?;
        let (id, config) = (f.id, f.config);
        // Its interrupt lines: as many as it can raise, up to a limit; the
        // same ones every time a driver is started for it.
        let (first_line, lines, reused) = match f.lines {
            Some((first, n)) => (first, n, None),
            None => {
                let lines = (f.vectors as u32).min(LINES_PER_DEVICE);
                // Lines a device that left gave back come first.
                match self.free_lines.iter().position(|&(_, n)| n >= lines) {
                    Some(k) => (self.free_lines[k].0, lines, Some(k)),
                    None if self.next_line as u64 + lines as u64 > sys::IRQ_LINES => {
                        return Err("the machine has no interrupt lines left for it");
                    }
                    None => (self.next_line, lines, None),
                }
            }
        };
        // Its registers: one frame per memory BAR.
        let mut grants = [Grant::none(); silica_driver::grant::COUNT];
        let mut frames = [None; 6];
        for (i, bar) in f.bars.iter().enumerate() {
            let Some(bar) = bar else { continue };
            // Registers smaller than a page are handed out as their page
            // when nothing else in the machine is there (another device's
            // registers would be reachable through it): the driver finds
            // where in the page they start from the BAR's address.
            let (base, bits) = if bar.bits < 12 {
                let page = bar.base & !0xFFF;
                let shares = self.functions.iter().flat_map(|g| g.bars.iter().flatten()).any(|b| {
                    (b.base, b.bits) != (bar.base, bar.bits) && b.base < page + 0x1000 && b.base.saturating_add(1 << b.bits) > page
                });
                if shares {
                    return Err("its registers share a page with another device's, which cannot be handed out on their own");
                }
                (page, 12)
            } else {
                (bar.base, bar.bits)
            };
            let frame = self.memory.frame(base, bits).map_err(|_| "its registers are not in the machine's device memory")?;
            grants[silica_driver::grant::BAR0 as usize + i] = Grant::lend(frame, RW);
            if let Some(slot) = frames.get_mut(i) {
                *slot = Some((frame, bar.bits));
            }
        }
        let f = &self.functions[index];
        let service = Object::new(ObjectType::Endpoint, 0).map_err(|_| "no memory for its service endpoint")?;
        // To receive on, and to make capabilities to itself from (a block
        // driver narrows a client's to a partition).
        grants[silica_driver::grant::SERVICE as usize] =
            Grant::lend(service.cap(), Rights(Rights::READ.0 | Rights::WRITE.0 | Rights::GRANT.0));
        grants[silica_driver::grant::IDENTITY as usize] =
            Grant::badged(granted(GRANT_DEVICES), Rights::ALL, id as u64 | (id as u64 + 1) << 32);
        // Its interrupt lines (none for a device that raises none).
        if lines != 0 {
            grants[silica_driver::grant::INTERRUPTS as usize] =
                Grant::badged(granted(GRANT_IRQS), Rights::ALL, first_line as u64 | (first_line as u64 + lines as u64) << 32);
        }
        grants[silica_driver::grant::CONFIG as usize] = Grant::lend(f.config_frame, Rights::READ);
        // A display: the framebuffer the firmware set up, if it is this
        // device's (its mode, and the BAR it starts at the first byte of).
        let mut display = [0u64; 3];
        let fb = self.info.framebuffer;
        if class_of(f) == Some(manager::Class::Display) && fb[0] != 0 {
            let bar = f.bars.iter().position(|b| b.is_some_and(|b| b.base == fb[0]));
            match bar {
                Some(bar) => display = [fb[1] | fb[2] << 32, fb[3] | fb[4] << 32, bar as u64],
                None => return Err("the firmware's framebuffer does not start a BAR of this display"),
            }
        }
        // What the driver may not change itself: the device answers memory
        // accesses, may do DMA and send message interrupts, and raises
        // those through MSI-X, never the legacy wire.
        let registers = config.registers();
        // What the driver's declaration asks to have set in the device's
        // own configuration registers, which the driver may only read.
        if let Some((_, writes)) = self.writes.iter().find(|(p, _)| *p == driver) {
            let caps: Vec<(u8, usize)> = config.capabilities().collect();
            if !writes.iter().all(|w| write_allowed(*w, &caps)) {
                return Err("its declaration asks to write configuration registers that are not its device's own");
            }
            for w in writes {
                match w.bytes {
                    1 => registers.write8(w.offset as usize, w.value as u8),
                    2 => registers.write16(w.offset as usize, w.value as u16),
                    _ => registers.write32(w.offset as usize, w.value),
                }
            }
        }
        // Bus mastering only for a driver that does DMA (`nodma`: off).
        let master = if dma { pci::COMMAND_MASTER } else { 0 };
        registers.write16(4, (registers.read16(4) & !pci::COMMAND_MASTER) | pci::COMMAND_MEMORY | master | pci::COMMAND_NO_INTX);
        // A device that keeps bus mastering after it was told no is not
        // given a driver trusted to do no DMA.
        if !dma && registers.read16(4) & pci::COMMAND_MASTER != 0 {
            return Err("its device kept bus mastering on, and its driver is trusted only because it does no DMA");
        }
        if let Some(msix) = config.msix() {
            // Every entry masked and emptied before any can fire: the table
            // still holds the last driver's messages, whose lines may since
            // belong to another device. Enabled under the function mask,
            // emptied, then the mask lifted; the new driver unmasks each
            // entry only after writing it (`Interrupt::bind_to`).
            let control = registers.read16(msix.cap + 2);
            registers.write16(msix.cap + 2, control | 1 << 15 | 1 << 14);
            match frames.get(msix.bar as usize).copied().flatten() {
                Some((frame, bits)) => mask_msix_table(frame, bits, msix.offset as usize, msix.vectors as usize)?,
                None => return Err("its MSI-X table is in no memory BAR"),
            }
            registers.write16(msix.cap + 2, (registers.read16(msix.cap + 2) | 1 << 15) & !(1 << 14));
        }
        self.next_id += 1;
        // A test image's fault to commit on purpose, in the driver's first
        // run only; a machine's image has no such thing to pass.
        #[cfg(feature = "harness")]
        let inject = if f.starts == 0 { inject_plan(driver) } else { 0 };
        #[cfg(not(feature = "harness"))]
        let inject = 0u32;
        let starts = f.starts;
        let log = self.log_of(index, driver);
        let events = OwnedObject::new(ObjectType::Notification, 0).map_err(|_| {
            silence(&config);
            "no memory for its driver's notification"
        })?;
        let program = Program {
            grants: &grants,
            args: [
                id as u64,
                first_line as u64,
                lines as u64,
                self.info.dma_top,
                starts as u64 | (inject as u64) << 32,
                display[0],
                display[1],
                display[2],
            ],
            aspace_bits: 18,
            events: Some(events.cap()),
            log,
            ..Program::new(image, self.next_id)
        };
        let child = spawn(&self.parent, &program).map_err(|e| {
            // Nothing drives it: it does no DMA and raises nothing.
            silence(&config);
            let command = config.registers().read16(4);
            println!(
                "devmgr: cannot start {driver}: {e:?}; {} left with bus mastering {} (command {command:#06x})",
                PciAddress(id),
                if command & pci::COMMAND_MASTER != 0 { "on" } else { "off" }
            );
            "its driver could not be started"
        })?;
        if self.functions[index].lines.is_none() {
            match reused {
                // What is left of a range given back stays free.
                Some(k) => {
                    let (first, n) = self.free_lines[k];
                    if n == lines {
                        self.free_lines.swap_remove(k);
                    } else {
                        self.free_lines[k] = (first + lines, n - lines);
                    }
                }
                None => self.next_line += lines,
            }
            self.functions[index].lines = Some((first_line, lines));
        }
        let f = &mut self.functions[index];
        f.starts += 1;
        f.restarts.started(silica_rt::clock().now());
        f.waiting = None;
        self.running.push(Running {
            name: driver,
            id: self.next_id,
            function: index,
            child,
            service,
            events,
            gone: Vec::new(),
            opened: false,
        });
        self.changed(index);
        Ok(())
    }
}

impl Manager {
    /// Function `index` gained or lost its driver: signal whoever watches
    /// its class. A watcher whose notification can no longer be signalled
    /// (its holder ended) is forgotten.
    fn changed(&mut self, index: usize) {
        let Some(class) = class_of(&self.functions[index]) else { return };
        self.watchers.retain(|(_, c, n)| *c != class || sys::signal(n.cap()).is_ok());
        self.watchdog_news |= class == manager::Class::Watchdog;
    }

    /// Tell the service manager that the watchdog's driver changed, by the
    /// capability it gave this program at its start (`GRANT_WATCHDOG`): the
    /// service manager alone pets a watchdog, and takes its driver when it
    /// hears. Called as the loop turns to listen, so the calls that follow
    /// (`list`, `open`) are answered at once; and again after every turn
    /// this program spent on something else, until the service manager has
    /// been seen to act (it opened the watchdog's driver, or asked and
    /// there is none), so one that gave up on a call while this program was
    /// busy hears again when it no longer is. The kernel keeps the signal
    /// until the service manager listens: nothing is asked for beforehand.
    fn tell_watchdog(&mut self) {
        if !self.watchdog_news || self.watchdog_told {
            return;
        }
        self.watchdog_told = true;
        if sys::signal(granted(GRANT_WATCHDOG)).is_err() {
            // Started by something that pets no watchdog: nobody to tell.
            self.watchdog_news = false;
        }
    }

    /// The log of the drivers of function `index` (`driver` names it with
    /// the function's address): made with the service manager the first
    /// time, the same ring after. `None` when the system keeps no log or
    /// gives no more; the driver then writes to the console itself.
    fn log_of(&mut self, index: usize, driver: &str) -> Option<(Cap, Cap)> {
        if self.functions[index].log.is_none() {
            let ring = Object::new(ObjectType::Frame, silica_rt::log::BITS).ok()?;
            let slot = free_slot()?;
            if sys::cap_derive(slots::SPACE, slot, ring.cap(), RW, 0).is_err() {
                release_slot(slot);
                return None;
            }
            let name = silica_rt::alloc::format!("{driver}@{}", PciAddress(self.functions[index].id));
            let mut system = silica_protocols::system::manager::Client::<Channel, Handle>::from(Channel::new(granted(GRANT_SYSTEM)));
            let wake = system.add_log(&name, Handle::new(Cap(slot))).ok()?.wake;
            self.functions[index].log = Some((ring, wake));
        }
        self.functions[index].log.as_ref().map(|(ring, wake)| (ring.cap(), wake.cap()))
    }

    /// The driver `r` is no longer to run: silence its device and take
    /// back everything the driver was made of. The kernel cuts the device
    /// off from memory as the driver's device address space goes.
    fn stop(&mut self, r: Running<'static>) -> bool {
        let config = self.functions[r.function].config;
        silence(&config);
        let ok = r.child.destroy().is_ok();
        // Its clients hear of it now, not on their next call.
        for (_, g) in r.gone {
            let _ = sys::signal(g.cap());
        }
        self.changed(r.function);
        // SAFETY: the endpoint was the ended driver's alone.
        #[allow(unsafe_code)]
        unsafe {
            r.service.destroy()
        };
        ok
    }

    /// End every driver, block devices' in order: each is asked
    /// ([`silica_rt::END`] on its events notification) and has until
    /// [`END_NS`] to make its device's cache durable, shut the device down
    /// and exit; one that has not is ended where it stands, as is every
    /// other driver (nothing they hold outlives them). Before, every driver
    /// was destroyed where it stood: a power cut for the disks' caches.
    /// Exits arrive on the endpoint clients call, and a client's call taken
    /// meanwhile is answered as at any other time. Before, it was left
    /// unanswered, and the next receive ended it as if this program had
    /// gone: a driver's end tells the class's watchers (`changed`), whose
    /// next call came in the wait for the others, and the service it was
    /// (netd, the service manager listing watchdogs) heard `PeerGone`
    /// from a device manager still running, and netd ended in error.
    /// Since the service manager answers `shutdown` before it stops anything
    /// and asks this program to end only after stopping every service that
    /// needs it (they started after it: providers start first), no client is
    /// left to call during this wait on a shutdown; the answering stays for
    /// any other way it comes to be asked to end.
    fn end_drivers(&mut self, listener: &mut Listener) {
        let mut asked = Vec::new();
        for r in &self.running {
            if class_of(&self.functions[r.function]) != Some(manager::Class::Block) {
                continue;
            }
            match signal_bits(r.events.cap(), silica_rt::END) {
                Ok(()) => asked.push(r.id),
                Err(e) => println!("devmgr: cannot ask {} to end: {e:?}", r.name),
            }
        }
        println!("devmgr: {} disk drivers asked to end, {} drivers in all", asked.len(), self.running.len());
        let deadline = silica_rt::clock().now() + END_NS;
        // The deadline is looked at on every turn: the kernel gives a message
        // already waiting even after it, and a driver that keeps faulting
        // (each fault answered below) would otherwise hold this wait, and
        // the drivers not yet ended, until the service manager gave up on
        // this program (`rogue_end`).
        while !asked.is_empty() && silica_rt::clock().now() < deadline {
            let Ok(msg) = listener.recv(Wait::Until(deadline)) else { break };
            if msg.signals().is_none() && msg.badge >= CLIENTS && msg.badge & FAULT_BADGE == 0 {
                self.caller = msg.badge;
                listener.answer(&msg, |request, caps, reply, reply_caps| manager::dispatch(self, request, caps, reply, reply_caps));
                continue;
            }
            // A driver touching memory a client lent it and took back (the
            // service manager stops the clients before it ends this
            // program) is answered as at any other time: before, it was
            // taken for the driver's end, and the driver was ended before
            // its flush (a hosted runner: "nvme ... did not end in order").
            if msg.badge & FAULT_BADGE != 0
                && let Some(at) = self.running.iter().position(|r| r.id == msg.badge & !FAULT_BADGE)
                && self.running[at].child.answer_peer_fault(&msg)
            {
                continue;
            }
            let Some(k) = asked.iter().position(|id| *id == msg.badge & !FAULT_BADGE) else { continue };
            asked.swap_remove(k);
            let Some(at) = self.running.iter().position(|r| r.id == msg.badge & !FAULT_BADGE) else { continue };
            let r = self.running.remove(at);
            let device = PciAddress(self.functions[r.function].id);
            if msg.badge & FAULT_BADGE == 0 && msg.info.label() == EXIT_LABEL && msg.words[0] == 0 {
                println!("devmgr: {} for {device} ended in order", r.name);
            } else {
                println!("devmgr: {} for {device} did not end in order (status {})", r.name, msg.words[0] as i64);
            }
            self.stop(r);
        }
        while let Some(r) = self.running.pop() {
            if asked.contains(&r.id) {
                println!("devmgr: {} did not end within {} ms; ended where it stood", r.name, END_NS / 1_000_000);
            }
            self.stop(r);
        }
    }
}

/// How long a driver asked to end has to do so (`Manager::end_drivers`):
/// a flush and an NVMe controller's shutdown, each bounded by the driver.
const END_NS: u64 = 8_000_000_000;

/// Signal `bits` on the notification `cap` (an unbadged capability signals
/// bit 0 alone).
fn signal_bits(cap: Cap, bits: u64) -> Result<(), sys::Error> {
    let slot = free_slot().ok_or(sys::Error::NoMemory)?;
    let made = sys::cap_derive(slots::SPACE, slot, cap, Rights::WRITE, bits).and_then(|()| sys::signal(Cap(slot)));
    // SAFETY: the capability was made here, for this signal alone.
    #[allow(unsafe_code)]
    let _ = unsafe { sys::cap_delete(Cap(slot)) };
    release_slot(slot);
    made
}

/// Map what this program is lent of the boot archive: an archive of its
/// own (the service manager's `drivers_archive`), holding the drivers list
/// and the programs it names and nothing else of the boot archive, which
/// holds files provisioned for other services. Checked against every rule
/// of its format before anything in it is read.
fn map_archive(frames: u64) -> Result<&'static [u8], &'static str> {
    // None (the boot archive had no drivers list, or there was no memory
    // for the copy, which the service manager says): no drivers, and the
    // rest of what this program does (the power button, the firmware's
    // tables, the clients' calls) as on any machine.
    if frames == 0 {
        println!("devmgr: lent no drivers' archive: no driver is started");
        return Ok(&[]);
    }
    if frames != 1 {
        return Err("not lent the drivers' archive");
    }
    let frame = granted(GRANT_FIRST_RAMDISK);
    let bits = match sys::inspect_slot(slots::SPACE, frame.0) {
        Ok(Some(s)) if s.ty == ObjectType::Frame => s.bits,
        _ => return Err("not lent the drivers' archive"),
    };
    let at = mem::map(frame, bits, Rights::READ).map_err(|_| "cannot map the drivers' archive")?;
    // SAFETY: the frame was just mapped read-only for good; the service
    // manager wrote it before lending it and writes it no more.
    #[allow(unsafe_code)]
    let whole = unsafe { core::slice::from_raw_parts(at as *const u8, 1usize << bits) };
    let len = whole.get(16..24).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))) as usize;
    let archive = whole.get(..len).ok_or("the drivers' archive is longer than its frame")?;
    ramdisk::check(archive, ramdisk::crc32c_update).map_err(|e| {
        println!("devmgr: the drivers' archive is refused: {e}");
        "the drivers' archive is not one"
    })?;
    Ok(archive)
}

fn main(process: &ProcessInfo) -> i64 {
    match run(process) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: devmgr: {e}");
            1
        }
    }
}

fn run(process: &ProcessInfo) -> Result<core::convert::Infallible, &'static str> {
    let bits = match sys::inspect_slot(slots::SPACE, granted(GRANT_INFO).0) {
        Ok(Some(s)) if s.ty == ObjectType::Frame => s.bits,
        _ => return Err("not started with the machine's description"),
    };
    let at = mem::map(granted(GRANT_INFO), bits, Rights::READ).map_err(|_| "cannot map the machine's description")?;
    // SAFETY: the kernel's start-up record, mapped read-only for good; the
    // frame is larger than a RootInfo and page-aligned.
    #[allow(unsafe_code)]
    let info: &'static RootInfo = unsafe { &*(at as *const RootInfo) };
    if info.magic != ROOT_MAGIC || (1usize << bits) < core::mem::size_of::<RootInfo>() {
        return Err("the machine's description is not one");
    }
    let (ramdisk_frames, untypeds) = (process.args[0], process.args[1]);
    let archive = map_archive(ramdisk_frames)?;
    // The device memory, in the order the kernel listed it.
    let mut memory = DeviceMemory::new();
    let device = info.untyped[..info.untyped_count as usize].iter().filter(|d| d.kind == KIND_DEVICE || d.kind == KIND_FIRMWARE);
    for (i, d) in device.enumerate() {
        if (i as u64) < untypeds {
            memory.add(d.base, d.bits, granted(GRANT_FIRST_RAMDISK + ramdisk_frames + i as u64));
        }
    }
    #[cfg(feature = "harness")]
    {
        // SAFETY: the RootInfo frame, mapped read-only above for good.
        #[allow(unsafe_code)]
        let info_bytes = unsafe { core::slice::from_raw_parts(at as *const u8, 1usize << bits) };
        find_in_lent(archive, info_bytes, &mut memory, info);
    }
    // Drivers report their exit, and the kernel their faults, to the
    // endpoint clients call, each badged with the driver's identifier.
    let events = granted(GRANT_ENDPOINT);
    match sys::inspect_slot(slots::SPACE, events.0) {
        Ok(Some(s)) if s.ty == ObjectType::Endpoint && s.rights.has(Rights(Rights::READ.0 | Rights::WRITE.0)) => {}
        _ => return Err("not given an endpoint to receive on and hand out"),
    }
    let scratch = mem::reserve(1 << 20, 1 << 21).ok_or("no address space to start drivers with")?;
    let parent = Parent { fault: events, ..Parent::of(process, events, scratch) };
    let mut m = Manager {
        info,
        memory,
        tables: BTreeMap::new(),
        archive,
        parent,
        functions: Vec::new(),
        running: Vec::new(),
        next_line: info.msi_first as u32,
        free_lines: Vec::new(),
        next_id: 0,
        listing: Vec::new(),
        described: silica_rt::alloc::string::String::new(),
        next_client: CLIENTS,
        ports: Vec::new(),
        bridges: Vec::new(),
        settling: Vec::new(),
        arrivals: 0,
        departures: 0,
        longest_turn: 0,
        table: drivers(archive),
        writes: config_writes(archive),
        no_dma: no_dma_drivers(archive),
        configs: BTreeMap::new(),
        watchers: Vec::new(),
        watchdog_news: true,
        watchdog_told: false,
        caller: 0,
    };
    m.enumerate()?;
    let table = m.table.clone();
    if table.is_empty() {
        println!("devmgr: the boot archive lists no drivers");
    }
    #[cfg(feature = "harness")]
    if info.dma_top == 0 {
        println!("devmgr: this machine cannot confine DMA: every driver started here is trusted with all of memory");
    }
    #[cfg(not(feature = "harness"))]
    if info.dma_top == 0 {
        println!("devmgr: this machine cannot confine DMA: no driver that does DMA is started (only a test image runs one unconfined)");
    }
    // Say what there is, then start the drivers.
    let mut failed = false;
    let mut wanted = Vec::new();
    for (i, f) in m.functions.iter().enumerate() {
        let driver = driver_for(f, &table);
        println!(
            "devmgr: {} {:04x}:{:04x} class {:02x}.{:02x}.{:02x}, {} interrupts: {}",
            PciAddress(f.id),
            f.vendor,
            f.device,
            f.class.0,
            f.class.1,
            f.class.2,
            f.vectors,
            driver.unwrap_or("no driver")
        );
        wanted.extend(driver.map(|d| (i, d)));
    }
    for (i, driver) in wanted {
        if let Err(e) = m.start(i, driver) {
            println!("ERROR: devmgr: {} is not driven: {e}", PciAddress(m.functions[i].id));
            failed = true;
        }
    }
    if failed {
        println!("ERROR: devmgr: not every device has its driver");
    }
    // What happens to the machine: the power button and the hot-plug slots,
    // each a bit (from 32 up) of its events notification, where the service
    // manager asks it to end (`silica_rt::END`).
    let happened = slots::EVENTS;
    let sender = |bits: u64| -> Result<Cap, &'static str> {
        let slot = free_slot().ok_or("no capability slots left")?;
        sys::cap_derive(slots::SPACE, slot, happened, Rights::WRITE, bits).map_err(|_| "cannot make a notification sender")?;
        Ok(Cap(slot))
    };
    let button = match power::Button::new(&mut m, granted(GRANT_PORTS), granted(GRANT_IRQS), sender(power::BUTTON)?) {
        Ok(b) => {
            // From here a press is heard; one before was cleared with the
            // button's old status (a machine keeps the press that turned it on).
            println!("devmgr: the power button is armed");
            Some(b)
        }
        Err(e) => {
            println!("devmgr: no power button: {e}");
            None
        }
    };
    m.arm_ports(sender(hotplug::HOTPLUG)?);
    // A device that arrived before the slots could tell.
    m.slots_changed();
    // From here on: clients' calls, drivers that end, the button and the slots.
    let mut listener = Listener::new(events);
    // The service manager accepted a shutdown this program asked for: a
    // later press asks nothing (its call would come while the machine goes
    // down, and fail).
    let mut going_down = false;
    // When the device manager last took something to do: how long it then
    // went without listening is its turn (`longest_turn`).
    let mut took = silica_rt::clock().now();
    loop {
        // Drivers whose restart is due, and when the next one is.
        let restart = m.restart_due();
        let slots = m.slots_due();
        let now = silica_rt::clock().now();
        m.longest_turn = m.longest_turn.max(now - took);
        let next = match (restart, slots) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        // About to listen: the service manager hears of a watchdog now.
        m.tell_watchdog();
        let got = listener.recv_listening(happened, next.map_or(Wait::Forever, Wait::Until));
        took = silica_rt::clock().now();
        // Anything but the service manager's answer to that news is this
        // program busy with something else: the news is told again after.
        let answering = matches!(&got, Ok(msg) if msg.signals().is_none()
            && msg.badge >= CLIENTS && msg.badge & FAULT_BADGE == 0 && scope::has(msg.badge, scope::DEVICE_WATCHDOG));
        m.watchdog_told &= answering;
        if matches!(got, Err(sys::Error::Timeout)) {
            continue;
        }
        let Ok(msg) = got else { return Err("its endpoint was taken away") };
        if let Some(bits) = msg.signals() {
            if bits & silica_rt::END != 0 {
                // The service manager is turning the machine off: the disks'
                // caches are made durable before anything is let go of.
                println!("devmgr: asked to end: its drivers end in order");
                m.end_drivers(&mut listener);
                silica_rt::exit(0);
            }
            if bits & hotplug::HOTPLUG != 0 {
                m.slots_changed();
            }
            if bits & power::BUTTON != 0
                && let Some(b) = &button
                && b.pressed()
            {
                if going_down {
                    println!("devmgr: the power button was pressed again; the machine is already going down");
                    continue;
                }
                println!("devmgr: the power button was pressed: shutting down");
                // The service manager answers at once and then turns the
                // machine off, asking this program to end (END, below) like
                // every service that has something to finish: its drivers
                // end in order then, and its clients are answered until it
                // exits.
                let mut system = silica_protocols::system::manager::Client::<Channel, Handle>::from(Channel::new(granted(GRANT_SYSTEM)));
                match system.shutdown(false) {
                    Ok(_) => going_down = true,
                    Err(e) => println!("ERROR: devmgr: the service manager would not shut down: {e:?}"),
                }
            }
            continue;
        }
        // Clients' badges are from CLIENTS up; a fault report's has
        // FAULT_BADGE, above them, which no client is given.
        if msg.badge >= CLIENTS && msg.badge & FAULT_BADGE == 0 {
            m.caller = msg.badge;
            listener.answer(&msg, |request, caps, reply, reply_caps| manager::dispatch(&mut m, request, caps, reply, reply_caps));
            continue;
        }
        // A fault report carries the driver's identifier plus FAULT_BADGE,
        // which no program can send itself.
        let fault = msg.badge & FAULT_BADGE != 0;
        let Some(at) = m.running.iter().position(|r| msg.badge & !FAULT_BADGE == r.id) else { continue };
        let label = msg.info.label();
        if fault && m.running[at].child.answer_peer_fault(&msg) {
            continue;
        }
        let r = m.running.remove(at);
        let (driver, function) = (r.name, r.function);
        let device = PciAddress(m.functions[function].id);
        let mut again = false;
        let ended_well = if label == EXIT_LABEL && !fault {
            let status = msg.words[0] as i64;
            println!("devmgr: {driver} for {device} ended with status {status}");
            status == 0
        } else if label == silica_rt::AGAIN_LABEL && !fault {
            // To reset its device for its next client: a start, not a
            // failure, of a driver a client was given since it started.
            println!("devmgr: {driver} for {device} ended to be started again");
            again = r.opened;
            again
        } else if fault {
            // The kernel's fault message: instruction, address, detail.
            let kind = match label - sys::FAULT_LABEL {
                1 => "touched memory it may not (page fault)",
                2 => "ran an instruction it may not",
                _ => "raised a processor exception",
            };
            println!("devmgr: {driver} for {device} {kind}: address {:#x}, instruction {:#x}", msg.words[1], msg.words[0]);
            false
        } else {
            m.running.insert(at, r);
            continue;
        };
        if !m.stop(r) {
            println!("ERROR: devmgr: cannot take back the memory of {driver}");
        }
        if again {
            // It asked to be started again (to reset its device): a start,
            // not a failure.
            m.start_again(function, driver);
            continue;
        }
        if ended_well {
            continue;
        }
        let now = silica_rt::clock().now();
        let due = m.functions[function].restarts.failed(now);
        if due > now {
            println!(
                "devmgr: {driver} for {device} has failed {} times in a row; started again in {} ms",
                m.functions[function].restarts.streak,
                (due - now) / 1_000_000
            );
            m.functions[function].waiting = Some(driver);
            continue;
        }
        m.start_again(function, driver);
    }
}

/// Mask and empty each of the `vectors` entries of the MSI-X table at
/// `offset` in the BAR whose frame is `frame` (`2^bits` bytes), before a
/// driver is started: an entry left by the last driver names a line that
/// may since be another device's (QEMU's VT-d model aborted re-routing one,
/// and real units fault every message through it).
fn mask_msix_table(frame: Cap, bits: u8, offset: usize, vectors: usize) -> Result<(), &'static str> {
    let at = mem::map(frame, bits, RW).map_err(|_| "its MSI-X table cannot be mapped")?;
    // SAFETY: the device's own BAR, mapped here and unmapped below before
    // its driver (which gets a copy of the frame) is started.
    #[allow(unsafe_code)]
    let table = unsafe { Mmio::new(at, 1 << bits) };
    let result = (|| {
        for v in 0..vectors {
            let entry = table.part(offset + v * 16, 16).ok_or("its MSI-X table lies outside its BAR")?;
            entry.write32(12, 1);
            entry.write32(0, 0);
            entry.write32(4, 0);
            entry.write32(8, 0);
        }
        Ok(())
    })();
    // SAFETY: nothing refers to the mapping after this.
    #[allow(unsafe_code)]
    let _ = unsafe { sys::unmap(frame) };
    result
}

/// The device of `config` may no longer do DMA or send message interrupts:
/// a device without a running driver (stopped, or never started because
/// starting it failed) is silenced, so that without an IOMMU it cannot
/// reach memory at all. Says so if the device does not take it.
/// A function just found: an endpoint is silenced ([`silence`]) until a
/// driver that does DMA is started for it, whatever the firmware left on
/// (the review of 2026-11-27: a device with no driver, or one refused,
/// kept the firmware's bus mastering). A bridge is left alone: its bus
/// mastering carries the requests of every device below it, each of which
/// is silenced itself.
fn silence_found(config: &Config) {
    if config.registers().read8(0x0E) & 0x7F == 0 {
        silence(config);
    }
}

fn silence(config: &Config) {
    let registers = config.registers();
    registers.write16(4, registers.read16(4) & !pci::COMMAND_MASTER);
    if let Some(msix) = config.msix() {
        registers.write16(msix.cap + 2, registers.read16(msix.cap + 2) & !(1 << 15));
    }
    if registers.read16(4) & pci::COMMAND_MASTER != 0 {
        println!("ERROR: devmgr: a device kept bus mastering after it was switched off");
    }
}

/// `find=<hex>` (test images only; a machine's device manager has no such
/// option): whether the bytes `<hex>` spells occur anywhere in what this
/// program is lent to read (the drivers' archive, the kernel's `RootInfo`
/// frame, and the firmware's memory, where its tables are), said on the
/// console. Device registers are not read, reading one being an act, but
/// for ranges a test names with `find_device=<base>+<length>` (hexadecimal):
/// the firmware's flash, which reads as memory. The secrets test gives it
/// the machine's secret, the flash it is kept in, and a part of the boot
/// archive the device manager must not see (`run_secrets`): a program that
/// parses what hostile devices say must hold none of it.
#[cfg(feature = "harness")]
fn find_in_lent(archive: &[u8], info: &[u8], memory: &mut DeviceMemory, root: &RootInfo) {
    let hex = |s: &str| -> Option<Vec<u8>> {
        let b = s.as_bytes();
        (b.len() % 2 == 0 && !b.is_empty())
            .then(|| b.chunks(2).map(|p| u8::from_str_radix(core::str::from_utf8(p).ok()?, 16).ok()).collect())
            .flatten()
    };
    // The memory read a page at a time: the firmware's, and the named ranges.
    let mut ranges: Vec<(u64, u64, &str)> = root.untyped[..root.untyped_count as usize]
        .iter()
        .filter(|d| d.kind == KIND_FIRMWARE)
        .map(|d| (d.base, 1u64 << d.bits, "the firmware's memory"))
        .collect();
    for w in silica_rt::options().split_ascii_whitespace().filter_map(|w| w.strip_prefix("find_device=")) {
        let range = w.split_once('+').and_then(|(b, l)| Some((u64::from_str_radix(b, 16).ok()?, u64::from_str_radix(l, 16).ok()?)));
        let Some((base, len)) = range else {
            println!("devmgr: find: {w} is not <base>+<length> in hexadecimal");
            continue;
        };
        // How much of it this program can read at all: what it is lent of it.
        let mut readable = 0;
        for page in (base & !0xFFF..base.saturating_add(len)).step_by(4096) {
            if memory.frame(page, 12).is_ok() {
                readable += 1;
                // SAFETY: the frame was just made and never mapped.
                #[allow(unsafe_code)]
                unsafe {
                    memory.release(page, 12)
                };
            }
        }
        println!("devmgr: find: of the device memory at {w}, this program can read {readable} pages");
        ranges.push((base & !0xFFF, len, "the named device memory"));
    }
    for word in silica_rt::options().split_ascii_whitespace().filter_map(|w| w.strip_prefix("find=")) {
        let Some(needle) = hex(word) else {
            println!("devmgr: find: {word} is not hexadecimal bytes");
            continue;
        };
        let has = |hay: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        let mut found = if has(archive) {
            Some("the drivers' archive")
        } else if has(info) {
            Some("the kernel's RootInfo")
        } else {
            None
        };
        // A page at a time, the needle's length less a byte carried over
        // from each page to the next. A page this program cannot make a
        // frame of is not lent to it.
        'ranges: for &(base, len, what) in &ranges {
            if found.is_some() {
                break;
            }
            let mut carry: Vec<u8> = Vec::new();
            for page in (base..base.saturating_add(len)).step_by(4096) {
                let Ok(at) = memory.frame(page, 12).and_then(|fr| mem::map(fr, 12, Rights::READ)) else {
                    carry.clear();
                    continue;
                };
                let mut window = core::mem::take(&mut carry);
                // SAFETY: the page was just mapped read-only (firmware
                // memory, or a range the test names that reads as memory),
                // is copied, and is given back at once (its frame revoked,
                // which unmaps it): nothing refers to it after, and nothing
                // else had been made of it before the probe.
                #[allow(unsafe_code)]
                unsafe {
                    window.extend_from_slice(core::slice::from_raw_parts(at as *const u8, 4096));
                    memory.release(page, 12);
                }
                if has(&window) {
                    found = Some(what);
                    break 'ranges;
                }
                let keep = needle.len().saturating_sub(1).min(window.len());
                carry = window[window.len() - keep..].to_vec();
            }
        }
        match found {
            Some(where_) => println!("devmgr: find: {word} is in what this program was lent, in {where_}"),
            None => println!("devmgr: find: {word} is not in what this program was lent"),
        }
    }
}
