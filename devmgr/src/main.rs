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
//! the driver is started again, at most [`MAX_RESTARTS`] times; the driver
//! is told how many times it has been started. A driver may be replaced:
//! `driver=<vendor>:<device>=<program>` on the kernel command line (four
//! hexadecimal digits each) starts `<program>` from the boot archive for
//! that kind of device instead of the driver the device manager would pick.
//! `inject=<driver>:<fault>@<n>` has the first run of `<driver>` commit a
//! device's fault at its `n`th request (`silica_driver::inject`).
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
//! 4 the interrupt lines, 5 the I/O ports (or nothing), then `args[0]`
//! frames of the ramdisk (in
//! `RootInfo` order, read-only), then `args[1]` Untyped capabilities, given
//! outright: the machine's device memory and the firmware's memory (where
//! its ACPI tables are), in `RootInfo` order.
#![no_std]
#![no_main]

mod hotplug;
mod phys;
mod power;

use libsys::root::{KIND_DEVICE, KIND_FIRMWARE, KIND_RAMDISK, ROOT_MAGIC, RootInfo};
use libsys::{self as sys, Cap, ObjectType, Rights, Wait};
use phys::DeviceMemory;
use silica_driver::pci::{self, Config};
use silica_formats::{acpi, ramdisk};
use silica_proc::{Child, FAULT_BADGE, Grant, Parent, Program, spawn};
use silica_rt::alloc::collections::BTreeMap;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle, Listener, free_slot, release_slot};
use silica_rt::mem::{self, Object};
use silica_rt::mmio::Mmio;
use silica_rt::{EXIT_LABEL, ProcessInfo, println, slots};

use silica_protocols::device::manager;

silica_rt::main!(main);

const RW: Rights = Rights(Rights::READ.0 | Rights::WRITE.0);
const GRANT_ENDPOINT: u64 = 0;
const GRANT_SYSTEM: u64 = 1;
const GRANT_INFO: u64 = 2;
const GRANT_DEVICES: u64 = 3;
const GRANT_IRQS: u64 = 4;
const GRANT_PORTS: u64 = 5;
const GRANT_FIRST_RAMDISK: u64 = 6;
/// Badges of the capabilities clients call through start here (and stay
/// below `silica_proc::FAULT_BADGE`); below are the drivers'.
pub const CLIENTS: u64 = 1 << 32;
/// Interrupt lines one device gets at most.
const LINES_PER_DEVICE: u32 = 8;
/// How often a driver that failed is started again before its device is
/// left alone.
const MAX_RESTARTS: u32 = 3;

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
    /// How many times its driver failed (faulted, or ended with a failure);
    /// an owner's restart is not a failure.
    failures: u32,
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
    /// What clients asked to have signalled when this driver ends.
    gone: Vec<Handle>,
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
    /// The next interrupt line to hand out.
    next_line: u32,
    next_id: u64,
    /// What `list` answers with, rebuilt for each call.
    listing: Vec<manager::Device<'static>>,
    /// Badges of driver capabilities handed out, so each client is told apart.
    next_client: u64,
    /// The kernel command line: `inject=<driver>:<fault>@<n>`
    /// (`silica_driver::inject`) is read at each driver's first start.
    cmdline: &'static [u8],
    /// Hot-plug capable ports, with the configuration space base (ECAM)
    /// and segment of the buses behind them.
    ports: Vec<(hotplug::Port, u64, u16)>,
    /// The archive's drivers, by what they drive.
    table: Vec<(Match, &'static str)>,
    /// Every configuration space mapped, by function identity.
    configs: BTreeMap<u32, (Config, Cap)>,
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
        failures: 0,
        log: None,
    }
}

/// The class of a function, from its PCI class code.
fn class_of(f: &Function) -> Option<manager::Class> {
    match f.class.0 {
        0x01 => Some(manager::Class::Block),
        0x02 => Some(manager::Class::Network),
        0x03 => Some(manager::Class::Display),
        0x09 => Some(manager::Class::Input),
        _ => None,
    }
}

impl manager::Server<Handle> for Manager {
    fn list<'a>(&'a mut self, class: manager::Class) -> manager::ListReply<'a, Handle> {
        self.listing.clear();
        for r in &self.running {
            let f = &self.functions[r.function];
            if class_of(f) == Some(class) {
                self.listing.push(manager::Device { id: f.id, class, driver: r.name });
            }
        }
        manager::ListReply { devices: silica_idl_rt::Array::new(&self.listing) }
    }

    fn open(&mut self, id: u32, gone: Option<Handle>) -> Result<manager::OpenReply<Handle>, manager::Error> {
        let functions = &self.functions;
        let r = self.running.iter_mut().find(|r| functions[r.function].id == id).ok_or(manager::Error::NoSuchDevice)?;
        if let Some(g) = gone {
            // Kept until the driver ends; a notice nobody can signal is dropped then.
            r.gone.push(g);
        }
        let slot = free_slot().ok_or(manager::Error::NoSuchDevice)?;
        self.next_client += 1;
        let rights = Rights(Rights::WRITE.0 | Rights::GRANT.0);
        if sys::cap_derive(slots::SPACE, slot, r.service.cap(), rights, self.next_client).is_err() {
            release_slot(slot);
            return Err(manager::Error::NoSuchDevice);
        }
        Ok(manager::OpenReply { driver: Handle::new(Cap(slot)) })
    }

    fn restart(&mut self, id: u32) -> Result<manager::RestartReply, manager::Error> {
        let at = self.running.iter().position(|r| self.functions[r.function].id == id).ok_or(manager::Error::NoSuchDevice)?;
        let r = self.running.remove(at);
        let (driver, function) = (r.name, r.function);
        println!("devmgr: restarting {driver} for {}, as asked", name(id));
        if !self.stop(r) {
            println!("ERROR: devmgr: cannot take back the memory of {driver}");
        }
        self.start(function, driver).map_err(|e| {
            println!("ERROR: devmgr: {} is not driven: {e}", name(id));
            manager::Error::NoSuchDevice
        })?;
        Ok(manager::RestartReply {})
    }
}

fn name(id: u32) -> impl core::fmt::Display {
    struct Bdf(u32);
    impl core::fmt::Display for Bdf {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{:02x}:{:02x}.{}", self.0 >> 8 & 0xFF, self.0 >> 3 & 31, self.0 & 7)
        }
    }
    Bdf(id)
}

/// The value of `key` on a command line of space-separated `key=value` words.
/// The fault `inject=<driver>:<fault>@<n>` asks `driver` to commit, as
/// `silica_driver::inject::Fault::plan` makes it (0: none).
fn inject_plan(cmdline: &[u8], driver: &str) -> u32 {
    for choice in option(cmdline, "inject") {
        let Some(colon) = choice.iter().position(|&b| b == b':') else { continue };
        if &choice[..colon] != driver.as_bytes() {
            continue;
        }
        let rest = &choice[colon + 1..];
        let (fault, n) = match rest.iter().position(|&b| b == b'@') {
            Some(at) => (&rest[..at], core::str::from_utf8(&rest[at + 1..]).ok().and_then(|n| n.parse().ok()).unwrap_or(1)),
            None => (rest, 1),
        };
        match silica_driver::inject::Fault::named(fault) {
            Some(f) => return f.plan(n),
            None => println!("devmgr: inject: no fault named {}", core::str::from_utf8(fault).unwrap_or("?")),
        }
    }
    0
}

fn option<'a>(cmdline: &'a [u8], key: &str) -> impl Iterator<Item = &'a [u8]> {
    cmdline.split(|b| b.is_ascii_whitespace()).filter_map(move |w| w.strip_prefix(key.as_bytes())?.strip_prefix(b"="))
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
    let mut table = Vec::new();
    let Some(text) = ramdisk::find(archive, "drivers").and_then(|b| core::str::from_utf8(b).ok()) else { return table };
    let hex16 = |s: &str| u16::from_str_radix(s, 16).ok().filter(|_| s.len() == 4);
    let hex8 = |s: &str| u8::from_str_radix(s, 16).ok().filter(|_| s.len() == 2);
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut w = line.split_ascii_whitespace();
        let m = match (w.next(), w.next()) {
            (Some("pci"), Some(id)) => id.split_once(':').and_then(|(v, d)| Some(Match::Id(hex16(v)?, hex16(d)?))),
            (Some("class"), Some(c)) => {
                let mut p = c.split('.');
                (|| Some(Match::Class(hex8(p.next()?)?, hex8(p.next()?)?, hex8(p.next()?)?)))()
            }
            _ => None,
        };
        match (m, w.next(), w.next()) {
            (Some(m), Some(program), None) => table.push((m, program)),
            _ => println!("devmgr: the archive's driver list has a line it cannot read: {line}"),
        }
    }
    table
}

/// The driver for a function: the owner's choice on the command line
/// (`driver=<vendor>:<device>=<program>`), else the first in the archive's
/// list that names its identifiers, else the first that names its class.
fn driver_for(f: &Function, cmdline: &'static [u8], table: &[(Match, &'static str)]) -> Option<&'static str> {
    let hex = |b: &[u8]| core::str::from_utf8(b).ok().and_then(|s| u16::from_str_radix(s, 16).ok());
    for choice in option(cmdline, "driver") {
        let mut parts = choice.splitn(2, |b| *b == b'=');
        let (Some(ids), Some(program)) = (parts.next(), parts.next()) else { continue };
        let mut ids = ids.splitn(2, |b| *b == b':');
        if (ids.next().and_then(hex), ids.next().and_then(hex)) == (Some(f.vendor), Some(f.device)) {
            return core::str::from_utf8(program).ok();
        }
    }
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
                Ok(()) => println!("devmgr: {} takes devices while the system runs", name(id)),
                Err(e) => println!("devmgr: {} could take devices while the system runs, but {e}", name(id)),
            }
        }
    }

    /// A slot's interrupt: devices that arrived get addresses and drivers,
    /// devices taken out lose theirs.
    fn slots_changed(&mut self) {
        for k in 0..self.ports.len() {
            match self.ports[k].0.changed() {
                Some(hotplug::Change::Arrived) => self.arrived(k),
                Some(hotplug::Change::Leaving | hotplug::Change::Left) => self.left(k),
                None => {}
            }
        }
    }

    fn arrived(&mut self, k: usize) {
        if !self.ports[k].0.power(true) {
            println!("devmgr: {}: a device arrived, but its link never came up", name(self.ports[k].0.id));
            return;
        }
        // PCI Express gives a device 100 ms after its link comes up
        // before it must answer configuration requests.
        let clock = silica_rt::clock();
        let until = clock.now() + 100_000_000;
        while clock.now() < until {
            sys::yield_now();
        }
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
                if let Err((bar, bits, memory, prefetchable)) = self.ports[k].0.place(&config) {
                    println!(
                        "devmgr: {}: its BAR {bar} (2^{bits} bytes) does not fit the port's windows (memory {memory:x?}, prefetchable {prefetchable:x?}); left alone",
                        name(id)
                    );
                    continue;
                }
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
                let driver = driver_for(f, self.cmdline, &self.table);
                println!(
                    "devmgr: {} {:04x}:{:04x} class {:02x}.{:02x}.{:02x} arrived: {}",
                    name(id),
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
                    println!("ERROR: devmgr: {} is not driven: {e}", name(id));
                }
            }
        }
    }

    fn left(&mut self, k: usize) {
        let (first, last) = (self.ports[k].0.secondary, self.ports[k].0.subordinate);
        while let Some(at) = self.running.iter().position(|r| {
            let bus = (self.functions[r.function].id >> 8 & 0xFF) as u8;
            (first..=last).contains(&bus)
        }) {
            let r = self.running.remove(at);
            let (driver, id) = (r.name, self.functions[r.function].id);
            if !self.stop(r) {
                println!("ERROR: devmgr: cannot take back the memory of {driver}");
            }
            println!("devmgr: {} was taken out; {driver} ended", name(id));
        }
        self.ports[k].0.power(false);
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
                    if behind > bus && behind <= last_bus && depth < 16 {
                        self.scan(ecam, segment, behind, last_bus, depth + 1);
                    }
                    if let Some(port) = hotplug::Port::of(id, config) {
                        self.ports.push((port, ecam, segment));
                    }
                }
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
        Ok(())
    }

    /// Start the driver `driver` for function number `index`.
    fn start(&mut self, index: usize, driver: &'static str) -> Result<(), &'static str> {
        let f = &self.functions[index];
        let image = ramdisk::find(self.archive, driver).ok_or("its driver is not in the boot archive")?;
        let (id, config) = (f.id, f.config);
        // Its interrupt lines: as many as it can raise, up to a limit; the
        // same ones every time a driver is started for it.
        let (first_line, lines) = match f.lines {
            Some(l) => l,
            None => {
                let lines = (f.vectors as u32).min(LINES_PER_DEVICE);
                if self.next_line as u64 + lines as u64 > sys::IRQ_LINES {
                    return Err("the machine has no interrupt lines left for it");
                }
                (self.next_line, lines)
            }
        };
        // Its registers: one frame per memory BAR.
        let mut grants = [Grant::none(); silica_driver::grant::COUNT];
        for (i, bar) in f.bars.iter().enumerate() {
            let Some(bar) = bar else { continue };
            if bar.bits < 12 {
                // Registers smaller than a page share their page with
                // whatever else the firmware put there.
                return Err("it has registers smaller than a page, which cannot be handed out on their own yet");
            }
            let frame = self.memory.frame(bar.base, bar.bits).map_err(|_| "its registers are not in the machine's device memory")?;
            grants[silica_driver::grant::BAR0 as usize + i] = Grant::lend(frame, RW);
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
        // What the driver may not change itself: the device answers memory
        // accesses, may do DMA and send message interrupts, and raises
        // those through MSI-X, never the legacy wire.
        let registers = config.registers();
        registers.write16(4, registers.read16(4) | pci::COMMAND_MEMORY | pci::COMMAND_MASTER | pci::COMMAND_NO_INTX);
        if let Some(msix) = config.msix() {
            registers.write16(msix.cap + 2, (registers.read16(msix.cap + 2) | 1 << 15) & !(1 << 14));
        }
        self.next_id += 1;
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
        // A fault to commit on purpose, in the driver's first run only.
        let inject = if f.starts == 0 { inject_plan(self.cmdline, driver) } else { 0 };
        let starts = f.starts;
        let log = self.log_of(index, driver);
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
            log,
            ..Program::new(image, self.next_id)
        };
        let child = spawn(&self.parent, &program).map_err(|e| {
            println!("devmgr: cannot start {driver}: {e:?}");
            "its driver could not be started"
        })?;
        let f = &mut self.functions[index];
        if f.lines.is_none() {
            f.lines = Some((first_line, lines));
            self.next_line += lines;
        }
        f.starts += 1;
        self.running.push(Running { name: driver, id: self.next_id, function: index, child, service, gone: Vec::new() });
        Ok(())
    }
}

impl Manager {
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
            let name = silica_rt::alloc::format!("{driver}@{}", name(self.functions[index].id));
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
        let registers = config.registers();
        registers.write16(4, registers.read16(4) & !pci::COMMAND_MASTER);
        if let Some(msix) = config.msix() {
            registers.write16(msix.cap + 2, registers.read16(msix.cap + 2) & !(1 << 15));
        }
        let ok = r.child.destroy().is_ok();
        // Its clients hear of it now, not on their next call.
        for g in r.gone {
            let _ = sys::signal(g.cap());
        }
        // SAFETY: the endpoint was the ended driver's alone.
        #[allow(unsafe_code)]
        unsafe {
            r.service.destroy()
        };
        ok
    }
}

/// Map the boot archive: the ramdisk frames, laid out as they are in memory.
fn map_archive(info: &RootInfo, frames: u64) -> Result<&'static [u8], &'static str> {
    let pieces = info.untyped[..info.untyped_count as usize].iter().filter(|d| d.kind == KIND_RAMDISK);
    let first = pieces.clone().map(|d| d.base).min().ok_or("the machine has no boot archive")?;
    let end = pieces.clone().map(|d| d.base + (1 << d.bits)).max().unwrap_or(first);
    let region = mem::reserve((end - first) as usize, 1 << 21).ok_or("no address space for the boot archive")?;
    for (i, d) in pieces.enumerate() {
        if i as u64 >= frames {
            return Err("the root task passed fewer boot archive frames than the machine has");
        }
        sys::map(slots::ASPACE, granted(GRANT_FIRST_RAMDISK + i as u64), region + (d.base - first) as usize, Rights::READ)
            .map_err(|_| "cannot map the boot archive")?;
    }
    // SAFETY: the archive's frames were just mapped read-only, contiguous
    // as they are in memory, and stay mapped; nothing writes them.
    #[allow(unsafe_code)]
    Ok(unsafe { core::slice::from_raw_parts((region + (info.ramdisk[0] - first) as usize) as *const u8, info.ramdisk[1] as usize) })
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
    let archive = map_archive(info, ramdisk_frames)?;
    // The device memory, in the order the kernel listed it.
    let mut memory = DeviceMemory::new();
    let device = info.untyped[..info.untyped_count as usize].iter().filter(|d| d.kind == KIND_DEVICE || d.kind == KIND_FIRMWARE);
    for (i, d) in device.enumerate() {
        if (i as u64) < untypeds {
            memory.add(d.base, d.bits, granted(GRANT_FIRST_RAMDISK + ramdisk_frames + i as u64));
        }
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
        next_id: 0,
        listing: Vec::new(),
        next_client: CLIENTS,
        cmdline: &info.cmdline[..(info.cmdline_len as usize).min(info.cmdline.len())],
        ports: Vec::new(),
        table: drivers(archive),
        configs: BTreeMap::new(),
    };
    m.enumerate()?;
    let cmdline = m.cmdline;
    let table = m.table.clone();
    if table.is_empty() {
        println!("devmgr: the boot archive lists no drivers");
    }
    if info.dma_top == 0 {
        println!("devmgr: this machine cannot confine DMA: every driver started here is trusted with all of memory");
    }
    // Say what there is, then start the drivers.
    let mut failed = false;
    let mut wanted = Vec::new();
    for (i, f) in m.functions.iter().enumerate() {
        let driver = driver_for(f, cmdline, &table);
        println!(
            "devmgr: {} {:04x}:{:04x} class {:02x}.{:02x}.{:02x}, {} interrupts: {}",
            name(f.id),
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
            println!("ERROR: devmgr: {} is not driven: {e}", name(m.functions[i].id));
            failed = true;
        }
    }
    if failed {
        println!("ERROR: devmgr: not every device has its driver");
    }
    // What happens to the machine: the power button and the hot-plug slots,
    // each a bit of one notification.
    let happened = Object::new(ObjectType::Notification, 0).map_err(|_| "no memory for its notification")?;
    let sender = |bits: u64| -> Result<Cap, &'static str> {
        let slot = free_slot().ok_or("no capability slots left")?;
        sys::cap_derive(slots::SPACE, slot, happened.cap(), Rights::WRITE, bits).map_err(|_| "cannot make a notification sender")?;
        Ok(Cap(slot))
    };
    let button = match power::Button::new(&mut m, granted(GRANT_PORTS), granted(GRANT_IRQS), sender(power::BUTTON)?) {
        Ok(b) => Some(b),
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
    loop {
        let got = listener.recv_listening(happened.cap(), Wait::Forever);
        let Ok(msg) = got else { return Err("its endpoint was taken away") };
        if let Some(bits) = msg.signals() {
            if bits & hotplug::HOTPLUG != 0 {
                m.slots_changed();
            }
            if bits & power::BUTTON != 0
                && let Some(b) = &button
                && b.pressed()
            {
                println!("devmgr: the power button was pressed: shutting down");
                let mut system = silica_protocols::system::manager::Client::<Channel, Handle>::from(Channel::new(granted(GRANT_SYSTEM)));
                if let Err(e) = system.shutdown(false) {
                    println!("ERROR: devmgr: the service manager would not shut down: {e:?}");
                }
            }
            continue;
        }
        // Clients' badges are from CLIENTS up; a fault report's has
        // FAULT_BADGE, above them, which no client is given.
        if msg.badge >= CLIENTS && msg.badge & FAULT_BADGE == 0 {
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
        let device = name(m.functions[function].id);
        let ended_well = if label == EXIT_LABEL && !fault {
            let status = msg.words[0] as i64;
            println!("devmgr: {driver} for {device} ended with status {status}");
            status == 0
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
        if ended_well {
            continue;
        }
        m.functions[function].failures += 1;
        if m.functions[function].failures > MAX_RESTARTS {
            println!("ERROR: devmgr: {driver} for {device} failed {} times; the device is left alone", m.functions[function].failures);
        } else if let Err(e) = m.start(function, driver) {
            println!("ERROR: devmgr: {device} is not driven: {e}");
        } else {
            println!("devmgr: {driver} for {device} started again");
        }
    }
}
