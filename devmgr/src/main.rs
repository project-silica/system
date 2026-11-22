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
//! A driver that faults or ends with a failure is taken down, its device
//! is silenced (no bus mastering; the kernel has already cut it off from
//! memory, which happens when the driver's device address space goes), and
//! the driver is started again, at most [`MAX_RESTARTS`] times; the driver
//! is told how many times it has been started. A driver may be replaced:
//! `driver=<vendor>:<device>=<program>` on the kernel command line (four
//! hexadecimal digits each) starts `<program>` from the boot archive for
//! that kind of device instead of the driver the device manager would pick.
//!
//! Started by the root task with, as grants: 0 the frame of the kernel's
//! `RootInfo` (read-only), 1 the device identities, 2 the interrupt lines,
//! 3 the I/O ports (or nothing), then `args[0]` frames of the ramdisk (in
//! `RootInfo` order, read-only), then `args[1]` Untyped capabilities, given
//! outright: the machine's device memory, in `RootInfo` order.
#![no_std]
#![no_main]

mod phys;

use libsys::root::{KIND_DEVICE, KIND_RAMDISK, ROOT_MAGIC, RootInfo};
use libsys::{self as sys, Cap, ObjectType, Rights, Wait};
use phys::DeviceMemory;
use silica_driver::pci::{self, Config};
use silica_formats::{acpi, ramdisk};
use silica_proc::{Child, Grant, Parent, Program, spawn};
use silica_rt::alloc::collections::BTreeMap;
use silica_rt::alloc::vec::Vec;
use silica_rt::mem::{self, Object};
use silica_rt::mmio::Mmio;
use silica_rt::{EXIT_LABEL, ProcessInfo, println, slots};

silica_rt::main!(main);

const RW: Rights = Rights(Rights::READ.0 | Rights::WRITE.0);
const GRANT_INFO: u64 = 0;
const GRANT_DEVICES: u64 = 1;
const GRANT_IRQS: u64 = 2;
const GRANT_FIRST_RAMDISK: u64 = 4;
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
}

/// A driver that is running.
struct Running<'a> {
    name: &'a str,
    /// The identifier its exit report and its faults carry.
    id: u64,
    function: usize,
    child: Child,
    /// The endpoint its clients call it on.
    #[allow(dead_code)]
    service: Object,
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
fn option<'a>(cmdline: &'a [u8], key: &str) -> impl Iterator<Item = &'a [u8]> {
    cmdline.split(|b| b.is_ascii_whitespace()).filter_map(move |w| w.strip_prefix(key.as_bytes())?.strip_prefix(b"="))
}

/// The driver for a function: the owner's choice on the command line
/// (`driver=<vendor>:<device>=<program>`), else by what the function says it is.
fn driver_for(f: &Function, cmdline: &'static [u8]) -> Option<&'static str> {
    let hex = |b: &[u8]| core::str::from_utf8(b).ok().and_then(|s| u16::from_str_radix(s, 16).ok());
    for choice in option(cmdline, "driver") {
        let mut parts = choice.splitn(2, |b| *b == b'=');
        let (Some(ids), Some(program)) = (parts.next(), parts.next()) else { continue };
        let mut ids = ids.splitn(2, |b| *b == b':');
        if (ids.next().and_then(hex), ids.next().and_then(hex)) == (Some(f.vendor), Some(f.device)) {
            return core::str::from_utf8(program).ok();
        }
    }
    match (f.vendor, f.device) {
        // virtio block: the 1.0 identifier, and the transitional one.
        (0x1AF4, 0x1042 | 0x1001) => Some("virtio-blk"),
        _ => None,
    }
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
        let frame = self.memory.frame(ecam + ((id as u64 & 0xFFFF) << 12), 12).ok()?;
        let at = mem::map(frame, 12, RW).ok()?;
        // SAFETY: the function's configuration space, just mapped, for as
        // long as the device manager runs.
        #[allow(unsafe_code)]
        let space = unsafe { Mmio::new(at, 4096) };
        Some((Config::new(space), frame))
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
                }
                let mut bars = [None; 6];
                let mut i = 0;
                while i < 6 {
                    let wide = config.bar_address(i).is_some_and(|(_, wide)| wide);
                    bars[i] = config.probe_bar(i);
                    i += if wide { 2 } else { 1 };
                }
                let vectors = config.msix().map_or(0, |m| m.vectors);
                let f = Function {
                    id,
                    config,
                    config_frame,
                    vendor: config.vendor(),
                    device: config.device(),
                    class: config.class(),
                    bars,
                    vectors,
                    lines: None,
                    starts: 0,
                };
                self.functions.push(f);
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
        grants[silica_driver::grant::SERVICE as usize] = Grant::lend(service.cap(), Rights::READ);
        grants[silica_driver::grant::IDENTITY as usize] =
            Grant::badged(granted(GRANT_DEVICES), Rights::ALL, id as u64 | (id as u64 + 1) << 32);
        grants[silica_driver::grant::INTERRUPTS as usize] =
            Grant::badged(granted(GRANT_IRQS), Rights::ALL, first_line as u64 | (first_line as u64 + lines as u64) << 32);
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
        let program = Program {
            grants: &grants,
            args: [id as u64, first_line as u64, lines as u64, self.info.dma_top, f.starts as u64, 0, 0, 0],
            aspace_bits: 18,
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
        self.running.push(Running { name: driver, id: self.next_id, function: index, child, service });
        Ok(())
    }
}

impl Manager {
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
        Ok(()) => 0,
        Err(e) => {
            println!("ERROR: devmgr: {e}");
            1
        }
    }
}

fn run(process: &ProcessInfo) -> Result<(), &'static str> {
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
    let device = info.untyped[..info.untyped_count as usize].iter().filter(|d| d.kind == KIND_DEVICE);
    for (i, d) in device.enumerate() {
        if (i as u64) < untypeds {
            memory.add(d.base, d.bits, granted(GRANT_FIRST_RAMDISK + ramdisk_frames + i as u64));
        }
    }
    // Drivers report their exit, and the kernel their faults, to one
    // endpoint, each badged with the driver's identifier.
    let events = Object::new(ObjectType::Endpoint, 0).map_err(|_| "no memory for the drivers' endpoint")?;
    let scratch = mem::reserve(1 << 20, 1 << 21).ok_or("no address space to start drivers with")?;
    let parent = Parent { fault: events.cap(), ..Parent::of(process, events.cap(), scratch) };
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
    };
    m.enumerate()?;
    let cmdline: &'static [u8] = &info.cmdline[..(info.cmdline_len as usize).min(info.cmdline.len())];
    if info.dma_top == 0 {
        println!("devmgr: this machine cannot confine DMA: every driver started here is trusted with all of memory");
    }
    // Say what there is, then start the drivers.
    let mut failed = false;
    let mut wanted = Vec::new();
    for (i, f) in m.functions.iter().enumerate() {
        let driver = driver_for(f, cmdline);
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
    // Until there is something that asks the device manager for devices,
    // its work is done when its drivers are: report each one's end, and
    // start again the ones that failed.
    while !m.running.is_empty() {
        let Ok(msg) = sys::recv(events.cap(), Wait::Until(silica_rt::clock().now() + 30_000_000_000)) else {
            println!("ERROR: devmgr: a driver has not finished after 30 s");
            return Err("drivers did not finish");
        };
        let Some(at) = m.running.iter().position(|r| msg.badge == r.id) else { continue };
        let label = msg.info.label();
        let r = m.running.remove(at);
        let (driver, function) = (r.name, r.function);
        let device = name(m.functions[function].id);
        let ended_well = if label == EXIT_LABEL {
            let status = msg.words[0] as i64;
            println!("devmgr: {driver} for {device} ended with status {status}");
            status == 0
        } else if label >= sys::FAULT_LABEL {
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
            failed = true;
        }
        if ended_well {
            continue;
        }
        if m.functions[function].starts > MAX_RESTARTS {
            println!("ERROR: devmgr: {driver} for {device} failed {} times; the device is left alone", m.functions[function].starts);
            failed = true;
        } else if let Err(e) = m.start(function, driver) {
            println!("ERROR: devmgr: {device} is not driven: {e}");
            failed = true;
        } else {
            println!("devmgr: {driver} for {device} started again");
        }
    }
    if failed { Err("a driver failed") } else { Ok(()) }
}
