//! The NVMe controller driver: one namespace of an NVMe controller (PCI
//! class 01.08.02) as a `silica.block.Device`.
//!
//! Written against the NVM Express Base Specification 2.0 (sections 3.1
//! registers, 3.5 controller initialization, 4.1 queues, 4.3 PRPs, 5 admin
//! commands) and the NVM Command Set Specification 1.0 (I/O commands,
//! Identify Namespace). One admin queue pair and one I/O queue pair, PRPs
//! for data. MSI-X entry 0 is the admin queue's and entry 1 the I/O
//! queue's; a controller with one vector (or a driver granted one line)
//! has both queues interrupt on entry 0, and every interrupt is then looked
//! at as the I/O queue's.
//!
//! Namespaces: every active one is identified (the first 1024 the
//! controller lists), the first this driver can serve is served, and each
//! of the others is reported with why it is not: one whose format carries
//! metadata or a block size outside 512 bytes to 64 KiB, and every one after
//! the served one, since the device manager names one disk per controller.
//! Blocks of 512 bytes to 64 KiB are served alike: a 4 KiB block that starts
//! part-way into a page of the client's memory spans two pages, and the PRPs
//! say so. A controller with no namespace this driver can serve is left
//! alone (the driver ends with status 0, which is not a failure).
//!
//! The device is not trusted: every completion's phase, queue, submission
//! queue head and command identifier is checked against what the driver
//! submitted before anything is done with it, and so is the namespace list.
//! A controller that answers nonsense, reports fatal status or stops
//! answering ends the driver with a failure; the device manager then starts
//! it again, which resets the controller, and the block client sends its
//! requests again.
//!
//! Not handled yet: serving more than one namespace (each would be a disk
//! of its own: the device manager's identities and endpoints are one per
//! PCI function today), namespaces with metadata or protection information,
//! more than one I/O queue, namespaces attached or detached while the driver
//! runs (they are seen when it is next started), the shutdown notification
//! (`CC.SHN`) before the driver ends.

#![no_std]
#![no_main]

use core::convert::Infallible;

use silica_block::device::{Error, Info};
use silica_block::service::{CLIENT, Completions, Device as BlockDevice, Refusal, Service, Ticket};
use silica_block::{Op, Request, Status};
use silica_driver::dma::{Dma, DmaMemory, Shared};
use silica_driver::inject::{self, Fault};
use silica_driver::irq::{Interrupt, Signals};
use silica_driver::{Device, DeviceError};
use silica_rt::alloc::vec::Vec;
use silica_rt::mmio::Mmio;
use silica_rt::println;
use silica_rt::sys::{self, Cap, Wait};

use nvme::{MAX_NAMESPACES, NO_BLOCKS, Namespace, Queue, status};

silica_rt::main!(main);

// Controller registers (base specification, section 3.1.4).
const CAP: usize = 0x00;
const VS: usize = 0x08;
const CC: usize = 0x14;
const CSTS: usize = 0x1C;
const AQA: usize = 0x24;
const ASQ: usize = 0x28;
const ACQ: usize = 0x30;
const DOORBELLS: usize = 0x1000;

const CC_EN: u32 = 1;
/// I/O submission entries of 64 bytes (2^6), completion entries of 16 (2^4);
/// NVM command set, 4 KiB pages, round robin: all zero.
const CC_ENTRY_SIZES: u32 = (6 << 16) | (4 << 20);
const CSTS_RDY: u32 = 1;
const CSTS_CFS: u32 = 2;

const ADMIN_CREATE_SQ: u32 = 0x01;
const ADMIN_CREATE_CQ: u32 = 0x05;
const ADMIN_IDENTIFY: u32 = 0x06;
const ADMIN_SET_FEATURES: u32 = 0x09;
const FEATURE_QUEUES: u32 = 0x07;
const IO_FLUSH: u32 = 0x00;
const IO_WRITE: u32 = 0x01;
const IO_READ: u32 = 0x02;

const PAGE: u64 = 4096;
const ADMIN_ENTRIES: u16 = 32;
const IO_ENTRIES: u16 = 256;
/// The most one request moves. Its pages after the first fit a PRP list
/// of `PRP_LIST_BYTES`, one per command identifier.
const MAX_TRANSFER: u64 = 128 * 1024;
const PRP_LIST_BYTES: usize = (MAX_TRANSFER / PAGE) as usize * 8;
/// How long an admin command may take (the specification gives none).
const ADMIN_TIMEOUT_NS: u64 = 5_000_000_000;
/// How often a register is read while waiting for the controller.
const POLL_NS: u64 = 50_000;

// The bits of the driver's notification: interrupt n signals 2 << n.
const ADMIN_BIT: u64 = 2;
const IO_BIT: u64 = 4;
/// How long the controller may take over an I/O command before the driver
/// gives up on it (Linux's default too): it ends, and the device manager
/// starts it again, which resets the controller.
const IO_TIMEOUT_NS: u64 = 30_000_000_000;

fn main(info: &'static silica_rt::ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("nvme: giving up on the controller: {:?}", e);
            1
        }
    }
}

fn now() -> u64 {
    silica_rt::clock().now()
}

/// The smallest power of two (at least a page) holding `bytes`, in bits.
fn bits_for(bytes: usize) -> u8 {
    bytes.next_power_of_two().trailing_zeros().max(12) as u8
}

/// A 64-bit register as two 32-bit accesses, low half first: what every
/// controller accepts.
fn read64(regs: &Mmio, at: usize) -> u64 {
    regs.read32(at) as u64 | (regs.read32(at + 4) as u64) << 32
}

fn write64(regs: &Mmio, at: usize, value: u64) {
    regs.write32(at, value as u32);
    regs.write32(at + 4, (value >> 32) as u32);
}

/// Queue pair `id` of `entries` entries in new DMA memory, with its
/// doorbells, and the device addresses of its submission and completion
/// queues.
fn queue(dma: &Dma, regs: &Mmio, stride: usize, id: u16, entries: u16) -> Result<(Queue, u64, u64), DeviceError> {
    let bell = |n: usize| regs.part(DOORBELLS + n * stride, 4).ok_or(DeviceError::Missing("a doorbell inside BAR 0"));
    // The device only reads its submissions; only completions are its to write.
    // Never unmapped (`DmaMemory`): the views outlive the values.
    let sq = dma.memory(bits_for(entries as usize * 64), false)?;
    let cq = dma.memory(bits_for(entries as usize * 16), true)?;
    let q = Queue::over(id, entries, sq.shared(), cq.shared(), bell(2 * id as usize)?, bell(2 * id as usize + 1)?)
        .ok_or(DeviceError::Missing("a queue of at least two entries"))?;
    Ok((q, sq.device_address(), cq.device_address()))
}

/// The controller during bring-up, when the driver waits for one thing at a time.
struct Controller {
    regs: Mmio,
    /// CAP.TO: the longest CSTS.RDY may take to follow CC.EN.
    ready_ns: u64,
    /// The driver's notification, where the admin queue's interrupt arrives.
    listen: Cap,
    admin: Queue,
    cid: u16,
}

impl Controller {
    fn status(&self) -> Result<u32, DeviceError> {
        match self.regs.read32(CSTS) {
            u32::MAX => Err(DeviceError::Protocol("the registers read as all ones: the controller is gone")),
            s => Ok(s),
        }
    }

    /// Wait until the notification is signalled or `until` (a sleep when
    /// nothing will signal it).
    fn sleep(&self, until: u64) {
        // A timeout is the expected end; anything else (an interrupt) is a wake-up.
        let _ = sys::recv(self.listen, Wait::Until(until));
    }

    /// Wait for CSTS.RDY to read `ready`, as long as CAP.TO allows.
    fn wait_ready(&self, ready: bool) -> Result<(), DeviceError> {
        let deadline = now() + self.ready_ns;
        loop {
            let status = self.status()?;
            if ready && status & CSTS_CFS != 0 {
                return Err(DeviceError::Protocol("the controller reports fatal status"));
            }
            if (status & CSTS_RDY != 0) == ready {
                return Ok(());
            }
            let t = now();
            if t >= deadline {
                return Err(DeviceError::Timeout(if ready { "CSTS.RDY to set" } else { "CSTS.RDY to clear" }));
            }
            self.sleep((t + POLL_NS).min(deadline));
        }
    }

    /// Run one admin command to completion: its completion's first word.
    fn admin(&mut self, mut command: [u32; 16], what: &'static str) -> Result<u32, DeviceError> {
        self.cid = (self.cid + 1) & 0x7FFF;
        command[0] |= (self.cid as u32) << 16;
        self.admin.push(&command);
        self.admin.ring();
        let deadline = now() + ADMIN_TIMEOUT_NS;
        loop {
            if let Some(c) = self.admin.pop()? {
                self.admin.release();
                if c.cid != self.cid {
                    return Err(DeviceError::Protocol("an admin completion names a command not in progress"));
                }
                if c.status & 0x7FF != 0 {
                    println!("nvme: {} failed: status type {}, code {:#x}", what, c.status >> 8 & 7, c.status & 0xFF);
                    return Err(DeviceError::Missing(what));
                }
                return Ok(c.result);
            }
            if self.status()? & CSTS_CFS != 0 {
                return Err(DeviceError::Protocol("the controller reports fatal status"));
            }
            if now() >= deadline {
                return Err(DeviceError::Timeout(what));
            }
            self.sleep(deadline);
        }
    }

    fn identify(&mut self, buffer: &DmaMemory, cns: u32, nsid: u32, what: &'static str) -> Result<(), DeviceError> {
        let mut c = [0u32; 16];
        c[0] = ADMIN_IDENTIFY;
        c[1] = nsid;
        c[6] = buffer.device_address() as u32;
        c[7] = (buffer.device_address() >> 32) as u32;
        c[10] = cns;
        self.admin(c, what).map(|_| ())
    }

    fn create_queue(&mut self, opcode: u32, q: &Queue, address: u64, cdw11: u32, what: &'static str) -> Result<(), DeviceError> {
        let mut c = [0u32; 16];
        c[0] = opcode;
        c[6] = address as u32;
        c[7] = (address >> 32) as u32;
        c[10] = (q.entries as u32 - 1) << 16 | q.id as u32;
        c[11] = cdw11;
        self.admin(c, what).map(|_| ())
    }
}

/// Namespace `nsid` as Identify Namespace describes it: `Ok(Err(why))` for
/// one this driver cannot serve, `Err` for a controller that cannot be
/// relied on.
fn namespace(ctl: &mut Controller, buffer: &DmaMemory, nsid: u32) -> Result<Result<Namespace, &'static str>, DeviceError> {
    ctl.identify(buffer, 0, nsid, "Identify Namespace")?;
    nvme::namespace(&buffer.shared(), nsid)
}

/// The controller's active namespaces, in increasing order (at most
/// [`MAX_NAMESPACES`]). `namespaces` is Identify Controller's NN.
fn active_namespaces(ctl: &mut Controller, buffer: &DmaMemory, version: u32, namespaces: u32) -> Result<Vec<u32>, DeviceError> {
    if version < 0x0001_0100 {
        // No list before NVMe 1.1: every identifier up to NN, the inactive
        // ones told apart by Identify Namespace.
        return Ok((1..=namespaces.min(MAX_NAMESPACES as u32)).collect());
    }
    ctl.identify(buffer, 2, 0, "Identify Active Namespace List")?;
    nvme::active_list(&buffer.shared(), namespaces)
}

/// The driver's part of the block service: the I/O queue pair.
struct Disk {
    dma: Dma,
    info: Info,
    regs: Mmio,
    nsid: u32,
    block_bits: u32,
    io: Queue,
    /// One PRP list per command identifier, read by the device.
    prp: DmaMemory,
    prp_mem: Mmio,
    /// The request each command identifier carries, while the device has
    /// it, and when it was started.
    tickets: Vec<Option<(Ticket, u64)>>,
    free: Vec<u16>,
    /// Commands pushed since the doorbell was last rung.
    unrung: bool,
    /// The bit the I/O queue's interrupt signals: `IO_BIT`, or `ADMIN_BIT`
    /// when both queues share a vector.
    io_bit: u64,
    // Kept alive for as long as the controller may use them.
    _admin: Queue,
    _interrupts: (Interrupt, Option<Interrupt>),
}

impl Disk {
    /// The PRP entries of `blocks` blocks at device address `address`, the
    /// list (if one is needed) written in command `cid`'s place.
    fn prps(&self, cid: u16, address: u64, blocks: u32) -> Option<(u64, u64)> {
        if blocks == 0 || blocks > self.info.max_blocks || address & 3 != 0 {
            return None;
        }
        let end = address.checked_add((blocks as u64) << self.block_bits)?;
        let second = (address | (PAGE - 1)).checked_add(1)?;
        if end <= second {
            return Some((address, 0));
        }
        if end <= second + PAGE {
            return Some((address, second));
        }
        let list = cid as usize * PRP_LIST_BYTES;
        let mut page = second;
        let mut i = 0;
        while page < end && i < PRP_LIST_BYTES {
            self.prp_mem.write64(list + i, page);
            page += PAGE;
            i += 8;
        }
        Some((address, self.prp.device_address() + list as u64))
    }
}

/// The controller cannot be relied on: end, so that the device manager
/// resets it by starting the driver again and the client sends again what
/// was in progress.
fn give_up(why: DeviceError) -> ! {
    println!("nvme: giving up on the controller: {:?}", why);
    silica_rt::exit(2)
}

impl BlockDevice for Disk {
    type Mapping = Shared;

    fn info(&self) -> Info {
        self.info.clone()
    }

    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, Shared), Error> {
        let s = self.dma.share(frame, bits, writable).map_err(|_| Error::NoRoom)?;
        Ok((s.address, s))
    }

    fn unmap(&mut self, mapping: Shared) {
        self.dma.unshare(mapping)
    }

    fn start(&mut self, request: &Request, address: u64, ticket: Ticket) -> Result<(), Refusal> {
        if self.io.full() {
            return Err(Refusal::Busy);
        }
        let Some(cid) = self.free.pop() else { return Err(Refusal::Busy) };
        let (opcode, prp1, prp2) = match request.op {
            Op::Flush => (IO_FLUSH, 0, 0),
            Op::Read | Op::Write => match self.prps(cid, address, request.blocks) {
                Some((a, b)) => (if matches!(request.op, Op::Read) { IO_READ } else { IO_WRITE }, a, b),
                None => {
                    self.free.push(cid);
                    return Err(Refusal::Fail(Status::Invalid));
                }
            },
        };
        let mut c = [0u32; 16];
        c[0] = opcode | (cid as u32) << 16;
        c[1] = self.nsid;
        c[6] = prp1 as u32;
        c[7] = (prp1 >> 32) as u32;
        c[8] = prp2 as u32;
        c[9] = (prp2 >> 32) as u32;
        if opcode != IO_FLUSH {
            c[10] = request.block as u32;
            c[11] = (request.block >> 32) as u32;
            c[12] = request.blocks - 1;
        }
        self.tickets[cid as usize] = Some((ticket, now()));
        // An injected fault (`silica_driver::inject`): the controller never
        // sees this command.
        if inject::due() == Some(Fault::Stuck) && inject::pending(Fault::Stuck) {
            return Ok(());
        }
        self.io.push(&c);
        self.unrung = true;
        Ok(())
    }

    fn kick(&mut self) {
        // An injected fault: the controller resets itself instead.
        if inject::pending(Fault::Reset) {
            self.regs.write32(CC, self.regs.read32(CC) & !CC_EN);
            self.unrung = false;
            return;
        }
        if self.unrung {
            self.io.ring();
            self.unrung = false;
        }
    }

    fn signals(&mut self, bits: u64, done: &mut Completions<'_>) {
        // An injected fault: this interrupt never came (what it brought
        // waits for the next look).
        if bits & self.io_bit != 0 && inject::pending(Fault::Missed) {
            return;
        }
        let mut taken = 0;
        loop {
            let c = match self.io.pop() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => give_up(e),
            };
            taken += 1;
            // An injected fault: the controller wrote nonsense in it.
            let cid = if inject::pending(Fault::Garbage) { u16::MAX } else { c.cid };
            let Some((ticket, _)) = self.tickets.get_mut(cid as usize).and_then(Option::take) else {
                give_up(DeviceError::Protocol("a completion names a command not in progress"));
            };
            self.free.push(c.cid);
            done(ticket, status(c.status));
        }
        if taken > 0 {
            self.io.release();
        } else if bits & (ADMIN_BIT | IO_BIT) != 0 {
            // An interrupt with nothing to show for it: is the controller still well?
            match self.regs.read32(CSTS) {
                u32::MAX => give_up(DeviceError::Protocol("the registers read as all ones: the controller is gone")),
                s if s & CSTS_CFS != 0 => give_up(DeviceError::Protocol("the controller reports fatal status")),
                _ => {}
            }
        }
    }

    fn deadline(&self) -> Option<u64> {
        let limit = if inject::armed() { inject::ARMED_TIMEOUT_NS } else { IO_TIMEOUT_NS };
        self.tickets.iter().flatten().map(|(_, t)| t + limit).min()
    }

    fn timeout(&mut self, done: &mut Completions<'_>) {
        // What finished without an interrupt first, then the verdict.
        self.signals(0, done);
        if self.deadline().is_some_and(|d| d <= now()) {
            give_up(DeviceError::Timeout("an I/O command the controller never completed"));
        }
    }
}

fn run(info: &silica_rt::ProcessInfo) -> Result<Infallible, DeviceError> {
    let device = Device::take(info)?;
    let regs = device.bar(0).ok_or(DeviceError::Missing("BAR 0, the controller's registers"))?;
    if regs.len() < DOORBELLS + 8 {
        return Err(DeviceError::Missing("BAR 0 large enough for the admin doorbells"));
    }
    let vectors = device.config().msix().ok_or(DeviceError::Missing("MSI-X"))?.vectors;
    let lines = device.lines.end.saturating_sub(device.lines.start);
    if vectors == 0 || lines == 0 {
        return Err(DeviceError::Missing("an interrupt"));
    }
    let dma = Dma::new(&device)?;
    let signals = Signals::new()?;
    let admin_irq = Interrupt::bind_to(&device, 0, signals.sender(ADMIN_BIT)?)?;
    // The I/O queue gets an interrupt of its own where there are two;
    // otherwise it shares the admin queue's.
    let io_irq = if vectors >= 2 && lines >= 2 { Some(Interrupt::bind_to(&device, 1, signals.sender(IO_BIT)?)?) } else { None };
    let io_bit = if io_irq.is_some() { IO_BIT } else { ADMIN_BIT };
    // Injected interrupts arrive as the I/O queue's would.
    inject::interrupts(signals.sender(io_bit)?);

    let cap = read64(&regs, CAP);
    if cap == u64::MAX {
        return Err(DeviceError::Protocol("the registers read as all ones: the controller is gone"));
    }
    if cap >> 37 & 1 == 0 {
        return Err(DeviceError::Missing("the NVM command set"));
    }
    if cap >> 48 & 0xF != 0 {
        return Err(DeviceError::Missing("4 KiB memory pages"));
    }
    let io_entries = nvme::queue_entries(cap, IO_ENTRIES);
    let stride = 4usize << (cap >> 32 & 0xF);
    let version = regs.read32(VS);

    let (admin, asq, acq) = queue(&dma, &regs, stride, 0, ADMIN_ENTRIES)?;
    let mut ctl = Controller {
        regs: regs.part(0, regs.len()).ok_or(DeviceError::Missing("BAR 0"))?,
        ready_ns: (cap >> 24 & 0xFF).max(1) * 500_000_000,
        listen: signals.listen(),
        admin,
        cid: 0,
    };

    // Reset: a driver started again finds the controller as the last one left it.
    let cc = regs.read32(CC);
    if cc & CC_EN != 0 {
        // Let an enable in progress finish first; a controller in fatal state never will.
        let _ = ctl.wait_ready(true);
        regs.write32(CC, cc & !CC_EN);
    }
    ctl.wait_ready(false)?;
    let a = ADMIN_ENTRIES as u32 - 1;
    regs.write32(AQA, a << 16 | a);
    write64(&regs, ASQ, asq);
    write64(&regs, ACQ, acq);
    regs.write32(CC, CC_ENTRY_SIZES | CC_EN);
    ctl.wait_ready(true)?;

    let buffer = dma.memory(12, true)?;
    let m = buffer.shared();
    ctl.identify(&buffer, 1, 0, "Identify Controller")?;
    let mdts = m.read8(77) as u32;
    let (sqes, cqes) = (m.read8(512), m.read8(513));
    if sqes & 0xF > 6 || sqes >> 4 < 6 || cqes & 0xF > 4 || cqes >> 4 < 4 {
        return Err(DeviceError::Missing("64-byte submission and 16-byte completion entries"));
    }
    let namespaces = m.read32(516);
    let write_cache = m.read8(525) & 1 != 0;
    let mut model = [0u8; 40];
    for (i, b) in model.iter_mut().enumerate() {
        *b = match m.read8(24 + i) {
            c @ 0x20..=0x7E => c,
            _ => b'?',
        };
    }

    // The first active namespace this driver can serve; the others said.
    let mut served: Option<Namespace> = None;
    for nsid in active_namespaces(&mut ctl, &buffer, version, namespaces)? {
        match namespace(&mut ctl, &buffer, nsid)? {
            Ok(ns) if served.is_none() => served = Some(ns),
            Ok(ns) => println!(
                "nvme: namespace {}: {} blocks of {} bytes, not served: one disk per controller",
                ns.id,
                ns.blocks,
                1u32 << ns.block_bits
            ),
            // Before NVMe 1.1 the identifiers tried include inactive ones.
            Err(why) if version < 0x0001_0100 && why == NO_BLOCKS => {}
            Err(why) => println!("nvme: namespace {nsid}: not served: {why}"),
        }
    }
    let Some(ns) = served else {
        // Nothing here this driver will ever serve: ending well leaves the
        // controller alone, where a failure would have it started again.
        println!("nvme: no namespace this driver can serve; leaving the controller alone");
        silica_rt::exit(0)
    };

    // One I/O queue pair (zero-based counts of submission and completion queues).
    let mut c = [0u32; 16];
    c[0] = ADMIN_SET_FEATURES;
    c[10] = FEATURE_QUEUES;
    ctl.admin(c, "Set Features (Number of Queues)")?;
    let (io, sq, cq) = queue(&dma, &regs, stride, 1, io_entries)?;
    let vector = io_irq.is_some() as u32;
    // Physically contiguous, interrupts on, on `vector`.
    ctl.create_queue(ADMIN_CREATE_CQ, &io, cq, vector << 16 | 3, "Create I/O Completion Queue")?;
    ctl.create_queue(ADMIN_CREATE_SQ, &io, sq, (io.id as u32) << 16 | 1, "Create I/O Submission Queue")?;

    let mut max_bytes = MAX_TRANSFER;
    if mdts != 0 && mdts < 32 {
        max_bytes = max_bytes.min(PAGE << mdts);
    }
    let max_blocks = (max_bytes >> ns.block_bits) as u32;
    if max_blocks == 0 {
        return Err(DeviceError::Missing("transfers of at least one block"));
    }
    let info_out = Info { block_size: 1 << ns.block_bits, blocks: ns.blocks, read_only: ns.read_only, write_cache, max_blocks };
    println!(
        "nvme: {}: namespace {}, {} blocks of {} bytes, {} I/O entries, MSI-X {}, write cache {}, max {} blocks per request",
        core::str::from_utf8(&model).unwrap_or("?").trim_end(),
        ns.id,
        info_out.blocks,
        info_out.block_size,
        io_entries,
        if io_irq.is_some() { "0 and 1" } else { "0 only" },
        if write_cache { "on" } else { "off" },
        info_out.max_blocks,
    );

    let prp = dma.memory(bits_for(io_entries as usize * PRP_LIST_BYTES), false)?;
    let disk = Disk {
        dma,
        info: info_out,
        regs,
        nsid: ns.id,
        block_bits: ns.block_bits,
        prp_mem: prp.shared(),
        prp,
        tickets: (0..io_entries).map(|_| None).collect(),
        free: (0..io_entries).rev().collect(),
        unrung: false,
        io_bit,
        io,
        _admin: ctl.admin,
        _interrupts: (admin_irq, io_irq),
    };
    let mut service = Service::new(disk, signals.sender(CLIENT)?, silica_driver::granted(silica_driver::grant::SERVICE));
    silica_rt::ipc::serve_events(silica_driver::granted(silica_driver::grant::SERVICE), signals.listen(), &mut service)
}
