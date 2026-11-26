//! The virtio block device driver (virtio 1.2, section 5.2).
//!
//! It provides `silica.block.Device` for its disk. Everything common to
//! block devices is `silica_block::service`; this file is what is virtio's:
//! the features, the device's configuration, the layout of a request, and
//! what a completion looks like. A request's data is never touched or
//! mapped here: the device reads and writes the client's frames directly,
//! at the addresses the IOMMU gives it for them.
//!
//! Features accepted, and what the driver does about each: read-only
//! devices (`RO`: writes are refused before they reach the device), the
//! logical block size (`BLK_SIZE`: requests are in those blocks), a
//! volatile write cache (`FLUSH`: flush requests are passed on). Requests
//! have one data buffer, so the device's segment limits never apply, and
//! at most 1 MiB, the largest a request of this protocol may be here.
//! Verified against QEMU's virtio-blk-pci device model only.
//!
//! A request the device has not finished in [`IO_TIMEOUT_NS`] (Linux's
//! default too) is looked for once more (its interrupt may have been lost);
//! if it is still not done, the driver ends and the device manager starts
//! it again, which resets the device. A device that breaks the protocol
//! ends it the same way. Either way the requests in flight are left to the
//! client, which sends them again to the next driver.
#![no_std]
#![no_main]

use silica_block::device::{Error, Info};
use silica_block::service::{CLIENT, Completions, Refusal, Service, Ticket};
use silica_block::{Op, Request, Status};
use silica_driver::dma::{Dma, DmaMemory, Shared};
use silica_driver::inject;
use silica_driver::irq::{Interrupt, Signals};
use silica_driver::virtio::{Buffer, Queue, Transport};
use silica_driver::{Device, DeviceError, grant, granted};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::serve_events;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

const F_RO: u64 = 1 << 5;
const F_BLK_SIZE: u64 = 1 << 6;
const F_FLUSH: u64 = 1 << 9;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
/// The notification bit of the queue's interrupt.
const INTERRUPT: u64 = 2;
/// The notification bit of the configuration interrupt (when it has its own
/// entry: `Transport::config_vector`).
const CONFIG: u64 = 4;
/// Descriptors in the queue, and so requests in flight at most a third of that.
const QUEUE_SIZE: u16 = 256;
/// Most bytes in one request.
const MAX_BYTES: u32 = 1 << 20;
/// How long the device may take over a request.
const IO_TIMEOUT_NS: u64 = 30_000_000_000;

struct Disk {
    transport: Transport,
    dma: Dma,
    queue: Queue,
    _interrupt: Interrupt,
    _config: Option<Interrupt>,
    /// The configuration interrupt shares the queue's.
    config_shared: bool,
    /// A 16-byte header per request slot: the device reads them.
    headers: DmaMemory,
    /// A status byte per request slot: the device writes them.
    status: DmaMemory,
    /// The request in each slot while the device has it, and when it was
    /// started.
    slots: Vec<Option<(Ticket, u64)>>,
    free: Vec<u16>,
    info: Info,
    /// 512-byte sectors in a block.
    sectors_per_block: u64,
}

impl Disk {
    /// The device cannot be relied on: end, so that the device manager
    /// resets it by starting the driver again. Nothing in flight is
    /// completed: the client sends it again to the next driver.
    fn give_up(&self, why: DeviceError) -> ! {
        println!("ERROR: virtio-blk: {why:?}; giving up on the device");
        self.transport.fail();
        silica_rt::exit(2)
    }

    fn timeout_ns() -> u64 {
        if inject::armed() { inject::ARMED_TIMEOUT_NS } else { IO_TIMEOUT_NS }
    }
}

impl silica_block::service::Device for Disk {
    type Mapping = Shared;

    fn info(&self) -> Info {
        self.info.clone()
    }

    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, Shared), Error> {
        let shared = self.dma.share(frame, bits, writable).map_err(|_| Error::NoRoom)?;
        Ok((shared.address, shared))
    }

    fn unmap(&mut self, mapping: Shared) {
        self.dma.unshare(mapping);
    }

    fn start(&mut self, r: &Request, address: u64, ticket: Ticket) -> Result<(), Refusal> {
        if self.queue.room() < 3 {
            return Err(Refusal::Busy);
        }
        let Some(slot) = self.free.pop() else { return Err(Refusal::Busy) };
        let at = slot as usize;
        let (header, status) = (self.headers.shared(), self.status.shared());
        header.write32(
            at * 16,
            match r.op {
                Op::Read => T_IN,
                Op::Write => T_OUT,
                Op::Flush => T_FLUSH,
            },
        );
        header.write32(at * 16 + 4, 0);
        header.write64(at * 16 + 8, r.block * self.sectors_per_block);
        status.write8(at, 0xFF);
        let head = Buffer { address: self.headers.device_address() + at as u64 * 16, len: 16, device_writes: false };
        let data = Buffer { address, len: r.blocks * self.info.block_size, device_writes: r.op == Op::Read };
        let tail = Buffer { address: self.status.device_address() + at as u64, len: 1, device_writes: true };
        let added =
            if r.op == Op::Flush { self.queue.add(&[head, tail], slot as u64) } else { self.queue.add(&[head, data, tail], slot as u64) };
        if added.is_err() {
            self.free.push(slot);
            return Err(Refusal::Busy);
        }
        self.slots[at] = Some((ticket, silica_rt::clock().now()));
        Ok(())
    }

    fn kick(&mut self) {
        self.queue.notify();
    }

    fn deadline(&self) -> Option<u64> {
        self.slots.iter().flatten().map(|(_, t)| t + Disk::timeout_ns()).min()
    }

    fn timeout(&mut self, done: &mut Completions<'_>) {
        // What the device finished without an interrupt, then the verdict.
        self.signals(INTERRUPT, done);
        if self.deadline().is_some_and(|d| d <= silica_rt::clock().now()) {
            self.give_up(DeviceError::Timeout("a request the device never finished"));
        }
    }

    fn signals(&mut self, bits: u64, done: &mut Completions<'_>) {
        // A device that gave up asks to be reset with a configuration
        // interrupt (on the queue's entry when it has no other: then an
        // interrupt that brings no completion is asked about).
        if bits & CONFIG != 0 && self.transport.needs_reset() {
            self.give_up(DeviceError::Protocol("the device asks to be reset"));
        }
        let mut any = false;
        loop {
            match self.queue.pop() {
                Ok(Some((token, _))) => {
                    any = true;
                    let Some((ticket, _)) = self.slots.get_mut(token as usize).and_then(Option::take) else { continue };
                    self.free.push(token as u16);
                    done(
                        ticket,
                        match self.status.shared().read8(token as usize) {
                            0 => Ok(()),
                            2 => Err(Status::Invalid),
                            _ => Err(Status::Io),
                        },
                    );
                }
                Ok(None) => {
                    if !any && self.config_shared && bits & INTERRUPT != 0 && self.transport.needs_reset() {
                        self.give_up(DeviceError::Protocol("the device asks to be reset"));
                    }
                    return;
                }
                Err(e) => self.give_up(e),
            }
        }
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: virtio-blk: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
    let device = Device::take(info)?;
    let dma = Dma::new(&device)?;
    let transport = Transport::new(&device)?;
    let features = transport.negotiate(&dma, F_RO | F_BLK_SIZE | F_FLUSH, 0)?;
    let signals = Signals::new()?;
    let interrupt = Interrupt::bind_to(&device, 0, signals.sender(INTERRUPT)?)?;
    inject::interrupts(signals.sender(INTERRUPT)?);
    // A request is a header, its data and a status byte.
    let mut queue = transport.queue(&dma, 0, QUEUE_SIZE, 3, Some(0))?;
    let config_vector = Transport::config_vector(&device, 1);
    let config_irq = if config_vector != 0 { Some(Interrupt::bind_to(&device, config_vector, signals.sender(CONFIG)?)?) } else { None };
    transport.config_interrupt(config_vector)?;
    // A processor idling for a completion sees the device write it, without
    // waiting for the interrupt to arrive (spec/ARCHITECTURE.md section 7).
    if let Err(e) = queue.watch(&interrupt) {
        println!("virtio-blk: completions wait for the interrupt alone: {e:?}");
    }
    let config = transport.device_config().ok_or(DeviceError::Missing("the block device's configuration"))?;
    if config.len() < 24 {
        return Err(DeviceError::Protocol("the block device's configuration is too short"));
    }
    // Fields that belong together are read under one configuration generation.
    let (sectors, block_size) = loop {
        let before = transport.config_generation();
        let sectors = config.read32(0) as u64 | (config.read32(4) as u64) << 32;
        let block_size = if features & F_BLK_SIZE != 0 { config.read32(20) } else { 512 };
        if transport.config_generation() == before {
            break (sectors, block_size);
        }
    };
    if !block_size.is_power_of_two() || !(512..=65536).contains(&block_size) {
        return Err(DeviceError::Protocol("a block size that is not a power of two from 512 bytes to 64 KiB"));
    }
    let sectors_per_block = (block_size / 512) as u64;
    let slots = (queue.size() / 3) as usize;
    let disk = Disk {
        headers: dma.memory(12, false)?,
        status: dma.memory(12, true)?,
        slots: (0..slots).map(|_| None).collect(),
        free: (0..slots as u16).rev().collect(),
        info: Info {
            block_size,
            blocks: sectors / sectors_per_block,
            read_only: features & F_RO != 0,
            write_cache: features & F_FLUSH != 0,
            max_blocks: MAX_BYTES / block_size,
        },
        sectors_per_block,
        transport,
        dma,
        queue,
        _interrupt: interrupt,
        _config: config_irq,
        config_shared: config_vector == 0,
    };
    disk.transport.start();
    println!(
        "virtio-blk: {} blocks of {} bytes{}{}, DMA {}",
        disk.info.blocks,
        block_size,
        if disk.info.read_only { ", read-only" } else { "" },
        if disk.info.write_cache { ", write cache" } else { "" },
        if disk.dma.confined() { "confined by the IOMMU" } else { "not confined" },
    );
    let mut service = Service::new(disk, signals.sender(CLIENT)?, silica_driver::granted(silica_driver::grant::SERVICE));
    serve_events(granted(grant::SERVICE), signals.listen(), &mut service)
}
