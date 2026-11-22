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
#![no_std]
#![no_main]

use silica_block::device::{Error, Info};
use silica_block::service::{Busy, CLIENT, Completions, Service, Ticket};
use silica_block::{Op, Request, Status};
use silica_driver::dma::{Dma, DmaMemory, Shared};
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
/// Descriptors in the queue, and so requests in flight at most a third of that.
const QUEUE_SIZE: u16 = 256;
/// Most bytes in one request.
const MAX_BYTES: u32 = 1 << 20;

struct Disk {
    transport: Transport,
    dma: Dma,
    queue: Queue,
    _interrupt: Interrupt,
    /// A 16-byte header per request slot: the device reads them.
    headers: DmaMemory,
    /// A status byte per request slot: the device writes them.
    status: DmaMemory,
    /// The request in each slot while the device has it.
    slots: Vec<Option<Ticket>>,
    free: Vec<u16>,
    info: Info,
    /// 512-byte sectors in a block.
    sectors_per_block: u64,
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

    fn start(&mut self, r: &Request, address: u64, ticket: Ticket) -> Result<(), Busy> {
        if self.queue.room() < 3 {
            return Err(Busy);
        }
        let Some(slot) = self.free.pop() else { return Err(Busy) };
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
            return Err(Busy);
        }
        self.slots[at] = Some(ticket);
        Ok(())
    }

    fn kick(&mut self) {
        self.queue.notify();
    }

    fn signals(&mut self, _bits: u64, done: &mut Completions<'_>) {
        loop {
            match self.queue.pop() {
                Ok(Some((token, _))) => {
                    let Some(ticket) = self.slots.get_mut(token as usize).and_then(Option::take) else { continue };
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
                Ok(None) => return,
                Err(e) => {
                    // The device broke the protocol: nothing it says can be
                    // relied on. Everything in flight is given up, and the
                    // driver ends; the device manager starts a new one,
                    // which resets the device.
                    println!("ERROR: virtio-blk: {e:?}; giving up on the device");
                    for ticket in self.slots.iter_mut().filter_map(Option::take) {
                        done(ticket, Err(Status::Aborted));
                    }
                    self.transport.fail();
                    silica_rt::exit(2);
                }
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
    let queue = transport.queue(&dma, 0, QUEUE_SIZE, Some(0))?;
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
    let mut service = Service::new(disk, signals.sender(CLIENT)?);
    serve_events(granted(grant::SERVICE), signals.listen(), &mut service)
}
