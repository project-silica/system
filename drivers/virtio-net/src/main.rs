//! The virtio network device driver (virtio 1.2, section 5.1).
//!
//! It provides `silica.net.Device` for its interface; everything common to
//! network interfaces is `silica_net::service`, and this file is what is
//! virtio's: the features, the configuration, the header in front of each
//! frame, and the two queues. Frames are never touched here: the device
//! reads what it sends from the client's memory and writes what it receives
//! into it, at the addresses the IOMMU gives it; the driver supplies only
//! the 12-byte header the device reads before a frame (a transmit's
//! offloads, one header per transmit slot) or writes before one it received.
//!
//! Features accepted: the device's address (`MAC`; without it the driver
//! makes a locally administered one from the device's identity), its MTU
//! (`MTU`; else 1500), the link's state (`STATUS`; else the link is taken to
//! be up), and the transmit offloads the class protocol carries: the
//! checksum (`CSUM`) and TCP over IPv4 segmentation (`HOST_TSO4`), each
//! offered to the client in `Info::offloads` only when negotiated. Nothing
//! on receive is offloaded yet, and one pair of queues. Receive queue:
//! MSI-X entry 0; transmit queue: 1;
//! configuration changes (the link): 2, or 0 when the device has fewer.
//!
//! A frame the device has not sent in [`TX_TIMEOUT_NS`] ends the driver, as
//! does a device that breaks the protocol; the device manager starts it
//! again, which resets the device, and the client offers its buffers and
//! frames again. Receive buffers wait for frames as long as it takes.
#![no_std]
#![no_main]

use silica_driver::dma::{Dma, DmaMemory, Shared};
#[cfg(feature = "harness")]
use silica_driver::inject;
use silica_driver::irq::{Interrupt, Signals};
use silica_driver::oldest::Oldest;
use silica_driver::virtio::{Buffer, Queue, Transport};
use silica_driver::{Device, DeviceError, grant, granted};
use silica_net::device::{Error, Info};
use silica_net::service::{CLIENT, Completions, Refusal, Service, Ticket};
use silica_net::{Op, Request, Status};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::serve_events;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

/// The device sums a frame's checksum when the header asks (NEEDS_CSUM).
const F_CSUM: u64 = 1 << 0;
const F_MTU: u64 = 1 << 3;
const F_MAC: u64 = 1 << 5;
/// The device cuts TCP over IPv4 frames (`gso_type` TCPV4; needs F_CSUM).
const F_HOST_TSO4: u64 = 1 << 11;
const F_STATUS: u64 = 1 << 16;
/// The header's flag: sum from `csum_start`, store at `csum_offset` past it.
const NEEDS_CSUM: u8 = 1;
const GSO_TCPV4: u8 = 1;
/// Where in `tx_headers` the header of zeros lies, after the slots' own
/// (at most 128 slots of 16 bytes), never written.
const ZERO_HEADER: usize = 2048;
/// The longest frame a segmentation request gives: an IPv4 packet's most.
const SEGMENT_BYTES: u32 = 65535 + silica_net::HEADER;
const S_LINK_UP: u16 = 1;
/// The header in front of every frame (`struct virtio_net_hdr`, with
/// `num_buffers`, as every virtio 1 device has it).
const HEADER: u32 = 12;
/// The notification bits of the receive queue, the transmit queue and
/// configuration changes.
const RX: u64 = 2;
const TX: u64 = 4;
const CONFIG: u64 = 8;
/// Descriptors in each queue; every request takes two.
const QUEUE_SIZE: u16 = 256;
/// How long the device may take to send a frame.
const TX_TIMEOUT_NS: u64 = 5_000_000_000;

struct Nic {
    transport: Transport,
    dma: Dma,
    rx: Queue,
    tx: Queue,
    /// A header per receive slot, which the device writes.
    rx_headers: DmaMemory,
    /// A header per transmit slot, which the device reads: the request's
    /// offloads, or zeros.
    tx_headers: DmaMemory,
    /// The request in each slot while the device has it (transmits with
    /// when they were started).
    rx_slots: Vec<Option<Ticket>>,
    tx_slots: Vec<Option<(Ticket, u64)>>,
    /// The oldest frame being sent, found without a walk.
    tx_oldest: Oldest,
    rx_free: Vec<u16>,
    tx_free: Vec<u16>,
    info: Info,
    status_feature: bool,
    _interrupts: Vec<Interrupt>,
}

impl Nic {
    /// The device cannot be relied on: end, so that the device manager
    /// resets it by starting the driver again. Nothing in flight is
    /// completed: the client offers it again to the next driver.
    fn give_up(&self, why: DeviceError) -> ! {
        println!("ERROR: virtio-net: {why:?}; giving up on the device");
        self.transport.fail();
        silica_rt::exit(2)
    }

    fn link_up(&self) -> bool {
        !self.status_feature || self.transport.device_config().is_some_and(|c| c.read16(6) & S_LINK_UP != 0)
    }
}

impl silica_net::service::Device for Nic {
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
        match r.op {
            Op::Receive => {
                let Some(slot) = self.rx_free.pop() else { return Err(Refusal::Busy) };
                let header = Buffer { address: self.rx_headers.device_address() + slot as u64 * 16, len: HEADER, device_writes: true };
                let data = Buffer { address, len: r.length, device_writes: true };
                if self.rx.add(&[header, data], slot as u64).is_err() {
                    self.rx_free.push(slot);
                    return Err(Refusal::Busy);
                }
                self.rx_slots[slot as usize] = Some(ticket);
            }
            Op::Transmit => {
                let Some(slot) = self.tx_free.pop() else { return Err(Refusal::Busy) };
                // struct virtio_net_hdr: flags, gso_type, hdr_len, gso_size,
                // csum_start, csum_offset (num_buffers is the device's).
                // The service checked the offloads against `info`, which
                // has only those negotiated.
                // A frame that asks nothing goes with the one header of
                // zeros every such frame shares (one line the device keeps
                // reading); one with offloads with its slot's own. (A header
                // per slot for every frame cost 2% of frames sent a second.)
                let o = r.offload;
                let at = if o == silica_net::Offload::NONE {
                    ZERO_HEADER
                } else {
                    let h = self.tx_headers.shared();
                    let at = slot as usize * 16;
                    let flags = if o.checksum { NEEDS_CSUM } else { 0 };
                    let gso = if o.segmentation { GSO_TCPV4 } else { 0 };
                    h.write32(at, u32::from(flags) | u32::from(gso) << 8 | u32::from(o.header_bytes) << 16);
                    h.write32(at + 4, u32::from(o.segment) | u32::from(o.checksum_start) << 16);
                    h.write32(at + 8, u32::from(o.checksum_offset));
                    at
                };
                let header = Buffer { address: self.tx_headers.device_address() + at as u64, len: HEADER, device_writes: false };
                let data = Buffer { address, len: r.length, device_writes: false };
                if self.tx.add(&[header, data], slot as u64).is_err() {
                    self.tx_free.push(slot);
                    return Err(Refusal::Busy);
                }
                let now = silica_rt::clock().now();
                self.tx_slots[slot as usize] = Some((ticket, now));
                let slots = &self.tx_slots;
                self.tx_oldest.started(slot as u32, now, slots.len(), |s, t| slots[s as usize].is_some_and(|(_, x)| x == t));
            }
        }
        Ok(())
    }

    fn holding(&self) -> usize {
        self.rx_slots.iter().flatten().count() + self.tx_slots.iter().flatten().count()
    }

    fn forget_client(&mut self) -> ! {
        // Virtio takes back buffers it was given only by resetting the
        // queue (RING_RESET, not taken) or the device.
        println!("virtio-net: its last client ended with {} requests in the device; starting again to take them back", self.holding());
        silica_rt::exit_again()
    }

    fn kick(&mut self) {
        self.rx.notify();
        self.tx.notify();
    }

    fn signals(&mut self, bits: u64, done: &mut Completions<'_>, link: &mut dyn FnMut(bool)) {
        loop {
            match self.rx.pop() {
                Ok(Some((token, written))) => {
                    let Some(ticket) = self.rx_slots.get_mut(token as usize).and_then(Option::take) else { continue };
                    self.rx_free.push(token as u16);
                    // The header, then the frame; anything shorter is no frame.
                    match written.checked_sub(HEADER) {
                        Some(n) if n >= silica_net::HEADER => done(ticket, Ok(n)),
                        _ => done(ticket, Err(Status::Io)),
                    }
                }
                Ok(None) => break,
                Err(e) => self.give_up(e),
            }
        }
        loop {
            match self.tx.pop() {
                Ok(Some((token, _))) => {
                    let Some((ticket, _)) = self.tx_slots.get_mut(token as usize).and_then(Option::take) else { continue };
                    self.tx_free.push(token as u16);
                    done(ticket, Ok(0));
                }
                Ok(None) => break,
                Err(e) => self.give_up(e),
            }
        }
        if bits & CONFIG != 0 {
            // A device that gave up asks to be reset this way too.
            if self.transport.needs_reset() {
                self.give_up(DeviceError::Protocol("the device asks to be reset"));
            }
            let up = self.link_up();
            if up != self.info.link_up {
                self.info.link_up = up;
                println!("virtio-net: link {}", if up { "up" } else { "down" });
                link(up);
            }
        }
    }

    fn deadline(&self) -> Option<u64> {
        let limit = silica_driver::io_limit(TX_TIMEOUT_NS);
        let slots = &self.tx_slots;
        self.tx_oldest.oldest(|s, t| slots[s as usize].is_some_and(|(_, x)| x == t)).map(|t| t + limit)
    }

    fn timeout(&mut self, done: &mut Completions<'_>) {
        // What the device finished without an interrupt, then the verdict.
        self.signals(0, done, &mut |_| {});
        if self.deadline().is_some_and(|d| d <= silica_rt::clock().now()) {
            self.give_up(DeviceError::Timeout("a frame the device never sent"));
        }
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: virtio-net: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
    let device = Device::take(info)?;
    let dma = Dma::new(&device)?;
    let transport = Transport::new(&device)?;
    let features = transport.negotiate(&dma, F_CSUM | F_HOST_TSO4 | F_MTU | F_MAC | F_STATUS, 0)?;
    let mut offloads = 0;
    if features & F_CSUM != 0 {
        offloads |= silica_net::OFFLOAD_CHECKSUM;
        if features & F_HOST_TSO4 != 0 {
            offloads |= silica_net::OFFLOAD_TCP4_SEGMENT;
        }
    }
    if transport.queues() < 2 {
        return Err(DeviceError::Missing("a receive and a transmit queue"));
    }
    let signals = Signals::new()?;
    let vectors = device.config().msix().map_or(0, |m| m.vectors) as u32;
    let lines = device.lines.end.saturating_sub(device.lines.start);
    let entries = vectors.min(lines);
    if entries == 0 {
        return Err(DeviceError::Missing("an interrupt"));
    }
    // One entry per queue and one for the link where there are three;
    // else everything on entry 0, its bits all set.
    let (rx_v, tx_v, cfg_v) = if entries >= 3 { (0, 1, 2) } else { (0, 0, 0) };
    let mut interrupts = Vec::new();
    if entries >= 3 {
        interrupts.push(Interrupt::bind_to(&device, 0, signals.sender(RX)?)?);
        interrupts.push(Interrupt::bind_to(&device, 1, signals.sender(TX)?)?);
        interrupts.push(Interrupt::bind_to(&device, 2, signals.sender(CONFIG)?)?);
    } else {
        interrupts.push(Interrupt::bind_to(&device, 0, signals.sender(RX | TX | CONFIG)?)?);
    }
    #[cfg(feature = "harness")]
    inject::interrupts(signals.sender(RX | TX)?);
    // A frame takes a header and its data: two descriptors each way.
    let mut rx = transport.queue(&dma, 0, QUEUE_SIZE, 2, Some(rx_v))?;
    let tx = transport.queue(&dma, 1, QUEUE_SIZE, 2, Some(tx_v))?;
    // A processor idling for a frame sees the device write it, without
    // waiting for the interrupt (spec/ARCHITECTURE.md section 7). Only where
    // the receive queue has an interrupt of its own (a shared one's news is
    // more than one queue's index). Sent frames are nobody's wait: watching
    // the transmit queue cost 2% of transmit throughput (2026-11-23).
    if entries >= 3
        && let Err(e) = rx.watch(&interrupts[0])
    {
        println!("virtio-net: completions wait for the interrupt alone: {e:?}");
    }
    // The link's changes, and a device asking to be reset (`needs_reset`).
    transport.config_interrupt(cfg_v)?;
    let config = transport.device_config().ok_or(DeviceError::Missing("the network device's configuration"))?;
    if config.len() < 12 {
        return Err(DeviceError::Protocol("the network device's configuration is too short"));
    }
    // Fields that belong together are read under one configuration generation.
    let (reported, mtu) = transport.read_config(|| {
        let reported = (features & F_MAC != 0).then(|| (0..6).fold(0u64, |a, i| a | (config.read8(i) as u64) << (8 * i)));
        let mtu = if features & F_MTU != 0 { config.read16(10) as u32 } else { 1500 };
        (reported, mtu)
    })?;
    // An address the device reports that no interface may have
    // (multicast, zeros) is not used (`silica_driver::mac`).
    let address = match reported {
        Some(a) if silica_driver::mac::usable(a) => a,
        Some(a) => {
            let local = silica_driver::mac::local(device.id);
            println!(
                "virtio-net: the device's address {} is multicast or zero; the interface uses {}",
                silica_driver::mac::Shown(a),
                silica_driver::mac::Shown(local)
            );
            local
        }
        None => silica_driver::mac::local(device.id),
    };
    if !(68..=65535).contains(&mtu) {
        return Err(DeviceError::Protocol("an MTU below 68 or above 65535"));
    }
    let rx_count = (rx.size() / 2) as usize;
    let tx_count = (tx.size() / 2) as usize;
    let mut nic = Nic {
        rx_headers: dma.memory(12, true)?,
        // 16 bytes a transmit slot, at most 128 slots: one page.
        tx_headers: dma.memory(12, false)?,
        rx_slots: (0..rx_count).map(|_| None).collect(),
        tx_slots: (0..tx_count).map(|_| None).collect(),
        tx_oldest: Oldest::for_slots(tx_count)?,
        rx_free: (0..rx_count as u16).rev().collect(),
        tx_free: (0..tx_count as u16).rev().collect(),
        // (Each receive descriptor bounds what the device writes: a buffer
        // the size of the largest frame is enough.)
        info: Info {
            address,
            mtu,
            link_up: true,
            receive_bytes: mtu + silica_net::HEADER,
            offloads,
            segment_bytes: if offloads & silica_net::OFFLOAD_TCP4_SEGMENT != 0 { SEGMENT_BYTES } else { 0 },
        },
        status_feature: features & F_STATUS != 0,
        transport,
        dma,
        rx,
        tx,
        _interrupts: interrupts,
    };
    nic.transport.start();
    nic.info.link_up = nic.link_up();
    let a = address.to_le_bytes();
    println!(
        "virtio-net: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, MTU {mtu}, link {}, DMA {}",
        a[0],
        a[1],
        a[2],
        a[3],
        a[4],
        a[5],
        if nic.info.link_up { "up" } else { "down" },
        if nic.dma.confined() { "confined by the IOMMU" } else { "not confined" },
    );
    let mut service = Service::new(nic, signals.sender(CLIENT)?);
    serve_events(granted(grant::SERVICE), signals.listen(), &mut service)
}
