//! The virtio console driver (virtio 1.2, section 5.3): port 0, without
//! the multiport feature, as a virtual machine's host offers its console.
//!
//! It provides `silica.console.Port`. The device fills buffers the driver
//! keeps offered on the receive queue; what arrives goes into the client's
//! ring (8-byte records), or is held (at most [`HELD`] bytes) until a client
//! connects. `write` puts the bytes in transmit buffers and answers once the
//! device has taken them, or `stalled` after [`WAIT_NS`]. The bytes are the
//! host's: nothing here looks at them.
//!
//! A device that breaks a queue's protocol ends the driver; the device
//! manager starts another, which resets it.
#![no_std]
#![no_main]

use silica_driver::dma::{Dma, DmaMemory};
use silica_driver::irq::{Interrupt, Signals};
use silica_driver::virtio::{Buffer, Queue, Transport};
use silica_driver::{Device, DeviceError, grant, granted};
use silica_idl_rt::CapList;
use silica_protocols::console::port::{self, ConnectReply, Error, WriteReply};
use silica_ring::Producer;
use silica_rt::alloc::collections::VecDeque;
use silica_rt::ipc::{Events, Handle, serve_events};
use silica_rt::sys::{self, ObjectType, Rights};
use silica_rt::{ProcessInfo, mem, println, slots};

silica_rt::main!(main);

/// The notification bit of the queues' interrupt.
const INTERRUPT: u64 = 2;
/// Receive buffers kept with the device, of [`RX_BYTES`] each (one page).
const RX_BUFFERS: u16 = 16;
const RX_BYTES: u32 = 256;
/// Transmit buffers, of [`TX_BYTES`] each (one page).
const TX_BUFFERS: usize = 2;
const TX_BYTES: usize = 2048;
/// Bytes held until a client connects.
const HELD: usize = 4096;
/// Records in the client's ring.
const RING: u32 = 256;
/// How long the device has to take what is written.
const WAIT_NS: u64 = 1_000_000_000;

struct Port {
    rx: Queue,
    rx_mem: DmaMemory,
    tx: Queue,
    tx_mem: DmaMemory,
    tx_busy: [bool; TX_BUFFERS],
    /// The client's ring and what to signal, once connected.
    client: Option<(Handle, Producer<8>, Handle)>,
    /// Where the client's ring is mapped: let go of with the client.
    mapped: Option<mem::Lent>,
    held: VecDeque<u8>,
    _interrupt: Interrupt,
}

/// The device cannot be relied on: end, so that the device manager starts
/// a driver again, which resets it.
fn give_up(why: DeviceError) -> ! {
    println!("ERROR: virtio-console: {why:?}; giving up on the device");
    silica_rt::exit(2)
}

impl Port {
    fn offer(&mut self, slot: u16) {
        let b = Buffer { address: self.rx_mem.device_address() + slot as u64 * RX_BYTES as u64, len: RX_BYTES, device_writes: true };
        let _ = self.rx.add(&[b], slot as u64);
    }

    /// Bytes that arrived: into the client's ring, or held. Returns whether
    /// records were added.
    fn deliver(&mut self, bytes: &[u8]) -> bool {
        let Some((_, ring, _)) = &mut self.client else {
            let room = HELD - self.held.len();
            self.held.extend(bytes.iter().take(room));
            return false;
        };
        let mut added = false;
        for chunk in bytes.chunks(7) {
            let mut r = [0u8; 8];
            r[0] = chunk.len() as u8;
            r[1..1 + chunk.len()].copy_from_slice(chunk);
            // A client that does not keep up loses the newest bytes.
            added |= ring.push(&r).is_ok();
        }
        added
    }

    /// Transmit buffers the device has finished with are free again.
    fn reap(&mut self) {
        loop {
            match self.tx.pop() {
                Ok(Some((slot, _))) => {
                    if let Some(b) = self.tx_busy.get_mut(slot as usize) {
                        *b = false;
                    }
                }
                Ok(None) => return,
                Err(e) => give_up(e),
            }
        }
    }

    /// Wait until transmit buffer `slot` is free, or `stalled`.
    fn free(&mut self, slot: usize) -> Result<(), Error> {
        let deadline = silica_rt::clock().now() + WAIT_NS;
        loop {
            self.reap();
            if !self.tx_busy[slot] {
                return Ok(());
            }
            if silica_rt::clock().now() > deadline {
                return Err(Error::Stalled);
            }
            sys::yield_now();
        }
    }
}

impl port::Server<Handle> for Port {
    fn connect(&mut self, ring: Handle, arrived: Handle) -> Result<ConnectReply, Error> {
        // One client: another may take over only once it has gone (its
        // ring's capability goes with it).
        if self.client.as_ref().is_some_and(|(r, _, _)| matches!(sys::inspect_slot(slots::SPACE, r.cap().0), Ok(Some(_)))) {
            return Err(Error::InUse);
        }
        match sys::inspect_slot(slots::SPACE, ring.cap().0) {
            Ok(Some(s)) if s.ty == ObjectType::Frame && s.bits == 12 && s.rights.has(Rights(3)) => {}
            _ => return Err(Error::BadMemory),
        }
        // Where lent memory goes: memory the client takes back reads as zeros.
        let mapped = mem::Lent::map(ring.cap(), 12, Rights(3)).map_err(|_| Error::BadMemory)?;
        let producer = Producer::new(mapped.region(), RING).ok_or(Error::BadMemory)?;
        self.client = Some((ring, producer, arrived));
        self.mapped = Some(mapped);
        let held: silica_rt::alloc::vec::Vec<u8> = self.held.drain(..).collect();
        if self.deliver(&held)
            && let Some((_, ring, arrived)) = &self.client
            && ring.wake_needed()
        {
            let _ = sys::signal(arrived.cap());
        }
        Ok(ConnectReply {})
    }

    fn write(&mut self, data: &[u8]) -> Result<WriteReply, Error> {
        let mut last = None;
        for (n, chunk) in data.chunks(TX_BYTES).enumerate() {
            let slot = n % TX_BUFFERS;
            self.free(slot)?;
            let m = self.tx_mem.shared();
            for (i, b) in chunk.iter().enumerate() {
                m.write8(slot * TX_BYTES + i, *b);
            }
            let b =
                Buffer { address: self.tx_mem.device_address() + (slot * TX_BYTES) as u64, len: chunk.len() as u32, device_writes: false };
            if self.tx.add(&[b], slot as u64).is_err() {
                give_up(DeviceError::Protocol("no room in the transmit queue for a free buffer"));
            }
            self.tx_busy[slot] = true;
            self.tx.notify();
            last = Some(slot);
        }
        if let Some(slot) = last {
            self.free(slot)?;
        }
        Ok(WriteReply {})
    }
}

impl Events for Port {
    fn call(&mut self, _badge: u64, request: &[u8], caps: CapList<Handle>, reply: &mut [u8], reply_caps: &mut CapList<Handle>) -> usize {
        port::dispatch(self, request, caps, reply, reply_caps)
    }

    fn signals(&mut self, _bits: u64) {
        self.reap();
        let mut added = false;
        let mut buf = [0u8; RX_BYTES as usize];
        loop {
            let (slot, n) = match self.rx.pop() {
                Ok(Some((slot, n))) => (slot as u16, n as usize),
                Ok(None) => break,
                Err(e) => give_up(e),
            };
            let m = self.rx_mem.shared();
            for (i, b) in buf.iter_mut().enumerate().take(n) {
                *b = m.read8(slot as usize * RX_BYTES as usize + i);
            }
            added |= self.deliver(&buf[..n]);
            self.offer(slot);
        }
        self.rx.notify();
        if added
            && let Some((_, ring, arrived)) = &self.client
            && ring.wake_needed()
        {
            let _ = sys::signal(arrived.cap());
        }
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: virtio-console: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
    let device = Device::take(info)?;
    let dma = Dma::new(&device)?;
    let transport = Transport::new(&device)?;
    transport.negotiate(&dma, 0, 0)?;
    let signals = Signals::new()?;
    let interrupt = Interrupt::bind_to(&device, 0, signals.sender(INTERRUPT)?)?;
    let rx = transport.queue(&dma, 0, RX_BUFFERS, Some(0))?;
    let tx = transport.queue(&dma, 1, TX_BUFFERS as u16, Some(0))?;
    let (rx_mem, tx_mem) = (dma.memory(12, true)?, dma.memory(12, false)?);
    let mut port =
        Port { rx, rx_mem, tx, tx_mem, tx_busy: [false; TX_BUFFERS], client: None, mapped: None, held: VecDeque::new(), _interrupt: interrupt };
    for slot in 0..RX_BUFFERS.min(port.rx.size()) {
        port.offer(slot);
    }
    transport.start();
    port.rx.notify();
    println!("virtio-console: port 0, {}", if dma.confined() { "DMA confined by the IOMMU" } else { "DMA not confined" });
    serve_events(granted(grant::SERVICE), signals.listen(), &mut port)
}
