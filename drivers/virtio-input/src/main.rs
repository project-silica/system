//! The virtio input device driver (virtio 1.2, section 5.8), for keyboards.
//!
//! It provides `silica.input.Device`: each key pressed or released goes
//! into the client's ring as its USB HID usage. virtio input devices speak
//! Linux's event codes; those are translated here, once, so nothing above
//! the driver knows them. Events other than keys (and key repeats, which a
//! client makes itself if it wants them) are dropped.
#![no_std]
#![no_main]

mod keys;

use silica_driver::dma::{Dma, DmaMemory};
use silica_driver::irq::{Interrupt, Signals};
use silica_driver::virtio::{Buffer, Queue, Transport};
use silica_driver::{Device, DeviceError, grant, granted};
use silica_idl_rt::CapList;
use silica_protocols::input::device::{self, ConnectReply, DescribeReply, Error, Kind};
use silica_ring::Producer;
use silica_rt::ipc::{Events, Handle, serve_events};
use silica_rt::sys::{self, ObjectType, Rights};
use silica_rt::{ProcessInfo, mem, println, slots};

silica_rt::main!(main);

/// The notification bit of the event queue's interrupt.
const INTERRUPT: u64 = 2;
/// Event buffers kept with the device.
const BUFFERS: u16 = 64;
/// Records in the client's ring.
const RING: u32 = 256;
/// Key records kept while no client is connected: what is typed before the
/// console has attached (at boot, typed by a test or a person who did not
/// wait for the prompt) is given to it when it does.
const EARLY: usize = 64;
const EV_KEY: u16 = 1;

struct Keyboard {
    queue: Queue,
    /// One 8-byte event per buffer, written by the device.
    events: DmaMemory,
    name: [u8; 64],
    name_len: usize,
    /// The client's ring and what to signal, once connected.
    client: Option<(Handle, Producer<8>, Handle)>,
    /// Keys that came before any client, oldest first.
    early: [[u8; 8]; EARLY],
    early_len: usize,
    _interrupt: Interrupt,
}

impl device::Server<Handle> for Keyboard {
    fn describe<'a>(&'a mut self) -> DescribeReply<'a> {
        DescribeReply { kind: Kind::Keyboard, name: core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("keyboard") }
    }

    fn connect(&mut self, ring: Handle, events: Handle) -> Result<ConnectReply, Error> {
        match sys::inspect_slot(slots::SPACE, ring.cap().0) {
            Ok(Some(s)) if s.ty == ObjectType::Frame && s.bits == 12 && s.rights.has(Rights(3)) => {}
            _ => return Err(Error::BadMemory),
        }
        // Where lent memory goes: memory the client takes back reads as zeros.
        let region = mem::peer(ring.cap(), 12, Rights(3)).map_err(|_| Error::BadMemory)?;
        let mut producer = Producer::new(region, RING).ok_or(Error::BadMemory)?;
        // What was typed before anyone listened goes first, in order.
        let mut added = false;
        for record in &self.early[..self.early_len] {
            added |= producer.push(record).is_ok();
        }
        self.early_len = 0;
        if added && producer.wake_needed() {
            let _ = sys::signal(events.cap());
        }
        self.client = Some((ring, producer, events));
        Ok(ConnectReply {})
    }
}

impl Keyboard {
    fn offer(&mut self, slot: u16) {
        let b = Buffer { address: self.events.device_address() + slot as u64 * 8, len: 8, device_writes: true };
        let _ = self.queue.add(&[b], slot as u64);
    }
}

impl Events for Keyboard {
    fn call(&mut self, _badge: u64, request: &[u8], caps: CapList<Handle>, reply: &mut [u8], reply_caps: &mut CapList<Handle>) -> usize {
        device::dispatch(self, request, caps, reply, reply_caps)
    }

    fn signals(&mut self, _bits: u64) {
        let mut added = false;
        loop {
            let (slot, written) = match self.queue.pop() {
                Ok(Some(done)) => done,
                Ok(None) => break,
                Err(e) => {
                    println!("ERROR: virtio-input: {e:?}; giving up on the device");
                    silica_rt::exit(2);
                }
            };
            let Ok(slot) = u16::try_from(slot) else { continue };
            if slot >= BUFFERS {
                continue;
            }
            let e = self.events.shared();
            let (kind, code, value) = (e.read16(slot as usize * 8), e.read16(slot as usize * 8 + 2), e.read32(slot as usize * 8 + 4));
            self.offer(slot);
            if written < 8 || kind != EV_KEY || value > 1 {
                continue;
            }
            let Some(usage) = keys::usage(code) else { continue };
            let mut record = [0u8; 8];
            record[..2].copy_from_slice(&usage.to_le_bytes());
            record[2] = value as u8;
            // A client that does not keep up loses the newest keys, and so
            // do keys typed before there is one, past the first EARLY.
            if let Some((_, ring, _)) = &mut self.client {
                added |= ring.push(&record).is_ok();
            } else if self.early_len < EARLY {
                self.early[self.early_len] = record;
                self.early_len += 1;
            }
        }
        self.queue.notify();
        if added
            && let Some((_, ring, events)) = &self.client
            && ring.wake_needed()
        {
            let _ = sys::signal(events.cap());
        }
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: virtio-input: {e:?}");
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
    let queue = transport.queue(&dma, 0, BUFFERS, Some(0))?;
    // The device's name: select 1 (ID_NAME), the string at byte 8.
    let mut name = [0u8; 64];
    let mut name_len = 0;
    if let Some(config) = transport.device_config().filter(|c| c.len() >= 136) {
        config.write8(0, 1);
        config.write8(1, 0);
        name_len = (config.read8(2) as usize).min(name.len());
        for (i, b) in name.iter_mut().enumerate().take(name_len) {
            *b = config.read8(8 + i);
        }
    }
    let events = dma.memory(12, true)?;
    let mut keyboard =
        Keyboard { queue, events, name, name_len, client: None, early: [[0; 8]; EARLY], early_len: 0, _interrupt: interrupt };
    for slot in 0..BUFFERS.min(keyboard.queue.size()) {
        keyboard.offer(slot);
    }
    transport.start();
    keyboard.queue.notify();
    println!("virtio-input: {}", core::str::from_utf8(&keyboard.name[..keyboard.name_len]).unwrap_or("a keyboard"));
    serve_events(granted(grant::SERVICE), signals.listen(), &mut keyboard)
}
