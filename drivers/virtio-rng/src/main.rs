//! The virtio entropy device driver (virtio 1.2, section 5.4): one queue,
//! whose buffers the device fills with random bytes.
//!
//! It provides `silica.entropy.Device` to the entropy service. Each `read`
//! offers the device one buffer of the size asked (at most 256 bytes) and
//! answers with what the device wrote into it, which may be less; the
//! queue never believes a length past the buffer (`silica_driver::virtio`).
//! The bytes are not tested or conditioned here: the entropy service mixes
//! them into what it has, so a device that lies weakens nothing.
//!
//! A device that does not answer within [`WAIT_NS`], or breaks the queue's
//! protocol, ends the driver: the device manager starts another, which
//! resets the device, and the caller's `read` fails (`peer_gone`).
#![no_std]
#![no_main]

use silica_driver::dma::{Dma, DmaMemory};
use silica_driver::irq::Interrupt;
use silica_driver::virtio::{Buffer, Queue, Transport};
use silica_driver::{Device, DeviceError, grant, granted};
use silica_idl_rt::CapList;
use silica_protocols::entropy::device::{self, Error, ReadReply};
use silica_rt::ipc::{Handle, serve};
use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

/// The most bytes one read gives.
const MOST: u32 = 256;
/// How long the device has to fill a buffer.
const WAIT_NS: u64 = 1_000_000_000;

struct Rng {
    queue: Queue,
    /// The buffer the device writes (one page; the first [`MOST`] bytes).
    buffer: DmaMemory,
    interrupt: Interrupt,
    transport: Transport,
    /// The bytes answered, copied out of the device's buffer.
    out: [u8; MOST as usize],
}

/// The device cannot be relied on: end, so that the device manager starts
/// a driver again, which resets it.
fn give_up(why: DeviceError) -> ! {
    println!("ERROR: virtio-rng: {why:?}; giving up on the device");
    silica_rt::exit(2)
}

impl device::Server<Handle> for Rng {
    fn read<'a>(&'a mut self, count: u32) -> Result<ReadReply<'a>, Error> {
        let n = count.min(MOST);
        if n == 0 {
            return Ok(ReadReply { data: &[] });
        }
        let b = Buffer { address: self.buffer.device_address(), len: n, device_writes: true };
        // One request at a time: the queue is empty when a read starts.
        if self.queue.add(&[b], 0).is_err() {
            give_up(DeviceError::Protocol("the queue is full with nothing in it"));
        }
        self.queue.notify();
        let deadline = silica_rt::clock().now() + WAIT_NS;
        loop {
            match self.queue.pop() {
                Ok(Some((_, written))) => {
                    let m = self.buffer.shared();
                    for (i, byte) in self.out.iter_mut().enumerate().take(written as usize) {
                        *byte = m.read8(i);
                    }
                    return Ok(ReadReply { data: &self.out[..written as usize] });
                }
                Ok(None) => {
                    // A device that gave up asks to be reset (its configuration
                    // interrupt is the queue's): it fills nothing now.
                    if self.transport.needs_reset() {
                        self.transport.fail();
                        give_up(DeviceError::Protocol("the device asks to be reset"));
                    }
                    if !self.interrupt.wait(Some(deadline)) {
                        give_up(DeviceError::Timeout("the device filled no buffer"));
                    }
                }
                Err(e) => give_up(e),
            }
        }
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: virtio-rng: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
    let device = Device::take(info)?;
    let dma = Dma::new(&device)?;
    let transport = Transport::new(&device)?;
    transport.negotiate(&dma, 0, 0)?;
    let interrupt = Interrupt::bind(&device, 0)?;
    let queue = transport.queue(&dma, 0, 8, 1, Some(0))?;
    transport.config_interrupt(0)?;
    let buffer = dma.memory(12, true)?;
    transport.start();
    println!("virtio-rng: an entropy source, {}", if dma.confined() { "DMA confined by the IOMMU" } else { "DMA not confined" });
    let mut rng = Rng { queue, buffer, interrupt, transport, out: [0; MOST as usize] };
    serve(granted(grant::SERVICE), |_badge, request, caps: CapList<Handle>, reply, reply_caps| {
        device::dispatch(&mut rng, request, caps, reply, reply_caps)
    })
}
