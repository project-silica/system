//! The virtio block device driver (virtio 1.2, section 5.2).
//!
//! At this stage it brings its device up and proves the whole path under
//! it: the device confined to the memory the driver maps for it, a request
//! through the virtqueue, the completion arriving as a message interrupt.
//! It reads the disk's second sector, where a GPT disk says so. The block
//! class protocol its clients will call comes next.
#![no_std]
#![no_main]

use silica_driver::dma::Dma;
use silica_driver::irq::Interrupt;
use silica_driver::virtio::{Buffer, Transport};
use silica_driver::{Device, DeviceError};
use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

/// Request type: read.
const T_IN: u32 = 0;
/// How long the device gets for one request.
const REQUEST_NS: u64 = 5_000_000_000;

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(()) => 0,
        Err(e) => {
            println!("ERROR: virtio-blk: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<(), DeviceError> {
    let device = Device::take(info)?;
    let dma = Dma::new(&device)?;
    let transport = Transport::new(&device)?;
    transport.negotiate(&dma, 0, 0)?;
    let interrupt = Interrupt::bind(&device, 0)?;
    let mut queue = transport.queue(&dma, 0, 256, Some(0))?;
    transport.start();
    let config = transport.device_config().ok_or(DeviceError::Missing("the block device's configuration"))?;
    if config.len() < 8 {
        return Err(DeviceError::Protocol("the block device's configuration is too short for a capacity"));
    }
    let sectors = config.read32(0) as u64 | (config.read32(4) as u64) << 32;

    // One request: the header, a sector of data, the status byte.
    let memory = dma.memory(13, true)?;
    let (m, base) = (memory.shared(), memory.device_address());
    m.write32(0, T_IN);
    m.write32(4, 0);
    m.write64(8, 1);
    m.write8(16, 0xFF);
    let request = [
        Buffer { address: base, len: 16, device_writes: false },
        Buffer { address: base + 4096, len: 512, device_writes: true },
        Buffer { address: base + 16, len: 1, device_writes: true },
    ];
    queue.add(&request, 1).map_err(|_| DeviceError::Protocol("an empty queue has no room for one request"))?;
    queue.notify();
    let deadline = silica_rt::clock().now() + REQUEST_NS;
    let (token, written) = loop {
        if let Some(done) = queue.pop()? {
            break done;
        }
        if !interrupt.wait(Some(deadline)) {
            return Err(DeviceError::Timeout("the device did not complete a read"));
        }
    };
    if token != 1 || written != 513 || m.read8(16) != 0 {
        println!("virtio-blk: read failed: token {token}, {written} bytes written, status {}", m.read8(16));
        return Err(DeviceError::Protocol("the device failed a read of sector 1"));
    }
    let mut signature = [0u8; 8];
    for (i, b) in signature.iter_mut().enumerate() {
        *b = m.read8(4096 + i);
    }
    println!(
        "virtio-blk: {} sectors, DMA {}; sector 1 begins {:?}",
        sectors,
        if dma.confined() { "confined by the IOMMU" } else { "not confined" },
        core::str::from_utf8(&signature).unwrap_or("(not text)")
    );
    Ok(())
}
