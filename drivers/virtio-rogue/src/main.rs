//! A hostile driver for a virtio block device: the test of what a driver
//! cannot do (`spec/TESTING.md`: every promise is tested by trying to break
//! it). The device manager starts it in place of the real driver
//! (`driver=1af4:1042=virtio-rogue` on the kernel command line), so it holds
//! exactly what a driver holds, and it uses that against the system:
//!
//! - it claims another device's identity and another device's interrupt;
//! - it tells its device to write to, and to read from, memory the driver
//!   never mapped for it, and to write to memory mapped for reading only;
//! - it asks where its memory physically is;
//! - it writes its device's configuration space.
//!
//! Each attempt must fail the way the design says, and the device must be
//! usable again afterwards. The last one is a fault: the device manager
//! takes the driver down and starts it again, and the second run checks that
//! a restarted driver finds a working device. Prints `TEST <name> PASS` per
//! check; any `ERROR:` line is a boundary that did not hold.
#![no_std]
#![no_main]

use silica_driver::dma::{Dma, DmaMemory};
use silica_driver::irq::Interrupt;
use silica_driver::virtio::{Buffer, Queue, STATUS_NEEDS_RESET, Transport};
use silica_driver::{Device, DeviceError, grant, granted};
use silica_rt::sys::{self, Cap, Error, Rights};
use silica_rt::{ProcessInfo, mem, println, slots};

silica_rt::main!(main);

const T_IN: u32 = 0;
const T_OUT: u32 = 1;
/// How long the device gets to answer, or to be seen not answering.
const WAIT_NS: u64 = 300_000_000;

struct Disk {
    transport: Transport,
    queue: Queue,
    interrupt: Interrupt,
    /// Header at 0, status at 16, a sector of data at 4096.
    request: DmaMemory,
}

fn bring_up(device: &Device, dma: &Dma) -> Result<Disk, DeviceError> {
    let transport = Transport::new(device)?;
    transport.negotiate(dma, 0, 0)?;
    let interrupt = Interrupt::bind(device, 0)?;
    let queue = transport.queue(dma, 0, 64, Some(0))?;
    transport.start();
    Ok(Disk { transport, queue, interrupt, request: dma.memory(13, true)? })
}

/// What became of a request.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The device completed it with this status byte.
    Status(u8),
    /// The device gave up (it wants a reset) or never answered.
    Refused,
}

impl Disk {
    /// One request for sector `sector` whose data the device finds at `data`.
    fn request(&mut self, kind: u32, sector: u64, data: u64) -> Result<Outcome, DeviceError> {
        let (m, base) = (self.request.shared(), self.request.device_address());
        m.write32(0, kind);
        m.write32(4, 0);
        m.write64(8, sector);
        m.write8(16, 0xFF);
        let buffers = [
            Buffer { address: base, len: 16, device_writes: false },
            Buffer { address: data, len: 512, device_writes: kind == T_IN },
            Buffer { address: base + 16, len: 1, device_writes: true },
        ];
        self.queue.add(&buffers, 7).map_err(|_| DeviceError::Protocol("no room in an empty queue"))?;
        self.queue.notify();
        let deadline = silica_rt::clock().now() + WAIT_NS;
        loop {
            if self.queue.pop()?.is_some() {
                return Ok(Outcome::Status(m.read8(16)));
            }
            if self.transport.status() & STATUS_NEEDS_RESET != 0 || !self.interrupt.wait(Some(deadline)) {
                return Ok(Outcome::Refused);
            }
        }
    }
}

fn pass(name: &str) {
    println!("TEST {name} PASS");
}

fn fail(name: &str, what: core::fmt::Arguments<'_>) -> DeviceError {
    println!("ERROR: virtio-rogue: {name}: {what}");
    DeviceError::Protocol("a boundary did not hold")
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(()) => 0,
        Err(e) => {
            println!("ERROR: virtio-rogue: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<(), DeviceError> {
    let device = Device::take(info)?;
    let dma = Dma::new(&device)?;
    if !dma.confined() {
        println!("ERROR: virtio-rogue: this machine does not confine DMA; there is no boundary to test");
        return Err(DeviceError::Missing("an IOMMU"));
    }
    if info.args[4] != 0 {
        // The second run, after the fault: the device works for a new driver.
        let mut disk = bring_up(&device, &dma)?;
        let data = disk.request.device_address() + 4096;
        let outcome = disk.request(T_IN, 1, data)?;
        if outcome != Outcome::Status(0) || disk.request.shared().read64(4096) != u64::from_le_bytes(*b"EFI PART") {
            return Err(fail("rogue_restart", format_args!("the restarted driver's read came back {outcome:?}")));
        }
        pass("rogue_restart");
        return Ok(());
    }

    // Authority over one device is not authority over another.
    let (identity, lines) = (granted(grant::IDENTITY), granted(grant::INTERRUPTS));
    let other = device.id ^ 8;
    let notification = mem::Object::new(sys::ObjectType::Notification, 0)?;
    let space = mem::alloc(16)?;
    let slot = silica_rt::ipc::free_slot().ok_or(Error::NoMemory)?;
    sys::retype_io_space(space, 16, slots::SPACE, slot)?;
    match sys::device_attach(identity, other, Cap(slot)) {
        Err(Error::BadArg) => pass("rogue_other_device"),
        r => return Err(fail("rogue_other_device", format_args!("attaching another device gave {r:?}"))),
    }
    match sys::irq_bind_msi(lines, device.lines.start, notification.cap(), identity, other) {
        Err(Error::BadArg) => {}
        r => return Err(fail("rogue_other_interrupt", format_args!("an interrupt for another device gave {r:?}"))),
    }
    match sys::irq_bind_msi(lines, device.lines.end, notification.cap(), identity, device.id) {
        Err(Error::BadArg) => pass("rogue_other_interrupt"),
        r => return Err(fail("rogue_other_interrupt", format_args!("a line outside its own gave {r:?}"))),
    }
    // Where its memory is, is not the driver's to know; and no device
    // address lies above what the IOMMU translates.
    let page = mem::Memory::new(12)?;
    match sys::frame_address(identity, page.frame()) {
        Err(Error::Unsupported) => pass("rogue_physical_address"),
        r => return Err(fail("rogue_physical_address", format_args!("asking for a physical address gave {r:?}"))),
    }
    let copy = silica_rt::ipc::free_slot().ok_or(Error::NoMemory)?;
    sys::cap_derive(slots::SPACE, copy, page.frame(), Rights::READ, 0)?;
    match sys::map(Cap(slot), Cap(copy), device.dma_top as usize, Rights::READ) {
        Err(Error::BadArg) => pass("rogue_address_above_the_top"),
        r => return Err(fail("rogue_address_above_the_top", format_args!("mapping above the top gave {r:?}"))),
    }

    // The device as a weapon: it is told to write to memory the driver
    // never mapped for it. Device address 1 MiB is ordinary memory to the
    // machine, and nothing to this device. What the device says about such
    // a request is not evidence (an emulated one reports success for a
    // write that went nowhere); the kernel's line naming the refused
    // access is, and the harness requires it.
    let mut disk = bring_up(&device, &dma)?;
    let own = disk.request.device_address() + 4096;
    if disk.request(T_IN, 1, own)? != Outcome::Status(0) {
        return Err(fail("rogue_setup", format_args!("an honest read failed")));
    }
    let outcome = disk.request(T_IN, 1, 0x10_0000)?;
    println!("virtio-rogue: told the device to write at 0x100000: {outcome:?}");
    // To read from it: a disk write whose data is someone else's memory.
    // (Sector 2: nothing in this test reads it afterwards, and the disk is
    // a snapshot.)
    let mut disk = bring_up(&device, &dma)?;
    let outcome = disk.request(T_OUT, 2, 0x20_0000)?;
    println!("virtio-rogue: told the device to read at 0x200000: {outcome:?}");
    // To write to memory it may only read. This one the driver sees for
    // itself: the memory is its own.
    let mut disk = bring_up(&device, &dma)?;
    let read_only = dma.memory(12, false)?;
    read_only.shared().write64(0, 0x5EA1_ED00_5EA1_ED00);
    let outcome = disk.request(T_IN, 1, read_only.device_address())?;
    if read_only.shared().read64(0) != 0x5EA1_ED00_5EA1_ED00 {
        return Err(fail("rogue_write_read_only", format_args!("the device wrote memory mapped for reading only ({outcome:?})")));
    }
    pass("rogue_write_read_only");
    // After all that, a reset makes the device usable again.
    let mut disk = bring_up(&device, &dma)?;
    let own = disk.request.device_address() + 4096;
    if disk.request(T_IN, 1, own)? != Outcome::Status(0) || disk.request.shared().read64(4096) != u64::from_le_bytes(*b"EFI PART") {
        return Err(fail("rogue_recovers", format_args!("the device does not work after a reset")));
    }
    pass("rogue_recovers");

    // Configuration space is the device manager's: writing it is a fault,
    // which ends this run. The device manager starts the driver again.
    println!("virtio-rogue: writing configuration space; a fault is expected");
    device.config().registers().write16(4, 0);
    Err(fail("rogue_config_space", format_args!("the driver wrote its device's configuration space")))
}
