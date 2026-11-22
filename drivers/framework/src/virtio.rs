//! virtio 1.x over PCI: the transport every virtio driver shares, and the
//! split virtqueue.
//!
//! Written against the virtio specification (OASIS, version 1.2, sections
//! 2.7, 3.1 and 4.1). A driver negotiates the features it knows, sets up its
//! queues, and from then on adds buffers and takes completions; what is
//! specific to a device (its configuration, the layout of its requests) is
//! the driver's.
//!
//! The device is not trusted with the driver's state. The descriptor table
//! and the available ring are mapped read-only for the device where an
//! IOMMU exists; the driver keeps its own record of which descriptors are
//! in use and never reads one back; a completion that names a descriptor
//! the driver did not offer is a protocol error, reported, not followed.

use crate::dma::{self, Dma, DmaMemory};
use crate::inject::{self, Fault};
use crate::pci::CAP_VENDOR;
use crate::{Device, DeviceError};
use silica_rt::alloc::vec::Vec;
use silica_rt::mmio::Mmio;

/// Feature: the device is a virtio 1.0 or later device.
pub const F_VERSION_1: u64 = 1 << 32;
/// Feature: the device reaches memory through the platform's IOMMU, at the
/// addresses the driver gives it there, instead of bypassing it.
pub const F_ACCESS_PLATFORM: u64 = 1 << 33;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
/// Status bit: the device has given up and must be reset.
pub const STATUS_NEEDS_RESET: u8 = 64;
const STATUS_FAILED: u8 = 128;

// The common configuration structure.
const DEVICE_FEATURE_SELECT: usize = 0x00;
const DEVICE_FEATURE: usize = 0x04;
const DRIVER_FEATURE_SELECT: usize = 0x08;
const DRIVER_FEATURE: usize = 0x0C;
const CONFIG_VECTOR: usize = 0x10;
const NUM_QUEUES: usize = 0x12;
const DEVICE_STATUS: usize = 0x14;
const CONFIG_GENERATION: usize = 0x15;
const QUEUE_SELECT: usize = 0x16;
const QUEUE_SIZE: usize = 0x18;
const QUEUE_VECTOR: usize = 0x1A;
const QUEUE_ENABLE: usize = 0x1C;
const QUEUE_NOTIFY_OFF: usize = 0x1E;
const QUEUE_DESC: usize = 0x20;
const QUEUE_DRIVER: usize = 0x28;
const QUEUE_DEVICE: usize = 0x30;
/// "No MSI-X vector."
const NO_VECTOR: u16 = 0xFFFF;

/// How long a device gets to finish a reset.
const RESET_NS: u64 = 1_000_000_000;

/// A virtio device's registers.
#[derive(Debug)]
pub struct Transport {
    common: Mmio,
    notify: Mmio,
    notify_multiplier: u32,
    device: Option<Mmio>,
}

impl Transport {
    /// Find the device's virtio structures through its PCI capabilities.
    pub fn new(device: &Device) -> Result<Transport, DeviceError> {
        let config = device.config();
        let reg = config.registers();
        let (mut common, mut notify, mut specific, mut multiplier) = (None, None, None, 0);
        for (id, at) in config.capabilities() {
            // The capability is 16 bytes; the notify one has 4 more.
            if id != CAP_VENDOR || reg.read8(at + 2) < 16 || at + 16 > reg.len() {
                continue;
            }
            let (kind, bar) = (reg.read8(at + 3), reg.read8(at + 4) as usize);
            let (offset, length) = (reg.read32(at + 8) as usize, reg.read32(at + 12) as usize);
            // The first capability of each kind that names registers the
            // driver was given wins (the specification's order of preference).
            let Some(part) = device.bar(bar).and_then(|b| b.part(offset, length)) else { continue };
            match kind {
                1 if common.is_none() && length >= 0x38 => common = Some(part),
                2 if notify.is_none() && reg.read8(at + 2) >= 20 && at + 20 <= reg.len() => {
                    multiplier = reg.read32(at + 16);
                    notify = Some(part);
                }
                4 if specific.is_none() => specific = Some(part),
                _ => {}
            }
        }
        Ok(Transport {
            common: common.ok_or(DeviceError::Missing("the virtio common configuration (a virtio 1.0 device)"))?,
            notify: notify.ok_or(DeviceError::Missing("the virtio notification structure"))?,
            notify_multiplier: multiplier,
            device: specific,
        })
    }

    /// The device-specific configuration, if the device has one.
    pub fn device_config(&self) -> Option<Mmio> {
        self.device
    }

    /// Changes every time the device-specific configuration changes: read
    /// it before and after reading several fields that belong together.
    pub fn config_generation(&self) -> u8 {
        self.common.read8(CONFIG_GENERATION)
    }

    /// The device's status register.
    pub fn status(&self) -> u8 {
        self.common.read8(DEVICE_STATUS)
    }

    /// Reset the device: it forgets its queues and features and stops
    /// touching memory. Returns when the device says it has.
    pub fn reset(&self) -> Result<(), DeviceError> {
        self.common.write8(DEVICE_STATUS, 0);
        let clock = silica_rt::clock();
        let start = clock.now();
        while self.status() != 0 {
            if clock.now() - start > RESET_NS {
                return Err(DeviceError::Timeout("the device did not finish its reset"));
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// Reset the device and agree on features: the device must offer all
    /// of `required` (and virtio 1.0), and gets those and whichever of
    /// `wanted` it offers. On a machine that confines DMA the device must
    /// also agree to go through the IOMMU. Returns what was agreed.
    pub fn negotiate(&self, dma: &Dma, wanted: u64, required: u64) -> Result<u64, DeviceError> {
        self.reset()?;
        self.common.write8(DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        self.common.write8(DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        let mut offered = 0u64;
        for half in 0..2 {
            self.common.write32(DEVICE_FEATURE_SELECT, half);
            offered |= (self.common.read32(DEVICE_FEATURE) as u64) << (32 * half);
        }
        let required = required | F_VERSION_1 | if dma.confined() { F_ACCESS_PLATFORM } else { 0 };
        if offered & required != required {
            self.fail();
            return Err(DeviceError::Missing(if offered & F_VERSION_1 == 0 {
                "virtio 1.0"
            } else if offered & F_ACCESS_PLATFORM == 0 && dma.confined() {
                "VIRTIO_F_ACCESS_PLATFORM: this device would bypass the IOMMU"
            } else {
                "a feature the driver requires"
            }));
        }
        let agreed = offered & (wanted | required | F_ACCESS_PLATFORM);
        for half in 0..2 {
            self.common.write32(DRIVER_FEATURE_SELECT, half);
            self.common.write32(DRIVER_FEATURE, (agreed >> (32 * half)) as u32);
        }
        self.common.write8(DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        if self.status() & STATUS_FEATURES_OK == 0 {
            self.fail();
            return Err(DeviceError::Protocol("the device refused the features it offered"));
        }
        Ok(agreed)
    }

    /// How many queues the device has.
    pub fn queues(&self) -> u16 {
        self.common.read16(NUM_QUEUES)
    }

    /// Set up queue `index` with at most `max_size` descriptors, its
    /// completions raising MSI-X entry `vector` (`None`: no interrupt; the
    /// driver polls). After [`Transport::negotiate`], before
    /// [`Transport::start`].
    pub fn queue(&self, dma: &Dma, index: u16, max_size: u16, vector: Option<u16>) -> Result<Queue, DeviceError> {
        self.common.write16(QUEUE_SELECT, index);
        let offered = self.common.read16(QUEUE_SIZE);
        if offered == 0 {
            return Err(DeviceError::Missing("the queue"));
        }
        // The largest power of two that both sides accept.
        let size = offered.min(max_size).min(1 << 15);
        let size = if size == 0 { 0 } else { 1u16 << (15 - size.leading_zeros()) };
        if size == 0 {
            return Err(DeviceError::Protocol("a queue of no descriptors"));
        }
        self.common.write16(QUEUE_SIZE, size);
        let q = Queue::new(dma, size)?;
        for (reg, address) in [(QUEUE_DESC, q.desc_address()), (QUEUE_DRIVER, q.avail_address()), (QUEUE_DEVICE, q.used_address())] {
            self.common.write32(reg, address as u32);
            self.common.write32(reg + 4, (address >> 32) as u32);
        }
        if let Some(v) = vector {
            self.common.write16(QUEUE_VECTOR, v);
            if self.common.read16(QUEUE_VECTOR) != v {
                return Err(DeviceError::Protocol("the device has no MSI-X vector for the queue"));
            }
        } else {
            self.common.write16(QUEUE_VECTOR, NO_VECTOR);
        }
        let at = self.common.read16(QUEUE_NOTIFY_OFF) as usize * self.notify_multiplier as usize;
        let notify =
            self.notify.part(at, 2).ok_or(DeviceError::Protocol("the queue's notification register lies outside its structure"))?;
        self.common.write16(QUEUE_ENABLE, 1);
        Ok(Queue { notify, index, common: self.common, ..q })
    }

    /// Changes of the device-specific configuration raise MSI-X entry `vector`.
    pub fn config_interrupt(&self, vector: u16) -> Result<(), DeviceError> {
        self.common.write16(CONFIG_VECTOR, vector);
        if self.common.read16(CONFIG_VECTOR) != vector {
            return Err(DeviceError::Protocol("the device has no MSI-X vector for configuration changes"));
        }
        Ok(())
    }

    /// The driver is ready: the device may use its queues.
    pub fn start(&self) {
        self.common.write8(DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    /// Tell the device the driver has given up on it.
    pub fn fail(&self) {
        self.common.write8(DEVICE_STATUS, self.status() | STATUS_FAILED);
    }
}

/// One buffer of a request: where the device finds it and whether the
/// device writes it.
#[derive(Clone, Copy, Debug)]
pub struct Buffer {
    /// The device's address for it ([`DmaMemory::device_address`], [`Dma::share`]).
    pub address: u64,
    /// Its length in bytes.
    pub len: u32,
    /// Whether the device writes it (otherwise it only reads it).
    pub device_writes: bool,
}

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;
const NONE: u16 = 0xFFFF;

/// A split virtqueue (virtio 1.2, section 2.7).
#[derive(Debug)]
pub struct Queue {
    size: u16,
    index: u16,
    /// Descriptor table, then the available ring: the device only reads them.
    driver_area: DmaMemory,
    /// The used ring: the device writes it.
    device_area: DmaMemory,
    notify: Mmio,
    /// Descriptors not in use, linked through `next`.
    free: u16,
    free_count: u16,
    /// The driver's own record of each descriptor's successor, and for a
    /// chain's first descriptor its token and length while it is with the device.
    next: Vec<u16>,
    offered: Vec<Option<(u64, u16)>>,
    /// The next available-ring index to write, and how many were written
    /// since the device was last told.
    avail: u16,
    pending: u16,
    /// The next used-ring entry to read.
    used: u16,
    /// The transport's common configuration: where an injected reset goes.
    common: Mmio,
}

/// The queue has too few free descriptors for the request; take
/// completions and try again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueFull;

impl Queue {
    fn new(dma: &Dma, size: u16) -> Result<Queue, DeviceError> {
        let n = size as usize;
        let bits_for = |bytes: usize| (usize::BITS - (bytes.max(4096) - 1).leading_zeros()) as u8;
        // Descriptors (16 bytes each), then flags, index, the ring, used_event.
        let driver_area = dma.memory(bits_for(16 * n + 6 + 2 * n), false)?;
        // Flags, index, the ring (8 bytes each), avail_event.
        let device_area = dma.memory(bits_for(6 + 8 * n), true)?;
        let mut next = Vec::new();
        let mut offered = Vec::new();
        next.try_reserve_exact(n).map_err(|_| silica_rt::sys::Error::NoMemory)?;
        offered.try_reserve_exact(n).map_err(|_| silica_rt::sys::Error::NoMemory)?;
        for i in 0..size {
            next.push(if i + 1 < size { i + 1 } else { NONE });
            offered.push(None);
        }
        // SAFETY: an empty range; replaced by the queue's notification
        // register before the queue is returned to the driver.
        #[allow(unsafe_code)]
        let notify = unsafe { Mmio::new(0, 0) };
        Ok(Queue {
            size,
            index: 0,
            driver_area,
            device_area,
            notify,
            common: notify,
            free: 0,
            free_count: size,
            next,
            offered,
            avail: 0,
            pending: 0,
            used: 0,
        })
    }

    fn desc_address(&self) -> u64 {
        self.driver_area.device_address()
    }
    fn avail_address(&self) -> u64 {
        self.driver_area.device_address() + 16 * self.size as u64
    }
    fn used_address(&self) -> u64 {
        self.device_area.device_address()
    }

    /// How many descriptors the queue has.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// How many descriptors are free: a request needs one per buffer.
    pub fn room(&self) -> u16 {
        self.free_count
    }

    /// Offer the device one request made of `buffers`, in order: those it
    /// reads first, then those it writes. `token` comes back from
    /// [`Queue::pop`] when the device has finished with it. The device is
    /// told by [`Queue::notify`], once for any number of requests.
    pub fn add(&mut self, buffers: &[Buffer], token: u64) -> Result<(), QueueFull> {
        if buffers.is_empty() || buffers.len() > self.free_count as usize {
            return Err(QueueFull);
        }
        let d = self.driver_area.shared();
        let head = self.free;
        let mut at = head;
        for (i, b) in buffers.iter().enumerate() {
            let last = i + 1 == buffers.len();
            let o = at as usize * 16;
            d.write32(o, b.address as u32);
            d.write32(o + 4, (b.address >> 32) as u32);
            d.write32(o + 8, b.len);
            d.write16(o + 12, if b.device_writes { DESC_WRITE } else { 0 } | if last { 0 } else { DESC_NEXT });
            d.write16(o + 14, if last { 0 } else { self.next[at as usize] });
            if !last {
                at = self.next[at as usize];
            }
        }
        self.free = self.next[at as usize];
        self.free_count -= buffers.len() as u16;
        self.offered[head as usize] = Some((token, buffers.len() as u16));
        // An injected fault (`inject`): the device never sees this one.
        if inject::due() == Some(Fault::Stuck) && inject::pending(Fault::Stuck) {
            return Ok(());
        }
        // Into the available ring; the index that makes it visible is
        // written after the entry.
        let ring = 16 * self.size as usize + 4;
        d.write16(ring + 2 * (self.avail & (self.size - 1)) as usize, head);
        self.avail = self.avail.wrapping_add(1);
        dma::write_barrier();
        d.write16(16 * self.size as usize + 2, self.avail);
        self.pending = self.pending.wrapping_add(1);
        Ok(())
    }

    /// Tell the device about the requests added since it was last told,
    /// unless it has said it is looking anyway.
    pub fn notify(&mut self) {
        if self.pending == 0 {
            return;
        }
        self.pending = 0;
        // An injected fault: the device resets itself instead.
        if inject::pending(Fault::Reset) {
            self.common.write8(DEVICE_STATUS, 0);
            return;
        }
        // The device's "no notification needed" flag is read after the
        // index it will look at was written.
        dma::full_barrier();
        if self.device_area.shared().read16(0) & 1 == 0 {
            self.notify.write16(0, self.index);
        }
    }

    /// The next request the device has finished: its token and how many
    /// bytes the device wrote into its writable buffers. `Ok(None)` when
    /// there is none yet. An answer that does not name a request the
    /// driver offered is the device breaking the protocol: the queue must
    /// not be used again until the device is reset.
    pub fn pop(&mut self) -> Result<Option<(u64, u32)>, DeviceError> {
        let u = self.device_area.shared();
        if u.read16(2) == self.used {
            return Ok(None);
        }
        // The entry is read after the index that says it is there.
        dma::read_barrier();
        let o = 4 + 8 * (self.used & (self.size - 1)) as usize;
        // Injected faults: no interrupt brought this one, or the device
        // wrote nonsense in it.
        if inject::pending(Fault::Missed) {
            return Ok(None);
        }
        if inject::pending(Fault::Garbage) {
            u.write32(o, 0xFFFF_FF00);
        }
        let (id, written) = (u.read32(o), u.read32(o + 4));
        let Some((token, count)) = self.offered.get_mut(id as usize).and_then(Option::take) else {
            return Err(DeviceError::Protocol("the device completed a request the driver never offered"));
        };
        self.used = self.used.wrapping_add(1);
        // The chain's descriptors are free again, from the driver's own record.
        let mut last = id as u16;
        for _ in 1..count {
            last = self.next[last as usize];
        }
        self.next[last as usize] = self.free;
        self.free = id as u16;
        self.free_count += count;
        Ok(Some((token, written)))
    }

    /// Ask the device not to interrupt for completions (the driver is
    /// polling), or to interrupt again. A hint: the device may interrupt
    /// anyway. After asking for interrupts again, look once more with
    /// [`Queue::pop`] before waiting.
    pub fn suppress_interrupts(&mut self, suppress: bool) {
        self.driver_area.shared().write16(16 * self.size as usize, suppress as u16);
        dma::full_barrier();
    }
}
