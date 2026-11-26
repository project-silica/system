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

use crate::dma::{self, Dma};
use crate::inject::{self, Fault};
use crate::pci::CAP_VENDOR;
use crate::{Device, DeviceError};
use silica_rt::alloc::vec::Vec;
use silica_rt::mmio::Mmio;
use silica_rt::sys::Cap;

/// Feature: the device is a virtio 1.0 or later device.
pub const F_VERSION_1: u64 = 1 << 32;
/// Feature: the device reaches memory through the platform's IOMMU, at the
/// addresses the driver gives it there, instead of bypassing it.
pub const F_ACCESS_PLATFORM: u64 = 1 << 33;
/// Event indices (virtio 1.2, 2.7.10): the driver says which completion it
/// wants an interrupt for, the device which request it wants a doorbell
/// for. Taken whenever the device offers it; the queue uses it unseen.
pub const F_RING_EVENT_IDX: u64 = 1 << 29;

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
/// How often [`Transport::read_config`] reads a configuration that changes
/// underneath before it gives the device up: a configuration changes when
/// something happens to the device (a disk resized, a link changed), not
/// sixty-four times in a row.
pub const CONFIG_READS: u32 = 64;
/// An injected `generation` was committed: every read after reports a new
/// generation ([`Transport::config_generation`]).
static CHURN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static TURNS: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(1);
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
    /// Event indices were agreed: the queues made from here on use them.
    event_idx: core::cell::Cell<bool>,
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
            // Every structure is 4-byte aligned (virtio 1.2, 4.1.4), the
            // notification one 2-byte; one that is not is not used.
            if offset % if kind == 2 { 2 } else { 4 } != 0 {
                continue;
            }
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
            event_idx: core::cell::Cell::new(false),
        })
    }

    /// The device-specific configuration, if the device has one.
    pub fn device_config(&self) -> Option<Mmio> {
        self.device
    }

    /// Fields of the device-specific configuration that belong together,
    /// as `read` reads them, under one configuration generation (virtio 1.2,
    /// 4.1.4.3.1): read again while the generation changes underneath, at
    /// most [`CONFIG_READS`] times, then the device is refused. A device
    /// whose configuration never settles spun its driver at bring-up for
    /// ever, and never said so (the 2026-11-25 drivers review).
    pub fn read_config<T>(&self, mut read: impl FnMut() -> T) -> Result<T, DeviceError> {
        for _ in 0..CONFIG_READS {
            let before = self.config_generation();
            let fields = read();
            if self.config_generation() == before {
                return Ok(fields);
            }
        }
        Err(DeviceError::Protocol("the configuration changes on every read"))
    }

    /// Changes every time the device-specific configuration changes: read
    /// it before and after reading several fields that belong together
    /// ([`Transport::read_config`]).
    pub fn config_generation(&self) -> u8 {
        let generation = self.common.read8(CONFIG_GENERATION);
        // Injected (`generation`): from here on the device reports a new
        // generation at every read, as one whose configuration never
        // settles would.
        if CHURN.load(core::sync::atomic::Ordering::Relaxed)
            || (inject::planned() == Some(Fault::Generation)
                && inject::due() == Some(Fault::Generation)
                && inject::pending(Fault::Generation))
        {
            CHURN.store(true, core::sync::atomic::Ordering::Relaxed);
            return generation.wrapping_add(TURNS.fetch_add(1, core::sync::atomic::Ordering::Relaxed));
        }
        generation
    }

    /// Whether the device has given up and asks to be reset (virtio 1.2,
    /// 2.1.2: it sets DEVICE_NEEDS_RESET and interrupts as for a change of
    /// its configuration). Nothing it does from then on can be trusted,
    /// and requests in flight may never complete: the driver ends, and the
    /// device manager starts it again, which resets the device. Asked on
    /// the configuration interrupt ([`Transport::config_vector`]), not on
    /// every completion: reading the register leaves a virtual machine.
    pub fn needs_reset(&self) -> bool {
        self.status() & STATUS_NEEDS_RESET != 0
    }

    /// The MSI-X entry for configuration changes (a device asking to be
    /// reset among them) on `device`, its queues using entries from 0 to
    /// `queues - 1`: an entry of its own when the device has one, so its
    /// interrupt says what it is; otherwise entry 0, shared with the
    /// first queue, whose driver then asks [`Transport::needs_reset`]
    /// when an interrupt brings no completion. Set with
    /// [`Transport::config_interrupt`] before [`Transport::start`].
    pub fn config_vector(device: &Device, queues: u16) -> u16 {
        let vectors = device.config().msix().map_or(0, |m| m.vectors);
        if vectors > queues { queues } else { 0 }
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
        let agreed = offered & (wanted | required | F_ACCESS_PLATFORM | F_RING_EVENT_IDX);
        self.event_idx.set(agreed & F_RING_EVENT_IDX != 0);
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

    /// Set up queue `index` with at most `max_size` descriptors and at least
    /// `per_request` (what one request of the driver's takes: a device that
    /// offers fewer is refused here, not found unusable request by request),
    /// its
    /// completions raising MSI-X entry `vector` (`None`: no interrupt; the
    /// driver polls). After [`Transport::negotiate`], before
    /// [`Transport::start`].
    pub fn queue(&self, dma: &Dma, index: u16, max_size: u16, per_request: u16, vector: Option<u16>) -> Result<Queue, DeviceError> {
        self.common.write16(QUEUE_SELECT, index);
        let offered = self.common.read16(QUEUE_SIZE);
        // An injected fault (`inject`): the device offers two descriptors.
        let offered = if inject::planned() == Some(Fault::Tiny) && inject::due() == Some(Fault::Tiny) && inject::pending(Fault::Tiny) {
            2
        } else {
            offered
        };
        if offered == 0 {
            return Err(DeviceError::Missing("the queue"));
        }
        // The largest power of two that both sides accept.
        let size = offered.min(max_size).min(1 << 15);
        let size = if size == 0 { 0 } else { 1u16 << (15 - size.leading_zeros()) };
        if size == 0 {
            return Err(DeviceError::Protocol("a queue of no descriptors"));
        }
        if size < per_request.max(1) {
            return Err(DeviceError::Protocol("a queue too small for one request"));
        }
        self.common.write16(QUEUE_SIZE, size);
        let (q, addresses) = Queue::new(dma, size)?;
        for (reg, address) in [QUEUE_DESC, QUEUE_DRIVER, QUEUE_DEVICE].into_iter().zip(addresses) {
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
        let notify = self
            .notify
            .part(at, 2)
            .filter(|n| n.addr() % 2 == 0)
            .ok_or(DeviceError::Protocol("the queue's notification register lies outside its structure or is misaligned"))?;
        self.common.write16(QUEUE_ENABLE, 1);
        Ok(Queue { notify, index, common: self.common, event_idx: self.event_idx.get(), ..q })
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
    /// The device's address for it ([`crate::dma::DmaMemory::device_address`], [`Dma::share`]).
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
    driver_area: Mmio,
    /// The used ring: the device writes it.
    device_area: Mmio,
    /// The frame it is in (none for a queue over memory of a test's).
    device_frame: Cap,
    /// The frame of the descriptor table and available ring.
    driver_frame: Cap,
    /// The kernel owns the available ring's "no interrupt" flag (`watch`).
    kernel_quiet: bool,
    notify: Mmio,
    /// Descriptors not in use, linked through `next`.
    free: u16,
    free_count: u16,
    /// The driver's own record of each descriptor's successor, and for a
    /// chain's first descriptor what it was offered as while it is with the device.
    next: Vec<u16>,
    offered: Vec<Option<Offered>>,
    /// The next available-ring index to write, and how many were written
    /// since the device was last told.
    avail: u16,
    pending: u16,
    /// The next used-ring entry to read.
    used: u16,
    /// The transport's common configuration: where an injected reset goes.
    common: Mmio,
    /// Event indices were agreed (`F_RING_EVENT_IDX`).
    event_idx: bool,
}

/// The queue has too few free descriptors for the request; take
/// completions and try again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueFull;

/// A request while the device has it: its token, how many descriptors it
/// takes, and how many bytes the device may write into it.
#[derive(Clone, Copy, Debug)]
struct Offered {
    token: u64,
    count: u16,
    writable: u64,
}

/// The bytes a split virtqueue of `size` descriptors takes in the area only
/// the driver writes (the descriptor table, then the available ring) and in
/// the area the device writes (the used ring).
pub const fn queue_areas(size: u16) -> (usize, usize) {
    let n = size as usize;
    // Descriptors (16 bytes each), then flags, index, the ring, used_event;
    // flags, index, the ring (8 bytes each), avail_event.
    (16 * n + 6 + 2 * n, 6 + 8 * n)
}

impl Queue {
    /// The queue's memory, and the device addresses of its descriptor
    /// table, available ring and used ring.
    fn new(dma: &Dma, size: u16) -> Result<(Queue, [u64; 3]), DeviceError> {
        let bits_for = |bytes: usize| (usize::BITS - (bytes.max(4096) - 1).leading_zeros()) as u8;
        let (driver, device) = queue_areas(size);
        let driver_area = dma.memory(bits_for(driver), false)?;
        let device_area = dma.memory(bits_for(device), true)?;
        // Never unmapped (`DmaMemory`), so the views outlive the values.
        let q = Queue {
            device_frame: device_area.frame(),
            driver_frame: driver_area.frame(),
            ..Queue::over(size, driver_area.shared(), device_area.shared())?
        };
        let at = driver_area.device_address();
        Ok((q, [at, at + 16 * size as u64, device_area.device_address()]))
    }

    /// A queue of `size` descriptors (a power of two up to 32768) laid out
    /// in `driver_area` and `device_area` ([`queue_areas`] says how many
    /// bytes each needs; both zeroed), with no notification register: what
    /// [`Transport::queue`] builds on, and how a test or a fuzzer plays the
    /// device against the queue a driver uses.
    pub fn over(size: u16, driver_area: Mmio, device_area: Mmio) -> Result<Queue, DeviceError> {
        let (driver, device) = queue_areas(size);
        if !size.is_power_of_two() || size > 1 << 15 || driver_area.len() < driver || device_area.len() < device {
            return Err(DeviceError::Kernel(silica_rt::sys::Error::BadArg));
        }
        let n = size as usize;
        let mut next = Vec::new();
        let mut offered = Vec::new();
        next.try_reserve_exact(n).map_err(|_| silica_rt::sys::Error::NoMemory)?;
        offered.try_reserve_exact(n).map_err(|_| silica_rt::sys::Error::NoMemory)?;
        for i in 0..size {
            next.push(if i + 1 < size { i + 1 } else { NONE });
            offered.push(None);
        }
        // SAFETY: an empty range; every access to it panics. The
        // transport replaces it with the queue's notification register.
        #[allow(unsafe_code)]
        let notify = unsafe { Mmio::new(0, 0) };
        Ok(Queue {
            size,
            index: 0,
            driver_area,
            device_area,
            device_frame: Cap::NONE,
            driver_frame: Cap::NONE,
            kernel_quiet: false,
            notify,
            common: notify,
            event_idx: false,
            free: 0,
            free_count: size,
            next,
            offered,
            avail: 0,
            pending: 0,
            used: 0,
        })
    }

    /// Use event indices (`F_RING_EVENT_IDX`), and `register` as the
    /// queue's notification register: for a queue made by [`Queue::over`].
    pub fn with_notify(self, register: Mmio, event_idx: bool) -> Queue {
        Queue { notify: register, event_idx, ..self }
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
        let d = self.driver_area;
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
        let writable = buffers.iter().filter(|b| b.device_writes).map(|b| b.len as u64).sum();
        self.offered[head as usize] = Some(Offered { token, count: buffers.len() as u16, writable });
        // Injected faults (`inject`): the device never sees this one, or
        // sees a chain it must refuse (its last descriptor says another
        // follows, at an index past the queue: the device gives up and
        // asks to be reset).
        let due = inject::due();
        if due == Some(Fault::Broken) && inject::pending(Fault::Broken) {
            let o = at as usize * 16;
            d.write16(o + 12, d.read16(o + 12) | DESC_NEXT);
            d.write16(o + 14, self.size);
        }
        if due == Some(Fault::Stuck) && inject::pending(Fault::Stuck) {
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
        let added = self.pending;
        self.pending = 0;
        // An injected fault: the device resets itself instead.
        if inject::pending(Fault::Reset) {
            self.common.write8(DEVICE_STATUS, 0);
            return;
        }
        // What the device asked for is read after the index it will look
        // at was written.
        dma::full_barrier();
        let wanted = if self.event_idx {
            // A doorbell only if the requests added since the last one
            // passed the one the device asked to be told about.
            let event = self.device_area.read16(4 + 8 * self.size as usize);
            let (new, old) = (self.avail, self.avail.wrapping_sub(added));
            new.wrapping_sub(event).wrapping_sub(1) < new.wrapping_sub(old)
        } else {
            // The device's "no notification needed" flag.
            self.device_area.read16(0) & 1 == 0
        };
        if wanted {
            self.notify.write16(0, self.index);
        }
    }

    /// The next request the device has finished: its token and how many
    /// bytes the device wrote into its writable buffers. `Ok(None)` when
    /// there is none yet. An answer that does not name a request the
    /// driver offered, or says the device wrote more than the request's
    /// writable buffers hold, is the device breaking the protocol: the
    /// queue must not be used again until the device is reset.
    pub fn pop(&mut self) -> Result<Option<(u64, u32)>, DeviceError> {
        let u = self.device_area;
        if u.read16(2) == self.used {
            if !self.event_idx {
                return Ok(None);
            }
            // Ask for an interrupt for the next completion, then look once
            // more: one that came while asking would bring none.
            self.driver_area.write16(16 * self.size as usize + 4 + 2 * self.size as usize, self.used);
            dma::full_barrier();
            if u.read16(2) == self.used {
                return Ok(None);
            }
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
        let (id, mut written) = (u.read32(o), u.read32(o + 4));
        let Some(slot) = self.offered.get_mut(id as usize) else {
            return Err(DeviceError::Protocol("the device completed a request the driver never offered"));
        };
        let Some(Offered { token, count, writable }) = *slot else {
            return Err(DeviceError::Protocol("the device completed a request the driver never offered"));
        };
        // Injected (`short`): a request with data for the driver completed
        // as if the device wrote only its last byte.
        if writable > 1 && inject::pending(Fault::Short) {
            written = 1;
        }
        // A length past the buffers would have a client read what the
        // device never wrote: the device is not believed.
        if written as u64 > writable {
            return Err(DeviceError::Protocol("the device says it wrote more than the request's buffers hold"));
        }
        *slot = None;
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

    /// Make `interrupt`, the queue's own, watched (`Interrupt::watch`): its
    /// news is the used ring's index, which the device advances before it
    /// interrupts, and [`Queue::pop`] until `None` takes all of it. Without
    /// event indices the device is also told not to interrupt while a
    /// processor watches (`Interrupt::quiet`, the available ring's
    /// `NO_INTERRUPT` flag, which the device reads after it writes the
    /// index); with them it reads `used_event` instead, which the driver
    /// writes as it takes completions, so there the interrupt that follows
    /// a watched completion is still sent, and dropped by the kernel. Before
    /// the first request.
    pub fn watch(&mut self, interrupt: &crate::irq::Interrupt) -> Result<(), DeviceError> {
        if self.device_frame == Cap::NONE {
            return Err(DeviceError::Kernel(silica_rt::sys::Error::BadArg));
        }
        // The ring's flags (16 bits) then its index (16 bits): the index alone.
        interrupt.watch(self.device_frame, 0, 0xFFFF_0000)?;
        if !self.event_idx {
            // The available ring's flags: the low half of the word at its start.
            interrupt.quiet(self.driver_frame, 16 * self.size as u64, 1)?;
            self.kernel_quiet = true;
        }
        Ok(())
    }

    /// Ask the device not to interrupt for completions (the driver is
    /// polling), or to interrupt again. A hint: the device may interrupt
    /// anyway. After asking for interrupts again, look once more with
    /// [`Queue::pop`] before waiting.
    pub fn suppress_interrupts(&mut self, suppress: bool) {
        // Once the kernel says when the device may interrupt (`watch`), the
        // flag is its alone.
        if !self.kernel_quiet {
            self.driver_area.write16(16 * self.size as usize, suppress as u16);
        }
        if self.event_idx {
            // The completion asked an interrupt for: one long past, or the next.
            let at = if suppress { self.used.wrapping_sub(0x8000) } else { self.used };
            self.driver_area.write16(16 * self.size as usize + 4 + 2 * self.size as usize, at);
        }
        dma::full_barrier();
    }
}
