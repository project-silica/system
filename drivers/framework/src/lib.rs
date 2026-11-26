//! The driver framework: what a Silica driver is written against.
//!
//! A driver is an ordinary program (`silica_rt`) that the device manager
//! starts for one device, holding that device's capabilities and nothing
//! else. What it is given, by grant number (`slots::FIRST_GRANT + n`):
//!
//! | grant | what |
//! | --- | --- |
//! | 0 | an endpoint to receive on: where its clients call it (its class protocol) |
//! | 1 | the device's identity: authority to say what the device reaches by DMA and which message interrupts it raises |
//! | 2 | the interrupt lines set aside for it |
//! | 3 | the device's PCI configuration space, 4 KiB, read-only |
//! | 4 to 9 | its memory BARs 0 to 5, each a frame of device registers (empty where the device has none) |
//!
//! and in `ProcessInfo::args`: 0 the device's identity (PCI segment, bus,
//! device, function, as `Syscall::DeviceAttach` takes it), 1 its first
//! interrupt line, 2 how many lines it has, 3 one past the highest address
//! a device can be given on this machine (0: the machine cannot confine
//! DMA), 4 how many times a driver was started for this device before (low
//! half; in a test image, built with the `harness` feature, the high half is
//! a fault for this run to commit on purpose, `inject`).
//!
//! A device gets one interrupt line per MSI-X table entry it has, up to 8
//! ([`Device::lines`]); [`irq`] binds them. A 64-bit BAR is the BAR of its
//! lower number (`bar(0)` for BARs 0 and 1 together; `bar(1)` is then
//! empty).
//!
//! [`Device::take`] turns that into a [`Device`]: registers mapped, ready to
//! use. The device manager has already switched on the device's memory
//! decoding, bus mastering and MSI-X; the driver never writes configuration
//! space. Until the driver attaches the device to a device address space
//! ([`dma::Dma`]) the device reaches no memory at all, and it reaches none
//! again the moment the driver ends, however it ends.
//!
//! # Declaring what a driver drives
//!
//! A driver is a program of the `system` workspace (as `silica_rt`
//! describes) whose `Cargo.toml` says which devices it is for:
//!
//! ```text
//! [package.metadata.silica]
//! drivers = ["pci 1af4:1042", "class 01.08.02"]
//! ```
//!
//! `pci <vendor>:<device>` (four hexadecimal digits each) names one kind of
//! device; `class <class>.<subclass>.<interface>` (two each) every device of
//! that kind, as the PCI class code says (`01.08.02` is an NVMe controller).
//! The image build collects these into the boot archive's `drivers` list,
//! and the device manager starts the first driver that names a device's
//! identifiers, else the first that names its class. Which program gets a
//! device's authority is said by that list alone, which is part of the
//! checked boot archive: an image that wants another program in a driver's
//! place for one kind of device (a test image's hostile driver) is built
//! with a `pci` line for it ahead of the others.
//!
//! The device manager knows what a device is for from its class code (01:
//! storage, a provider of `silica.block.Device`) and hands clients the
//! driver's endpoint ([`grant::SERVICE`]) through `silica.device.Manager`.
//! A block driver implements `silica_block::service::Device` and serves it
//! with `silica_rt::ipc::serve_events`.
//!
//! # What happens when a driver fails
//!
//! A driver that faults, or exits with a status other than 0, is destroyed
//! (its memory, its capabilities, and its device's view of memory with
//! them), its device is silenced, and it is started again: at once the
//! first time, then after a wait that doubles up to a minute, never given
//! up for good (`silica_proc::Restarts`); [`Device::starts`] says how many
//! times it has been. Its clients see `peer_gone` and open the new one. A
//! driver that exits with 0 is not started again. Reading memory a client
//! lent it (`silica_rt::mem::map_peer`) never faults: memory the client
//! took back reads as zeros.
//!
//! A driver that cannot go on ends with a nonzero status (or
//! `silica_rt::exit`, from anywhere) and is restarted, which resets its
//! device. One that finds a device it will never support (a format it does
//! not know) says why and ends with status 0: it is not restarted, and the
//! device is left alone.
//!
//! A driver is told when the machine is turning off: its parent signals
//! `silica_rt::END` on the notification it listens on ([`irq::Signals`]),
//! and a driver with something to finish does so and exits 0 (a block
//! driver's service flushes the device's write cache and lets the device
//! shut down as its specification asks: an NVMe controller's normal
//! shutdown). A driver that does not exit within the device manager's bound
//! is ended where it stands; what a client was told is flushed is on the
//! medium regardless.
//!
//! # Waiting for a device
//!
//! A register that changes when the device is ready (a reset finished, a
//! controller enabled) is waited for with [`settle`]: it looks, sleeps and
//! looks again until the bound the device's own specification gives for
//! that step, and no driver spins a processor meanwhile.
//!
//! A driver's `Cargo.toml` needs only the runtime, this crate, and its
//! class's crate:
//!
//! ```text
//! [package]
//! name = "mydisk"
//! version.workspace = true
//! edition.workspace = true
//! license.workspace = true
//! publish.workspace = true
//!
//! [package.metadata.silica]
//! drivers = ["pci 1234:5678"]
//!
//! [[bin]]
//! name = "mydisk"
//! path = "src/main.rs"
//! test = false
//! bench = false
//!
//! [dependencies]
//! silica-rt = { workspace = true }
//! silica-driver = { workspace = true }
//! silica-block = { workspace = true }
//!
//! [lints]
//! workspace = true
//! ```
//!
//! and a line in the workspace's `members`. What it prints goes to the
//! console prefixed by nothing: begin lines with the driver's name. Test
//! results a harness reads are `TEST <driver>.<name> PASS` lines.
//!
//! A device is not trusted. Every offset and length read from one is
//! checked before use ([`Mmio::part`](silica_rt::mmio::Mmio::part)), and a
//! device that answers nonsense gets an error, never a panic.
#![no_std]
#![deny(unsafe_code)]

pub mod dma;
pub mod framebuffer;
#[cfg(feature = "harness")]
pub mod inject;
pub mod irq;
pub mod mac;
pub mod oldest;
pub mod pci;
pub mod virtio;

use core::ops::Range;
use silica_rt::mmio::Mmio;
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{ProcessInfo, mem, slots};

/// How long a driver waits for its device to answer a request: `limit`, the
/// device's own. (In a test image, built with the `harness` feature, a run
/// with a fault armed waits `inject::ARMED_TIMEOUT_NS` instead, so the
/// test of a device that never answers takes a second.)
#[inline]
pub fn io_limit(limit: u64) -> u64 {
    #[cfg(feature = "harness")]
    if inject::armed() {
        return inject::ARMED_TIMEOUT_NS;
    }
    limit
}

/// What a driver sleeps on between looks at a register ([`settle`]): a
/// notification nobody signals (a receive with a deadline is how a program
/// sleeps), made the first time it is needed and kept.
static NAP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The first sleep between two looks at a register; each one after is twice
/// as long, up to [`SETTLE_LONGEST_NS`].
const SETTLE_FIRST_NS: u64 = 50_000;
const SETTLE_LONGEST_NS: u64 = 10_000_000;

/// Wait for the device to finish a step it reports in a register: `done`
/// reads it (`Ok(true)`: finished; an error ends the wait with that error),
/// now and after each sleep, until `bound_ns` have passed, when the wait
/// fails with `DeviceError::Timeout(what)`. `bound_ns` is what the device's
/// specification gives the step (NVMe's CAP.TO and RTD3E, the 82574's reset
/// time), not a number of the driver's own. A device that is ready at once
/// costs one read; one that takes its whole time costs no processor, and
/// nothing the driver listens on is consumed meanwhile.
pub fn settle(bound_ns: u64, what: &'static str, mut done: impl FnMut() -> Result<bool, DeviceError>) -> Result<(), DeviceError> {
    use core::sync::atomic::Ordering;
    let clock = silica_rt::clock();
    let deadline = clock.now().saturating_add(bound_ns);
    let mut nap = SETTLE_FIRST_NS;
    loop {
        if done()? {
            return Ok(());
        }
        let now = clock.now();
        if now >= deadline {
            return Err(DeviceError::Timeout(what));
        }
        if NAP.load(Ordering::Relaxed) == 0
            && let Ok(n) = mem::Object::new(ObjectType::Notification, 0)
        {
            NAP.store(n.cap().0, Ordering::Relaxed);
        }
        match NAP.load(Ordering::Relaxed) {
            // No memory for it: the bound still holds, the sleep does not.
            0 => sys::yield_now(),
            n => {
                // The deadline passing is the wake-up.
                let _ = sys::recv(Cap(n), sys::Wait::Until((now + nap).min(deadline)));
            }
        }
        nap = (nap * 2).min(SETTLE_LONGEST_NS);
    }
}

/// Grant numbers of what the device manager gives a driver.
pub mod grant {
    /// The endpoint its clients call it on.
    pub const SERVICE: u64 = 0;
    /// The device's identity.
    pub const IDENTITY: u64 = 1;
    /// Its interrupt lines.
    pub const INTERRUPTS: u64 = 2;
    /// Its configuration space.
    pub const CONFIG: u64 = 3;
    /// Its first BAR; the others follow.
    pub const BAR0: u64 = 4;
    /// How many grants a driver gets.
    pub const COUNT: usize = 10;
}

/// What can be wrong with a device or with what the driver was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceError {
    /// The program was not started as a driver: a grant is missing or is
    /// not what a driver gets.
    NotADriver,
    /// The device lacks something the driver needs (a capability, a BAR, a
    /// feature); the string says what.
    Missing(&'static str),
    /// The device said something its specification does not allow; the
    /// string says what.
    Protocol(&'static str),
    /// The device did not answer in the time its specification gives it.
    Timeout(&'static str),
    /// The device refused a command (what the string says) with this
    /// status, in the device's own terms.
    Refused(&'static str, u64),
    /// A kernel operation failed (most often `NoMemory`).
    Kernel(sys::Error),
}

impl From<sys::Error> for DeviceError {
    fn from(e: sys::Error) -> DeviceError {
        DeviceError::Kernel(e)
    }
}

/// The driver's device.
#[derive(Debug)]
pub struct Device {
    /// Its identity (PCI segment, bus, device, function).
    pub id: u32,
    /// The interrupt lines set aside for it.
    pub lines: Range<u32>,
    /// One past the highest device address, or 0 where DMA is not confined.
    pub dma_top: u64,
    /// How many times a driver was started for this device before this one
    /// (0 the first time): a driver started again may find its device in
    /// whatever state the last one left it, and resets it.
    pub starts: u32,
    config: Mmio,
    bars: [Option<Mmio>; 6],
}

/// The capability a driver was granted as grant `n`.
pub const fn granted(n: u64) -> Cap {
    Cap(slots::FIRST_GRANT + n)
}

impl Device {
    /// The device this driver was started for, its registers mapped.
    pub fn take(info: &ProcessInfo) -> Result<Device, DeviceError> {
        if (info.grants as usize) < grant::COUNT {
            return Err(DeviceError::NotADriver);
        }
        let frame = |n: u64| match sys::inspect_slot(slots::SPACE, granted(n).0) {
            Ok(Some(s)) if s.ty == ObjectType::Frame => Ok(Some(s.bits)),
            Ok(None) => Ok(None),
            _ => Err(DeviceError::NotADriver),
        };
        let bits = frame(grant::CONFIG)?.ok_or(DeviceError::NotADriver)?;
        let at = mem::map(granted(grant::CONFIG), bits, Rights::READ)?;
        // SAFETY: the device's configuration space, just mapped, for as
        // long as the program runs.
        #[allow(unsafe_code)]
        let config = unsafe { Mmio::new(at, 1 << bits) };
        let mut bars = [None; 6];
        for (i, bar) in bars.iter_mut().enumerate() {
            if let Some(bits) = frame(grant::BAR0 + i as u64)? {
                let at = mem::map(granted(grant::BAR0 + i as u64), bits, Rights(Rights::READ.0 | Rights::WRITE.0))?;
                // SAFETY: the device's registers, just mapped, for as long
                // as the program runs.
                #[allow(unsafe_code)]
                let m = unsafe { Mmio::new(at, 1 << bits) };
                // Registers smaller than a page come as their page: they
                // start where the BAR's address says within it.
                let offset = pci::Config::new(config).bar_address(i).map_or(0, |(a, _)| (a & ((1 << bits) - 1)) as usize);
                *bar = Some(if offset == 0 { m } else { m.part(offset, (1 << bits) - offset).ok_or(DeviceError::NotADriver)? });
            }
        }
        let first = info.args[1] as u32;
        // A fault to commit on purpose, for this run only: test images
        // alone are built with it (`inject`, the `harness` feature).
        #[cfg(feature = "harness")]
        inject::arm((info.args[4] >> 32) as u32);
        Ok(Device {
            id: info.args[0] as u32,
            lines: first..first + info.args[2] as u32,
            dma_top: info.args[3],
            starts: info.args[4] as u32,
            config,
            bars,
        })
    }

    /// A device whose configuration space is `config` (4 KiB) and whose
    /// BARs are `bars`, with `lines` interrupt lines, unconfined, not given
    /// by the device manager: how a test or a fuzzer plays a device against
    /// the code that reads one.
    pub fn over(config: Mmio, bars: [Option<Mmio>; 6], lines: u32) -> Device {
        Device { id: 0, lines: 0..lines, dma_top: 0, starts: 0, config, bars }
    }

    /// MSI-X table entry `index` of the device, and the line that carries
    /// it: where [`irq::Interrupt::bind`] writes the message. An entry
    /// beyond the table, the lines, or the BAR the device says holds the
    /// table is an error.
    pub fn msix_entry(&self, index: u16) -> Result<(u32, Mmio), DeviceError> {
        let pci::Msix { vectors, bar, offset, .. } = self.config().msix().ok_or(DeviceError::Missing("MSI-X"))?;
        let line = self.lines.start.checked_add(index as u32).filter(|l| *l < self.lines.end && index < vectors);
        let line = line.ok_or(DeviceError::Missing("an interrupt line for this MSI-X entry"))?;
        let table = self.bar(bar as usize).ok_or(DeviceError::Protocol("the MSI-X table is in a BAR the device does not have"))?;
        let entry = (offset as usize).checked_add(index as usize * 16).and_then(|at| table.part(at, 16));
        Ok((line, entry.ok_or(DeviceError::Protocol("the MSI-X table lies outside its BAR"))?))
    }

    /// Its configuration space (read-only).
    pub fn config(&self) -> pci::Config {
        pci::Config::new(self.config)
    }

    /// The registers behind memory BAR `index`, if the device has it.
    pub fn bar(&self, index: usize) -> Option<Mmio> {
        self.bars.get(index).copied().flatten()
    }
}
