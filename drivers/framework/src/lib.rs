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
//! DMA), 4 how many times a driver was started for this device before.
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
//! identifiers, else the first that names its class. The owner can put
//! another program in a driver's place for one kind of device with
//! `driver=<vendor>:<device>=<program>` on the kernel command line.
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
//! them), its device is silenced, and it is started again, at most three
//! times; [`Device::starts`] says how many times it has been. Its clients
//! see `peer_gone` and open the new one. A driver that exits with 0 is not
//! started again. Reading memory a client lent it (`silica_rt::mem::map_peer`)
//! never faults: memory the client took back reads as zeros.
//!
//! A device is not trusted. Every offset and length read from one is
//! checked before use ([`Mmio::part`](silica_rt::mmio::Mmio::part)), and a
//! device that answers nonsense gets an error, never a panic.
#![no_std]
#![deny(unsafe_code)]

pub mod dma;
pub mod irq;
pub mod pci;
pub mod virtio;

use core::ops::Range;
use silica_rt::mmio::Mmio;
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{ProcessInfo, mem, slots};

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
                *bar = Some(m);
            }
        }
        let first = info.args[1] as u32;
        Ok(Device {
            id: info.args[0] as u32,
            lines: first..first + info.args[2] as u32,
            dma_top: info.args[3],
            starts: info.args[4] as u32,
            config,
            bars,
        })
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
