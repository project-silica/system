//! Memory a device reaches.
//!
//! On a machine with an IOMMU a device reaches nothing until its driver
//! attaches it to a device address space and maps frames there; this module
//! does both. The address a device is given for a frame is the address the
//! frame has in the driver ([`Dma::memory`]) or an address reserved for it
//! ([`Dma::share`]): the driver never learns physical addresses and has no
//! use for them.
//!
//! On a machine without one (`Device::dma_top` is 0) nothing confines the
//! device: the same calls return physical addresses, and the device
//! manager's decision to start the driver at all was a decision to trust
//! it with the machine. A driver is written once for both.

use crate::{Device, DeviceError, grant, granted};
use silica_rt::ipc::{free_slot, release_slot};
use silica_rt::mem::{self, Memory};
use silica_rt::mmio::Mmio;
use silica_rt::slots;
use silica_rt::sys::{self, Cap, Rights};

/// Size in bits of the device address space's table memory: 64 KiB, the
/// root and 14 tables, which maps some 20 MiB of small frames that lie
/// together (and any amount in 2 MiB frames).
const TABLE_BITS: u8 = 16;

/// The device's view of memory.
#[derive(Debug)]
pub struct Dma {
    /// The device address space; `None` where DMA is not confined.
    space: Option<Cap>,
    top: u64,
}

/// Memory the driver and its device share: mapped in the driver, and
/// reachable by the device at [`DmaMemory::device_address`].
#[derive(Debug)]
pub struct DmaMemory {
    memory: Memory,
    device_address: u64,
}

impl DmaMemory {
    /// The address the device uses for the first byte.
    pub fn device_address(&self) -> u64 {
        self.device_address
    }
    /// The address the driver uses for the first byte.
    pub fn addr(&self) -> usize {
        self.memory.addr()
    }
    /// The size in bytes.
    pub fn len(&self) -> usize {
        self.memory.len()
    }
    /// Whether it is empty (never).
    pub fn is_empty(&self) -> bool {
        false
    }
    /// The memory as the driver reads and writes it: like registers, one
    /// access at a time, because the device may be writing it too. Nothing
    /// read from it is trusted.
    pub fn shared(&self) -> Mmio {
        // SAFETY: memory of this value's own frame, mapped for as long as
        // the value lives (it is never unmapped), holding no Rust object.
        #[allow(unsafe_code)]
        unsafe {
            Mmio::new(self.memory.addr(), self.memory.len())
        }
    }
}

impl Dma {
    /// Give the device its own, empty view of memory: from here on it
    /// reaches exactly what this `Dma` maps for it.
    pub fn new(device: &Device) -> Result<Dma, DeviceError> {
        if device.dma_top == 0 {
            return Ok(Dma { space: None, top: 0 });
        }
        let block = mem::alloc(TABLE_BITS)?;
        let slot = free_slot().ok_or(sys::Error::NoMemory)?;
        sys::retype_io_space(block, TABLE_BITS, slots::SPACE, slot).inspect_err(|_| release_slot(slot))?;
        sys::device_attach(granted(grant::IDENTITY), device.id, Cap(slot))?;
        Ok(Dma { space: Some(Cap(slot)), top: device.dma_top })
    }

    /// Whether the device is confined to what this `Dma` maps.
    pub fn confined(&self) -> bool {
        self.space.is_some()
    }

    /// New zeroed memory of `2^bits` bytes that the driver reads and writes
    /// and the device reads, and with `device_writes` also writes.
    pub fn memory(&self, bits: u8, device_writes: bool) -> Result<DmaMemory, DeviceError> {
        let memory = Memory::new(bits)?;
        // The device's address for it is the driver's own.
        let device_address = self.map(memory.frame(), memory.addr() as u64, device_writes)?;
        Ok(DmaMemory { memory, device_address })
    }

    /// Let the device reach `frame` (of `2^bits` bytes; someone else's
    /// memory, lent to the driver), without mapping it in the driver.
    /// Returns the address the device uses for it. The device loses it
    /// again when the lender revokes the frame.
    pub fn share(&self, frame: Cap, bits: u8, device_writes: bool) -> Result<u64, DeviceError> {
        let size = 1usize.checked_shl(bits as u32).ok_or(sys::Error::BadArg)?;
        let at = mem::reserve(size, size.min(1 << sys::LARGE_BITS)).ok_or(sys::Error::NoMemory)?;
        self.map(frame, at as u64, device_writes)
    }

    fn map(&self, frame: Cap, at: u64, device_writes: bool) -> Result<u64, DeviceError> {
        let Some(space) = self.space else {
            return Ok(sys::frame_address(granted(grant::IDENTITY), frame)?);
        };
        if at >= self.top {
            return Err(DeviceError::Missing("device addresses as high as this driver's memory"));
        }
        // One frame capability maps in one place: the device's mapping is
        // made through a copy, which goes when the original does.
        let copy = free_slot().ok_or(sys::Error::NoMemory)?;
        let rights = Rights(Rights::READ.0 | if device_writes { Rights::WRITE.0 } else { 0 });
        sys::cap_derive(slots::SPACE, copy, frame, rights, 0).inspect_err(|_| release_slot(copy))?;
        if let Err(e) = sys::map(space, Cap(copy), at as usize, rights) {
            // SAFETY: the copy made above, mapped nowhere.
            #[allow(unsafe_code)]
            let _ = unsafe { sys::cap_delete(Cap(copy)) };
            release_slot(copy);
            return Err(e.into());
        }
        Ok(at)
    }
}
