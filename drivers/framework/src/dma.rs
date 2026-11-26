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
//!
//! Memory from [`Dma::memory`] is one frame: its `2^bits` bytes lie
//! together at consecutive device addresses (and, without an IOMMU, at
//! consecutive physical addresses), and its device address is a multiple
//! of `2^bits` up to 2 MiB (so a page-sized queue is page-aligned). The
//! same holds for [`Dma::share`]. Dropping a [`DmaMemory`] does not take
//! it from the device; keep it for as long as the device may use it.
//!
//! # Ordering
//!
//! The processor may reorder accesses to DMA memory against each other and
//! against registers, as the device sees them. Three barriers say what the
//! device must see in order, and are all a driver needs:
//!
//! - [`write_barrier`] between writing a command, descriptor or index in
//!   DMA memory and telling the device (a doorbell register, or another
//!   index the device reads first);
//! - [`read_barrier`] between reading what says an entry is complete (a
//!   phase bit, a used index) and reading the rest of the entry;
//! - [`full_barrier`] between writing something the device reads and
//!   reading something the device writes when the read decides whether to
//!   tell it (virtio's "notification needed" flag).
//!
//! On x86 the first two only keep the compiler from moving accesses; on Arm
//! they are `dmb oshst` and `dmb oshld`, and the third is `dmb osh` (the
//! outer shareable domain, where devices are).

/// Writes to DMA memory before this are seen by the device before any
/// write after it (to DMA memory or a register). See the module's
/// ordering rules.
#[inline(always)]
pub fn write_barrier() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a barrier: no memory is touched.
    #[allow(unsafe_code)]
    unsafe {
        core::arch::asm!("dmb oshst", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Reads of DMA memory after this see what the device wrote no earlier
/// than reads before it did. See the module's ordering rules.
#[inline(always)]
pub fn read_barrier() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a barrier: no memory is touched.
    #[allow(unsafe_code)]
    unsafe {
        core::arch::asm!("dmb oshld", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Every access before this is seen by the device before every access
/// after it, writes before reads included. See the module's ordering rules.
#[inline(always)]
pub fn full_barrier() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a barrier: no memory is touched.
    #[allow(unsafe_code)]
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

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
    /// Device addresses of shared memory let go of ([`Dma::unshare`]), as
    /// (address, bits), for the next frame of the same size: clients may
    /// add and remove memory any number of times, and the device's
    /// addresses (and the IOMMU's tables under them) are not used up.
    free: core::cell::RefCell<silica_rt::alloc::vec::Vec<(u64, u8)>>,
}

/// Someone else's memory the device was let reach ([`Dma::share`]).
#[derive(Debug)]
pub struct Shared {
    /// The address the device uses for its first byte.
    pub address: u64,
    /// Its size in bits.
    bits: u8,
    /// The slot of the copy of the frame capability the device's mapping
    /// was made through (0 where DMA is not confined).
    copy: u64,
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
    /// The frame it is: what a watched interrupt names (`Interrupt::watch`).
    pub fn frame(&self) -> Cap {
        self.memory.frame()
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
            return Ok(Dma { space: None, top: 0, free: Default::default() });
        }
        let block = mem::alloc(TABLE_BITS)?;
        let slot = free_slot().ok_or(sys::Error::NoMemory)?;
        sys::retype_io_space(block, TABLE_BITS, slots::SPACE, slot).inspect_err(|_| release_slot(slot))?;
        sys::device_attach(granted(grant::IDENTITY), device.id, Cap(slot))?;
        Ok(Dma { space: Some(Cap(slot)), top: device.dma_top, free: Default::default() })
    }

    /// Whether the device is confined to what this `Dma` maps.
    pub fn confined(&self) -> bool {
        self.space.is_some()
    }

    /// From now on every access of `device` the IOMMU refuses signals
    /// `faults` (a notification), and is counted ([`Dma::refused`]).
    /// `Unsupported` where DMA is not confined.
    pub fn watch_faults(&self, device: &Device, faults: Cap) -> Result<(), DeviceError> {
        let space = self.space.ok_or(sys::Error::Unsupported)?;
        sys::device_attach_noting(granted(grant::IDENTITY), device.id, space, faults)?;
        Ok(())
    }

    /// How many accesses of the device the IOMMU has refused (0 where DMA is
    /// not confined).
    pub fn refused(&self) -> u64 {
        self.space.and_then(|s| sys::inspect_io_space(s).ok()).map_or(0, |(_, n)| n)
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
    /// memory, lent to the driver), without mapping it in the driver. The
    /// device loses it again when the lender revokes the frame, or with
    /// [`Dma::unshare`].
    pub fn share(&self, frame: Cap, bits: u8, device_writes: bool) -> Result<Shared, DeviceError> {
        let size = 1usize.checked_shl(bits as u32).ok_or(sys::Error::BadArg)?;
        if self.space.is_none() {
            return self.map_copy(frame, 0, bits, device_writes);
        }
        let reused = {
            let mut free = self.free.borrow_mut();
            free.iter().position(|(_, b)| *b == bits).map(|k| free.swap_remove(k).0)
        };
        let at = match reused {
            Some(at) => at,
            None => mem::reserve(size, size.min(1 << sys::LARGE_BITS)).ok_or(sys::Error::NoMemory)? as u64,
        };
        self.map_copy(frame, at, bits, device_writes).inspect_err(|_| self.free.borrow_mut().push((at, bits)))
    }

    /// The device no longer reaches what `shared` let it reach; when this
    /// returns, the IOMMU has dropped it.
    pub fn unshare(&self, shared: Shared) {
        if shared.copy != 0 {
            // SAFETY: the copy `share` made, used for the device's mapping
            // and nothing else.
            #[allow(unsafe_code)]
            let gone = unsafe { sys::cap_delete(Cap(shared.copy)) };
            release_slot(shared.copy);
            // The IOMMU has dropped the mapping (`Unmap` returns after it
            // has): the device address is free for the next frame.
            if gone.is_ok() {
                self.free.borrow_mut().push((shared.address, shared.bits));
            }
        }
    }

    fn map(&self, frame: Cap, at: u64, device_writes: bool) -> Result<u64, DeviceError> {
        self.map_copy(frame, at, 0, device_writes).map(|s| s.address)
    }

    fn map_copy(&self, frame: Cap, at: u64, bits: u8, device_writes: bool) -> Result<Shared, DeviceError> {
        let Some(space) = self.space else {
            return Ok(Shared { address: sys::frame_address(granted(grant::IDENTITY), frame)?, bits, copy: 0 });
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
        Ok(Shared { address: at, bits, copy })
    }
}
