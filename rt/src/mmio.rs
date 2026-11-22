//! Device registers: memory a device answers, read and written exactly as
//! the program says.
//!
//! An [`Mmio`] is a range of mapped device memory. Every access is one
//! volatile read or write of the stated width at the stated offset, in the
//! machine's byte order (little-endian on every machine Silica runs on, as
//! PCI and virtio registers are), and is checked against the range: an
//! offset a device supplied is never trusted to lie inside it.
#![allow(unsafe_code)]

/// A range of mapped device memory.
#[derive(Clone, Copy, Debug)]
pub struct Mmio {
    base: usize,
    len: usize,
}

macro_rules! access {
    ($read:ident, $write:ident, $t:ty) => {
        /// Read the register at byte `offset`. Panics when it does not lie
        /// in the range or its address is not a multiple of its width (take
        /// offsets from a device through [`Mmio::part`], and check their
        /// alignment where the device chose them).
        pub fn $read(&self, offset: usize) -> $t {
            let p = self.at(offset, core::mem::size_of::<$t>());
            // SAFETY: `at` checked that the access lies inside the range,
            // which `new`'s caller promised is mapped device memory.
            unsafe { core::ptr::read_volatile(p as *const $t) }
        }
        /// Write the register at byte `offset`. Panics as the read does.
        pub fn $write(&self, offset: usize, value: $t) {
            let p = self.at(offset, core::mem::size_of::<$t>());
            // SAFETY: as for the read.
            unsafe { core::ptr::write_volatile(p as *mut $t, value) }
        }
    };
}

impl Mmio {
    /// The `len` bytes of device memory mapped at `base`.
    ///
    /// # Safety
    /// The range must be mapped readable and writable for as long as the
    /// value (and every [`Mmio::part`] of it) is used, and must be memory
    /// whose reads and writes cannot break the program's own state: a
    /// device's registers, not the program's stack or data.
    pub const unsafe fn new(base: usize, len: usize) -> Mmio {
        Mmio { base, len }
    }

    /// The address the range is mapped at.
    pub const fn addr(&self) -> usize {
        self.base
    }

    /// The length of the range in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the range is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `len` bytes from `offset`, or `None` when they do not lie in
    /// this range: how an offset read from a device is taken.
    pub fn part(&self, offset: usize, len: usize) -> Option<Mmio> {
        (offset.checked_add(len)? <= self.len).then_some(Mmio { base: self.base + offset, len })
    }

    fn at(&self, offset: usize, width: usize) -> usize {
        // Aligned as an address, not only as an offset: a range taken at an
        // offset a device chose ([`Mmio::part`]) may itself be misaligned.
        assert!(
            offset.checked_add(width).is_some_and(|end| end <= self.len) && (self.base + offset).is_multiple_of(width),
            "device register access outside its range or misaligned"
        );
        self.base + offset
    }

    access!(read8, write8, u8);
    access!(read16, write16, u16);
    access!(read32, write32, u32);
    access!(read64, write64, u64);
}
