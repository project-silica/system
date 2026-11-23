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

    /// The 32-bit word at `offset` of memory another program shares, read
    /// as an atomic with acquire ordering: everything its writer wrote
    /// before the [`Mmio::store_release32`] of the value read is seen
    /// after. Panics as [`Mmio::read32`] does.
    pub fn load_acquire32(&self, offset: usize) -> u32 {
        self.word32(offset).load(core::sync::atomic::Ordering::Acquire)
    }

    /// Write the 32-bit word at `offset` as an atomic with release
    /// ordering, after everything written before it (see
    /// [`Mmio::load_acquire32`]). Panics as [`Mmio::write32`] does.
    pub fn store_release32(&self, offset: usize, value: u32) {
        self.word32(offset).store(value, core::sync::atomic::Ordering::Release);
    }

    fn word32(&self, offset: usize) -> &core::sync::atomic::AtomicU32 {
        let p = self.at(offset, 4);
        // SAFETY: `at` checked that the word lies inside the range, which
        // `new`'s caller promised is mapped, and is aligned for a u32; an
        // atomic is how memory another program writes concurrently may be
        // accessed. The reference lives no longer than `self`.
        unsafe { core::sync::atomic::AtomicU32::from_ptr(p as *mut u32) }
    }

    /// Copy `out.len()` bytes from `offset` into `out`, each byte read once:
    /// what memory a device or another program may be writing holds is
    /// taken as one copy, and then parsed from there (reading it in place
    /// twice could see two different things). Eight bytes at a time where
    /// the address allows. Panics when the range does not lie inside.
    pub fn read_bytes(&self, offset: usize, out: &mut [u8]) {
        assert!(offset.checked_add(out.len()).is_some_and(|end| end <= self.len), "device memory copy outside its range");
        let base = self.base + offset;
        let mut i = 0;
        while i < out.len() {
            let p = base + i;
            if p.is_multiple_of(8) && out.len() - i >= 8 {
                // SAFETY: inside the checked range, aligned for a u64.
                let v = unsafe { core::ptr::read_volatile(p as *const u64) };
                out[i..i + 8].copy_from_slice(&v.to_ne_bytes());
                i += 8;
            } else {
                // SAFETY: inside the checked range.
                out[i] = unsafe { core::ptr::read_volatile(p as *const u8) };
                i += 1;
            }
        }
    }

    /// Copy `bytes` to `offset`, each byte written once, eight at a time
    /// where the address allows. Panics when the range does not lie inside.
    pub fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        assert!(offset.checked_add(bytes.len()).is_some_and(|end| end <= self.len), "device memory copy outside its range");
        let base = self.base + offset;
        let mut i = 0;
        while i < bytes.len() {
            let p = base + i;
            if p.is_multiple_of(8) && bytes.len() - i >= 8 {
                let mut w = [0u8; 8];
                w.copy_from_slice(&bytes[i..i + 8]);
                // SAFETY: inside the checked range, aligned for a u64.
                unsafe { core::ptr::write_volatile(p as *mut u64, u64::from_ne_bytes(w)) };
                i += 8;
            } else {
                // SAFETY: inside the checked range.
                unsafe { core::ptr::write_volatile(p as *mut u8, bytes[i]) };
                i += 1;
            }
        }
    }
}
