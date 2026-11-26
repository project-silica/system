//! PCI configuration space, as a function's 4 KiB of registers (PCI
//! Express ECAM). Read by the device manager to find devices and by a
//! driver to find its device's capabilities; only the device manager, which
//! maps it writable, changes it.

use silica_rt::mmio::Mmio;

/// The vendor ID a function that is not there reads as.
pub const NO_DEVICE: u16 = 0xFFFF;
/// Capability ID: MSI-X.
pub const CAP_MSIX: u8 = 0x11;
/// Capability ID: vendor-specific (virtio's structures).
pub const CAP_VENDOR: u8 = 0x09;
/// Capability ID: PCI Express.
pub const CAP_EXPRESS: u8 = 0x10;
/// Command register bit: answer memory accesses.
pub const COMMAND_MEMORY: u16 = 1 << 1;
/// Command register bit: may start DMA and send message interrupts.
pub const COMMAND_MASTER: u16 = 1 << 2;
/// Command register bit: do not raise the legacy interrupt wire.
pub const COMMAND_NO_INTX: u16 = 1 << 10;

/// One function's configuration space.
#[derive(Clone, Copy, Debug)]
pub struct Config(Mmio);

/// A memory BAR as the firmware set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    /// Physical address of the registers.
    pub base: u64,
    /// Size in bits.
    pub bits: u8,
}

/// Where a function's MSI-X table is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix {
    /// Offset of the capability in configuration space.
    pub cap: usize,
    /// How many interrupts the function can raise.
    pub vectors: u16,
    /// The BAR holding the table, and the table's offset in it.
    pub bar: u8,
    /// See `bar`.
    pub offset: u32,
}

impl Config {
    /// The configuration space mapped at `space` (at least 256 bytes).
    pub fn new(space: Mmio) -> Config {
        Config(space)
    }

    /// The registers themselves.
    pub fn registers(&self) -> Mmio {
        self.0
    }

    /// Vendor ID ([`NO_DEVICE`] when there is no function here).
    pub fn vendor(&self) -> u16 {
        self.0.read16(0)
    }

    /// Device ID.
    pub fn device(&self) -> u16 {
        self.0.read16(2)
    }

    /// Class code: base class, subclass, programming interface.
    pub fn class(&self) -> (u8, u8, u8) {
        let v = self.0.read32(8);
        ((v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8)
    }

    /// The header type: 0 a device, 1 a bridge to another bus.
    pub fn header(&self) -> u8 {
        self.0.read8(0x0E) & 0x7F
    }

    /// Whether the device has more functions than function 0.
    pub fn multifunction(&self) -> bool {
        self.0.read8(0x0E) & 0x80 != 0
    }

    /// For a bridge: the bus behind it.
    pub fn secondary_bus(&self) -> u8 {
        self.0.read8(0x19)
    }

    /// Each capability's ID and offset, following the list as far as it is
    /// well formed (a list that loops or leaves configuration space ends).
    pub fn capabilities(&self) -> impl Iterator<Item = (u8, usize)> + '_ {
        let mut at = if self.0.read16(6) & 1 << 4 != 0 { self.0.read8(0x34) as usize & !3 } else { 0 };
        let mut left = 48; // more capabilities than fit in 256 bytes
        core::iter::from_fn(move || {
            if !(0x40..=0xFC).contains(&at) || left == 0 {
                return None;
            }
            left -= 1;
            let here = at;
            let id = self.0.read8(here);
            at = self.0.read8(here + 1) as usize & !3;
            Some((id, here))
        })
    }

    /// The function's MSI-X capability, if it has one whose eight bytes lie
    /// in the space that is mapped: the device says where the capability
    /// is, and one it puts in the last four bytes of a 256-byte space has
    /// its table register beyond them (the `virtio_transport` fuzz target's
    /// first finding: the read panicked).
    pub fn msix(&self) -> Option<Msix> {
        let (_, cap) = self.capabilities().find(|(id, at)| *id == CAP_MSIX && at + 8 <= self.0.len())?;
        let table = self.0.read32(cap + 4);
        Some(Msix { cap, vectors: (self.0.read16(cap + 2) & 0x7FF) + 1, bar: (table & 7) as u8, offset: table & !7 })
    }

    /// Memory BAR `index` as it is now, without its size: its address, and
    /// whether it takes two registers (64 bits). `None` for an I/O port BAR
    /// or an index beyond the header's BARs (six for a device, two for a
    /// bridge, none for a header type this does not know), including a
    /// 64-bit BAR whose upper half would lie beyond them.
    pub fn bar_address(&self, index: usize) -> Option<(u64, bool)> {
        let count = match self.header() {
            0 => 6,
            1 => 2,
            _ => 0,
        };
        if index >= count {
            return None;
        }
        let lo = self.0.read32(0x10 + index * 4);
        if lo & 1 != 0 {
            return None;
        }
        let wide = lo >> 1 & 3 == 2;
        if wide && index + 1 >= count {
            return None;
        }
        let hi = if wide { self.0.read32(0x14 + index * 4) } else { 0 };
        Some(((hi as u64) << 32 | (lo & !0xF) as u64, wide))
    }

    /// Find the size of memory BAR `index` the way the PCI specification
    /// says: with the function's decoding off, write all ones, read back
    /// which bits stick, and put the address back. Needs configuration
    /// space mapped writable; only the device manager calls it, before any
    /// driver runs. `None` where there is no memory BAR or it is not set.
    pub fn probe_bar(&self, index: usize) -> Option<Bar> {
        let (base, _) = self.bar_address(index)?;
        let (bits, _) = self.bar_size(index)?;
        // A BAR nobody assigned, or one whose address is not aligned to its size.
        if base == 0 || base & ((1 << bits) - 1) != 0 {
            return None;
        }
        Some(Bar { base, bits })
    }

    /// The size of memory BAR `index` in bits, whatever its address, and
    /// whether it is prefetchable; as [`Config::probe_bar`] finds it (and
    /// with the same needs). `None` where there is no memory BAR or its
    /// answer makes no sense.
    pub fn bar_size(&self, index: usize) -> Option<(u8, bool)> {
        let (_, wide) = self.bar_address(index)?;
        let (lo_at, hi_at) = (0x10 + index * 4, 0x14 + index * 4);
        let command = self.0.read16(4);
        self.0.write16(4, command & !(COMMAND_MEMORY | 1));
        let lo = self.0.read32(lo_at);
        self.0.write32(lo_at, !0);
        let low = self.0.read32(lo_at) & !0xF;
        let mut mask = low as u64 | 0xFFFF_FFFF_0000_0000;
        self.0.write32(lo_at, lo);
        let mut high = 0;
        if wide {
            let hi = self.0.read32(hi_at);
            self.0.write32(hi_at, !0);
            high = self.0.read32(hi_at);
            mask = (mask & 0xFFFF_FFFF) | (high as u64) << 32;
            self.0.write32(hi_at, hi);
        }
        self.0.write16(4, command);
        // A BAR the function does not implement keeps no bit of the ones.
        if low == 0 && high == 0 {
            return None;
        }
        let bits = mask.trailing_zeros() as u8;
        if bits >= 48 || mask != !0u64 << bits {
            return None;
        }
        Some((bits, lo & 1 << 3 != 0))
    }

    /// Put memory BAR `index` at `base` (a multiple of its size; the
    /// function's decoding off while it moves). Only the device manager.
    pub fn set_bar(&self, index: usize, base: u64) {
        let Some((_, wide)) = self.bar_address(index) else { return };
        let command = self.0.read16(4);
        self.0.write16(4, command & !(COMMAND_MEMORY | 1));
        let lo_at = 0x10 + index * 4;
        self.0.write32(lo_at, base as u32 | (self.0.read32(lo_at) & 0xF));
        if wide {
            self.0.write32(lo_at + 4, (base >> 32) as u32);
        }
        self.0.write16(4, command);
    }
}
