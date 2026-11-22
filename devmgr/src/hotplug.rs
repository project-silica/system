//! Native PCI Express hot-plug: a device put into a slot of a hot-plug
//! capable port while the system runs is found, given addresses and a
//! driver; one taken out loses its driver (PCI Express Base Specification,
//! sections 6.7 and 7.5.3: the slot registers of the port's PCI Express
//! capability).
//!
//! At start the device manager arms every such port: its slot interrupts
//! (presence detect and data link layer state changes) through the port's
//! own MSI-X entry 0, bound to the device manager's notification with the
//! bit [`HOTPLUG`]. On that bit it asks each port what changed. A device
//! that arrives has no addresses: the firmware left the port's memory
//! windows for it, and the device manager hands its BARs out of them, the
//! smallest windows first, each BAR at a multiple of its size.
//!
//! The firmware decides how big a port's windows are (QEMU's root ports:
//! `mem-reserve`, `pref64-reserve`); a device whose BARs do not fit is
//! left alone, and said so.

use silica_driver::pci::{CAP_EXPRESS, COMMAND_MASTER, COMMAND_MEMORY, Config};

/// The bit of the device manager's notification a slot's change sets.
pub const HOTPLUG: u64 = 2;

// The PCI Express capability's registers, from its start.
const CAPS: usize = 0x02;
const LINK_STATUS: usize = 0x12;
const SLOT_CAPS: usize = 0x14;
const SLOT_CONTROL: usize = 0x18;
const SLOT_STATUS: usize = 0x1A;
/// PCI Express Capabilities: the port has a slot.
const SLOT_IMPLEMENTED: u16 = 1 << 8;
/// Slot Capabilities: the slot can take a device while the system runs;
/// it has a power controller (the slot's power is the system's to switch).
const HOT_PLUG_CAPABLE: u32 = 1 << 6;
const POWER_CONTROLLER: u32 = 1 << 1;
/// Slot Control: the power indicator (bits 8, 9: 01 on, 11 off), the power
/// controller (bit 10: 1 off).
const POWER_INDICATOR: u16 = 3 << 8;
const INDICATOR_ON: u16 = 1 << 8;
const POWER_OFF: u16 = 1 << 10;
/// Slot Control: interrupts for the attention button, presence changes,
/// the link, at all.
const BUTTON_ENABLE: u16 = 1;
const PRESENCE_ENABLE: u16 = 1 << 3;
const INTERRUPT_ENABLE: u16 = 1 << 5;
const LINK_ENABLE: u16 = 1 << 12;
/// Slot Status (each cleared by writing it back): the attention button was
/// pressed (someone asks to take the device out), presence changed, a
/// command completed, a device is present, the link changed.
const BUTTON_PRESSED: u16 = 1;
const PRESENCE_CHANGED: u16 = 1 << 3;
const COMMAND_COMPLETED: u16 = 1 << 4;
const PRESENT: u16 = 1 << 6;
const LINK_CHANGED: u16 = 1 << 8;
/// Link Status: the link to the device is up.
const LINK_ACTIVE: u16 = 1 << 13;

/// What happened to a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// A device was put in.
    Arrived,
    /// Someone asks to take the device out (the attention button).
    Leaving,
    /// The device is gone.
    Left,
}

/// A BAR that did not fit: its index, its size in bits, and the port's
/// plain and prefetchable windows as they were (next free address, end).
pub type Misfit = (usize, u8, Option<(u64, u64)>, Option<(u64, u64)>);

/// A window of addresses behind a port, handed out upward.
#[derive(Clone, Copy, Debug)]
struct Window {
    next: u64,
    end: u64,
}

impl Window {
    fn take(&mut self, bits: u8) -> Option<u64> {
        let size = 1u64 << bits;
        let at = self.next.checked_add(size - 1)? & !(size - 1);
        let end = at.checked_add(size)?;
        (end <= self.end).then(|| {
            self.next = end;
            at
        })
    }
}

/// A hot-plug capable port.
pub struct Port {
    /// Its identity, as the kernel takes it.
    pub id: u32,
    pub config: Config,
    express: usize,
    /// The buses behind it.
    pub secondary: u8,
    pub subordinate: u8,
    /// Its memory windows: plain, and prefetchable.
    memory: Option<Window>,
    prefetchable: Option<Window>,
    /// The windows as the firmware left them: all theirs again when the
    /// slot empties.
    windows: (Option<Window>, Option<Window>),
    /// Whether a device is in the slot, as last seen.
    pub occupied: bool,
    /// Whether the slot's power is the system's to switch.
    powered: bool,
}

impl Port {
    /// `config` as a hot-plug port, if it is one.
    pub fn of(id: u32, config: Config) -> Option<Port> {
        let (_, express) = config.capabilities().find(|(c, _)| *c == CAP_EXPRESS)?;
        let r = config.registers();
        if r.read16(express + CAPS) & SLOT_IMPLEMENTED == 0 || r.read32(express + SLOT_CAPS) & HOT_PLUG_CAPABLE == 0 {
            return None;
        }
        let window = |base: u64, limit: u64| (base <= limit).then_some(Window { next: base, end: limit + 1 });
        // Bits 15..4 of the base and limit registers are address bits 31..20.
        let memory = window(((r.read16(0x20) & 0xFFF0) as u64) << 16, ((r.read16(0x22) & 0xFFF0) as u64) << 16 | 0xF_FFFF);
        let (pb, pl) = (r.read16(0x24), r.read16(0x26));
        let wide = pb & 0xF == 1;
        let upper = |at: usize| if wide { (r.read32(at) as u64) << 32 } else { 0 };
        let prefetchable = window(((pb & 0xFFF0) as u64) << 16 | upper(0x28), ((pl & 0xFFF0) as u64) << 16 | 0xF_FFFF | upper(0x2C));
        let occupied = r.read16(express + SLOT_STATUS) & PRESENT != 0;
        let windows = (memory, prefetchable);
        let powered = r.read32(express + SLOT_CAPS) & POWER_CONTROLLER != 0;
        Some(Port {
            id,
            config,
            express,
            secondary: r.read8(0x19),
            subordinate: r.read8(0x1A),
            memory,
            prefetchable,
            windows,
            occupied,
            powered,
        })
    }

    /// Let the slot interrupt, through the port's MSI-X entry 0 (already
    /// written by the caller): the port may send it, and its MSI-X is on.
    pub fn arm(&self) {
        let r = self.config.registers();
        r.write16(4, r.read16(4) | COMMAND_MEMORY | COMMAND_MASTER);
        if let Some(m) = self.config.msix() {
            // Enabled, the function's mask off.
            r.write16(m.cap + 2, (r.read16(m.cap + 2) | 1 << 15) & !(1 << 14));
        }
        // The interrupts on; what changed before is looked at by the caller
        // asking (`changed`) once now.
        r.write16(
            self.express + SLOT_CONTROL,
            r.read16(self.express + SLOT_CONTROL) | BUTTON_ENABLE | PRESENCE_ENABLE | LINK_ENABLE | INTERRUPT_ENABLE,
        );
    }

    /// Switch the slot's power on or off (a slot with a power controller
    /// keeps a device it holds unpowered, and invisible, until the system
    /// switches it on), with its indicator. When switching on, wait until
    /// the link to the device is up (at most a second): false if it never is.
    pub fn power(&self, on: bool) -> bool {
        let r = self.config.registers();
        if self.powered {
            let control = r.read16(self.express + SLOT_CONTROL) & !(POWER_OFF | POWER_INDICATOR);
            r.write16(self.express + SLOT_CONTROL, control | if on { INDICATOR_ON } else { POWER_OFF | POWER_INDICATOR });
        }
        if !on {
            return true;
        }
        let clock = silica_rt::clock();
        let until = clock.now() + 1_000_000_000;
        while r.read16(self.express + LINK_STATUS) & LINK_ACTIVE == 0 {
            if clock.now() > until {
                return false;
            }
            libsys::yield_now();
        }
        true
    }

    /// After the interrupt (or once after arming): what happened to the
    /// slot since it was last asked.
    pub fn changed(&mut self) -> Option<Change> {
        let r = self.config.registers();
        let status = r.read16(self.express + SLOT_STATUS);
        let news = status & (BUTTON_PRESSED | PRESENCE_CHANGED | COMMAND_COMPLETED | LINK_CHANGED);
        if news != 0 {
            r.write16(self.express + SLOT_STATUS, news);
        }
        // Present is what counts: an unpowered slot's link is down until
        // the system powers it (`power`).
        let now = status & PRESENT != 0;
        let was = core::mem::replace(&mut self.occupied, now);
        if !now {
            (self.memory, self.prefetchable) = self.windows;
        }
        match (was, now) {
            (false, true) => Some(Change::Arrived),
            (true, false) => Some(Change::Left),
            // The device is still there, and someone asks to take it out:
            // its drivers end and the slot's power goes off, after which it
            // can be pulled (and its absence reported).
            (true, true) if status & BUTTON_PRESSED != 0 => Some(Change::Leaving),
            _ => None,
        }
    }

    /// Give every memory BAR of the arrived function `f` an address out of
    /// the port's windows. When one does not fit: which, how large, and the
    /// windows as they are.
    pub fn place(&mut self, f: &Config) -> Result<(), Misfit> {
        let mut i = 0;
        while i < 6 {
            let Some((_, wide)) = f.bar_address(i) else {
                i += 1;
                continue;
            };
            if let Some((bits, prefetch)) = f.bar_size(i) {
                let bits = bits.max(12);
                // Prefetchable memory from its own window when the port has one.
                let at = match (prefetch, self.prefetchable.as_mut()) {
                    (true, Some(w)) => w.take(bits),
                    _ => self.memory.as_mut().and_then(|w| w.take(bits)),
                };
                let Some(at) = at else {
                    let w = |w: Option<Window>| w.map(|w| (w.next, w.end));
                    return Err((i, bits, w(self.memory), w(self.prefetchable)));
                };
                f.set_bar(i, at);
            }
            i += if wide { 2 } else { 1 };
        }
        Ok(())
    }
}
