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
    /// A device is there, but the slot's presence changed since it was
    /// last asked: the one seen before was taken out and another (or the
    /// same) put in before the change was read. Its drivers end and the
    /// slot is found again, as for a departure and an arrival.
    Replaced,
}

/// What happened to a slot whose device was there (`was`), given the
/// Slot Status register read now: the change, and whether a device is
/// there now. Presence Detect Changed is a sticky bit: a removal and a
/// re-insertion between two reads set it once and leave Presence Detect
/// State as it was, so a change with a device there both times is a
/// replacement, never nothing (the 2026-11-24 audit: such a swap was
/// invisible, its stale driver left on the new device).
pub fn classify(was: bool, status: u16) -> (Option<Change>, bool) {
    let now = status & PRESENT != 0;
    let change = match (was, now) {
        (false, true) => Some(Change::Arrived),
        (true, false) => Some(Change::Left),
        // Someone asks to take the device out: its drivers end and the
        // slot's power goes off, after which it can be pulled.
        (true, true) if status & BUTTON_PRESSED != 0 => Some(Change::Leaving),
        (true, true) if status & PRESENCE_CHANGED != 0 => Some(Change::Replaced),
        _ => None,
    };
    (change, now)
}

/// The Slot Status bits to write back after reading `status`: exactly the
/// change bits that were set when it was read. They are write-1-to-clear,
/// so a change that happens after the read keeps its bit (it is written as
/// 0) and raises the next interrupt; writing back more would lose it.
pub fn to_clear(status: u16) -> u16 {
    status & (BUTTON_PRESSED | PRESENCE_CHANGED | COMMAND_COMPLETED | LINK_CHANGED)
}

/// Whether a hot-plug port on bus `bus`, whose bridge says the buses
/// behind it are `secondary` to `subordinate`, may be trusted with them:
/// behind it (above its own bus), in order, within the segment's last bus
/// (`last`), and overlapping no other bridge's buses except by nesting
/// (`others`: each other bridge's secondary and subordinate). A device
/// found on buses a port does not own would be given addresses out of the
/// port's windows, re-placing a live device's registers (the audit: the
/// numbers were used as the bridge gave them).
pub fn buses_valid(bus: u8, secondary: u8, subordinate: u8, last: u8, others: &[(u8, u8)]) -> bool {
    // `a` behind `b`: its first bus after `b`'s own (a bridge behind another
    // sits on one of its buses and numbers buses after it).
    let behind = |a: (u8, u8), b: (u8, u8)| b.0 < a.0 && a.1 <= b.1;
    secondary > bus
        && secondary <= subordinate
        && subordinate <= last
        && others.iter().all(|&o| {
            let disjoint = o.1 < secondary || subordinate < o.0;
            let own = (secondary, subordinate);
            disjoint || behind(own, o) || behind(o, own)
        })
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
    /// `2^bits` bytes at a multiple of their size; for a 32-bit BAR
    /// (`wide` false) below 4 GiB, which is all its register can say.
    fn take(&mut self, bits: u8, wide: bool) -> Option<u64> {
        let size = 1u64 << bits;
        let at = self.next.checked_add(size - 1)? & !(size - 1);
        let end = at.checked_add(size)?;
        let limit = if wide { self.end } else { self.end.min(1 << 32) };
        (end <= limit).then(|| {
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
        // A limit at the very top of the address space (a 64-bit window's
        // upper half all ones) gives up its last byte rather than wrap.
        let window = |base: u64, limit: u64| (base <= limit).then_some(Window { next: base, end: limit.saturating_add(1) });
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
    /// switches it on), with its indicator. It returns at once: whether the
    /// link has come up is [`Port::link_up`]'s, asked while the device
    /// manager goes on serving (before, it waited here for up to a second,
    /// and every client and fault report with it).
    pub fn power(&self, on: bool) {
        let r = self.config.registers();
        if self.powered {
            let control = r.read16(self.express + SLOT_CONTROL) & !(POWER_OFF | POWER_INDICATOR);
            r.write16(self.express + SLOT_CONTROL, control | if on { INDICATOR_ON } else { POWER_OFF | POWER_INDICATOR });
        }
    }

    /// Whether the link to the slot's device is up.
    pub fn link_up(&self) -> bool {
        self.config.registers().read16(self.express + LINK_STATUS) & LINK_ACTIVE != 0
    }

    /// After the interrupt (or once after arming): what happened to the
    /// slot since it was last asked ([`classify`]).
    pub fn changed(&mut self) -> Option<Change> {
        let r = self.config.registers();
        let status = r.read16(self.express + SLOT_STATUS);
        let news = to_clear(status);
        if news != 0 {
            r.write16(self.express + SLOT_STATUS, news);
        }
        // Present is what counts: an unpowered slot's link is down until
        // the system powers it (`power`).
        let (change, now) = classify(self.occupied, status);
        self.occupied = now;
        if !now || change == Some(Change::Replaced) {
            self.empty();
        }
        change
    }

    /// The slot is empty (or about to be found again): its windows are
    /// all the next device's.
    pub fn empty(&mut self) {
        (self.memory, self.prefetchable) = self.windows;
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
                // Prefetchable memory from its own window when the port has
                // one with room (a 32-bit BAR: below 4 GiB), else from the
                // plain window, where any BAR may go.
                let mut at = None;
                if prefetch {
                    at = self.prefetchable.as_mut().and_then(|w| w.take(bits, wide));
                }
                if at.is_none() {
                    at = self.memory.as_mut().and_then(|w| w.take(bits, wide));
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A removal and re-insertion between two reads of the slot leaves one
    /// Presence Detect Changed and a device present both times: before,
    /// that read as nothing (`None`), the new device kept the driver of
    /// the one taken out and was never given addresses or its own.
    #[test]
    fn a_swap_between_two_reads_is_a_replacement() {
        assert_eq!(classify(true, PRESENT | PRESENCE_CHANGED), (Some(Change::Replaced), true));
        assert_eq!(classify(true, PRESENT | PRESENCE_CHANGED | LINK_CHANGED), (Some(Change::Replaced), true));
        // A link change alone (the slot was just powered) is no change.
        assert_eq!(classify(true, PRESENT | LINK_CHANGED), (None, true));
        assert_eq!(classify(false, PRESENT | PRESENCE_CHANGED), (Some(Change::Arrived), true));
        assert_eq!(classify(true, PRESENCE_CHANGED), (Some(Change::Left), false));
        assert_eq!(classify(true, PRESENT | BUTTON_PRESSED | PRESENCE_CHANGED), (Some(Change::Leaving), true));
        assert_eq!(classify(false, 0), (None, false));
    }

    /// Only the change bits that were read are written back: a change after
    /// the read keeps its bit and raises the next interrupt.
    #[test]
    fn only_the_bits_read_are_cleared() {
        assert_eq!(to_clear(PRESENT | PRESENCE_CHANGED), PRESENCE_CHANGED);
        assert_eq!(to_clear(PRESENT | LINK_ACTIVE_IN_STATUS_NEVER), 0);
        assert_eq!(to_clear(0xFFFF), BUTTON_PRESSED | PRESENCE_CHANGED | COMMAND_COMPLETED | LINK_CHANGED);
    }
    const LINK_ACTIVE_IN_STATUS_NEVER: u16 = 1 << 13;

    /// A port's bus numbers are taken only when they are its own: behind
    /// it, in order, within the segment, overlapping no other bridge but by
    /// nesting.
    #[test]
    fn bus_numbers_a_bridge_cannot_own_are_refused() {
        let others = [(1, 1), (2, 4), (3, 3)];
        assert!(buses_valid(0, 5, 5, 255, &others));
        assert!(buses_valid(2, 3, 3, 255, &[(1, 1), (2, 4)]), "nested in its parent's range");
        assert!(!buses_valid(0, 0, 0, 255, &others), "its own bus (bus 0 is the machine's)");
        assert!(!buses_valid(4, 2, 2, 255, &[]), "below its own bus");
        assert!(!buses_valid(0, 6, 5, 255, &others), "out of order");
        assert!(!buses_valid(0, 5, 9, 8, &others), "past the segment's last bus");
        assert!(!buses_valid(0, 1, 1, 255, &others), "another bridge's bus");
        assert!(!buses_valid(0, 3, 6, 255, &others), "overlapping another bridge's range");
        assert!(!buses_valid(0, 1, 5, 255, &[(1, 1)]), "another bridge starting at its own first bus");
    }
}
