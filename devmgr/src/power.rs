//! The machine's ACPI fixed power button: the PM1 event registers and the
//! SCI, as the FADT names them. The other ACPI events (general-purpose
//! events, the embedded controller) need the AML interpreter (E03): they
//! are switched off here, so the shared interrupt line stays quiet.

use crate::Manager;
use libsys::{self as sys, Cap, ObjectType, Rights};
use silica_formats::acpi;
use silica_rt::mem::Object;

/// PM1 status and enable bit of the fixed power button.
const PWRBTN: u16 = 1 << 8;

/// The power button, its interrupt bound to a notification.
pub struct Button {
    ports: Cap,
    lines: Cap,
    status: u16,
    sci: u32,
    note: Object,
}

impl Button {
    /// Find the button in the FADT, quiet every other ACPI event, and let
    /// the button interrupt.
    pub fn new(m: &mut Manager, ports: Cap, lines: Cap) -> Result<Button, &'static str> {
        if !matches!(sys::inspect_slot(silica_rt::slots::SPACE, ports.0), Ok(Some(_))) {
            return Err("this machine has no I/O ports");
        }
        let rsdp = m.info.rsdp;
        let mut read = |a: u64, b: &mut [u8]| m.read(a, b);
        let (fadt_at, len) = acpi::find_table(&mut read, rsdp, b"FACP").ok_or("no FADT")?;
        let mut fadt = [0u8; 280];
        let n = (len as usize).min(fadt.len());
        if !m.read(fadt_at, &mut fadt[..n]) {
            return Err("the FADT cannot be read");
        }
        let p = acpi::power(&fadt[..n]).ok_or("the FADT makes no sense")?;
        let (status, half) = (p.pm1_event[0], p.pm1_event_len as u16 / 2);
        if status == 0 || half < 2 {
            return Err("the FADT names no PM1 event block");
        }
        let out16 = |port: u16, v: u16| sys::port_out(ports, port, 2, v as u32);
        let out8 = |port: u16, v: u8| sys::port_out(ports, port, 1, v as u32);
        // General-purpose events off, and their status cleared.
        let (gpe, gpe_len) = (p.gpe0.0, p.gpe0.1 as u16 / 2);
        for i in 0..gpe_len {
            let _ = out8(gpe + gpe_len + i, 0);
            let _ = out8(gpe + i, 0xFF);
        }
        // Only the power button among the fixed events; its old status gone.
        out16(status + half, PWRBTN).map_err(|_| "the PM1 enable register cannot be written")?;
        out16(status, 0xFFFF).map_err(|_| "the PM1 status register cannot be written")?;
        // The SCI: level-triggered, active low, unless the MADT says otherwise.
        let sci = p.sci as u32;
        let flags = interrupt_flags(m, sci).unwrap_or(sys::IRQ_LEVEL | sys::IRQ_ACTIVE_LOW);
        let note = Object::new(ObjectType::Notification, 0).map_err(|_| "no memory")?;
        sys::irq_bind(lines, sci, note.cap(), flags).map_err(|_| "the SCI cannot be bound")?;
        let _ = Rights::READ;
        Ok(Button { ports, lines, status, sci, note })
    }

    /// The notification the button's interrupt signals.
    pub fn notification(&self) -> Cap {
        self.note.cap()
    }

    /// The interrupt came: whether it was the button (its status is
    /// cleared, and the line let go either way).
    pub fn pressed(&self) -> bool {
        let pressed = sys::port_in(self.ports, self.status, 2).is_ok_and(|v| v as u16 & PWRBTN != 0);
        if pressed {
            let _ = sys::port_out(self.ports, self.status, 2, PWRBTN as u32);
        }
        let _ = sys::irq_ack(self.lines, self.sci);
        pressed
    }
}

/// The trigger and polarity the MADT's interrupt source overrides give
/// global interrupt `gsi`, as `IrqBind` flags.
fn interrupt_flags(m: &mut Manager, gsi: u32) -> Option<u64> {
    let rsdp = m.info.rsdp;
    let mut read = |a: u64, b: &mut [u8]| m.read(a, b);
    let (madt, len) = acpi::find_table(&mut read, rsdp, b"APIC")?;
    let mut at = madt + 44;
    while at + 2 <= madt + len as u64 {
        let mut h = [0u8; 10];
        if !m.read(at, &mut h[..2]) || h[1] < 2 {
            return None;
        }
        if h[0] == 2 && h[1] >= 10 && m.read(at, &mut h) {
            let (target, flags) = (u32::from_le_bytes([h[4], h[5], h[6], h[7]]), u16::from_le_bytes([h[8], h[9]]));
            if target == gsi {
                let low = flags & 3 == 3 || (flags & 3 == 0);
                let level = flags >> 2 & 3 == 3 || (flags >> 2 & 3 == 0);
                return Some(if level { sys::IRQ_LEVEL } else { 0 } | if low { sys::IRQ_ACTIVE_LOW } else { 0 });
            }
        }
        at += h[1] as u64;
    }
    None
}
