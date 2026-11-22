//! A device's interrupts: message-signalled (MSI-X), each one a
//! notification the driver waits on.

use crate::pci::Msix;
use crate::{Device, DeviceError, grant, granted};
use silica_rt::mem::Object;
use silica_rt::mmio::Mmio;
use silica_rt::sys::{self, Cap, ObjectType, Wait};

/// One interrupt of the device, bound to a notification of the driver's.
#[derive(Debug)]
pub struct Interrupt {
    notification: Object,
    /// The MSI-X table entry it was put in.
    entry: Mmio,
}

impl Interrupt {
    /// Make the device's interrupt number `index` (an entry of its MSI-X
    /// table; `index` also picks which of the driver's lines carries it)
    /// signal a new notification, delivered on the calling thread's
    /// processor, and let the device raise it.
    pub fn bind(device: &Device, index: u16) -> Result<Interrupt, DeviceError> {
        let Msix { vectors, bar, offset, .. } = device.config().msix().ok_or(DeviceError::Missing("MSI-X"))?;
        let line = device.lines.start.checked_add(index as u32).filter(|l| *l < device.lines.end && index < vectors);
        let line = line.ok_or(DeviceError::Missing("an interrupt line for this MSI-X entry"))?;
        let table = device.bar(bar as usize).ok_or(DeviceError::Protocol("the MSI-X table is in a BAR the device does not have"))?;
        let entry =
            table.part(offset as usize + index as usize * 16, 16).ok_or(DeviceError::Protocol("the MSI-X table lies outside its BAR"))?;
        let notification = Object::new(ObjectType::Notification, 0)?;
        let (address, data) = sys::irq_bind_msi(granted(grant::INTERRUPTS), line, notification.cap(), granted(grant::IDENTITY), device.id)?;
        // Masked while the message changes, as the PCI specification asks.
        entry.write32(12, 1);
        entry.write32(0, address as u32);
        entry.write32(4, (address >> 32) as u32);
        entry.write32(8, data as u32);
        entry.write32(12, 0);
        Ok(Interrupt { notification, entry })
    }

    /// The notification the interrupt signals, to wait on directly or
    /// together with other things.
    pub fn notification(&self) -> Cap {
        self.notification.cap()
    }

    /// Wait until the device has raised the interrupt (it may have done so
    /// before the call), or until the monotonic time `deadline` (in
    /// nanoseconds; `None`: for ever). `false` when the deadline passed.
    pub fn wait(&self, deadline: Option<u64>) -> bool {
        sys::recv(self.notification.cap(), deadline.map_or(Wait::Forever, Wait::Until)).is_ok()
    }

    /// Stop the device raising it, or let it again.
    pub fn mask(&self, masked: bool) {
        self.entry.write32(12, masked as u32);
    }
}
