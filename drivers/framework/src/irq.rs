//! A device's interrupts: message-signalled (MSI-X), each one a
//! notification the driver waits on.
//!
//! Interrupt `index` is the device's MSI-X table entry `index`, carried by
//! the driver's line `Device::lines.start + index`; it exists when `index`
//! is below both the table's size (`Config::msix`) and the number of lines
//! the driver was given. The table belongs to this module: it writes the
//! entries it binds and masks, and a driver never writes the table itself,
//! even where it lies in a BAR the driver holds.
//!
//! A driver that serves (`silica_rt::ipc::serve_events`) hears every
//! interrupt on one [`Signals`], each with its own bit; a notification has
//! 64 bits, so give interrupts bits that leave room for the others (a block
//! driver's `CLIENT` is bit 0). During bring-up, before it serves, it waits
//! for one with [`Signals::wait`] (or [`Interrupt::wait`] on an interrupt
//! bound alone), with a deadline.

use crate::pci::Msix;
use crate::{Device, DeviceError, grant, granted};
use silica_rt::ipc::{free_slot, release_slot};
use silica_rt::mem::Object;
use silica_rt::mmio::Mmio;
use silica_rt::slots;
use silica_rt::sys::{self, Cap, ObjectType, Rights, Wait};

/// One interrupt of the device, bound to a notification of the driver's.
#[derive(Debug)]
pub struct Interrupt {
    notification: Cap,
    /// The MSI-X table entry it was put in.
    entry: Mmio,
}

/// The one notification a driver hears everything on: its device's
/// interrupts and its clients' wake-ups, each as a bit of its own (a badge),
/// so that the driver's single wait (`silica_rt::ipc::serve_events`) says
/// which of them happened.
#[derive(Debug)]
pub struct Signals {
    notification: Object,
}

impl Signals {
    /// A new notification.
    pub fn new() -> Result<Signals, DeviceError> {
        Ok(Signals { notification: Object::new(ObjectType::Notification, 0)? })
    }

    /// The notification itself: what the driver listens on.
    pub fn listen(&self) -> Cap {
        self.notification.cap()
    }

    /// Wait until it is signalled (it may have been before the call), or
    /// until the monotonic time `deadline` (nanoseconds; `None`: for ever).
    /// Returns the bits it was signalled with, cleared by the wait, or
    /// `None` when the deadline passed first. Also how a driver sleeps.
    pub fn wait(&self, deadline: Option<u64>) -> Option<u64> {
        sys::recv(self.listen(), deadline.map_or(Wait::Forever, Wait::Until)).ok().map(|m| m.badge)
    }

    /// A capability that signals it with the bits `bits` and can do nothing
    /// else: what an interrupt is bound to, or a client is given.
    pub fn sender(&self, bits: u64) -> Result<Cap, DeviceError> {
        let slot = free_slot().ok_or(sys::Error::NoMemory)?;
        sys::cap_derive(slots::SPACE, slot, self.notification.cap(), Rights::WRITE, bits).inspect_err(|_| release_slot(slot))?;
        Ok(Cap(slot))
    }
}

impl Interrupt {
    /// Make the device's interrupt number `index` (an entry of its MSI-X
    /// table; `index` also picks which of the driver's lines carries it)
    /// signal a new notification of its own, delivered on the calling
    /// thread's processor, and let the device raise it. For a driver that
    /// waits for one thing at a time ([`Interrupt::wait`]).
    pub fn bind(device: &Device, index: u16) -> Result<Interrupt, DeviceError> {
        // It lives as long as the driver: no need to keep the object.
        let notification = Object::new(ObjectType::Notification, 0)?;
        Interrupt::bind_to(device, index, notification.cap())
    }

    /// As [`Interrupt::bind`], signalling `notification` (a capability from
    /// [`Signals::sender`], whose bits say which interrupt it was).
    pub fn bind_to(device: &Device, index: u16, notification: Cap) -> Result<Interrupt, DeviceError> {
        let Msix { vectors, bar, offset, .. } = device.config().msix().ok_or(DeviceError::Missing("MSI-X"))?;
        let line = device.lines.start.checked_add(index as u32).filter(|l| *l < device.lines.end && index < vectors);
        let line = line.ok_or(DeviceError::Missing("an interrupt line for this MSI-X entry"))?;
        let table = device.bar(bar as usize).ok_or(DeviceError::Protocol("the MSI-X table is in a BAR the device does not have"))?;
        let entry =
            table.part(offset as usize + index as usize * 16, 16).ok_or(DeviceError::Protocol("the MSI-X table lies outside its BAR"))?;
        let (address, data) = sys::irq_bind_msi(granted(grant::INTERRUPTS), line, notification, granted(grant::IDENTITY), device.id)?;
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
        self.notification
    }

    /// Wait until the device has raised the interrupt (it may have done so
    /// before the call), or until the monotonic time `deadline` (in
    /// nanoseconds; `None`: for ever). `false` when the deadline passed.
    pub fn wait(&self, deadline: Option<u64>) -> bool {
        sys::recv(self.notification, deadline.map_or(Wait::Forever, Wait::Until)).is_ok()
    }

    /// Stop the device raising it, or let it again.
    pub fn mask(&self, masked: bool) {
        self.entry.write32(12, masked as u32);
    }
}
