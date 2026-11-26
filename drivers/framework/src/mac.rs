//! An interface's own Ethernet address, from what its device reports.
//!
//! A device reports the address it was given (a virtio device's
//! configuration, an Intel NIC's NVM), and a device can report one no
//! interface may have: a multicast address (its first octet's lowest bit),
//! as whose source every station on the link would see the interface's
//! frames dropped or flooded, or all zeros. Such an address is not used: the
//! interface takes a locally administered one made from the device's
//! identity, and its driver says so (the 2026-11-25 drivers review).
//! Addresses are kept as a driver reads them: the first octet in the low
//! byte.

/// Whether `address` can be an interface's own: unicast and not all zeros.
pub fn usable(address: u64) -> bool {
    address & 0xFFFF_FFFF_FFFF != 0 && address & 1 == 0
}

/// A locally administered unicast address made from the device's identity
/// `id` (PCI segment, bus, device and function), unique on one machine.
pub fn local(id: u32) -> u64 {
    0x02 | 0x5E << 8 | (id as u64) << 16
}

/// An address shown as people write one: six octets in order, with colons.
pub struct Shown(pub u64);

impl core::fmt::Display for Shown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for i in 0..6 {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02x}", (self.0 >> (8 * i)) as u8)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_and_zero_are_not_an_interfaces_own() {
        // 52:54:00:12:34:56 (QEMU's), and one with the local bit.
        assert!(usable(0x5634_1200_5452));
        assert!(usable(local(0x10)));
        // 01:00:5e:00:00:01 (a multicast group), ff:ff:ff:ff:ff:ff, zeros.
        assert!(!usable(0x0100_005e_0001));
        assert!(!usable(0xFFFF_FFFF_FFFF));
        assert!(!usable(0));
        // Only the six octets count.
        assert!(!usable(0xFFFF_0000_0000_0000));
        // The local one is unicast, locally administered, and names the device.
        assert_eq!(local(0x10) & 0xFF, 0x02);
        assert_ne!(local(0x10), local(0x18));
    }
}
