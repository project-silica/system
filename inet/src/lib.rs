//! The network stack's wire formats: what arrives is parsed from bytes
//! nobody vouches for, and what leaves is built into a buffer.
//!
//! Every parser takes a whole frame or packet as `&[u8]` (the stack's own
//! copy, taken once from the memory a device wrote: the device may go on
//! writing there, so nothing is parsed in place) and either returns a view
//! whose every field lies inside it, or says why not ([`Malformed`]). It
//! checks lengths, versions and checksums; it does not decide what to do
//! with a packet that is well formed but unwanted (another host's address,
//! an option the stack does not use): that is the stack's.
//!
//! Every builder writes into a `&mut [u8]` it is given and returns how many
//! bytes it wrote, or `None` when the buffer is too short. Nothing here
//! allocates, and nothing is `unsafe`.
//!
//! Multi-byte fields are big-endian on the wire (network order) and are
//! converted at the edges: the views and builders speak host integers.
#![no_std]
#![deny(unsafe_code)]

pub mod arp;
pub mod checksum;
pub mod dhcp;
pub mod dhcp_client;
pub mod ether;
pub mod icmp;
pub mod ipv4;
pub mod udp;

use core::fmt;

/// An Ethernet (MAC-48) address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Every station on the link.
    pub const BROADCAST: Mac = Mac([0xFF; 6]);
    /// No station (an ARP request's target hardware address).
    pub const ZERO: Mac = Mac([0; 6]);

    /// Whether frames to this address go to more than one station (the
    /// group bit, broadcast included).
    pub fn is_group(&self) -> bool {
        self.0[0] & 1 != 0
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An IPv4 address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Ipv4(pub [u8; 4]);

impl Ipv4 {
    /// The unspecified address (a host that has none yet).
    pub const UNSPECIFIED: Ipv4 = Ipv4([0; 4]);
    /// The limited broadcast address.
    pub const BROADCAST: Ipv4 = Ipv4([0xFF; 4]);

    /// The address as a host integer.
    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// The address with this host integer.
    pub fn from_u32(v: u32) -> Ipv4 {
        Ipv4(v.to_be_bytes())
    }

    /// Whether `other` is on the same subnet as this address, for a prefix
    /// of `prefix` bits (0 to 32).
    pub fn same_subnet(self, other: Ipv4, prefix: u8) -> bool {
        let mask = mask(prefix);
        self.to_u32() & mask == other.to_u32() & mask
    }

    /// Whether this is a multicast address (224.0.0.0/4).
    pub fn is_multicast(self) -> bool {
        self.0[0] & 0xF0 == 0xE0
    }
}

/// The netmask of a prefix of `prefix` bits (more than 32 counts as 32).
pub fn mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

/// The prefix length of a netmask, when it is one (ones, then zeros).
pub fn prefix_of(netmask: Ipv4) -> Option<u8> {
    let m = netmask.to_u32();
    let ones = m.leading_ones();
    (m.checked_shl(ones).unwrap_or(0) == 0).then_some(ones as u8)
}

impl fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.0;
        write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3])
    }
}

impl fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Why bytes were not taken as a packet of the kind asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// Shorter than its header, or than a length it states.
    Truncated,
    /// A version, kind or length field has a value the format forbids.
    BadHeader,
    /// The checksum does not match the bytes.
    BadChecksum,
    /// A fragment of a larger packet (this stack does not reassemble yet).
    Fragment,
    /// An option list that does not end where it must.
    BadOptions,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Malformed::Truncated => "truncated",
            Malformed::BadHeader => "bad header",
            Malformed::BadChecksum => "bad checksum",
            Malformed::Fragment => "a fragment",
            Malformed::BadOptions => "bad options",
        })
    }
}

/// A big-endian u16 at `at` (the caller checked the length).
pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// A big-endian u32 at `at` (the caller checked the length).
pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_and_prefixes_round_trip() {
        assert_eq!(mask(0), 0);
        assert_eq!(mask(24), 0xFFFF_FF00);
        assert_eq!(mask(32), u32::MAX);
        assert_eq!(mask(40), u32::MAX);
        for p in 0..=32u8 {
            assert_eq!(prefix_of(Ipv4::from_u32(mask(p))), Some(p));
        }
        assert_eq!(prefix_of(Ipv4([255, 0, 255, 0])), None, "ones after a zero are not a netmask");
        assert!(Ipv4([10, 0, 2, 15]).same_subnet(Ipv4([10, 0, 2, 2]), 24));
        assert!(!Ipv4([10, 0, 2, 15]).same_subnet(Ipv4([10, 0, 3, 2]), 24));
    }
}
