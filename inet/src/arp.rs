//! ARP for IPv4 over Ethernet (RFC 826): who has an address, and who
//! answers for it. Only that pairing is spoken; any other hardware or
//! protocol type is a malformed packet here.

use crate::{Ipv4, Mac, Malformed, be16};

/// The packet's length (Ethernet hardware, IPv4 protocol).
pub const LEN: usize = 28;
/// A request: who has `target_ip`?
pub const REQUEST: u16 = 1;
/// A reply: `sender_ip` is at `sender_mac`.
pub const REPLY: u16 = 2;

/// An ARP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4,
    pub target_mac: Mac,
    pub target_ip: Ipv4,
}

/// Read an ARP packet (an Ethernet frame's payload; padding after it is
/// ignored).
pub fn parse(p: &[u8]) -> Result<Arp, Malformed> {
    if p.len() < LEN {
        return Err(Malformed::Truncated);
    }
    // Ethernet (1), IPv4 (0x0800), six-byte and four-byte addresses.
    if be16(p, 0) != 1 || be16(p, 2) != 0x0800 || p[4] != 6 || p[5] != 4 {
        return Err(Malformed::BadHeader);
    }
    let op = be16(p, 6);
    if op != REQUEST && op != REPLY {
        return Err(Malformed::BadHeader);
    }
    let mac = |at: usize| {
        let mut m = [0u8; 6];
        m.copy_from_slice(&p[at..at + 6]);
        Mac(m)
    };
    let ip = |at: usize| Ipv4([p[at], p[at + 1], p[at + 2], p[at + 3]]);
    Ok(Arp { op, sender_mac: mac(8), sender_ip: ip(14), target_mac: mac(18), target_ip: ip(24) })
}

/// Write `a` into `out`; returns [`LEN`].
pub fn build(out: &mut [u8], a: &Arp) -> Option<usize> {
    let out = out.get_mut(..LEN)?;
    out[0..8].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 0]);
    out[6..8].copy_from_slice(&a.op.to_be_bytes());
    out[8..14].copy_from_slice(&a.sender_mac.0);
    out[14..18].copy_from_slice(&a.sender_ip.0);
    out[18..24].copy_from_slice(&a.target_mac.0);
    out[24..28].copy_from_slice(&a.target_ip.0);
    Some(LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_replies_round_trip_and_other_kinds_are_refused() {
        let a = Arp {
            op: REQUEST,
            sender_mac: Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]),
            sender_ip: Ipv4([10, 0, 2, 15]),
            target_mac: Mac::ZERO,
            target_ip: Ipv4([10, 0, 2, 2]),
        };
        let mut b = [0u8; 46];
        assert_eq!(build(&mut b, &a), Some(LEN));
        assert_eq!(parse(&b).unwrap(), a, "padding after the packet is ignored");
        assert_eq!(parse(&b[..27]).unwrap_err(), Malformed::Truncated);
        let mut c = b;
        c[1] = 6; // token ring
        assert_eq!(parse(&c).unwrap_err(), Malformed::BadHeader);
        let mut c = b;
        c[7] = 3; // RARP request
        assert_eq!(parse(&c).unwrap_err(), Malformed::BadHeader);
        assert!(build(&mut b[..27], &a).is_none());
    }
}
