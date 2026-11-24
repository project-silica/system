//! IPv4 headers (RFC 791). A packet is taken whole: options are skipped
//! (their length is checked, their content is not used), a fragment is
//! refused until the stack reassembles, and the payload ends where the
//! total length says, not where the frame does (Ethernet pads short ones).

use crate::checksum;
use crate::{Ipv4, Malformed, be16};

/// The header's length without options.
pub const HEADER: usize = 20;
/// ICMP.
pub const ICMP: u8 = 1;
/// TCP.
pub const TCP: u8 = 6;
/// UDP.
pub const UDP: u8 = 17;
/// The time to live a packet starts with.
pub const TTL: u8 = 64;

/// A packet's header fields the stack uses, and its payload.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub src: Ipv4,
    pub dst: Ipv4,
    pub protocol: u8,
    pub ttl: u8,
    pub id: u16,
    pub payload: &'a [u8],
}

/// Read a packet from an Ethernet payload.
pub fn parse(p: &[u8]) -> Result<Packet<'_>, Malformed> {
    if p.len() < HEADER {
        return Err(Malformed::Truncated);
    }
    let ihl = (p[0] & 0x0F) as usize * 4;
    if p[0] >> 4 != 4 || ihl < HEADER {
        return Err(Malformed::BadHeader);
    }
    let total = be16(p, 2) as usize;
    if total < ihl {
        return Err(Malformed::BadHeader);
    }
    if p.len() < total {
        return Err(Malformed::Truncated);
    }
    if checksum::of(&p[..ihl]) != 0 {
        return Err(Malformed::BadChecksum);
    }
    let flags_fragment = be16(p, 6);
    // More fragments, or an offset: part of a larger packet. The reserved
    // bit set is a malformed header (RFC 791).
    if flags_fragment & 0x8000 != 0 {
        return Err(Malformed::BadHeader);
    }
    if flags_fragment & 0x2000 != 0 || flags_fragment & 0x1FFF != 0 {
        return Err(Malformed::Fragment);
    }
    Ok(Packet {
        src: Ipv4([p[12], p[13], p[14], p[15]]),
        dst: Ipv4([p[16], p[17], p[18], p[19]]),
        protocol: p[9],
        ttl: p[8],
        id: be16(p, 4),
        payload: &p[ihl..total],
    })
}

/// Write a header without options for a payload of `payload_len` bytes
/// (don't-fragment set: the stack does not fragment what it sends); returns
/// the payload's place after it.
pub fn header(out: &mut [u8], src: Ipv4, dst: Ipv4, protocol: u8, id: u16, payload_len: usize) -> Option<&mut [u8]> {
    if out.len() < HEADER + payload_len {
        return None;
    }
    header_only(&mut out[..HEADER], src, dst, protocol, id, payload_len)?;
    Some(&mut out[HEADER..HEADER + payload_len])
}

/// The header alone, into the first 20 bytes of `out`, for a payload of
/// `payload_len` bytes written elsewhere; `None` when `out` is shorter or
/// the packet would be longer than IPv4 allows.
pub fn header_only(out: &mut [u8], src: Ipv4, dst: Ipv4, protocol: u8, id: u16, payload_len: usize) -> Option<()> {
    let total = u16::try_from(HEADER + payload_len).ok()?;
    let h = out.get_mut(..HEADER)?;
    h[0] = 0x45;
    h[1] = 0;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    h[8] = TTL;
    h[9] = protocol;
    h[10..12].fill(0);
    h[12..16].copy_from_slice(&src.0);
    h[16..20].copy_from_slice(&dst.0);
    let sum = checksum::of(h);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload: &[u8]) -> [u8; 64] {
        let mut b = [0u8; 64];
        let p = header(&mut b, Ipv4([10, 0, 2, 15]), Ipv4([10, 0, 2, 2]), UDP, 7, payload.len()).unwrap();
        p.copy_from_slice(payload);
        b
    }

    #[test]
    fn a_packet_round_trips_and_ends_at_its_total_length() {
        let b = packet(&[1, 2, 3]);
        let p = parse(&b).unwrap();
        assert_eq!((p.src, p.dst, p.protocol, p.ttl, p.id), (Ipv4([10, 0, 2, 15]), Ipv4([10, 0, 2, 2]), UDP, TTL, 7));
        assert_eq!(p.payload, &[1, 2, 3], "the frame's padding is not payload");
        assert_eq!(parse(&b[..22]).unwrap_err(), Malformed::Truncated, "shorter than the total length");
    }

    #[test]
    fn bad_versions_lengths_checksums_and_fragments_are_refused() {
        let b = packet(&[0; 8]);
        let mut c = b;
        c[0] = 0x65;
        assert_eq!(parse(&c).unwrap_err(), Malformed::BadHeader, "IPv6's version");
        let mut c = b;
        c[0] = 0x44;
        assert_eq!(parse(&c).unwrap_err(), Malformed::BadHeader, "a header shorter than 20 bytes");
        let mut c = b;
        c[19] ^= 1;
        assert_eq!(parse(&c).unwrap_err(), Malformed::BadChecksum);
        let fragment = |flags: u16| {
            let mut c = b;
            c[6..8].copy_from_slice(&flags.to_be_bytes());
            c[10..12].fill(0);
            let s = checksum::of(&c[..20]);
            c[10..12].copy_from_slice(&s.to_be_bytes());
            parse(&c).map(|_| ())
        };
        assert_eq!(fragment(0x2000), Err(Malformed::Fragment), "more fragments");
        assert_eq!(fragment(0x0001), Err(Malformed::Fragment), "an offset");
        assert_eq!(fragment(0x8000), Err(Malformed::BadHeader), "the reserved bit");
        assert_eq!(fragment(0x0000), Ok(()), "don't-fragment clear is whole too");
        let mut small = [0u8; 30];
        assert!(header(&mut small, Ipv4::UNSPECIFIED, Ipv4::BROADCAST, UDP, 0, 11).is_none());
    }

    #[test]
    fn options_are_skipped() {
        let mut b = [0u8; 40];
        b[0] = 0x46; // 24-byte header
        b[2..4].copy_from_slice(&28u16.to_be_bytes());
        b[8] = 64;
        b[9] = ICMP;
        b[20..24].copy_from_slice(&[1, 1, 1, 0]); // NOPs, end of list
        b[24..28].copy_from_slice(&[9, 9, 9, 9]);
        let s = checksum::of(&b[..24]);
        b[10..12].copy_from_slice(&s.to_be_bytes());
        assert_eq!(parse(&b).unwrap().payload, &[9, 9, 9, 9]);
    }
}
