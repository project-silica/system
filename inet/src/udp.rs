//! UDP over IPv4 (RFC 768). The checksum covers a pseudo-header of the IP
//! addresses; a sender may leave it zero over IPv4, which is accepted.

use crate::checksum::Sum;
use crate::{Ipv4, Malformed, be16};

/// The header: ports, length, checksum.
pub const HEADER: usize = 8;

/// A datagram: its ports and data.
#[derive(Clone, Copy, Debug)]
pub struct Datagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub data: &'a [u8],
}

/// Read a datagram (an IPv4 payload) sent from `src` to `dst`.
pub fn parse(p: &[u8], src: Ipv4, dst: Ipv4) -> Result<Datagram<'_>, Malformed> {
    if p.len() < HEADER {
        return Err(Malformed::Truncated);
    }
    let len = be16(p, 4) as usize;
    if len < HEADER {
        return Err(Malformed::BadHeader);
    }
    if p.len() < len {
        return Err(Malformed::Truncated);
    }
    let p = &p[..len];
    if be16(p, 6) != 0 && Sum::new().pseudo(src, dst, crate::ipv4::UDP, len as u16).bytes(p).finish() != 0 {
        return Err(Malformed::BadChecksum);
    }
    Ok(Datagram { src_port: be16(p, 0), dst_port: be16(p, 2), data: &p[HEADER..] })
}

/// Write a datagram carrying `data` from `src`:`src_port` to
/// `dst`:`dst_port`, with its checksum; returns its length.
pub fn build(out: &mut [u8], src: Ipv4, src_port: u16, dst: Ipv4, dst_port: u16, data: &[u8]) -> Option<usize> {
    let len = HEADER + data.len();
    let len16 = u16::try_from(len).ok()?;
    let d = out.get_mut(..len)?;
    d[0..2].copy_from_slice(&src_port.to_be_bytes());
    d[2..4].copy_from_slice(&dst_port.to_be_bytes());
    d[4..6].copy_from_slice(&len16.to_be_bytes());
    d[6..8].fill(0);
    d[HEADER..].copy_from_slice(data);
    let sum = Sum::new().pseudo(src, dst, crate::ipv4::UDP, len16).bytes(d).finish();
    // A computed zero is sent as all ones: zero means "no checksum".
    let sum = if sum == 0 { 0xFFFF } else { sum };
    d[6..8].copy_from_slice(&sum.to_be_bytes());
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4 = Ipv4([10, 0, 2, 15]);
    const B: Ipv4 = Ipv4([10, 0, 2, 2]);

    #[test]
    fn datagrams_round_trip_and_the_pseudo_header_is_checked() {
        let mut b = [0u8; 32];
        let n = build(&mut b, A, 68, B, 67, b"lease").unwrap();
        let d = parse(&b[..n], A, B).unwrap();
        assert_eq!((d.src_port, d.dst_port, d.data), (68, 67, &b"lease"[..]));
        assert_eq!(parse(&b[..n], A, Ipv4([10, 0, 2, 3])).unwrap_err(), Malformed::BadChecksum, "another destination");
        let mut c = b;
        c[6..8].fill(0);
        c[8] ^= 1;
        assert!(parse(&c[..n], A, B).is_ok(), "no checksum over IPv4");
        let mut c = b;
        c[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(parse(&c[..n], A, B).unwrap_err(), Malformed::BadHeader);
        let mut c = b;
        c[4..6].copy_from_slice(&40u16.to_be_bytes());
        assert_eq!(parse(&c[..n], A, B).unwrap_err(), Malformed::Truncated);
        assert!(build(&mut b[..10], A, 1, B, 2, b"abc").is_none());
    }
}
