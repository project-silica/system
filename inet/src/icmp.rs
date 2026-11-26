//! ICMP for IPv4 (RFC 792): echo requests and replies. Other messages are
//! parsed as their type and code, checksum checked, and left to the stack.

use crate::Malformed;
use crate::checksum;

/// The header: type, code, checksum, and four bytes the type defines.
pub const HEADER: usize = 8;
/// An echo reply.
pub const ECHO_REPLY: u8 = 0;
/// A destination that cannot be reached.
pub const UNREACHABLE: u8 = 3;
/// An echo request.
pub const ECHO_REQUEST: u8 = 8;

/// A message: its type and code, the four type-defined bytes, the rest.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    pub kind: u8,
    pub code: u8,
    /// For echoes: the identifier and sequence number.
    pub rest: [u8; 4],
    pub data: &'a [u8],
}

impl Message<'_> {
    /// An echo's identifier.
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.rest[0], self.rest[1]])
    }
    /// An echo's sequence number.
    pub fn seq(&self) -> u16 {
        u16::from_be_bytes([self.rest[2], self.rest[3]])
    }
}

/// Read a message (an IPv4 payload).
pub fn parse(p: &[u8]) -> Result<Message<'_>, Malformed> {
    if p.len() < HEADER {
        return Err(Malformed::Truncated);
    }
    if checksum::of(p) != 0 {
        return Err(Malformed::BadChecksum);
    }
    Ok(Message { kind: p[0], code: p[1], rest: [p[4], p[5], p[6], p[7]], data: &p[HEADER..] })
}

/// "Fragmentation needed and don't fragment set" (type 3, code 4).
pub const FRAGMENTATION_NEEDED: u8 = 4;

/// What a "fragmentation needed" message says (RFC 1191): the most the
/// next hop carries (bytes) and the TCP segment it quotes, as its sender
/// sent it: source and destination address, ports, sequence number. `None`
/// for any other message, or one that quotes no TCP segment whole enough.
/// A router that gives no size (an older one, 0) is taken to carry half the
/// packet it quotes.
pub fn too_big(m: &Message<'_>) -> Option<(u16, QuotedTcp)> {
    if m.kind != UNREACHABLE || m.code != FRAGMENTATION_NEEDED {
        return None;
    }
    let d = m.data;
    if d.len() < 20 || d[0] >> 4 != 4 || d[9] != 6 {
        return None;
    }
    let ihl = usize::from(d[0] & 0xF) * 4;
    let t = d.get(ihl..ihl.checked_add(8)?).filter(|_| ihl >= 20)?;
    let quoted_len = u16::from_be_bytes([d[2], d[3]]);
    let mtu = match u16::from_be_bytes([m.rest[2], m.rest[3]]) {
        0 => quoted_len / 2,
        n => n,
    };
    let ip = |at: usize| crate::Ipv4([d[at], d[at + 1], d[at + 2], d[at + 3]]);
    Some((
        mtu,
        QuotedTcp {
            src: ip(12),
            dst: ip(16),
            src_port: u16::from_be_bytes([t[0], t[1]]),
            dst_port: u16::from_be_bytes([t[2], t[3]]),
            seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
        },
    ))
}

/// The TCP segment an ICMP error quotes ([`too_big`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotedTcp {
    pub src: crate::Ipv4,
    pub dst: crate::Ipv4,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
}

/// Write an echo request or reply (`kind`) carrying `data`; returns its
/// length.
pub fn echo(out: &mut [u8], kind: u8, id: u16, seq: u16, data: &[u8]) -> Option<usize> {
    let len = HEADER + data.len();
    let m = out.get_mut(..len)?;
    m[0] = kind;
    m[1] = 0;
    m[2..4].fill(0);
    m[4..6].copy_from_slice(&id.to_be_bytes());
    m[6..8].copy_from_slice(&seq.to_be_bytes());
    m[HEADER..].copy_from_slice(data);
    let sum = checksum::of(m);
    m[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoes_round_trip_and_a_bad_checksum_is_refused() {
        let mut b = [0u8; 40];
        let n = echo(&mut b, ECHO_REQUEST, 0x511C, 3, &[1, 2, 3]).unwrap();
        let m = parse(&b[..n]).unwrap();
        assert_eq!((m.kind, m.code, m.id(), m.seq(), m.data), (ECHO_REQUEST, 0, 0x511C, 3, &[1, 2, 3][..]));
        b[9] ^= 0xFF;
        assert_eq!(parse(&b[..n]).unwrap_err(), Malformed::BadChecksum);
        assert_eq!(parse(&b[..7]).unwrap_err(), Malformed::Truncated);
        assert!(echo(&mut b[..10], ECHO_REPLY, 0, 0, &[0; 3]).is_none());
    }

    /// A router's "fragmentation needed": its size and the quoted segment's
    /// addresses, ports and sequence number; nothing from another message,
    /// a quote too short, or one of another protocol.
    #[test]
    fn a_router_s_word_on_a_packet_too_large_is_read() {
        let mut quote = [0u8; 28];
        quote[0] = 0x45;
        quote[2..4].copy_from_slice(&1500u16.to_be_bytes());
        quote[9] = 6;
        quote[12..16].copy_from_slice(&[10, 0, 2, 15]);
        quote[16..20].copy_from_slice(&[10, 0, 2, 2]);
        quote[20..22].copy_from_slice(&40000u16.to_be_bytes());
        quote[22..24].copy_from_slice(&80u16.to_be_bytes());
        quote[24..28].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        let m = Message { kind: UNREACHABLE, code: FRAGMENTATION_NEEDED, rest: [0, 0, 0x05, 0x78], data: &quote };
        let (mtu, q) = too_big(&m).unwrap();
        assert_eq!(mtu, 1400);
        assert_eq!(
            (q.src, q.dst, q.src_port, q.dst_port, q.seq),
            (crate::Ipv4([10, 0, 2, 15]), crate::Ipv4([10, 0, 2, 2]), 40000, 80, 0x1234_5678)
        );
        assert_eq!(too_big(&Message { rest: [0; 4], ..m }).map(|(mtu, _)| mtu), Some(750), "no size given: half the quoted packet");
        assert!(too_big(&Message { code: 1, ..m }).is_none());
        assert!(too_big(&Message { data: &quote[..27], ..m }).is_none());
        let mut udp = quote;
        udp[9] = 17;
        assert!(too_big(&Message { data: &udp, ..m }).is_none());
    }
}
