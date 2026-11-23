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
}
