//! Ethernet II frames: destination, source, EtherType, payload. The frame
//! check sequence is the device's; frames here start at the destination
//! address and end at the payload's last byte (padding included).

use crate::{Mac, Malformed, be16};

/// Bytes of header before the payload.
pub const HEADER: usize = 14;
/// The shortest frame on the wire without its check sequence: shorter ones
/// are padded with zeros by the sender.
pub const MIN_FRAME: usize = 60;
/// IPv4.
pub const IPV4: u16 = 0x0800;
/// ARP.
pub const ARP: u16 = 0x0806;
/// IPv6.
pub const IPV6: u16 = 0x86DD;

/// A frame's header and payload, borrowed from the frame.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Read a frame. A tagged frame (802.1Q) or an 802.3 length field instead
/// of an EtherType is reported as it is: the caller drops what it does not
/// speak.
pub fn parse(frame: &[u8]) -> Result<Frame<'_>, Malformed> {
    if frame.len() < HEADER {
        return Err(Malformed::Truncated);
    }
    let mac = |at: usize| {
        let mut m = [0u8; 6];
        m.copy_from_slice(&frame[at..at + 6]);
        Mac(m)
    };
    Ok(Frame { dst: mac(0), src: mac(6), ethertype: be16(frame, 12), payload: &frame[HEADER..] })
}

/// Write a header into `out` and return the payload's place after it.
pub fn header(out: &mut [u8], dst: Mac, src: Mac, ethertype: u16) -> Option<&mut [u8]> {
    if out.len() < HEADER {
        return None;
    }
    out[0..6].copy_from_slice(&dst.0);
    out[6..12].copy_from_slice(&src.0);
    out[12..14].copy_from_slice(&ethertype.to_be_bytes());
    Some(&mut out[HEADER..])
}

/// The length to send for a frame of `len` bytes: at least [`MIN_FRAME`],
/// the bytes after the frame's end zeroed in `out` by the caller's buffer
/// (`pad` does it).
pub fn pad(out: &mut [u8], len: usize) -> usize {
    let to = len.max(MIN_FRAME).min(out.len());
    if to > len {
        out[len..to].fill(0);
    }
    to
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_round_trips_and_short_ones_are_refused() {
        let mut b = [0u8; 64];
        let p = header(&mut b, Mac::BROADCAST, Mac([2, 0, 0, 0, 0, 1]), ARP).unwrap();
        p[0] = 0x55;
        let f = parse(&b[..15]).unwrap();
        assert_eq!((f.dst, f.src, f.ethertype, f.payload), (Mac::BROADCAST, Mac([2, 0, 0, 0, 0, 1]), ARP, &[0x55][..]));
        assert_eq!(parse(&b[..13]).unwrap_err(), Malformed::Truncated);
        assert!(header(&mut b[..13], Mac::ZERO, Mac::ZERO, IPV4).is_none());
        b[20] = 9;
        assert_eq!(pad(&mut b, 20), 60);
        assert_eq!(b[20], 0, "padding is zeros");
        assert_eq!(pad(&mut b, 61), 61);
    }
}
