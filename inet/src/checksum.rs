//! The internet checksum (RFC 1071): the ones' complement of the ones'
//! complement sum of 16-bit big-endian words, an odd last byte padded with
//! zero. IPv4 headers, ICMP and UDP (over a pseudo-header) use it.

use crate::Ipv4;

/// A running ones' complement sum, folded at the end.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sum(u64);

impl Sum {
    /// An empty sum.
    pub fn new() -> Sum {
        Sum(0)
    }

    /// Add `bytes` as 16-bit big-endian words. A sum built in pieces must
    /// give every piece but the last an even length.
    pub fn bytes(mut self, bytes: &[u8]) -> Sum {
        let (words, rest) = bytes.as_chunks::<2>();
        for w in words {
            self.0 += u16::from_be_bytes(*w) as u64;
        }
        if let [last] = rest {
            self.0 += (*last as u64) << 8;
        }
        self
    }

    /// Add one 16-bit word.
    pub fn add16(mut self, w: u16) -> Sum {
        self.0 += w as u64;
        self
    }

    /// Add the pseudo-header UDP and TCP over IPv4 sum (RFC 768).
    pub fn pseudo(self, src: Ipv4, dst: Ipv4, protocol: u8, len: u16) -> Sum {
        self.bytes(&src.0).bytes(&dst.0).add16(protocol as u16).add16(len)
    }

    /// The checksum: the complement of the folded sum.
    pub fn finish(self) -> u16 {
        let mut s = self.0;
        while s > 0xFFFF {
            s = (s & 0xFFFF) + (s >> 16);
        }
        !(s as u16)
    }
}

/// The checksum of `bytes`. Over bytes that include their own correct
/// checksum it is 0.
pub fn of(bytes: &[u8]) -> u16 {
    Sum::new().bytes(bytes).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example_and_self_check() {
        // RFC 1071 section 3: the sum of these words is 0xddf2.
        let b = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(of(&b), !0xddf2);
        // A header carrying its own checksum sums to zero.
        let mut h = [0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7];
        let c = of(&h);
        assert_eq!(c, 0xb861, "the classic example header (Wikipedia, IPv4 header checksum)");
        h[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(of(&h), 0);
        // An odd length pads with zero.
        assert_eq!(of(&[0xAB]), !0xAB00);
        // Pieces of even length sum as the whole.
        assert_eq!(Sum::new().bytes(&b[..4]).bytes(&b[4..]).finish(), of(&b));
    }
}
