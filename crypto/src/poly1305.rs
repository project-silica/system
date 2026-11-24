//! Poly1305 (RFC 8439 section 2.5): a one-time authenticator. The 32-byte
//! key must never authenticate two messages; [`crate::aead`] derives a
//! fresh one for each.
//!
//! Five 26-bit limbs and 64-bit products, the shape of poly1305-donna-32:
//! no branch or index depends on the key or the message.

const MASK: u32 = 0x3ff_ffff;

/// A Poly1305 computation in progress.
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    len: usize,
}

fn le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        // r, clamped as the RFC says.
        let r = [
            le(key, 0) & 0x3ff_ffff,
            (le(key, 3) >> 2) & 0x3ff_ff03,
            (le(key, 6) >> 4) & 0x3ff_c0ff,
            (le(key, 9) >> 6) & 0x3f0_3fff,
            (le(key, 12) >> 8) & 0x00f_ffff,
        ];
        let s = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        let pad = [le(key, 16), le(key, 20), le(key, 24), le(key, 28)];
        Poly1305 { r, s, h: [0; 5], pad, buf: [0; 16], len: 0 }
    }

    /// One 16-byte block; `hibit` is 2^128 for a whole block, 0 for the
    /// padded last one (whose 1 byte is already in `m`).
    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let [s1, s2, s3, s4] = self.s.map(u64::from);
        let h = &mut self.h;
        h[0] += le(m, 0) & MASK;
        h[1] += (le(m, 3) >> 2) & MASK;
        h[2] += (le(m, 6) >> 4) & MASK;
        h[3] += (le(m, 9) >> 6) & MASK;
        h[4] += (le(m, 12) >> 8) | hibit;
        let [h0, h1, h2, h3, h4] = h.map(u64::from);
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let mut c = d0 >> 26;
        h[0] = d0 as u32 & MASK;
        d1 += c;
        c = d1 >> 26;
        h[1] = d1 as u32 & MASK;
        d2 += c;
        c = d2 >> 26;
        h[2] = d2 as u32 & MASK;
        d3 += c;
        c = d3 >> 26;
        h[3] = d3 as u32 & MASK;
        d4 += c;
        c = d4 >> 26;
        h[4] = d4 as u32 & MASK;
        h[0] += c as u32 * 5;
        let c = h[0] >> 26;
        h[0] &= MASK;
        h[1] += c;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.len > 0 {
            let take = (16 - self.len).min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len < 16 {
                return;
            }
            let b = self.buf;
            self.block(&b, 1 << 24);
            self.len = 0;
        }
        let (blocks, rest) = data.as_chunks::<16>();
        for b in blocks {
            self.block(b, 1 << 24);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    /// Pad what was given so far with zeros to a multiple of 16 bytes (the
    /// AEAD's layout).
    pub fn pad16(&mut self) {
        if self.len > 0 {
            self.buf[self.len..].fill(0);
            let b = self.buf;
            self.block(&b, 1 << 24);
            self.len = 0;
        }
    }

    pub fn finish(mut self) -> [u8; 16] {
        if self.len > 0 {
            let mut b = [0u8; 16];
            b[..self.len].copy_from_slice(&self.buf[..self.len]);
            b[self.len] = 1;
            self.block(&b, 0);
        }
        let h = &mut self.h;
        // Carry fully.
        let mut c = h[1] >> 26;
        h[1] &= MASK;
        for x in &mut h[2..5] {
            *x += c;
            c = *x >> 26;
            *x &= MASK;
        }
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= MASK;
        h[1] += c;
        // g = h - p = h + 5 - 2^130; take it when it did not go negative.
        let mut g = [0u32; 5];
        g[0] = h[0] + 5;
        c = g[0] >> 26;
        g[0] &= MASK;
        for i in 1..4 {
            g[i] = h[i] + c;
            c = g[i] >> 26;
            g[i] &= MASK;
        }
        g[4] = (h[4] + c).wrapping_sub(1 << 26);
        // All ones when g[4] did not borrow (h >= p), else zero.
        let take_g = (g[4] >> 31).wrapping_sub(1);
        g[4] &= MASK;
        for i in 0..5 {
            h[i] = (h[i] & !take_g) | (g[i] & take_g);
        }
        // h mod 2^128, then + pad.
        let w = [h[0] | h[1] << 26, h[1] >> 6 | h[2] << 20, h[2] >> 12 | h[3] << 14, h[3] >> 18 | h[4] << 8];
        let mut out = [0u8; 16];
        let mut f = 0u64;
        for i in 0..4 {
            f = u64::from(w[i]) + u64::from(self.pad[i]) + (f >> 32);
            out[4 * i..4 * i + 4].copy_from_slice(&(f as u32).to_le_bytes());
        }
        out
    }
}

/// The tag of `message` under the one-time `key`.
pub fn tag(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(message);
    p.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn rfc8439_tag() {
        // Section 2.5.2.
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")[..32].try_into().unwrap();
        let t = tag(&key, b"Cryptographic Forum Research Group");
        assert_eq!(t[..], hex("a8061dc1305136c6c22b8baf0c0127a9")[..16]);
    }

    #[test]
    fn pieces_make_the_whole() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8 * 7 + 3);
        let msg: [u8; 200] = core::array::from_fn(|i| (i * 31) as u8);
        let whole = tag(&key, &msg);
        for split in [0, 1, 15, 16, 17, 33, 100, 199, 200] {
            let mut p = Poly1305::new(&key);
            p.update(&msg[..split]);
            p.update(&msg[split..]);
            assert_eq!(p.finish(), whole, "split at {split}");
        }
    }

    #[test]
    fn rfc8439_appendix_a3_edge_cases() {
        // Test vector #5: h reaches p exactly in the last reduction.
        let mut key = [0u8; 32];
        key[0] = 2;
        let t = tag(&key, &[0xff; 16]);
        assert_eq!(t[..], hex("03000000000000000000000000000000")[..16]);
        // Test vector #6: the pad's carry wraps around 2^128.
        let mut key = [0u8; 32];
        key[0] = 2;
        key[16..].fill(0xff);
        let mut m = [0u8; 16];
        m[0] = 2;
        let t = tag(&key, &m);
        assert_eq!(t[..], hex("03000000000000000000000000000000")[..16]);
        // Test vector #8: h is p exactly before the pad.
        let mut key = [0u8; 32];
        key[0] = 1;
        let m = hex("fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101");
        let t = tag(&key, &m[..48]);
        assert_eq!(t[..], hex("00000000000000000000000000000000")[..16]);
    }
}
