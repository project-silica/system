//! X25519 (RFC 7748): Diffie-Hellman on Curve25519.
//!
//! Field elements are five 51-bit limbs with 128-bit products; the ladder
//! swaps by mask. Nothing branches on, or indexes by, a secret.

/// A private key: 32 random bytes (clamped when used).
pub type Secret = [u8; 32];
/// A public key, or the result of an exchange.
pub type Public = [u8; 32];

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

fn load8(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// The low 255 bits of `b`, little-endian (bit 255 is ignored, as the
    /// RFC requires of a u-coordinate).
    fn from_bytes(b: &[u8; 32]) -> Fe {
        Fe([
            load8(b, 0) & MASK,
            (load8(b, 6) >> 3) & MASK,
            (load8(b, 12) >> 6) & MASK,
            (load8(b, 19) >> 1) & MASK,
            (load8(b, 24) >> 12) & MASK,
        ])
    }

    /// The canonical encoding: fully reduced mod p = 2^255 - 19.
    fn to_bytes(self) -> [u8; 32] {
        let mut h = self.carry().carry().0;
        // q = 1 when h >= p: whether h + 19 reaches 2^255.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        h[1] += h[0] >> 51;
        h[0] &= MASK;
        h[2] += h[1] >> 51;
        h[1] &= MASK;
        h[3] += h[2] >> 51;
        h[2] &= MASK;
        h[4] += h[3] >> 51;
        h[3] &= MASK;
        h[4] &= MASK;
        let w = [h[0] | h[1] << 51, h[1] >> 13 | h[2] << 38, h[2] >> 26 | h[3] << 25, h[3] >> 39 | h[4] << 12];
        let mut out = [0u8; 32];
        for (i, x) in w.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes());
        }
        out
    }

    /// Limbs back under 2^51 (the first a little over), value unchanged.
    fn carry(self) -> Fe {
        let mut h = self.0;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        h[0] += 19 * (h[4] >> 51);
        h[4] &= MASK;
        Fe(h)
    }

    fn add(self, b: Fe) -> Fe {
        let (a, b) = (self.0, b.0);
        Fe([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    /// `self - b`, adding 2p first so that no limb goes below zero (each of
    /// `b`'s limbs is under 2^52: every operand here is a carried result).
    fn sub(self, b: Fe) -> Fe {
        let (a, b) = (self.0, b.0);
        Fe([
            a[0] + 0xF_FFFF_FFFF_FFDA - b[0],
            a[1] + 0xF_FFFF_FFFF_FFFE - b[1],
            a[2] + 0xF_FFFF_FFFF_FFFE - b[2],
            a[3] + 0xF_FFFF_FFFF_FFFE - b[3],
            a[4] + 0xF_FFFF_FFFF_FFFE - b[4],
        ])
        .carry()
    }

    /// The 128-bit limbs of a product, carried back to 51 bits.
    fn reduce(r: [u128; 5]) -> Fe {
        let m = u128::from(MASK);
        let mut r = r;
        r[1] += r[0] >> 51;
        r[2] += r[1] >> 51;
        r[3] += r[2] >> 51;
        r[4] += r[3] >> 51;
        let c = (r[4] >> 51) as u64;
        let mut h = [(r[0] & m) as u64, (r[1] & m) as u64, (r[2] & m) as u64, (r[3] & m) as u64, (r[4] & m) as u64];
        // Inputs under 2^54 keep c under 2^59.4, so 19c fits.
        h[0] += c * 19;
        h[1] += h[0] >> 51;
        h[0] &= MASK;
        Fe(h)
    }

    fn mul(self, b: Fe) -> Fe {
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let (a, b) = (self.0, b.0);
        let b19 = [b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        Fe::reduce([
            m(a[0], b[0]) + m(a[1], b19[3]) + m(a[2], b19[2]) + m(a[3], b19[1]) + m(a[4], b19[0]),
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[3]) + m(a[3], b19[2]) + m(a[4], b19[1]),
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b19[3]) + m(a[4], b19[2]),
            m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[3]),
            m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
        ])
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    fn mul_small(self, k: u32) -> Fe {
        let k = u128::from(k);
        Fe::reduce(self.0.map(|x| u128::from(x) * k))
    }

    /// `self^(p-2)`, the inverse (0 for 0). The exponent is public, so
    /// branching on its bits reveals nothing.
    fn invert(self) -> Fe {
        // p - 2 = 2^255 - 21: bits 254..5 set, then 01011.
        let mut r = Fe::ONE;
        for bit in (0..255).rev() {
            r = r.square();
            let set = bit >= 5 || (0b01011 >> bit) & 1 == 1;
            if set {
                r = r.mul(self);
            }
        }
        r
    }

    /// Swap `a` and `b` when `swap` is 1, by mask.
    fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }
}

/// The scalar multiplication `k * u` (RFC 7748 section 5).
pub fn x25519(k: &Secret, u: &Public) -> Public {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= bit;
        Fe::cswap(swap, &mut x2, &mut x3);
        Fe::cswap(swap, &mut z2, &mut z3);
        swap = bit;
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121_665)));
    }
    Fe::cswap(swap, &mut x2, &mut x3);
    Fe::cswap(swap, &mut z2, &mut z3);
    crate::wipe(&mut k);
    x2.mul(z2.invert()).to_bytes()
}

/// The public key of `secret`.
pub fn public(secret: &Secret) -> Public {
    let mut nine = [0u8; 32];
    nine[0] = 9;
    x25519(secret, &nine)
}

/// The peer's key was of small order: the exchange gives all zeros, which
/// no honest peer's key does (RFC 7748 section 6.1). Refused, so that a
/// peer cannot force a known shared secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowOrder;

/// The shared secret of `secret` and the peer's `public`.
pub fn exchange(secret: &Secret, public: &Public) -> Result<[u8; 32], LowOrder> {
    let s = x25519(secret, public);
    if crate::equal(&s, &[0; 32]) { Err(LowOrder) } else { Ok(s) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn h32(s: &str) -> [u8; 32] {
        hex(s)[..32].try_into().unwrap()
    }

    #[test]
    fn rfc7748_vectors() {
        // Section 5.2.
        let k = h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(x25519(&k, &u), h32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
        let k = h32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = h32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(x25519(&k, &u), h32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
    }

    #[test]
    fn rfc7748_iterated() {
        let mut k = h32("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for n in 1..=1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if n == 1 {
                assert_eq!(k, h32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
            }
        }
        assert_eq!(k, h32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
    }

    #[test]
    fn rfc7748_exchange() {
        // Section 6.1.
        let a = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(public(&a), h32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        assert_eq!(public(&b), h32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        let shared = h32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(exchange(&a, &public(&b)), Ok(shared));
        assert_eq!(exchange(&b, &public(&a)), Ok(shared));
    }

    #[test]
    fn small_order_points_are_refused() {
        let a = [7u8; 32];
        // 0, 1, and a point of order 8.
        for u in ["00", "01", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"] {
            let mut p = [0u8; 32];
            let b = hex(u);
            let n = u.len() / 2;
            p[..n].copy_from_slice(&b[..n]);
            assert_eq!(exchange(&a, &p), Err(LowOrder), "{u}");
        }
    }

    #[test]
    fn non_canonical_u_reduces() {
        // p + 9 encodes the same point as 9 (bit 255 ignored, then reduced).
        let k = [0x11u8; 32];
        let mut pu = h32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        pu[0] = pu[0].wrapping_add(9);
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert_eq!(x25519(&k, &pu), x25519(&k, &nine));
        let mut high = nine;
        high[31] |= 0x80;
        assert_eq!(x25519(&k, &high), x25519(&k, &nine));
    }
}
