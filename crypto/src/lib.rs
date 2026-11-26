//! The cryptography Silica speaks on a network.
//!
//! Three primitives and one protocol built from them, the set WireGuard
//! chose and Noise names `25519_ChaChaPoly_BLAKE2s`:
//!
//! - [`x25519`]: Diffie-Hellman on Curve25519 (RFC 7748).
//! - [`aead`]: ChaCha20-Poly1305 (RFC 8439), from [`chacha20`] and
//!   [`poly1305`].
//! - [`blake2s`]: BLAKE2s-256 (RFC 7693, the kernel's own), with HMAC and
//!   Noise's HKDF.
//! - [`noise`]: the Noise IK handshake (revision 34) and the transport
//!   it leaves: how the owner's machine and a Silica machine that knows its
//!   key agree on keys in one round trip, each proving who it is.
//!
//! `no_std`, no allocation, no `unsafe`. Secret data never chooses a branch
//! or an address: the field arithmetic, the ladder's swap, Poly1305's last
//! reduction and tag comparison are masks, not conditions. Every primitive
//! is checked against its RFC's test vectors (`cargo test -p silica-crypto`).
#![no_std]
#![forbid(unsafe_code)]

pub mod aead;
pub mod blake2s;
pub mod chacha20;
pub mod noise;
pub mod poly1305;
pub mod x25519;

/// Whether `a` and `b` are equal, in time that depends only on their
/// lengths.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // 0 only when every byte was equal; no branch on the bytes themselves.
    (u16::from(d).wrapping_sub(1) >> 8) & 1 == 1
}

/// Overwrite `b` with zeros in a way the optimizer keeps: a secret that is
/// done with does not stay in memory a later bug could show.
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        *x = 0;
    }
    core::hint::black_box(b);
}

/// [`wipe`], for words.
pub fn wipe_words(w: &mut [u32]) {
    for x in w.iter_mut() {
        *x = 0;
    }
    core::hint::black_box(w);
}

#[cfg(test)]
pub(crate) fn hex(s: &str) -> [u8; 256] {
    let mut out = [0u8; 256];
    let s: &[u8] = s.as_bytes();
    let digits = s.iter().filter(|c| c.is_ascii_hexdigit()).count();
    assert!(digits % 2 == 0 && digits / 2 <= 256);
    let mut n = 0;
    let mut hi = None;
    for c in s.iter().filter(|c| c.is_ascii_hexdigit()) {
        let v = (*c as char).to_digit(16).unwrap() as u8;
        match hi.take() {
            None => hi = Some(v),
            Some(h) => {
                out[n] = h << 4 | v;
                n += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn equal_is_equality() {
        assert!(super::equal(b"abc", b"abc"));
        assert!(!super::equal(b"abc", b"abd"));
        assert!(!super::equal(b"abc", b"ab"));
        assert!(super::equal(b"", b""));
        for i in 0..=255u8 {
            assert_eq!(super::equal(&[i], &[0x5a]), i == 0x5a);
        }
    }
}
