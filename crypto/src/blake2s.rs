//! BLAKE2s-256 (RFC 7693; the kernel's own, `silica_formats::blake2s`,
//! which the loader conditions boot entropy with), and the HMAC and HKDF
//! that Noise builds on it.

pub use silica_formats::blake2s::Blake2s;

/// The hash's length, and Noise's `HASHLEN`.
pub const LEN: usize = 32;
/// The compression function's block, and HMAC's.
pub const BLOCK: usize = 64;

/// BLAKE2s-256 of the concatenation of `parts`.
pub fn hash(parts: &[&[u8]]) -> [u8; LEN] {
    let mut b = Blake2s::new();
    for p in parts {
        b.update(p);
    }
    b.finish()
}

/// HMAC-BLAKE2s (RFC 2104) of the concatenation of `parts`, with a key of
/// [`LEN`] bytes, as Noise uses it.
pub fn hmac(key: &[u8; LEN], parts: &[&[u8]]) -> [u8; LEN] {
    let mut k = [0u8; BLOCK];
    k[..LEN].copy_from_slice(key);
    let mut inner = Blake2s::new();
    let mut pad = k.map(|b| b ^ 0x36);
    inner.update(&pad);
    for p in parts {
        inner.update(p);
    }
    let ih = inner.finish();
    let mut outer = Blake2s::new();
    pad = k.map(|b| b ^ 0x5c);
    outer.update(&pad);
    outer.update(&ih);
    crate::wipe(&mut k);
    crate::wipe(&mut pad);
    outer.finish()
}

/// Noise's HKDF (section 4.3): two outputs from a chaining key and input
/// key material.
pub fn hkdf2(chaining: &[u8; LEN], ikm: &[u8]) -> ([u8; LEN], [u8; LEN]) {
    let mut temp = hmac(chaining, &[ikm]);
    let a = hmac(&temp, &[&[1]]);
    let b = hmac(&temp, &[&a, &[2]]);
    crate::wipe(&mut temp);
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn rfc7693_abc() {
        // Appendix B.
        assert_eq!(hash(&[b"abc"])[..], hex("508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982")[..32]);
    }

    #[test]
    fn known_answers() {
        // From the BLAKE2 reference's own vectors and `openssl dgst -blake2s256`.
        assert_eq!(hash(&[b""])[..], hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")[..32]);
        let block: [u8; 64] = core::array::from_fn(|i| i as u8);
        assert_eq!(hash(&[&block])[..], hex("56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e")[..32]);
        let more: [u8; 65] = core::array::from_fn(|i| i as u8);
        assert_eq!(hash(&[&more])[..], hex("1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472")[..32]);
    }

    #[test]
    fn pieces_make_the_whole() {
        let data: [u8; 300] = core::array::from_fn(|i| (i * 13 + 1) as u8);
        let whole = hash(&[&data]);
        for split in [0, 1, 63, 64, 65, 128, 129, 299, 300] {
            assert_eq!(hash(&[&data[..split], &data[split..]]), whole, "split at {split}");
        }
    }
}
