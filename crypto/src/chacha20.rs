//! ChaCha20 (RFC 8439 section 2.4): a 256-bit key, a 96-bit nonce and a
//! 32-bit block counter make a key stream that is added to the data.

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
}

/// The 64-byte block of key stream number `counter`.
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        init[4 + i] = word(key, i);
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = word(nonce, i);
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

/// Add the key stream from block `counter` on to `data` in place: the same
/// call encrypts and decrypts. The counter does not wrap: `data` may be at
/// most 2^32 - `counter` blocks long, as RFC 8439 requires.
pub fn apply(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for (n, chunk) in data.chunks_mut(64).enumerate() {
        let counter = counter.checked_add(n as u32).expect("ChaCha20's block counter would wrap");
        let mut ks = block(key, counter, nonce);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
        // The keystream is as secret as the key.
        crate::wipe(&mut ks);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn rfc8439_block() {
        // Section 2.3.2.
        let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[..32].try_into().unwrap();
        let nonce: [u8; 12] = hex("000000090000004a00000000")[..12].try_into().unwrap();
        let want = hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e
                        d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
        assert_eq!(block(&key, 1, &nonce)[..], want[..64]);
    }

    #[test]
    fn rfc8439_encryption() {
        // Section 2.4.2.
        let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[..32].try_into().unwrap();
        let nonce: [u8; 12] = hex("000000000000004a00000000")[..12].try_into().unwrap();
        let mut text =
            *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        apply(&key, 1, &nonce, &mut text);
        let want = hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
                        f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
                        07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
                        5af90bbf74a35be6b40b8eedf2785e42874d");
        assert_eq!(text[..], want[..text.len()]);
    }
}
