//! ChaCha20-Poly1305 (RFC 8439 section 2.8): encryption with associated
//! data. The tag is [`TAG`] bytes, appended to the ciphertext.

use crate::chacha20;
use crate::poly1305::Poly1305;

/// The length of the authentication tag.
pub const TAG: usize = 16;

/// The message was not sealed with this key, nonce and associated data,
/// or it was changed on the way. Nothing of it may be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forged;

fn mac(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let block = chacha20::block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[..32]);
    let mut p = Poly1305::new(&otk);
    crate::wipe(&mut otk);
    p.update(ad);
    p.pad16();
    p.update(ciphertext);
    p.pad16();
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    p.update(&lens);
    p.finish()
}

/// Encrypt `buf[..buf.len() - TAG]` in place and write its tag into the
/// last [`TAG`] bytes.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], buf: &mut [u8]) {
    let n = buf.len().checked_sub(TAG).expect("a sealed message has room for its tag");
    let (text, tag) = buf.split_at_mut(n);
    chacha20::apply(key, 1, nonce, text);
    tag.copy_from_slice(&mac(key, nonce, ad, text));
}

/// Check the tag in the last [`TAG`] bytes of `buf` and decrypt the rest
/// in place. On [`Forged`] the buffer is left as it came (nothing was
/// decrypted).
pub fn open(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], buf: &mut [u8]) -> Result<usize, Forged> {
    let n = buf.len().checked_sub(TAG).ok_or(Forged)?;
    let (text, tag) = buf.split_at_mut(n);
    if !crate::equal(&mac(key, nonce, ad, text), tag) {
        return Err(Forged);
    }
    chacha20::apply(key, 1, nonce, text);
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn rfc8439_aead() {
        // Section 2.8.2.
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")[..32].try_into().unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647")[..12].try_into().unwrap();
        let ad = &hex("50515253c0c1c2c3c4c5c6c7")[..12];
        let text = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut buf = [0u8; 114 + TAG];
        buf[..114].copy_from_slice(text);
        seal(&key, &nonce, ad, &mut buf);
        let want = hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
                        3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
                        92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
                        3ff4def08e4b7a9de576d26586cec64b6116");
        assert_eq!(buf[..114], want[..114]);
        assert_eq!(buf[114..], hex("1ae10b594f09e26a7e902ecbd0600691")[..16]);
        assert_eq!(open(&key, &nonce, ad, &mut buf), Ok(114));
        assert_eq!(&buf[..114], &text[..]);
    }

    #[test]
    fn any_change_is_refused() {
        let key = [9u8; 32];
        let nonce = [1u8; 12];
        let mut sealed = [0u8; 40 + TAG];
        sealed[..40].copy_from_slice(&[0x42; 40]);
        seal(&key, &nonce, b"ad", &mut sealed);
        for i in 0..sealed.len() {
            let mut b = sealed;
            b[i] ^= 1;
            assert_eq!(open(&key, &nonce, b"ad", &mut b), Err(Forged), "byte {i}");
            assert_eq!(
                b[..],
                {
                    let mut c = sealed;
                    c[i] ^= 1;
                    c
                }[..],
                "a refused message is left as it came"
            );
        }
        let mut b = sealed;
        assert_eq!(open(&key, &nonce, b"aD", &mut b), Err(Forged));
        let mut b = sealed;
        assert_eq!(open(&key, &[2; 12], b"ad", &mut b), Err(Forged));
        let mut short = [0u8; 15];
        assert_eq!(open(&key, &nonce, b"", &mut short), Err(Forged));
    }
}
