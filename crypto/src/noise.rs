//! The Noise IK handshake (Noise Protocol Framework, revision 34), as
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s`, and the transport it leaves.
//!
//! ```text
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se
//! ```
//!
//! The initiator knows the responder's static key before it starts (the
//! owner's tool knows the machine's, as `known_hosts` does for SSH) and
//! sends its own encrypted in the first message, so the responder learns
//! who is asking before it answers, and answers nobody it does not know.
//! One round trip; then each side has a key to send with and one to
//! receive with, and the handshake's hash, which names the session.
//!
//! The first message can be replayed by anyone who saw it: what it carries
//! (its payload) must be harmless to repeat. The transport keys depend on
//! the responder's fresh ephemeral, so nothing after the handshake can be.
//!
//! Every function works in place on caller buffers: no allocation.

use crate::aead::{self, TAG};
use crate::blake2s::{self, LEN};
use crate::x25519::{self, Public, Secret};

/// The protocol name, hashed into the first state.
pub const NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// The first message's length without its payload: `e`, the encrypted
/// `s` and the payload's tag.
pub const FIRST: usize = 32 + 32 + TAG + TAG;
/// The second message's length without its payload: `e` and the
/// payload's tag.
pub const SECOND: usize = 32 + TAG;

/// Why a handshake or transport message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The message is shorter than its fixed part, or the buffer for one
    /// is too small for it.
    Length,
    /// It does not authenticate: not made by the holder of the keys this
    /// side expects, or changed on the way.
    Forged,
    /// A key in it is of small order: no honest peer sends one.
    LowOrder,
    /// The 2^64 - 1 messages one key may seal are used up.
    Exhausted,
}

impl From<aead::Forged> for Error {
    fn from(_: aead::Forged) -> Self {
        Error::Forged
    }
}

impl From<x25519::LowOrder> for Error {
    fn from(_: x25519::LowOrder) -> Self {
        Error::LowOrder
    }
}

/// A static key: the secret and its public half, computed once.
#[derive(Clone)]
pub struct Keypair {
    pub secret: Secret,
    pub public: Public,
}

impl Keypair {
    pub fn new(secret: Secret) -> Keypair {
        Keypair { public: x25519::public(&secret), secret }
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        crate::wipe(&mut self.secret);
    }
}

/// A key and its nonce (Noise's CipherState).
pub struct Cipher {
    key: [u8; 32],
    n: u64,
}

impl Cipher {
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.n.to_le_bytes());
        nonce
    }

    /// Seal `buf[..len - TAG]` in place, its tag in the last [`TAG`] bytes.
    pub fn seal(&mut self, ad: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        if self.n == u64::MAX {
            return Err(Error::Exhausted);
        }
        if buf.len() < TAG {
            return Err(Error::Length);
        }
        aead::seal(&self.key, &self.nonce(), ad, buf);
        self.n += 1;
        Ok(())
    }

    /// Open `buf` in place: the plaintext's length, in its first bytes.
    pub fn open(&mut self, ad: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
        if self.n == u64::MAX {
            return Err(Error::Exhausted);
        }
        let n = aead::open(&self.key, &self.nonce(), ad, buf)?;
        self.n += 1;
        Ok(n)
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        crate::wipe(&mut self.key);
    }
}

/// Noise's SymmetricState.
struct Symmetric {
    ck: [u8; LEN],
    h: [u8; LEN],
    k: Option<Cipher>,
}

impl Symmetric {
    fn new(prologue: &[u8]) -> Self {
        // NAME is longer than HASHLEN: hashed.
        let h = blake2s::hash(&[NAME]);
        let mut s = Symmetric { ck: h, h, k: None };
        s.mix_hash(prologue);
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = blake2s::hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, mut ikm: [u8; 32]) {
        let (ck, k) = blake2s::hkdf2(&self.ck, &ikm);
        crate::wipe(&mut ikm);
        self.ck = ck;
        self.k = Some(Cipher { key: k, n: 0 });
    }

    /// Encrypt `buf[..len - TAG]` (with a key; there always is one where
    /// this is used) and hash the ciphertext.
    fn encrypt_and_hash(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let h = self.h;
        self.k.as_mut().ok_or(Error::Forged)?.seal(&h, buf)?;
        self.mix_hash(buf);
        Ok(())
    }

    fn decrypt_and_hash(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let h = self.h;
        let next = blake2s::hash(&[&self.h, buf]);
        let n = self.k.as_mut().ok_or(Error::Forged)?.open(&h, buf)?;
        self.h = next;
        Ok(n)
    }

    fn split(mut self) -> (Cipher, Cipher, [u8; LEN]) {
        let (a, b) = blake2s::hkdf2(&self.ck, &[]);
        crate::wipe(&mut self.ck);
        (Cipher { key: a, n: 0 }, Cipher { key: b, n: 0 }, self.h)
    }
}

/// What a finished handshake leaves: a cipher for each direction and the
/// handshake's hash.
pub struct Transport {
    pub send: Cipher,
    pub receive: Cipher,
    /// The handshake hash: the same on both sides, and on no other session.
    pub hash: [u8; LEN],
}

impl Transport {
    /// Seal `buf[..len - TAG]` in place for the peer.
    pub fn seal(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.send.seal(&[], buf)
    }

    /// Open a sealed message from the peer in place: its plaintext's length.
    pub fn open(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.receive.open(&[], buf)
    }
}

/// The side that starts: it knows the responder's static key.
pub struct Initiator {
    sym: Symmetric,
    s: Secret,
    e: Secret,
}

impl Initiator {
    /// Write the first message into `out`: `payload` after the fixed part
    /// ([`FIRST`] + payload bytes in all). `s` is this side's static
    /// secret, `rs` the responder's public key, `e` fresh random bytes.
    pub fn start(
        prologue: &[u8],
        s: &Keypair,
        rs: &Public,
        e: Secret,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<(Initiator, usize), Error> {
        let len = FIRST + payload.len();
        if out.len() < len {
            return Err(Error::Length);
        }
        let mut sym = Symmetric::new(prologue);
        sym.mix_hash(rs);
        // e
        let e_pub = x25519::public(&e);
        out[..32].copy_from_slice(&e_pub);
        sym.mix_hash(&e_pub);
        // es
        sym.mix_key(x25519::exchange(&e, rs)?);
        // s
        out[32..64].copy_from_slice(&s.public);
        sym.encrypt_and_hash(&mut out[32..64 + TAG])?;
        // ss
        sym.mix_key(x25519::exchange(&s.secret, rs)?);
        out[64 + TAG..len - TAG].copy_from_slice(payload);
        sym.encrypt_and_hash(&mut out[64 + TAG..len])?;
        Ok((Initiator { sym, s: s.secret, e }, len))
    }

    /// Read the responder's answer in place; its payload is
    /// `msg[32..32 + n]`.
    pub fn finish(mut self, msg: &mut [u8]) -> Result<(Transport, usize), Error> {
        if msg.len() < SECOND {
            return Err(Error::Length);
        }
        let re: Public = msg[..32].try_into().map_err(|_| Error::Length)?;
        self.sym.mix_hash(&re);
        // ee, se
        self.sym.mix_key(x25519::exchange(&self.e, &re)?);
        self.sym.mix_key(x25519::exchange(&self.s, &re)?);
        let n = self.sym.decrypt_and_hash(&mut msg[32..])?;
        msg.copy_within(32..32 + n, 0);
        let sym = core::mem::replace(&mut self.sym, Symmetric { ck: [0; LEN], h: [0; LEN], k: None });
        let (i2r, r2i, hash) = sym.split();
        Ok((Transport { send: i2r, receive: r2i, hash }, n))
    }
}

impl Drop for Initiator {
    fn drop(&mut self) {
        crate::wipe(&mut self.s);
        crate::wipe(&mut self.e);
    }
}

/// The side that answers, after the first message: it knows who asked
/// ([`Responder::peer`]) and decides whether to answer.
pub struct Responder {
    sym: Symmetric,
    re: Public,
    rs: Public,
}

impl Responder {
    /// Read the first message in place with this side's static secret
    /// `s`: the state to answer from, and the payload's length (it is
    /// `msg[..n]` afterwards).
    pub fn read(prologue: &[u8], s: &Keypair, msg: &mut [u8]) -> Result<(Responder, usize), Error> {
        if msg.len() < FIRST {
            return Err(Error::Length);
        }
        let mut sym = Symmetric::new(prologue);
        sym.mix_hash(&s.public);
        let re: Public = msg[..32].try_into().map_err(|_| Error::Length)?;
        sym.mix_hash(&re);
        sym.mix_key(x25519::exchange(&s.secret, &re)?);
        let k = sym.decrypt_and_hash(&mut msg[32..64 + TAG])?;
        debug_assert_eq!(k, 32);
        let rs: Public = msg[32..64].try_into().map_err(|_| Error::Length)?;
        sym.mix_key(x25519::exchange(&s.secret, &rs)?);
        let n = sym.decrypt_and_hash(&mut msg[64 + TAG..])?;
        msg.copy_within(64 + TAG..64 + TAG + n, 0);
        Ok((Responder { sym, re, rs }, n))
    }

    /// The initiator's static public key: who is asking. It has proved it
    /// holds the secret half only once the session's first transport
    /// message opens (the `ss` term binds it, but a replayed first message
    /// carries it too).
    pub fn peer(&self) -> &Public {
        &self.rs
    }

    /// Write the answer into `out` ([`SECOND`] + payload bytes), with `e`
    /// fresh random bytes; the session's transport.
    pub fn answer(mut self, mut e: Secret, payload: &[u8], out: &mut [u8]) -> Result<(Transport, usize), Error> {
        let len = SECOND + payload.len();
        if out.len() < len {
            return Err(Error::Length);
        }
        let e_pub = x25519::public(&e);
        out[..32].copy_from_slice(&e_pub);
        self.sym.mix_hash(&e_pub);
        let ee = x25519::exchange(&e, &self.re);
        let se = x25519::exchange(&e, &self.rs);
        crate::wipe(&mut e);
        self.sym.mix_key(ee?);
        self.sym.mix_key(se?);
        out[32..len - TAG].copy_from_slice(payload);
        self.sym.encrypt_and_hash(&mut out[32..len])?;
        let (i2r, r2i, hash) = self.sym.split();
        Ok((Transport { send: r2i, receive: i2r, hash }, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROLOGUE: &[u8] = b"test";

    fn keys(seed: u8) -> (Keypair, Public) {
        let k = Keypair::new(core::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8)));
        let p = k.public;
        (k, p)
    }

    fn eph(seed: u8) -> Secret {
        keys(seed).0.secret
    }

    fn handshake() -> (Transport, Transport) {
        let (is, _) = keys(1);
        let (rs, rp) = keys(2);
        let mut m1 = [0u8; 256];
        let (init, n1) = Initiator::start(PROLOGUE, &is, &rp, eph(3), b"hello", &mut m1).unwrap();
        let (resp, p) = Responder::read(PROLOGUE, &rs, &mut m1[..n1]).unwrap();
        assert_eq!(&m1[..p], b"hello");
        assert_eq!(resp.peer(), &keys(1).1);
        let mut m2 = [0u8; 256];
        let (rt, n2) = resp.answer(eph(4), b"hi", &mut m2).unwrap();
        let (it, p) = init.finish(&mut m2[..n2]).unwrap();
        assert_eq!(&m2[..p], b"hi");
        assert_eq!(it.hash, rt.hash);
        (it, rt)
    }

    #[test]
    fn both_sides_agree_and_talk() {
        let (mut i, mut r) = handshake();
        for round in 0..5u8 {
            let mut b = [round; 40 + TAG];
            i.seal(&mut b).unwrap();
            assert_eq!(r.open(&mut b), Ok(40));
            assert_eq!(b[..40], [round; 40]);
            let mut b = [round ^ 0xff; 7 + TAG];
            r.seal(&mut b).unwrap();
            assert_eq!(i.open(&mut b), Ok(7));
        }
    }

    #[test]
    fn a_message_out_of_order_or_repeated_is_refused() {
        let (mut i, mut r) = handshake();
        let mut a = [1u8; 8 + TAG];
        let mut b = [2u8; 8 + TAG];
        i.seal(&mut a).unwrap();
        i.seal(&mut b).unwrap();
        let mut b2 = b;
        assert_eq!(r.open(&mut b2), Err(Error::Forged));
        let (mut i, mut r) = handshake();
        let mut a = [1u8; 8 + TAG];
        i.seal(&mut a).unwrap();
        let mut again = a;
        assert_eq!(r.open(&mut a), Ok(8));
        assert_eq!(r.open(&mut again), Err(Error::Forged));
    }

    #[test]
    fn the_wrong_machine_key_fails_the_first_message() {
        let (is, _) = keys(1);
        let (_, rp) = keys(2);
        let (other, _) = keys(9);
        let mut m1 = [0u8; 128];
        let (_, n1) = Initiator::start(PROLOGUE, &is, &rp, eph(3), b"", &mut m1).unwrap();
        assert!(matches!(Responder::read(PROLOGUE, &other, &mut m1[..n1]), Err(Error::Forged)));
    }

    #[test]
    fn a_different_prologue_fails() {
        let (is, _) = keys(1);
        let (rs, rp) = keys(2);
        let mut m1 = [0u8; 128];
        let (_, n1) = Initiator::start(b"one", &is, &rp, eph(3), b"", &mut m1).unwrap();
        assert!(matches!(Responder::read(b"two", &rs, &mut m1[..n1]), Err(Error::Forged)));
    }

    #[test]
    fn every_changed_byte_is_refused() {
        let (is, _) = keys(1);
        let (rs, rp) = keys(2);
        let mut m1 = [0u8; 128];
        let (init, n1) = Initiator::start(PROLOGUE, &is, &rp, eph(3), b"x", &mut m1).unwrap();
        for k in 0..n1 {
            let mut m = m1;
            m[k] ^= 0x20;
            assert!(Responder::read(PROLOGUE, &rs, &mut m[..n1]).is_err(), "first message, byte {k}");
        }
        let (resp, _) = Responder::read(PROLOGUE, &rs, &mut { m1 }[..n1]).unwrap();
        let mut m2 = [0u8; 128];
        let (_, n2) = resp.answer(eph(4), b"y", &mut m2).unwrap();
        // The initiator can only finish once; check each change on a fresh one.
        drop(init);
        for k in 0..n2 {
            let mut m = m2;
            m[k] ^= 0x20;
            let mut fresh = [0u8; 128];
            let (init, _) = Initiator::start(PROLOGUE, &is, &rp, eph(3), b"x", &mut fresh).unwrap();
            assert!(init.finish(&mut m[..n2]).is_err(), "second message, byte {k}");
        }
        for short in 0..FIRST {
            assert!(matches!(Responder::read(PROLOGUE, &rs, &mut { m1 }[..short]), Err(Error::Length)));
        }
    }

    #[test]
    fn a_replayed_first_message_gives_the_replayer_nothing() {
        // The responder answers a replay with a new ephemeral; without the
        // initiator's ephemeral secret the attacker cannot open what follows,
        // and the transport differs from the real session's.
        let (is, _) = keys(1);
        let (rs, rp) = keys(2);
        let mut m1 = [0u8; 128];
        let (_, n1) = Initiator::start(PROLOGUE, &is, &rp, eph(3), b"", &mut m1).unwrap();
        let (r1, _) = Responder::read(PROLOGUE, &rs, &mut { m1 }[..n1]).unwrap();
        let (r2, _) = Responder::read(PROLOGUE, &rs, &mut { m1 }[..n1]).unwrap();
        let (t1, _) = r1.answer(eph(4), b"", &mut [0u8; 64]).unwrap();
        let (t2, _) = r2.answer(eph(5), b"", &mut [0u8; 64]).unwrap();
        assert_ne!(t1.hash, t2.hash);
    }

    /// The Noise_IK_25519_ChaChaPoly_BLAKE2s vector of cacophony's
    /// `vectors/cacophony.txt` (haskell-cryptography/cacophony): the
    /// handshake and four transport messages, byte for byte.
    #[test]
    fn cacophony_vector() {
        use crate::hex;
        fn h32(s: &str) -> [u8; 32] {
            hex(s)[..32].try_into().unwrap()
        }
        fn bytes(s: &str) -> ([u8; 256], usize) {
            (hex(s), s.len() / 2)
        }
        let prologue = &hex("4a6f686e2047616c74")[..9];
        let is = Keypair::new(h32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
        let ie = h32("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
        let rs = Keypair::new(h32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
        let re = h32("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
        assert_eq!(rs.public, h32("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"));
        let messages = [
            (
                "4c756477696720766f6e204d69736573",
                "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440b03ddc7aac5123d06a1b23b71670e32e76c28239a7ca4ac8f784de7e44c1adbfc6e83fef7352a58d9d56157400c0a737b1d171ce368229c7b752ac25b8faf4eca690f6d896f543be02c996ab2b86b76",
            ),
            (
                "4d757272617920526f746862617264",
                "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d9b5a8927f0ac9655ef76833bc7e5561f42e691ac8404efd6fbd6308b6a27c",
            ),
            ("462e20412e20486179656b", "2c256ed08fcd08c2980f954ee4beaccb61c9581340f5dd2fd1cf3b"),
            ("4361726c204d656e676572", "d6033f70eee20945c7c9dba304e397ee3b284ff5e00fd9efb095d3"),
            ("4a65616e2d426170746973746520536179", "a9c068ca5d8babf72560652d8e851adbfac35c8a66e810d560863173e96adf4cfe"),
            ("457567656e2042f6686d20766f6e2042617765726b", "2a09d8f459e5927e40fdd2eddc99bdafb04e13a26f145cb5cfe9e6ba34c94331ebc17d5156"),
        ];
        let (p, pn) = bytes(messages[0].0);
        let (c, cn) = bytes(messages[0].1);
        let mut out = [0u8; 256];
        let (init, n) = Initiator::start(prologue, &is, &rs.public, ie, &p[..pn], &mut out).unwrap();
        assert_eq!(out[..n], c[..cn], "first message");
        let (resp, k) = Responder::read(prologue, &rs, &mut out[..n]).unwrap();
        assert_eq!(out[..k], p[..pn]);
        assert_eq!(resp.peer(), &is.public);
        let (p, pn) = bytes(messages[1].0);
        let (c, cn) = bytes(messages[1].1);
        let (mut rt, n) = resp.answer(re, &p[..pn], &mut out).unwrap();
        assert_eq!(out[..n], c[..cn], "second message");
        let (mut it, k) = init.finish(&mut out[..n]).unwrap();
        assert_eq!(out[..k], p[..pn]);
        assert_eq!(it.hash, h32("48f3cb8bc9319da4ba1e9933991b1c4ed4034f1f126a76d3a1fbcfd7f94248d4"));
        assert_eq!(rt.hash, it.hash);
        // Transport: the initiator sends the odd ones, the responder the even.
        for (m, (payload, cipher)) in messages.iter().enumerate().skip(2) {
            let (p, pn) = bytes(payload);
            let (c, cn) = bytes(cipher);
            let (from, to) = if m % 2 == 0 { (&mut it, &mut rt) } else { (&mut rt, &mut it) };
            let mut b = [0u8; 256];
            b[..pn].copy_from_slice(&p[..pn]);
            from.seal(&mut b[..pn + TAG]).unwrap();
            assert_eq!(b[..cn], c[..cn], "message {m}");
            assert_eq!(to.open(&mut b[..cn]), Ok(pn));
            assert_eq!(b[..pn], p[..pn]);
        }
    }

    #[test]
    fn a_low_order_ephemeral_is_refused() {
        let (rs, _) = keys(2);
        let mut m = [0u8; FIRST];
        assert!(matches!(Responder::read(PROLOGUE, &rs, &mut m), Err(Error::LowOrder)));
    }
}
