//! The remote management session's wire (`silica.remote.Session`'s page
//! says what travels; this crate is how), shared by the machine's service
//! (`remote`) and the owner's client (the host's `silica-remote`).
//!
//! A TCP connection carries messages, each its length (2 bytes,
//! big-endian) and that many bytes ([`Frames`] finds them in what arrived).
//! The first two are the Noise IK handshake ([`silica_crypto::noise`],
//! [`PROLOGUE`], no payloads); every later one is sealed, and its plaintext
//! is a call ([`call`]: channel, IDL request) or an answer ([`answer`]:
//! channel, status, IDL reply).
//!
//! Keys travel as text: 64 hexadecimal digits. A machine's key file holds
//! its secret; its owners file holds a public key per line, each with a
//! name after it that the machine's log uses for whoever holds it
//! ([`owners`]).
#![no_std]
#![forbid(unsafe_code)]

pub use silica_crypto::aead::TAG;
pub use silica_crypto::noise;

/// The port a machine listens on.
pub const PORT: u16 = 22;
/// Hashed into every handshake: a client of another protocol, or another
/// version of this one, fails the handshake instead of being misread.
pub const PROLOGUE: &[u8] = b"silica.remote 1";
/// The largest IDL message (`silica_idl_rt::MAX_MESSAGE`).
pub const MAX_MESSAGE: usize = 4000;
/// The largest plaintext: an answer's channel and status, then a message.
pub const MAX_PLAIN: usize = 2 + MAX_MESSAGE;
/// The largest message on the connection after its length.
pub const MAX_FRAME: usize = MAX_PLAIN + TAG;
/// The channel of `silica.remote.Session` itself.
pub const SESSION: u8 = 0;

/// What an answer says about its call before the reply (`answer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// The IDL reply follows.
    Reply = 0,
    /// The protocol's provider went away during the call.
    PeerGone = 1,
    /// The machine holds no capability to the protocol (any more).
    Revoked = 2,
    /// No protocol has that channel.
    NoChannel = 3,
}

impl Status {
    pub fn from_u8(b: u8) -> Option<Status> {
        Some(match b {
            0 => Status::Reply,
            1 => Status::PeerGone,
            2 => Status::Revoked,
            3 => Status::NoChannel,
            _ => return None,
        })
    }
}

/// A message's length did not fit the protocol (0, or past [`MAX_FRAME`]):
/// the connection is not this protocol's, or its peer is broken. Nothing
/// more from it can be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadLength(pub usize);

/// Messages in the bytes a connection delivered.
pub struct Frames;

impl Frames {
    /// The first whole message in `input` as the range of its bytes (after
    /// its length) and how many bytes of `input` it took in all; `None`
    /// while it has not all arrived.
    pub fn next(input: &[u8]) -> Result<Option<(core::ops::Range<usize>, usize)>, BadLength> {
        let [a, b, ..] = *input else { return Ok(None) };
        let n = usize::from(u16::from_be_bytes([a, b]));
        if n == 0 || n > MAX_FRAME {
            return Err(BadLength(n));
        }
        if input.len() < 2 + n {
            return Ok(None);
        }
        Ok(Some((2..2 + n, 2 + n)))
    }

    /// The two bytes of length to send before a message of `n` bytes.
    pub fn length(n: usize) -> [u8; 2] {
        debug_assert!(n > 0 && n <= MAX_FRAME);
        (n as u16).to_be_bytes()
    }
}

/// A call's plaintext: its channel and the IDL request, or `None` for a
/// plaintext too short to have both.
pub fn call(plain: &[u8]) -> Option<(u8, &[u8])> {
    let (&channel, request) = plain.split_first()?;
    (!request.is_empty()).then_some((channel, request))
}

/// An answer's plaintext: its channel, its status and the IDL reply (empty
/// unless the status is [`Status::Reply`]).
pub fn answer(plain: &[u8]) -> Option<(u8, Status, &[u8])> {
    let [channel, status, reply @ ..] = plain else { return None };
    Some((*channel, Status::from_u8(*status)?, reply))
}

/// A key: 64 hexadecimal digits, with nothing else but space around them.
pub fn parse_key(text: &str) -> Option<[u8; 32]> {
    let t = text.trim().as_bytes();
    if t.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in t.chunks(2).enumerate() {
        let d = |c: u8| (c as char).to_digit(16);
        out[i] = (d(pair[0])? << 4 | d(pair[1])?) as u8;
    }
    Some(out)
}

/// A key as the text [`parse_key`] reads.
pub fn key_text(key: &[u8; 32]) -> [u8; 64] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in key.iter().enumerate() {
        out[2 * i] = DIGITS[usize::from(b >> 4)];
        out[2 * i + 1] = DIGITS[usize::from(b & 15)];
    }
    out
}

/// A line of an owners file that is not a key and a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadLine(pub usize);

/// The owners an owners file names: each line a public key, space, and the
/// owner's name (no spaces in it); blank lines and lines from `#` are
/// skipped. The first line that is neither is an error naming it (from 1),
/// so that a mistyped key is never silently nobody.
pub fn owners(text: &str) -> impl Iterator<Item = Result<([u8; 32], &str), BadLine>> {
    text.lines().enumerate().filter_map(|(n, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut words = line.split_ascii_whitespace();
        let key = words.next().and_then(parse_key);
        let name = words.next();
        Some(match (key, name, words.next()) {
            (Some(k), Some(name), None) => Ok((k, name)),
            _ => Err(BadLine(n + 1)),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_found_whole() {
        assert_eq!(Frames::next(&[]), Ok(None));
        assert_eq!(Frames::next(&[0]), Ok(None));
        assert_eq!(Frames::next(&[0, 3, 1, 2]), Ok(None));
        assert_eq!(Frames::next(&[0, 3, 1, 2, 3, 9]), Ok(Some((2..5, 5))));
        assert_eq!(Frames::next(&[0, 0]), Err(BadLength(0)));
        let too = Frames::length(MAX_FRAME);
        assert_eq!(Frames::next(&too), Ok(None));
        let past = ((MAX_FRAME + 1) as u16).to_be_bytes();
        assert_eq!(Frames::next(&past), Err(BadLength(MAX_FRAME + 1)));
    }

    #[test]
    fn calls_and_answers() {
        assert_eq!(call(&[]), None);
        assert_eq!(call(&[1]), None);
        assert_eq!(call(&[1, 7, 8]), Some((1, &[7u8, 8][..])));
        assert_eq!(answer(&[2]), None);
        assert_eq!(answer(&[2, 9]), None);
        assert_eq!(answer(&[2, 1]), Some((2, Status::PeerGone, &[][..])));
        assert_eq!(answer(&[2, 0, 5]), Some((2, Status::Reply, &[5u8][..])));
    }

    #[test]
    fn keys_round_trip() {
        let k: [u8; 32] = core::array::from_fn(|i| (i * 37) as u8);
        let t = key_text(&k);
        assert_eq!(parse_key(core::str::from_utf8(&t).unwrap()), Some(k));
        assert_eq!(parse_key("  00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF\n").map(|k| k[31]), Some(0xff));
        assert_eq!(parse_key("0011"), None);
        assert_eq!(parse_key(&"g".repeat(64)), None);
        assert_eq!(parse_key(&"0".repeat(65)), None);
    }

    #[test]
    fn owners_files() {
        let a = "00".repeat(32);
        let b = "11".repeat(32);
        let text = owners_text(&a, &b);
        let got: [_; 2] = {
            let mut it = owners(&text);
            [it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!(got[0], Ok(([0; 32], "alice@laptop")));
        assert_eq!(got[1], Ok(([0x11; 32], "ci")));
        assert_eq!(owners(&text).count(), 2);
        assert_eq!(owners("# none\n\n").count(), 0);
        assert_eq!(owners("abc name\n").next(), Some(Err(BadLine(1))));
        let mut no_name = a.clone();
        no_name.insert(0, '\n');
        assert_eq!(owners(&no_name).next(), Some(Err(BadLine(2))));
    }

    extern crate std;
    use std::string::String;

    fn owners_text(a: &str, b: &str) -> String {
        std::format!("# who may manage this machine\n{a} alice@laptop\n\n  {b} ci  \n")
    }
}
