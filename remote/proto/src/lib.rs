//! The remote management session's wire (`silica.remote.Session`'s page
//! says what travels; this crate is how), shared by the machine's service
//! (`remote`) and the owner's client (the host's `silica-remote`).
//!
//! A TCP connection carries messages, each its length (2 bytes,
//! big-endian) and that many bytes ([`Frames`] finds them in what arrived).
//! The first two are the Noise IK handshake ([`silica_crypto::noise`],
//! [`PROLOGUE`]; the owner's first message carries the time it was made,
//! [`stamp`], and the machine's answer nothing); every later one is sealed, and its plaintext
//! is a call ([`call`]: channel, IDL request) or an answer ([`answer`]:
//! channel, status, IDL reply).
//!
//! Keys travel as text: 64 hexadecimal digits. A machine's key file holds
//! its secret; its owners file holds a public key per line, each with a
//! name after it that the machine's log uses for whoever holds it
//! ([`owners`]).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub use silica_crypto::aead::TAG;
pub use silica_crypto::noise;

/// The port a machine listens on.
pub const PORT: u16 = 22;
/// Hashed into every handshake: a client of another protocol, or another
/// version of this one, fails the handshake instead of being misread.
pub const PROLOGUE: &[u8] = b"silica.remote 2";
/// The length of the payload of an owner's first handshake message: when
/// it was made ([`stamp`]).
pub const STAMP: usize = 8;

/// The payload of an owner's first handshake message: the owner's clock
/// in nanoseconds since 1970, big-endian. Sealed with the handshake, so
/// nobody but the owner makes one; a machine takes a first message from
/// an owner only with a time later than every one it took from that owner
/// before, so a first message recorded and sent again (by anyone who saw
/// it pass) is refused at once instead of being answered (version 2 of the
/// wire; version 1 carried none, and its replays were answered). An owner
/// whose clock goes back is refused until it is past its last time again,
/// as WireGuard does.
pub fn stamp(unix_ns: u64) -> [u8; STAMP] {
    unix_ns.to_be_bytes()
}

/// The time a first message's payload carries ([`stamp`]), or `None` for
/// a payload that is not one.
pub fn stamp_of(payload: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(payload.try_into().ok()?))
}

/// How far behind the machine's clock an owner's first message may be made
/// (its clock may lag): older is a recording.
pub const STAMP_WINDOW: u64 = 300_000_000_000;

/// What a first message made at `made` is, to a machine that took one made
/// at `newest` from that owner last and whose wall clock reads `wall`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stamp {
    /// Later than the last, and within [`STAMP_WINDOW`] of the clock.
    Fresh,
    /// Later than the last, but the machine does not know the time, so a
    /// recording made after the newest it kept cannot be told from a new
    /// message.
    Unjudged,
    /// No later than the last taken from the owner: a replay, or the
    /// owner's clock went back.
    Replayed,
    /// This many nanoseconds older than the clock allows.
    Stale(u64),
}

/// The wall clock first messages are judged by: the machine's, but never
/// earlier than this service has read it to be, so a step back (one time
/// server's answer moves the clock up to 1000 s, and anyone on the path to
/// it can answer) does not widen [`STAMP_WINDOW`] for a recording. Kept as
/// the largest wall-minus-monotonic offset read (`offset`, 0: the time was
/// never known), which this service keeps across its restarts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Floor {
    pub offset: u64,
}

impl Floor {
    /// The clock to judge by at monotonic time `now` (ns), given the
    /// machine's wall clock `wall` (`None`: unknown): `None` only while it
    /// was never known.
    pub fn read(&mut self, wall: Option<u64>, now: u64) -> Option<u64> {
        if let Some(w) = wall {
            self.offset = self.offset.max(w.saturating_sub(now));
        }
        (self.offset != 0).then(|| self.offset.saturating_add(now))
    }
}

/// The most handshakes answered while the machine does not know the time
/// ([`Stamp::Unjudged`]) that wait at once to be proven.
pub const MAX_UNJUDGED: usize = 2;

/// Of the unjudged handshakes waiting (each a key and its first message's
/// time), the one to close while more than [`MAX_UNJUDGED`] wait: the
/// oldest made. A recording is answered only while it is newer than every
/// first message taken from its owner, so an owner's new handshake is the
/// newest of its owner's and is never the one closed for a recording.
pub fn unjudged_to_close<K: Copy>(waiting: impl Iterator<Item = (K, u64)> + Clone) -> Option<K> {
    if waiting.clone().count() <= MAX_UNJUDGED {
        return None;
    }
    waiting.min_by_key(|w| w.1).map(|w| w.0)
}

/// Judge a first message's time ([`Stamp`]).
pub fn judge_stamp(made: u64, newest: u64, wall: Option<u64>) -> Stamp {
    if made <= newest {
        return Stamp::Replayed;
    }
    match wall {
        Some(w) if made.saturating_add(STAMP_WINDOW) < w => Stamp::Stale(w - made),
        Some(_) => Stamp::Fresh,
        None => Stamp::Unjudged,
    }
}

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

/// Why a piece of a program was not kept ([`Sending::write`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotKept {
    /// Past the largest program, or past the end of what was sent so far.
    TooLarge,
    /// No memory for it.
    NoRoom,
}

/// A program an owner is sending, a piece a call, as the machine's service
/// keeps it until the owner's `update`: in blocks of [`Sending::BLOCK`]
/// bytes, so a longer program costs one more block and never a copy of
/// what came before (a growing vector needed twice the program's size).
#[derive(Debug, Default)]
pub struct Sending {
    blocks: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    len: usize,
}

impl Sending {
    /// The bytes of one block.
    pub const BLOCK: usize = 1 << 16;

    /// The bytes it has memory for now: a piece ending past them needs more.
    pub fn room(&self) -> usize {
        self.blocks.len() * Self::BLOCK
    }

    /// The bytes sent so far.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing was sent.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Write `data` at byte `at`, the program at most `most` bytes. In
    /// order: a piece starts where the last one ended, or earlier; one at
    /// byte 0 starts another program, and the last one's memory goes
    /// first. A piece not kept changes nothing but that.
    pub fn write(&mut self, at: u64, data: &[u8], most: u64) -> Result<(), NotKept> {
        if at == 0 {
            *self = Sending::default();
        }
        let end = at.checked_add(data.len() as u64).filter(|e| *e <= most && at <= self.len as u64).ok_or(NotKept::TooLarge)?;
        let (at, end) = (at as usize, end as usize);
        while self.blocks.len() * Self::BLOCK < end {
            let mut block = alloc::vec::Vec::new();
            block.try_reserve_exact(Self::BLOCK).map_err(|_| NotKept::NoRoom)?;
            block.resize(Self::BLOCK, 0);
            self.blocks.try_reserve(1).map_err(|_| NotKept::NoRoom)?;
            self.blocks.push(block);
        }
        let mut done = 0;
        while done < data.len() {
            let (block, offset) = ((at + done) / Self::BLOCK, (at + done) % Self::BLOCK);
            let n = (Self::BLOCK - offset).min(data.len() - done);
            self.blocks[block][offset..offset + n].copy_from_slice(&data[done..done + n]);
            done += n;
        }
        self.len = self.len.max(end);
        Ok(())
    }

    /// The first `length` bytes, in order, as the offset and bytes of each
    /// part; `None` when fewer were sent.
    pub fn parts(&self, length: usize) -> Option<impl Iterator<Item = (usize, &[u8])>> {
        (length <= self.len).then(|| {
            self.blocks.iter().enumerate().map_while(move |(i, b)| {
                let at = i * Self::BLOCK;
                (at < length).then(|| (at, &b[..Self::BLOCK.min(length - at)]))
            })
        })
    }
}

/// A line of an owners file that is not an owner (see [`owners`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadLine(pub usize);

/// An owner an owners file names: its key, its name, what it may do (the
/// scopes), which services its `control` and `update` reach (`None`: the
/// line names none), and how long its sessions may stay without a whole
/// message, in seconds (`None`: the service's own bound), and its line
/// (from 1).
pub type Owner<'a> = ([u8; 32], &'a str, &'a str, Option<&'a str>, Option<u64>, usize);

/// The owners an owners file names: each line a public key, space, the
/// owner's name (no spaces in it), what the owner may do
/// (`silica.system.Manager` scopes joined with `+`, as a service
/// declaration gives them: `observe+control`), optionally
/// `controls=<service>,<service>...` (or `*`: every service the remote
/// service may control): the services its `control` and `update` reach,
/// and optionally `idle=<seconds>` (from 1): how long a session of that
/// owner's is kept with no whole message arriving, a bound on a peer set
/// where the peer is named. The scopes are not optional: a line without
/// them is no owner (it was given everything the remote service has, the
/// audit's M2). Blank lines and lines from `#` are skipped. The first line
/// that is none of these is an error naming it (from 1), so that a
/// mistyped key, scope or bound is never silently nobody's or nothing.
pub fn owners(text: &str) -> impl Iterator<Item = Result<Owner<'_>, BadLine>> {
    text.lines().enumerate().filter_map(|(n, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut words = line.split_ascii_whitespace();
        let key = words.next().and_then(parse_key);
        let name = words.next();
        let mut rest = words.peekable();
        let scopes = rest.next_if(|w| !w.contains('='));
        let controls = rest.next_if(|w| w.starts_with("controls=")).map(|w| &w[9..]);
        let idle = rest.next_if(|w| w.starts_with("idle=")).map(|w| w[5..].parse::<u64>().ok().filter(|s| *s > 0));
        // Every item of a list names something: an empty one (`controls=`,
        // `controls=,`, `controls=httpd,`) is a mistyped line.
        if controls.is_some_and(|c| c.split(',').any(str::is_empty)) {
            return Some(Err(BadLine(n + 1)));
        }
        Some(match (key, name, scopes, controls, idle, rest.next()) {
            (Some(k), Some(name), Some(s), c, None, None) => Ok((k, name, s, c, None, n + 1)),
            (Some(k), Some(name), Some(s), c, Some(Some(i)), None) => Ok((k, name, s, c, Some(i), n + 1)),
            _ => Err(BadLine(n + 1)),
        })
    })
}

/// The service that runs the sessions: reached by its name alone.
pub const SELF: &str = "remote";

/// Whether an owner's `controls=` list reaches service `name`: by its
/// name, or by `*`, which reaches every service but [`SELF`]. Updating the
/// remote service is holding its machine key and every scope it has, so an
/// owner does it only where its line names it.
pub fn controls(list: &str, name: &str) -> bool {
    list.split(',').any(|c| c == name || (c == "*" && name != SELF))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A step back of the machine's clock (up to 1000 s from one time
    /// server's answer) does not let a recording older than the window be
    /// judged fresh: first messages are judged by a clock that never goes
    /// back (the review of audit-net-auth). A step forward is taken.
    #[test]
    fn a_clock_stepped_back_does_not_widen_the_window() {
        let s = 1_000_000_000u64;
        let wall = 1_800_000_000 * s;
        let mut floor = Floor::default();
        assert_eq!(floor.read(None, 10 * s), None);
        assert_eq!(floor.read(Some(wall), 20 * s), Some(wall));
        // Ten seconds on, the clock is stepped back 999 s.
        let judged = floor.read(Some(wall + 10 * s - 999 * s), 30 * s);
        assert_eq!(judged, Some(wall + 10 * s), "the step back moved the clock first messages are judged by");
        let recording = wall - 1300 * s;
        assert!(matches!(judge_stamp(recording, 0, judged), Stamp::Stale(_)), "a recording 1300 s old judged fresh");
        // Forward steps are taken.
        assert_eq!(floor.read(Some(wall + 500 * s), 40 * s), Some(wall + 500 * s));
        assert_eq!(floor.read(None, 50 * s), Some(wall + 510 * s));
    }

    /// Handshakes answered while the time is unknown have a bound of their
    /// own, the oldest made closed first: recordings crowding in do not
    /// close an owner's new handshake, which is the newest (the review of
    /// audit-net-auth: as strangers, any crowd closed the oldest arrival,
    /// the owner's).
    #[test]
    fn an_owners_unjudged_handshake_outlasts_recordings() {
        let s = 1_000_000_000u64;
        // The owner's, made now, arrived first; recordings made before it.
        let waiting = [("owner", 1000 * s), ("r1", 10 * s), ("r2", 20 * s), ("r3", 30 * s)];
        let mut open: alloc::vec::Vec<(&str, u64)> = waiting.to_vec();
        while let Some(k) = unjudged_to_close(open.iter().copied()) {
            assert_ne!(k, "owner", "the owner's handshake was closed for room");
            open.retain(|w| w.0 != k);
        }
        assert_eq!(open.len(), MAX_UNJUDGED);
        assert!(open.iter().any(|w| w.0 == "owner"));
        assert_eq!(unjudged_to_close([("a", 1u64)].into_iter()), None);
    }

    /// A machine that does not know the time cannot tell a recorded first
    /// message made after the newest it kept from a new one: it says so
    /// (`Unjudged`) rather than calling it fresh (the audit of 2026-11-27,
    /// M9: the check of the clock was skipped and the recording answered as
    /// an owner's). Known times judge as before.
    #[test]
    fn a_first_message_is_judged_fresh_only_against_a_known_clock() {
        let s = 1_000_000_000u64;
        assert_eq!(judge_stamp(100 * s, 0, None), Stamp::Unjudged, "a recording answered as fresh while the time is unknown");
        assert_eq!(judge_stamp(100 * s, 100 * s, None), Stamp::Replayed);
        assert_eq!(judge_stamp(100 * s, 50 * s, Some(200 * s)), Stamp::Fresh);
        assert_eq!(judge_stamp(100 * s, 50 * s, Some(100 * s + STAMP_WINDOW + s)), Stamp::Stale(STAMP_WINDOW + s));
        assert_eq!(judge_stamp(100 * s, 0, Some(100 * s + STAMP_WINDOW)), Stamp::Fresh);
    }

    #[test]
    fn a_stamp_is_eight_bytes_of_time_and_nothing_else_is_one() {
        assert_eq!(stamp_of(&stamp(0x0102_0304_0506_0708)), Some(0x0102_0304_0506_0708));
        assert_eq!(stamp(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(stamp_of(&[]), None);
        assert_eq!(stamp_of(&[0; 7]), None);
        assert_eq!(stamp_of(&[0; 9]), None);
    }

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
        assert_eq!(got[0], Ok(([0; 32], "alice@laptop", "observe+control", Some("*"), None, 2)));
        assert_eq!(got[1], Ok(([0x11; 32], "ci", "observe", None, None, 4)));
        let scoped = std::format!("{a} watcher observe\n");
        assert_eq!(owners(&scoped).next(), Some(Ok(([0; 32], "watcher", "observe", None, None, 1))));
        // A bound on that owner's idle sessions, after its scopes; one that
        // is no number of seconds, zero, given twice or before the scopes
        // is the line's error.
        let line = |rest: &str| {
            owners(&std::format!("{a} w {rest}\n")).next().unwrap().map(|(_, _, s, c, i, _)| (String::from(s), c.map(String::from), i))
        };
        assert_eq!(line("observe idle=6"), Ok((String::from("observe"), None, Some(6))));
        assert_eq!(line("observe+control idle=3600"), Ok((String::from("observe+control"), None, Some(3600))));
        assert_eq!(
            line("observe+control controls=httpd,netd idle=5"),
            Ok((String::from("observe+control"), Some(String::from("httpd,netd")), Some(5)))
        );
        for bad in [
            "idle=",
            "idle=0",
            "observe idle=-1",
            "observe idle=six",
            "observe idle=6 idle=7",
            "idle=6 observe",
            "observe idle=6 more",
            "observe idle=6 controls=*",
            "controls=* observe",
            "observe controls=",
            "observe controls=,",
            "observe controls=httpd,",
            "observe controls=,httpd",
            "mode=1",
            "observe idle=99999999999999999999",
        ] {
            assert_eq!(line(bad), Err(BadLine(1)), "{bad}");
        }
        assert_eq!(owners(&std::format!("{a} x observe more\n")).next(), Some(Err(BadLine(1))));
        assert_eq!(owners(&text).count(), 2);
        assert_eq!(owners("# none\n\n").count(), 0);
        assert_eq!(owners("abc name\n").next(), Some(Err(BadLine(1))));
        let mut no_name = a.clone();
        no_name.insert(0, '\n');
        assert_eq!(owners(&no_name).next(), Some(Err(BadLine(2))));
    }

    /// An owner is given what its line says and nothing it does not: a line
    /// that names no scopes is no owner (before, it was given every scope
    /// the remote service has, update and power among them: the audit's
    /// M2).
    #[test]
    fn an_owner_line_names_its_scopes() {
        let a = "00".repeat(32);
        let first = |rest: &str| owners(&std::format!("{a} alice {rest}\n")).next().unwrap().map(|_| ());
        assert_eq!(first(""), Err(BadLine(1)), "an owner with no scopes");
        assert_eq!(first("idle=6"), Err(BadLine(1)), "an owner with no scopes, a bound on its sessions");
        assert_eq!(first("controls=*"), Err(BadLine(1)), "an owner with no scopes, the services they would reach");
        assert_eq!(first("observe"), Ok(()));
        // Whom a `controls=` list reaches: the names it gives, or every one.
        assert!(controls("httpd,netd", "netd") && !controls("httpd,netd", "logd") && controls("*", "logd"));
        // The remote service itself, only by its name: updating it is
        // holding its machine key and every scope (the review of
        // audit-control: `*` reached it).
        assert!(!controls("*", SELF) && controls("*,remote", SELF) && controls("remote", SELF));
        assert!(!controls("httpd", "http") && !controls("httpd", ""));
    }

    #[test]
    fn a_program_is_kept_in_order_and_within_its_bound() {
        let mut s = Sending::default();
        let most = 3 * Sending::BLOCK as u64;
        // Past what was sent so far, past the bound, or wrapping: not kept.
        assert_eq!(s.write(1, b"x", most), Err(NotKept::TooLarge));
        assert_eq!(s.write(u64::MAX, b"xy", most), Err(NotKept::TooLarge));
        assert_eq!(s.write(1 << 40, b"x", most), Err(NotKept::TooLarge));
        assert!(s.is_empty());
        // Pieces across a block's end, one rewritten in place.
        let bytes: std::vec::Vec<u8> = (0..2 * Sending::BLOCK + 100).map(|i| (i % 251) as u8).collect();
        for (k, piece) in bytes.chunks(3900).enumerate() {
            assert_eq!(s.write((k * 3900) as u64, piece, most), Ok(()));
        }
        assert_eq!(s.write(3900, &bytes[3900..7800], most), Ok(()));
        assert_eq!(s.len(), bytes.len());
        let mut got = std::vec![0u8; bytes.len()];
        for (at, part) in s.parts(bytes.len()).unwrap() {
            got[at..at + part.len()].copy_from_slice(part);
        }
        assert_eq!(got, bytes);
        // A shorter length is the first bytes; a longer one is not there.
        assert_eq!(s.parts(5).unwrap().map(|(at, p)| (at, p.len())).collect::<std::vec::Vec<_>>(), [(0, 5)]);
        assert!(s.parts(bytes.len() + 1).is_none());
        // Past the bound: refused, and what was sent stays.
        assert_eq!(s.write(bytes.len() as u64, &[0; 3900], bytes.len() as u64 + 10), Err(NotKept::TooLarge));
        assert_eq!(s.len(), bytes.len());
        // A piece at byte 0 starts another program.
        assert_eq!(s.write(0, b"new", most), Ok(()));
        assert_eq!(s.len(), 3);
        assert_eq!(s.parts(3).unwrap().next(), Some((0, &b"new"[..])));
        assert!(s.parts(4).is_none());
    }
    extern crate std;
    use std::string::String;

    fn owners_text(a: &str, b: &str) -> String {
        std::format!("# who may manage this machine\n{a} alice@laptop observe+control controls=*\n\n  {b} ci observe \n")
    }
}
