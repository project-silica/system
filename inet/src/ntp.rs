//! SNTP: a time server's answer, read, and a question built (RFC 5905's
//! client side, as RFC 4330 describes it for a client of one server).
//!
//! An NTP timestamp is seconds since 1900-01-01 in its high 32 bits and a
//! binary fraction in its low 32; it wraps in 2036, so a timestamp whose
//! seconds are below 2^31 is taken to be after that (era 1), as RFC 5905
//! section 6 suggests for clients that know the time to within 68 years.

use crate::Malformed;

/// The port servers answer on.
pub const PORT: u16 = 123;
/// Bytes of a message without extensions.
pub const LEN: usize = 48;
/// Seconds from 1900-01-01 to 1970-01-01.
const UNIX_EPOCH: u64 = 2_208_988_800;
const NS: u64 = 1_000_000_000;

/// The NTP timestamp of `ns` nanoseconds since 1970.
pub fn from_unix_ns(ns: u64) -> u64 {
    let secs = (ns / NS + UNIX_EPOCH) & 0xFFFF_FFFF;
    let frac = ((ns % NS) << 32) / NS;
    secs << 32 | frac
}

/// Nanoseconds since 1970. A missing timestamp or a date before 1970
/// has no value in the system's unsigned wall clock.
pub fn to_unix_ns(t: u64) -> Option<u64> {
    if t == 0 {
        return None;
    }
    let mut secs = t >> 32;
    if secs < 1 << 31 {
        secs += 1 << 32; // the era after 2036
    }
    let frac = ((t & 0xFFFF_FFFF) * NS) >> 32;
    Some(secs.checked_sub(UNIX_EPOCH)? * NS + frac)
}

/// A client's question carrying `transmit`, which the answer must echo:
/// the client's guard against answers it did not ask for, so not its clock
/// (which anyone can guess) but a random number it keeps (RFC 5905
/// section 9.1 allows any value; the client keeps its own send time).
pub fn request(out: &mut [u8; LEN], transmit: u64) {
    out.fill(0);
    out[0] = 4 << 3 | 3; // no leap warning, version 4, client
    out[40..48].copy_from_slice(&transmit.to_be_bytes());
}

/// A server's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub stratum: u8,
    /// The question's transmit time, echoed (`T1`).
    pub originate: u64,
    /// When the server received the question (`T2`) and sent this (`T3`).
    pub receive: u64,
    pub transmit: u64,
}

fn be64(p: &[u8], at: usize) -> u64 {
    u64::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3], p[at + 4], p[at + 5], p[at + 6], p[at + 7]])
}

/// Read a server's answer (a UDP payload). Refused: a message too short, not
/// a server's (mode 4) of version 3 or 4, from a server that is not
/// synchronized (leap indicator 3, or stratum 0, a "kiss of death", or
/// above 15), or without the times a client needs.
pub fn parse(p: &[u8]) -> Result<Reply, Malformed> {
    if p.len() < LEN {
        return Err(Malformed::Truncated);
    }
    let (leap, version, mode) = (p[0] >> 6, (p[0] >> 3) & 7, p[0] & 7);
    let stratum = p[1];
    if mode != 4 || !(3..=4).contains(&version) || leap == 3 || !(1..=15).contains(&stratum) {
        return Err(Malformed::BadHeader);
    }
    let r = Reply { stratum, originate: be64(p, 24), receive: be64(p, 32), transmit: be64(p, 40) };
    if r.originate == 0 || r.receive == 0 || r.transmit == 0 {
        return Err(Malformed::BadHeader);
    }
    Ok(r)
}

/// The clock's offset from the server's and the round trip's delay, in
/// nanoseconds, from the four times (all nanoseconds since 1970): `t1` the
/// question sent and `t4` the answer received by the client's clock, `t2`
/// and `t3` the server's (RFC 5905 section 8). The offset is what to add
/// to the client's clock. `None` for times that cannot be: the server
/// sending before it received, the answer before the question, a delay
/// below zero, or an offset past what 64 bits of nanoseconds hold.
pub fn offset(t1: u64, t2: u64, t3: u64, t4: u64) -> Option<(i64, i64)> {
    if t3 < t2 || t4 < t1 {
        return None;
    }
    let d = |a: u64, b: u64| a as i128 - b as i128;
    let offset = (d(t2, t1) + d(t3, t4)) / 2;
    let delay = d(t4, t1) - d(t3, t2);
    if delay < 0 {
        return None;
    }
    Some((i64::try_from(offset).ok()?, i64::try_from(delay).ok()?))
}

/// The longest round trip an answer may take to be believed: a longer one
/// leaves too much room for its times to be wrong (half of it is the
/// offset's uncertainty).
pub const DELAY_MOST: i64 = 1_000_000_000;
/// The most a clock is moved by one answer: past it, the answer is not
/// believed alone (ntpd's panic threshold), whether the clock was set or
/// not (one nothing set reads 1970, so every answer moves it this far).
/// [`Steps`] takes such a step once a second answer agrees.
pub const STEP_MOST: u64 = 1000 * NS;

/// Why an answer is not believed ([`judge`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Its times cannot be ([`offset`]).
    Impossible,
    /// The round trip took this many nanoseconds, past [`DELAY_MOST`].
    Slow(i64),
    /// It would move the clock by this many nanoseconds, past [`STEP_MOST`].
    Step(i64),
    /// As `Step`, and no earlier answer agrees yet ([`Steps`]).
    Unconfirmed(i64),
}

/// Whether to believe an answer with the four times of [`offset`] alone:
/// the offset to add to the client's clock and the round trip, or why
/// not.
pub fn judge(t1: u64, t2: u64, t3: u64, t4: u64) -> Result<(i64, i64), Refused> {
    let (shift, delay) = offset(t1, t2, t3, t4).ok_or(Refused::Impossible)?;
    if delay > DELAY_MOST {
        return Err(Refused::Slow(delay));
    }
    if shift.unsigned_abs() > STEP_MOST {
        return Err(Refused::Step(shift));
    }
    Ok((shift, delay))
}

/// How far apart two answers must come to confirm a step past [`STEP_MOST`]
/// ([`Steps`]): separate questions, each with its own random number and port.
pub const CONFIRM_APART: u64 = NS;

/// A clock's steps past [`STEP_MOST`]: one answer never makes one, two
/// answers to separate questions at least [`CONFIRM_APART`] apart that agree
/// within their round trips do. So a lie, or a wrong first answer, is not
/// locked in or acted on alone, and a clock that really is wrong (a
/// firmware's clock years out, set before a restart) is still corrected.
#[derive(Clone, Copy, Debug, Default)]
pub struct Steps {
    /// The last step refused: its offset, round trip, and when (ns).
    pending: Option<(i64, i64, u64)>,
}

impl Steps {
    pub const fn new() -> Steps {
        Steps { pending: None }
    }

    /// [`judge`], at `now` (ns, monotonic): a step past [`STEP_MOST`] is
    /// [`Refused::Unconfirmed`] until a second answer agrees, whether the
    /// clock was set or not.
    pub fn judge(&mut self, t1: u64, t2: u64, t3: u64, t4: u64, now: u64) -> Result<(i64, i64), Refused> {
        match judge(t1, t2, t3, t4) {
            Err(Refused::Step(shift)) => {
                // Within the limits judge checked but the step.
                let delay = offset(t1, t2, t3, t4).map_or(DELAY_MOST, |(_, d)| d);
                if let Some((before, before_delay, at)) = self.pending
                    && now.saturating_sub(at) >= CONFIRM_APART
                    && shift.abs_diff(before) <= (before_delay + delay) as u64 + 10_000_000
                {
                    self.pending = None;
                    return Ok((shift, delay));
                }
                self.pending = Some((shift, delay, now));
                Err(Refused::Unconfirmed(shift))
            }
            Ok(j) => {
                self.pending = None;
                Ok(j)
            }
            e => e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_time_starts_at_the_unix_epoch() {
        let epoch = UNIX_EPOCH << 32;
        assert_eq!(to_unix_ns(epoch - 1), None);
        assert_eq!(to_unix_ns(epoch), Some(0));
        assert_eq!(to_unix_ns(epoch + (1 << 31)), Some(NS / 2));
    }

    #[test]
    fn timestamps_round_trip_and_wrap_in_2036() {
        let ns = 1_795_483_425_123_456_789; // 2026-11-24
        let t = from_unix_ns(ns);
        assert!(to_unix_ns(t).unwrap().abs_diff(ns) < 2, "within the fraction's resolution");
        // 2036-02-07T06:28:16Z is NTP second 2^32: era 1 starts at 0.
        let after = (2_085_978_496 + 10) * NS;
        assert_eq!(from_unix_ns(after) >> 32, 10);
        assert_eq!(to_unix_ns(from_unix_ns(after)), Some(after));
        assert_eq!(to_unix_ns(0), None);
    }

    fn answer(first: u8, stratum: u8) -> [u8; LEN] {
        let mut p = [0u8; LEN];
        p[0] = first;
        p[1] = stratum;
        p[24..32].copy_from_slice(&7u64.to_be_bytes());
        p[32..40].copy_from_slice(&8u64.to_be_bytes());
        p[40..48].copy_from_slice(&9u64.to_be_bytes());
        p
    }

    #[test]
    fn only_a_synchronized_servers_answer_is_read() {
        assert_eq!(parse(&answer(4 << 3 | 4, 2)), Ok(Reply { stratum: 2, originate: 7, receive: 8, transmit: 9 }));
        assert_eq!(parse(&answer(3 << 3 | 4, 1)).map(|r| r.stratum), Ok(1), "version 3");
        assert_eq!(parse(&answer(4 << 3 | 3, 2)), Err(Malformed::BadHeader), "a client's");
        assert_eq!(parse(&answer(3 << 6 | 4 << 3 | 4, 2)), Err(Malformed::BadHeader), "not synchronized");
        assert_eq!(parse(&answer(4 << 3 | 4, 0)), Err(Malformed::BadHeader), "a kiss of death");
        assert_eq!(parse(&answer(4 << 3 | 4, 16)), Err(Malformed::BadHeader), "stratum 16");
        assert_eq!(parse(&answer(4 << 3 | 4, 2)[..47]), Err(Malformed::Truncated));
        let mut p = answer(4 << 3 | 4, 2);
        p[24..32].fill(0);
        assert_eq!(parse(&p), Err(Malformed::BadHeader), "no originate time");
    }

    #[test]
    fn offset_and_delay_are_rfc_5905s() {
        // The client is 10 s behind; the way out takes 3 ms, back 1 ms, the
        // server holds it 2 ms.
        let s = NS;
        let t1 = 100 * s;
        let t2 = t1 + 10 * s + 3_000_000;
        let t3 = t2 + 2_000_000;
        let t4 = t3 - 10 * s + 1_000_000;
        let (o, delay) = offset(t1, t2, t3, t4).unwrap();
        assert_eq!(delay, 4_000_000);
        assert_eq!(o, 10 * s as i64 + 1_000_000, "the asymmetry is half in the offset, as NTP says");
    }

    /// Times that cannot be are not used to set a clock: a server that
    /// sends before it receives, an answer before its question, a round
    /// trip below zero, an offset past 64 bits (once truncated into a
    /// garbage clock).
    #[test]
    fn times_that_cannot_be_give_no_offset() {
        let s = NS;
        assert_eq!(offset(100 * s, 50 * s, 49 * s, 101 * s), None, "sent before received");
        assert_eq!(offset(100 * s, 50 * s, 50 * s, 99 * s), None, "answered before asked");
        assert_eq!(offset(100 * s, 50 * s, 60 * s, 101 * s), None, "the server held it longer than the round trip");
        assert_eq!(offset(0, u64::MAX, u64::MAX, 1), None, "an offset past 64 bits");
        assert!(offset(0, 1 << 62, 1 << 62, 1).is_some());
    }

    /// A slow answer is not believed, nor one that would move a clock the
    /// network set by more than [`STEP_MOST`] either way; the first set
    /// moves it any amount.
    #[test]
    fn slow_answers_and_large_steps_are_not_believed() {
        let s = NS;
        let t1 = 1_000_000 * s;
        // Ten years ahead, a 4 ms round trip.
        let far = 10 * 365 * 86_400 * s;
        let (t2, t3, t4) = (t1 + far + 2_000_000, t1 + far + 2_000_000, t1 + 4_000_000);
        // Not alone, whether the clock was set or not (`Steps` confirms it).
        assert!(matches!(judge(t1, t2, t3, t4), Err(Refused::Step(x)) if x > 0));
        // Back 2,000 s.
        assert!(matches!(judge(t1, t1 - 2000 * s, t1 - 2000 * s, t1 + 1_000_000), Err(Refused::Step(x)) if x < 0));
        // 999 s is believed.
        assert!(judge(t1, t1 + 999 * s, t1 + 999 * s, t1 + 1_000_000).is_ok());
        // A round trip of 1.5 s.
        assert_eq!(judge(t1, t1 + s, t1 + s, t1 + 1_500_000_000), Err(Refused::Slow(1_500_000_000)));
        assert_eq!(judge(t1, t1 + s, t1 + s - 1, t1 + 1000), Err(Refused::Impossible));
    }

    /// A clock set before a restart (the time page says so) is not moved
    /// ten years by the first answer after it, nor by any one answer: a lie
    /// is not acted on alone, and a wrong first answer is not locked in.
    /// Two answers to separate questions, a second or more apart, agreeing
    /// within their round trips, do move it: a clock that really is wrong
    /// is corrected. Before, the limit applied only once netd itself had set
    /// the clock, so the first answer after a restart moved it any amount.
    #[test]
    fn one_answer_never_steps_a_set_clock_and_agreeing_answers_do() {
        let s = NS;
        let far = 10 * 365 * 86_400 * s;
        let at = |t: u64| (t, t + far + 2_000_000, t + far + 2_000_000, t + 4_000_000);
        let mut steps = Steps::new();
        // After a restart: the clock is set (firmware, or the instance before).
        let (t1, t2, t3, t4) = at(1_000_000 * s);
        assert!(matches!(steps.judge(t1, t2, t3, t4, 10 * s), Err(Refused::Unconfirmed(x)) if x > 0), "a lone answer ten years out");
        // Another answer at once, or one that disagrees, confirms nothing.
        assert!(steps.judge(t1, t2, t3, t4, 10 * s + 1).is_err(), "too soon after the first");
        let (u1, u2, u3, u4) = (1_000_005 * s, 1_000_005 * s + far + 60 * s, 1_000_005 * s + far + 60 * s, 1_000_005 * s + 4_000_000);
        assert!(steps.judge(u1, u2, u3, u4, 15 * s).is_err(), "an answer a minute away from the last");
        // Two that agree, apart: the step is taken.
        let (v1, v2, v3, v4) = at(1_000_020 * s);
        assert!(matches!(steps.judge(v1, v2, v3, v4, 30 * s), Err(Refused::Unconfirmed(_))));
        let (w1, w2, w3, w4) = at(1_000_022 * s);
        assert!(matches!(steps.judge(w1, w2, w3, w4, 32 * s), Ok((x, _)) if x > 0), "agreeing answers correct a wrong clock");
        // Within the limit, one answer is enough, as before.
        assert!(steps.judge(t1, t1 + 999 * s, t1 + 999 * s, t1 + 1_000_000, 40 * s).is_ok());
    }

    /// A clock nothing has set (no firmware clock: it reads 1970) is not
    /// set by one answer either: any answer moves it far, and the one a
    /// forger got in first was taken whole (the audit of 2026-11-27, M9).
    /// Two agreeing answers to separate questions set it.
    #[test]
    fn one_answer_never_sets_an_unset_clock() {
        let s = NS;
        let years = 50 * 365 * 86_400 * s;
        let (t1, t4) = (5 * s, 5 * s + 2_000_000);
        let mut steps = Steps::new();
        assert!(matches!(steps.judge(t1, years, years, t4, 5 * s), Err(Refused::Unconfirmed(_))), "one answer set a clock nothing had set");
        let (u1, u4) = (8 * s, 8 * s + 2_000_000);
        assert!(matches!(steps.judge(u1, years + 3 * s, years + 3 * s, u4, 8 * s), Ok((x, _)) if x > 0));
    }

    #[test]
    fn a_request_is_a_version_4_clients() {
        let mut q = [1u8; LEN];
        request(&mut q, 0x0102_0304_0506_0708);
        assert_eq!(q[0], 0x23);
        assert!(q[1..40].iter().all(|b| *b == 0));
        assert_eq!(&q[40..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
