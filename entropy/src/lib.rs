//! The entropy service's pool: what it knows that nobody else does, and how
//! output is made from it, as a library the host tests check.
//!
//! The state is one 32-byte key. Input is mixed in by hashing it with the
//! key into the next key (BLAKE2s, keyed), so the key stays unpredictable
//! as long as any input ever was, and an input chosen to cancel another
//! cannot. Output block `i` of an answer is BLAKE2s keyed with the key over
//! a counter, and after every answer the key is replaced by one more such
//! block that is never given out: whoever reads the state afterwards learns
//! nothing about what was answered before (fast key erasure).
#![no_std]
#![deny(unsafe_code)]

use silica_formats::blake2s::Blake2s;

/// Domain separation of the three uses of the key.
const MIX: &[u8] = b"silica.entropy mix";
const OUT: &[u8] = b"silica.entropy out";
const NEXT: &[u8] = b"silica.entropy next key";

/// The pool.
pub struct Pool {
    key: [u8; 32],
    counter: u64,
}

impl Pool {
    /// A pool keyed with `seed`.
    pub fn new(seed: [u8; 32]) -> Pool {
        Pool { key: seed, counter: 0 }
    }

    /// Mix `input` into the key.
    pub fn mix(&mut self, input: &[u8]) {
        self.key = Blake2s::keyed(&self.key).update(MIX).update(input).finish();
    }

    /// Fill `out` with output, then replace the key.
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            let block = self.block(OUT);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        self.key = self.block(NEXT);
    }

    fn block(&mut self, what: &[u8]) -> [u8; 32] {
        self.counter += 1;
        Blake2s::keyed(&self.key).update(what).update(&self.counter.to_le_bytes()).finish()
    }
}


/// Whether `read`, bytes a randomness device just gave, may be counted
/// towards the pool being seeded: they pass the continuous health tests a
/// noise source's output must (NIST SP 800-90B, 4.4), for the full entropy
/// a device claims (8 bits a byte), and do not repeat the device's last
/// read (`last`). Bytes that fail are still mixed in (they cannot weaken the
/// pool) but are not counted: a broken device that gives constant bytes, or
/// the same bytes every time, does not make the service say it is seeded.
///
/// - Repetition count: no value four times in a row (the cutoff for
///   H = 8 at a false-positive rate of 2^-20: 1 + ceil(20 / 8)).
/// - Proportion: no value more than 13 times among the 64 bytes asked for
///   (the binomial's tail for p = 1/256 at 2^-20 is near 9; 13 leaves room).
/// - At least 32 distinct values among 64 (about 56 are expected).
pub fn healthy(read: &[u8], last: &[u8]) -> Result<(), &'static str> {
    if read.len() < 16 {
        return Err("too few bytes to judge");
    }
    if read == last {
        return Err("the same bytes as the read before");
    }
    let mut run = 1;
    for w in read.windows(2) {
        run = if w[0] == w[1] { run + 1 } else { 1 };
        if run >= 4 {
            return Err("a byte repeated four times in a row");
        }
    }
    let mut counts = [0u8; 256];
    for b in read {
        counts[*b as usize] = counts[*b as usize].saturating_add(1);
    }
    let limit = (read.len() * 13).div_ceil(64).max(4);
    if counts.iter().any(|c| *c as usize > limit) {
        return Err("one value far more often than chance");
    }
    let distinct = counts.iter().filter(|c| **c != 0).count();
    if distinct * 2 < read.len().min(256) {
        return Err("too few distinct values");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_output_and_another_seed_other_output() {
        let (mut a, mut b, mut c) = (Pool::new([1; 32]), Pool::new([1; 32]), Pool::new([2; 32]));
        let (mut x, mut y, mut z) = ([0u8; 100], [0u8; 100], [0u8; 100]);
        a.fill(&mut x);
        b.fill(&mut y);
        c.fill(&mut z);
        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    #[test]
    fn no_two_answers_repeat_and_mixing_changes_what_follows() {
        let mut p = Pool::new([7; 32]);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let mut out = [0u8; 32];
            p.fill(&mut out);
            assert!(seen.insert(out), "an answer repeated");
        }
        let (mut q, mut r) = (Pool::new([7; 32]), Pool::new([7; 32]));
        q.mix(b"device bytes");
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        q.fill(&mut a);
        r.fill(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn the_key_after_an_answer_is_not_the_key_that_made_it() {
        let mut p = Pool::new([9; 32]);
        let before = p.key;
        let mut out = [0u8; 64];
        p.fill(&mut out);
        // The state left holds neither the old key nor anything answered.
        assert_ne!(p.key, before);
        assert!(!out.windows(32).any(|w| w == p.key));
    }

    #[test]
    fn output_is_not_lopsided() {
        // Some 64 KiB: the share of one bits is within six standard
        // deviations of a half (a smoke test, not a certification).
        let mut p = Pool::new([3; 32]);
        let mut buf = [0u8; 65536];
        p.fill(&mut buf);
        let ones: u64 = buf.iter().map(|b| b.count_ones() as u64).sum();
        let n = buf.len() as u64 * 8;
        let sigma = ((n / 4) as f64).sqrt();
        assert!(((ones as f64) - (n / 2) as f64).abs() < 6.0 * sigma, "{ones} ones in {n} bits");
    }

    #[test]
    fn a_device_that_is_stuck_or_constant_is_not_counted() {
        let zeros = [0u8; 64];
        assert!(healthy(&zeros, &[]).is_err(), "all zeros");
        let mut run = [0u8; 64];
        for (i, b) in run.iter_mut().enumerate() {
            *b = i as u8;
        }
        run[10..14].fill(7);
        assert!(healthy(&run, &[]).is_err(), "a byte four times in a row");
        let two: [u8; 64] = core::array::from_fn(|i| if i % 2 == 0 { 0x55 } else { 0xAA });
        assert!(healthy(&two, &[]).is_err(), "two values alternating");
        // What a generator gives passes, but not twice the same.
        let mut pool = Pool::new([9; 32]);
        let mut good = [0u8; 64];
        for _ in 0..1000 {
            pool.fill(&mut good);
            assert_eq!(healthy(&good, &[]), Ok(()));
        }
        assert!(healthy(&good, &good).is_err(), "the same read again");
    }
}
