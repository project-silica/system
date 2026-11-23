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
}
