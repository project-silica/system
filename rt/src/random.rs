//! Random numbers: every program's own generator.
//!
//! A program's generator is ChaCha20 (RFC 8439) used with fast key erasure:
//! it makes four blocks at a time under its key, the first 32 bytes of them
//! become the next key, and every byte it hands out is overwritten in its
//! buffer as it goes. So reading the program's memory later recovers neither
//! the key it had nor anything it gave out before.
//!
//! The seed comes from the program's parent, which takes 32 bytes from its
//! own generator for each program it starts (`silica_proc::spawn` does it,
//! and puts them at [`SEED_OFFSET`] of the start-up page, which the runtime
//! overwrites with zeros once it has them). The root task's generator is
//! seeded from what the boot loader gathered (`RootInfo::entropy`). No two
//! programs share a generator, no call to the kernel or to a service is
//! made for a random number, and there is no `fork` to duplicate one.
//!
//! Asking for random numbers before the generator is seeded ends the
//! program: an unseeded generator has nothing to give.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// Where in the start-up page (after the `ProcessInfo`) the parent puts the
/// child's 32-byte seed.
pub const SEED_OFFSET: usize = 2048;
const _: () = assert!(core::mem::size_of::<crate::ProcessInfo>() <= SEED_OFFSET && SEED_OFFSET + 32 <= 4096);

/// Bytes made per refill: four ChaCha20 blocks.
const BUF: usize = 256;

/// The ChaCha20 block function (RFC 8439 section 2.3): 64 bytes of key
/// stream for `key`, block `counter` and `nonce`.
pub fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    s[4..12].copy_from_slice(key);
    s[12] = counter;
    s[13..].copy_from_slice(nonce);
    let start = s;
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
    for (i, (w, s0)) in s.iter().zip(start).enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.wrapping_add(s0).to_le_bytes());
    }
    out
}

fn words(bytes: &[u8]) -> [u32; 8] {
    let mut k = [0u32; 8];
    for (w, b) in k.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*b);
    }
    k
}

/// The generator's state: its key, and what it has made and not yet given.
struct State {
    key: [u32; 8],
    buf: [u8; BUF],
    /// The first byte of `buf` not yet given out (`BUF`: none left).
    at: usize,
    seeded: bool,
}

impl State {
    /// Four blocks under the key; the first 32 bytes are the next key.
    fn refill(&mut self) {
        for (i, chunk) in self.buf.as_chunks_mut::<64>().0.iter_mut().enumerate() {
            chunk.copy_from_slice(&chacha20_block(&self.key, i as u32, &[0; 3]));
        }
        self.key = words(&self.buf[..32]);
        self.buf[..32].fill(0);
        self.at = 32;
    }

    fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.at == BUF {
                self.refill();
            }
            let n = (BUF - self.at).min(out.len() - done);
            out[done..done + n].copy_from_slice(&self.buf[self.at..self.at + n]);
            self.buf[self.at..self.at + n].fill(0);
            self.at += n;
            done += n;
        }
    }
}

/// The program's generator, behind a spin lock (threads share it).
struct Generator {
    lock: AtomicBool,
    state: UnsafeCell<State>,
}

// SAFETY: `state` is only touched holding `lock`.
#[allow(unsafe_code)]
unsafe impl Sync for Generator {}

static GENERATOR: Generator =
    Generator { lock: AtomicBool::new(false), state: UnsafeCell::new(State { key: [0; 8], buf: [0; BUF], at: BUF, seeded: false }) };

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    while GENERATOR.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the lock is held, so this is the only reference.
    #[allow(unsafe_code)]
    let r = f(unsafe { &mut *GENERATOR.state.get() });
    GENERATOR.lock.store(false, Ordering::Release);
    r
}

/// Key the generator with `seed` (the runtime does it before `main`).
pub(crate) fn seed(seed: &[u8; 32]) {
    with(|s| {
        s.key = words(seed);
        s.buf.fill(0);
        s.at = BUF;
        s.seeded = true;
    })
}

/// Fill `out` with random bytes.
pub fn fill(out: &mut [u8]) {
    if !with(|s| {
        if s.seeded {
            s.fill(out);
        }
        s.seeded
    }) {
        crate::println!("ERROR: random numbers were asked for before the generator was seeded");
        crate::exit(-4);
    }
}

/// A random 64-bit number.
pub fn u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_block_function_is_rfc_8439s() {
        // RFC 8439 section 2.3.2.
        let key = words(&core::array::from_fn::<u8, 32, _>(|i| i as u8));
        let out = chacha20_block(&key, 1, &[0x0900_0000, 0x4a00_0000, 0]);
        assert_eq!(&out[..16], &[0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4]);
        assert_eq!(&out[48..], &[0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e]);
    }

    #[test]
    fn what_is_given_out_is_erased_and_the_key_moves_on() {
        let mut s = State { key: words(&[7; 32]), buf: [0; BUF], at: BUF, seeded: true };
        let first_key = s.key;
        let mut a = [0u8; 300];
        s.fill(&mut a);
        assert_ne!(s.key, first_key, "the key is replaced at each refill");
        assert!(s.buf[..s.at].iter().all(|b| *b == 0), "nothing given out stays in the buffer");
        // The same seed gives the same stream; another gives another.
        let mut t = State { key: words(&[7; 32]), buf: [0; BUF], at: BUF, seeded: true };
        let mut b = [0u8; 300];
        t.fill(&mut b[..100]);
        t.fill(&mut b[100..]);
        assert_eq!(a, b, "the stream does not depend on how it is asked for");
        let mut u = State { key: words(&[8; 32]), buf: [0; BUF], at: BUF, seeded: true };
        let mut c = [0u8; 300];
        u.fill(&mut c);
        assert_ne!(a, c);
    }
}
