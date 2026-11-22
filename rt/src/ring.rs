//! Rings: how two programs pass a stream of small fixed-size records
//! through memory they share, without a system call per record.
//!
//! A ring has one producer and one consumer. It is a header and `capacity`
//! records of `N` bytes in shared memory ([`size`] bytes in all); what a
//! record means is the protocol's business (`silica_block` for block
//! devices). Both sides are told the capacity and record size by the
//! protocol, never by the shared memory.
//!
//! **Wake-ups.** Neither side makes a system call while the other is busy.
//! A consumer starts out awake, so one that waits for a signal from the
//! start says it sleeps first ([`Consumer::sleep`]).
//! A consumer that finds the ring empty says so in the header
//! ([`Consumer::sleep`]) before it waits on its notification; a producer
//! looks at that after adding records ([`Producer::wake_needed`]) and
//! signals only then. The two steps are ordered so that a record added
//! while the consumer is on its way to sleep is never missed.
//!
//! **Trust.** The other side is not trusted. The memory may change under
//! the reader at any time, so every access is a single read or write of
//! one word, a record is copied out before it is looked at, and the other
//! side's index is checked: a consumer that sees more records announced
//! than the ring holds gets [`Broken`] instead of reading stale ones as
//! new. What the records say is the protocol's to check. The worst a
//! hostile peer does to this library is make it report `Broken`, a full
//! ring, or spurious wake-ups.

use crate::mmio::Mmio;
use core::sync::atomic::{AtomicU32, Ordering};

/// Bytes of the header before the records.
pub const HEADER: usize = 64;
const TAIL: usize = 0;
const SLEEPING: usize = 4;
const HEAD: usize = 32;

/// Bytes of shared memory a ring of `capacity` records of `n` bytes takes.
pub const fn size(capacity: u32, n: usize) -> usize {
    HEADER + capacity as usize * n
}

/// The ring is full: the consumer has not taken enough records yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// The other side announced more records than the ring holds: it broke the
/// protocol (or the memory was taken away and reads as nonsense). Nothing
/// more can be taken from this ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Broken;

#[derive(Debug)]
struct Shared {
    region: Mmio,
    base: usize,
    mask: u32,
}

impl Shared {
    fn new<const N: usize>(region: Mmio, capacity: u32) -> Option<Shared> {
        let fits = capacity.is_power_of_two() && N != 0 && N.is_multiple_of(8) && region.len() >= size(capacity, N);
        fits.then(|| Shared { region, base: region.addr(), mask: capacity - 1 })
    }

    /// One of the header's three words.
    fn word(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset.is_multiple_of(4) && offset < HEADER);
        // SAFETY: inside the region, which its `Mmio` promises is mapped
        // shared memory for as long as it is used, and 4-byte aligned (the
        // region starts on a page). An atomic is how memory another program
        // writes concurrently may be accessed.
        #[allow(unsafe_code)]
        unsafe {
            AtomicU32::from_ptr((self.base + offset) as *mut u32)
        }
    }

    fn slot<const N: usize>(&self, index: u32) -> usize {
        HEADER + (index & self.mask) as usize * N
    }
}

/// The producing end of a ring of `N`-byte records.
#[derive(Debug)]
pub struct Producer<const N: usize> {
    ring: Shared,
    tail: u32,
}

impl<const N: usize> Producer<N> {
    /// The producing end of the ring in `region` (page-aligned shared
    /// memory of at least [`size`] bytes), which holds `capacity` records, a
    /// power of two. `N` is a multiple of 8. `None` when the region is too
    /// small or the sizes are not as required. A new ring's memory is zero.
    pub fn new(region: Mmio, capacity: u32) -> Option<Producer<N>> {
        let ring = Shared::new::<N>(region, capacity)?;
        let tail = ring.word(TAIL).load(Ordering::Relaxed);
        Some(Producer { ring, tail })
    }

    /// How many more records fit right now.
    pub fn room(&self) -> u32 {
        let used = self.tail.wrapping_sub(self.ring.word(HEAD).load(Ordering::Acquire));
        // A consumer that claims to have taken more than was added gets no room.
        (self.ring.mask + 1).saturating_sub(used.min(self.ring.mask + 1))
    }

    /// Add a record.
    pub fn push(&mut self, record: &[u8; N]) -> Result<(), Full> {
        if self.room() == 0 {
            return Err(Full);
        }
        let at = self.ring.slot::<N>(self.tail);
        for (i, word) in record.as_chunks::<8>().0.iter().enumerate() {
            self.ring.region.write64(at + i * 8, u64::from_le_bytes(*word));
        }
        self.tail = self.tail.wrapping_add(1);
        self.ring.word(TAIL).store(self.tail, Ordering::Release);
        Ok(())
    }

    /// After adding records: whether the consumer said it was going to
    /// sleep, in which case signal its notification. The answer is given
    /// once (the consumer says so again before it next sleeps).
    pub fn wake_needed(&self) -> bool {
        // The flag is read after the new tail was written, and the consumer
        // reads the tail after writing the flag: one of the two sees the other.
        self.ring.word(SLEEPING).swap(0, Ordering::SeqCst) != 0
    }
}

/// The consuming end of a ring of `N`-byte records.
#[derive(Debug)]
pub struct Consumer<const N: usize> {
    ring: Shared,
    head: u32,
}

impl<const N: usize> Consumer<N> {
    /// The consuming end; see [`Producer::new`].
    pub fn new(region: Mmio, capacity: u32) -> Option<Consumer<N>> {
        let ring = Shared::new::<N>(region, capacity)?;
        let head = ring.word(HEAD).load(Ordering::Relaxed);
        Some(Consumer { ring, head })
    }

    fn waiting(&self) -> Result<u32, Broken> {
        let n = self.ring.word(TAIL).load(Ordering::Acquire).wrapping_sub(self.head);
        if n > self.ring.mask + 1 { Err(Broken) } else { Ok(n) }
    }

    /// Take the next record, copied out of the shared memory.
    pub fn pop(&mut self) -> Result<Option<[u8; N]>, Broken> {
        if self.waiting()? == 0 {
            return Ok(None);
        }
        let at = self.ring.slot::<N>(self.head);
        let mut record = [0u8; N];
        for (i, word) in record.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            *word = self.ring.region.read64(at + i * 8).to_le_bytes();
        }
        self.head = self.head.wrapping_add(1);
        self.ring.word(HEAD).store(self.head, Ordering::Release);
        Ok(Some(record))
    }

    /// After [`Broken`]: give up what the ring holds and go on from the
    /// record the producer says it will write next, as if everything
    /// before it had been taken. For a consumer that outlives its
    /// producers (a log whose writer is replaced): the records are lost,
    /// the ring is usable again once its producer writes sense.
    pub fn skip(&mut self) {
        self.head = self.ring.word(TAIL).load(Ordering::Acquire);
        self.ring.word(HEAD).store(self.head, Ordering::Release);
    }

    /// Before waiting for a wake-up: say that this side is going to sleep.
    /// Returns whether to wait: `false` when a record arrived meanwhile
    /// (take it instead). After `true`, wait on the notification the
    /// producer signals; a signal may also come when there is nothing new.
    pub fn sleep(&mut self) -> bool {
        self.ring.word(SLEEPING).store(1, Ordering::SeqCst);
        if self.waiting() != Ok(0) {
            self.ring.word(SLEEPING).store(0, Ordering::SeqCst);
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A zeroed, aligned region of host memory standing in for a shared frame.
    fn region(bytes: usize) -> Mmio {
        let words: &'static mut [u64] = Vec::leak(std::vec![0u64; bytes.div_ceil(8)]);
        // SAFETY: leaked memory of the test's own, never freed, holding only
        // integers.
        #[allow(unsafe_code)]
        unsafe {
            Mmio::new(words.as_mut_ptr() as usize, bytes)
        }
    }

    #[test]
    fn records_come_out_in_order_and_the_ring_fills_and_empties() {
        let r = region(size(4, 16));
        let (mut p, mut c) = (Producer::<16>::new(r, 4).unwrap(), Consumer::<16>::new(r, 4).unwrap());
        assert_eq!(c.pop(), Ok(None));
        for round in 0..10u64 {
            for i in 0..4 {
                let mut rec = [0u8; 16];
                rec[..8].copy_from_slice(&(round * 4 + i).to_le_bytes());
                rec[8..].copy_from_slice(&(!i).to_le_bytes());
                assert_eq!(p.push(&rec), Ok(()));
            }
            assert_eq!((p.room(), p.push(&[0; 16])), (0, Err(Full)));
            for i in 0..4 {
                let rec = c.pop().unwrap().unwrap();
                assert_eq!(u64::from_le_bytes(rec[..8].try_into().unwrap()), round * 4 + i);
                assert_eq!(u64::from_le_bytes(rec[8..].try_into().unwrap()), !i);
            }
            assert_eq!((c.pop(), p.room()), (Ok(None), 4));
        }
    }

    #[test]
    fn sizes_that_do_not_fit_are_refused() {
        assert!(Producer::<16>::new(region(size(4, 16) - 1), 4).is_none());
        assert!(Producer::<16>::new(region(size(4, 16)), 3).is_none());
        assert!(Consumer::<12>::new(region(4096), 4).is_none());
    }

    #[test]
    fn a_sleeping_consumer_is_woken_once_and_a_late_record_stops_the_sleep() {
        let r = region(size(4, 8));
        let (mut p, mut c) = (Producer::<8>::new(r, 4).unwrap(), Consumer::<8>::new(r, 4).unwrap());
        p.push(&[1; 8]).unwrap();
        assert!(!p.wake_needed(), "nobody sleeps: no signal");
        assert!(!c.sleep(), "a record is there: do not sleep");
        assert_eq!(c.pop(), Ok(Some([1; 8])));
        assert!(c.sleep());
        p.push(&[2; 8]).unwrap();
        assert!(p.wake_needed());
        assert!(!p.wake_needed(), "told once");
    }

    #[test]
    fn a_peer_that_lies_about_its_index_gets_nowhere() {
        let r = region(size(4, 8));
        let (mut p, mut c) = (Producer::<8>::new(r, 4).unwrap(), Consumer::<8>::new(r, 4).unwrap());
        // A producer announcing more than the ring holds.
        r.write32(TAIL, 9);
        assert_eq!(c.pop(), Err(Broken));
        assert!(!c.sleep(), "a broken ring is not slept on");
        // A consumer claiming to have taken what was never added.
        r.write32(TAIL, 0);
        r.write32(HEAD, 100);
        assert_eq!(p.room(), 0);
        assert_eq!(p.push(&[0; 8]), Err(Full));
    }

    /// Two threads, a million records, every sleep announced: nothing is
    /// lost, nothing repeated, and the consumer is never left asleep.
    #[test]
    fn a_producer_and_a_consumer_on_two_threads_lose_nothing() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Condvar, Mutex};
        const COUNT: u64 = if cfg!(miri) { 2_000 } else { 1_000_000 };
        let r = region(size(64, 8));
        let (mut p, mut c) = (Producer::<8>::new(r, 64).unwrap(), Consumer::<8>::new(r, 64).unwrap());
        // The notification: a flag and a condition variable.
        let signal = Arc::new((Mutex::new(false), Condvar::new()));
        let done = Arc::new(AtomicBool::new(false));
        let (s2, d2) = (signal.clone(), done.clone());
        let consumer = std::thread::spawn(move || {
            let mut next = 0u64;
            while next < COUNT {
                match c.pop().unwrap() {
                    Some(rec) => {
                        assert_eq!(u64::from_le_bytes(rec), next);
                        next += 1;
                    }
                    None if c.sleep() => {
                        let mut woken = s2.0.lock().unwrap();
                        while !*woken {
                            woken = s2.1.wait(woken).unwrap();
                        }
                        *woken = false;
                    }
                    None => {}
                }
            }
            d2.store(true, Ordering::Release);
        });
        for i in 0..COUNT {
            while p.push(&i.to_le_bytes()) == Err(Full) {
                std::thread::yield_now();
            }
            if p.wake_needed() {
                *signal.0.lock().unwrap() = true;
                signal.1.notify_one();
            }
        }
        consumer.join().unwrap();
        assert!(done.load(Ordering::Acquire));
    }
}
