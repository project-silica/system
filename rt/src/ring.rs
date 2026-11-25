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

    /// How many records wait to be taken (a producer that claims more than
    /// the ring holds: as many as it holds).
    pub fn waiting_now(&self) -> u32 {
        self.waiting().unwrap_or(self.ring.mask + 1)
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
        // The flag before the tail is read: a store followed by a load of
        // another word may otherwise be reordered (an acquire load on
        // aarch64 may pass the store), and a record added meanwhile would
        // neither be seen here nor wake this side. The producer's swap of
        // the flag is a full barrier after its store of the tail.
        core::sync::atomic::fence(Ordering::SeqCst);
        if self.waiting() != Ok(0) {
            self.ring.word(SLEEPING).store(0, Ordering::SeqCst);
            return false;
        }
        true
    }
}

/// A stream of bytes from one program to another, over the same kind of
/// shared memory as the record rings: a header of [`STREAM_HEADER`] bytes
/// and a data area of any size. TCP's connections reach programs through
/// two of these in one frame (`silica_net::tcp`). It adds to the record
/// ring what a stream needs:
///
/// - **Room.** A producer that finds the stream full says so in the header
///   ([`StreamProducer::sleep_for_room`]) before it waits, and a consumer
///   that takes bytes signals it then ([`StreamConsumer::room_needed`]),
///   ordered as the consumer's sleep is: one of the two sees the other.
/// - **The end.** The producer may say that nothing more will come, with a
///   reason ([`StreamProducer::close`]): 0 for an orderly end, a protocol's
///   error code otherwise. The consumer sees it once it has taken every
///   byte before it.
///
/// Positions count bytes modulo twice the capacity, so the capacity need
/// not be a power of two (a frame holds two headers and two data areas
/// with nothing left over), and a full stream is told from an empty one.
/// The other side is not trusted, as for the record rings: a position it
/// writes that makes no sense reports [`Broken`].
pub const STREAM_HEADER: usize = 64;
const STREAM_TAIL: usize = 0;
const STREAM_SLEEPING: usize = 4;
const STREAM_CLOSED: usize = 8;
const STREAM_REASON: usize = 12;
const STREAM_HEAD: usize = 32;
const STREAM_WANTS_ROOM: usize = 36;

#[derive(Debug)]
struct StreamShared {
    header: Shared,
    data: Mmio,
    capacity: u32,
}

impl StreamShared {
    fn new(header: Mmio, data: Mmio) -> Option<StreamShared> {
        let capacity = u32::try_from(data.len()).ok().filter(|c| *c >= 8 && *c <= 1 << 30)?;
        let aligned = header.addr().is_multiple_of(8) && header.len() >= STREAM_HEADER;
        aligned.then(|| StreamShared { header: Shared { region: header, base: header.addr(), mask: 0 }, data, capacity })
    }

    fn word(&self, offset: usize) -> &AtomicU32 {
        self.header.word(offset)
    }

    /// Bytes between position `head` and position `tail`, or [`Broken`]
    /// when either is not a position or they are further apart than the
    /// stream holds.
    fn between(&self, head: u32, tail: u32) -> Result<u32, Broken> {
        let wrap = 2 * self.capacity;
        if head >= wrap || tail >= wrap {
            return Err(Broken);
        }
        let n = if tail >= head { tail - head } else { tail + wrap - head };
        if n > self.capacity { Err(Broken) } else { Ok(n) }
    }

    fn advance(&self, at: u32, n: usize) -> u32 {
        let next = at as u64 + n as u64;
        (next % (2 * self.capacity as u64)) as u32
    }

    /// Copy bytes at position `at` out into `out`, or in from `bytes`, in
    /// at most two pieces (where the data wraps).
    fn copy_out(&self, at: u32, out: &mut [u8]) {
        let start = (at % self.capacity) as usize;
        let first = out.len().min(self.capacity as usize - start);
        self.data.read_bytes(start, &mut out[..first]);
        self.data.read_bytes(0, &mut out[first..]);
    }

    fn copy_in(&self, at: u32, bytes: &[u8]) {
        let start = (at % self.capacity) as usize;
        let first = bytes.len().min(self.capacity as usize - start);
        self.data.write_bytes(start, &bytes[..first]);
        self.data.write_bytes(0, &bytes[first..]);
    }
}

/// The writing end of a byte stream.
#[derive(Debug)]
pub struct StreamProducer {
    s: StreamShared,
    tail: u32,
}

impl StreamProducer {
    /// The writing end of the stream whose header is `header` (at least
    /// [`STREAM_HEADER`] bytes, 8-byte aligned) and whose bytes are `data`
    /// (8 bytes to 1 GiB), both shared memory that starts zeroed. A
    /// position found there that makes no sense is taken as the start.
    pub fn new(header: Mmio, data: Mmio) -> Option<StreamProducer> {
        let s = StreamShared::new(header, data)?;
        let tail = s.word(STREAM_TAIL).load(Ordering::Relaxed);
        let tail = if tail < 2 * s.capacity { tail } else { 0 };
        Some(StreamProducer { s, tail })
    }

    /// How many more bytes fit now (none when the consumer's position
    /// makes no sense).
    pub fn room(&self) -> usize {
        let head = self.s.word(STREAM_HEAD).load(Ordering::Acquire);
        self.s.between(head, self.tail).map_or(0, |used| (self.s.capacity - used) as usize)
    }

    /// How many bytes written the consumer has not taken yet (all of the
    /// stream when its position makes no sense).
    pub fn unread(&self) -> usize {
        self.s.capacity as usize - self.room()
    }

    /// Add as much of `bytes` as fits; returns how much did. After the
    /// last write, [`StreamProducer::wake_needed`].
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len().min(self.room());
        if n == 0 {
            return 0;
        }
        self.s.copy_in(self.tail, &bytes[..n]);
        self.tail = self.s.advance(self.tail, n);
        self.s.word(STREAM_TAIL).store(self.tail, Ordering::Release);
        n
    }

    /// Nothing more will be written: `reason` 0 for an orderly end, a
    /// protocol's error code otherwise. Then [`StreamProducer::wake_needed`].
    pub fn close(&mut self, reason: u32) {
        self.s.word(STREAM_REASON).store(reason, Ordering::Relaxed);
        self.s.word(STREAM_CLOSED).store(1, Ordering::Release);
    }

    /// After writing or closing: whether the consumer said it sleeps, in
    /// which case signal it. Told once.
    pub fn wake_needed(&self) -> bool {
        self.s.word(STREAM_SLEEPING).swap(0, Ordering::SeqCst) != 0
    }

    /// Before waiting for room: say so. Returns whether to wait: `false`
    /// when room appeared meanwhile (write instead).
    pub fn sleep_for_room(&mut self) -> bool {
        self.s.word(STREAM_WANTS_ROOM).store(1, Ordering::SeqCst);
        // As `Consumer::sleep`: the flag before the position is read.
        core::sync::atomic::fence(Ordering::SeqCst);
        if self.room() != 0 {
            self.s.word(STREAM_WANTS_ROOM).store(0, Ordering::SeqCst);
            return false;
        }
        true
    }
}

/// The reading end of a byte stream.
#[derive(Debug)]
pub struct StreamConsumer {
    s: StreamShared,
    head: u32,
}

/// What a read found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// This many bytes (more than 0).
    Bytes(usize),
    /// Nothing yet.
    Empty,
    /// Nothing more will come: the producer closed it, with this reason.
    Closed(u32),
}

impl StreamConsumer {
    /// The reading end; see [`StreamProducer::new`].
    pub fn new(header: Mmio, data: Mmio) -> Option<StreamConsumer> {
        let s = StreamShared::new(header, data)?;
        let head = s.word(STREAM_HEAD).load(Ordering::Relaxed);
        let head = if head < 2 * s.capacity { head } else { 0 };
        Some(StreamConsumer { s, head })
    }

    /// Bytes waiting now.
    pub fn available(&self) -> Result<usize, Broken> {
        let tail = self.s.word(STREAM_TAIL).load(Ordering::Acquire);
        self.s.between(self.head, tail).map(|n| n as usize)
    }

    /// Take up to `out.len()` bytes, copied out of the shared memory. After
    /// taking bytes, [`StreamConsumer::room_needed`].
    pub fn read(&mut self, out: &mut [u8]) -> Result<Read, Broken> {
        // The end is looked at before the bytes: a close seen here follows
        // every byte written before it.
        let closed = self.s.word(STREAM_CLOSED).load(Ordering::Acquire) != 0;
        let n = self.available()?.min(out.len());
        if n == 0 {
            return Ok(if closed && !out.is_empty() {
                Read::Closed(self.s.word(STREAM_REASON).load(Ordering::Relaxed))
            } else {
                Read::Empty
            });
        }
        self.s.copy_out(self.head, &mut out[..n]);
        self.head = self.s.advance(self.head, n);
        self.s.word(STREAM_HEAD).store(self.head, Ordering::Release);
        Ok(Read::Bytes(n))
    }

    /// After taking bytes: whether the producer said it waits for room, in
    /// which case signal it. Told once.
    pub fn room_needed(&self) -> bool {
        self.s.word(STREAM_WANTS_ROOM).swap(0, Ordering::SeqCst) != 0
    }

    /// Whether the producer closed the stream, and with what reason,
    /// whether or not its bytes were all taken: what a program that only
    /// writes looks at to learn that its connection failed.
    pub fn ended(&self) -> Option<u32> {
        (self.s.word(STREAM_CLOSED).load(Ordering::Acquire) != 0).then(|| self.s.word(STREAM_REASON).load(Ordering::Relaxed))
    }

    /// Before waiting for bytes: say so. Returns whether to wait: `false`
    /// when bytes (or the end) arrived meanwhile, or the stream is broken.
    pub fn sleep(&mut self) -> bool {
        self.s.word(STREAM_SLEEPING).store(1, Ordering::SeqCst);
        core::sync::atomic::fence(Ordering::SeqCst);
        let closed = self.s.word(STREAM_CLOSED).load(Ordering::Acquire) != 0;
        if self.available() != Ok(0) || closed {
            self.s.word(STREAM_SLEEPING).store(0, Ordering::SeqCst);
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

    #[test]
    fn a_stream_carries_bytes_across_its_wrap_and_says_how_it_ended() {
        let (h, d) = (region(STREAM_HEADER), region(16));
        let (mut p, mut c) = (StreamProducer::new(h, d).unwrap(), StreamConsumer::new(h, d).unwrap());
        let mut out = [0u8; 32];
        assert_eq!(c.read(&mut out), Ok(Read::Empty));
        let mut sent = 0u8;
        let mut got = 0u8;
        for round in 0..20 {
            // Writes of uneven sizes, so the data wraps at every place.
            let chunk: std::vec::Vec<u8> = (0..(round % 7 + 3)).map(|i| sent.wrapping_add(i)).collect();
            let n = p.write(&chunk);
            sent = sent.wrapping_add(n as u8);
            let Ok(Read::Bytes(k)) = c.read(&mut out[..5]) else { panic!("bytes were written") };
            for b in &out[..k] {
                assert_eq!(*b, got);
                got = got.wrapping_add(1);
            }
        }
        while let Ok(Read::Bytes(k)) = c.read(&mut out) {
            for b in &out[..k] {
                assert_eq!(*b, got);
                got = got.wrapping_add(1);
            }
        }
        assert_eq!(got, sent);
        assert_eq!(p.write(&[0; 40]), 16, "an empty stream takes its capacity");
        assert_eq!(p.write(&[0; 1]), 0, "a full one nothing");
        p.close(7);
        assert_eq!(c.read(&mut out), Ok(Read::Bytes(16)), "the bytes before the end first");
        assert_eq!(c.read(&mut out), Ok(Read::Closed(7)));
    }

    #[test]
    fn a_full_stream_wakes_its_producer_when_room_appears() {
        let (h, d) = (region(STREAM_HEADER), region(8));
        let (mut p, mut c) = (StreamProducer::new(h, d).unwrap(), StreamConsumer::new(h, d).unwrap());
        assert_eq!(p.write(&[1; 8]), 8);
        assert_eq!(p.write(&[1]), 0);
        assert!(p.sleep_for_room());
        let mut out = [0u8; 3];
        assert_eq!(c.read(&mut out), Ok(Read::Bytes(3)));
        assert!(c.room_needed());
        assert!(!c.room_needed(), "told once");
        assert!(!p.sleep_for_room(), "room is there: do not sleep");
        assert!(!c.sleep(), "bytes are there: do not sleep");
    }

    #[test]
    fn a_stream_peer_that_lies_about_its_index_gets_nowhere() {
        let (h, d) = (region(STREAM_HEADER), region(8));
        let (mut p, mut c) = (StreamProducer::new(h, d).unwrap(), StreamConsumer::new(h, d).unwrap());
        // Further ahead than the stream holds, and not a position at all.
        h.write32(STREAM_TAIL, 9);
        assert_eq!(c.read(&mut [0; 4]), Err(Broken));
        assert!(!c.sleep(), "a broken stream is not slept on");
        h.write32(STREAM_TAIL, 16);
        assert_eq!(c.available(), Err(Broken));
        h.write32(STREAM_TAIL, 0);
        h.write32(STREAM_HEAD, 100);
        assert_eq!((p.room(), p.write(&[0; 4])), (0, 0));
        assert!(StreamProducer::new(region(STREAM_HEADER - 8), region(8)).is_none());
        assert!(StreamConsumer::new(region(STREAM_HEADER), region(4)).is_none());
    }

    /// Two threads, sixteen megabytes in writes and reads of every size,
    /// both sides sleeping: every byte arrives once, in order, and neither
    /// side is left asleep.
    #[test]
    fn a_stream_between_two_threads_loses_nothing() {
        use std::sync::{Arc, Condvar, Mutex};
        const TOTAL: usize = if cfg!(miri) { 20_000 } else { 16 << 20 };
        // A capacity that is not a power of two.
        let (h, d) = (region(STREAM_HEADER), region(4000));
        let (mut p, mut c) = (StreamProducer::new(h, d).unwrap(), StreamConsumer::new(h, d).unwrap());
        // A notification each way: a flag and a condition variable.
        type Note = Arc<(Mutex<bool>, Condvar)>;
        // A wake-up that never comes fails the test instead of hanging it.
        let wait = |n: &Note| {
            let mut s = n.0.lock().unwrap();
            while !*s {
                let (g, t) = n.1.wait_timeout(s, std::time::Duration::from_secs(10)).unwrap();
                assert!(!t.timed_out(), "a side slept 10 s: its wake-up was lost (or the other side died)");
                s = g;
            }
            *s = false;
        };
        let signal = |n: &Note| {
            *n.0.lock().unwrap() = true;
            n.1.notify_one();
        };
        let (data, room): (Note, Note) = (Arc::default(), Arc::default());
        let (d2, r2) = (data.clone(), room.clone());
        let consumer = std::thread::spawn(move || {
            let mut next = 0usize;
            let mut out = std::vec![0u8; 3006];
            let mut size = 1;
            loop {
                size = size % 2999 + 7;
                match c.read(&mut out[..size]).unwrap() {
                    Read::Bytes(k) => {
                        for b in &out[..k] {
                            assert_eq!(*b, (next % 251) as u8);
                            next += 1;
                        }
                        if c.room_needed() {
                            signal(&r2);
                        }
                    }
                    Read::Closed(reason) => {
                        assert_eq!((reason, next), (0, TOTAL));
                        return;
                    }
                    Read::Empty if c.sleep() => wait(&d2),
                    Read::Empty => {}
                }
            }
        });
        let bytes: std::vec::Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
        let (mut at, mut size) = (0, 1);
        while at < TOTAL {
            size = size % 4999 + 13;
            let n = p.write(&bytes[at..(at + size).min(TOTAL)]);
            at += n;
            if p.wake_needed() {
                signal(&data);
            }
            if n == 0 && p.sleep_for_room() {
                wait(&room);
            }
        }
        p.close(0);
        if p.wake_needed() {
            signal(&data);
        }
        consumer.join().unwrap();
    }
}
