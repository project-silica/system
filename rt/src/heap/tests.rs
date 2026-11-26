//! The heap's bookkeeping on the host, over a fake source of frames: an
//! arena of address space, frames "mapped" in it zeroed and "unmapped"
//! poisoned, overlapping maps refused, and a limit on the bytes held.

extern crate std;

use super::*;
use std::collections::BTreeMap;
use std::vec::Vec;

const BITS: u8 = 30;

struct Fake {
    arena: usize,
    live: BTreeMap<usize, u8>,
    /// Most bytes of frames (record pages included) held at once.
    limit: usize,
    /// Frames made and given back, ever.
    made: usize,
    unmapped: usize,
}

impl Fake {
    fn new(limit: usize) -> Fake {
        let layout = std::alloc::Layout::from_size_align(1 << BITS, 1 << CHUNK_MAX_BITS).unwrap();
        // SAFETY: a non-zero layout; the arena is leaked (tests are short).
        let arena = unsafe { std::alloc::alloc_zeroed(layout) } as usize;
        assert_ne!(arena, 0);
        Fake { arena, live: BTreeMap::new(), limit, made: 0, unmapped: 0 }
    }

    fn held(&self) -> usize {
        self.live.values().map(|b| 1usize << b).sum()
    }
}

impl Source for Fake {
    type Frame = (usize, u8);

    fn window(&mut self, bits: u8) -> Option<usize> {
        assert_eq!(bits, BITS);
        Some(self.arena)
    }

    fn map(&mut self, at: usize, bits: u8) -> Option<(usize, u8)> {
        let size = 1usize << bits;
        assert!(at >= self.arena && at + size <= self.arena + (1 << BITS), "a frame outside the window");
        assert_eq!(at % size, 0, "a frame not aligned to its size");
        if let Some((&a, &b)) = self.live.range(..at + size).next_back() {
            assert!(a + (1 << b) <= at, "a frame mapped over another");
        }
        if self.held() + size > self.limit {
            return None;
        }
        // SAFETY: inside the arena, mapped to nothing else (checked).
        unsafe { (at as *mut u8).write_bytes(0, size) };
        self.live.insert(at, bits);
        self.made += 1;
        Some((at, bits))
    }

    unsafe fn unmap(&mut self, (at, bits): (usize, u8)) {
        assert_eq!(self.live.remove(&at), Some(bits), "a frame given back that was not mapped");
        // Poisoned: a read of it after this shows up as nonsense.
        // SAFETY: inside the arena, no longer the heap's.
        unsafe { (at as *mut u8).write_bytes(0xA5, 1 << bits) };
        self.unmapped += 1;
    }
}

fn heap(limit: usize) -> Core<Fake> {
    Core::new(Fake::new(limit), BITS)
}

fn layout(size: usize) -> Layout {
    Layout::from_size_align(size, 1).unwrap()
}

/// The heap's frames other than its record pages.
fn held(h: &Core<Fake>) -> usize {
    let records = h.next_records();
    h.src.live.iter().filter(|(a, _)| **a >= records).map(|(_, b)| 1usize << b).sum()
}

impl Core<Fake> {
    fn next_records(&self) -> usize {
        self.base + ((1usize << (BITS as u32 - UNIT_BITS)) * RECORD).next_multiple_of(1 << CHUNK_MAX_BITS)
    }
}

/// `n` bytes of the heap as `size`-byte requests, each written, then all
/// checked and given back.
fn phase(h: &mut Core<Fake>, size: usize, n: usize) {
    let mut got = Vec::new();
    for k in 0..n / size {
        let p = h.alloc(layout(size));
        assert!(!p.is_null(), "{size}-byte request {k} refused with {} bytes held", held(h));
        // SAFETY: `size` bytes the heap handed out.
        unsafe { p.write_bytes(k as u8, size) };
        got.push(p);
    }
    for (k, p) in got.into_iter().enumerate() {
        // SAFETY: as above; still the test's.
        unsafe {
            assert_eq!((*p, *p.add(size - 1)), (k as u8, k as u8), "a {size}-byte block was written by someone else");
            h.dealloc(p, layout(size));
        }
    }
}

/// Memory freed at one size serves the next: 8 MiB of 2 KiB pieces, then
/// of 32 KiB blocks, then of 256 KiB blocks, three times over, hold about
/// 8 MiB, not 24, and the third round no more than the first. (The heap
/// before kept every freed piece on its size's list: each round's three
/// phases held their own 8 MiB, and the fake's 16 MiB limit refused the
/// third phase.)
#[test]
fn memory_freed_at_one_size_serves_another() {
    let mut h = heap(16 << 20);
    let mut after = Vec::new();
    for _ in 0..3 {
        phase(&mut h, 2048, 8 << 20);
        phase(&mut h, 32 << 10, 8 << 20);
        phase(&mut h, 256 << 10, 8 << 20);
        after.push(held(&h));
    }
    assert!(after[0] <= 10 << 20, "the heap holds {} bytes for 8 MiB at a time", after[0]);
    assert_eq!(after[0], after[2], "the heap grew from round to round: {after:?}");
}

/// A frame over 2 MiB goes back when freed (its slots and memory with it),
/// and its addresses serve the next frame of its size.
#[test]
fn large_frames_go_back() {
    let mut h = heap(64 << 20);
    let before = held(&h);
    let first: Vec<*mut u8> = (0..4).map(|_| h.alloc(layout(4 << 20))).collect();
    assert!(first.iter().all(|p| !p.is_null()));
    assert_eq!(held(&h), before + (16 << 20));
    for p in &first {
        // SAFETY: handed out above, unused.
        unsafe { h.dealloc(*p, layout(4 << 20)) };
    }
    assert_eq!(held(&h), before, "freed frames were kept");
    assert_eq!(h.src.unmapped, 4);
    let again: Vec<*mut u8> = (0..4).map(|_| h.alloc(layout(4 << 20))).collect();
    let (mut a, mut b) = (first.clone(), again.clone());
    a.sort();
    b.sort();
    assert_eq!(a, b, "a frame of a size freed before took fresh address space");
}

/// A unit whose pieces are all free goes back to the blocks, unless it is
/// its class's only one with room: a piece taken and given back in turn
/// does not make and give back units.
#[test]
fn an_empty_unit_goes_back_but_one_stays() {
    let mut h = heap(16 << 20);
    let pieces: Vec<*mut u8> = (0..(2 * UNIT / 16)).map(|_| h.alloc(layout(16))).collect();
    let held_two = held(&h);
    for p in &pieces {
        // SAFETY: handed out above, unused.
        unsafe { h.dealloc(*p, layout(16)) };
    }
    // One unit went back: a 64 KiB block now needs no new chunk.
    let made = h.src.made;
    let block = h.alloc(layout(64 << 10));
    assert!(!block.is_null());
    assert_eq!(h.src.made, made, "a freed unit did not serve the block");
    // And the class's kept unit serves its pieces.
    for _ in 0..1000 {
        let p = h.alloc(layout(16));
        // SAFETY: handed out above, unused.
        unsafe { h.dealloc(p, layout(16)) };
    }
    assert_eq!(h.src.made, made);
    assert_eq!(held(&h), held_two);
}

/// Running out is a null pointer, never a panic, and memory freed after
/// serves again.
#[test]
fn running_out_is_null_and_recovers() {
    let mut h = heap(4 << 20);
    let mut got = Vec::new();
    loop {
        let p = h.alloc(layout(48 << 10));
        if p.is_null() {
            break;
        }
        got.push(p);
        assert!(got.len() < 1000, "a 4 MiB limit gave out more than 48 MiB");
    }
    assert!(h.alloc(layout(8 << 20)).is_null());
    assert!(!got.is_empty());
    for p in got.drain(..) {
        // SAFETY: handed out above, unused.
        unsafe { h.dealloc(p, layout(48 << 10)) };
    }
    for _ in 0..8 {
        assert!(!h.alloc(layout(128 << 10)).is_null(), "freed memory did not serve again");
    }
}

/// Random requests of every size and alignment against a model: no two
/// live blocks overlap, each is aligned as asked, holds what was written
/// into it until it is freed, and everything frees.
#[test]
fn random_requests_never_overlap_or_corrupt() {
    let mut h = heap(256 << 20);
    let mut live: BTreeMap<usize, (usize, Layout, u8)> = BTreeMap::new();
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut rand = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let rounds = if cfg!(miri) { 300 } else { 30_000 };
    for n in 0..rounds {
        let free_one = !live.is_empty() && (live.len() > 400 || rand() % 2 == 0);
        if free_one {
            let k = *live.keys().nth(rand() as usize % live.len()).unwrap();
            let (size, l, tag) = live.remove(&k).unwrap();
            let p = k as *mut u8;
            // SAFETY: a live block of `size` bytes.
            unsafe {
                assert_eq!((*p, *p.add(size - 1)), (tag, tag), "a block changed under its owner");
                h.dealloc(p, l);
            }
            continue;
        }
        let size = match rand() % 100 {
            0..60 => 1 + rand() as usize % 512,
            60..85 => 1 + rand() as usize % (40 << 10),
            85..97 => 1 + rand() as usize % (2 << 20),
            _ => 1 + rand() as usize % (6 << 20),
        };
        let align = 1usize << (rand() % 13);
        let l = Layout::from_size_align(size, align).unwrap();
        let p = h.alloc(l);
        assert!(!p.is_null(), "request {n} of {size} bytes refused");
        let at = p as usize;
        assert_eq!(at % align, 0, "a block not aligned as asked");
        if let Some((&a, &(s, _, _))) = live.range(..at + size).next_back() {
            assert!(a + s <= at, "two live blocks overlap");
        }
        let tag = n as u8;
        // SAFETY: `size` bytes handed out.
        unsafe {
            *p = tag;
            *p.add(size - 1) = tag;
        }
        live.insert(at, (size, l, tag));
    }
    for (k, (_, l, _)) in live {
        // SAFETY: live blocks, unused.
        unsafe { h.dealloc(k as *mut u8, l) };
    }
    // Every large frame went back; what is held is chunks.
    assert!(h.src.live.values().all(|b| *b <= CHUNK_MAX_BITS));
}

/// Chunks whose every unit is free again go back to the program's memory
/// (which, with its buddy tree, serves any size with them), but for one
/// spare: after 8 MiB of 256 KiB blocks is given back, the heap holds one
/// chunk at most, and the next request is served from it without a new
/// frame. Before, chunks were kept once made: the 8 MiB stayed the heap's.
#[test]
fn free_chunks_go_back_but_one_stays() {
    let mut h = heap(16 << 20);
    phase(&mut h, 256 << 10, 8 << 20);
    assert!(held(&h) <= 1 << CHUNK_MAX_BITS, "the heap kept {} bytes with nothing in use", held(&h));
    assert!(h.src.unmapped > 0, "no chunk went back");
    let made = h.src.made;
    let p = h.alloc(layout(64 << 10));
    assert!(!p.is_null());
    assert_eq!(h.src.made, made, "the spare chunk did not serve the next request");
    // SAFETY: handed out above, unused.
    unsafe { h.dealloc(p, layout(64 << 10)) };
    // A request at a time, taken and given back over and over, makes no frames.
    for _ in 0..1000 {
        let p = h.alloc(layout(128 << 10));
        assert!(!p.is_null());
        // SAFETY: as above.
        unsafe { h.dealloc(p, layout(128 << 10)) };
    }
    assert_eq!(h.src.made, made, "a hot take-and-give pair made and gave back frames");
    // Short of memory, the program gives the spare back too: nothing is held.
    let unmapped = h.src.unmapped;
    assert!(h.trim() > 0, "a spare chunk was kept, and trim gave nothing back");
    assert_eq!(h.src.unmapped, unmapped + 1);
    assert_eq!(held(&h), 0, "the heap kept {} bytes after trim", held(&h));
    assert_eq!(h.trim(), 0, "a second trim found another spare");
    // And it serves again afterwards.
    let p = h.alloc(layout(64 << 10));
    assert!(!p.is_null());
    // SAFETY: as above.
    unsafe { h.dealloc(p, layout(64 << 10)) };
}
