//! The program's heap: what `alloc` (boxes, vectors, maps) allocates from.
//!
//! Small requests (up to 2 KiB) come from size classes, powers of two from
//! 16 bytes, each a list of free pieces refilled 64 KiB at a time. Larger
//! ones are blocks of a power-of-two size, kept by size when freed and used
//! again for the next request of that size: up to 64 KiB cut from the same
//! chunks as the small pieces, past that a frame each. (A frame costs two
//! capability slots; a program holding many medium buffers, as the network
//! stack holds two of 32 KiB per connection, would run its CapSpace out
//! long before its memory.) Memory once taken from
//! the program's Untyped stays with the heap: a program that must return
//! memory to its parent holds it as [`crate::mem::Memory`] instead.
//!
//! Running out is reported the way Rust's allocator interface reports it:
//! a null pointer, which `alloc`'s fallible calls (`try_reserve`) turn into
//! an error and its infallible ones into a panic that names the request.
#![allow(unsafe_code)]

use crate::mem::Memory;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

const MIN_SHIFT: u32 = 4;
const CLASSES: usize = 8; // 16 bytes to 2 KiB
/// The first chunks are 64 KiB; every fourth doubles the size, up to 2 MiB,
/// so a large heap is made of few frames (each costs two capability slots).
const CHUNK_BITS: u8 = 16;
const CHUNK_MAX_BITS: u8 = 21;
/// Frame sizes kept when freed: 4 KiB to 1 GiB.
const FRAMES: usize = 19;

struct Lists {
    small: [*mut u8; CLASSES],
    frames: [*mut u8; FRAMES],
    /// A chunk being cut into pieces: the next unused byte and the end.
    chunk: (usize, usize),
    chunks: u8,
}

impl Lists {
    /// The next 64 KiB of the current chunk, aligned to 64 KiB, taking a new
    /// chunk when it is used up (chunks are 64 KiB to 2 MiB, mapped at a
    /// multiple of their size).
    fn unit(&mut self) -> Option<usize> {
        if self.chunk.0 == self.chunk.1 {
            let bits = (CHUNK_BITS + self.chunks / 4).min(CHUNK_MAX_BITS);
            let chunk = Memory::new(bits).ok()?;
            self.chunk = (chunk.addr(), chunk.addr() + chunk.len());
            self.chunks = self.chunks.saturating_add(1);
        }
        let base = self.chunk.0;
        self.chunk.0 += 1 << CHUNK_BITS;
        Some(base)
    }
}

/// The heap. `silica_rt` installs one as the program's global allocator.
pub struct Heap {
    lock: AtomicBool,
    lists: UnsafeCell<Lists>,
}

// SAFETY: `lists` is only touched holding `lock`.
unsafe impl Sync for Heap {}

impl Heap {
    /// An empty heap.
    pub const fn new() -> Heap {
        Heap {
            lock: AtomicBool::new(false),
            lists: UnsafeCell::new(Lists { small: [null_mut(); CLASSES], frames: [null_mut(); FRAMES], chunk: (0, 0), chunks: 0 }),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Lists) -> R) -> R {
        while self.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held, so this is the only reference.
        let r = f(unsafe { &mut *self.lists.get() });
        self.lock.store(false, Ordering::Release);
        r
    }
}

impl Default for Heap {
    fn default() -> Heap {
        Heap::new()
    }
}

/// The size class of a request, or `None` for one that takes whole frames.
fn class(layout: Layout) -> Option<usize> {
    let size = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    let shift = usize::BITS - (size - 1).leading_zeros();
    Some((shift - MIN_SHIFT) as usize).filter(|c| *c < CLASSES)
}

/// The frame size, in bits, of a request too large for the classes.
fn frame_bits(layout: Layout) -> Option<u8> {
    let size = layout.size().max(layout.align()).max(4096);
    let bits = (usize::BITS - (size - 1).leading_zeros()) as u8;
    ((bits as usize) < 12 + FRAMES).then_some(bits)
}

// SAFETY: every block handed out is exclusively the caller's until it is
// freed, is at least as large as asked and aligned to its (power-of-two)
// size, which is at least the alignment asked.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with(|l| {
            if let Some(c) = class(layout) {
                if l.small[c].is_null() {
                    // 64 KiB of the current chunk, cut into pieces of this
                    // class.
                    let Some(base) = l.unit() else { return null_mut() };
                    let (piece, len) = (1usize << (c as u32 + MIN_SHIFT), 1usize << CHUNK_BITS);
                    for at in (0..len).step_by(piece).rev() {
                        let p = (base + at) as *mut u8;
                        // SAFETY: a piece of fresh memory this heap owns,
                        // large enough and aligned for a pointer.
                        unsafe { p.cast::<*mut u8>().write(l.small[c]) };
                        l.small[c] = p;
                    }
                }
                let p = l.small[c];
                // SAFETY: a free piece holds the address of the next one.
                l.small[c] = unsafe { p.cast::<*mut u8>().read() };
                return p;
            }
            let Some(bits) = frame_bits(layout) else { return null_mut() };
            let kept = &mut l.frames[bits as usize - 12];
            if !kept.is_null() {
                let p = *kept;
                // SAFETY: as for the pieces.
                *kept = unsafe { p.cast::<*mut u8>().read() };
                return p;
            }
            if bits <= CHUNK_BITS {
                // Up to 64 KiB: a 64 KiB piece of the current chunk, cut into
                // blocks of this size, the first given now and the rest kept
                // as freed ones are. A frame each would cost two capability
                // slots apiece: the network stack's 32 KiB connection buffers
                // ran its 1,024 slots out at about 240 connections.
                let Some(base) = l.unit() else { return null_mut() };
                let piece = 1usize << bits;
                for at in (piece..1 << CHUNK_BITS).step_by(piece).rev() {
                    let p = (base + at) as *mut u8;
                    // SAFETY: as for the pieces: fresh memory this heap owns,
                    // aligned to its size (units are 64 KiB-aligned).
                    unsafe { p.cast::<*mut u8>().write(l.frames[bits as usize - 12]) };
                    l.frames[bits as usize - 12] = p;
                }
                return base as *mut u8;
            }
            Memory::new(bits).map_or(null_mut(), |m| m.addr() as *mut u8)
        })
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        self.with(|l| {
            let list = match class(layout) {
                Some(c) => &mut l.small[c],
                None => &mut l.frames[frame_bits(layout).map_or(0, |b| b as usize - 12)],
            };
            // SAFETY: the block is the heap's again, large enough and
            // aligned for a pointer.
            unsafe { p.cast::<*mut u8>().write(*list) };
            *list = p;
        })
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout, passed on.
        let p = unsafe { self.alloc(layout) };
        if !p.is_null() {
            // SAFETY: `p` is valid for `layout.size()` bytes. (Fresh frames
            // are zero already, reused blocks are not; clearing both keeps
            // this simple and is cheap beside the allocation.)
            unsafe { p.write_bytes(0, layout.size()) };
        }
        p
    }
}
