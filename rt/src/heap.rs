//! The program's heap: what `alloc` (boxes, vectors, maps) allocates from.
//!
//! Memory comes in *chunks*, frames of 64 KiB to 2 MiB (the first small, a
//! program that needs more getting larger ones: every frame costs two
//! capability slots), cut into 64 KiB *units* and handed out by a buddy
//! allocator: a block of 2^k units, aligned to its size, split from a
//! larger free one and merged with its free buddy when it is given back.
//! - Requests of up to 32 KiB come from size classes, powers of two from
//!   16 bytes: a unit is cut into pieces of one class, and goes back to the
//!   buddy allocator when its last piece is freed (a class keeps one empty
//!   unit for its next request, so a piece taken and freed in turn costs no
//!   more than a list push and pop).
//! - Requests of 64 KiB to 2 MiB are buddy blocks.
//! - Larger ones are frames of their own, given back to the program's
//!   memory when freed.
//!
//! So memory freed at one size serves any other: what the heap holds is
//! its peak of small and medium memory taken together, not the sum of each
//! size's peak (the 2026-11-24 audit: freed pieces stayed on their class's
//! list for good, and a long-running service ran out with most of its heap
//! free). A chunk whose every unit is free again goes back to the program's
//! memory, which serves any size with it (`mem`'s buddy tree), but for one
//! spare kept so that taking and giving back in turn costs no system calls.
//!
//! The bookkeeping is out of the memory handed out: the heap takes one
//! window of address space (64 GiB of it; address space costs nothing
//! unmapped) and puts every chunk and large frame inside it, and a record
//! of 64 bytes per 64 KiB unit at the window's start, mapped a 64 KiB page
//! (1,024 records) at a time as units come into use. Free pieces and free
//! blocks hold nothing but list links in their first word. The same logic
//! runs on the host against a fake source of frames (the tests below).
//!
//! Running out is reported the way Rust's allocator interface reports it:
//! a null pointer, which `alloc`'s fallible calls (`try_reserve`) turn into
//! an error and its infallible ones into a panic that names the request.
#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

const UNIT_BITS: u32 = 16;
const UNIT: usize = 1 << UNIT_BITS;
const MIN_SHIFT: u32 = 4;
/// Size classes: 16 bytes to 32 KiB.
const CLASSES: usize = 12;
const CHUNK_MIN_BITS: u8 = 16;
const CHUNK_MAX_BITS: u8 = 21;
/// Buddy orders: a block of 2^order units, 64 KiB to 2 MiB.
const ORDERS: usize = (CHUNK_MAX_BITS - CHUNK_MIN_BITS) as usize + 1;
/// The largest frame a request may have.
const MAX_BITS: u8 = 30;
/// The window the heap's chunks, frames and records are in (64 GiB).
const WINDOW_BITS: u8 = 36;
/// Bytes of a unit's record, and records a record page holds.
const RECORD: usize = 64;
const PER_PAGE: usize = UNIT / RECORD;
/// Record pages a window can need (one bit each).
const PAGE_WORDS: usize = (1 << (WINDOW_BITS as u32 - UNIT_BITS)) / PER_PAGE / 64;

/// What a unit is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Kind {
    /// Not in use by the heap: not mapped, or inside a block whose first
    /// unit says what it is.
    None = 0,
    /// The first unit of a free buddy block (`order`).
    Free,
    /// The first unit of a buddy block handed out whole (`order`).
    Block,
    /// A unit cut into pieces of class `class`.
    Pieces,
    /// The start of a frame of its own (a request over 2 MiB): `frame`.
    Large,
    /// The start of a range of the window a frame was in, free to map a
    /// frame of the same size again (`order` holds its size in bits).
    Range,
}

/// What the heap keeps about one unit of its window.
#[repr(C)]
struct Record<F> {
    kind: Kind,
    class: u8,
    order: u8,
    /// Bits of the chunk the unit is in (0: none).
    chunk_bits: u8,
    /// `Pieces`: how many are free.
    free: u16,
    /// List links, as unit indices (0: none; index 0 is the records' own).
    next: u32,
    prev: u32,
    /// `Pieces`: the first free piece.
    head: usize,
    /// The first unit of a chunk: the chunk's frame; `Large`: its frame.
    frame: MaybeUninit<F>,
}

/// Where the heap's frames come from: the program's memory, or a fake on
/// the host.
pub(crate) trait Source {
    /// A frame, owned: given back with [`Source::unmap`].
    type Frame;
    /// `2^bits` bytes of address space aligned to 2 MiB, nothing mapped.
    fn window(&mut self, bits: u8) -> Option<usize>;
    /// A new frame of `2^bits` bytes, zeroed, mapped readable and writable
    /// at `at`.
    fn map(&mut self, at: usize, bits: u8) -> Option<Self::Frame>;
    /// Unmap `frame` and give its memory back.
    ///
    /// # Safety
    /// Nothing may refer to the frame's memory any more.
    unsafe fn unmap(&mut self, frame: Self::Frame);
}

/// The heap's bookkeeping over a source of frames.
pub(crate) struct Core<S: Source> {
    src: S,
    bits: u8,
    /// The window (0: not taken yet), where its chunks and frames start,
    /// and the next address of it never used.
    base: usize,
    next: usize,
    end: usize,
    /// Which record pages are mapped.
    pages: [u64; PAGE_WORDS],
    /// Units with free pieces, by class.
    partial: [u32; CLASSES],
    /// Free buddy blocks, by order.
    free: [u32; ORDERS],
    /// Ranges of the window free to map a frame in, by size in bits.
    ranges: [u32; 64],
    /// A chunk wholly free, kept for the next request rather than given
    /// back (its first unit; 0: none): a hot allocate-and-free pair costs
    /// no system calls.
    spare: u32,
    /// Chunks made (each larger as more are).
    chunks: u32,
}

impl<S: Source> Core<S> {
    pub(crate) const fn new(src: S, bits: u8) -> Core<S> {
        Core {
            src,
            bits,
            base: 0,
            next: 0,
            end: 0,
            pages: [0; PAGE_WORDS],
            partial: [0; CLASSES],
            free: [0; ORDERS],
            ranges: [0; 64],
            chunks: 0,
            spare: 0,
        }
    }

    /// Take the window, once.
    fn ready(&mut self) -> bool {
        if self.base != 0 {
            return true;
        }
        const { assert!(core::mem::size_of::<Record<S::Frame>>() <= RECORD) };
        let Some(base) = self.src.window(self.bits) else { return false };
        let units = 1usize << (self.bits as u32 - UNIT_BITS);
        if units / PER_PAGE > PAGE_WORDS * 64 {
            return false;
        }
        let records = (units * RECORD).next_multiple_of(1 << CHUNK_MAX_BITS);
        self.base = base;
        self.next = base + records;
        self.end = base + (1 << self.bits);
        true
    }

    fn index(&self, at: usize) -> u32 {
        ((at - self.base) >> UNIT_BITS) as u32
    }

    fn at(&self, i: u32) -> usize {
        self.base + ((i as usize) << UNIT_BITS)
    }

    /// Unit `i`'s record, its page mapped.
    fn record(&mut self, i: u32) -> Option<&mut Record<S::Frame>> {
        let page = i as usize / PER_PAGE;
        if self.pages[page / 64] & 1 << (page % 64) == 0 {
            // A page of records, never given back: forgotten, mapped.
            let frame = self.src.map(self.base + page * UNIT, UNIT_BITS as u8)?;
            core::mem::forget(frame);
            self.pages[page / 64] |= 1 << (page % 64);
        }
        // SAFETY: the page holding record `i` is mapped (above, or when its
        // bit was set), readable and writable, belongs to this heap alone,
        // was zeroed when mapped (a zero record is `Kind::None`, all links
        // 0), and records are only reached through `&mut self`.
        Some(unsafe { &mut *((self.base + i as usize * RECORD) as *mut Record<S::Frame>) })
    }

    /// The record of a unit already in use (its page is mapped).
    fn rec(&mut self, i: u32) -> &mut Record<S::Frame> {
        debug_assert!(self.pages[i as usize / PER_PAGE / 64] & 1 << (i as usize / PER_PAGE % 64) != 0);
        // SAFETY: as in `record`, the page mapped because the unit is in
        // use (its record was reached through `record` when it was).
        unsafe { &mut *((self.base + i as usize * RECORD) as *mut Record<S::Frame>) }
    }

    fn head(&mut self, list: List) -> &mut u32 {
        match list {
            List::Free(o) => &mut self.free[o],
            List::Partial(c) => &mut self.partial[c],
        }
    }

    // Doubly linked lists through the records.
    fn push(&mut self, list: List, i: u32) {
        let h = *self.head(list);
        let r = self.rec(i);
        r.prev = 0;
        r.next = h;
        if h != 0 {
            self.rec(h).prev = i;
        }
        *self.head(list) = i;
    }

    fn unlink(&mut self, list: List, i: u32) {
        let (p, n) = {
            let r = self.rec(i);
            (r.prev, r.next)
        };
        if p != 0 {
            self.rec(p).next = n;
        } else {
            *self.head(list) = n;
        }
        if n != 0 {
            self.rec(n).prev = p;
        }
        let r = self.rec(i);
        r.next = 0;
        r.prev = 0;
    }

    /// `2^bits` bytes of the window aligned to their size, for a frame:
    /// one given back at that size, or never used.
    fn range(&mut self, bits: u8) -> Option<usize> {
        let i = self.ranges[bits as usize];
        if i != 0 {
            let n = self.rec(i).next;
            self.ranges[bits as usize] = n;
            self.rec(i).kind = Kind::None;
            return Some(self.at(i));
        }
        let at = self.next.next_multiple_of(1 << bits);
        if at.checked_add(1 << bits)? > self.end {
            return None;
        }
        self.next = at + (1 << bits);
        Some(at)
    }

    fn give_range(&mut self, at: usize, bits: u8) {
        let i = self.index(at);
        let head = self.ranges[bits as usize];
        let r = self.rec(i);
        r.kind = Kind::Range;
        r.order = bits;
        r.next = head;
        self.ranges[bits as usize] = i;
    }

    /// A new chunk with a free block of at least `order`: as large as the
    /// chunks the program holds call for, or smaller, down to `order`, when
    /// its memory has no room for that.
    fn chunk(&mut self, order: usize) -> bool {
        let grown = CHUNK_MIN_BITS + (self.chunks / 4).min((CHUNK_MAX_BITS - CHUNK_MIN_BITS) as u32) as u8;
        let least = CHUNK_MIN_BITS + order as u8;
        (least..=grown.max(least)).rev().any(|bits| self.chunk_of(bits))
    }

    /// A new chunk of `2^bits` bytes, its whole a free block.
    fn chunk_of(&mut self, bits: u8) -> bool {
        let Some(at) = self.range(bits) else { return false };
        let first = self.index(at);
        let units = 1u32 << (bits as u32 - UNIT_BITS);
        // Every unit's record first: a chunk that cannot have them is not
        // made (and its range, whose first record may not exist, is not
        // kept: it is address space only).
        for i in first..first + units {
            if self.record(i).is_none() {
                return false;
            }
        }
        let Some(frame) = self.src.map(at, bits) else {
            self.give_range(at, bits);
            return false;
        };
        for i in first..first + units {
            let r = self.rec(i);
            r.kind = Kind::None;
            r.chunk_bits = bits;
        }
        self.rec(first).frame = MaybeUninit::new(frame);
        self.chunks += 1;
        self.give_block(first, (bits - CHUNK_MIN_BITS) as usize);
        true
    }

    fn give_block(&mut self, i: u32, order: usize) {
        let r = self.rec(i);
        r.kind = Kind::Free;
        r.order = order as u8;
        self.push(List::Free(order), i);
    }

    /// A block of 2^order units, split from the smallest free one that holds
    /// it, from a new chunk if none does.
    fn block(&mut self, order: usize) -> Option<u32> {
        let k = match (order..ORDERS).find(|k| self.free[*k] != 0) {
            Some(k) => k,
            None => {
                if !self.chunk(order) {
                    return None;
                }
                (order..ORDERS).find(|k| self.free[*k] != 0)?
            }
        };
        let i = self.free[k];
        self.unlink(List::Free(k), i);
        if i == self.spare {
            self.spare = 0;
        }
        for o in (order..k).rev() {
            self.give_block(i + (1 << o), o);
        }
        let r = self.rec(i);
        r.kind = Kind::Block;
        r.order = order as u8;
        Some(i)
    }

    /// Give back the block at unit `i` of 2^order units, merged with its
    /// buddy for as long as that is free, within its chunk.
    fn unblock(&mut self, mut i: u32, mut order: usize) {
        let chunk_order = (self.rec(i).chunk_bits - CHUNK_MIN_BITS) as usize;
        while order < chunk_order {
            let b = i ^ (1 << order);
            let r = self.rec(b);
            if r.kind != Kind::Free || r.order as usize != order {
                break;
            }
            self.unlink(List::Free(order), b);
            self.rec(b).kind = Kind::None;
            if b < i {
                self.rec(i).kind = Kind::None;
            }
            i = i.min(b);
            order += 1;
        }
        if order == chunk_order && self.spare != 0 {
            return self.give_chunk(i, order);
        }
        if order == chunk_order {
            self.spare = i;
        }
        self.give_block(i, order);
    }

    /// The chunk at unit `i`, of 2^order units, is wholly free, and a spare
    /// is kept already: its frame goes back to the program's memory, which
    /// serves any size with it (`mem`), and its range of the window to the
    /// next chunk or frame of its size.
    fn give_chunk(&mut self, i: u32, order: usize) {
        // Chunks held, not made: a program that needs less is given smaller ones.
        self.chunks = self.chunks.saturating_sub(1);
        let units = 1u32 << order;
        // SAFETY: a chunk's first unit holds its frame from when it was made
        // (`chunk`) until now, and nothing else reads it after this.
        let frame = unsafe { self.rec(i).frame.assume_init_read() };
        for u in i..i + units {
            let r = self.rec(u);
            r.kind = Kind::None;
            r.chunk_bits = 0;
        }
        // SAFETY: every unit of the chunk is free: nothing refers to it.
        unsafe { self.src.unmap(frame) };
        let at = self.at(i);
        self.give_range(at, order as u8 + CHUNK_MIN_BITS);
    }

    fn piece(&mut self, class: usize) -> *mut u8 {
        let size = 1usize << (class as u32 + MIN_SHIFT);
        let mut i = self.partial[class];
        if i == 0 {
            let Some(u) = self.block(0) else { return null_mut() };
            let base = self.at(u);
            // The unit's pieces, threaded in address order.
            let mut head = 0;
            for at in (0..UNIT).step_by(size).rev() {
                let p = (base + at) as *mut usize;
                // SAFETY: a piece of a unit this heap owns and hands out
                // nothing of, mapped, aligned to its size (at least 16).
                unsafe { p.write(head) };
                head = p as usize;
            }
            let r = self.rec(u);
            r.kind = Kind::Pieces;
            r.class = class as u8;
            r.free = (UNIT / size) as u16;
            r.head = head;
            self.push(List::Partial(class), u);
            i = u;
        }
        let r = self.rec(i);
        let p = r.head;
        // SAFETY: a free piece of this unit holds the address of the next.
        r.head = unsafe { (p as *const usize).read() };
        r.free -= 1;
        if r.free == 0 {
            self.unlink(List::Partial(class), i);
        }
        p as *mut u8
    }

    /// # Safety
    /// `p` is a piece of class `class` this heap handed out and nothing
    /// uses any more.
    unsafe fn unpiece(&mut self, p: *mut u8, class: usize) {
        let size = 1usize << (class as u32 + MIN_SHIFT);
        let i = self.index(p as usize);
        let (free, head) = {
            let r = self.rec(i);
            debug_assert!(r.kind == Kind::Pieces && r.class as usize == class);
            (r.free, r.head)
        };
        // SAFETY: the piece is the heap's again (the caller's promise),
        // large enough and aligned for an address.
        unsafe { (p as *mut usize).write(head) };
        let r = self.rec(i);
        r.head = p as usize;
        r.free = free + 1;
        if free == 0 {
            self.push(List::Partial(class), i);
        } else if (free + 1) as usize == UNIT / size {
            // All free: the unit goes back, unless it is the class's only
            // unit with room (kept for the class's next request).
            let only = self.partial[class] == i && self.rec(i).next == 0;
            if !only {
                self.unlink(List::Partial(class), i);
                self.rec(i).kind = Kind::Block;
                self.unblock(i, 0);
            }
        }
    }

    fn large(&mut self, bits: u8) -> *mut u8 {
        let Some(at) = self.range(bits) else { return null_mut() };
        let i = self.index(at);
        if self.record(i).is_none() {
            return null_mut(); // its range is address space only
        }
        let Some(frame) = self.src.map(at, bits) else {
            self.give_range(at, bits);
            return null_mut();
        };
        let r = self.rec(i);
        r.kind = Kind::Large;
        r.order = bits;
        r.frame = MaybeUninit::new(frame);
        at as *mut u8
    }

    /// # Safety
    /// `p` is a frame of `2^bits` bytes this heap handed out and nothing
    /// uses any more.
    unsafe fn unlarge(&mut self, p: *mut u8, bits: u8) {
        let i = self.index(p as usize);
        let r = self.rec(i);
        debug_assert!(r.kind == Kind::Large && r.order == bits);
        r.kind = Kind::None;
        // SAFETY: `Large` records hold the frame written by `large`, read
        // out once here (the kind no longer says it holds one).
        let frame = unsafe { r.frame.assume_init_read() };
        // SAFETY: the caller's promise: nothing uses the frame's memory.
        unsafe { self.src.unmap(frame) };
        self.give_range(p as usize, bits);
    }

    pub(crate) fn alloc(&mut self, layout: Layout) -> *mut u8 {
        if !self.ready() {
            return null_mut();
        }
        match size(layout) {
            Size::Class(c) => self.piece(c),
            Size::Order(o) => self.block(o).map_or(null_mut(), |i| self.at(i) as *mut u8),
            Size::Frame(b) => self.large(b),
            Size::TooLarge => null_mut(),
        }
    }

    /// # Safety
    /// `p` came from `alloc` with `layout` and nothing uses it any more.
    pub(crate) unsafe fn dealloc(&mut self, p: *mut u8, layout: Layout) {
        match size(layout) {
            // SAFETY: the caller's promise, passed on.
            Size::Class(c) => unsafe { self.unpiece(p, c) },
            Size::Order(o) => {
                let i = self.index(p as usize);
                debug_assert!(self.rec(i).kind == Kind::Block);
                self.unblock(i, o);
            }
            // SAFETY: the caller's promise, passed on.
            Size::Frame(b) => unsafe { self.unlarge(p, b) },
            Size::TooLarge => {}
        }
    }
}

/// A list the records are linked in: free blocks of an order, units with
/// free pieces of a class.
#[derive(Clone, Copy)]
enum List {
    Free(usize),
    Partial(usize),
}

enum Size {
    Class(usize),
    Order(usize),
    Frame(u8),
    TooLarge,
}

/// Where a request is served from: its size and alignment rounded to a
/// power of two.
fn size(layout: Layout) -> Size {
    let size = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    let Some(rounded) = size.checked_next_power_of_two() else { return Size::TooLarge };
    let bits = rounded.trailing_zeros();
    if bits < UNIT_BITS {
        Size::Class((bits - MIN_SHIFT) as usize)
    } else if bits <= CHUNK_MAX_BITS as u32 {
        Size::Order((bits - UNIT_BITS) as usize)
    } else if bits <= MAX_BITS as u32 {
        Size::Frame(bits as u8)
    } else {
        Size::TooLarge
    }
}

/// The program's memory, as the heap's source.
pub(crate) struct System;

impl Source for System {
    type Frame = crate::mem::Object;

    fn window(&mut self, bits: u8) -> Option<usize> {
        crate::mem::reserve(1 << bits, 1 << CHUNK_MAX_BITS)
    }

    fn map(&mut self, at: usize, bits: u8) -> Option<crate::mem::Object> {
        use crate::sys;
        let frame = crate::mem::Object::new(sys::ObjectType::Frame, bits).ok()?;
        if sys::map(crate::slots::ASPACE, frame.cap(), at, sys::Rights(sys::Rights::READ.0 | sys::Rights::WRITE.0)).is_err() {
            // SAFETY: never mapped; nothing uses it.
            unsafe { frame.destroy() };
            return None;
        }
        Some(frame)
    }

    unsafe fn unmap(&mut self, frame: crate::mem::Object) {
        // SAFETY: the caller's promise; destroying the frame unmaps it.
        unsafe { frame.destroy() }
    }
}

/// The heap. `silica_rt` installs one as the program's global allocator.
pub struct Heap {
    lock: AtomicBool,
    core: UnsafeCell<Core<System>>,
}

// SAFETY: `core` is only touched holding `lock`.
unsafe impl Sync for Heap {}

impl Heap {
    /// An empty heap.
    pub const fn new() -> Heap {
        Heap { lock: AtomicBool::new(false), core: UnsafeCell::new(Core::new(System, WINDOW_BITS)) }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Core<System>) -> R) -> R {
        while self.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held, so this is the only reference.
        let r = f(unsafe { &mut *self.core.get() });
        self.lock.store(false, Ordering::Release);
        r
    }
}

impl Default for Heap {
    fn default() -> Heap {
        Heap::new()
    }
}

// SAFETY: every block handed out is exclusively the caller's until it is
// freed, is at least as large as asked and aligned to its (power-of-two)
// size, which is at least the alignment asked (`size`).
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with(|c| c.alloc(layout))
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: the caller's promise (GlobalAlloc's contract), passed on.
        self.with(|c| unsafe { c.dealloc(p, layout) })
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout, passed on.
        let p = unsafe { self.alloc(layout) };
        if !p.is_null() {
            // SAFETY: `p` is valid for `layout.size()` bytes. (A fresh
            // frame is zero already, reused memory is not.)
            unsafe { p.write_bytes(0, layout.size()) };
        }
        p
    }
}

#[cfg(test)]
mod tests;
