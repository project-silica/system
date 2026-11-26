//! The program's memory: Untyped capabilities handed out in blocks and
//! taken back.
//!
//! The kernel gives memory out of an Untyped from the front and takes it
//! back only when everything made from that Untyped is gone. So memory that
//! comes and goes is managed here, in blocks: a block is an Untyped of its
//! own, made from one of the program's sources; whoever is done with a block
//! revokes it, which destroys everything made from it, and the empty block
//! goes back to a buddy tree over the sources (`blocks`): split to serve
//! a smaller request, merged with its buddy when both are free, so memory
//! given back at one size serves any other.
//!
//! A program's source is its own Untyped ([`crate::slots::UNTYPED`]); the
//! root task's are all the memory of the machine.

use crate::ipc::{free_slot, release_slot};
use crate::mmio::Mmio;
use crate::slots;
use crate::sys::{self, Cap, Error, ObjectType};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod blocks;

/// The program's blocks (`blocks`), under a lock: a program's threads
/// allocate at once, and the heap asks for chunks holding its own lock.
struct Tree {
    lock: AtomicBool,
    blocks: UnsafeCell<blocks::Blocks>,
}

// SAFETY: `blocks` is only touched holding `lock`.
#[allow(unsafe_code)]
unsafe impl Sync for Tree {}

static TREE: Tree = Tree { lock: AtomicBool::new(false), blocks: UnsafeCell::new(blocks::Blocks::new()) };

fn with<R>(f: impl FnOnce(&mut blocks::Blocks) -> R) -> R {
    while TREE.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the lock is held, so this is the only reference.
    #[allow(unsafe_code)]
    let r = f(unsafe { &mut *TREE.blocks.get() });
    TREE.lock.store(false, Ordering::Release);
    r
}

/// The kernel's side of the tree: the program's own CapSpace.
struct Kernel;

impl blocks::Ops for Kernel {
    fn carve(&mut self, parent: u64, bits: u8) -> Result<u64, Error> {
        let slot = free_slot().ok_or(Error::NoMemory)?;
        sys::retype(Cap(parent), ObjectType::Untyped, bits, slots::SPACE, slot, 1).inspect_err(|_| release_slot(slot))?;
        Ok(slot)
    }

    fn delete(&mut self, slot: u64) {
        // SAFETY: an empty block of the tree's, which nothing names.
        #[allow(unsafe_code)]
        let _ = unsafe { sys::cap_delete(Cap(slot)) };
        release_slot(slot);
    }
}

/// Bytes [`alloc()`] can still give out: the free blocks, which a block
/// given back with [`free`] joins at once.
pub fn available() -> u64 {
    with(|b| b.available())
}

/// Add `untyped`, of `2^bits` bytes, to what [`alloc()`] makes blocks from.
/// A request is served from the smallest free block that holds it, so
/// large ones stay whole for large requests. A source the table has no
/// room for is not used. Call it while the program has one thread.
pub fn add_source(untyped: Cap, bits: u8) {
    with(|b| b.add_source(untyped.0, bits));
}

/// An empty Untyped of `2^bits` bytes, or `NoMemory`.
pub fn alloc(bits: u8) -> Result<Cap, Error> {
    with(|b| b.alloc(&mut Kernel, bits)).map(Cap)
}

/// Give back the block `block` of `2^bits` bytes from [`alloc()`]: everything
/// made from it is destroyed, in whatever CapSpace its capabilities are,
/// and its memory serves the next request of any size.
///
/// # Safety
/// Nothing the program still uses may be made from the block: no memory it
/// has mapped and references, no object it will name again.
#[allow(unsafe_code)]
pub unsafe fn free(block: Cap, bits: u8) {
    let _ = bits;
    // Emptied before the lock is taken: destroying what was made from it
    // can take long (a CapSpace's slots, a large frame's mappings).
    // SAFETY: the caller's promise is this function's.
    if unsafe { sys::cap_revoke(block) }.is_err() {
        return; // not a block: nothing to keep
    }
    if !with(|b| b.free(&mut Kernel, block.0)) {
        // Not one the tree handed out: let it go.
        // SAFETY: the block is empty and is the caller's to give up.
        let _ = unsafe { sys::cap_delete(block) };
        release_slot(block.0);
    }
}

/// A kernel object with a block of memory to itself, so that freeing it
/// gives its memory back. For objects that come and go; one that lives as
/// long as the program can be retyped from [`slots::UNTYPED`] directly.
#[derive(Debug)]
pub struct Object {
    cap: Cap,
    block: Cap,
    bits: u8,
}

impl Object {
    /// A new object of type `ty` and size `2^bits` bytes (`bits` is 0 for
    /// the types that have one size), in a slot of the program's CapSpace.
    pub fn new(ty: ObjectType, bits: u8) -> Result<Object, Error> {
        let block_bits = ty.storage_bits(bits.into())?;
        let block = alloc(block_bits)?;
        // The allocator already returned an Untyped of exactly this size.
        if ty == ObjectType::Untyped {
            return Ok(Object { cap: block, block, bits: block_bits });
        }
        let made = free_slot()
            .ok_or(Error::NoMemory)
            .and_then(|slot| sys::retype(block, ty, bits, slots::SPACE, slot, 1).map(|()| slot).inspect_err(|_| release_slot(slot)));
        match made {
            Ok(slot) => Ok(Object { cap: Cap(slot), block, bits: block_bits }),
            Err(e) => {
                // SAFETY: nothing was made from the block.
                #[allow(unsafe_code)]
                unsafe {
                    free(block, block_bits)
                };
                Err(e)
            }
        }
    }

    /// The capability to the object: the original, from which the ones
    /// given to others are derived.
    pub fn cap(&self) -> Cap {
        self.cap
    }

    /// Destroy the object, with every capability to it anywhere, and take
    /// its memory back.
    ///
    /// # Safety
    /// As for [`free`]: the program must not still be using the object
    /// (a mapped frame it holds references into, most of all).
    #[allow(unsafe_code)]
    pub unsafe fn destroy(self) {
        // SAFETY: the caller's promise is this function's.
        unsafe { free(self.block, self.bits) };
        if self.cap != self.block {
            release_slot(self.cap.0);
        }
    }
}

/// Where this program's own mappings go: from 64 GiB to 512 GiB, handed
/// out upward by [`reserve`] and never reused. Above every image, below the
/// start-up record, in the part of the address space the first page-table
/// level of the image already covers, and below the lowest limit an IOMMU
/// puts on device addresses (2^39), so a driver can give its device the
/// addresses it uses itself.
const RESERVE_BASE: u64 = 0x10_0000_0000;
const RESERVE_END: u64 = 0x80_0000_0000;
static RESERVED: AtomicU64 = AtomicU64::new(RESERVE_BASE);

/// `bytes` of this program's address space that nothing else will be mapped
/// in, at a multiple of `align` (a power of two, at least a page): where to
/// map a frame. Address space is not memory: a reservation costs nothing
/// until something is mapped there (and then page tables, one per 2 MiB
/// touched, from the address space's own pool), so it is never given back.
/// `None` when the range set aside for it is used up.
pub fn reserve(bytes: usize, align: usize) -> Option<usize> {
    let align = align.max(4096) as u64;
    let mut at = RESERVED.load(Ordering::Relaxed);
    loop {
        let start = at.checked_add(align - 1)? & !(align - 1);
        let end = start.checked_add((bytes as u64).checked_add(4095)? & !4095)?;
        if end > RESERVE_END {
            return None;
        }
        match RESERVED.compare_exchange_weak(at, end, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(start as usize),
            Err(now) => at = now,
        }
    }
}

/// Where memory lent by other programs is mapped ([`map_peer`]): 512 GiB to
/// 1 TiB. A peer can take its memory back at any moment (it revokes the
/// frame, or ends), which unmaps it here. A program's supervisor answers a
/// fault in this range by mapping a page of zeros in its place, so reading
/// or writing lent memory never stops the program: memory that was lent
/// can turn into zeros, and code that reads it treats what it reads as
/// untrusted anyway. Nowhere else is a missing page forgiven.
pub const PEER_BASE: u64 = 0x80_0000_0000;
/// One past the end of that range.
pub const PEER_END: u64 = 0x100_0000_0000;
static PEER_RESERVED: AtomicU64 = AtomicU64::new(PEER_BASE);

/// Map `frame`, of `2^bits` bytes, lent by another program, with `rights`,
/// and say where. See [`PEER_BASE`] for what happens when the lender takes
/// it back.
pub fn map_peer(frame: Cap, bits: u8, rights: sys::Rights) -> Result<usize, Error> {
    let size = 1u64.checked_shl(bits as u32).ok_or(Error::BadArg)?;
    let align = size.min(1 << sys::LARGE_BITS);
    let mut at = PEER_RESERVED.load(Ordering::Relaxed);
    let start = loop {
        let start = (at + align - 1) & !(align - 1);
        let end = start.checked_add(size).filter(|e| *e <= PEER_END).ok_or(Error::NoMemory)?;
        match PEER_RESERVED.compare_exchange_weak(at, end, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break start,
            Err(now) => at = now,
        }
    };
    sys::map(slots::ASPACE, frame, start as usize, rights)?;
    Ok(start as usize)
}

/// [`map_peer`], as shared memory: the frame read and written one access
/// at a time, because its lender may be writing it too. Safe to use for as
/// long as the program likes: when the lender takes it back the range reads
/// as zeros, and its addresses are never given to anything else.
pub fn peer(frame: Cap, bits: u8, rights: sys::Rights) -> Result<Mmio, Error> {
    let at = map_peer(frame, bits, rights)?;
    // SAFETY: just mapped among lent memory (see above), whose addresses no
    // other mapping ever takes: accesses there reach this frame, or zeros.
    #[allow(unsafe_code)]
    Ok(unsafe { Mmio::new(at, 1 << bits) })
}

/// Lent memory a provider maps for one client at a time and lets go of when
/// that client goes: the network stack's programs' memory, a queue's
/// rings, a display's pixels. [`peer`] never gives its addresses to
/// anything else, which costs a fresh range for every client a provider
/// ever had (512 GiB of them, so a client lending 256 MiB and ending in a
/// loop ran a provider out after about two thousand); a `Lent` gives its
/// addresses back when it is dropped, emptied first of whatever is mapped
/// there (the frame, if its lender has not taken it back, and any page of
/// zeros the supervisor put in its place), and the next `Lent` of the same
/// size takes them.
///
/// What its region reads before the drop is the lender's memory, or zeros
/// once the lender takes it back, as with [`peer`]. A copy of the region
/// (`Mmio` is `Copy`) kept past the drop reaches whatever is lent next at
/// the same addresses: keep the region, and every part of it, in the same
/// structure as the `Lent`, so that they go together.
#[derive(Debug)]
pub struct Lent {
    region: Mmio,
}

impl Lent {
    /// Map `frame`, of `2^bits` bytes, lent by another program, with
    /// `rights`.
    pub fn map(frame: Cap, bits: u8, rights: sys::Rights) -> Result<Lent, Error> {
        let size = 1usize.checked_shl(bits as u32).ok_or(Error::BadArg)?;
        let at = match reused(bits) {
            Some(at) => at,
            None => {
                let align = (size as u64).min(1 << sys::LARGE_BITS);
                let mut at = PEER_RESERVED.load(Ordering::Relaxed);
                loop {
                    let start = (at + align - 1) & !(align - 1);
                    let end = start.checked_add(size as u64).filter(|e| *e <= PEER_END).ok_or(Error::NoMemory)?;
                    match PEER_RESERVED.compare_exchange_weak(at, end, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => break start as usize,
                        Err(now) => at = now,
                    }
                }
            }
        };
        if let Err(e) = sys::map(slots::ASPACE, frame, at, rights) {
            give_back(at, bits);
            return Err(e);
        }
        // SAFETY: just mapped among lent memory, whose range no other
        // mapping takes until this value is dropped (see above).
        #[allow(unsafe_code)]
        Ok(Lent { region: unsafe { Mmio::new(at, size) } })
    }

    /// The memory, read and written one access at a time (its lender may be
    /// writing it too); see [`Lent`] for how long it may be used.
    pub fn region(&self) -> Mmio {
        self.region
    }
}

impl Drop for Lent {
    fn drop(&mut self) {
        let (at, len) = (self.region.addr(), self.region.len());
        // SAFETY: the range is this value's alone, and it is going.
        #[allow(unsafe_code)]
        let cleared = unsafe { sys::unmap_range(slots::ASPACE, at, len) };
        // A range that could not be emptied is not used again.
        if cleared.is_ok() {
            give_back(at, len.trailing_zeros() as u8);
        }
    }
}

/// Ranges of lent memory let go of, for the next [`Lent`] of the same
/// size: `address | bits` (addresses are page-aligned), 0 for none. A
/// range that does not fit is not used again (address space, not memory).
const FREE_RANGES: usize = 256;
struct Ranges {
    lock: AtomicBool,
    at: core::cell::UnsafeCell<[u64; FREE_RANGES]>,
}
// SAFETY: `at` is touched only holding `lock`.
#[allow(unsafe_code)]
unsafe impl Sync for Ranges {}
static RANGES: Ranges = Ranges { lock: AtomicBool::new(false), at: core::cell::UnsafeCell::new([0; FREE_RANGES]) };

fn ranges<R>(f: impl FnOnce(&mut [u64; FREE_RANGES]) -> R) -> R {
    while RANGES.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the lock is held, so this is the only reference.
    #[allow(unsafe_code)]
    let r = f(unsafe { &mut *RANGES.at.get() });
    RANGES.lock.store(false, Ordering::Release);
    r
}

fn reused(bits: u8) -> Option<usize> {
    ranges(|r| {
        let k = r.iter().position(|e| *e != 0 && *e & 0xFFF == bits as u64)?;
        let at = r[k] & !0xFFF;
        r[k] = 0;
        Some(at as usize)
    })
}

fn give_back(at: usize, bits: u8) {
    ranges(|r| {
        if let Some(e) = r.iter_mut().find(|e| **e == 0) {
            *e = at as u64 | bits as u64;
        }
    })
}

/// Map `frame`, of `2^bits` bytes, somewhere in this program with `rights`,
/// and say where. The mapping lasts until the capability is deleted or
/// unmapped.
pub fn map(frame: Cap, bits: u8, rights: sys::Rights) -> Result<usize, Error> {
    let size = 1usize.checked_shl(bits as u32).ok_or(Error::BadArg)?;
    let at = reserve(size, size.min(1 << sys::LARGE_BITS)).ok_or(Error::NoMemory)?;
    sys::map(slots::ASPACE, frame, at, rights)?;
    Ok(at)
}

/// Memory of this program's own: a frame of `2^bits` bytes from its
/// Untyped, mapped readable and writable, zeroed.
#[derive(Debug)]
pub struct Memory {
    frame: Object,
    addr: usize,
    bits: u8,
}

impl Memory {
    /// New memory of `2^bits` bytes (at least a page: `bits` from 12).
    pub fn new(bits: u8) -> Result<Memory, Error> {
        let frame = Object::new(ObjectType::Frame, bits)?;
        match map(frame.cap(), bits, sys::Rights(sys::Rights::READ.0 | sys::Rights::WRITE.0)) {
            Ok(addr) => Ok(Memory { frame, addr, bits }),
            Err(e) => {
                // SAFETY: the frame was never mapped; nothing uses it.
                #[allow(unsafe_code)]
                unsafe {
                    frame.destroy()
                };
                Err(e)
            }
        }
    }

    /// Where it is mapped.
    pub fn addr(&self) -> usize {
        self.addr
    }

    /// Its size in bytes.
    pub fn len(&self) -> usize {
        1 << self.bits
    }

    /// Whether it is empty (never: the smallest is a page).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Its size in bits.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// The memory as shared memory: read and written one access at a time
    /// (as device registers are), because another program or a device may
    /// be writing it too. Accesses after the memory is freed fault: its
    /// addresses are never given to anything else.
    pub fn shared(&self) -> Mmio {
        // SAFETY: this frame's own mapping, for as long as it lives; after
        // that the range is mapped to nothing, ever (`reserve`).
        #[allow(unsafe_code)]
        unsafe {
            Mmio::new(self.addr, self.len())
        }
    }

    /// The frame capability: the original, to derive what others are given
    /// from (a device address space maps a copy, a peer gets a derived one).
    pub fn frame(&self) -> Cap {
        self.frame.cap()
    }

    /// Unmap it and give the memory back.
    ///
    /// # Safety
    /// Nothing may still refer to the memory: no reference into it, and no
    /// device still told to write there.
    #[allow(unsafe_code)]
    pub unsafe fn free(self) {
        // SAFETY: the caller's promise.
        unsafe { self.frame.destroy() }
    }
}
