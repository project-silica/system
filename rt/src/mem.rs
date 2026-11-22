//! The program's memory: Untyped capabilities handed out in blocks and
//! taken back.
//!
//! The kernel gives memory out of an Untyped from the front and takes it
//! back only when everything made from that Untyped is gone. So memory that
//! comes and goes is managed here, in blocks: a block is an Untyped of its
//! own, made from one of the program's sources; whoever is done with a block
//! revokes it, which destroys everything made from it, and the empty block
//! is kept for the next request of its size. Nothing is merged or split:
//! a program that uses a few sizes over and over, as a parent starting and
//! ending children does, never runs out by fragmentation.
//!
//! A program's source is its own Untyped ([`crate::slots::UNTYPED`]); the
//! root task's are all the memory of the machine.

use crate::ipc::{free_slot, release_slot};
use crate::slots;
use crate::sys::{self, Cap, Error, ObjectType};
use core::sync::atomic::{AtomicU64, Ordering};

/// Untyped capabilities blocks are made from, as `slot | bits << 56`,
/// smallest first (0: none, at the end).
static SOURCES: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
/// Flag in a source's entry: blocks have been made from it.
const USED: u64 = 1 << 63;
/// A source that was handed out whole as a block: skipped from then on (it
/// comes back through the list of empty blocks when it is freed).
const SPENT: u64 = 1 << 62;
/// Empty blocks: `slot | bits << 56` (0: none).
static FREE: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];

/// Add `untyped`, of `2^bits` bytes, to what [`alloc`] makes blocks from.
/// A request is served from the smallest source that has room, so the
/// large ones stay whole for large requests. When there are more sources
/// than this module keeps, the smallest are left out. Call it while the
/// program has one thread.
pub fn add_source(untyped: Cap, bits: u8) {
    let mut entry = untyped.0 | (bits as u64) << 56;
    // Insert in order of size; what falls off the end is the largest so
    // far, so swap it against the smallest instead.
    for s in &SOURCES {
        let have = s.load(Ordering::Relaxed);
        if have == 0 {
            s.store(entry, Ordering::Relaxed);
            return;
        }
        if have >> 56 > entry >> 56 {
            s.store(entry, Ordering::Relaxed);
            entry = have;
        }
    }
    // Full: `entry` is now the largest of all. Drop the smallest for it.
    for i in 0..SOURCES.len() - 1 {
        SOURCES[i].store(SOURCES[i + 1].load(Ordering::Relaxed), Ordering::Relaxed);
    }
    SOURCES[SOURCES.len() - 1].store(entry, Ordering::Relaxed);
}

/// An empty Untyped of `2^bits` bytes, or `NoMemory`.
pub fn alloc(bits: u8) -> Result<Cap, Error> {
    for f in &FREE {
        let v = f.load(Ordering::Relaxed);
        if v != 0 && (v >> 56) as u8 == bits && f.compare_exchange(v, 0, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            return Ok(Cap(v & ((1 << 56) - 1)));
        }
    }
    let slot = free_slot().ok_or(Error::NoMemory)?;
    for s in &SOURCES {
        let entry = s.load(Ordering::Relaxed);
        if entry == 0 {
            break;
        }
        let entry_bits = ((entry & !USED) >> 56) as u8;
        if entry == SPENT || entry_bits < bits {
            continue;
        }
        let source = entry & ((1 << 56) - 1);
        match sys::retype(Cap(source), ObjectType::Untyped, bits, slots::SPACE, slot, 1) {
            Ok(()) => {
                s.store(entry | USED, Ordering::Relaxed);
                return Ok(Cap(slot));
            }
            // A source of exactly this size cannot be made into a smaller
            // one: while nothing has been made from it, it is the block.
            Err(Error::NoMemory) if entry_bits == bits && entry & USED == 0 => {
                if s.compare_exchange(entry, SPENT, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    release_slot(slot);
                    return Ok(Cap(source));
                }
            }
            Err(Error::NoMemory) => {}
            Err(e) => {
                release_slot(slot);
                return Err(e);
            }
        }
    }
    release_slot(slot);
    Err(Error::NoMemory)
}

/// Give back the block `block` of `2^bits` bytes from [`alloc`]: everything
/// made from it is destroyed, in whatever CapSpace its capabilities are.
///
/// # Safety
/// Nothing the program still uses may be made from the block: no memory it
/// has mapped and references, no object it will name again.
#[allow(unsafe_code)]
pub unsafe fn free(block: Cap, bits: u8) {
    // SAFETY: the caller's promise is this function's.
    if unsafe { sys::cap_revoke(block) }.is_err() {
        return; // not a block: nothing to keep
    }
    let v = block.0 | (bits as u64) << 56;
    if FREE.iter().any(|f| f.compare_exchange(0, v, Ordering::Relaxed, Ordering::Relaxed).is_ok()) {
        return;
    }
    // No room to remember it: its memory stays out of use until the source
    // it came from is revoked as a whole.
    // SAFETY: the block is empty and is the caller's to give up.
    let _ = unsafe { sys::cap_delete(block) };
    release_slot(block.0);
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
