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
        if ((entry >> 56) as u8) < bits {
            continue;
        }
        let source = entry & ((1 << 56) - 1);
        match sys::retype(Cap(source), ObjectType::Untyped, bits, slots::SPACE, slot, 1) {
            Ok(()) => return Ok(Cap(slot)),
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
