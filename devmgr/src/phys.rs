//! The machine's device memory, handed out as frames.
//!
//! The kernel gives device memory (device registers, firmware tables) as
//! Untyped capabilities that are never zeroed and only become frames or
//! smaller Untyped. A frame for one device's registers is cut out by
//! halving the Untyped that contains it until a piece has exactly the
//! frame's place and size; the halves beside it stay whole for whoever
//! needs them next.

use libsys::{self as sys, Cap, Error, ObjectType};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{free_slot, release_slot};
use silica_rt::slots;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An Untyped nothing was made from.
    Whole,
    /// An Untyped that was halved; its halves are pieces of their own.
    Halved,
    /// A frame.
    Frame,
}

#[derive(Clone, Copy)]
struct Piece {
    base: u64,
    bits: u8,
    cap: Cap,
    /// For a frame: the Untyped it was made from, to take it back (`release`).
    untyped: Cap,
    kind: Kind,
}

/// Device memory and what has been made of it.
pub struct DeviceMemory {
    pieces: Vec<Piece>,
}

impl DeviceMemory {
    /// No memory yet.
    pub fn new() -> DeviceMemory {
        DeviceMemory { pieces: Vec::new() }
    }

    /// The Untyped `cap` covers `2^bits` bytes of device memory at `base`.
    pub fn add(&mut self, base: u64, bits: u8, cap: Cap) {
        self.pieces.push(Piece { base, bits, cap, untyped: cap, kind: Kind::Whole });
    }

    /// The frame of `2^bits` bytes at physical address `base` (a multiple
    /// of its size): the original capability, from which the ones given to
    /// drivers are derived. Asking again for the same frame returns the
    /// same capability. `BadArg` when the range is not device memory,
    /// `InUse` when part of it already belongs to a frame of another size.
    pub fn frame(&mut self, base: u64, bits: u8) -> Result<Cap, Error> {
        if !(12..=46).contains(&bits) || base & ((1 << bits) - 1) != 0 {
            return Err(Error::BadArg);
        }
        loop {
            let covers = |p: &Piece| p.kind != Kind::Halved && p.base <= base && base + (1 << bits) <= p.base + (1 << p.bits);
            let i = self.pieces.iter().position(covers).ok_or(Error::BadArg)?;
            let p = self.pieces[i];
            match p.kind {
                Kind::Frame if p.bits == bits => return Ok(p.cap),
                Kind::Frame => return Err(Error::InUse),
                Kind::Whole if p.bits == bits => {
                    let slot = free_slot().ok_or(Error::NoMemory)?;
                    sys::retype(p.cap, ObjectType::Frame, bits, slots::SPACE, slot, 1).inspect_err(|_| release_slot(slot))?;
                    self.pieces[i] = Piece { cap: Cap(slot), untyped: p.cap, kind: Kind::Frame, ..p };
                    return Ok(Cap(slot));
                }
                _ => {
                    // Halve it: the lower half is made first, so it is the
                    // one at the Untyped's start.
                    self.pieces.try_reserve(2).map_err(|_| Error::NoMemory)?;
                    for half in 0..2u64 {
                        let slot = free_slot().ok_or(Error::NoMemory)?;
                        sys::retype(p.cap, ObjectType::Untyped, p.bits - 1, slots::SPACE, slot, 1).inspect_err(|_| release_slot(slot))?;
                        self.pieces.push(Piece {
                            base: p.base + (half << (p.bits - 1)),
                            bits: p.bits - 1,
                            cap: Cap(slot),
                            untyped: Cap(slot),
                            kind: Kind::Whole,
                        });
                    }
                    self.pieces[i].kind = Kind::Halved;
                }
            }
        }
    }

    /// Take back the frame of `2^bits` bytes at `base` (from [`DeviceMemory::frame`]):
    /// it and everything derived from it go, its memory is whole again, and
    /// halves that are both whole merge back into what they were cut from.
    /// What a device that left gives back: the next device in its slot may
    /// lay its registers out otherwise (before, the old frames stayed and a
    /// device with a register block of another size there was refused:
    /// `InUse`). Nothing happens for a frame that is not there.
    ///
    /// # Safety
    /// Nothing may still use the frame: its driver has ended, and the device
    /// manager has not mapped it.
    #[allow(unsafe_code)]
    pub unsafe fn release(&mut self, base: u64, bits: u8) {
        let Some(i) = self.pieces.iter().position(|p| p.kind == Kind::Frame && p.base == base && p.bits == bits) else { return };
        let p = self.pieces[i];
        // SAFETY: the caller's promise; the frame is the only thing made
        // from its Untyped.
        if unsafe { sys::cap_revoke(p.untyped) }.is_err() {
            return;
        }
        release_slot(p.cap.0);
        self.pieces[i] = Piece { cap: p.untyped, kind: Kind::Whole, ..p };
        // Merge upward while both halves are whole.
        let (mut base, mut bits) = (p.base, p.bits);
        loop {
            let parent_base = base & !((1u64 << (bits + 1)) - 1);
            let Some(pi) = self.pieces.iter().position(|q| q.kind == Kind::Halved && q.base == parent_base && q.bits == bits + 1) else {
                return;
            };
            let half = |b: u64| self.pieces.iter().position(|q| q.kind == Kind::Whole && q.base == b && q.bits == bits);
            let (Some(lo), Some(hi)) = (half(parent_base), half(parent_base + (1 << bits))) else { return };
            let parent = self.pieces[pi];
            // SAFETY: both halves are whole, nothing made from them.
            if unsafe { sys::cap_revoke(parent.cap) }.is_err() {
                return;
            }
            let (lo_cap, hi_cap) = (self.pieces[lo].cap, self.pieces[hi].cap);
            release_slot(lo_cap.0);
            release_slot(hi_cap.0);
            self.pieces[pi].kind = Kind::Whole;
            // The higher index first, so the lower stays where it is.
            let (a, b) = if lo > hi { (lo, hi) } else { (hi, lo) };
            self.pieces.swap_remove(a);
            self.pieces.swap_remove(b);
            (base, bits) = (parent_base, bits + 1);
        }
    }
}
