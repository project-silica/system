//! Starting programs.
//!
//! [`spawn`] turns an ELF image and a memory budget into a running program:
//! one thread in its own address space with its own CapSpace, laid out as
//! `silica_rt` documents, holding the capabilities its parent listed and
//! nothing else. Everything the child is made of comes from one Untyped
//! the parent sets aside for it, so the parent ends the child, and gets all
//! of its memory back, by revoking that one capability ([`Child::destroy`]).
//!
//! There is no `fork` and nothing is inherited: a child's world is what its
//! parent wrote down in the call.
#![no_std]
#![deny(unsafe_code)]

use libsys::{self as sys, Cap, Error, ObjectType, Rights};
use silica_formats::elf::{EM_X86_64, Elf, ElfError, PF_W, PF_X};
use silica_rt::{PROCESS_MAGIC, ProcessInfo, slots};

/// Where a child finds its start-up record.
pub const INFO_VADDR: usize = 0x7F00_0000_0000;
/// Where a child's first IPC buffer is mapped.
pub const IPC_VADDR: usize = 0x7F00_0001_0000;
/// The lowest address of a child's first stack (64 KiB).
pub const STACK_VADDR: usize = 0x7F00_0010_0000;
const STACK_BITS: u8 = 16;
/// Slots in a child's CapSpace, in bits.
const SPACE_BITS: u8 = 10;
/// Size of a child's address-space object in bits (room for 14 page tables).
const ASPACE_BITS: u8 = 16;
/// Largest frame the image is loaded in, in bits. Below the large-page
/// size, so a frame can be mapped at any page-aligned address.
const CHUNK_BITS: u8 = 20;
/// First slot of the child's CapSpace used for its image, stack and record.
const FIRST_IMAGE_SLOT: u64 = 64;
/// Most capabilities one spawn can grant.
pub const MAX_GRANTS: usize = (FIRST_IMAGE_SLOT - slots::FIRST_GRANT) as usize;

/// What the parent spawns with: its own capabilities and working space.
pub struct Parent<'a> {
    /// The parent's CapSpace.
    pub space: Cap,
    /// The parent's address space.
    pub aspace: Cap,
    /// The Untyped children are carved from.
    pub untyped: Cap,
    /// Gives a free slot of the parent's CapSpace each time it is called.
    pub free_slot: &'a mut dyn FnMut() -> u64,
    /// A page-aligned address in the parent's address space with 1 MiB of
    /// nothing mapped after it: where the child's memory is filled in.
    pub scratch: usize,
    /// An endpoint children report their exit on (each child gets a
    /// send-only capability badged with its `id`).
    pub exit: Cap,
    /// The debug console to pass on, or [`Cap::NONE`].
    pub debug: Cap,
    /// Number of processors and clock calibration, passed on unchanged.
    pub cpus: u64,
    /// See `cpus`.
    pub clock: [u64; 3],
}

/// One capability to give the child.
#[derive(Clone, Copy)]
pub struct Grant {
    /// The parent's capability. The child's is derived from it: revoking
    /// this one takes the child's away.
    pub cap: Cap,
    /// The rights the child gets (at most the parent's).
    pub rights: Rights,
    /// A badge for an endpoint or notification capability (0: none).
    pub badge: u64,
}

/// A running child, as its parent holds it.
#[derive(Clone, Copy, Debug)]
pub struct Child {
    /// The Untyped everything of the child was made from.
    pub untyped: Cap,
    /// The child's first thread.
    pub thread: Cap,
    /// The child's CapSpace.
    pub space: Cap,
    /// The child's address space.
    pub aspace: Cap,
}

impl Child {
    /// End the child and take back all of its memory.
    pub fn destroy(self) -> Result<(), Error> {
        // SAFETY: everything derived from this Untyped is the child's; the
        // parent uses none of it.
        #[allow(unsafe_code)]
        unsafe {
            sys::cap_revoke(self.untyped)?;
            sys::cap_delete(self.untyped)
        }
    }
}

/// Why a program could not be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnError {
    /// The image is not a loadable ELF file for this machine.
    Image(ElfError),
    /// A segment is writable and executable, overlaps another, or lies
    /// outside the addresses programs may use.
    Segment,
    /// More than [`MAX_GRANTS`] capabilities, or an image in too many pieces.
    TooMany,
    /// A kernel operation failed: most often `NoMemory` (the budget is too
    /// small for the image) or `BadCap` (a grant names no capability).
    Kernel(Error),
}

impl From<Error> for SpawnError {
    fn from(e: Error) -> SpawnError {
        SpawnError::Kernel(e)
    }
}

/// Start the program in `image` with `2^mem_bits` bytes of memory in all.
/// `id` badges the child's capability to the parent's exit endpoint.
pub fn spawn(p: &mut Parent<'_>, image: &[u8], mem_bits: u8, id: u64, grants: &[Grant], args: [u64; 8]) -> Result<Child, SpawnError> {
    let untyped = Cap((p.free_slot)());
    sys::retype(p.untyped, ObjectType::Untyped, mem_bits, p.space, untyped.0, 1)?;
    let child = Child { untyped, thread: Cap((p.free_slot)()), space: Cap((p.free_slot)()), aspace: Cap((p.free_slot)()) };
    match build(p, &child, image, mem_bits, id, grants, args) {
        Ok(()) => Ok(child),
        Err(e) => {
            // Nothing half-made stays behind.
            let _ = child.destroy();
            Err(e)
        }
    }
}

fn build(p: &mut Parent<'_>, c: &Child, image: &[u8], mem_bits: u8, id: u64, grants: &[Grant], args: [u64; 8]) -> Result<(), SpawnError> {
    let elf = Elf::parse(image, EM_X86_64).map_err(SpawnError::Image)?;
    if grants.len() > MAX_GRANTS {
        return Err(SpawnError::TooMany);
    }
    let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
    let (tmp, own) = (Cap((p.free_slot)()), Cap((p.free_slot)()));
    // The child's own allocatable memory comes first: half the budget.
    sys::retype(c.untyped, ObjectType::Untyped, mem_bits - 1, p.space, own.0, 1)?;
    sys::retype(c.untyped, ObjectType::CapSpace, SPACE_BITS, p.space, c.space.0, 1)?;
    sys::retype(c.untyped, ObjectType::AddressSpace, ASPACE_BITS, p.space, c.aspace.0, 1)?;
    sys::retype(c.untyped, ObjectType::Thread, 0, p.space, c.thread.0, 1)?;

    // A frame of `bits` filled by `fill` (given the address it is mapped at
    // in the parent), mapped at `vaddr` in the child, its capability left in
    // the child's CapSpace at `slot`.
    let next_slot = core::cell::Cell::new(FIRST_IMAGE_SLOT);
    let place = |bits: u8, vaddr: usize, rights: Rights, slot: Option<u64>, fill: &mut dyn FnMut(usize)| -> Result<(), SpawnError> {
        sys::retype(c.untyped, ObjectType::Frame, bits, p.space, tmp.0, 1)?;
        sys::map(p.aspace, tmp, p.scratch, rw)?;
        fill(p.scratch);
        // SAFETY: nothing but `fill`, which has returned, used the mapping.
        #[allow(unsafe_code)]
        unsafe {
            sys::unmap(tmp)?
        };
        sys::map(c.aspace, tmp, vaddr, rights)
            .map_err(|e| if e == Error::Overlap || e == Error::BadArg { SpawnError::Segment } else { e.into() })?;
        let to = slot.unwrap_or_else(|| next_slot.replace(next_slot.get() + 1));
        if to >= 1 << SPACE_BITS {
            return Err(SpawnError::TooMany);
        }
        sys::cap_move(c.space, to, tmp)?;
        Ok(())
    };

    for seg in elf.segments() {
        if seg.flags & PF_W != 0 && seg.flags & PF_X != 0 {
            return Err(SpawnError::Segment);
        }
        let rights = Rights(
            Rights::READ.0
                | if seg.flags & PF_W != 0 { Rights::WRITE.0 } else { 0 }
                | if seg.flags & PF_X != 0 { Rights::EXEC.0 } else { 0 },
        );
        let (start, end) = (seg.vaddr & !0xFFF, (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF);
        if end as usize > INFO_VADDR {
            return Err(SpawnError::Segment);
        }
        // Cover [start, end) with frames: the largest power of two that
        // fits what is left, up to 1 MiB each.
        let mut at = start;
        while at < end {
            let bits = (63 - (end - at).leading_zeros() as u8).min(CHUNK_BITS);
            let size = 1u64 << bits;
            place(bits, at as usize, rights, None, &mut |mapped| {
                // The part of the segment's file bytes that falls in this frame.
                let from = at.max(seg.vaddr);
                let off = (from - seg.vaddr) as usize;
                if off < seg.data.len() {
                    let n = (seg.data.len() - off).min((at + size - from) as usize);
                    copy(&seg.data[off..off + n], mapped + (from - at) as usize);
                }
            })?;
            at += size;
        }
    }
    place(STACK_BITS, STACK_VADDR, rw, None, &mut |_| {})?;
    // The record itself takes the next slot.
    let first_free = next_slot.get();
    let info = ProcessInfo {
        magic: PROCESS_MAGIC,
        ipc_buffer: IPC_VADDR as u64,
        capspace_slots: 1 << SPACE_BITS,
        first_free_slot: first_free + 1,
        untyped_bits: mem_bits as u64 - 1,
        grants: grants.len() as u64,
        cpus: p.cpus,
        clock: p.clock,
        args,
    };
    place(12, INFO_VADDR, Rights::READ, None, &mut |mapped| write_info(&info, mapped))?;

    // The IPC buffer: the thread is configured with it while the
    // capability is still the parent's to name.
    sys::retype(c.untyped, ObjectType::Frame, 12, p.space, tmp.0, 1)?;
    sys::map(c.aspace, tmp, IPC_VADDR, rw)?;
    sys::thread_configure(c.thread, c.space, c.aspace, Cap::NONE, tmp)?;
    sys::cap_move(c.space, slots::IPC_BUFFER.0, tmp)?;

    // What every program starts with, then what this one was granted.
    sys::cap_duplicate(c.space, slots::THREAD.0, c.thread, Rights::ALL, 0)?;
    sys::cap_duplicate(c.space, slots::SPACE.0, c.space, Rights::ALL, 0)?;
    sys::cap_duplicate(c.space, slots::ASPACE.0, c.aspace, Rights::ALL, 0)?;
    sys::cap_move(c.space, slots::UNTYPED.0, own)?;
    sys::cap_derive(c.space, slots::PARENT.0, p.exit, Rights::WRITE, id)?;
    if p.debug != Cap::NONE {
        sys::cap_derive(c.space, slots::DEBUG.0, p.debug, Rights::ALL, 0)?;
    }
    for (i, g) in grants.iter().enumerate() {
        sys::cap_derive(c.space, slots::FIRST_GRANT + i as u64, g.cap, g.rights, g.badge)?;
    }
    // SAFETY: the entry point of an image just loaded into the thread's
    // address space, on the stack just mapped there.
    #[allow(unsafe_code)]
    unsafe {
        sys::thread_start(c.thread, elf.entry as usize, STACK_VADDR + (1 << STACK_BITS), INFO_VADDR as u64, true)?
    };
    Ok(())
}

/// Copy `data` to the address `to` in the parent's scratch mapping.
fn copy(data: &[u8], to: usize) {
    // SAFETY: `to` lies in a frame the caller has just mapped read-write at
    // the scratch address, at least `data.len()` bytes before its end.
    #[allow(unsafe_code)]
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), to as *mut u8, data.len())
    }
}

/// Write the start-up record to the page mapped at `to`.
fn write_info(info: &ProcessInfo, to: usize) {
    // SAFETY: `to` is a fresh page mapped read-write, large enough for and
    // aligned as a ProcessInfo.
    #[allow(unsafe_code)]
    unsafe {
        core::ptr::copy_nonoverlapping(core::ptr::from_ref(info), to as *mut ProcessInfo, 1)
    }
}
