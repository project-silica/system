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
use silica_formats::elf::{EM_NATIVE, Elf, ElfError, PF_W, PF_X};
use silica_rt::ipc::{free_slot, release_slot};
use silica_rt::mem;
use silica_rt::{PROCESS_MAGIC, ProcessInfo, slots};

pub mod root;

/// Where a child finds its start-up record.
pub const INFO_VADDR: usize = 0x7F00_0000_0000;
/// Where a child's first IPC buffer is mapped.
pub const IPC_VADDR: usize = 0x7F00_0001_0000;
/// The lowest address of a child's first stack (64 KiB).
pub const STACK_VADDR: usize = 0x7F00_0010_0000;
const STACK_BITS: u8 = 16;
/// Slots in a child's CapSpace, in bits, unless the program says otherwise.
const SPACE_BITS: u8 = 10;
/// Size of a child's address-space object in bits unless the program says
/// otherwise (room for 14 page tables: about 20 MiB of mappings).
const ASPACE_BITS: u8 = 16;
/// Largest frame the image is loaded in, in bits. Below the large-page
/// size, so a frame can be mapped at any page-aligned address.
const CHUNK_BITS: u8 = 20;
/// Added to a child's `id` in the badge of its fault reports ([`Parent::fault`]).
pub const FAULT_BADGE: u64 = 1 << 62;
/// Most capabilities one spawn can grant.
pub const MAX_GRANTS: usize = 2048;

/// What the parent spawns with: its own capabilities and working space.
#[derive(Clone, Copy, Debug)]
pub struct Parent {
    /// The parent's CapSpace.
    pub space: Cap,
    /// The parent's address space.
    pub aspace: Cap,
    /// A page-aligned address in the parent's address space with 1 MiB of
    /// nothing mapped after it: where the child's memory is filled in.
    pub scratch: usize,
    /// An endpoint children report their exit on (each child gets a
    /// send-only capability badged with its `id`).
    pub exit: Cap,
    /// An endpoint the kernel reports a child's fault on, as a call badged
    /// with the child's `id` plus [`FAULT_BADGE`] ([`Cap::NONE`]: a faulting
    /// child stops and the kernel logs it). The child holds no capability
    /// with that badge, so it cannot send what looks like its own fault. The message is the kernel's fault message
    /// (`libsys::FAULT_LABEL`); whoever receives it decides what becomes of
    /// the child, usually by destroying it.
    pub fault: Cap,
    /// The debug console to pass on, or [`Cap::NONE`].
    pub debug: Cap,
    /// Number of processors and clock calibration, passed on unchanged.
    pub cpus: u64,
    /// See `cpus`.
    pub clock: [u64; 3],
}

/// One capability to give the child.
#[derive(Clone, Copy, Debug)]
pub struct Grant {
    /// The parent's capability ([`Cap::NONE`]: nothing; the child's slot
    /// stays empty). Unless `give` is set the child's is derived from it:
    /// revoking this one takes the child's away.
    pub cap: Cap,
    /// The rights the child gets (at most the parent's).
    pub rights: Rights,
    /// A badge for an endpoint or notification capability, or the range of
    /// a hardware capability (start in the low half, end in the high half);
    /// 0: none.
    pub badge: u64,
    /// The child gets the capability itself and the parent no longer has
    /// it (`rights` and `badge` are not used): the only way to pass on an
    /// Untyped, which has one capability. It comes back with everything
    /// else the child held only if it was made from the child's memory;
    /// otherwise it is gone when the child is destroyed.
    pub give: bool,
}

impl Grant {
    /// Lend `cap` with `rights`: the child's capability is derived from it.
    pub const fn lend(cap: Cap, rights: Rights) -> Grant {
        Grant { cap, rights, badge: 0, give: false }
    }
    /// The same with a badge (or a hardware capability's narrower range).
    pub const fn badged(cap: Cap, rights: Rights, badge: u64) -> Grant {
        Grant { cap, rights, badge, give: false }
    }
    /// Give `cap` away: the child holds the capability itself.
    pub const fn give(cap: Cap) -> Grant {
        Grant { cap, rights: Rights::ALL, badge: 0, give: true }
    }
    /// An empty slot, keeping the numbering of the grants after it.
    pub const fn none() -> Grant {
        Grant { cap: Cap::NONE, rights: Rights::NONE, badge: 0, give: false }
    }
}

/// A running child owned by its parent. Destroying it consumes this handle
/// and returns its memory and capability slots to the parent's allocators.
///
/// ```compile_fail,E0382
/// fn end_twice(child: silica_proc::Child) {
///     child.destroy().unwrap();
///     child.destroy().unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct Child {
    untyped: Cap,
    mem_bits: u8,
    thread: Cap,
    space: Cap,
    aspace: Cap,
}

impl Parent {
    /// The parent an ordinary program is: it spawns from its own Untyped,
    /// into its own CapSpace, and its children report their exit on `exit`
    /// (an endpoint of the program's) and print where it prints. `scratch`
    /// is as in [`Parent::scratch`].
    pub fn of(info: &ProcessInfo, exit: Cap, scratch: usize) -> Parent {
        Parent {
            space: slots::SPACE,
            aspace: slots::ASPACE,
            scratch,
            exit,
            fault: Cap::NONE,
            debug: slots::DEBUG,
            cpus: info.cpus,
            clock: info.clock,
        }
    }
}

impl Child {
    /// The Untyped holding the child's objects and memory.
    pub fn untyped(&self) -> Cap {
        self.untyped
    }

    /// Size in bits of the child's memory budget.
    pub fn mem_bits(&self) -> u8 {
        self.mem_bits
    }

    /// The child's first thread.
    pub fn thread(&self) -> Cap {
        self.thread
    }

    /// The child's CapSpace.
    pub fn space(&self) -> Cap {
        self.space
    }

    /// The child's address space.
    pub fn aspace(&self) -> Cap {
        self.aspace
    }

    /// Move the child's first thread to processor `cpu`. It carries on
    /// with what it was doing (a call in progress included) there.
    pub fn place(&self, cpu: usize) -> Result<(), Error> {
        sys::thread_set_cpu(self.thread, cpu)
    }

    /// End the child and take back all of its memory.
    pub fn destroy(self) -> Result<(), Error> {
        // SAFETY: everything derived from this Untyped is the child's; the
        // parent uses none of it.
        #[allow(unsafe_code)]
        unsafe {
            // Checked here so that a failure is reported; returning the
            // block revokes again, which is then nothing to do.
            sys::cap_revoke(self.untyped)?;
            mem::free(self.untyped, self.mem_bits);
        }
        // The revocation emptied the other three slots.
        for cap in [self.thread, self.space, self.aspace] {
            release_slot(cap.0);
        }
        Ok(())
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
    /// The parent's CapSpace has no free slot left.
    NoSlot,
    /// A kernel operation failed: most often `NoMemory` (the budget is too
    /// small for the image) or `BadCap` (a grant names no capability).
    Kernel(Error),
}

impl From<Error> for SpawnError {
    fn from(e: Error) -> SpawnError {
        SpawnError::Kernel(e)
    }
}

/// A program to start: what [`spawn`] needs to know about the child.
#[derive(Clone, Copy, Debug)]
pub struct Program<'a> {
    /// The ELF image.
    pub image: &'a [u8],
    /// The child is made from `2^mem_bits` bytes in all, half of which it
    /// can allocate from (at least 2^20: the child's tables, image and stack
    /// come out of the other half).
    pub mem_bits: u8,
    /// Badges the child's capability to the parent's exit endpoint, so the
    /// parent knows whose exit report it receives.
    pub id: u64,
    /// The capabilities the child gets, in order from `slots::FIRST_GRANT`.
    pub grants: &'a [Grant],
    /// Words the child reads from `ProcessInfo::args`.
    pub args: [u64; 8],
    /// The processor its first thread runs on (an index below `Parent::cpus`).
    pub cpu: usize,
    /// Slots in its CapSpace, in bits (at least 8; room is needed for the
    /// grants, one slot per megabyte of image, and what it makes itself).
    pub space_bits: u8,
    /// Size in bits of its address-space object: a header page, the root
    /// table and one page table per further page (16: about 20 MiB of
    /// mappings; a program that maps more, or far apart, needs more).
    pub aspace_bits: u8,
}

impl<'a> Program<'a> {
    /// `image` with 4 MiB, no grants, no arguments, on processor 0.
    pub fn new(image: &'a [u8], id: u64) -> Self {
        Program { image, mem_bits: 22, id, grants: &[], args: [0; 8], cpu: 0, space_bits: SPACE_BITS, aspace_bits: ASPACE_BITS }
    }
}

/// Start `prog`: its first thread runs on `prog.cpu` from its first
/// instruction.
pub fn spawn(p: &Parent, prog: &Program) -> Result<Child, SpawnError> {
    let Program { image, mem_bits, cpu, .. } = *prog;
    if cpu as u64 >= p.cpus || !(8..=20).contains(&prog.space_bits) {
        return Err(SpawnError::Kernel(Error::BadArg));
    }
    // Three slots for the child's objects and two to work with.
    let mut got = [0u64; 5];
    for i in 0..got.len() {
        let Some(s) = free_slot() else {
            got[..i].iter().for_each(|s| release_slot(*s));
            return Err(SpawnError::NoSlot);
        };
        got[i] = s;
    }
    let give_back = |slots: &[u64]| slots.iter().for_each(|s| release_slot(*s));
    let untyped = match mem::alloc(mem_bits) {
        Ok(u) => u,
        Err(e) => {
            give_back(&got);
            return Err(e.into());
        }
    };
    let child = Child { untyped, mem_bits, thread: Cap(got[0]), space: Cap(got[1]), aspace: Cap(got[2]) };
    let result = match build(p, &child, [Cap(got[3]), Cap(got[4])], image, prog) {
        Ok(()) => Ok(child),
        Err(e) => {
            // Nothing half-made stays behind: returning the block revokes
            // it, which empties every slot used on the way.
            // SAFETY: everything made from the block was the child's.
            #[allow(unsafe_code)]
            unsafe {
                mem::free(untyped, mem_bits)
            };
            give_back(&got[..3]);
            Err(e)
        }
    };
    // On success both working slots are empty: their capabilities moved to the child.
    give_back(&got[3..]);
    result
}

fn build(p: &Parent, c: &Child, [tmp, own]: [Cap; 2], image: &[u8], prog: &Program) -> Result<(), SpawnError> {
    let Program { mem_bits, id, grants, args, cpu, space_bits, aspace_bits, .. } = *prog;
    let elf = Elf::parse(image, EM_NATIVE).map_err(SpawnError::Image)?;
    // The image's slots follow the grants.
    let first_image_slot = slots::FIRST_GRANT + grants.len() as u64;
    if grants.len() > MAX_GRANTS || first_image_slot >= 1 << space_bits {
        return Err(SpawnError::TooMany);
    }
    let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
    // The child's own allocatable memory comes first: half the budget.
    sys::retype(c.untyped, ObjectType::Untyped, mem_bits - 1, p.space, own.0, 1)?;
    sys::retype(c.untyped, ObjectType::CapSpace, space_bits, p.space, c.space.0, 1)?;
    sys::retype(c.untyped, ObjectType::AddressSpace, aspace_bits, p.space, c.aspace.0, 1)?;
    sys::retype(c.untyped, ObjectType::Thread, 0, p.space, c.thread.0, 1)?;

    // A frame of `bits` filled by `fill` (given the address it is mapped at
    // in the parent), mapped at `vaddr` in the child, its capability left in
    // the child's CapSpace at `slot`.
    let next_slot = core::cell::Cell::new(first_image_slot);
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
        if to >= 1 << space_bits {
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
        capspace_slots: 1 << space_bits,
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
    // Its faults go to the parent's fault endpoint, badged with its id. The
    // thread keeps a capability of its own; the working one goes again.
    if p.fault != Cap::NONE {
        sys::cap_derive(p.space, tmp.0, p.fault, Rights::WRITE, id | FAULT_BADGE)?;
        sys::thread_configure(c.thread, Cap::KEEP, Cap::KEEP, tmp, Cap::KEEP)?;
        // SAFETY: a capability made two lines up, used by nothing else.
        #[allow(unsafe_code)]
        unsafe {
            sys::cap_delete(tmp)?
        };
    }

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
        let to = slots::FIRST_GRANT + i as u64;
        if g.cap == Cap::NONE {
            continue;
        }
        if g.give {
            sys::cap_move(c.space, to, g.cap)?;
        } else {
            sys::cap_derive(c.space, to, g.cap, g.rights, g.badge)?;
        }
    }
    sys::thread_set_cpu(c.thread, cpu)?;
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

/// What a program holds, for its owner: every capability in the CapSpace
/// `space` (a capability in the caller's own CapSpace), and once per
/// thread among them, what that thread is doing. One line each on `out`:
///
/// ```text
/// process <name>: <n> capabilities, <m> threads
///   slot <i>: <type> rights <r> bits <b> object <id> badge <b> depth <d>
///   thread <id>: <state> on processor <c>, at <ip>, waiting on <id>
/// ```
///
/// An object's id (`SlotInfo::object`) is the same in every line about it,
/// so a thread waiting on an endpoint names the id its capabilities show.
/// Returns the numbers of capabilities and threads.
pub fn report(out: &mut dyn core::fmt::Write, name: &str, space: Cap) -> Result<(u64, u64), Error> {
    let size = sys::inspect_slot(slots::SPACE, space.0)?.filter(|i| i.ty == ObjectType::CapSpace).ok_or(Error::WrongType)?;
    let slots = 1u64 << size.bits;
    let (mut caps, mut threads) = (0u64, 0u64);
    for i in 1..slots {
        if sys::inspect_slot(space, i)?.is_some() {
            caps += 1;
        }
    }
    // Threads are listed once each, however many capabilities name them.
    let mut seen = [0u64; 64];
    for i in 1..slots {
        let Some(info) = sys::inspect_slot(space, i)? else { continue };
        if info.ty == ObjectType::Thread && !seen[..threads.min(64) as usize].contains(&info.object) {
            if (threads as usize) < seen.len() {
                seen[threads as usize] = info.object;
            }
            threads += 1;
        }
    }
    let _ = writeln!(out, "process {name}: {caps} capabilities, {threads} threads");
    let mut listed = [0u64; 64];
    let mut n = 0usize;
    for i in 1..slots {
        let Some(info) = sys::inspect_slot(space, i)? else { continue };
        let r = info.rights.0;
        let rights = [(1, 'r'), (2, 'w'), (4, 'x'), (8, 'g')].map(|(b, c)| if r & b != 0 { c } else { '-' });
        let _ = writeln!(
            out,
            "  slot {i}: {:?} rights {}{}{}{} bits {} object {:#x} badge {:#x} depth {}",
            info.ty, rights[0], rights[1], rights[2], rights[3], info.bits, info.object, info.badge, info.depth
        );
        if info.ty == ObjectType::Thread && !listed[..n].contains(&info.object) {
            if n < listed.len() {
                listed[n] = info.object;
                n += 1;
            }
            let t = sys::inspect_thread_in(space, i)?;
            let state =
                ["inactive", "runnable", "sending", "receiving", "waiting for a reply"].get(t.state as usize).copied().unwrap_or("unknown");
            let _ =
                writeln!(out, "  thread {:#x}: {state} on processor {}, at {:#x}, waiting on {:#x}", info.object, t.cpu, t.ip, t.waits_on);
        }
    }
    Ok((caps, threads))
}
