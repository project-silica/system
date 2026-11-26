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
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{free_slot, release_slot};
use silica_rt::mem::{self, Object};
use silica_rt::{PROCESS_MAGIC, ProcessInfo, slots};

pub mod root;

/// Where a child finds its start-up record.
pub const INFO_VADDR: usize = 0x7F00_0000_0000;
/// Where a child's first IPC buffer is mapped.
pub const IPC_VADDR: usize = 0x7F00_0001_0000;
/// The lowest address of a child's first stack (256 KiB: a generated
/// protocol client alone takes 8 KiB).
pub const STACK_VADDR: usize = 0x7F00_0010_0000;
const STACK_BITS: u8 = 18;
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
/// The lowest slot of a child's CapSpace used for its image, stack and record.
const FIRST_IMAGE_SLOT: u64 = 64;
/// Most pages of zeros a child holds at once in place of lent memory taken
/// back ([`Child::answer_peer_fault`]): past them the oldest is moved to
/// where the child touched now, so the parent's memory for them stays
/// bounded and the child is never stopped for touching lent memory, however
/// many lenders take theirs back over its life.
pub const ZERO_PAGES: usize = 64;

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
    /// The time page children are given read-only when their `Program`
    /// names none ([`Cap::NONE`]: none).
    pub time: Cap,
    /// The parent's own scheduling context (`slots::SCHED`; the root
    /// task's `libsys::root::SLOT_CONTEXT`): what a child runs on when its
    /// `Program` names none.
    pub sched: Cap,
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
    /// otherwise it is gone when the child is destroyed, unless the parent
    /// takes it back first ([`Child::take_back`]).
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
    /// Pages of zeros mapped where lent memory was taken back, from the
    /// parent's memory: a child cannot be made to pay for its peers.
    zero_pages: Vec<Object>,
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
            time: if matches!(sys::inspect_slot(slots::SPACE, slots::TIME.0), Ok(Some(_))) { slots::TIME } else { Cap::NONE },
            sched: slots::SCHED,
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

    /// Answer the kernel's report of the child's fault `m` (on
    /// [`Parent::fault`]) if it is the child touching memory a peer lent it
    /// and took back (an address from [`mem::PEER_BASE`] to
    /// [`mem::PEER_END`]): a page of zeros is mapped there and the child
    /// carries on, as `silica_rt::mem` promises every program. Returns
    /// whether it was answered; any other fault is the child's own. The
    /// child holds at most [`ZERO_PAGES`] of them: past that, the one it
    /// was given longest ago goes (touched again, that place is answered
    /// again), and its memory makes the new one.
    pub fn answer_peer_fault(&mut self, m: &sys::Message) -> bool {
        let at = m.words[1];
        if m.info.label() != sys::FAULT_LABEL + sys::Fault::Page as u64 || !(mem::PEER_BASE..mem::PEER_END).contains(&at) {
            return false;
        }
        if self.zero_pages.len() >= ZERO_PAGES {
            let oldest = self.zero_pages.remove(0);
            // SAFETY: the parent maps it nowhere; destroying it unmaps it
            // from the child, which faults again if it touches that place
            // once more. Its memory comes back for the fresh page below.
            #[allow(unsafe_code)]
            unsafe {
                oldest.destroy()
            };
        }
        let Ok(page) = Object::new(ObjectType::Frame, 12) else { return false };
        if sys::fault_map(self.aspace, page.cap(), at as usize & !0xFFF, Rights(Rights::READ.0 | Rights::WRITE.0)).is_ok() {
            self.zero_pages.push(page);
            return true;
        }
        // SAFETY: mapped nowhere.
        #[allow(unsafe_code)]
        unsafe {
            page.destroy()
        };
        false
    }

    /// Take back what slot `index` of the child's CapSpace holds (grant
    /// `n` is at `slots::FIRST_GRANT + n`) into the parent's empty slot
    /// `to`, keeping its place in the derivation tree: what a parent does
    /// before destroying a child it gave something outright.
    pub fn take_back(&self, index: u64, to: u64) -> Result<(), Error> {
        sys::cap_move_from(slots::SPACE, to, self.space, index)
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
        for page in self.zero_pages {
            // SAFETY: mapped only in the child, which is gone.
            #[allow(unsafe_code)]
            unsafe {
                page.destroy()
            };
        }
        Ok(())
    }
}

/// The seed a parent gives a child for its `start`th start: a keyed
/// BLAKE2s of the parent's secret `boot` over the child's `name` and the
/// start, so no two starts of any child share one, and knowing one says
/// nothing about `boot` or about another's (the service manager's `seed`
/// declaration; the entropy service is seeded so).
pub fn seed(boot: &[u8; 32], name: &str, start: u64) -> [u8; 32] {
    silica_formats::blake2s::Blake2s::keyed(boot).update(b"silica child seed").update(name.as_bytes()).update(&start.to_le_bytes()).finish()
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
    /// Slots in its CapSpace, in bits (at least 8; room is needed for the
    /// grants, one slot per megabyte of image, and what it makes itself).
    pub space_bits: u8,
    /// Size in bits of its address-space object: a header page, the root
    /// table and one page table per further page (16: about 20 MiB of
    /// mappings; a program that maps more, or far apart, needs more).
    pub aspace_bits: u8,
    /// Its log: a ring frame of `silica_rt::log::BITS` and what wakes the
    /// log service (derived into `slots::LOG` and `slots::LOG_WAKE`); without
    /// one it prints to the debug console.
    pub log: Option<(Cap, Cap)>,
    /// Its own notification (derived, with every right, into
    /// `slots::EVENTS`): what its parent tells it of its providers.
    pub events: Option<Cap>,
    /// A page that outlives it (derived, readable and writable, into
    /// `slots::KEEP`).
    pub keep: Option<Cap>,
    /// The time page and whether it may set the time (derived into
    /// `slots::TIME`). Without one, a program started by a program that
    /// has a time page gets that page, read-only.
    pub time: Option<(Cap, bool)>,
    /// Its options (`silica_rt::options`), at most
    /// `silica_rt::OPTIONS_MAX` bytes: longer is refused.
    pub options: &'a [u8],
    /// The scheduling context it runs on (`libsys::sched_fair`: one share
    /// of one processor): its first thread is bound to it and runs on its
    /// processor, and the child holds it readable (`slots::SCHED`), which
    /// is all it can bind the threads it makes to, so its threads together
    /// take that one share however many it makes. `None`: the parent's own
    /// (`Parent::sched`), which the child then shares with its parent.
    pub sched: Option<Cap>,
    /// Its address space isolated against speculative execution
    /// (`libsys::ASPACE_ISOLATED`): for a program that holds secrets. Every
    /// switch into or out of it flushes the processor's predictors.
    pub isolated: bool,
    /// The parent hears when it first waits for requests: a notification
    /// and the badge the child signals it with, from `slots::SERVING`
    /// (`silica_rt::serving`). What the service manager asks of a program
    /// an update installed.
    pub says_serving: Option<(Cap, u64)>,
}

impl<'a> Program<'a> {
    /// `image` with 4 MiB, no grants, no arguments, on its parent's
    /// scheduling context.
    pub fn new(image: &'a [u8], id: u64) -> Self {
        Program {
            image,
            mem_bits: 22,
            id,
            grants: &[],
            args: [0; 8],
            space_bits: SPACE_BITS,
            aspace_bits: ASPACE_BITS,
            log: None,
            events: None,
            keep: None,
            time: None,
            options: &[],
            sched: None,
            isolated: false,
            says_serving: None,
        }
    }
}

/// The most loadable segments an image may have.
pub const MAX_SEGMENTS: usize = 16;

/// Check that `image` is a program [`spawn`] can load, without making
/// anything: an ELF image for this machine whose loadable segments (at
/// least one, at most [`MAX_SEGMENTS`]) are each writable or executable
/// but not both, lie below the start-up record ([`INFO_VADDR`]) once
/// rounded out to pages, and share no page. Returns each segment's page
/// range, in file order. What the service manager checks a program sent
/// to it with before it ends the program it replaces (`update`), and what
/// `spawn` loads by; fuzzed (`system/proc/fuzz`, target `image`).
pub fn check_image(image: &[u8]) -> Result<Vec<(u64, u64)>, SpawnError> {
    let elf = Elf::parse(image, EM_NATIVE).map_err(SpawnError::Image)?;
    let mut pages: Vec<(u64, u64)> = Vec::new();
    for seg in elf.segments() {
        if seg.flags & PF_W != 0 && seg.flags & PF_X != 0 {
            return Err(SpawnError::Segment);
        }
        let start = seg.vaddr & !0xFFF;
        let end = seg.vaddr.checked_add(seg.memsz).and_then(|e| e.checked_add(0xFFF)).ok_or(SpawnError::Segment)? & !0xFFF;
        if end > INFO_VADDR as u64 || pages.len() == MAX_SEGMENTS {
            return Err(SpawnError::Segment);
        }
        if pages.iter().any(|&(s, e)| start < e && s < end) {
            return Err(SpawnError::Segment);
        }
        pages.push((start, end));
    }
    if pages.is_empty() {
        return Err(SpawnError::Segment);
    }
    Ok(pages)
}

/// Start `prog`: its first thread runs from its first instruction, on
/// the processor of the scheduling context it is given. A given grant
/// leaves the parent only on success. Keep its source slot reserved for
/// the duration of this call.
pub fn spawn(p: &Parent, prog: &Program) -> Result<Child, SpawnError> {
    let Program { image, mem_bits, .. } = *prog;
    if !(8..=20).contains(&prog.space_bits) || prog.options.len() > silica_rt::OPTIONS_MAX {
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
    let child = Child { untyped, mem_bits, thread: Cap(got[0]), space: Cap(got[1]), aspace: Cap(got[2]), zero_pages: Vec::new() };
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
    let Program { mem_bits, id, grants, args, space_bits, aspace_bits, isolated, .. } = *prog;
    let pages = check_image(image)?;
    let elf = Elf::parse(image, EM_NATIVE).map_err(SpawnError::Image)?;
    // The image's slots follow the grants, from slot 64 at the lowest: the
    // slots from FIRST_GRANT to 64 a parent did not fill stay empty, for
    // capabilities given to the program later (as a supervisor does).
    let first_image_slot = (slots::FIRST_GRANT + grants.len() as u64).max(FIRST_IMAGE_SLOT);
    if grants.len() > MAX_GRANTS || first_image_slot >= 1 << space_bits {
        return Err(SpawnError::TooMany);
    }
    let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
    // The child's own allocatable memory comes first: half the budget.
    sys::retype(c.untyped, ObjectType::Untyped, mem_bits - 1, p.space, own.0, 1)?;
    sys::retype(c.untyped, ObjectType::CapSpace, space_bits, p.space, c.space.0, 1)?;
    if isolated {
        sys::retype_isolated_space(c.untyped, aspace_bits, p.space, c.aspace.0)?;
    } else {
        sys::retype(c.untyped, ObjectType::AddressSpace, aspace_bits, p.space, c.aspace.0, 1)?;
    }
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

    for (seg, (start, end)) in elf.segments().zip(pages) {
        let rights = Rights(
            Rights::READ.0
                | if seg.flags & PF_W != 0 { Rights::WRITE.0 } else { 0 }
                | if seg.flags & PF_X != 0 { Rights::EXEC.0 } else { 0 },
        );
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
        says_serving: prog.says_serving.is_some() as u64,
    };
    // The program's own page, read-write: the runtime takes the seed of its
    // random number generator from it and overwrites it (`silica_rt::random`).
    let mut seed = [0u8; 32];
    silica_rt::random::fill(&mut seed);
    place(12, INFO_VADDR, rw, None, &mut |mapped| {
        write_info(&info, mapped);
        write_seed(&seed, mapped + silica_rt::random::SEED_OFFSET);
        write_options(prog.options, mapped + silica_rt::OPTIONS_OFFSET);
    })?;
    seed.fill(0);

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
    if let Some((ring, wake)) = prog.log {
        sys::cap_derive(c.space, slots::LOG.0, ring, Rights(Rights::READ.0 | Rights::WRITE.0), 0)?;
        sys::cap_derive(c.space, slots::LOG_WAKE.0, wake, Rights::WRITE, 0)?;
    }
    // The wall clock: the page given, or this program's own, read-only.
    let time = prog.time.or_else(|| (p.time != Cap::NONE).then_some((p.time, false)));
    if let Some((page, writable)) = time {
        let rights = if writable { Rights(Rights::READ.0 | Rights::WRITE.0) } else { Rights::READ };
        sys::cap_derive(c.space, slots::TIME.0, page, rights, 0)?;
    }
    if let Some(page) = prog.keep {
        sys::cap_derive(c.space, slots::KEEP.0, page, Rights(Rights::READ.0 | Rights::WRITE.0), 0)?;
    }
    if let Some(events) = prog.events {
        sys::cap_derive(c.space, slots::EVENTS.0, events, Rights::ALL, 0)?;
    }
    if let Some((note, badge)) = prog.says_serving {
        sys::cap_derive(c.space, slots::SERVING.0, note, Rights::WRITE, badge)?;
    }
    // Processor time: the context named, or the parent's own. The child
    // holds it readable, to bind what it makes and to pass on; its first
    // thread has no time until it is bound, and runs on the context's
    // processor.
    let sched = prog.sched.unwrap_or(p.sched);
    sys::cap_derive(c.space, slots::SCHED.0, sched, Rights::READ, 0)?;
    sys::thread_bind(c.thread, sched)?;
    let mut installed = 0;
    let result = (|| {
        for (i, g) in grants.iter().enumerate() {
            let to = slots::FIRST_GRANT + i as u64;
            if g.cap != Cap::NONE {
                if g.give {
                    sys::cap_move(c.space, to, g.cap)?;
                } else {
                    sys::cap_derive(c.space, to, g.cap, g.rights, g.badge)?;
                }
            }
            installed = i + 1;
        }
        // SAFETY: the entry point of an image just loaded into the thread's
        // address space, on the stack just mapped there.
        #[allow(unsafe_code)]
        unsafe {
            sys::thread_start(c.thread, elf.entry as usize, STACK_VADDR + (1 << STACK_BITS), INFO_VADDR as u64, true)
        }
    })();
    if result.is_err() {
        // The child never ran. Each successful move left its reserved
        // parent slot empty. Derived grants go away with the child.
        let mut rollback = Ok(());
        for (i, g) in grants[..installed].iter().enumerate().rev() {
            if g.give
                && g.cap != Cap::NONE
                && let Err(e) = sys::cap_move_from(p.space, g.cap.0, c.space, slots::FIRST_GRANT + i as u64)
            {
                rollback = Err(e);
            }
        }
        rollback?;
    }
    result.map_err(Into::into)
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
fn write_seed(seed: &[u8; 32], to: usize) {
    // SAFETY: `to` lies inside the same fresh page, mapped read-write, past
    // the ProcessInfo (SEED_OFFSET + 32 <= 4096).
    #[allow(unsafe_code)]
    unsafe {
        core::ptr::copy_nonoverlapping(seed.as_ptr(), to as *mut u8, 32)
    }
}

/// Write the options, their length first, to the page at `to`.
fn write_options(options: &[u8], to: usize) {
    let len = (options.len() as u16).to_le_bytes();
    // SAFETY: `to` lies inside the same fresh page, mapped read-write, at
    // OPTIONS_OFFSET, and the options were checked to fit before it
    // (`spawn`: at most OPTIONS_MAX bytes after the two of length).
    #[allow(unsafe_code)]
    unsafe {
        core::ptr::copy_nonoverlapping(len.as_ptr(), to as *mut u8, 2);
        core::ptr::copy_nonoverlapping(options.as_ptr(), (to + 2) as *mut u8, options.len());
    }
}

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
            "  slot {i}: {:?} rights {}{}{}{} bits {} object {:#x} badge {:#x} depth {}{}",
            info.ty,
            rights[0],
            rights[1],
            rights[2],
            rights[3],
            info.bits,
            info.object,
            info.badge,
            info.depth,
            if info.isolated { " isolated against speculation" } else { "" }
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

#[cfg(test)]
mod tests {
    use super::*;
    use silica_formats::elf::ElfError;
    use silica_rt::alloc;
    const PF_R: u32 = 4;

    /// An ELF image for this machine with one loadable segment per
    /// `(vaddr, memsz, flags)`, each with 16 bytes in the file.
    fn image(segments: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut f = alloc::vec![0u8; 64 + 56 * segments.len()];
        f[..6].copy_from_slice(b"\x7fELF\x02\x01");
        f[16..18].copy_from_slice(&2u16.to_le_bytes());
        f[18..20].copy_from_slice(&EM_NATIVE.to_le_bytes());
        f[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        let data = f.len() as u64;
        for (i, &(vaddr, memsz, flags)) in segments.iter().enumerate() {
            let p = 64 + 56 * i;
            f[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
            f[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
            f[p + 8..p + 16].copy_from_slice(&data.to_le_bytes());
            f[p + 16..p + 24].copy_from_slice(&vaddr.to_le_bytes());
            f[p + 32..p + 40].copy_from_slice(&16u64.min(memsz).to_le_bytes());
            f[p + 40..p + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        f.extend_from_slice(&[0x90; 16]);
        f
    }

    #[test]
    fn a_program_is_checked_by_its_segments() {
        let (rx, rw) = (PF_R | PF_X, PF_R | PF_W);
        assert_eq!(
            check_image(&image(&[(0x40_0000, 0x1800, rx), (0x40_2000, 0x10, rw)])),
            Ok(alloc::vec![(0x40_0000, 0x40_2000), (0x40_2000, 0x40_3000)])
        );
        // Writable and executable at once.
        assert_eq!(check_image(&image(&[(0x40_0000, 0x1000, rx | PF_W)])), Err(SpawnError::Segment));
        // Two segments in one page.
        assert_eq!(check_image(&image(&[(0x40_0000, 0x100, rx), (0x40_0800, 0x10, rw)])), Err(SpawnError::Segment));
        // Past the start-up record, or rounding past the top of the addresses.
        assert_eq!(check_image(&image(&[(INFO_VADDR as u64 - 0x800, 0x1000, rw)])), Err(SpawnError::Segment));
        assert_eq!(check_image(&image(&[(u64::MAX - 0x20, 0x10, rw)])), Err(SpawnError::Segment));
        // No segment at all, and too many.
        assert_eq!(check_image(&image(&[])), Err(SpawnError::Segment));
        let many: Vec<_> = (0..MAX_SEGMENTS as u64 + 1).map(|i| (0x40_0000 + i * 0x1000, 0x10, rw)).collect();
        assert_eq!(check_image(&image(&many)), Err(SpawnError::Segment));
        assert!(check_image(&image(&many[..MAX_SEGMENTS])).is_ok());
        // Not ELF at all.
        assert_eq!(check_image(b"not a program\n"), Err(SpawnError::Image(ElfError::NotElf)));
    }
}

/// When a program that fails is started again: the service manager's
/// services, the device manager's drivers. The first failure is restarted
/// at once, so a program that fails once costs its clients only the start;
/// each further failure soon after its start waits twice as long as the one
/// before, from [`Restarts::SECOND`] up to [`Restarts::LONGEST`], so a
/// program that fails as it starts does not take a processor with it. One
/// that ran [`Restarts::STEADY`] before failing begins the count again: on
/// a machine that runs for months, failures far apart are each the first.
/// Nothing is given up on for good: a program that always fails is tried
/// once a [`Restarts::LONGEST`], and shown as failed meanwhile. (Before, a
/// service's fourth failure in the machine's life stopped it until reboot,
/// restarts were immediate, and a start that failed was never tried again.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Restarts {
    /// Failures in a row, each soon after its start.
    pub streak: u32,
    /// Failures since the machine started.
    pub total: u32,
    /// When it last started.
    started: u64,
    /// When to start it again (0: it is not waiting to be).
    pub due: u64,
}

impl Restarts {
    /// The wait before the second restart in a row.
    pub const SECOND: u64 = 100_000_000;
    /// The longest wait.
    pub const LONGEST: u64 = 60_000_000_000;
    /// How long a program must run for its next failure to count as a
    /// first.
    pub const STEADY: u64 = 60_000_000_000;

    /// It started at `now`.
    pub fn started(&mut self, now: u64) {
        self.started = now;
        self.due = 0;
    }

    /// It failed (or could not be started) at `now`: returns when to start
    /// it again.
    pub fn failed(&mut self, now: u64) -> u64 {
        self.total = self.total.saturating_add(1);
        if now.saturating_sub(self.started) >= Self::STEADY {
            self.streak = 0;
        }
        self.streak = self.streak.saturating_add(1);
        let wait = match self.streak {
            1 => 0,
            n => Self::SECOND.saturating_mul(1 << (n - 2).min(20)).min(Self::LONGEST),
        };
        // The start that follows is measured from when it is due.
        self.started = now + wait;
        self.due = (now + wait).max(1);
        self.due
    }

    /// Not to be started again by itself (its owner stopped it).
    pub fn cancel(&mut self) {
        self.due = 0;
    }
}

#[cfg(test)]
mod restarts {
    use super::{Restarts, Vec};
    const S: u64 = 1_000_000_000;

    #[test]
    fn the_first_failure_restarts_at_once_and_a_loop_backs_off_to_a_minute() {
        let mut r = Restarts::default();
        r.started(10 * S);
        assert_eq!(r.failed(11 * S), 11 * S);
        r.started(11 * S);
        let mut now = 11 * S;
        let mut waits = Vec::new();
        for _ in 0..12 {
            let due = r.failed(now);
            waits.push(due - now);
            now = due;
            r.started(now);
        }
        assert_eq!(&waits[..4], &[Restarts::SECOND, 2 * Restarts::SECOND, 4 * Restarts::SECOND, 8 * Restarts::SECOND]);
        assert!(waits.iter().all(|w| *w <= Restarts::LONGEST));
        assert_eq!(*waits.last().unwrap(), Restarts::LONGEST, "an endless loop settles at a try a minute, never stops");
        assert_eq!(r.total, 13);
    }

    #[test]
    fn failures_far_apart_are_each_a_first() {
        let mut r = Restarts::default();
        let mut now = 0;
        for _ in 0..100 {
            r.started(now);
            now += Restarts::STEADY + S;
            assert_eq!(r.failed(now), now, "a failure after a steady run waits for nothing");
        }
        assert_eq!((r.streak, r.total), (1, 100));
    }
}

/// Where a service asks to run (its declaration's `cpu=`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// On this processor.
    Fixed(u32),
    /// Wherever its parent chooses.
    Any,
}

/// The processor each of `wanted` runs on, on a machine of `cpus`
/// processors: the one it names, or processor 0 when the machine has no
/// such processor (`true` beside it: the caller says so); for
/// [`Placement::Any`], the processors after the first in turn (processor 0
/// on a machine of one), so what the declarations let go is spread over
/// what processor 0, where everything else runs, does not.
pub fn place(wanted: &[Placement], cpus: usize) -> Vec<(usize, bool)> {
    let mut next = 1;
    wanted
        .iter()
        .map(|w| match *w {
            Placement::Fixed(n) if (n as usize) < cpus => (n as usize, false),
            Placement::Fixed(_) => (0, true),
            Placement::Any if cpus <= 1 => (0, false),
            Placement::Any => {
                let c = next;
                next = if next + 1 < cpus { next + 1 } else { 1 };
                (c, false)
            }
        })
        .collect()
}

#[cfg(test)]
mod placement {
    use super::{Placement as P, place};

    #[test]
    fn named_processors_are_kept_missing_ones_fall_back_and_any_is_spread_past_the_first() {
        let wanted = [P::Fixed(0), P::Any, P::Fixed(3), P::Any, P::Any, P::Fixed(9)];
        assert_eq!(place(&wanted, 4), [(0, false), (1, false), (3, false), (2, false), (3, false), (0, true)]);
        // `any` wraps past the last processor, never onto the first.
        assert_eq!(place(&[P::Any, P::Any, P::Any], 3), [(1, false), (2, false), (1, false)]);
        // One processor: everything on it, a named other one said to be missing.
        assert_eq!(place(&[P::Any, P::Fixed(1)], 1), [(0, false), (0, true)]);
    }
}
