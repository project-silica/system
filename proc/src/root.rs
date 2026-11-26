//! The root task's start: from the kernel's start-up record to a
//! [`Parent`] that can spawn the programs in the ramdisk.

use crate::Parent;
use libsys::root::{
    KIND_RAM, KIND_RAMDISK, ROOT_MAGIC, RootInfo, SLOT_ASPACE, SLOT_CAPSPACE, SLOT_CONSOLE, SLOT_FIRST_UNTYPED, SLOT_PORTS, SLOT_POWER,
};
use libsys::{self as sys, Cap, ObjectType, Rights};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::free_slot;
use silica_rt::mem;

/// The ramdisk is mapped at this address plus its physical address.
const RAMDISK_VADDR: usize = 0x40_0000_0000;
/// Where children's memory is filled in.
const SCRATCH_VADDR: usize = 0x50_0000_0000;

/// What the root task works with once it has started.
pub struct Root {
    /// The ramdisk archive (`silica_formats::ramdisk` reads it), mapped read-only.
    pub archive: &'static [u8],
    /// Children report their exit on `parent.exit` and print on the
    /// kernel's console. All the machine's memory is in `silica_rt::mem`.
    pub parent: Parent,
    /// Every I/O port of the machine (x86_64; an empty slot elsewhere).
    pub ports: Cap,
    /// The frames of the ramdisk, in the order the kernel listed its memory:
    /// what a program that reads the boot archive itself is lent.
    pub ramdisk: Vec<Cap>,
    /// The boot secret (`libsys::root::secret`): every seed and key the root
    /// task hands out descends from it. It is in the root task's memory
    /// only, never in a frame lent to anyone.
    pub secret: [u8; 32],
}

/// Start the runtime in the root task and prepare it to spawn. On failure
/// says what was wrong with what the kernel handed over. `secret`: the
/// four words the root thread started with after the record
/// (`libsys::root::secret`).
pub fn start(info: &'static RootInfo, secret: [u64; 4]) -> Result<Root, &'static str> {
    let secret = libsys::root::secret(secret);
    let (space, aspace, ports) = (Cap(SLOT_CAPSPACE), Cap(SLOT_ASPACE), Cap(SLOT_PORTS));
    silica_rt::start_root(Cap(SLOT_CONSOLE), info.clock, info.ipc_buffer, info.first_free_slot, info.capspace_slots, &secret);
    if info.magic != ROOT_MAGIC {
        return Err("the kernel's start-up record has the wrong magic");
    }
    if info.entropy_sources == 0 {
        // Every program's generator descends from this one.
        silica_rt::println!("ERROR: the boot loader found no source of randomness it trusts: random numbers are predictable");
    }
    let descs = &info.untyped[..info.untyped_count as usize];
    // All of the machine's memory.
    let mut added = 0;
    for (i, d) in descs.iter().enumerate().filter(|(_, d)| d.kind == KIND_RAM) {
        mem::add_source(Cap(SLOT_FIRST_UNTYPED + i as u64), d.bits);
        added += 1;
    }
    if added == 0 {
        return Err("the kernel handed over no memory");
    }

    let mut ramdisk = Vec::new();
    for (i, d) in descs.iter().enumerate().filter(|(_, d)| d.kind == KIND_RAMDISK) {
        let frame = free_slot().ok_or("the root CapSpace is full")?;
        ramdisk.push(Cap(frame));
        sys::retype(Cap(SLOT_FIRST_UNTYPED + i as u64), ObjectType::Frame, d.bits, space, frame, 1)
            .and_then(|()| sys::map(aspace, Cap(frame), RAMDISK_VADDR + d.base as usize, Rights::READ))
            .map_err(|_| "cannot map the ramdisk")?;
    }
    // SAFETY: the frames covering the archive were just mapped read-only at
    // RAMDISK_VADDR plus their physical address, and nothing writes them.
    #[allow(unsafe_code)]
    let archive = unsafe { core::slice::from_raw_parts((RAMDISK_VADDR + info.ramdisk[0] as usize) as *const u8, info.ramdisk[1] as usize) };

    // What children get of the console: a capability derived from the
    // root's, which can write and nothing else.
    let (debug, exit) = (free_slot().ok_or("the root CapSpace is full")?, free_slot().ok_or("the root CapSpace is full")?);
    sys::cap_derive(space, debug, Cap(SLOT_CONSOLE), Rights::WRITE, 0).map_err(|_| "cannot derive the console")?;
    // The exit endpoint lives as long as the system: no block of its own.
    let page = mem::alloc(12).map_err(|_| "no memory for the exit endpoint")?;
    sys::retype(page, ObjectType::Endpoint, 0, space, exit, 1).map_err(|_| "cannot create the exit endpoint")?;
    let parent = Parent {
        space,
        aspace,
        scratch: SCRATCH_VADDR,
        exit: Cap(exit),
        fault: Cap::NONE,
        debug: Cap(debug),
        cpus: info.cpus,
        clock: info.clock,
        time: Cap::NONE,
        sched: Cap(libsys::root::SLOT_CONTEXT),
    };
    Ok(Root { archive, parent, ports, ramdisk, secret })
}

/// Turn the machine off, telling a test harness whether everything
/// passed; where it cannot be turned off yet, say why and stop for ever.
pub fn finish(ok: bool) -> ! {
    let why = sys::power_off(Cap(SLOT_POWER), if ok { 0 } else { 1 });
    silica_rt::println!("init: the machine cannot be turned off: {why:?}");
    loop {
        let _ = sys::thread_suspend(Cap(libsys::root::SLOT_THREAD));
    }
}
