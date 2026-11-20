//! The root task's start: from the kernel's start-up record to a
//! [`Parent`] that can spawn the programs in the ramdisk.

use crate::Parent;
use libsys::root::{KIND_RAM, KIND_RAMDISK, ROOT_MAGIC, RootInfo, SLOT_ASPACE, SLOT_CAPSPACE, SLOT_FIRST_UNTYPED, SLOT_PORTS};
use libsys::{self as sys, Cap, ObjectType, Rights};
use silica_rt::ipc::free_slot;

/// The ramdisk is mapped at this address plus its physical address.
const RAMDISK_VADDR: usize = 0x40_0000_0000;
/// Where children's memory is filled in.
const SCRATCH_VADDR: usize = 0x50_0000_0000;

/// What the root task works with once it has started.
pub struct Root {
    /// The ramdisk archive (`silica_formats::ramdisk` reads it), mapped read-only.
    pub archive: &'static [u8],
    /// Spawns from the largest piece of memory the kernel handed over;
    /// children report their exit on `parent.exit` and print on the serial port.
    pub parent: Parent,
    /// Every I/O port of the machine.
    pub ports: Cap,
}

/// Start the runtime in the root task and prepare it to spawn. On failure
/// says what was wrong with what the kernel handed over.
pub fn start(info: &'static RootInfo) -> Result<Root, &'static str> {
    let (space, aspace, ports) = (Cap(SLOT_CAPSPACE), Cap(SLOT_ASPACE), Cap(SLOT_PORTS));
    silica_rt::start_root(ports, info.clock, info.ipc_buffer, info.first_free_slot, info.capspace_slots);
    if info.magic != ROOT_MAGIC {
        return Err("the kernel's start-up record has the wrong magic");
    }
    let descs = &info.untyped[..info.untyped_count as usize];
    let memory =
        (0..descs.len()).filter(|&i| descs[i].kind == KIND_RAM).max_by_key(|&i| descs[i].bits).ok_or("the kernel handed over no memory")?;
    let untyped = Cap(SLOT_FIRST_UNTYPED + memory as u64);

    for (i, d) in descs.iter().enumerate().filter(|(_, d)| d.kind == KIND_RAMDISK) {
        let frame = free_slot().ok_or("the root CapSpace is full")?;
        sys::retype(Cap(SLOT_FIRST_UNTYPED + i as u64), ObjectType::Frame, d.bits, space, frame, 1)
            .and_then(|()| sys::map(aspace, Cap(frame), RAMDISK_VADDR + d.base as usize, Rights::READ))
            .map_err(|_| "cannot map the ramdisk")?;
    }
    // SAFETY: the frames covering the archive were just mapped read-only at
    // RAMDISK_VADDR plus their physical address, and nothing writes them.
    #[allow(unsafe_code)]
    let archive = unsafe { core::slice::from_raw_parts((RAMDISK_VADDR + info.ramdisk[0] as usize) as *const u8, info.ramdisk[1] as usize) };

    // What children get of the serial port: its eight ports, nothing else.
    let (debug, exit) = (free_slot().ok_or("the root CapSpace is full")?, free_slot().ok_or("the root CapSpace is full")?);
    sys::cap_derive(space, debug, ports, Rights::ALL, 0x3F8 | 0x400 << 32).map_err(|_| "cannot derive the serial port")?;
    sys::retype(untyped, ObjectType::Endpoint, 0, space, exit, 1).map_err(|_| "cannot create the exit endpoint")?;
    let parent =
        Parent { space, aspace, untyped, scratch: SCRATCH_VADDR, exit: Cap(exit), debug: Cap(debug), cpus: info.cpus, clock: info.clock };
    Ok(Root { archive, parent, ports })
}

/// Leave the emulator with a status through its debug-exit device (the
/// test harness reads it), or stop for ever on a real machine.
pub fn finish(ok: bool) -> ! {
    let _ = sys::port_out(Cap(SLOT_PORTS), 0xF4, 1, if ok { 0x10 } else { 0x11 });
    loop {
        let _ = sys::thread_suspend(Cap(libsys::root::SLOT_THREAD));
    }
}
