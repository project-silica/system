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
/// Where a ramdisk frame is mapped again, writable, for [`Root::wipe`].
const WIPE_VADDR: usize = 0x60_0000_0000;

/// What the root task works with once it has started.
pub struct Root {
    /// The ramdisk archive (`silica_formats::ramdisk` reads it), mapped read-only.
    pub archive: &'static [u8],
    /// Children report their exit on `parent.exit` and print on the
    /// kernel's console. All the machine's memory is in `silica_rt::mem`.
    pub parent: Parent,
    /// Every I/O port of the machine (x86_64; an empty slot elsewhere).
    pub ports: Cap,
    /// The frames of the ramdisk (capability, physical base, size in
    /// bits), in the order the kernel listed its memory: lent to nobody.
    /// The archive holds files provisioned for one service each (`files=`:
    /// a machine key), wiped once their service has them ([`Root::wipe`]);
    /// a program that reads part of the archive is lent an archive of just
    /// that part ([`archive_of`]).
    ramdisk: Vec<(Cap, u64, u8)>,
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
        ramdisk.push((Cap(frame), d.base, d.bits));
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

impl Root {
    /// Zero `data`, a part of the boot archive (an entry's bytes, as
    /// `silica_formats::ramdisk::find` gives them), where it lies in memory:
    /// a file provisioned for one service (`files=`) once that service's
    /// copy is made, so that no later reader of the archive, and nothing
    /// else that reaches its memory, finds it there. Each frame it lies in
    /// is mapped again, writable, through a copy of its capability, and the
    /// copy deleted after. The archive's checksum no longer holds for that
    /// entry: it is checked once, by the kernel, before anything runs.
    pub fn wipe(&self, data: &[u8]) -> Result<(), &'static str> {
        if data.is_empty() {
            return Ok(());
        }
        let (at, archive) = (data.as_ptr() as usize, self.archive.as_ptr() as usize);
        if at < archive || at + data.len() > archive + self.archive.len() {
            return Err("what is to be wiped is not part of the boot archive");
        }
        // Physical addresses: the archive is mapped at RAMDISK_VADDR plus them.
        let (from, to) = ((at - RAMDISK_VADDR) as u64, (at - RAMDISK_VADDR + data.len()) as u64);
        let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
        for &(frame, base, bits) in &self.ramdisk {
            let (lo, hi) = (from.max(base), to.min(base + (1u64 << bits)));
            if lo >= hi {
                continue;
            }
            let copy = free_slot().ok_or("the root CapSpace is full")?;
            sys::cap_derive(Cap(SLOT_CAPSPACE), copy, frame, rw, 0)
                .and_then(|()| sys::map(Cap(SLOT_ASPACE), Cap(copy), WIPE_VADDR + base as usize, rw))
                .map_err(|_| "cannot map the boot archive to wipe it")?;
            // SAFETY: the frame's copy was just mapped writable at
            // WIPE_VADDR plus its physical base, and `lo..hi` lies inside
            // it. The bytes are the archive's, mapped read-only at
            // RAMDISK_VADDR for `archive`, whose readers never read an
            // entry they have taken (init reads each provisioned file once,
            // to copy it, before it is wiped).
            #[allow(unsafe_code)]
            unsafe {
                core::ptr::write_bytes((WIPE_VADDR + lo as usize) as *mut u8, 0, (hi - lo) as usize);
                // Deleting the copy unmaps it.
                let _ = sys::cap_delete(Cap(copy));
            }
            silica_rt::ipc::release_slot(copy);
        }
        Ok(())
    }
}

/// A boot archive holding `entries` (name and bytes, in this order) in a
/// frame of its own, in `silica_formats::ramdisk`'s format, checked by its
/// validator before it is returned: what a program that reads part of the
/// boot archive is lent instead of all of it (the device manager: the
/// drivers it starts). Written in place, its checksum computed as it is.
pub fn archive_of(entries: &[(&str, &[u8])]) -> Result<mem::Memory, &'static str> {
    use silica_formats::ramdisk as f;
    let align = |n: usize| n.div_ceil(f::ALIGN) * f::ALIGN;
    if entries.len() > f::MAX_ENTRIES {
        return Err("too many entries for one archive");
    }
    let table_end = f::HEADER + f::ENTRY * entries.len();
    let mut offsets = Vec::with_capacity(entries.len());
    let mut len = align(table_end);
    for (name, data) in entries {
        if !f::name_ok(name.as_bytes()) {
            return Err("an entry name the archive's format does not allow");
        }
        offsets.push(len);
        len = align(len + data.len());
    }
    let bits = (len.next_power_of_two().trailing_zeros() as u8).max(12);
    let m = mem::Memory::new(bits).map_err(|_| "no memory for an archive")?;
    let out = m.shared();
    // The frame is zeroed: padding is written as nothing, and counted.
    let zeros = |mut crc: u32, mut n: usize| {
        while n > 0 {
            let k = n.min(64);
            crc = f::crc32c_update(crc, &[0; 64][..k]);
            n -= k;
        }
        crc
    };
    // The header, its checksum and reserved fields zero while it is summed.
    let mut header = [0u8; f::HEADER];
    header[..8].copy_from_slice(&f::MAGIC);
    header[8..12].copy_from_slice(&f::VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    header[16..24].copy_from_slice(&(len as u64).to_le_bytes());
    let mut crc = f::crc32c_update(!0, &header);
    for (i, ((name, data), at)) in entries.iter().zip(&offsets).enumerate() {
        let mut e = [0u8; f::ENTRY];
        e[..name.len()].copy_from_slice(name.as_bytes());
        e[32..40].copy_from_slice(&(*at as u64).to_le_bytes());
        e[40..48].copy_from_slice(&(data.len() as u64).to_le_bytes());
        out.write_bytes(f::HEADER + i * f::ENTRY, &e);
        crc = f::crc32c_update(crc, &e);
    }
    let mut pos = table_end;
    for ((_, data), at) in entries.iter().zip(&offsets) {
        crc = zeros(crc, at - pos);
        out.write_bytes(*at, data);
        crc = f::crc32c_update(crc, data);
        pos = at + data.len();
    }
    crc = zeros(crc, len - pos);
    header[24..28].copy_from_slice(&(!crc).to_le_bytes());
    out.write_bytes(0, &header);
    // SAFETY: the frame is this program's own, mapped readable for as long
    // as `m` lives, and at least `len` bytes; nothing writes it now.
    #[allow(unsafe_code)]
    let made = unsafe { core::slice::from_raw_parts(m.addr() as *const u8, len) };
    f::check(made, f::crc32c_update).map_err(|_| "the archive made does not pass its format's check")?;
    Ok(m)
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
