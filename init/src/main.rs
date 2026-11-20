//! The root task (component D01).
//!
//! The kernel starts this one program and gives it every capability there
//! is. It maps the ramdisk, starts the programs in it, each with the memory
//! and capabilities it is meant to have and no more, and takes back the
//! memory of every program that ends.
//!
//! At this stage of M2 it starts `hello` and checks the whole round trip:
//! the program runs in its own address space and CapSpace, reports its
//! exit, and its memory comes back. The service manager (D02) grows from here.
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};
use libsys::root::{KIND_RAM, KIND_RAMDISK, RootInfo, SLOT_ASPACE, SLOT_CAPSPACE, SLOT_FIRST_UNTYPED, SLOT_PORTS};
use libsys::{self as sys, Cap, ObjectType, Rights, Wait};
use silica_formats::ramdisk;
use silica_proc::{Grant, Parent, spawn};
use silica_rt::{EXIT_LABEL, println};

const SPACE: Cap = Cap(SLOT_CAPSPACE);
const ASPACE: Cap = Cap(SLOT_ASPACE);
const PORTS: Cap = Cap(SLOT_PORTS);
/// The ramdisk is mapped at this address plus its physical address.
const RAMDISK_VADDR: usize = 0x40_0000_0000;
/// Where children's memory is filled in.
const SCRATCH_VADDR: usize = 0x50_0000_0000;

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);

fn free_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

/// Leave the emulator with a status (the debug-exit device), or stop.
fn finish(ok: bool) -> ! {
    let _ = sys::port_out(PORTS, 0xF4, 1, if ok { 0x10 } else { 0x11 });
    loop {
        let _ = sys::thread_suspend(Cap(libsys::root::SLOT_THREAD));
    }
}

fn fail(what: &str) -> ! {
    println!("ERROR: init: {what}");
    finish(false)
}

/// Map the ramdisk archive read-only and return it.
fn map_ramdisk(info: &'static RootInfo) -> &'static [u8] {
    let (base, len) = (info.ramdisk[0], info.ramdisk[1]);
    for i in 0..info.untyped_count as usize {
        let d = info.untyped[i];
        if d.kind != KIND_RAMDISK {
            continue;
        }
        let frame = Cap(free_slot());
        if sys::retype(Cap(SLOT_FIRST_UNTYPED + i as u64), ObjectType::Frame, d.bits, SPACE, frame.0, 1).is_err()
            || sys::map(ASPACE, frame, RAMDISK_VADDR + d.base as usize, Rights::READ).is_err()
        {
            fail("cannot map the ramdisk");
        }
    }
    // SAFETY: the frames covering [base, base + len) were just mapped
    // read-only at RAMDISK_VADDR + their physical address; nothing writes them.
    #[allow(unsafe_code)]
    unsafe {
        core::slice::from_raw_parts((RAMDISK_VADDR + base as usize) as *const u8, len as usize)
    }
}

/// Program entry, called by libsys's `_start`.
// SAFETY: the one definition of the symbol `_start` calls.
#[unsafe(no_mangle)]
extern "C" fn silica_main(info: &'static RootInfo) -> ! {
    silica_rt::init(PORTS, info.clock);
    if info.magic != libsys::root::ROOT_MAGIC {
        fail("the kernel's start-up record has the wrong magic");
    }
    NEXT_SLOT.store(info.first_free_slot, Ordering::Relaxed);
    let Some(memory) = (0..info.untyped_count as usize).filter(|&i| info.untyped[i].kind == KIND_RAM).max_by_key(|&i| info.untyped[i].bits)
    else {
        fail("the kernel handed over no memory")
    };
    let archive = map_ramdisk(info);

    // What children get of the serial port: its eight ports, nothing else.
    let debug = Cap(free_slot());
    let exit = Cap(free_slot());
    if sys::cap_derive(SPACE, debug.0, PORTS, Rights::ALL, 0x3F8 | 0x400 << 32).is_err()
        || sys::retype(Cap(SLOT_FIRST_UNTYPED + memory as u64), ObjectType::Endpoint, 0, SPACE, exit.0, 1).is_err()
    {
        fail("cannot create the exit endpoint");
    }
    let mut slot = free_slot;
    let mut parent = Parent {
        space: SPACE,
        aspace: ASPACE,
        untyped: Cap(SLOT_FIRST_UNTYPED + memory as u64),
        free_slot: &mut slot,
        scratch: SCRATCH_VADDR,
        exit,
        debug,
        cpus: info.cpus,
        clock: info.clock,
    };

    let Some(image) = ramdisk::find(archive, "hello") else { fail("the ramdisk has no program named hello") };
    // Twice: the second start must find all of the first one's memory back.
    for round in 0..2u64 {
        let child = match spawn(&mut parent, image, 22, 100 + round, &[], [7 + round, 0, 0, 0, 0, 0, 0, 0]) {
            Ok(c) => c,
            Err(e) => {
                println!("ERROR: init: cannot start hello: {e:?}");
                finish(false)
            }
        };
        let Ok(m) = sys::recv(exit, Wait::Until(silica_rt::clock().now() + 5_000_000_000)) else {
            fail("hello did not report its exit within 5 s")
        };
        if m.info.label() != EXIT_LABEL || m.badge != 100 + round || m.words[0] != 7 + round {
            fail("hello's exit message is not what it was started to send");
        }
        if child.destroy().is_err() {
            fail("cannot take back hello's memory");
        }
        println!("init: hello (id {}) exited with status {}; its memory is back", m.badge, m.words[0]);
    }
    // Two programs that talk: a provider of the sample.Echo protocol and a
    // client of it, connected by one endpoint. The provider may only
    // receive on it; the client may only send (and pass capabilities).
    // The first pair is the runtime's own; the second was written from the
    // published documentation alone and is kept exactly as it first built.
    for (n, (server_name, client_name)) in [("echo-server", "echo-client"), ("trial-server", "trial-client")].into_iter().enumerate() {
        let id = 200 + 2 * n as u64;
        let (Some(server_image), Some(client_image)) = (ramdisk::find(archive, server_name), ramdisk::find(archive, client_name)) else {
            println!("ERROR: init: the ramdisk lacks {server_name} or {client_name}");
            finish(false)
        };
        let endpoint = Cap((parent.free_slot)());
        if sys::retype(parent.untyped, ObjectType::Endpoint, 0, SPACE, endpoint.0, 1).is_err() {
            fail("cannot create an endpoint for the echo programs");
        }
        let receive = Grant { cap: endpoint, rights: Rights::READ, badge: 0 };
        let send = Grant { cap: endpoint, rights: Rights(Rights::WRITE.0 | Rights::GRANT.0), badge: 7 };
        let server = spawn(&mut parent, server_image, 22, id, &[receive], [0; 8]);
        let client = spawn(&mut parent, client_image, 22, id + 1, &[send], [0; 8]);
        let (Ok(server), Ok(client)) = (server, client) else {
            println!("ERROR: init: cannot start {server_name} and {client_name}");
            finish(false)
        };
        let Ok(m) = sys::recv(exit, Wait::Until(silica_rt::clock().now() + 10_000_000_000)) else {
            println!("ERROR: init: {client_name} did not finish within 10 s");
            finish(false)
        };
        if m.badge != id + 1 || m.words[0] != 0 {
            println!("ERROR: init: program {} of the pair {server_name}, {client_name} exited with status {}", m.badge, m.words[0] as i64);
            finish(false);
        }
        if client.destroy().is_err() || server.destroy().is_err() {
            fail("cannot take back the echo programs' memory");
        }
        println!("init: {client_name} and {server_name} talked over sample.Echo; both are gone and their memory is back");
    }
    println!("BOOT OK");
    finish(true)
}
