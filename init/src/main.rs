//! The root task (component D01).
//!
//! The kernel starts this one program and gives it every capability there
//! is. It starts the programs in the ramdisk, each with the memory and
//! capabilities it is meant to have and no more, and takes back the memory
//! of every program that ends.
//!
//! At this stage of M2 it checks the round trips everything later rests
//! on: a program runs in its own address space and CapSpace, reports its
//! exit, and its memory comes back; two programs call each other through a
//! protocol. The service manager (D02) grows from here.
#![no_std]
#![no_main]

use libsys::root::{KIND_DEVICE, RootInfo, SLOT_DEVICES, SLOT_FIRST_UNTYPED, SLOT_INFO, SLOT_IRQS};
use libsys::{self as sys, ObjectType, Rights, Wait};
use silica_formats::ramdisk;
use silica_proc::root::{self, finish};
use silica_proc::{Grant, Program, spawn};
use silica_rt::alloc::vec::Vec;
use silica_rt::mem::Object;
use silica_rt::{EXIT_LABEL, println};

macro_rules! fail {
    ($($a:tt)*) => {{
        silica_rt::print!("ERROR: init: ");
        println!($($a)*);
        finish(false)
    }};
}

/// Program entry, called by libsys's `_start`.
// SAFETY: the one definition of the symbol `_start` calls.
#[unsafe(no_mangle)]
extern "C" fn silica_main(info: &'static RootInfo) -> ! {
    let root = match root::start(info) {
        Ok(r) => r,
        Err(e) => fail!("{e}"),
    };
    let (parent, archive) = (&root.parent, root.archive);

    let Some(image) = ramdisk::find(archive, "hello") else { fail!("the ramdisk has no program named hello") };
    // Twice: the second start must find all of the first one's memory back.
    for round in 0..2u64 {
        let child = match spawn(parent, &Program { args: [7 + round, 0, 0, 0, 0, 0, 0, 0], ..Program::new(image, 100 + round) }) {
            Ok(c) => c,
            Err(e) => fail!("cannot start hello: {e:?}"),
        };
        let Ok(m) = sys::recv(parent.exit, Wait::Until(silica_rt::clock().now() + 5_000_000_000)) else {
            fail!("hello did not report its exit within 5 s")
        };
        if m.info.label() != EXIT_LABEL || m.badge != 100 + round || m.words[0] != 7 + round {
            fail!("hello's exit message is not what it was started to send");
        }
        if child.destroy().is_err() {
            fail!("cannot take back hello's memory");
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
            fail!("the ramdisk lacks {server_name} or {client_name}")
        };
        let Ok(endpoint_object) = Object::new(ObjectType::Endpoint, 0) else { fail!("cannot create an endpoint for the echo programs") };
        let endpoint = endpoint_object.cap();
        let receive = Grant::lend(endpoint, Rights::READ);
        let send = Grant::badged(endpoint, Rights(Rights::WRITE.0 | Rights::GRANT.0), 7);
        let server = spawn(parent, &Program { grants: &[receive], ..Program::new(server_image, id) });
        let client = spawn(parent, &Program { grants: &[send], ..Program::new(client_image, id + 1) });
        let (Ok(server), Ok(client)) = (server, client) else { fail!("cannot start {server_name} and {client_name}") };
        let Ok(m) = sys::recv(parent.exit, Wait::Until(silica_rt::clock().now() + 10_000_000_000)) else {
            fail!("{client_name} did not finish within 10 s")
        };
        if m.badge != id + 1 || m.words[0] != 0 {
            fail!("program {} of the pair {server_name}, {client_name} exited with status {}", m.badge, m.words[0] as i64);
        }
        if client.destroy().is_err() || server.destroy().is_err() {
            fail!("cannot take back the echo programs' memory");
        }
        // SAFETY: the endpoint was made for this pair, which is gone.
        #[allow(unsafe_code)]
        unsafe {
            endpoint_object.destroy()
        };
        println!("init: {client_name} and {server_name} talked over sample.Echo; both are gone and their memory is back");
    }
    // The device manager: it is given the machine's description and every
    // device capability, and nothing of the machine's ordinary memory
    // beyond its own budget. Its one endpoint is made here, so that init
    // can hand out what clients call it through.
    let Some(image) = ramdisk::find(archive, "devmgr") else { fail!("the ramdisk has no program named devmgr") };
    let Ok(devmgr_ep) = Object::new(ObjectType::Endpoint, 0) else { fail!("cannot create the device manager's endpoint") };
    let mut grants = Vec::new();
    grants.push(Grant::lend(sys::Cap(SLOT_INFO), Rights::READ));
    grants.push(Grant::lend(sys::Cap(SLOT_DEVICES), Rights::ALL));
    grants.push(Grant::lend(sys::Cap(SLOT_IRQS), Rights::ALL));
    grants.push(if root.ports != sys::Cap::NONE { Grant::lend(root.ports, Rights::ALL) } else { Grant::none() });
    grants.push(Grant::lend(devmgr_ep.cap(), Rights::ALL));
    grants.extend(root.ramdisk.iter().map(|f| Grant::lend(*f, Rights::READ)));
    let frames = root.ramdisk.len() as u64;
    let device = info.untyped[..info.untyped_count as usize].iter().enumerate().filter(|(_, d)| d.kind == KIND_DEVICE);
    grants.extend(device.map(|(i, _)| Grant::give(sys::Cap(SLOT_FIRST_UNTYPED + i as u64))));
    let untypeds = grants.len() as u64 - 5 - frames;
    let program = Program {
        grants: &grants,
        args: [frames, untypeds, 0, 0, 0, 0, 0, 0],
        mem_bits: 26,
        space_bits: 13,
        aspace_bits: 18,
        ..Program::new(image, 300)
    };
    let _devmgr = match spawn(parent, &program) {
        Ok(c) => c,
        Err(e) => fail!("cannot start the device manager: {e:?}"),
    };

    // What init checks at boot (`checks=` on the command line, default all):
    // `block` runs blkcheck against the first disk.
    let cmdline = &info.cmdline[..(info.cmdline_len as usize).min(info.cmdline.len())];
    let checks = cmdline.split(|b| b.is_ascii_whitespace()).find_map(|w| w.strip_prefix(b"checks=")).unwrap_or(b"block");
    if checks.split(|b| *b == b',').any(|c| c == b"block") {
        let Some(image) = ramdisk::find(archive, "blkcheck") else { fail!("the ramdisk has no program named blkcheck") };
        // Clients of the device manager call with badges from 2^32 up.
        let devices = Grant::badged(devmgr_ep.cap(), Rights(Rights::WRITE.0 | Rights::GRANT.0), 1 << 32);
        let check = match spawn(parent, &Program { grants: &[devices], mem_bits: 23, ..Program::new(image, 400) }) {
            Ok(c) => c,
            Err(e) => fail!("cannot start blkcheck: {e:?}"),
        };
        let Ok(m) = sys::recv(parent.exit, Wait::Until(silica_rt::clock().now() + 60_000_000_000)) else {
            fail!("blkcheck did not finish within 60 s")
        };
        if m.badge != 400 || m.words[0] != 0 {
            fail!("program {} ended with status {} (400 is blkcheck, 300 the device manager)", m.badge, m.words[0] as i64);
        }
        if check.destroy().is_err() {
            fail!("cannot take back blkcheck's memory");
        }
        println!("init: blkcheck read and wrote the disk through the device manager and its driver");
        // `bench` on the command line: blkcheck's measurements are the
        // block benchmarks (tools/bench.sh reads them up to this line).
        if cmdline.split(|b| b.is_ascii_whitespace()).any(|w| w == b"bench") {
            println!("BENCH DONE");
        }
    } else {
        // No check to end the boot: the system stays up, and init reports
        // whatever of its programs ends.
        println!("BOOT OK");
        loop {
            if let Ok(m) = sys::recv(parent.exit, Wait::Forever) {
                println!("ERROR: init: program {} ended with status {}", m.badge, m.words[0] as i64);
            }
        }
    }
    println!("BOOT OK");
    // `halt=reboot` on the command line: reset the machine instead of
    // turning it off (the test of the reset path).
    if cmdline.split(|b| b.is_ascii_whitespace()).any(|w| w == b"halt=reboot") {
        let why = sys::reboot(sys::Cap(libsys::root::SLOT_POWER), 0);
        fail!("the machine cannot be reset: {why:?}");
    }
    finish(true)
}
