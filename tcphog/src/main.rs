//! A hostile program of the network stack's (`silica.net.Tcp`), run as the
//! check `tcphog`: what one program must not be able to do to the others.
//!
//! - It opens connections, to an address on the link that never answers
//!   (each stays a handshake that is retried), until the stack refuses.
//!   A program has as many connections as the memory it lent pays for,
//!   one for every 64 KiB (what a connection costs the stack in buffers
//!   of its own), however small it cuts its blocks: before 2026-11-25
//!   one program took every place in the stack's table, then half of
//!   it whatever it lent. It lends 1 MiB and must be refused its 17th
//!   with `no_room`.
//! - It names blocks of the memory it lent that are not in it: at the top
//!   of the 64-bit range (where the end wraps past zero), past its end, and
//!   larger than all of it. Each must be refused as `bad_memory`, and the
//!   stack must still answer (one that checked the end with an addition
//!   that overflowed aborted, taking every connection on the machine).
//! - It listens on ports its capability does not carry (it is given
//!   `connect` alone): the remote service's, the web server's and one
//!   nobody holds. Each must be refused as `not_granted`.
//!
//! Says `tcphog: PASS` and exits 0, or says what went wrong and exits 1.
#![no_std]
#![no_main]

use silica_idl_rt::CallError;
use silica_protocols::net::tcp::{self as proto, Endpoint, Error};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::{Memory, Object};
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

/// What a connection costs the stack (netd's two buffers of 32 KiB), and
/// so how many this program's memory pays for.
const COST: usize = 64 << 10;
const SHARE: usize = (1 << MEMORY_BITS) / COST;
/// 10.0.2.99: on QEMU's user-mode link, nobody.
const NOBODY: Endpoint = Endpoint { address: 0x0A00_0263, port: 9 };
/// The memory lent, in blocks of 4 KiB.
const MEMORY_BITS: u8 = 20;
const BLOCK_BITS: u8 = 12;

fn lend(cap: Cap, rights: Rights, badge: u64) -> Option<Handle> {
    let slot = silica_rt::ipc::free_slot()?;
    if sys::cap_derive(slots::SPACE, slot, cap, rights, badge).is_err() {
        silica_rt::ipc::release_slot(slot);
        return None;
    }
    Some(Handle::new(Cap(slot)))
}

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => {
            println!("tcphog: PASS");
            0
        }
        Err(why) => {
            println!("ERROR: tcphog: {why}");
            1
        }
    }
}

fn run() -> Result<(), silica_rt::alloc::string::String> {
    use silica_rt::alloc::format;
    let mut stack = proto::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT)));
    let memory = Memory::new(MEMORY_BITS).map_err(|e| format!("no memory: {e:?}"))?;
    let note = Object::new(ObjectType::Notification, 0).map_err(|e| format!("no notification: {e:?}"))?;
    let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
    stack.add_memory(lend(memory.frame(), rw, 0).ok_or("no slot")?).map_err(|e| format!("add_memory: {e:?}"))?;
    // Its capability carries no port (`connect` alone). Before, any holder
    // took any port first come, first served (the remote service's, while it
    // started again). Naming one (the retired `listen`) is refused whatever
    // the port, and so is listening on the port its capability carries.
    for (port, whose) in [(22, "the remote service's"), (80, "the web server's"), (8080, "nobody's")] {
        let ready = lend(note.cap(), Rights::WRITE, 2).ok_or("no slot")?;
        match stack.listen(port, 1, ready) {
            Err(CallError::Error(Error::NotGranted)) => {}
            r => return Err(format!("naming port {port}, {whose}, to listen on: {r:?}, not not_granted")),
        }
    }
    let ready = lend(note.cap(), Rights::WRITE, 2).ok_or("no slot")?;
    match stack.listen_granted(ready) {
        Err(CallError::Error(Error::NotGranted)) => {}
        r => return Err(format!("listening with a capability that carries no port: {r:?}, not not_granted")),
    }
    // The retired backlog-taking listen is refused as well.
    let ready = lend(note.cap(), Rights::WRITE, 2).ok_or("no slot")?;
    match stack.listen_given(1, ready) {
        Err(CallError::Error(Error::NotGranted)) => {}
        r => return Err(format!("the retired listen_given: {r:?}, not not_granted")),
    }
    let connect = |stack: &mut proto::Client<Channel, Handle>, offset: u64, bits: u8| {
        let wake = lend(note.cap(), Rights::WRITE, 1).ok_or(CallError::Error(Error::NoRoom))?;
        stack.connect(NOBODY, offset, bits, wake).map(|r| r.connection)
    };
    // The first, once the stack has an address (DHCP may still be asking).
    let clock = silica_rt::clock();
    let until = clock.now() + 20_000_000_000;
    let first = loop {
        match connect(&mut stack, 0, BLOCK_BITS) {
            Ok(c) => break c,
            Err(CallError::Error(Error::NoAddress)) if clock.now() < until => {
                let _ = sys::recv(note.cap(), sys::Wait::Until(clock.now() + 100_000_000));
            }
            Err(e) => return Err(format!("the first connection: {e:?}")),
        }
    };
    let mut held = Vec::from([first]);
    let refusal = loop {
        let block = held.len() as u64;
        if block << BLOCK_BITS >= 1 << MEMORY_BITS {
            break None;
        }
        match connect(&mut stack, block << BLOCK_BITS, BLOCK_BITS) {
            Ok(c) => held.push(c),
            Err(e) => break Some(e),
        }
    };
    println!("tcphog: {} connections held, then {refusal:?}", held.len());
    if refusal != Some(CallError::Error(Error::NoRoom)) || held.len() != SHARE {
        return Err(format!(
            "a program that lent {} KiB held {} connections before it was refused ({refusal:?}); its memory pays for {SHARE}",
            (1 << MEMORY_BITS) >> 10,
            held.len()
        ));
    }
    // Room for the blocks below: one connection let go of.
    let last = held.pop().ok_or("none held")?;
    stack.close(last).map_err(|e| format!("close: {e:?}"))?;
    let top = !((1u64 << BLOCK_BITS) - 1);
    for (what, offset, bits) in [
        ("at the top of the range, its end wrapping past zero", top, BLOCK_BITS),
        ("the largest block at the top", !((1u64 << 24) - 1), 24),
        ("just past the memory lent", 1 << MEMORY_BITS, BLOCK_BITS),
        ("larger than the memory lent", 0, 24),
        ("overlapping a connection's", 0, BLOCK_BITS),
    ] {
        match connect(&mut stack, offset, bits) {
            Err(CallError::Error(Error::BadMemory)) => {}
            r => return Err(format!("a block {what} ({offset:#x}, 2^{bits} bytes): {r:?}, not bad_memory")),
        }
    }
    // The stack still answers, and takes a block that is right.
    let again = connect(&mut stack, (held.len() as u64) << BLOCK_BITS, BLOCK_BITS)
        .map_err(|e| format!("after the bad blocks, a good one: {e:?}"))?;
    held.push(again);
    for c in held {
        let _ = stack.close(c);
    }
    Ok(())
}
