//! Checks the block server (`silica.block.Partitions`) on the first
//! partition of the first disk, opened as a disk of its own
//! (`silica_block::client::Disk::open_partition`): its block 0 is the disk's
//! block where the partition starts (read through the whole disk too), it
//! says it has the partition's blocks, a request past its end is refused
//! (the driver enforces the capability's range), and a write to its last
//! block reads back through the whole disk at the right place (and is put
//! back). Prints `TEST partitions.<name> PASS` for each.
//!
//! Grants: 0 the device manager, 1 the block server.
#![no_std]
#![no_main]

use silica_block::client::{Disk, Error};
use silica_block::partitions;
use silica_block::service::TRACED;
use silica_block::{Op, Request, Status, device};
use silica_protocols::device::manager;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

const SECOND: u64 = 1_000_000_000;

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            println!("ERROR: partcheck: {e}");
            1
        }
    }
}

fn run() -> Result<(), &'static str> {
    let pass = |name: &str| println!("TEST partitions.{name} PASS");
    let devices = Cap(slots::FIRST_GRANT);
    let server = Cap(slots::FIRST_GRANT + 1);
    let mut list = partitions::Client::<Channel, Handle>::from(Channel::new(server));
    let listed = list.list().map_err(|_| "the block server does not answer")?;
    let Some(p) = listed.partitions.iter().next() else { return Err("the block server lists no partition") };
    let (id, disk_id, first, blocks) = (p.id, p.disk, p.first, p.blocks);
    println!("partcheck: partition {id:#x} of disk {disk_id:#x}: blocks {first} to {}, {} {}", first + blocks - 1, p.kind, p.name);
    let mut part = Disk::open_partition(server, id).map_err(|_| "the partition cannot be opened")?;
    let mut whole = Disk::open(devices, disk_id).map_err(|_| "the disk cannot be opened")?;
    let bs = part.info().block_size as usize;
    if part.info().blocks != blocks {
        println!("partcheck: the partition says {} blocks", part.info().blocks);
        return Err("the partition's size is not its table entry's");
    }
    pass("size");
    let memory = Memory::new(16).map_err(|_| "no memory")?;
    part.add_memory(0, &memory, true).map_err(|_| "cannot register memory for the partition")?;
    whole.add_memory(0, &memory, true).map_err(|_| "cannot register memory for the disk")?;
    let m = memory.shared();
    let deadline = || Some(silica_rt::clock().now() + 5 * SECOND);
    let req = |op, block, offset, n, tag| Request { op, memory: 0, block, offset, blocks: n, tag };
    // Block 0 of the partition is the disk's block `first`.
    part.run(&req(Op::Read, 0, 0, 1, 1), deadline()).map_err(|_| "reading the partition's block 0 failed")?;
    whole.run(&req(Op::Read, first, bs as u32, 1, 2), deadline()).map_err(|_| "reading the disk failed")?;
    if (0..bs).step_by(8).any(|i| m.read64(i) != m.read64(bs + i)) {
        return Err("the partition's block 0 is not the disk's block where it starts");
    }
    pass("offset");
    // Past its end, nothing.
    for (r, what) in [
        (req(Op::Read, blocks, 0, 1, 3), "its first block past the end"),
        (req(Op::Read, blocks - 1, 0, 2, 4), "a read running past the end"),
    ] {
        match part.run(&r, deadline()) {
            Err(Error::Request(Status::Invalid)) => {}
            other => {
                println!("partcheck: {what}: {other:?}");
                return Err("the partition reached past its end");
            }
        }
    }
    pass("confined");
    // A write to its last block lands on the disk's block first + blocks - 1.
    let last = blocks - 1;
    part.run(&req(Op::Read, last, 0, 1, 5), deadline()).map_err(|_| "reading the last block failed")?;
    for i in (0..bs).step_by(8) {
        m.write64(bs + i, 0x9A57_0000_0000_0000 | i as u64);
    }
    part.run(&req(Op::Write, last, bs as u32, 1, 6), deadline()).map_err(|_| "writing the last block failed")?;
    whole.run(&req(Op::Read, first + last, 2 * bs as u32, 1, 7), deadline()).map_err(|_| "reading it through the disk failed")?;
    let landed = (0..bs).step_by(8).all(|i| m.read64(2 * bs + i) == 0x9A57_0000_0000_0000 | i as u64);
    part.run(&req(Op::Write, last, 0, 1, 8), deadline()).map_err(|_| "putting the last block back failed")?;
    if !landed {
        return Err("a write to the partition did not land where it belongs on the disk");
    }
    pass("write");

    // What a capability's scopes allow (`silica_protocols::scope`): the
    // third grant may list partitions and not open them.
    let mut listing = partitions::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT + 2)));
    match listing.open(id, None) {
        Err(silica_idl_rt::CallError::Error(partitions::Error::Refused)) => {}
        Ok(_) => return Err("a capability given only `list` opened a partition"),
        Err(e) => {
            println!("partcheck: open through the list-only capability: {e:?}");
            return Err("open through the list-only capability failed otherwise than refused");
        }
    }
    if listing.list().map_or(true, |r| r.partitions.iter().next().is_none()) {
        return Err("the list-only capability lists nothing");
    }
    pass("scopes");

    // Opening a partition again and again (each open asks the driver to
    // narrow the disk's capability): the same range is the same window,
    // so the driver's windows are not used up (they were, at 256 opens).
    for n in 0..300 {
        if let Err(e) = list.open(id, None) {
            println!("partcheck: open {n} of the same partition: {e:?}");
            return Err("opening one partition again and again used up the driver's windows");
        }
    }
    pass("opens_bounded");

    // A partition's client narrowing its capability as often as it likes:
    // it gets a few windows under its own, and the disk's holders can
    // still narrow theirs (a client once used up every window there was,
    // and no partition could be opened after it).
    // The capability is kept while it is used: dropping it deletes it.
    let opened = list.open(id, None).map_err(|_| "the partition cannot be opened")?.device;
    let mut inside = device::Client::<Channel, Handle>::from(Channel::new(opened.cap()));
    let mut granted = 0;
    for i in 0..300u64 {
        if inside.narrow(i % blocks, 1).is_ok() {
            granted += 1;
        }
    }
    println!("partcheck: a partition's client asked for 300 windows under its own and was given {granted}");
    let mut devices_client = manager::Client::<Channel, Handle>::from(Channel::new(devices));
    let driver = devices_client.open(disk_id, None).map_err(|_| "the disk's driver cannot be opened")?.driver;
    let mut disk_control = device::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
    if let Err(e) = disk_control.narrow(first + blocks / 2, 7) {
        println!("partcheck: after a partition's client narrowed 300 times ({granted} granted), a new window of the disk: {e:?}");
        return Err("a partition's client narrowing used up the windows of the disk's other holders");
    }
    if granted > 4 {
        println!("partcheck: a partition's client was granted {granted} windows under its own");
        return Err("a partition's client is not bounded in the windows it makes");
    }
    pass("narrowing_bounded");

    // A flush through a partition reaches the device only when a write
    // needs it: one with nothing written since the last makes the device
    // do nothing (any partition's client could make the whole disk flush
    // at any rate). Traced (bit 62 of the tag), so the driver says whether
    // the device was given it.
    let flush = |tag| Request { op: Op::Flush, memory: 0, block: 0, offset: 0, blocks: 0, tag: TRACED | tag };
    if part.info().write_cache {
        part.run(&flush(20), deadline()).map_err(|_| "a flush failed")?;
        for tag in 21..31 {
            part.run(&flush(tag), deadline()).map_err(|_| "a flush failed")?;
            let (_, started, _) = part.trace(TRACED | tag).map_err(|_| "the driver lost a traced flush")?;
            if started != 0 {
                return Err("a flush with nothing written since the last made the device flush the whole disk");
            }
        }
        // And one after a write does reach it.
        part.run(&req(Op::Write, last, 0, 1, 31), deadline()).map_err(|_| "a write failed")?;
        part.run(&flush(32), deadline()).map_err(|_| "a flush after a write failed")?;
        let (_, started, _) = part.trace(TRACED | 32).map_err(|_| "the driver lost a traced flush")?;
        if started == 0 {
            return Err("a flush after a write did not reach the device");
        }
    }
    pass("flush_bounded");
    Ok(())
}
