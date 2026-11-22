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
use silica_block::{Op, Request, Status};
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
    Ok(())
}
