//! A client of the block path, from the outside: it finds a disk through
//! the device manager (its first grant, `silica.device.Manager`), connects
//! to its driver (`silica.block.Device`), and checks what a filesystem
//! will rely on:
//!
//! - the disk is what it says (sector 1 of a GPT disk begins `EFI PART`);
//! - a write is read back as written, and the block it replaced is put back;
//! - requests the driver must refuse are refused (blocks beyond the disk,
//!   data beyond its memory, memory never registered) and the connection
//!   still works after them;
//! - many requests in flight at once all complete, each with its own data.
//!
//! Then it measures: 4 KiB reads at queue depth 1 (latency) and 32
//! (throughput), printed as `BENCH` lines. It prints `TEST <name> PASS` for
//! each check (`<driver>.<check>`), for every disk the device manager
//! lists, and exits with status 0 when every one passed.
#![no_std]
#![no_main]

use silica_block::client::{Disk, Error};
use silica_block::{Op, Request, Status};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::mmio::Mmio;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

use silica_protocols::device::manager;

silica_rt::main!(main);

const SECOND: u64 = 1_000_000_000;

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            println!("ERROR: blkcheck: {e}");
            1
        }
    }
}

/// Every block device with a driver: its identity and its driver's name.
fn disks(devices: &mut manager::Client<Channel, Handle>) -> Result<Vec<(u32, silica_rt::alloc::string::String)>, &'static str> {
    // The device manager answers once it has started a driver for every
    // device it found; a disk may still be on its way when the first
    // answer comes, so an empty list is asked again for a while.
    let deadline = silica_rt::clock().now() + 10 * SECOND;
    loop {
        let listed = devices.list(manager::Class::Block).map_err(|e| why(e, "the device manager does not answer"))?;
        let found: Vec<_> = listed.devices.iter().map(|d| (d.id, silica_rt::alloc::string::String::from(d.driver))).collect();
        if !found.is_empty() {
            return Ok(found);
        }
        if silica_rt::clock().now() > deadline {
            return Err("no block device has a driver after 10 s");
        }
        silica_rt::sys::yield_now();
    }
}

/// Say what the error was, and return what failed.
fn why<E: core::fmt::Debug>(e: E, what: &'static str) -> &'static str {
    println!("blkcheck: {what}: {e:?}");
    what
}

fn run() -> Result<(), &'static str> {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT)));
    for (id, driver) in disks(&mut devices)? {
        println!("blkcheck: disk {id:#x}, driven by {driver}");
        let disk = Disk::open(Cap(slots::FIRST_GRANT), id).map_err(|e| why(e, "cannot open the disk"))?;
        // The gated block benchmarks are virtio-blk's (blk_*); another
        // driver's are named after it.
        let prefix = if driver == "virtio-blk" { "blk" } else { driver.as_str() };
        check(disk, &driver, prefix)?;
    }
    Ok(())
}

fn check(mut disk: Disk, driver: &str, prefix: &str) -> Result<(), &'static str> {
    let pass = |name: &str| println!("TEST {driver}.{name} PASS");
    let info = disk.info().clone();
    let bs = info.block_size as usize;
    println!("blkcheck: {} blocks of {} bytes{}", info.blocks, bs, if info.write_cache { ", write cache" } else { "" });
    // One megabyte the device reads and writes.
    let memory = Memory::new(20).map_err(|e| why(e, "no memory"))?;
    disk.add_memory(0, &memory, true).map_err(|e| why(e, "cannot register memory with the driver"))?;
    // SAFETY: the memory just made, this program's own and mapped for as
    // long as it runs; the device writes it, so it is read as registers are.
    #[allow(unsafe_code)]
    let m = unsafe { Mmio::new(memory.addr(), memory.len()) };
    let deadline = || Some(silica_rt::clock().now() + 5 * SECOND);
    let req = |op, block, offset, blocks, tag| Request { op, memory: 0, block, offset, blocks, tag };

    // The disk is what it says.
    disk.run(&req(Op::Read, 512 / bs as u64, 0, 1, 1), deadline()).map_err(|e| why(e, "reading the GPT header failed"))?;
    let off = 512 % bs;
    if m.read64(off) != u64::from_le_bytes(*b"EFI PART") {
        return Err("block 1 is not a GPT header");
    }
    pass("block_read");

    // A write reads back as written; then the old contents go back. The
    // block is in the middle of the disk (inside the ESP's free space on
    // the test image, and the image is booted as a snapshot anyway).
    let target = info.blocks / 2;
    disk.run(&req(Op::Read, target, 0, 1, 2), deadline()).map_err(|e| why(e, "reading the block to overwrite failed"))?;
    for i in (0..bs).step_by(8) {
        m.write64(bs + i, 0x5111_CA00_0000_0000 | i as u64);
    }
    disk.run(&req(Op::Write, target, bs as u32, 1, 3), deadline()).map_err(|e| why(e, "a write failed"))?;
    if info.write_cache {
        disk.run(&req(Op::Flush, 0, 0, 0, 4), deadline()).map_err(|e| why(e, "a flush failed"))?;
    }
    for i in (0..bs).step_by(8) {
        m.write64(2 * bs + i, 0);
    }
    disk.run(&req(Op::Read, target, 2 * bs as u32, 1, 5), deadline()).map_err(|e| why(e, "reading the written block failed"))?;
    if (0..bs).step_by(8).any(|i| m.read64(2 * bs + i) != 0x5111_CA00_0000_0000 | i as u64) {
        return Err("a written block reads back changed");
    }
    disk.run(&req(Op::Write, target, 0, 1, 6), deadline()).map_err(|e| why(e, "putting the block back failed"))?;
    pass("block_write_read_back");

    // What the driver must refuse, and the connection afterwards.
    let refused = [
        (req(Op::Read, info.blocks, 0, 1, 10), "a block beyond the disk"),
        (req(Op::Read, info.blocks - 1, 0, 2, 11), "a request running off the end of the disk"),
        (req(Op::Read, 0, (memory.len() - bs + 512) as u32, 1, 12), "data beyond the registered memory"),
        (Request { memory: 7, ..req(Op::Read, 0, 0, 1, 13) }, "memory that was never registered"),
        (req(Op::Read, 0, 0, 0, 14), "no blocks at all"),
    ];
    for (r, what) in refused {
        match disk.run(&r, deadline()) {
            Err(Error::Request(Status::Invalid)) => {}
            other => {
                println!("blkcheck: {what}: {other:?}");
                return Err("the driver did not refuse a request it must refuse");
            }
        }
    }
    disk.run(&req(Op::Read, 512 / bs as u64, 0, 1, 15), deadline()).map_err(|e| why(e, "the connection is broken after refusals"))?;
    pass("block_refusals");

    // Many in flight: 128 reads of different blocks into different places,
    // checked against reads of the same blocks one at a time.
    let n = 128usize.min(memory.len() / (2 * bs));
    for i in 0..n {
        disk.submit(&req(Op::Read, i as u64 * 7, (i * bs) as u32, 1, 1000 + i as u64)).map_err(|e| why(e, "the request ring is full"))?;
    }
    disk.kick();
    let mut seen = Vec::new();
    seen.resize(n, false);
    for _ in 0..n {
        let c = disk.wait(deadline()).map_err(|e| why(e, "a request in flight did not complete"))?;
        let i = c.tag.wrapping_sub(1000) as usize;
        if i >= n || seen[i] || c.status.is_err() {
            return Err("a completion is unknown, repeated or failed");
        }
        seen[i] = true;
    }
    let half = memory.len() / 2;
    for i in 0..n {
        disk.run(&req(Op::Read, i as u64 * 7, half as u32, 1, 2000 + i as u64), deadline()).map_err(|e| why(e, "a read failed"))?;
        if (0..bs).step_by(8).any(|o| m.read64(i * bs + o) != m.read64(half + o)) {
            return Err("a read in flight brought back another block's data");
        }
    }
    pass("block_in_flight");

    // Requests of many pages, starting part-way into a page: one write of
    // a pattern, read back a block at a time; one read of it, compared,
    // with the bytes after it untouched. Then the old contents go back, a
    // block at a time. (Single pages only would pass a driver whose
    // scatter lists are wrong.)
    let quarter = memory.len() / 4;
    let most = (info.max_blocks as usize).min((128 << 10) / bs);
    let target = info.blocks / 2 + 64;
    for (blocks, offset) in [(9usize.min(most), 3584usize), (most, 512)] {
        if blocks < 2 || target + blocks as u64 > info.blocks {
            continue;
        }
        let (save, pattern, back, single) = (0, quarter, 2 * quarter, 3 * quarter);
        let word = |j: usize, i: usize| 0xB10C_0000_0000_0000 | (blocks as u64) << 32 | (j * bs + i) as u64;
        // One block to or from `at`.
        let one = |disk: &mut Disk, op, block: u64, at: usize| disk.run(&req(op, block, at as u32, 1, 4000), deadline());
        for j in 0..blocks {
            one(&mut disk, Op::Read, target + j as u64, save + j * bs).map_err(|e| why(e, "saving a block failed"))?;
        }
        for j in 0..blocks {
            for i in (0..bs).step_by(8) {
                m.write64(pattern + offset + j * bs + i, word(j, i));
            }
        }
        disk.run(&req(Op::Write, target, (pattern + offset) as u32, blocks as u32, 4100), deadline())
            .map_err(|e| why(e, "a write of many pages failed"))?;
        if info.write_cache {
            disk.run(&req(Op::Flush, 0, 0, 0, 4101), deadline()).map_err(|e| why(e, "a flush failed"))?;
        }
        for j in 0..blocks {
            one(&mut disk, Op::Read, target + j as u64, single + j * bs).map_err(|e| why(e, "reading a block back failed"))?;
            if (0..bs).step_by(8).any(|i| m.read64(single + j * bs + i) != word(j, i)) {
                println!("blkcheck: {blocks} blocks from memory offset {offset}: block {j} reads back wrong");
                return Err("a write of many pages wrote the wrong data");
            }
        }
        let end = back + offset + blocks * bs;
        for i in (back..end + 512).step_by(8) {
            m.write64(i, 0xA5A5_A5A5_A5A5_A5A5);
        }
        disk.run(&req(Op::Read, target, (back + offset) as u32, blocks as u32, 4102), deadline())
            .map_err(|e| why(e, "a read of many pages failed"))?;
        for j in 0..blocks {
            if (0..bs).step_by(8).any(|i| m.read64(back + offset + j * bs + i) != word(j, i)) {
                println!("blkcheck: {blocks} blocks into memory offset {offset}: block {j} arrived wrong");
                return Err("a read of many pages brought back the wrong data");
            }
        }
        if (end..end + 512).step_by(8).any(|i| m.read64(i) != 0xA5A5_A5A5_A5A5_A5A5) {
            return Err("a read of many pages wrote past its end");
        }
        for j in 0..blocks {
            one(&mut disk, Op::Write, target + j as u64, save + j * bs).map_err(|e| why(e, "putting a block back failed"))?;
        }
    }
    pass("block_many_pages");

    // Measurements: 4 KiB reads spread over the first 4 MiB of the disk by
    // the sequence the Linux baseline uses (os/bench/linux/init.c), so both
    // read the same places of disks of different sizes.
    let blocks4k = (4096 / bs) as u32;
    let span = ((4u64 << 20) / bs as u64).min(info.blocks).saturating_sub(blocks4k as u64).max(1);
    let mut lat = Vec::new();
    let clock = silica_rt::clock();
    for i in 0..2000u64 {
        let block = (i * 2654435761) % span;
        let t = clock.now();
        disk.run(&req(Op::Read, block, 0, blocks4k, 3000 + i), deadline()).map_err(|e| why(e, "a measured read failed"))?;
        if i >= 200 {
            lat.push(clock.now() - t);
        }
    }
    lat.sort_unstable();
    println!("BENCH {prefix}_read4k_qd1 {} ns", lat[lat.len() / 2]);
    println!("BENCH {prefix}_read4k_qd1_p99 {} ns", lat[lat.len() * 99 / 100]);
    let (depth, total) = (32u64, 20000u64);
    let (mut sent, mut done) = (0u64, 0u64);
    let start = clock.now();
    while done < total {
        while sent < total && sent - done < depth {
            let block = (sent * 2654435761) % span;
            disk.submit(&req(Op::Read, block, ((sent % depth) * 4096) as u32, blocks4k, sent))
                .map_err(|e| why(e, "the request ring is full"))?;
            sent += 1;
        }
        disk.kick();
        let c = disk.wait(deadline()).map_err(|e| why(e, "a measured read did not complete"))?;
        if c.status.is_err() {
            return Err("a measured read failed");
        }
        done += 1;
    }
    let ns = clock.now() - start;
    println!("BENCH {prefix}_read4k_qd32 {} ops/s", total * SECOND / ns.max(1));
    Ok(())
}
