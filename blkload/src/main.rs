//! The block path under load while its driver is killed (the M3 exit
//! test's recovery item, `spec/MILESTONES.md`).
//!
//! It finds the scratch disk (a block device whose block 1 is not a GPT
//! header: the test machine's second disk), and writes every one of its
//! first [`BLOCKS`] blocks [`ROUNDS`] times, in a scattered order, [`DEPTH`] at a time,
//! with a flush after every [`FLUSH_EVERY`] completed writes, while asking
//! the device manager to restart the disk's driver every [`KILL_EVERY_NS`]
//! (an abrupt end: its memory, its capabilities and its device's view of
//! memory are taken away at once). It reports how long each recovery took,
//! from the driver's end to the first completion after it, and fails if one
//! took longer than [`RECOVERY_NS`]. Block `b` ends holding the 64-bit
//! words `ROUNDS << 40 | b << 16 | i` (each round writes its own number),
//! so the host can check after the run that the last write of every block
//! is on the disk and no older one came back (`tools/test.sh`'s recovery
//! run reads the image).
#![no_std]
#![no_main]

use silica_block::client::Disk;
use silica_block::{Op, Request};
use silica_protocols::device::manager;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::mmio::Mmio;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

/// Blocks written (of 512 bytes), and how many times each.
const BLOCKS: u64 = 16384;
const ROUNDS: u64 = 4;
const DEPTH: u64 = 32;
const FLUSH_EVERY: u64 = 256;
const KILL_EVERY_NS: u64 = 200_000_000;
/// The longest a recovery may take.
const RECOVERY_NS: u64 = 250_000_000;
const SECOND: u64 = 1_000_000_000;

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            println!("ERROR: blkload: {e}");
            1
        }
    }
}

/// The scratch disk: the block device whose block 1 is not a GPT header.
fn scratch(devices: &mut manager::Client<Channel, Handle>, buffer: &Memory, m: Mmio) -> Result<(u32, Disk), &'static str> {
    let listed: Vec<u32> =
        devices.list(manager::Class::Block).map_err(|_| "the device manager does not answer")?.devices.iter().map(|d| d.id).collect();
    for id in listed {
        let mut disk = Disk::open(Cap(slots::FIRST_GRANT), id).map_err(|_| "cannot open a disk")?;
        disk.add_memory(0, buffer, true).map_err(|_| "cannot register memory")?;
        let deadline = Some(silica_rt::clock().now() + 5 * SECOND);
        disk.run(&Request { op: Op::Read, memory: 0, block: 1, offset: 0, blocks: 1, tag: 0 }, deadline)
            .map_err(|_| "cannot read a disk")?;
        if m.read64(0) != u64::from_le_bytes(*b"EFI PART") && disk.info().blocks >= BLOCKS && disk.info().block_size == 512 {
            return Ok((id, disk));
        }
    }
    Err("no scratch disk (a second disk without a GPT header, of 8 MiB or more)")
}

fn run() -> Result<(), &'static str> {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT)));
    let buffer = Memory::new(20).map_err(|_| "no memory")?;
    // The device reads and writes it, so it is used as registers are.
    let m = buffer.shared();
    let (id, mut disk) = scratch(&mut devices, &buffer, m)?;
    println!("blkload: scratch disk {id:#x}, {} blocks", disk.info().blocks);
    // Leave an acknowledged device write in the completion ring across
    // restart. Its buffer is withdrawn before the ring is read: only the
    // original result can succeed, since a replay has no registered frame.
    let tag = silica_block::service::TRACED;
    disk.submit(&Request { op: Op::Write, memory: 0, block: 0, offset: 0, blocks: 1, tag })
        .map_err(|_| "cannot submit the traced write")?;
    disk.kick();
    let clock = silica_rt::clock();
    let until = clock.now() + 5 * SECOND;
    loop {
        if disk.trace(tag).is_ok_and(|(_, _, done)| done != 0) {
            break;
        }
        if clock.now() >= until {
            return Err("the driver did not report completing the traced write");
        }
        silica_rt::sys::yield_now();
    }
    devices.restart(id).map_err(|_| "cannot restart after the traced write")?;
    disk.remove_memory(0).map_err(|_| "cannot withdraw the traced write's buffer")?;
    let completed = disk.wait(Some(clock.now() + 5 * SECOND)).map_err(|_| "lost the traced write's completion")?;
    if completed.tag != tag || completed.status.is_err() {
        return Err("the client lost a successful write completion across restart");
    }
    disk.add_memory(0, &buffer, true).map_err(|_| "cannot register the load buffer again")?;
    disk.run(&Request { op: Op::Read, memory: 0, block: 0, offset: 0, blocks: 1, tag: 0 }, Some(clock.now() + 5 * SECOND))
        .map_err(|_| "the replacement driver did not serve the next read")?;
    // A write done and not flushed when the driver ends: the next driver
    // resets the device, whose volatile cache need not keep it, so the
    // next flush must say so (`Status::Lost`) rather than succeed, and
    // the one after it, with nothing lost since, succeeds.
    let flush = Request { op: Op::Flush, memory: 0, block: 0, offset: 0, blocks: 0, tag: 0 };
    // What the restart above left unflushed is reported first, if anything.
    match disk.run(&flush, Some(clock.now() + 5 * SECOND)) {
        Ok(()) | Err(silica_block::client::Error::Request(silica_block::Status::Lost)) => {}
        Err(_) => return Err("the flush after the traced write's restart failed"),
    }
    disk.run(&Request { op: Op::Write, memory: 0, block: 2, offset: 0, blocks: 1, tag: 1 }, Some(clock.now() + 5 * SECOND))
        .map_err(|_| "the write before the unflushed restart failed")?;
    devices.restart(id).map_err(|_| "cannot restart after the unflushed write")?;
    match disk.run(&flush, Some(clock.now() + 5 * SECOND)) {
        Err(silica_block::client::Error::Request(silica_block::Status::Lost)) => {}
        Ok(()) => return Err("a flush after a driver ended with an unflushed write said it was durable"),
        Err(_) => return Err("the flush after the unflushed restart failed"),
    }
    disk.run(&flush, Some(clock.now() + 5 * SECOND)).map_err(|_| "the flush after the lost one did not succeed")?;
    println!("blkload: a driver's end after an unflushed write is reported by the next flush");
    disk.take_recovery();
    // Each slot of the buffer holds one write's data while it is in flight.
    let fill = |slot: u64, round: u64, block: u64| {
        for i in 0..64u64 {
            m.write64((slot * 512 + i * 8) as usize, round << 40 | block << 16 | i);
        }
    };
    let (start, mut next_kill) = (clock.now(), clock.now() + KILL_EVERY_NS);
    let (mut sent, mut done, mut since_flush, mut kills) = (0u64, 0u64, 0u64, 0u32);
    let mut rewrites = 0u64;
    let mut recoveries = Vec::new();
    let mut flushing = false;
    // Where the writes the last successful flush made durable end: a lost
    // flush sends everything after it again.
    let mut durable = 0u64;
    // A slot is free when no write in flight uses it.
    let mut free: Vec<u64> = (0..DEPTH).collect();
    let mut slot_of = silica_rt::alloc::collections::BTreeMap::new();
    let total = BLOCKS * ROUNDS;
    while done < total || flushing {
        // A round's writes all complete and are flushed before the next
        // round's start, so a block's rounds never race each other.
        while sent < total
            && !flushing
            && sent / BLOCKS <= done / BLOCKS
            && let Some(slot) = free.pop()
        {
            // A scattered order: every block once a round (BLOCKS is a power of two).
            let block = (sent * 7919) % BLOCKS;
            fill(slot, sent / BLOCKS + 1, block);
            let tag = sent + 1;
            slot_of.insert(tag, slot);
            disk.submit(&Request { op: Op::Write, memory: 0, block, offset: (slot * 512) as u32, blocks: 1, tag })
                .map_err(|_| "a write could not be submitted")?;
            sent += 1;
        }
        disk.kick();
        if clock.now() >= next_kill && kills < 10 {
            // The driver ends now, with writes in flight.
            devices.restart(id).map_err(|_| "the device manager would not restart the driver")?;
            kills += 1;
            next_kill = clock.now() + KILL_EVERY_NS;
        }
        let c = disk.wait(Some(clock.now() + 5 * SECOND)).map_err(|e| {
            println!("blkload: waiting: {e:?}");
            "a request did not complete"
        })?;
        if let Some(r) = disk.take_recovery() {
            recoveries.push(r.total);
        }
        if c.tag == 0 && c.status == Err(silica_block::Status::Lost) {
            // A driver ended with writes not yet durable: write them again.
            rewrites += sent - durable;
            (sent, done, since_flush, flushing) = (durable, durable, 0, false);
            continue;
        }
        if c.status.is_err() {
            println!("blkload: request {} failed: {:?}", c.tag, c.status);
            return Err("a request failed");
        }
        if c.tag == 0 {
            flushing = false;
            durable = sent;
            since_flush = 0;
            continue;
        }
        done += 1;
        since_flush += 1;
        free.extend(slot_of.remove(&c.tag));
        if since_flush >= FLUSH_EVERY || done % BLOCKS == 0 {
            // Everything completed so far becomes durable with this.
            while disk.in_progress() != 0 {
                let c = disk.wait(Some(clock.now() + 5 * SECOND)).map_err(|_| "a request did not complete")?;
                if c.status.is_err() {
                    return Err("a request failed");
                }
                if let Some(r) = disk.take_recovery() {
                    recoveries.push(r.total);
                }
                done += 1;
                free.extend(slot_of.remove(&c.tag));
            }
            disk.submit(&Request { op: Op::Flush, memory: 0, block: 0, offset: 0, blocks: 0, tag: 0 })
                .map_err(|_| "a flush could not be submitted")?;
            flushing = true;
        }
    }
    let worst = recoveries.iter().copied().max().unwrap_or(0);
    println!(
        "blkload: {BLOCKS} blocks written {ROUNDS} times and flushed in {} ms, the driver killed {kills} times; recoveries (us): {:?}",
        (clock.now() - start) / 1_000_000,
        recoveries.iter().map(|r| r / 1000).collect::<Vec<_>>()
    );
    // Every kill must have happened, under load, and been recovered from:
    // one kill was once enough to pass.
    if kills < 10 || recoveries.len() < kills as usize {
        return Err("the driver was not killed while writes were in flight");
    }
    if worst > RECOVERY_NS {
        return Err("a recovery took longer than 250 ms");
    }
    // What is on the disk now: every block's last round, word by word.
    verify(&mut disk, m)?;
    println!("blkload: {rewrites} writes sent again after lost flushes; every block reads back its last round");
    println!("BENCH blk_recovery_max {} us", worst / 1000);
    println!("BLKLOAD OK");
    Ok(())
}

/// Read every block back and check it holds its last round's words.
fn verify(disk: &mut Disk, m: Mmio) -> Result<(), &'static str> {
    let clock = silica_rt::clock();
    // As many blocks as one request and the 1 MiB buffer take.
    let per_read = (disk.info().max_blocks as u64).min(2048);
    for at in (0..BLOCKS).step_by(per_read as usize) {
        let r = Request { op: Op::Read, memory: 0, block: at, offset: 0, blocks: per_read.min(BLOCKS - at) as u32, tag: 0 };
        disk.run(&r, Some(clock.now() + 5 * SECOND)).map_err(|_| "reading the disk back failed")?;
        for b in 0..per_read.min(BLOCKS - at) {
            for i in 0..64u64 {
                if m.read64((b * 512 + i * 8) as usize) != ROUNDS << 40 | (at + b) << 16 | i {
                    println!("blkload: block {} word {i} reads {:#x}", at + b, m.read64((b * 512 + i * 8) as usize));
                    return Err("a block does not hold its last write");
                }
            }
        }
    }
    Ok(())
}
