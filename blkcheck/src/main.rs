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
use silica_block::service::TRACED;
use silica_block::{Op, Request, Status};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

use silica_protocols::device::manager;

silica_rt::main!(main);

const SECOND: u64 = 1_000_000_000;

/// How long after boot the measurements start (monotonic nanoseconds).
const SETTLED: u64 = 500_000_000;

/// Wait until [`SETTLED`].
fn settle() {
    let Ok(n) = silica_rt::mem::Object::new(silica_rt::sys::ObjectType::Notification, 0) else { return };
    while silica_rt::clock().now() < SETTLED {
        let _ = silica_rt::sys::recv(n.cap(), silica_rt::sys::Wait::Until(SETTLED));
    }
}

/// Processors the machine has (from `ProcessInfo`).
static CPUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn main(info: &'static ProcessInfo) -> i64 {
    CPUS.store(info.cpus, core::sync::atomic::Ordering::Relaxed);
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

/// Make `writes` (just done) durable: a flush, and when the flush says
/// they may have been lost to a driver's restart (`Status::Lost`, the
/// block client's contract), the writes again and another flush. A disk
/// without a volatile cache needs nothing.
fn durable(disk: &mut Disk, writes: &[Request], tag: u64) -> Result<(), &'static str> {
    if !disk.info().write_cache {
        return Ok(());
    }
    let deadline = || Some(silica_rt::clock().now() + 5 * SECOND);
    let flush = Request { op: Op::Flush, memory: 0, block: 0, offset: 0, blocks: 0, tag };
    for _ in 0..4 {
        match disk.run(&flush, deadline()) {
            Err(Error::Request(Status::Lost)) => {
                println!("blkcheck: a flush says writes may have been lost to a driver's restart; writing them again");
                for w in writes {
                    disk.run(w, deadline()).map_err(|e| why(e, "writing again after a lost flush failed"))?;
                }
            }
            r => return r.map_err(|e| why(e, "a flush failed")),
        }
    }
    Err("four flushes in a row said writes were lost")
}

/// Say what the error was, and return what failed.
fn why<E: core::fmt::Debug>(e: E, what: &'static str) -> &'static str {
    println!("blkcheck: {what}: {e:?}");
    what
}

fn run() -> Result<(), &'static str> {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT)));
    let found = disks(&mut devices)?;
    for (id, driver) in found.iter().cloned() {
        println!("blkcheck: disk {id:#x}, driven by {driver}");
        let disk = Disk::open(Cap(slots::FIRST_GRANT), id).map_err(|e| why(e, "cannot open the disk"))?;
        // The gated block benchmarks are virtio-blk's (blk_*); another
        // driver's are named after it.
        let prefix = if driver == "virtio-blk" { "blk" } else { driver.as_str() };
        check(disk, &driver, prefix)?;
    }
    // After the disks' checks, so an injected fault lands where it did.
    hostile(&mut devices, found[0].0)?;
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
    // The device writes it, so it is read as registers are.
    let m = memory.shared();
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
    durable(&mut disk, &[req(Op::Write, target, bs as u32, 1, 3)], 4)?;
    for i in (0..bs).step_by(8) {
        m.write64(2 * bs + i, 0);
    }
    disk.run(&req(Op::Read, target, 2 * bs as u32, 1, 5), deadline()).map_err(|e| why(e, "reading the written block failed"))?;
    if (0..bs).step_by(8).any(|i| m.read64(2 * bs + i) != 0x5111_CA00_0000_0000 | i as u64) {
        return Err("a written block reads back changed");
    }
    disk.run(&req(Op::Write, target, 0, 1, 6), deadline()).map_err(|e| why(e, "putting the block back failed"))?;
    durable(&mut disk, &[req(Op::Write, target, 0, 1, 6)], 7)?;
    pass("block_write_read_back");

    // What the driver must refuse, and the connection afterwards.
    let refused = [
        (req(Op::Read, info.blocks, 0, 1, 10), "a block beyond the disk"),
        (req(Op::Read, info.blocks - 1, 0, 2, 11), "a request running off the end of the disk"),
        (req(Op::Read, 0, (memory.len() - bs + 512) as u32, 1, 12), "data beyond the registered memory"),
        (Request { memory: 7, ..req(Op::Read, 0, 0, 1, 13) }, "memory that was never registered"),
        (req(Op::Read, 0, 0, 0, 14), "no blocks at all"),
        (req(Op::Read, u64::MAX, 0, 2, 16), "a block range that overflows"),
        (req(Op::Read, 0, 0, info.max_blocks + 1, 17), "more blocks than one request may cover"),
        (req(Op::Read, 0, 100, 1, 18), "data at an offset that is not a multiple of 512"),
        (Request { memory: 1, ..req(Op::Read, 0, 0, 1, 19) }, "a read into memory registered read-only"),
    ];
    // Memory the device may read but not write: registered for a read
    // above, which must be refused.
    disk.add_memory(1, &memory, false).map_err(|e| why(e, "cannot register read-only memory"))?;
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
        durable(&mut disk, &[req(Op::Write, target, (pattern + offset) as u32, blocks as u32, 4100)], 4101)?;
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
        let back: Vec<Request> = (0..blocks).map(|j| req(Op::Write, target + j as u64, (save + j * bs) as u32, 1, 4000)).collect();
        durable(&mut disk, &back, 4103)?;
    }
    pass("block_many_pages");

    // Measurements: 4 KiB reads spread over the first 4 MiB of the disk by
    // the sequence the Linux baseline uses (os/bench/linux/init.c), so both
    // read the same places of disks of different sizes. They start once the
    // system is up (SETTLED after boot), as Linux's do (its benchmark is
    // all there is once it runs): measured during the boot, the reads share
    // processor 0 with the services and drivers still starting there, and a
    // tenth of a run's reads waited behind them (spec/ARCHITECTURE.md
    // section 7).
    settle();
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
    // Where the client waits from matters as much as what it does: from
    // each processor in turn, the median of 500 reads (not gated; what the
    // completion path costs across processors and on the driver's own).
    let cpus = CPUS.load(core::sync::atomic::Ordering::Relaxed).min(8) as usize;
    if cpus > 1 {
        let mut line = silica_rt::alloc::string::String::new();
        for cpu in 0..cpus {
            if silica_rt::sys::thread_set_cpu(slots::THREAD, cpu).is_err() {
                continue;
            }
            let mut by = Vec::new();
            for i in 0..600u64 {
                let block = (i * 2654435761) % span;
                let t = clock.now();
                disk.run(&req(Op::Read, block, 0, blocks4k, 9000 + i), deadline()).map_err(|e| why(e, "a read failed"))?;
                if i >= 100 {
                    by.push(clock.now() - t);
                }
            }
            by.sort_unstable();
            use core::fmt::Write;
            let _ = write!(line, " {cpu}:{}", by[by.len() / 2]);
        }
        let _ = silica_rt::sys::thread_set_cpu(slots::THREAD, 0);
        println!("blkcheck: depth-1 read median (ns) from each processor:{line}");
    }
    // Where a depth-1 read's time goes (not gated): the driver keeps a
    // traced request's times, read back after each read, outside its time.
    // Submit to the driver taking it (the client's wake-up of the driver),
    // to the device given it (the checks), to the driver seeing it done (the
    // device, its interrupt and the driver's wake-up), to the client back
    // (the completion, the client's wake-up and its return).
    let mut stages: [Vec<u64>; 4] = Default::default();
    for i in 0..300u64 {
        let block = (i * 2654435761) % span;
        let tag = TRACED | (20000 + i);
        let t = clock.now();
        disk.run(&req(Op::Read, block, 0, blocks4k, tag), deadline()).map_err(|e| why(e, "a traced read failed"))?;
        let back = clock.now();
        let (taken, started, done) = disk.trace(tag).map_err(|e| why(e, "the driver lost a traced read"))?;
        if i >= 50 && t <= taken && taken <= started && started <= done && done <= back {
            for (s, d) in stages.iter_mut().zip([taken - t, started - taken, done - started, back - done]) {
                s.push(d);
            }
        }
    }
    if stages[0].is_empty() {
        return Err("no traced read had its times in order");
    }
    for s in stages.iter_mut() {
        s.sort_unstable();
    }
    let m = |s: &Vec<u64>| s[s.len() / 2];
    println!(
        "blkcheck: depth-1 read stages, median ns of {}: to the driver {}, to the device {}, device to the driver {}, to the client {}",
        stages[0].len(),
        m(&stages[0]),
        m(&stages[1]),
        m(&stages[2]),
        m(&stages[3])
    );
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
        let c = disk.kick_wait(deadline()).map_err(|e| why(e, "a measured read did not complete"))?;
        if c.status.is_err() {
            return Err("a measured read failed");
        }
        done += 1;
    }
    let ns = clock.now() - start;
    println!("BENCH {prefix}_read4k_qd32 {} ops/s", total * SECOND / ns.max(1));
    // The connection goes, then the memory it reached comes back for the
    // next disk (a check of two disks ran out of it).
    drop(disk);
    // SAFETY: nothing refers to the memory now: the connection is gone.
    #[allow(unsafe_code)]
    unsafe {
        memory.free()
    };
    Ok(())
}

/// A capability derived from `cap` with `rights`, to give away.
fn lend(cap: Cap, rights: silica_rt::sys::Rights) -> Result<Handle, &'static str> {
    let slot = silica_rt::ipc::free_slot().ok_or("no capability slot")?;
    if silica_rt::sys::cap_derive(slots::SPACE, slot, cap, rights, 0).is_err() {
        silica_rt::ipc::release_slot(slot);
        return Err("cannot derive a capability");
    }
    Ok(Handle::new(Cap(slot)))
}

/// Clients that attack the drivers and the device manager through what
/// any client holds. Each prints `TEST hostile.<name> PASS`; a class with
/// no device is said and not tested.
fn hostile(devices: &mut manager::Client<Channel, Handle>, disk: u32) -> Result<(), &'static str> {
    use silica_rt::sys::{ObjectType, Rights};
    let pass = |name: &str| println!("TEST hostile.{name} PASS");
    let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
    let note = silica_rt::mem::Object::new(ObjectType::Notification, 0).map_err(|e| why(e, "no memory"))?;

    // The device manager keeps what a client gives it (a death notice with
    // each `open`, a notification with each `watch`): one per client and
    // device or class, so a client calling again and again, or a client
    // recovering in a loop, cannot use up its capability slots (8192), after
    // which nothing could be opened, watched or restarted.
    for n in 0..9000u32 {
        let gone = lend(note.cap(), Rights::WRITE)?;
        if let Err(e) = devices.open(disk, Some(gone)) {
            println!("blkcheck: open {n} with a death notice: {e:?}");
            return Err("the device manager stopped opening the disk for a client that opened it again and again");
        }
        let changed = lend(note.cap(), Rights::WRITE)?;
        let _ = devices.watch(manager::Class::Block, changed);
    }
    let mut again =
        Disk::open(Cap(slots::FIRST_GRANT), disk).map_err(|e| why(e, "after 9000 opens and watches, the disk cannot be opened"))?;
    let buffer = Memory::new(20).map_err(|e| why(e, "no memory"))?;
    again.add_memory(0, &buffer, true).map_err(|e| why(e, "cannot register memory"))?;
    let deadline = || Some(silica_rt::clock().now() + 5 * SECOND);
    again
        .run(&Request { op: Op::Read, memory: 0, block: 1, offset: 0, blocks: 1, tag: 1 }, deadline())
        .map_err(|e| why(e, "after 9000 opens and watches, a read failed"))?;
    pass("device_manager_bounded");

    // Memory registered and withdrawn again and again: the device's
    // addresses for it (and the IOMMU's tables under them) are reused. A
    // driver once took fresh addresses for each, from a range of 448 GiB:
    // some 114,000 registrations of 4 MiB used it up, and from then on no
    // client of that driver could register anything. `blkcheck.churn=`
    // says how many (the hostile machine's run: past that point).
    let cycles: u32 = silica_rt::option("churn").and_then(|n| n.parse().ok()).unwrap_or(5000);
    let churn = Memory::new(22).map_err(|e| why(e, "no memory"))?;
    again.add_memory(1, &churn, true).map_err(|e| why(e, "cannot register memory"))?;
    for n in 0..cycles {
        again.remove_memory(1).map_err(|e| why(e, "withdrawing memory failed"))?;
        if let Err(e) = again.add_memory(1, &churn, true) {
            println!("blkcheck: registration {n}: {e:?}");
            return Err("registering memory again and again used up the device's addresses");
        }
    }
    again.remove_memory(1).map_err(|e| why(e, "withdrawing memory failed"))?;
    println!("blkcheck: 4 MiB registered and withdrawn {cycles} times");
    // SAFETY: withdrawn: nothing refers to it.
    #[allow(unsafe_code)]
    unsafe {
        churn.free()
    };
    again
        .run(&Request { op: Op::Read, memory: 0, block: 1, offset: 0, blocks: 1, tag: 2 }, deadline())
        .map_err(|e| why(e, "after the registrations, a read failed"))?;
    pass("dma_churn");

    // A client that breaks its ring (takes the frame of its rings back)
    // while its requests are on the device: the driver must keep the
    // memory those requests use mapped until the device has finished
    // them. The device is shared with every other client; unmapped under
    // it, its writes fault (the harness requires no line of the kernel
    // refusing this device a write), and without an IOMMU they would land
    // in memory given to someone else by then.
    {
        let driver = devices.open(disk, None).map_err(|e| why(e, "cannot open the disk's driver"))?.driver;
        let mut control = silica_block::device::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
        let max = control.info().map_err(|e| why(e, "info failed"))?.info.max_blocks.min(2048);
        let rings = Memory::new(silica_queue::RINGS_BITS).map_err(|e| why(e, "no memory"))?;

        let wake = control
            .connect(lend(rings.frame(), rw)?, lend(note.cap(), Rights::WRITE)?)
            .map_err(|e| why(e, "a raw connection was refused"))?
            .requests;
        control.add_memory(0, lend(buffer.frame(), rw)?, true).map_err(|e| why(e, "registering memory on the raw connection failed"))?;
        let region = rings.shared();
        let mut requests = silica_rt::ring::Producer::<{ silica_queue::REQUEST_BYTES }>::new(
            region.part(0, silica_queue::COMPLETIONS_AT).ok_or("the ring frame is too small")?,
            silica_queue::QUEUE,
        )
        .ok_or("cannot lay the request ring out")?;
        for i in 0..32u64 {
            let r = Request { op: Op::Read, memory: 0, block: i * max as u64, offset: 0, blocks: max, tag: TRACED | (30000 + i) };
            requests.push(&r.encode()).map_err(|_| "the raw request ring is full")?;
        }
        let _ = silica_rt::sys::signal(wake.cap());
        // Once the driver has taken them, the ring goes.
        let until = silica_rt::clock().now() + 5 * SECOND;
        while control.trace(TRACED | 30031).map_or(true, |t| t.started == 0) {
            if silica_rt::clock().now() > until {
                return Err("the driver never took the raw connection's requests");
            }
            silica_rt::sys::yield_now();
        }
        // SAFETY: nothing of this program's refers to the rings any more.
        #[allow(unsafe_code)]
        unsafe {
            rings.free()
        };
        // The driver is woken at once: it finds the ring broken while
        // the device still works on the requests.
        let _ = silica_rt::sys::signal(wake.cap());
        println!("blkcheck: a client broke its ring with 32 requests of {} KiB on the device", max as u64 * 512 / 1024);
        // The driver goes on serving the others.
        let pause = silica_rt::clock().now() + 200_000_000;
        let _ = silica_rt::sys::recv(note.cap(), silica_rt::sys::Wait::Until(pause));
        again
            .run(&Request { op: Op::Read, memory: 0, block: 1, offset: 0, blocks: 1, tag: 3 }, deadline())
            .map_err(|e| why(e, "after a client broke its ring, another's read failed"))?;
    }
    pass("broken_ring_in_flight");

    // One client at a time on an input device, a console port and a display:
    // whoever holds a driver's endpoint cannot take over the keyboard, the
    // port's traffic or the screen from the client already there (the
    // console), which it once did unnoticed.
    let ring = Memory::new(12).map_err(|e| why(e, "no memory"))?;
    for (class, name) in [(manager::Class::Input, "input"), (manager::Class::Port, "port"), (manager::Class::Display, "display")] {
        let Some(id) = devices.list(class).ok().and_then(|r| r.devices.iter().next().map(|d| d.id)) else {
            println!("blkcheck: no {name} device; its takeover is not tried");
            continue;
        };
        let driver = devices.open(id, None).map_err(|e| why(e, "cannot open a device's driver"))?.driver;
        let channel = Channel::new(driver.cap());
        let took = match class {
            manager::Class::Input => {
                use silica_protocols::input::device;
                match device::Client::<Channel, Handle>::from(channel).connect(lend(ring.frame(), rw)?, lend(note.cap(), Rights::WRITE)?) {
                    Err(silica_idl_rt::CallError::Error(device::Error::InUse)) => false,
                    r => {
                        println!("blkcheck: connecting to the keyboard: {r:?}");
                        true
                    }
                }
            }
            manager::Class::Port => {
                use silica_protocols::console::port;
                match port::Client::<Channel, Handle>::from(channel).connect(lend(ring.frame(), rw)?, lend(note.cap(), Rights::WRITE)?) {
                    Err(silica_idl_rt::CallError::Error(port::Error::InUse)) => false,
                    r => {
                        println!("blkcheck: connecting to the console port: {r:?}");
                        true
                    }
                }
            }
            _ => {
                use silica_protocols::display::device;
                match device::Client::<Channel, Handle>::from(channel).attach(lend(ring.frame(), Rights::READ)?) {
                    Err(silica_idl_rt::CallError::Error(device::Error::InUse)) => false,
                    r => {
                        println!("blkcheck: attaching to the display: {r:?}");
                        true
                    }
                }
            }
        };
        if took {
            return Err("a second client took a device over from the one connected");
        }
        pass(&silica_rt::alloc::format!("takeover_{name}"));
    }
    Ok(())
}
