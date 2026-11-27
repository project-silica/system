//! Checks the block server (`silica.block.Partitions`) on the first
//! partition of the first disk, opened as a disk of its own
//! (`silica_block::client::Disk::open_partition`): its block 0 is the disk's
//! block where the partition starts (read through the whole disk too), it
//! says it has the partition's blocks, a request past its end is refused
//! (the driver enforces the capability's range), and a write to its last
//! block reads back through the whole disk at the right place (and is put
//! back). Prints `TEST partitions.<name> PASS` for each.
//!
//! Grants: 0 the device manager, 1 the block server, 2 the block server
//! (list only), 3 the device manager (list only).
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

/// Wait until the block server lists partitions (as many as
/// `partcheck.partitions=<n>` says, when it says), woken by the device
/// manager each time a disk gains or loses its driver (`watch` first, then
/// `list`, so no change between them is missed). The block server serves
/// from its start with the disks it has; a disk still on its way is the
/// client's to wait for, on the device manager's word. The bound is a
/// backstop: past it no disk came, which is this test's failure.
fn wait_for_partitions(devices: Cap, list: &mut partitions::Client<Channel, Handle>) -> Result<(), &'static str> {
    use silica_rt::sys::{self, ObjectType, Rights, Wait};
    let changed = silica_rt::mem::Object::new(ObjectType::Notification, 0).map_err(|_| "no memory for a notification")?;
    let slot = silica_rt::ipc::free_slot().ok_or("no free slot")?;
    sys::cap_derive(slots::SPACE, slot, changed.cap(), Rights::WRITE, 0).map_err(|_| "the notification cannot be lent")?;
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(devices));
    devices.watch(manager::Class::Block, Handle::new(Cap(slot))).map_err(|_| "the device manager does not answer a watch")?;
    let want = silica_rt::option("partitions").and_then(|n| n.parse::<u32>().ok());
    let deadline = silica_rt::clock().now() + 30 * SECOND;
    loop {
        let (mut n, mut from) = (0u32, 0);
        loop {
            let part = list.list(from).map_err(|_| "the block server does not answer")?;
            n += part.partitions.iter().count() as u32;
            if part.next == 0 || part.next <= from {
                break;
            }
            from = part.next;
        }
        if n > 0 && want.is_none_or(|w| n >= w) {
            return Ok(());
        }
        if sys::recv(changed.cap(), Wait::Until(deadline)).is_err() {
            println!("partcheck: {n} partitions listed after 30 s of the device manager's news");
            return Err("no disk with the partitions expected arrived");
        }
    }
}

fn run() -> Result<(), &'static str> {
    let pass = |name: &str| println!("TEST partitions.{name} PASS");
    let devices = Cap(slots::FIRST_GRANT);
    let server = Cap(slots::FIRST_GRANT + 1);
    let mut list = partitions::Client::<Channel, Handle>::from(Channel::new(server));
    wait_for_partitions(devices, &mut list)?;
    // Every partition of every disk, part after part: as many as the
    // machine's disks have (`partcheck.partitions=<n>` says how many to
    // expect: a disk with a full table of 128 is one before which the list
    // was refused to every caller, too long for one message).
    let (mut all, mut ids, mut from, mut parts) = (0u32, silica_rt::alloc::vec::Vec::new(), 0, 0);
    loop {
        let part = list.list(from).map_err(|_| "the block server does not answer")?;
        parts += 1;
        for p in part.partitions.iter() {
            all += 1;
            ids.push(p.id);
        }
        if part.next == 0 {
            break;
        }
        if part.next <= from {
            return Err("the block server's next part does not move on");
        }
        from = part.next;
    }
    ids.sort_unstable();
    ids.dedup();
    if ids.len() as u32 != all {
        return Err("the block server listed a partition twice");
    }
    if let Some(n) = silica_rt::option("partitions").and_then(|n| n.parse::<u32>().ok())
        && n != all
    {
        println!("partcheck: {all} partitions listed, {n} expected");
        return Err("the block server did not list every partition");
    }
    println!("partcheck: {all} partitions listed, in {parts} parts");
    pass("listed_whole");
    let listed = list.list(0).map_err(|_| "the block server does not answer")?;
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
    if listing.list(0).map_or(true, |r| r.partitions.iter().next().is_none()) {
        return Err("the list-only capability lists nothing");
    }
    pass("scopes");

    // The fourth grant may see the devices and not open them: it lists the
    // disk, and its open of the disk's driver is refused (a program that
    // only shows devices was given `open` of every class with `list`).
    let mut seeing = manager::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT + 3)));
    let seen = seeing.list(manager::Class::Block, 0).map_err(|_| "the device manager does not answer a list-only capability")?;
    if !seen.devices.iter().any(|d| d.id == disk_id) {
        return Err("a capability given `list` does not see the disk");
    }
    match seeing.open(disk_id, None) {
        Err(silica_idl_rt::CallError::Error(manager::Error::Refused)) => {}
        Ok(_) => return Err("a capability given only `list` opened a disk's driver"),
        Err(e) => {
            println!("partcheck: open through the list-only device capability: {e:?}");
            return Err("open through the list-only device capability failed otherwise than refused");
        }
    }
    pass("device_list");

    // Opening a partition again and again, each open let go of (each asks
    // the driver to narrow the disk's capability, a window of its own):
    // what was let go of is given back, so the windows are not used up
    // (they were, at 256 opens).
    for n in 0..300 {
        if let Err(e) = list.open(id, None) {
            println!("partcheck: open {n} of the same partition: {e:?}");
            return Err("opening one partition again and again used up the driver's windows");
        }
    }
    pass("opens_bounded");

    // A partition's client narrowing its capability as often as it likes,
    // holding every window it is given: it gets a few under its own, and
    // the disk's holders can still narrow theirs (a client once used up
    // every window there was, and no partition could be opened after it).
    // Windows it lets go of are its own to have again, so it holds them.
    // The capability is kept while it is used: dropping it deletes it.
    let opened = list.open(id, None).map_err(|_| "the partition cannot be opened")?.device;
    let mut inside = device::Client::<Channel, Handle>::from(Channel::new(opened.cap()));
    let mut kept = silica_rt::alloc::vec::Vec::new();
    for i in 0..300u64 {
        if let Ok(r) = inside.narrow(i % blocks, 1) {
            kept.push(r.device);
        }
    }
    let granted = kept.len();
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

    // Two openers of one partition are two holders: the second cannot
    // touch the first's connection, its memory or its traces (every holder
    // of a partition once shared one badge, so a second opener removed the
    // first's memory and read its traces, and could not connect at all).
    part.run(&req(Op::Read, 0, 0, 1, TRACED | 40), deadline()).map_err(|_| "a traced read failed")?;
    let second = list.open(id, None).map_err(|_| "the partition cannot be opened a second time")?.device;
    let mut other = device::Client::<Channel, Handle>::from(Channel::new(second.cap()));
    if other.remove_memory(0).is_ok() {
        return Err("a second opener of a partition removed the first opener's memory");
    }
    if other.trace(TRACED | 40).is_ok() {
        return Err("a second opener of a partition read the first opener's trace");
    }
    drop(second);
    part.run(&req(Op::Read, 0, 0, 1, 41), deadline()).map_err(|_| "the first opener's read failed after a second opener came")?;
    let mut again = Disk::open_partition(server, id).map_err(|_| "a second opener of a partition has no connection of its own")?;
    let memory2 = Memory::new(12).map_err(|_| "no memory")?;
    again.add_memory(0, &memory2, true).map_err(|_| "the second opener cannot register its memory")?;
    again.run(&req(Op::Read, 0, 0, 1, 42), deadline()).map_err(|_| "the second opener's read failed")?;
    part.run(&req(Op::Read, 0, 0, 1, 43), deadline()).map_err(|_| "the first opener's read failed beside a second")?;
    drop(again);
    pass("holders_apart");

    // A holder of the whole disk narrowing as many windows as it likes
    // takes none of anyone else's: the partition's holder reads on (the
    // oldest of 128 windows went for each new one, the partitions' first).
    let driver = devices_client.open(disk_id, None).map_err(|_| "the disk's driver cannot be opened")?.driver;
    let mut narrower = device::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
    let mut held = silica_rt::alloc::vec::Vec::new();
    for i in 0..200u64 {
        if let Ok(r) = narrower.narrow(first + i % blocks, 1 + i / blocks) {
            held.push(r.device);
        }
    }
    println!("partcheck: a holder of the disk asked for 200 windows and was given {}", held.len());
    part.run(&req(Op::Read, 0, 0, 1, 44), deadline())
        .map_err(|_| "a holder of the disk narrowing 200 windows took the partition's away")?;
    drop(held);
    drop(driver);
    pass("windows_kept");

    // A client opening the disk again and again (each open a capability of
    // its own, each connected) is refused past its own share, and what it
    // lets go of is its own again: its partition then connects. (The
    // other programs' side of this is `run_partitions_peers`: the shell
    // traces while this program holds all it may.)
    let mut opened_disks = silica_rt::alloc::vec::Vec::new();
    for _ in 0..40 {
        match Disk::open(devices, disk_id) {
            Ok(d) => opened_disks.push(d),
            Err(_) => break,
        }
    }
    println!("partcheck: a client opened and connected the disk {} times", opened_disks.len());
    if opened_disks.len() >= 40 {
        return Err("a client's connections to the driver are not bounded");
    }
    drop(opened_disks);
    let mut late = Disk::open_partition(server, id).map_err(|_| "a client's own connections, let go of, did not come back")?;
    late.add_memory(0, &memory2, true).map_err(|_| "the late partition cannot register its memory")?;
    late.run(&req(Op::Read, 0, 0, 1, 45), deadline()).map_err(|_| "the late partition's read failed")?;
    drop(late);
    pass("connections_bounded");

    // A partition opened and narrowed once, both let go of, again and again:
    // what was let go of comes back each time, the window under it with
    // the partition's (before, a window that ever had one under it was
    // never given back, and after 128 such opens no partition of the disk
    // could be opened until its driver started again).
    for n in 0..200 {
        let opened = list.open(id, None).map_err(|_| "opening a partition failed after others were opened, narrowed and let go of")?.device;
        let mut c = device::Client::<Channel, Handle>::from(Channel::new(opened.cap()));
        if let Err(e) = c.narrow(0, 1) {
            println!("partcheck: narrowing open {n}: {e:?}");
            return Err("narrowing a partition failed after others were opened, narrowed and let go of");
        }
    }
    let mut after =
        Disk::open_partition(server, id).map_err(|_| "a partition cannot be opened after others were narrowed and let go of")?;
    after.add_memory(0, &memory2, true).map_err(|_| "cannot register memory after others were narrowed and let go of")?;
    after.run(&req(Op::Read, 0, 0, 1, 46), deadline()).map_err(|_| "a read failed after others were narrowed and let go of")?;
    drop(after);
    pass("reclaimed_with_inner");

    // Asked to (`partcheck.hold=1`): hold all this program may of the disk
    // (partitions opened, connected, with memory, and windows) and wait to
    // be asked to end, while another program (the shell's `trace`, typed at
    // the console port) opens a partition of the same disk.
    if silica_rt::option("hold").is_some() {
        hold(server, devices, id, disk_id)?;
    }
    Ok(())
}

/// Hold all of the disk this program's share allows, say so, and wait to be
/// asked to end (`silica_rt::END`).
fn hold(server: Cap, devices: Cap, id: u32, disk_id: u32) -> Result<(), &'static str> {
    use silica_rt::sys::{self, Wait};
    let memory = Memory::new(12).map_err(|_| "no memory")?;
    let mut parts = silica_rt::alloc::vec::Vec::new();
    for _ in 0..64 {
        let Ok(mut p) = Disk::open_partition(server, id) else { break };
        let full = p.add_memory(0, &memory, true).is_err();
        parts.push(p);
        if full {
            break;
        }
    }
    let mut devices_client = manager::Client::<Channel, Handle>::from(Channel::new(devices));
    let driver = devices_client.open(disk_id, None).map_err(|_| "the disk's driver cannot be opened")?.driver;
    let mut whole = device::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
    let mut windows = silica_rt::alloc::vec::Vec::new();
    for i in 0..200u64 {
        let Ok(r) = whole.narrow(i, 1) else { break };
        windows.push(r.device);
    }
    println!("partcheck: holding {} partitions and {} windows", parts.len(), windows.len());
    loop {
        if sys::recv(slots::EVENTS, Wait::Forever).is_ok_and(|m| m.badge & silica_rt::END != 0) {
            return Ok(());
        }
    }
}
