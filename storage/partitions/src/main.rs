//! The block server (component F01): it provides `silica.block.Partitions`,
//! the partitions of every disk the device manager has a driver for, as
//! each disk's GPT describes them.
//!
//! It reads each table once, at start, through an ordinary connection to
//! the disk (checking both of the table's checksums: a table that does not
//! add up is reported and its disk offered whole only), and answers `open`
//! by asking the disk's driver for a capability that reaches the partition
//! alone (`silica.block.Device`'s `narrow`): requests then go from the
//! client to the driver directly. The client's death notice goes to the
//! device manager with its `open`, so a client hears of its driver's end
//! as one of a whole disk does.
//!
//! Grants: 0 its endpoint, 1 the device manager.
#![no_std]
#![no_main]

use ::partitions as gpt;
use silica_block::client::Disk;
use silica_block::device;
use silica_block::partitions::{self, Error, ListReply, OpenReply, Partition};
use silica_block::{Op, Request};
use silica_idl_rt::{Array, CapList};
use silica_protocols::device::manager;
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle, serve};
use silica_rt::mem::Memory;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

const SECOND: u64 = 1_000_000_000;
const ENDPOINT: Cap = Cap(slots::FIRST_GRANT);
const DEVICES: Cap = Cap(slots::FIRST_GRANT + 1);

/// A partition. The table is read once, at start: its strings are made
/// once and kept as long as the service runs.
struct Part {
    id: u32,
    disk: u32,
    first: u64,
    blocks: u64,
    kind: &'static str,
    name: &'static str,
}

struct Server {
    devices: manager::Client<Channel, Handle>,
    parts: Vec<Part>,
    listed: Vec<Partition<'static>>,
}

fn keep(s: String) -> &'static str {
    silica_rt::alloc::boxed::Box::leak(s.into_boxed_str())
}

/// The partitions of disk `id`, from its GPT.
fn table(id: u32) -> Result<Vec<Part>, &'static str> {
    let mut disk = Disk::open(DEVICES, id).map_err(|_| "it cannot be opened")?;
    let bs = disk.info().block_size as usize;
    let disk_blocks = disk.info().blocks;
    let memory = Memory::new(16).map_err(|_| "no memory")?;
    disk.add_memory(0, &memory, true).map_err(|_| "its driver takes no memory")?;
    let m = memory.shared();
    let read = |disk: &mut Disk, block: u64, blocks: u32| -> Result<Vec<u8>, &'static str> {
        let r = Request { op: Op::Read, memory: 0, block, offset: 0, blocks, tag: block };
        disk.run(&r, Some(silica_rt::clock().now() + 5 * SECOND)).map_err(|_| "a read failed")?;
        Ok((0..blocks as usize * bs).map(|i| m.read8(i)).collect())
    };
    let Some(header) = gpt::header(&read(&mut disk, 1, 1)?, disk_blocks)? else { return Ok(Vec::new()) };
    let blocks = header.entries_len().div_ceil(bs) as u32;
    if blocks as usize * bs > memory.len() {
        return Err("its GPT's entries do not fit the memory read into");
    }
    let entries = read(&mut disk, header.entries_at, blocks)?;
    let parts = gpt::entries(&header, &entries, |i, why| println!("partitions: disk {id:#x}: entry {i} left out: {why}"))?;
    // A partition is named by its disk and its index in a byte.
    for e in parts.iter().filter(|e| e.index > 0xFF) {
        println!("partitions: disk {id:#x}: entry {} left out: only the first 256 entries are numbered", e.index);
    }
    Ok(parts
        .into_iter()
        .filter(|e| e.index <= 0xFF)
        .map(|e| Part { id: id << 8 | e.index as u32, disk: id, first: e.first, blocks: e.blocks, kind: keep(e.kind), name: keep(e.name) })
        .collect())
}

impl partitions::Server<Handle> for Server {
    fn list<'a>(&'a mut self) -> ListReply<'a, Handle> {
        self.listed.clear();
        for p in &self.parts {
            self.listed.push(Partition { id: p.id, disk: p.disk, first: p.first, blocks: p.blocks, kind: p.kind, name: p.name });
        }
        ListReply { partitions: Array::new(&self.listed) }
    }

    fn open(&mut self, id: u32, gone: Option<Handle>) -> Result<OpenReply<Handle>, Error> {
        let p = self.parts.iter().find(|p| p.id == id).ok_or(Error::NoSuchPartition)?;
        let driver = self.devices.open(p.disk, gone).map_err(|_| Error::Gone)?.driver;
        let mut control = device::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
        let narrowed = control.narrow(p.first, p.blocks).map_err(|_| Error::Gone)?.device;
        Ok(OpenReply { device: narrowed })
    }
}

fn main(_info: &'static ProcessInfo) -> i64 {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(DEVICES));
    // The device manager answers once it has started a driver for every
    // device it found; a disk may still be on its way, so it is waited for
    // a while: told by the device manager (`watch`) when a disk gains a
    // driver, not asked again in a loop (on a machine with no disk that
    // spun a processor for the whole ten seconds).
    let deadline = silica_rt::clock().now() + 10 * SECOND;
    let changed = silica_rt::mem::Object::new(silica_rt::sys::ObjectType::Notification, 0).ok();
    if let Some(n) = &changed
        && let Some(slot) = silica_rt::ipc::free_slot()
    {
        if silica_rt::sys::cap_derive(slots::SPACE, slot, n.cap(), silica_rt::sys::Rights::WRITE, 0).is_ok() {
            let _ = devices.watch(manager::Class::Block, Handle::new(Cap(slot)));
        } else {
            silica_rt::ipc::release_slot(slot);
        }
    }
    let disks: Vec<u32> = loop {
        let found: Vec<u32> = devices.list(manager::Class::Block).map(|r| r.devices.iter().map(|d| d.id).collect()).unwrap_or_default();
        if !found.is_empty() || silica_rt::clock().now() > deadline {
            break found;
        }
        match &changed {
            Some(n) => {
                let _ = silica_rt::sys::recv(n.cap(), silica_rt::sys::Wait::Until(deadline));
            }
            None => silica_rt::sys::yield_now(),
        }
    };
    let mut parts = Vec::new();
    for id in disks {
        match table(id) {
            Ok(t) => {
                println!("partitions: disk {id:#x}: {} partitions", t.len());
                parts.extend(t);
            }
            Err(e) => println!("partitions: disk {id:#x}: {e}; offered whole only"),
        }
    }
    let mut server = Server { devices, parts, listed: Vec::new() };
    serve(ENDPOINT, |_badge, request, caps: CapList<Handle>, reply, reply_caps| {
        partitions::dispatch(&mut server, request, caps, reply, reply_caps)
    })
}
