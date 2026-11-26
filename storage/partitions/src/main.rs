//! The block server (component F01): it provides `silica.block.Partitions`,
//! the partitions of every disk the device manager has a driver for, as
//! each disk's GPT describes them.
//!
//! It reads each disk's table through an ordinary connection to the disk
//! (checking both of the table's checksums: a table that does not add up
//! is reported and its disk offered whole only), and reads them all again
//! whenever the device manager says a disk gained or lost its driver
//! (`watch`), before it next answers: a disk added later gets its
//! partitions, and a disk swapped for another under the same identity is
//! never narrowed with the old disk's ranges (one whose table cannot be
//! read then is offered no partitions until it can). It answers `open`
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
use silica_protocols::{paging, scope};
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

/// A partition. Its strings are made when its table is read and kept as
/// long as the service runs (a table read again makes new ones).
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
    /// Signalled when a disk gains or loses its driver (`None`: the device
    /// manager could not be asked to): the tables are read again.
    changed: Option<silica_rt::mem::Object>,
    /// Disks whose table could not be read.
    unread: Vec<u32>,
    /// Every name and kind kept (`keep`).
    names: Vec<&'static str>,
    /// The badge of the call being answered: its scopes
    /// (`silica_protocols::scope`).
    caller: u64,
}

/// `s` as a string kept for as long as the service runs: the one kept
/// already if an equal one was (`names`), so reading tables again keeps
/// nothing new for names it has seen.
fn keep(names: &mut Vec<&'static str>, s: String) -> &'static str {
    if let Some(k) = names.iter().find(|k| **k == s) {
        return k;
    }
    let k: &'static str = silica_rt::alloc::boxed::Box::leak(s.into_boxed_str());
    names.push(k);
    k
}

/// The partitions of disk `id`, from its GPT.
fn table(id: u32, names: &mut Vec<&'static str>) -> Result<Vec<Part>, &'static str> {
    let mut disk = Disk::open(DEVICES, id).map_err(|_| "it cannot be opened")?;
    let bs = disk.info().block_size as usize;
    let disk_blocks = disk.info().blocks;
    let memory = Memory::new(16).map_err(|_| "no memory")?;
    let max_blocks = memory.len().checked_div(bs).unwrap_or(0).min(disk.info().max_blocks as usize);
    if max_blocks == 0 {
        return Err("its transfer limits do not allow a block to be read");
    }
    disk.add_memory(0, &memory, true).map_err(|_| "its driver takes no memory")?;
    let m = memory.shared();
    let read = |disk: &mut Disk, mut block: u64, bytes: usize| -> Result<Vec<u8>, &'static str> {
        if block.checked_add(bytes.div_ceil(bs) as u64).is_none_or(|end| end > disk_blocks) {
            return Err("its GPT read would extend beyond the disk");
        }
        let mut data = Vec::new();
        data.try_reserve_exact(bytes).map_err(|_| "no memory for its GPT")?;
        while data.len() < bytes {
            let left = bytes - data.len();
            let blocks = left.div_ceil(bs).min(max_blocks);
            let r = Request { op: Op::Read, memory: 0, block, offset: 0, blocks: blocks as u32, tag: block };
            disk.run(&r, Some(silica_rt::clock().now() + 5 * SECOND)).map_err(|_| "a read failed")?;
            data.extend((0..left.min(blocks * bs)).map(|i| m.read8(i)));
            block += blocks as u64;
        }
        Ok(data)
    };
    // The table from one copy of the header: `Ok(None)` when that copy is
    // not there at all.
    let copy = |disk: &mut Disk, at: u64| -> Result<Option<Vec<gpt::Entry>>, &'static str> {
        let Some(header) = gpt::header_at(&read(disk, at, bs)?, disk_blocks, at)? else { return Ok(None) };
        let entries = read(disk, header.entries_at, header.entries_len())?;
        gpt::entries(&header, &entries, |i, why| println!("partitions: disk {id:#x}: entry {i} left out: {why}")).map(Some)
    };
    // The primary copy, else the backup at the disk's last block (a torn
    // write or a damaged first block leaves the backup whole: the table is
    // there twice for this).
    let parts = match copy(&mut disk, 1) {
        Ok(Some(p)) => p,
        primary => match copy(&mut disk, disk_blocks.saturating_sub(1).max(1)) {
            Ok(Some(p)) => {
                let why = primary.err().unwrap_or("it has no primary GPT header");
                println!("partitions: disk {id:#x}: {why}; its backup GPT is used");
                p
            }
            Ok(None) => return primary.map(|_| Vec::new()),
            Err(_) => return primary.map(|_| Vec::new()),
        },
    };
    // A partition is named by its disk and its index in a byte.
    for e in parts.iter().filter(|e| e.index > 0xFF) {
        println!("partitions: disk {id:#x}: entry {} left out: only the first 256 entries are numbered", e.index);
    }
    Ok(parts
        .into_iter()
        .filter(|e| e.index <= 0xFF)
        .map(|e| Part {
            id: id << 8 | e.index as u32,
            disk: id,
            first: e.first,
            blocks: e.blocks,
            kind: keep(names, e.kind),
            name: keep(names, e.name),
        })
        .collect())
}

impl Server {
    /// Read every disk's table again if a disk gained or lost its driver
    /// since they were read.
    fn refresh(&mut self) {
        let Some(n) = &self.changed else { return };
        if silica_rt::sys::recv(n.cap(), silica_rt::sys::Wait::Poll).is_err() {
            return;
        }
        let disks: Vec<u32> = block_disks(&mut self.devices);
        (self.parts, self.unread) = read_tables(&disks, &mut self.names);
    }
}

/// Every block device that has a driver, part after part (`from` and
/// `next`); none when the device manager does not answer.
fn block_disks(devices: &mut manager::Client<Channel, Handle>) -> Vec<u32> {
    let (mut disks, mut from) = (Vec::new(), 0);
    while let Ok(r) = devices.list(manager::Class::Block, from) {
        disks.extend(r.devices.iter().map(|d| d.id));
        if r.next == 0 || r.next <= from {
            break;
        }
        from = r.next;
    }
    disks
}

/// The partitions of disks `disks`, each disk's table read now, and the
/// disks whose table could not be read.
fn read_tables(disks: &[u32], names: &mut Vec<&'static str>) -> (Vec<Part>, Vec<u32>) {
    let mut parts = Vec::new();
    let mut unread = Vec::new();
    for &id in disks {
        match table(id, names) {
            Ok(t) => {
                println!("partitions: disk {id:#x}: {} partitions", t.len());
                parts.extend(t);
            }
            Err(e) => {
                println!("partitions: disk {id:#x}: {e}; offered whole only");
                unread.push(id);
            }
        }
    }
    (parts, unread)
}

impl partitions::Server<Handle> for Server {
    fn list<'a>(&'a mut self, from: u32) -> ListReply<'a, Handle> {
        self.refresh();
        self.listed.clear();
        // Nothing to a caller not given `list`.
        if !scope::has(self.caller, scope::PARTITIONS_LIST) {
            return ListReply { partitions: Array::new(&self.listed), next: 0 };
        }
        let listed = &mut self.listed;
        let next = paging::part(
            &self.parts,
            from,
            |p| paging::record(4 + 4 + 8 + 8 + paging::text(p.kind.len()) + paging::text(p.name.len())),
            |p| listed.push(Partition { id: p.id, disk: p.disk, first: p.first, blocks: p.blocks, kind: p.kind, name: p.name }),
        );
        ListReply { partitions: Array::new(&self.listed), next }
    }

    fn open(&mut self, id: u32, gone: Option<Handle>) -> Result<OpenReply<Handle>, Error> {
        if !scope::has(self.caller, scope::PARTITIONS_OPEN) {
            return Err(Error::Refused);
        }
        self.refresh();
        // A disk whose table could not be read when it was last asked (its
        // driver starting again, say) is read now: until it can be, its
        // partitions are on their way, not missing.
        let disk = id >> 8;
        if !self.parts.iter().any(|p| p.id == id) && self.unread.contains(&disk) {
            let t = table(disk, &mut self.names).map_err(|_| Error::Gone)?;
            self.unread.retain(|d| *d != disk);
            self.parts.extend(t);
        }
        let p = self.parts.iter().find(|p| p.id == id).ok_or(Error::NoSuchPartition)?;
        let driver = self.devices.open(p.disk, gone).map_err(|_| Error::Gone)?.driver;
        let mut control = device::Client::<Channel, Handle>::from(Channel::within(driver.cap(), silica_rt::ipc::DRIVER_CALL_LIMIT));
        let narrowed = control.narrow(p.first, p.blocks).map_err(|_| Error::Gone)?.device;
        Ok(OpenReply { device: narrowed })
    }
}

fn main(_info: &'static ProcessInfo) -> i64 {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(DEVICES));
    // Served at once with the disks that have drivers now: one still on its
    // way is read when the device manager says it gained its driver
    // (`watch`, looked at before each call: `refresh`). This service
    // watches from its start, before any client can, and the device manager
    // signals watchers in the order they asked, so a client woken by its own
    // watch finds the new disk's table here.
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
    let disks: Vec<u32> = block_disks(&mut devices);
    let mut names = Vec::new();
    let (parts, unread) = read_tables(&disks, &mut names);
    let mut server = Server { devices, parts, listed: Vec::new(), changed, unread, names, caller: 0 };
    serve(ENDPOINT, |badge, request, caps: CapList<Handle>, reply, reply_caps| {
        server.caller = badge;
        partitions::dispatch(&mut server, request, caps, reply, reply_caps)
    })
}
