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

use silica_block::client::Disk;
use silica_block::device;
use silica_block::partitions::{self, Error, ListReply, OpenReply, Partition};
use silica_block::{Op, Request};
use silica_idl_rt::{Array, CapList};
use silica_protocols::device::manager;
use silica_rt::alloc::format;
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

/// CRC-32 (IEEE, reflected), as the GPT uses.
fn crc32(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { c >> 1 ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    le32(b, at) as u64 | (le32(b, at + 4) as u64) << 32
}

/// A GUID in its usual text form (the first three fields little-endian).
fn guid(g: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        le32(g, 0),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// The partitions of disk `id`, from its GPT.
fn table(id: u32) -> Result<Vec<Part>, &'static str> {
    let mut disk = Disk::open(DEVICES, id).map_err(|_| "it cannot be opened")?;
    let bs = disk.info().block_size as usize;
    let memory = Memory::new(16).map_err(|_| "no memory")?;
    disk.add_memory(0, &memory, true).map_err(|_| "its driver takes no memory")?;
    let m = memory.shared();
    let read = |disk: &mut Disk, block: u64, blocks: u32| -> Result<Vec<u8>, &'static str> {
        let r = Request { op: Op::Read, memory: 0, block, offset: 0, blocks, tag: block };
        disk.run(&r, Some(silica_rt::clock().now() + 5 * SECOND)).map_err(|_| "a read failed")?;
        Ok((0..blocks as usize * bs).map(|i| m.read8(i)).collect())
    };
    let mut header = read(&mut disk, 1, 1)?;
    if &header[..8] != b"EFI PART" {
        return Ok(Vec::new());
    }
    let size = (le32(&header, 12) as usize).clamp(92, bs);
    let sum = le32(&header, 16);
    header[16..20].fill(0);
    if crc32(&header[..size]) != sum {
        return Err("its GPT header's checksum is wrong");
    }
    let (at, count, entry) = (le64(&header, 72), le32(&header, 80) as usize, le32(&header, 84) as usize);
    if !(128..=1024).contains(&entry) || !entry.is_power_of_two() || count > 1024 {
        return Err("its GPT describes entries no table has");
    }
    let bytes = count * entry;
    let blocks = bytes.div_ceil(bs) as u32;
    if blocks as usize * bs > memory.len() {
        return Err("its GPT's entries do not fit the memory read into");
    }
    let entries = read(&mut disk, at, blocks)?;
    if crc32(&entries[..bytes]) != le32(&header, 88) {
        return Err("its GPT entries' checksum is wrong");
    }
    let disk_blocks = disk.info().blocks;
    let mut parts = Vec::new();
    for i in 0..count {
        let e = &entries[i * entry..(i + 1) * entry];
        if e[..16].iter().all(|b| *b == 0) {
            continue;
        }
        let (first, last) = (le64(e, 32), le64(e, 40));
        if first > last || last >= disk_blocks {
            println!("partitions: disk {id:#x}: entry {i} lies outside the disk; left out");
            continue;
        }
        let name: String = char::decode_utf16((0..36).map(|k| u16::from_le_bytes([e[56 + 2 * k], e[57 + 2 * k]])).take_while(|c| *c != 0))
            .map(|c| c.unwrap_or('?'))
            .collect();
        parts.push(Part {
            id: id << 8 | i as u32,
            disk: id,
            first,
            blocks: last - first + 1,
            kind: keep(guid(&e[..16])),
            name: keep(name),
        });
    }
    Ok(parts)
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
    // device it found; a disk may still be on its way, so an empty list
    // is asked again for a while.
    let deadline = silica_rt::clock().now() + 10 * SECOND;
    let disks: Vec<u32> = loop {
        let found: Vec<u32> = devices.list(manager::Class::Block).map(|r| r.devices.iter().map(|d| d.id).collect()).unwrap_or_default();
        if !found.is_empty() || silica_rt::clock().now() > deadline {
            break found;
        }
        silica_rt::sys::yield_now();
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
