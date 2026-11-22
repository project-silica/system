//! The GUID Partition Table (UEFI 2.10, section 5.3), as the partitions
//! service reads it from a disk: a library, so the fuzz target (`fuzz/`)
//! reads tables exactly as the service does. Nothing here does I/O.
//!
//! A disk's table is untrusted input. A header is taken only with its
//! checksum right and its sizes those a table can have; an entry only
//! inside the header's usable blocks and the disk, and overlapping no
//! entry taken before it: each partition is handed out as a capability
//! reaching its blocks alone, so two that overlap would let one client
//! reach another's data.
#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The most entries a table is read with.
pub const MAX_ENTRIES: usize = 1024;

/// A GPT header, checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The block the entries start at.
    pub entries_at: u64,
    /// How many entries, and the bytes of each (128 to 1024, a power of two).
    pub count: usize,
    pub entry_bytes: usize,
    /// The CRC-32 of the entries.
    pub entries_crc: u32,
    /// The blocks partitions may use, first and last.
    pub first_usable: u64,
    pub last_usable: u64,
}

impl Header {
    /// Bytes the entries take.
    pub fn entries_len(&self) -> usize {
        self.count * self.entry_bytes
    }
}

/// A partition, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its index in the table.
    pub index: usize,
    /// Its first block and how many it has (at least one).
    pub first: u64,
    pub blocks: u64,
    /// Its type GUID, in text form.
    pub kind: String,
    /// Its name.
    pub name: String,
}

/// CRC-32 (IEEE, reflected), as the GPT uses.
pub fn crc32(bytes: &[u8]) -> u32 {
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
pub fn guid(g: &[u8; 16]) -> String {
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

/// The header in `block` (block 1 of a disk of `disk_blocks` blocks, as
/// many bytes as a block has, at least 512): `Ok(None)` when the disk has
/// no GPT, `Err` when what it has is not one.
pub fn header(block: &[u8], disk_blocks: u64) -> Result<Option<Header>, &'static str> {
    if block.len() < 512 || &block[..8] != b"EFI PART" {
        return Ok(None);
    }
    let size = le32(block, 12) as usize;
    if !(92..=block.len()).contains(&size) {
        return Err("its GPT header's size is not one a header has");
    }
    let mut copy = Vec::new();
    copy.extend_from_slice(&block[..size]);
    copy[16..20].fill(0);
    if crc32(&copy) != le32(block, 16) {
        return Err("its GPT header's checksum is wrong");
    }
    let (count, entry_bytes) = (le32(block, 80) as usize, le32(block, 84) as usize);
    if !(128..=1024).contains(&entry_bytes) || !entry_bytes.is_power_of_two() || count > MAX_ENTRIES {
        return Err("its GPT describes entries no table has");
    }
    let (first_usable, last_usable) = (le64(block, 40), le64(block, 48));
    if first_usable > last_usable || last_usable >= disk_blocks {
        return Err("its GPT's usable blocks lie outside the disk");
    }
    Ok(Some(Header { entries_at: le64(block, 72), count, entry_bytes, entries_crc: le32(block, 88), first_usable, last_usable }))
}

/// The partitions in `bytes` (at least [`Header::entries_len`] of them, as
/// read from [`Header::entries_at`]), in table order. An entry that lies
/// outside the usable blocks, or overlaps one taken before it, is left
/// out and `left_out` told which and why; `Err` when the entries' checksum
/// is wrong.
pub fn entries(h: &Header, bytes: &[u8], mut left_out: impl FnMut(usize, &'static str)) -> Result<Vec<Entry>, &'static str> {
    let bytes = bytes.get(..h.entries_len()).ok_or("its GPT entries were not all read")?;
    if crc32(bytes) != h.entries_crc {
        return Err("its GPT entries' checksum is wrong");
    }
    let mut parts: Vec<Entry> = Vec::new();
    for (index, e) in bytes.chunks_exact(h.entry_bytes).enumerate() {
        let kind: &[u8; 16] = e[..16].try_into().unwrap_or(&[0; 16]);
        if kind.iter().all(|b| *b == 0) {
            continue;
        }
        let (first, last) = (le64(e, 32), le64(e, 40));
        if first > last || first < h.first_usable || last > h.last_usable {
            left_out(index, "it lies outside the disk's usable blocks");
            continue;
        }
        if parts.iter().any(|p| first < p.first + p.blocks && p.first <= last) {
            left_out(index, "it overlaps a partition before it");
            continue;
        }
        let name: String = char::decode_utf16((0..36).map(|k| u16::from_le_bytes([e[56 + 2 * k], e[57 + 2 * k]])).take_while(|c| *c != 0))
            .map(|c| c.unwrap_or('?'))
            .collect();
        parts.push(Entry { index, first, blocks: last - first + 1, kind: guid(kind), name });
    }
    Ok(parts)
}
