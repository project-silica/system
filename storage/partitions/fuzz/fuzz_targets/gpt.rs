//! A disk's GPT is written by whoever wrote the disk: an image downloaded,
//! a stick plugged in. The partitions service reads it (`partitions`'s
//! library) and hands out each partition as a capability reaching its
//! blocks alone. Given any header block and entries, and any disk size:
//!
//! - nothing panics;
//! - every partition taken has at least one block, lies inside the
//!   header's usable blocks and the disk, and overlaps no other;
//! - a header or entries whose checksum is wrong are refused.
//!
//! The checksums are what a fuzzer cannot guess, so the harness writes
//! them right unless the input's first byte says not to. Input: a byte of
//! flags, the disk's size in blocks (8 bytes), the header block (512
//! bytes), then the entries.
#![no_main]

use libfuzzer_sys::fuzz_target;
use partitions::{Header, crc32, entries, header};

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 + 512 {
        return;
    }
    let flags = data[0];
    let disk_blocks = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let mut block = data[9..9 + 512].to_vec();
    let mut table = data[9 + 512..].to_vec();
    block[..8].copy_from_slice(b"EFI PART");
    // Sizes a fuzzer would rarely hit by chance, unless it asks not to.
    if flags & 4 == 0 {
        block[12..16].copy_from_slice(&92u32.to_le_bytes());
        block[84..88].copy_from_slice(&(128u32 << (flags >> 4 & 3)).to_le_bytes());
        let count = (block[80] as u32) % 64;
        block[80..84].copy_from_slice(&count.to_le_bytes());
    }
    let count = u32::from_le_bytes(block[80..84].try_into().unwrap()) as usize;
    let entry = u32::from_le_bytes(block[84..88].try_into().unwrap()) as usize;
    if let Some(len) = count.checked_mul(entry).filter(|n| *n <= 1 << 20) {
        if table.len() < len {
            table.resize(len, 0);
        }
        if flags & 1 == 0 {
            block[88..92].copy_from_slice(&crc32(&table[..len]).to_le_bytes());
        }
    }
    if flags & 2 == 0 {
        let size = (u32::from_le_bytes(block[12..16].try_into().unwrap()) as usize).clamp(92, 512);
        block[16..20].fill(0);
        let sum = crc32(&block[..size]);
        block[16..20].copy_from_slice(&sum.to_le_bytes());
    }
    let Ok(Some(h)) = header(&block, disk_blocks) else { return };
    let Header { count, entry_bytes, first_usable, last_usable, .. } = h;
    assert!(count <= 1024 && (128..=1024).contains(&entry_bytes) && entry_bytes.is_power_of_two());
    assert!(first_usable <= last_usable && last_usable < disk_blocks);
    let Ok(parts) = entries(&h, &table, |_, _| {}) else { return };
    for (i, p) in parts.iter().enumerate() {
        assert!(
            p.blocks >= 1 && p.first >= first_usable && p.first + (p.blocks - 1) <= last_usable,
            "a partition outside the usable blocks"
        );
        for q in &parts[..i] {
            assert!(p.first + p.blocks <= q.first || q.first + q.blocks <= p.first, "two partitions overlap");
        }
        assert!(p.name.chars().count() <= 36);
    }
});
