//! The tree against a model of the kernel's Untyped rules: children carved
//! upward from a watermark that returns to the start only when an Untyped
//! has no children, a child strictly smaller than its parent, and only an
//! empty Untyped deleted.

extern crate std;
use super::*;
use std::collections::HashMap;
use std::vec::Vec;

struct Untyped {
    base: u64,
    bits: u8,
    parent: Option<u64>,
    watermark: u64,
    children: usize,
}

#[derive(Default)]
struct Kernel {
    slots: HashMap<u64, Untyped>,
    next: u64,
    carves: usize,
}

impl Kernel {
    fn source(&mut self, base: u64, bits: u8) -> u64 {
        self.next += 1;
        self.slots.insert(self.next, Untyped { base, bits, parent: None, watermark: 0, children: 0 });
        self.next
    }
}

impl Ops for Kernel {
    fn carve(&mut self, parent: u64, bits: u8) -> Result<u64, Error> {
        let p = self.slots.get_mut(&parent).expect("carving from no Untyped");
        if p.children == 0 {
            p.watermark = 0;
        }
        if bits >= p.bits {
            return Err(Error::NoMemory);
        }
        let size = 1u64 << bits;
        let start = (p.watermark + size - 1) & !(size - 1);
        if start + size > 1 << p.bits {
            return Err(Error::NoMemory);
        }
        p.watermark = start + size;
        p.children += 1;
        let base = p.base + start;
        self.next += 1;
        self.carves += 1;
        self.slots.insert(self.next, Untyped { base, bits, parent: Some(parent), watermark: 0, children: 0 });
        Ok(self.next)
    }

    fn delete(&mut self, slot: u64) {
        let u = self.slots.remove(&slot).expect("deleting no Untyped");
        assert_eq!(u.children, 0, "deleted an Untyped that still had children");
        if let Some(p) = u.parent {
            self.slots.get_mut(&p).unwrap().children -= 1;
        }
    }
}

/// Memory given back at one size serves another: a source used up in
/// 64 KiB blocks and given back is one 4 MiB block again, then four of
/// 1 MiB. Before, the freed blocks were kept for 64 KiB requests alone.
#[test]
fn memory_freed_at_one_size_serves_another() {
    let mut k = Kernel::default();
    let mut b = Blocks::new();
    let src = k.source(0, 22);
    assert!(b.add_source(src, 22));
    let small: Vec<u64> = core::iter::from_fn(|| b.alloc(&mut k, 16).ok()).collect();
    assert_eq!(small.len(), 64, "a 4 MiB source holds 64 blocks of 64 KiB");
    assert_eq!(b.available(), 0);
    for s in &small {
        assert!(b.free(&mut k, *s));
    }
    assert_eq!(b.available(), 4 << 20);
    assert_eq!(b.records(), 1, "every block merged back into the source");
    let whole = b.alloc(&mut k, 22).expect("the source whole again");
    assert_eq!(whole, src);
    assert!(b.free(&mut k, whole));
    let mid: Vec<u64> = (0..4).map(|_| b.alloc(&mut k, 20).expect("1 MiB")).collect();
    assert_eq!(b.alloc(&mut k, 12), Err(Error::NoMemory));
    for s in mid {
        assert!(b.free(&mut k, s));
    }
    assert_eq!(b.records(), 1);
    assert!(!b.free(&mut k, 999), "a slot never handed out is not taken");
}

/// Random requests and returns at every size: blocks never overlap, every
/// byte is either free or handed out, and when all are back the tree is
/// its sources again.
#[test]
fn random_use_keeps_the_tree_whole() {
    let mut k = Kernel::default();
    let mut b = Blocks::new();
    let mut total = 0u64;
    for (base, bits) in [(0u64, 22u8), (1 << 30, 20), (2 << 30, 24)] {
        let s = k.source(base, bits);
        assert!(b.add_source(s, bits));
        total += 1 << bits;
    }
    let mut held: Vec<(u64, u8)> = Vec::new();
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut rand = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..if cfg!(miri) { 300 } else { 20_000 } {
        if rand() % 2 == 0 || held.is_empty() {
            let bits = 12 + (rand() % 12) as u8;
            if let Ok(s) = b.alloc(&mut k, bits) {
                assert_eq!(k.slots[&s].bits, bits);
                held.push((s, bits));
            }
        } else {
            let (s, _) = held.swap_remove((rand() % held.len() as u64) as usize);
            assert!(b.free(&mut k, s));
        }
        let used: u64 = held.iter().map(|(_, bits)| 1u64 << bits).sum();
        assert_eq!(b.available() + used, total, "every byte free or handed out");
        let mut spans: Vec<(u64, u64)> = held.iter().map(|(s, bits)| (k.slots[s].base, 1u64 << bits)).collect();
        spans.sort();
        assert!(spans.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0), "two blocks overlap");
    }
    for (s, _) in held.drain(..) {
        assert!(b.free(&mut k, s));
    }
    assert_eq!(b.records(), 3, "the tree is its sources again");
    assert_eq!(b.available(), total);
}

/// A table with no room for a split's two halves refuses the request and
/// leaves the tree as it was.
#[test]
fn no_room_for_records_refuses_without_harm() {
    let mut k = Kernel::default();
    let mut b = Blocks::new();
    for i in 0..NODES as u64 - 1 {
        let s = k.source(i << 30, 13);
        assert!(b.add_source(s, 13));
    }
    let carves = k.carves;
    assert_eq!(b.alloc(&mut k, 12), Err(Error::NoMemory));
    assert_eq!(k.carves, carves, "nothing was carved");
    assert_eq!(b.alloc(&mut k, 13).map(|s| k.slots[&s].bits), Ok(13), "a whole source still is");
}
