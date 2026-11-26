//! The program's memory as a buddy tree of Untyped blocks.
//!
//! Each source (an Untyped the program was given) is the root of a binary
//! tree. A block is handed out whole when it has the size asked for, or
//! split first: the kernel carves an Untyped's children upward from its
//! start, so two children of half its size made one after the other are
//! its two halves, and splitting is two `Retype`s. A block given back
//! (emptied by the caller's `CapRevoke`) merges with its buddy when that
//! is free too: both are deleted, which leaves their parent with no
//! children, and the kernel makes a childless Untyped whole again. So
//! memory freed at one size serves any other, and nothing is lost to
//! fragmentation that the tree can mend. (Before, every freed block was
//! kept for the next request of its own size alone: a program that freed
//! 1 MiB blocks could not have one of 2 MiB from them, and one that freed
//! more blocks than the list held lost them.)
//!
//! The tree's nodes are records in a fixed table, a record per block that
//! exists (handed out, free, or split); no allocation, since the heap
//! takes its memory from here. Everything here runs under the caller's
//! lock; the kernel operations are behind [`Ops`] so the bookkeeping runs
//! on the host too.

use crate::sys::Error;

/// Records in the table: blocks handed out, free and split together.
pub(crate) const NODES: usize = 2048;
const NONE: u16 = u16::MAX;

const UNUSED: u8 = 0;
const FREE: u8 = 1;
const USED: u8 = 2;
const SPLIT: u8 = 3;

#[derive(Clone, Copy)]
struct Node {
    /// The block's slot in the program's CapSpace.
    slot: u32,
    /// The record of the block it is half of (`NONE`: a source).
    up: u16,
    bits: u8,
    state: u8,
}

const EMPTY: Node = Node { slot: 0, up: NONE, bits: 0, state: UNUSED };

/// What the tree asks of the kernel.
pub(crate) trait Ops {
    /// An empty Untyped of `2^bits` bytes made from the one in slot
    /// `parent`, in a new slot: the next part of it upward.
    fn carve(&mut self, parent: u64, bits: u8) -> Result<u64, Error>;
    /// Delete the empty Untyped in `slot` and let the slot go.
    fn delete(&mut self, slot: u64);
}

/// The tree.
pub(crate) struct Blocks {
    nodes: [Node; NODES],
}

impl Blocks {
    pub(crate) const fn new() -> Blocks {
        Blocks { nodes: [EMPTY; NODES] }
    }

    fn record(&self) -> Option<usize> {
        self.nodes.iter().position(|n| n.state == UNUSED)
    }

    fn records_free(&self, want: usize) -> bool {
        self.nodes.iter().filter(|n| n.state == UNUSED).take(want).count() == want
    }

    /// Add the Untyped in `slot`, of `2^bits` bytes, as a source. False
    /// when the table has no room (the source is then not used).
    pub(crate) fn add_source(&mut self, slot: u64, bits: u8) -> bool {
        match (self.record(), u32::try_from(slot)) {
            (Some(i), Ok(slot)) => {
                self.nodes[i] = Node { slot, up: NONE, bits, state: FREE };
                true
            }
            _ => false,
        }
    }

    /// Bytes in free blocks.
    pub(crate) fn available(&self) -> u64 {
        self.nodes
            .iter()
            .filter(|n| n.state == FREE)
            .fold(0u64, |s, n| s.saturating_add(1u64.checked_shl(n.bits.into()).unwrap_or(u64::MAX)))
    }

    /// An empty block of `2^bits` bytes: a free one of that size, or the
    /// smallest larger free one split down to it. Its slot.
    pub(crate) fn alloc(&mut self, ops: &mut impl Ops, bits: u8) -> Result<u64, Error> {
        let exact = self.nodes.iter().position(|n| n.state == FREE && n.bits == bits);
        let mut i = match exact {
            Some(i) => i,
            None => (0..NODES)
                .filter(|&i| self.nodes[i].state == FREE && self.nodes[i].bits > bits)
                .min_by_key(|&i| self.nodes[i].bits)
                .ok_or(Error::NoMemory)?,
        };
        while self.nodes[i].bits > bits {
            // Two records for the halves, or the split is not begun.
            if !self.records_free(2) {
                return Err(Error::NoMemory);
            }
            let (parent, half) = (self.nodes[i].slot as u64, self.nodes[i].bits - 1);
            let a = ops.carve(parent, half)?;
            let b = match ops.carve(parent, half) {
                Ok(b) => b,
                Err(e) => {
                    ops.delete(a);
                    return Err(e);
                }
            };
            let (Ok(sa), Ok(sb)) = (u32::try_from(a), u32::try_from(b)) else {
                ops.delete(a);
                ops.delete(b);
                return Err(Error::NoMemory);
            };
            self.nodes[i].state = SPLIT;
            let up = i as u16;
            let ra = self.record().ok_or(Error::NoMemory)?;
            self.nodes[ra] = Node { slot: sa, up, bits: half, state: FREE };
            let rb = self.record().ok_or(Error::NoMemory)?;
            self.nodes[rb] = Node { slot: sb, up, bits: half, state: FREE };
            i = ra;
        }
        self.nodes[i].state = USED;
        Ok(self.nodes[i].slot as u64)
    }

    /// The block in `slot`, emptied by the caller, is free again, merged
    /// with its buddy and theirs as far as they are free. False when the
    /// slot is no block this tree handed out.
    pub(crate) fn free(&mut self, ops: &mut impl Ops, slot: u64) -> bool {
        let Some(mut i) = self.nodes.iter().position(|n| n.state == USED && n.slot as u64 == slot) else { return false };
        self.nodes[i].state = FREE;
        loop {
            let up = self.nodes[i].up;
            if up == NONE {
                return true;
            }
            let Some(j) = (0..NODES).find(|&j| j != i && self.nodes[j].state != UNUSED && self.nodes[j].up == up) else {
                return true;
            };
            if self.nodes[j].state != FREE {
                return true;
            }
            ops.delete(self.nodes[i].slot as u64);
            ops.delete(self.nodes[j].slot as u64);
            self.nodes[i] = EMPTY;
            self.nodes[j] = EMPTY;
            i = up as usize;
            self.nodes[i].state = FREE;
        }
    }

    /// Records in use, for tests.
    #[cfg(test)]
    pub(crate) fn records(&self) -> usize {
        self.nodes.iter().filter(|n| n.state != UNUSED).count()
    }
}

#[cfg(test)]
mod tests;
