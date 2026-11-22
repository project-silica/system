//! What the NVMe driver reads from its controller, as a library: the queue
//! pair (whose completion entries the controller writes), the Identify data
//! and the capabilities register. The driver (`main.rs`) puts them in DMA
//! memory and registers; the fuzz target (`fuzz/`) plays a hostile
//! controller against them in host memory. Nothing here allocates device
//! memory or makes a system call.
//!
//! The controller is not trusted: every completion's phase, queue,
//! submission queue head and command identifier is checked against what the
//! driver submitted before anything is done with it, and so is everything
//! Identify says.
#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use silica_block::Status;
use silica_driver::{DeviceError, dma};
use silica_rt::mmio::Mmio;

/// One completion queue entry, checked against its queue.
#[derive(Clone, Copy, Debug)]
pub struct Completion {
    /// Command specific (dword 0).
    pub result: u32,
    /// The command identifier the controller says it completed: the caller
    /// checks that it has such a command in progress.
    pub cid: u16,
    /// Status field without the phase: SC bits 0..8, SCT 8..11, CRD, M, DNR.
    pub status: u16,
}

/// A submission queue and the completion queue it reports to, of the same
/// size: `entries` entries of 64 and of 16 bytes.
#[derive(Debug)]
pub struct Queue {
    /// The queue pair's identifier (0: the admin queues).
    pub id: u16,
    /// Entries in each queue.
    pub entries: u16,
    sq: Mmio,
    cq: Mmio,
    sq_bell: Mmio,
    cq_bell: Mmio,
    /// Where the next command goes.
    tail: u16,
    /// The oldest command the controller has not yet taken, as it last said.
    head: u16,
    cq_head: u16,
    phase: bool,
}

impl Queue {
    /// The queue pair `id` of `entries` entries (at least 2) in `sq` and
    /// `cq` (zeroed, at least 64 and 16 bytes an entry), with its two
    /// doorbell registers. `None` when the sizes are not as required.
    pub fn over(id: u16, entries: u16, sq: Mmio, cq: Mmio, sq_bell: Mmio, cq_bell: Mmio) -> Option<Queue> {
        let fits = entries >= 2 && sq.len() >= 64 * entries as usize && cq.len() >= 16 * entries as usize;
        let fits = fits && sq_bell.len() >= 4 && cq_bell.len() >= 4;
        fits.then_some(Queue { id, entries, sq, cq, sq_bell, cq_bell, tail: 0, head: 0, cq_head: 0, phase: true })
    }

    /// Commands submitted that the controller has not yet said it took.
    pub fn submitted(&self) -> u16 {
        ((self.tail as u32 + self.entries as u32 - self.head as u32) % self.entries as u32) as u16
    }

    /// Whether another command would overrun the controller's head.
    pub fn full(&self) -> bool {
        self.submitted() == self.entries - 1
    }

    /// Put `command` in the next free entry (the caller checked `full`).
    pub fn push(&mut self, command: &[u32; 16]) {
        let at = self.tail as usize * 64;
        for (i, word) in command.iter().enumerate() {
            self.sq.write32(at + 4 * i, *word);
        }
        self.tail = ((self.tail as u32 + 1) % self.entries as u32) as u16;
    }

    /// Tell the controller about every command pushed so far.
    pub fn ring(&self) {
        // The entries must be in memory before the controller hears of them.
        dma::write_barrier();
        self.sq_bell.write32(0, self.tail as u32);
    }

    /// The next completion, if the controller has posted one. A completion
    /// for another queue, or one that moves the submission head past what
    /// was submitted, is the controller breaking the protocol.
    pub fn pop(&mut self) -> Result<Option<Completion>, DeviceError> {
        let at = self.cq_head as usize * 16;
        let dw3 = self.cq.read32(at + 12);
        if (dw3 & 1 << 16 != 0) != self.phase {
            return Ok(None);
        }
        dma::read_barrier();
        let result = self.cq.read32(at);
        let dw2 = self.cq.read32(at + 8);
        self.cq_head += 1;
        if self.cq_head == self.entries {
            self.cq_head = 0;
            self.phase = !self.phase;
        }
        let (sq_head, sq_id) = (dw2 as u16, (dw2 >> 16) as u16);
        if sq_id != self.id {
            return Err(DeviceError::Protocol("a completion names another submission queue"));
        }
        let moved = (sq_head as u32 + self.entries as u32 - self.head as u32) % self.entries as u32;
        if sq_head >= self.entries || moved > self.submitted() as u32 {
            return Err(DeviceError::Protocol("a completion moves the submission queue head past its tail"));
        }
        self.head = sq_head;
        Ok(Some(Completion { result, cid: dw3 as u16, status: (dw3 >> 17) as u16 }))
    }

    /// Give the completions taken so far back to the controller.
    pub fn release(&self) {
        self.cq_bell.write32(0, self.cq_head as u32);
    }
}

/// A completion's status as the block protocol says it.
pub fn status(s: u16) -> Result<(), Status> {
    let (code, kind) = (s & 0xFF, s >> 8 & 7);
    match (kind, code) {
        (0, 0) => Ok(()),
        // Invalid opcode, invalid field, LBA out of range.
        (0, 0x01 | 0x02 | 0x80) => Err(Status::Invalid),
        _ => Err(Status::Io),
    }
}

/// The entries of an I/O queue pair: as many as the controller takes
/// (CAP.MQES, zero-based: up to 65536) up to `most`, and at least 2.
pub fn queue_entries(cap: u64, most: u16) -> u16 {
    ((cap & 0xFFFF) + 1).min(most as u64).max(2) as u16
}

/// A namespace this driver can serve, as Identify Namespace describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Namespace {
    /// Its identifier.
    pub id: u32,
    /// Its block size, in bits (9 to 16).
    pub block_bits: u32,
    /// Its size in blocks (not 0).
    pub blocks: u64,
    /// Whether it is write protected.
    pub read_only: bool,
}

/// Why a namespace with no blocks (or an inactive one) is not served.
pub const NO_BLOCKS: &str = "it has no blocks";

/// Namespace `nsid` from its Identify Namespace data `m` (4 KiB):
/// `Ok(Err(why))` for one the driver cannot serve, `Err` for data no
/// controller should give.
pub fn namespace(m: &Mmio, nsid: u32) -> Result<Result<Namespace, &'static str>, DeviceError> {
    let blocks = m.read32(0) as u64 | (m.read32(4) as u64) << 32;
    if blocks == 0 {
        // Before NVMe 1.1 an inactive namespace reads as zeros.
        return Ok(Err(NO_BLOCKS));
    }
    let formats = m.read8(25) as u32; // NLBAF, zero-based
    let flbas = m.read8(26) as u32;
    let format = (flbas & 0xF) | (flbas >> 5 & 3) << 4;
    if format > formats {
        return Err(DeviceError::Protocol("the namespace's format index names no format"));
    }
    let lbaf = m.read32(128 + 4 * format as usize);
    if lbaf & 0xFFFF != 0 {
        return Ok(Err("its format carries metadata"));
    }
    let block_bits = lbaf >> 16 & 0xFF;
    if !(9..=16).contains(&block_bits) {
        return Ok(Err("its blocks are not 512 bytes to 64 KiB"));
    }
    Ok(Ok(Namespace { id: nsid, block_bits, blocks, read_only: m.read8(99) & 1 != 0 }))
}

/// The most namespaces looked at: one page of Identify's active list.
pub const MAX_NAMESPACES: usize = 1024;

/// The active namespace identifiers from Identify's Active Namespace List
/// `m` (4 KiB), in increasing order: every one above 0 and at most
/// `namespaces` (Identify Controller's NN; 0: no limit), the list ending at
/// the first zero.
pub fn active_list(m: &Mmio, namespaces: u32) -> Result<Vec<u32>, DeviceError> {
    let mut ids: Vec<u32> = Vec::new();
    for i in 0..MAX_NAMESPACES {
        let id = m.read32(4 * i);
        if id == 0 {
            break;
        }
        if id == u32::MAX || ids.last().is_some_and(|&last| id <= last) || (namespaces != 0 && id > namespaces) {
            return Err(DeviceError::Protocol("the active namespace list is not one"));
        }
        ids.try_reserve(1).map_err(|_| silica_rt::sys::Error::NoMemory)?;
        ids.push(id);
    }
    Ok(ids)
}
