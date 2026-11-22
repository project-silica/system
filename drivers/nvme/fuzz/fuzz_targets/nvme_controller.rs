//! An NVMe controller writes the completion queues of its driver and the
//! Identify data the driver asks for, and reports its capabilities in a
//! register; any of it may be nonsense. The fuzzer plays that controller
//! against the driver's own code (`nvme`'s library), mixing an honest
//! controller's moves (take commands from the submission queue, complete
//! them in any order with the right phase, head and queue) with a hostile
//! one's (any entry, any phase, any head, any queue, any command
//! identifier). Given any input:
//!
//! - nothing panics or reads outside its memory;
//! - the driver never believes more commands are submitted than the queue
//!   holds, and a completion it takes names its own queue and moves the
//!   head no further than what was submitted;
//! - a completion naming a command not in progress is caught (the driver
//!   gives up on the controller, as `main.rs` does), and an honest
//!   controller never gets a protocol error;
//! - Identify Namespace gives a namespace with blocks and a block size of
//!   512 bytes to 64 KiB, or a reason; the active namespace list is
//!   strictly increasing, without 0 or `u32::MAX`, within NN and at most
//!   1024 long;
//! - an I/O queue has 2 to 256 entries whatever CAP.MQES says.
//!
//! The first input byte picks what is fuzzed: the queue pair (its size from
//! the second byte), or Identify data and the capabilities register.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nvme::{MAX_NAMESPACES, Queue};
use silica_rt::mmio::Mmio;
use std::collections::BTreeSet;

/// Memory shared with the controller, zeroed, 8-byte aligned.
struct Area(Vec<u64>);

impl Area {
    fn new(bytes: usize) -> Area {
        Area(vec![0; bytes.div_ceil(8)])
    }
    fn mmio(&self) -> Mmio {
        // SAFETY: this value's own heap memory, holding no Rust object but
        // integers, alive until the end of the input, after every user.
        unsafe { Mmio::new(self.0.as_ptr() as usize, self.0.len() * 8) }
    }
}

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes([self.u8()?, self.u8()?, self.u8()?, self.u8()?]))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    match input.u8() {
        Some(m) if m & 1 == 0 => queue(input),
        Some(_) => identify(input),
        None => {}
    }
});

fn queue(mut input: Input) {
    let Some(shape) = input.u8() else { return };
    let entries = 2 + (shape % 15) as u16;
    let id = (shape >> 4) as u16 & 1;
    let (sq, cq, bells) = (Area::new(64 * entries as usize), Area::new(16 * entries as usize), Area::new(8));
    let (sqm, cqm, bm) = (sq.mmio(), cq.mmio(), bells.mmio());
    let mut q = Queue::over(id, entries, sqm, cqm, bm.part(0, 4).unwrap(), bm.part(4, 4).unwrap()).expect("a queue that fits");

    // The driver's commands in progress, by identifier, and the next one.
    let mut in_progress = BTreeSet::new();
    let mut cid = 0u16;
    // The honest controller: the next submission entry it reads, commands
    // it took and has not completed, where it posts the next completion,
    // and with which phase.
    let (mut sq_head, mut taken, mut cq_tail, mut phase) = (0u16, Vec::<u16>::new(), 0u16, true);
    let mut hostile = false;

    while let Some(op) = input.u8() {
        match op % 8 {
            // The driver submits a command and rings, unless the queue is full.
            0 => {
                if !q.full() {
                    let mut c = [0u32; 16];
                    c[0] = 2 | (cid as u32) << 16;
                    q.push(&c);
                    q.ring();
                    in_progress.insert(cid);
                    cid = cid.wrapping_add(1);
                }
            }
            // The driver takes completions, as its interrupt handler does.
            1 => {
                loop {
                    match q.pop() {
                        Ok(Some(c)) => {
                            if !in_progress.remove(&c.cid) {
                                assert!(hostile, "an honest controller completed a command not in progress");
                                return;
                            }
                            let _ = nvme::status(c.status);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            assert!(hostile, "an honest controller broke the protocol: {e:?}");
                            return;
                        }
                    }
                }
                q.release();
            }
            // The honest controller takes the next command the doorbell says is there.
            2 => {
                let tail = bm.read32(0) as u16;
                if sq_head != tail {
                    taken.push((sqm.read32(sq_head as usize * 64) >> 16) as u16);
                    sq_head = (sq_head + 1) % entries;
                }
            }
            // The honest controller completes one it took, if the
            // completion queue has room (the driver's doorbell says where
            // it has read to).
            3 => {
                let Some(pick) = input.u8() else { break };
                let cq_read = bm.read32(4) as u16;
                if taken.is_empty() || (cq_tail + 1) % entries == cq_read {
                    continue;
                }
                let c = taken.swap_remove(pick as usize % taken.len());
                let at = cq_tail as usize * 16;
                cqm.write32(at, 0);
                cqm.write32(at + 8, (id as u32) << 16 | sq_head as u32);
                cqm.write32(at + 12, (phase as u32) << 16 | c as u32);
                cq_tail += 1;
                if cq_tail == entries {
                    cq_tail = 0;
                    phase = !phase;
                }
            }
            // A hostile controller writes any completion entry...
            4 => {
                let (Some(slot), Some(dw2), Some(dw3)) = (input.u8(), input.u32(), input.u32()) else { break };
                let at = (slot as usize % entries as usize) * 16;
                cqm.write32(at + 8, dw2);
                cqm.write32(at + 12, dw3);
                hostile = true;
            }
            // ...or completes a command, honestly formed but with any
            // identifier, head or queue.
            5 => {
                let (Some(c), Some(head), Some(qid)) = (input.u16(), input.u16(), input.u8()) else { break };
                let at = cq_tail as usize * 16;
                cqm.write32(at + 8, ((qid & 1) as u32) << 16 | head as u32);
                cqm.write32(at + 12, (phase as u32) << 16 | c as u32);
                cq_tail += 1;
                if cq_tail == entries {
                    cq_tail = 0;
                    phase = !phase;
                }
                hostile = true;
            }
            _ => {}
        }
        assert!(q.submitted() < entries, "more submitted than the queue holds");
    }
}

fn identify(mut input: Input) {
    let (Some(cap), Some(nn)) = (input.u32(), input.u32()) else { return };
    let entries = nvme::queue_entries(cap as u64 | (input.u32().unwrap_or(0) as u64) << 32, 256);
    assert!((2..=256).contains(&entries));
    let page = Area::new(4096);
    let m = page.mmio();
    for (i, b) in input.0.iter().take(4096).enumerate() {
        m.write8(i, *b);
    }
    match nvme::namespace(&m, 1) {
        Ok(Ok(ns)) => assert!(ns.blocks != 0 && (9..=16).contains(&ns.block_bits) && ns.id == 1),
        Ok(Err(_)) | Err(_) => {}
    }
    if let Ok(ids) = nvme::active_list(&m, nn) {
        assert!(ids.len() <= MAX_NAMESPACES);
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "an active list out of order");
        assert!(ids.iter().all(|&id| id != 0 && id != u32::MAX && (nn == 0 || id <= nn)));
    }
}
