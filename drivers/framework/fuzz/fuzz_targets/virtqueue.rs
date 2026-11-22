//! A virtio device writes the used ring of every queue its driver offers it
//! (virtio-blk, virtio-net and virtio-input all take completions through
//! `silica_driver::virtio::Queue`), and may write anything there: any
//! index, any descriptor ID, any length, at any time. The fuzzer plays that
//! device against the queue a driver uses, mixing an honest device's moves
//! (take a request from the available ring, complete it, in any order) with
//! a hostile one's (write any used entry, any used index, any flags). Given
//! any sequence:
//!
//! - the queue never panics and never reads or writes outside its memory;
//! - a completion it returns names a request the driver offered and has not
//!   had back, and its length is no more than that request's writable
//!   buffers hold (a client reads that many bytes);
//! - every descriptor is either free or in exactly one outstanding request;
//! - an honest device never gets a protocol error;
//! - after a protocol error the driver stops using the queue (as drivers do).
//!
//! The first input byte picks the queue's size (1 to 128) and whether event
//! indices were agreed; then each byte is a move, followed by its operands.
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_driver::virtio::{Buffer, Queue, queue_areas};
use silica_rt::mmio::Mmio;
use std::collections::BTreeMap;

/// Memory a queue lives in, zeroed, 8-byte aligned.
struct Area(Vec<u64>);

impl Area {
    fn new(bytes: usize) -> Area {
        Area(vec![0; bytes.div_ceil(8)])
    }
    fn mmio(&self) -> Mmio {
        // SAFETY: this value's own heap memory, holding no Rust object but
        // the integers it was made of, alive for as long as the queue that
        // uses it (the queue is dropped first, at the end of the input).
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

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(first) = input.u8() else { return };
    let size = 1u16 << (first & 7);
    let event_idx = first & 8 != 0;
    let (driver_bytes, device_bytes) = queue_areas(size);
    let (driver, device, bell) = (Area::new(driver_bytes), Area::new(device_bytes), Area::new(8));
    let (d, u) = (driver.mmio(), device.mmio());
    let mut q = Queue::over(size, d, u).expect("a valid queue").with_notify(bell.mmio(), event_idx);
    let n = size as usize;
    let (avail_idx, avail_ring, used_ring, avail_event) = (16 * n + 2, 16 * n + 4, 4, 4 + 8 * n);

    // The driver's side: each outstanding token, its descriptor count and
    // its writable bytes.
    let mut outstanding: BTreeMap<u64, (u16, u64)> = BTreeMap::new();
    let mut token = 0u64;
    // The honest device's side: the next available entry it reads, the
    // heads it has taken and not completed, and its used index.
    let (mut taken_at, mut taken, mut used) = (0u16, Vec::<u16>::new(), 0u16);
    let mut hostile = false;

    while let Some(op) = input.u8() {
        match op % 10 {
            // The driver offers a request of one to four buffers.
            0 => {
                let Some(shape) = input.u8() else { break };
                let count = 1 + (shape & 3) as usize;
                let mut buffers = Vec::new();
                for i in 0..count {
                    let Some(len) = input.u16() else { break };
                    buffers.push(Buffer { address: 0x1000 * (i as u64 + 1), len: len as u32, device_writes: shape >> (4 + i) & 1 != 0 });
                }
                let room = q.room();
                match q.add(&buffers, token) {
                    Ok(()) => {
                        assert!(buffers.len() <= room as usize);
                        let writable = buffers.iter().filter(|b| b.device_writes).map(|b| b.len as u64).sum();
                        outstanding.insert(token, (buffers.len() as u16, writable));
                        token += 1;
                    }
                    Err(_) => assert!(buffers.is_empty() || buffers.len() > room as usize, "refused a request that fits"),
                }
            }
            1 => q.notify(),
            2 => q.suppress_interrupts(input.u8().is_some_and(|b| b & 1 != 0)),
            // The driver takes completions, as a driver's interrupt handler does.
            3 => loop {
                match q.pop() {
                    Ok(Some((t, written))) => {
                        let (_, writable) = outstanding.remove(&t).expect("a completion of a request not outstanding");
                        assert!(written as u64 <= writable, "a length past the request's buffers");
                    }
                    Ok(None) => break,
                    Err(e) => {
                        assert!(hostile, "an honest device broke the protocol: {e:?}");
                        return;
                    }
                }
            },
            // The honest device takes the next request from the available ring.
            4 => {
                if d.read16(avail_idx) != taken_at {
                    taken.push(d.read16(avail_ring + 2 * (taken_at % size) as usize));
                    taken_at = taken_at.wrapping_add(1);
                }
            }
            // The honest device completes one it has taken, in any order,
            // writing no more than the chain's writable descriptors hold.
            5 => {
                let (Some(pick), Some(claim)) = (input.u8(), input.u32()) else { break };
                if taken.is_empty() {
                    continue;
                }
                let head = taken.swap_remove(pick as usize % taken.len());
                let (mut at, mut writable, mut hops) = (head, 0u64, 0);
                loop {
                    let o = 16 * (at % size) as usize;
                    let flags = d.read16(o + 12);
                    if flags & DESC_WRITE != 0 {
                        writable += d.read32(o + 8) as u64;
                    }
                    hops += 1;
                    if flags & DESC_NEXT == 0 || hops == size {
                        break;
                    }
                    at = d.read16(o + 14);
                }
                let written = (claim as u64).min(writable) as u32;
                let o = used_ring + 8 * (used % size) as usize;
                u.write32(o, head as u32);
                u.write32(o + 4, written);
                used = used.wrapping_add(1);
                u.write16(2, used);
            }
            // The device asks to be told of the request at an index, or for
            // no notifications (honest or not, the driver must cope).
            6 => {
                let Some(v) = input.u16() else { break };
                if event_idx { u.write16(avail_event, v) } else { u.write16(0, v) }
            }
            // A hostile device writes any used entry...
            7 => {
                let (Some(slot), Some(id), Some(len)) = (input.u8(), input.u32(), input.u32()) else { break };
                let o = used_ring + 8 * (slot as u16 % size) as usize;
                u.write32(o, id);
                u.write32(o + 4, len);
                hostile = true;
            }
            // ...any used index...
            8 => {
                let Some(v) = input.u16() else { break };
                u.write16(2, v);
                hostile = true;
            }
            // ...or completes a request it was never given.
            _ => {
                let Some(claim) = input.u32() else { break };
                let o = used_ring + 8 * (used % size) as usize;
                u.write32(o, claim % size as u32);
                u.write32(o + 4, claim >> 8);
                used = used.wrapping_add(1);
                u.write16(2, used);
                hostile = true;
            }
        }
        let held: usize = outstanding.values().map(|&(c, _)| c as usize).sum();
        assert_eq!(q.room() as usize + held, n, "descriptors lost or counted twice");
    }
});
