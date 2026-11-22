//! A ring (`silica_rt::ring`) lies in memory two programs share, and each
//! side may write any of it at any time: the producer's index, the
//! consumer's index, the sleeping flag, the records. Every class's data path
//! (`silica-queue`: requests one way, completions the other) and every
//! program's log (`silica_rt::log`, read by logd) is one. The fuzzer drives
//! both library ends of one ring and, between their moves, writes the
//! shared memory as a hostile peer would. Given any sequence:
//!
//! - nothing panics, and nothing reads or writes outside the ring;
//! - the producer never claims more room than the ring holds;
//! - a consumer that sees more records announced than the ring holds says
//!   `Broken` instead of reading stale ones, and `skip` makes the ring
//!   usable again;
//! - while no hostile write has happened, records come out exactly as they
//!   went in, none lost, none repeated, `Broken` never said, and a consumer
//!   that goes to sleep has nothing waiting;
//! - a log record's text (`silica_rt::log::text`) lies inside the record,
//!   whatever its length byte says.
//!
//! The first input byte picks the capacity (1 to 8 records); then each byte
//! is a move, followed by its operands.
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_rt::log::{self, RECORD};
use silica_rt::mmio::Mmio;
use silica_rt::ring::{self, Consumer, Full, HEADER, Producer};
use std::collections::VecDeque;

/// The shared memory, zeroed, 8-byte aligned.
struct Area(Vec<u64>);

impl Area {
    fn mmio(&self) -> Mmio {
        // SAFETY: this value's own heap memory, holding no Rust object but
        // integers, alive until the end of the input, after both ends.
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
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes([self.u8()?, self.u8()?, self.u8()?, self.u8()?]))
    }
}

// The header words, as `silica_rt::ring` lays them out.
const TAIL: usize = 0;
const SLEEPING: usize = 4;
const HEAD: usize = 32;

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(first) = input.u8() else { return };
    let capacity = 1u32 << (first % 4);
    let bytes = ring::size(capacity, RECORD);
    let area = Area(vec![0; bytes.div_ceil(8)]);
    let m = area.mmio();
    let mut p = Producer::<RECORD>::new(m, capacity).expect("a ring that fits");
    let mut c = Consumer::<RECORD>::new(m, capacity).expect("a ring that fits");
    let mut sent: VecDeque<[u8; RECORD]> = VecDeque::new();
    let (mut hostile, mut n) = (false, 0u8);

    while let Some(op) = input.u8() {
        match op % 8 {
            // The producer adds a record (its length byte any value).
            0 => {
                let Some(len) = input.u8() else { break };
                n = n.wrapping_add(1);
                let mut r = [n; RECORD];
                r[0] = len;
                let room = p.room();
                match p.push(&r) {
                    Ok(()) => {
                        assert!(room > 0, "a push into a ring with no room");
                        sent.push_back(r);
                    }
                    Err(Full) => assert_eq!(room, 0, "a ring with room refused a record"),
                }
            }
            // The consumer takes one.
            1 => match c.pop() {
                Ok(Some(r)) => {
                    let text = log::text(&r);
                    assert!(text.len() < RECORD && text.as_ptr() > r.as_ptr());
                    if !hostile {
                        assert_eq!(Some(r), sent.pop_front(), "a record out of order, lost or repeated");
                    }
                }
                Ok(None) => assert!(hostile || sent.is_empty(), "a record never arrived"),
                Err(_) => assert!(hostile, "an honest ring said Broken"),
            },
            2 => {
                if c.sleep() {
                    assert!(hostile || sent.is_empty(), "the consumer slept on a record");
                }
            }
            3 => {
                let _ = p.wake_needed();
            }
            4 => {
                c.skip();
                sent.clear();
            }
            // A hostile peer writes the producer's index...
            5 => {
                let Some(v) = input.u32() else { break };
                m.write32(TAIL, v);
                hostile = true;
            }
            // ...the consumer's...
            6 => {
                let Some(v) = input.u32() else { break };
                m.write32(HEAD, v);
                hostile = true;
            }
            // ...the sleeping flag, or a record's bytes.
            _ => {
                let (Some(at), Some(v)) = (input.u8(), input.u32()) else { break };
                if at & 1 == 0 {
                    m.write32(SLEEPING, v);
                } else {
                    let o = HEADER + (at as usize * 4) % (bytes - HEADER);
                    m.write32(o, v);
                    hostile = true;
                }
            }
        }
        assert!(p.room() <= capacity, "more room than the ring holds");
    }
});
