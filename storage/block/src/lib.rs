//! The block device class (`silica.block.Device`): the data path, a client,
//! and the service every block driver provides.
//!
//! # The data path
//!
//! After `connect`, requests and completions travel through the two rings
//! every device class shares (`silica_queue` documents them: their frame,
//! the wake-up rule, where the memory number and the tag sit). A block
//! request ([`Request`], little-endian):
//!
//! | offset | type | field |
//! | --- | --- | --- |
//! | 0 | u8 | operation: 0 read, 1 write, 2 flush |
//! | 4 | u32 | memory: the number of a registered frame (`add_memory`) |
//! | 8 | u64 | first block |
//! | 16 | u32 | offset of the data in that frame, in bytes, a multiple of 512 |
//! | 20 | u32 | number of blocks |
//! | 24 | u64 | tag: the client's own, returned in the completion |
//!
//! A completion ([`Completion`]): the tag, then a status (0 is success,
//! otherwise a [`Status`]); its value is 0.
//!
//! Every request gets exactly one completion, in any order. Data is never
//! copied: a read is written by the device straight into the client's
//! frame, a write is read from it. The client must leave the bytes of a
//! request alone until its completion arrives.
#![no_std]
#![deny(unsafe_code)]

pub mod client;
pub mod service;

include!(concat!(env!("OUT_DIR"), "/silica_block_device.rs"));
include!(concat!(env!("OUT_DIR"), "/silica_block_partitions.rs"));

pub use silica_queue::{COMPLETION_BYTES, COMPLETIONS_AT, MEMORIES, QUEUE, REQUEST_BYTES, RINGS_BITS};

/// What a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Read blocks into the client's memory.
    Read = 0,
    /// Write blocks from the client's memory.
    Write = 1,
    /// Make every completed write durable (no data).
    Flush = 2,
}

/// One request, as it lies in the request ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// What to do.
    pub op: Op,
    /// Which registered frame holds the data.
    pub memory: u32,
    /// The first block.
    pub block: u64,
    /// Where the data starts in the frame, in bytes.
    pub offset: u32,
    /// How many blocks.
    pub blocks: u32,
    /// The client's tag.
    pub tag: u64,
}

impl Request {
    /// The record for the ring.
    pub fn encode(&self) -> [u8; REQUEST_BYTES] {
        let mut r = [0u8; REQUEST_BYTES];
        r[0] = self.op as u8;
        r[4..8].copy_from_slice(&self.memory.to_le_bytes());
        r[8..16].copy_from_slice(&self.block.to_le_bytes());
        r[16..20].copy_from_slice(&self.offset.to_le_bytes());
        r[20..24].copy_from_slice(&self.blocks.to_le_bytes());
        r[24..32].copy_from_slice(&self.tag.to_le_bytes());
        r
    }

    /// A record from the ring; `None` when its operation is none of [`Op`].
    /// The other fields are any values: the provider checks them against
    /// the device and the registered memory.
    pub fn decode(r: &[u8; REQUEST_BYTES]) -> Option<Request> {
        let word = |at: usize| u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
        let wide = |at: usize| word(at) as u64 | (word(at + 4) as u64) << 32;
        let op = match r[0] {
            0 => Op::Read,
            1 => Op::Write,
            2 => Op::Flush,
            _ => return None,
        };
        Some(Request { op, memory: word(4), block: wide(8), offset: word(16), blocks: word(20), tag: wide(24) })
    }
}

/// How a request ended, when not with success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The device reported an error reading or writing.
    Io = 1,
    /// The request is not one the device does, or is malformed: an unknown
    /// operation, blocks outside the device, data outside its frame, a
    /// frame that is not registered or not writable for a read, a write to
    /// a read-only device.
    Invalid = 2,
    /// The provider gave up on the device (it was reset or is gone); the
    /// request may or may not have taken effect.
    Aborted = 3,
}

/// One completion, as it lies in the completion ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The request's tag.
    pub tag: u64,
    /// `Ok`, or why not.
    pub status: Result<(), Status>,
}

impl Completion {
    /// The record for the ring.
    pub fn encode(&self) -> [u8; COMPLETION_BYTES] {
        silica_queue::Completion { tag: self.tag, status: self.status.map_or_else(|s| s as u32, |()| 0), value: 0 }.encode()
    }

    /// A record from the ring. A status this version does not know reads as
    /// [`Status::Aborted`].
    pub fn decode(r: &[u8; COMPLETION_BYTES]) -> Completion {
        Completion::from(silica_queue::Completion::decode(r))
    }
}

impl From<silica_queue::Completion> for Completion {
    fn from(c: silica_queue::Completion) -> Completion {
        let status = match c.status {
            0 => Ok(()),
            1 => Err(Status::Io),
            2 => Err(Status::Invalid),
            _ => Err(Status::Aborted),
        };
        Completion { tag: c.tag, status }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_survive_the_ring_and_garbage_is_not_a_request() {
        let q = Request { op: Op::Write, memory: 7, block: 0x1234_5678_9ABC, offset: 4096, blocks: 8, tag: u64::MAX - 1 };
        assert_eq!(Request::decode(&q.encode()), Some(q));
        let mut raw = q.encode();
        raw[0] = 3;
        assert_eq!(Request::decode(&raw), None);
        for status in [Ok(()), Err(Status::Io), Err(Status::Invalid), Err(Status::Aborted)] {
            let c = Completion { tag: 99, status };
            assert_eq!(Completion::decode(&c.encode()), c);
        }
        let mut raw = Completion { tag: 1, status: Ok(()) }.encode();
        raw[8] = 200;
        assert_eq!(Completion::decode(&raw).status, Err(Status::Aborted));
        // The rings fit the frame, one after the other.
        assert!(silica_ring::size(QUEUE, REQUEST_BYTES) <= COMPLETIONS_AT);
        assert!(COMPLETIONS_AT + silica_ring::size(QUEUE, COMPLETION_BYTES) <= 1 << RINGS_BITS);
    }
}
