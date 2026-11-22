//! The network interface class (`silica.net.Device`): the data path's
//! records, a client, and the service every network driver provides.
//!
//! # The data path
//!
//! After `connect`, requests and completions travel through the two rings
//! every device class shares (`silica_queue` documents them). A request
//! ([`Request`], little-endian):
//!
//! | offset | type | field |
//! | --- | --- | --- |
//! | 0 | u8 | operation: 0 transmit, 1 receive |
//! | 4 | u32 | memory: the number of a registered frame (`add_memory`) |
//! | 8 | u32 | offset in that frame, in bytes |
//! | 12 | u32 | length: of the frame to send, or of the buffer to receive into |
//! | 24 | u64 | tag: the client's own, returned in the completion |
//!
//! A transmit sends the Ethernet frame at the offset (destination address
//! first, no frame check sequence), from 14 bytes to the MTU plus 14. A
//! receive offers a buffer of at least the MTU plus 14 bytes in writable
//! memory; it completes when a frame has arrived in it, with the frame's
//! length as the completion's value. A completion's status is 0 or a
//! [`Status`].
//!
//! The provider also adds records that answer no request: a tag of
//! [`LINK`] says the link went up (value 1) or down (value 0).
//!
//! Frames are never copied between the client and the device: the device
//! reads what it sends from the client's memory and writes what it
//! receives into it. The client leaves a request's bytes alone until its
//! completion arrives.
#![no_std]
#![deny(unsafe_code)]

pub mod client;
pub mod service;

include!(concat!(env!("OUT_DIR"), "/silica_net_device.rs"));

pub use silica_queue::{COMPLETION_BYTES, MEMORIES, QUEUE, REQUEST_BYTES};

/// The tag of a link record: the link went up (value 1) or down (value 0).
pub const LINK: u64 = silica_queue::client::EVENTS | 1;
/// An Ethernet header's bytes: two addresses and the type.
pub const HEADER: u32 = 14;

/// What a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Send the frame.
    Transmit = 0,
    /// Fill the buffer with the next frame that arrives.
    Receive = 1,
}

/// One request, as it lies in the request ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// What to do.
    pub op: Op,
    /// Which registered frame holds the bytes.
    pub memory: u32,
    /// Where they start in the frame.
    pub offset: u32,
    /// How many: the frame's length, or the buffer's.
    pub length: u32,
    /// The client's tag (below 2^63).
    pub tag: u64,
}

impl Request {
    /// The record for the ring.
    pub fn encode(&self) -> [u8; REQUEST_BYTES] {
        let mut r = [0u8; REQUEST_BYTES];
        r[0] = self.op as u8;
        r[4..8].copy_from_slice(&self.memory.to_le_bytes());
        r[8..12].copy_from_slice(&self.offset.to_le_bytes());
        r[12..16].copy_from_slice(&self.length.to_le_bytes());
        r[24..32].copy_from_slice(&self.tag.to_le_bytes());
        r
    }

    /// A record from the ring; `None` when its operation is none of [`Op`].
    pub fn decode(r: &[u8; REQUEST_BYTES]) -> Option<Request> {
        let word = |at: usize| u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
        let op = match r[0] {
            0 => Op::Transmit,
            1 => Op::Receive,
            _ => return None,
        };
        Some(Request { op, memory: word(4), offset: word(8), length: word(12), tag: silica_queue::tag_of(r) })
    }
}

/// How a request ended, when not with success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The device reported an error sending or receiving.
    Io = 1,
    /// The request is malformed: an unknown operation, bytes outside their
    /// frame, a frame shorter than a header or longer than the MTU allows,
    /// a receive buffer that is not writable or too short for a frame.
    Invalid = 2,
    /// The provider gave up on the request.
    Aborted = 3,
}

/// One completion, as it lies in the completion ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The request's tag (or [`LINK`]).
    pub tag: u64,
    /// For a receive, the frame's length; for a link record, whether the
    /// link is up; or why the request failed.
    pub result: Result<u32, Status>,
}

impl From<silica_queue::Completion> for Completion {
    fn from(c: silica_queue::Completion) -> Completion {
        let result = match c.status {
            0 => Ok(c.value),
            1 => Err(Status::Io),
            2 => Err(Status::Invalid),
            _ => Err(Status::Aborted),
        };
        Completion { tag: c.tag, result }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_survive_the_ring_and_garbage_is_not_a_request() {
        let q = Request { op: Op::Receive, memory: 3, offset: 2048, length: 1514, tag: 77 };
        assert_eq!(Request::decode(&q.encode()), Some(q));
        let mut raw = q.encode();
        raw[0] = 9;
        assert_eq!(Request::decode(&raw), None);
        let c = silica_queue::Completion { tag: 5, status: 0, value: 60 };
        assert_eq!(Completion::from(c), Completion { tag: 5, result: Ok(60) });
        let c = silica_queue::Completion { tag: 5, status: 77, value: 0 };
        assert_eq!(Completion::from(c).result, Err(Status::Aborted));
    }
}
