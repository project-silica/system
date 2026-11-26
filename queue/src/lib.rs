//! The data path every device class shares (`silica.block.Device`,
//! `silica.net.Device`): what is the same about moving requests to a
//! provider and completions back, whatever the requests ask for.
//!
//! # The rings
//!
//! After a class's `connect`, requests and completions travel through two
//! rings (`silica_rt::ring`) in the 16 KiB frame the client shared:
//!
//! | bytes | what |
//! | --- | --- |
//! | 0 to 8255 | the request ring: [`QUEUE`] records of 32 bytes, client to provider |
//! | 8256 to 8319 | unused |
//! | 8320 to 12479 | the completion ring: [`QUEUE`] records of 16 bytes, provider to client |
//!
//! Every class lays its request records out its own way, with two fields
//! in the same place: the number of the registered frame the data is in
//! (u32 at byte 4; `u32::MAX` for a request with no data), and the client's
//! tag (u64 at byte 24). A completion is the tag (u64), a status (u32; 0 is
//! success, any other value the class's own), and a value of the class's
//! (u32: a received frame's length, for example).
//!
//! Every request gets exactly one completion, in any order. The client
//! keeps at most [`QUEUE`] requests in progress, so the completion ring
//! cannot overflow. Either side signals the other's notification after
//! adding records only when the other said it was going to sleep
//! (`silica_rt::ring`'s wake-up rule).
//!
//! Data is never copied: the device reads and writes the client's
//! registered frames in place. The client leaves the bytes of a request
//! alone until its completion arrives.
//!
//! [`provider`] is the provider's half, which a class's service builds on;
//! [`client`] the client's, which outlives the provider.
#![no_std]
#![deny(unsafe_code)]

pub mod client;
pub mod provider;

/// Records in each ring, and so the most requests in progress.
pub const QUEUE: u32 = 256;
/// Size in bits of the frame holding both rings.
pub const RINGS_BITS: u8 = 14;
/// Where the completion ring starts in that frame.
pub const COMPLETIONS_AT: usize = 8320;
/// Bytes of a request record.
pub const REQUEST_BYTES: usize = 32;
/// Bytes of a completion record.
pub const COMPLETION_BYTES: usize = 16;
/// Most frames a client registers (memory numbers are below this).
pub const MEMORIES: u32 = 64;
/// The memory number of a request with no data.
pub const NO_MEMORY: u32 = u32::MAX;

/// A provider's events (a class's news that answers no request, such as a
/// network link going up) are not records in the completion ring but state:
/// a slot each, at the end of the rings' frame, holding the latest of its
/// kind. The completion ring holds [`QUEUE`] records, as many as a client
/// may have requests in flight, so every completion has its place whatever
/// happened meanwhile. (Before, events were completion records: one posted
/// while the ring had room took the place a completion needed later, the
/// completion was dropped and its client waited for it for ever: the
/// 2026-11-24 audit.)
///
/// A slot is 32 bytes: a sequence word (odd while the provider writes the
/// slot, even and higher after each event), the tag, the status and the
/// value. A client takes a slot whose sequence is even and moved since it
/// last looked, read twice the same around the fields.
pub const EVENT_SLOTS: usize = 8;
/// Bytes of an event slot.
pub const EVENT_BYTES: usize = 32;
/// Where the event slots start in the rings' frame.
pub const EVENTS_AT: usize = (1 << RINGS_BITS) - EVENT_SLOTS * EVENT_BYTES;
const _: () = assert!(
    COMPLETIONS_AT >= silica_rt::ring::size(QUEUE, REQUEST_BYTES)
        && EVENTS_AT >= COMPLETIONS_AT + silica_rt::ring::size(QUEUE, COMPLETION_BYTES)
);

/// A request record as it lies in the ring.
pub type Raw = [u8; REQUEST_BYTES];

/// The tag of a request record.
pub fn tag_of(r: &Raw) -> u64 {
    u64::from_le_bytes([r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31]])
}

/// The memory number of a request record.
pub fn memory_of(r: &Raw) -> u32 {
    u32::from_le_bytes([r[4], r[5], r[6], r[7]])
}

/// One completion, as it lies in the completion ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The request's tag.
    pub tag: u64,
    /// 0 for success, else the class's own status.
    pub status: u32,
    /// The class's value (a length), or 0.
    pub value: u32,
}

impl Completion {
    /// The record for the ring.
    pub fn encode(&self) -> [u8; COMPLETION_BYTES] {
        let mut r = [0u8; COMPLETION_BYTES];
        r[0..8].copy_from_slice(&self.tag.to_le_bytes());
        r[8..12].copy_from_slice(&self.status.to_le_bytes());
        r[12..16].copy_from_slice(&self.value.to_le_bytes());
        r
    }

    /// A record from the ring.
    pub fn decode(r: &[u8; COMPLETION_BYTES]) -> Completion {
        let word = |at: usize| u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
        Completion { tag: word(0) as u64 | (word(4) as u64) << 32, status: word(8), value: word(12) }
    }
}

/// Why the provider refused a call, the same for every class (each class's
/// IDL error has these values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Another client is connected, or this one already is.
    Busy = 1,
    /// `connect` has not been called.
    NotConnected = 2,
    /// The capability is not a frame of a usable size, or the number is in
    /// use or names nothing.
    BadMemory = 3,
    /// The provider has no room for more.
    NoRoom = 4,
    /// Requests that use the memory are still in progress.
    InUse = 5,
    /// Outside what the capability reaches.
    Outside = 6,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_completion_reads_back_as_written() {
        let c = Completion { tag: 0x0102_0304_0506_0708, status: 3, value: 1514 };
        assert_eq!(Completion::decode(&c.encode()), c);
    }
}
