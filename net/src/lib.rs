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
//! | 1 | u8 | a transmit's offloads: 1 checksum, 2 TCP over IPv4 segmentation (0 for a receive) |
//! | 4 | u32 | memory: the number of a registered frame (`add_memory`) |
//! | 8 | u32 | offset in that frame, in bytes |
//! | 12 | u32 | length: of the frame to send, or of the buffer to receive into |
//! | 16 | u16 | checksum start: the first byte summed, from the frame's start |
//! | 18 | u16 | checksum offset: where the sum goes, from the checksum start |
//! | 20 | u16 | segment: the payload bytes of each frame cut from this one |
//! | 22 | u16 | header bytes: Ethernet, IPv4 and TCP headers, repeated in each |
//! | 24 | u64 | tag: the client's own, returned in the completion |
//!
//! A transmit sends the Ethernet frame at the offset (destination address
//! first, no frame check sequence), from 14 bytes to the MTU plus 14. With
//! the checksum offload (`Info::offloads` & 1, asked in the request's byte
//! 1), the device takes the 16-bit ones' complement sum of the bytes
//! from the checksum start to the frame's end, the 16 bits at the checksum
//! offset holding the pseudo-header's sum, and puts its complement there:
//! for TCP, start 34 and offset 16 (IPv4 without options). With
//! segmentation (& 2, which needs the checksum too), the frame may be up to
//! `Info::segment_bytes`: the device cuts what follows its first `header
//! bytes` into payloads of `segment` bytes (the last shorter) and sends each
//! behind those headers, with the IPv4 total length, identification and
//! header checksum and the TCP sequence number, flags (FIN and PSH on the
//! last only) and checksum made right for it; the pseudo-header sum in the
//! request's TCP checksum is the one of the whole frame's TCP length. A
//! request that asks what the interface did not offer, or whose positions
//! fall outside the frame, is refused (`Status::Invalid`). A
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
pub mod tcp;

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
    /// What a transmit asks the device to do for it.
    pub offload: Offload,
}

/// Offloads (`Info::offloads` bits).
pub const OFFLOAD_CHECKSUM: u32 = 1;
pub const OFFLOAD_TCP4_SEGMENT: u32 = 2;

/// What a transmit asks of the device: a checksum and segmentation, or
/// neither ([`Offload::NONE`]). The positions are from the frame's start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Offload {
    pub checksum: bool,
    pub segmentation: bool,
    pub checksum_start: u16,
    pub checksum_offset: u16,
    pub segment: u16,
    pub header_bytes: u16,
}

impl Offload {
    pub const NONE: Offload =
        Offload { checksum: false, segmentation: false, checksum_start: 0, checksum_offset: 0, segment: 0, header_bytes: 0 };

    /// Whether a transmit of `length` bytes may ask this of an interface
    /// with `info`: only offloads it has, positions inside the frame,
    /// segmentation of a frame with whole Ethernet, IPv4 and TCP headers,
    /// at most `segment_bytes` long, in pieces that fit the MTU.
    pub fn allowed(&self, length: u32, info: &device::Info) -> bool {
        if !self.checksum {
            return !self.segmentation && length <= info.mtu.saturating_add(HEADER);
        }
        let start = u32::from(self.checksum_start);
        let checksum_fits =
            info.offloads & OFFLOAD_CHECKSUM != 0 && start >= HEADER && start + u32::from(self.checksum_offset) + 2 <= length;
        if !self.segmentation {
            return checksum_fits && length <= info.mtu.saturating_add(HEADER);
        }
        let headers = u32::from(self.header_bytes);
        checksum_fits
            && info.offloads & OFFLOAD_TCP4_SEGMENT != 0
            && length <= info.segment_bytes
            && headers >= HEADER + 40
            && headers < length
            && self.segment > 0
            && headers - HEADER + u32::from(self.segment) <= info.mtu
    }
}

impl Request {
    /// The record for the ring.
    pub fn encode(&self) -> [u8; REQUEST_BYTES] {
        let mut r = [0u8; REQUEST_BYTES];
        r[0] = self.op as u8;
        r[1] = u8::from(self.offload.checksum) | u8::from(self.offload.segmentation) << 1;
        r[4..8].copy_from_slice(&self.memory.to_le_bytes());
        r[8..12].copy_from_slice(&self.offset.to_le_bytes());
        r[12..16].copy_from_slice(&self.length.to_le_bytes());
        r[16..18].copy_from_slice(&self.offload.checksum_start.to_le_bytes());
        r[18..20].copy_from_slice(&self.offload.checksum_offset.to_le_bytes());
        r[20..22].copy_from_slice(&self.offload.segment.to_le_bytes());
        r[22..24].copy_from_slice(&self.offload.header_bytes.to_le_bytes());
        r[24..32].copy_from_slice(&self.tag.to_le_bytes());
        r
    }

    /// A record from the ring; `None` when its operation is none of [`Op`].
    pub fn decode(r: &[u8; REQUEST_BYTES]) -> Option<Request> {
        let word = |at: usize| u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
        let half = |at: usize| u16::from_le_bytes([r[at], r[at + 1]]);
        let op = match r[0] {
            0 => Op::Transmit,
            1 => Op::Receive,
            _ => return None,
        };
        // Bits beyond the two offloads, or offloads on a receive: not a request.
        if r[1] > 3 || (op == Op::Receive && r[1] != 0) {
            return None;
        }
        let offload = Offload {
            checksum: r[1] & 1 != 0,
            segmentation: r[1] & 2 != 0,
            checksum_start: half(16),
            checksum_offset: half(18),
            segment: half(20),
            header_bytes: half(22),
        };
        Some(Request { op, memory: word(4), offset: word(8), length: word(12), tag: silica_queue::tag_of(r), offload })
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
        let q = Request { op: Op::Receive, memory: 3, offset: 2048, length: 1514, tag: 77, offload: Offload::NONE };
        assert_eq!(Request::decode(&q.encode()), Some(q));
        let mut raw = q.encode();
        raw[0] = 9;
        assert_eq!(Request::decode(&raw), None);
        let c = silica_queue::Completion { tag: 5, status: 0, value: 60 };
        assert_eq!(Completion::from(c), Completion { tag: 5, result: Ok(60) });
        let c = silica_queue::Completion { tag: 5, status: 77, value: 0 };
        assert_eq!(Completion::from(c).result, Err(Status::Aborted));
    }

    fn tso() -> Offload {
        Offload { checksum: true, segmentation: true, checksum_start: 34, checksum_offset: 16, segment: 1448, header_bytes: 66 }
    }

    fn info(offloads: u32) -> device::Info {
        device::Info { address: 0, mtu: 1500, link_up: true, receive_bytes: 1514, offloads, segment_bytes: 65535 }
    }

    #[test]
    fn a_transmit_carries_its_offloads_and_a_receive_none() {
        let t = Request { op: Op::Transmit, memory: 1, offset: 0, length: 60_000, tag: 9, offload: tso() };
        assert_eq!(Request::decode(&t.encode()), Some(t));
        let mut raw = t.encode();
        raw[1] = 4;
        assert_eq!(Request::decode(&raw), None, "an offload bit no version has");
        raw[0] = Op::Receive as u8;
        raw[1] = 1;
        assert_eq!(Request::decode(&raw), None, "a receive with an offload");
    }

    #[test]
    fn only_what_the_interface_offers_and_only_inside_the_frame() {
        let all = info(OFFLOAD_CHECKSUM | OFFLOAD_TCP4_SEGMENT);
        assert!(Offload::NONE.allowed(1514, &info(0)));
        assert!(!Offload::NONE.allowed(1515, &all), "longer than the MTU without segmentation");
        let sum = Offload { segmentation: false, segment: 0, header_bytes: 0, ..tso() };
        assert!(sum.allowed(1514, &all));
        assert!(!sum.allowed(1514, &info(0)), "a checksum the interface does not do");
        assert!(!sum.allowed(51, &all), "its position past the frame's end");
        assert!(!Offload { checksum_start: 10, ..sum }.allowed(1514, &all), "a start inside the Ethernet header");
        assert!(tso().allowed(65535, &all));
        assert!(!tso().allowed(65536, &all), "longer than segment_bytes");
        assert!(!tso().allowed(65535, &info(OFFLOAD_CHECKSUM)), "segmentation the interface does not do");
        assert!(!Offload { checksum: false, ..tso() }.allowed(65535, &all), "segmentation without the checksum");
        assert!(!Offload { segment: 1449, ..tso() }.allowed(65535, &all), "pieces longer than the MTU");
        assert!(!Offload { segment: 0, ..tso() }.allowed(65535, &all));
        assert!(!Offload { header_bytes: 53, ..tso() }.allowed(65535, &all), "no room for IPv4 and TCP headers");
        assert!(!Offload { header_bytes: 66, ..tso() }.allowed(66, &all), "headers and no payload");
    }
}
