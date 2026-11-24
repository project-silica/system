//! What a network driver takes from its client: request records, any 32
//! bytes, judged against an interface's description, any. Nothing may panic
//! or overflow; a record that decodes encodes to one that decodes the same;
//! and a transmit `Offload::allowed` lets through keeps inside its frame
//! every position the device will use, and asks only what the interface
//! said it does (silica_net's documentation of the data path).
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_net::device::Info;
use silica_net::{HEADER, OFFLOAD_CHECKSUM, OFFLOAD_TCP4_SEGMENT, Op, REQUEST_BYTES, Request};

fuzz_target!(|data: &[u8]| {
    let Some((head, records)) = data.split_first_chunk::<12>() else { return };
    let word = |at: usize| u32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
    let info = Info {
        address: 0,
        mtu: word(0) % 70_000,
        link_up: true,
        receive_bytes: 0,
        offloads: word(4) & 7,
        segment_bytes: word(8) % 140_000,
    };
    for raw in records.chunks_exact(REQUEST_BYTES) {
        let raw: &[u8; REQUEST_BYTES] = raw.try_into().unwrap();
        let Some(r) = Request::decode(raw) else { continue };
        assert_eq!(Request::decode(&r.encode()), Some(r));
        if r.op != Op::Transmit || !r.offload.allowed(r.length, &info) {
            continue;
        }
        let o = r.offload;
        if !o.segmentation {
            assert!(r.length <= info.mtu + HEADER);
        }
        if o.checksum {
            assert!(info.offloads & OFFLOAD_CHECKSUM != 0);
            assert!(u32::from(o.checksum_start) >= HEADER);
            assert!(u32::from(o.checksum_start) + u32::from(o.checksum_offset) + 2 <= r.length);
        }
        if o.segmentation {
            assert!(o.checksum && info.offloads & OFFLOAD_TCP4_SEGMENT != 0);
            assert!(r.length <= info.segment_bytes);
            let headers = u32::from(o.header_bytes);
            assert!(headers >= HEADER + 40 && headers < r.length && o.segment > 0);
            assert!(headers - HEADER + u32::from(o.segment) <= info.mtu);
        }
    }
});
