//! An 82574 writes back the descriptors of its driver's rings (each one's
//! length, status and errors), and may write anything anywhere in them. The
//! fuzzer plays that device against the driver's own code (`e1000e`'s
//! library), mixing an honest device's moves (write back the oldest
//! descriptor it was given, done and ending a frame, with a length a frame
//! can have) with a hostile one's (any byte anywhere in the ring), while the
//! driver gives descriptors and takes finished ones back. Given any input:
//!
//! - nothing panics or reads outside its memory;
//! - the driver never holds more descriptors than the ring allows (one less
//!   than its size), and refuses one more when it holds that many;
//! - it takes back only requests it gave, in the order given, each once;
//! - a frame it accepts (`receive` says `Ok(Ok(length))`) has a length from
//!   a header (14 bytes) to the buffer (2048), ended in its descriptor, with
//!   no receive error, and the length is the one the device wrote;
//! - an honest device never makes it give up, and every frame it writes
//!   back is accepted.
//!
//! Each input byte is a move: give descriptors, let the honest device write
//! some back, take them back, or a hostile write (its offset and value from
//! the next bytes).
#![no_main]

use e1000e::{DD, DESC, RECEIVE_BYTES, RING, RX_EOP, RX_ERRORS, Ring, receive};
use libfuzzer_sys::fuzz_target;
use silica_rt::mmio::Mmio;
use std::collections::VecDeque;

/// Memory shared with the device, zeroed, 8-byte aligned.
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

fuzz_target!(|data: &[u8]| {
    let area = Area::new(RING * DESC);
    let words = area.mmio();
    let mut ring: Ring<u32> = Ring::over(area.mmio()).expect("a ring that fits");
    // What the driver gave and has not taken back, oldest first; the next
    // ticket; how many of the given the honest device has written back.
    let (mut given, mut ticket, mut written) = (VecDeque::new(), 0u32, 0usize);
    let mut hostile = false;
    let mut bytes = data.iter().copied();
    while let Some(op) = bytes.next() {
        let n = usize::from(op >> 2) + 1;
        match op & 3 {
            // The driver gives up to n descriptors.
            0 => {
                for _ in 0..n {
                    let full = ring.holding() == RING - 1;
                    let took = ring.add(0x1000 * u64::from(ticket), 0, 0, ticket, 0);
                    assert_eq!(took, !full, "a descriptor given to a full ring, or refused by one that is not");
                    if took {
                        given.push_back(ticket);
                        ticket += 1;
                    }
                }
            }
            // The honest device writes back up to n, in order: done, ending a
            // frame, a frame's length (from the next byte), no error.
            1 => {
                for _ in 0..n {
                    if written == given.len() {
                        break;
                    }
                    let at = ((ring.next + written) % RING) * DESC;
                    let length = (14 + u16::from(bytes.next().unwrap_or(0)) * 8).min(RECEIVE_BYTES as u16);
                    words.write16(at + 8, length);
                    words.write8(at + 13, 0);
                    words.write8(at + 12, DD | RX_EOP);
                    written += 1;
                }
            }
            // The driver takes back what is done, up to n.
            2 => {
                for _ in 0..n {
                    let Some(d) = ring.pop() else { break };
                    let oldest = given.pop_front().expect("taken back with nothing given");
                    assert_eq!(d.ticket, oldest, "taken back out of order, or twice");
                    written = written.saturating_sub(1);
                    match receive(&d) {
                        Ok(Ok(length)) => {
                            assert!((14..=RECEIVE_BYTES).contains(&length), "a frame of {length} bytes accepted");
                            assert_eq!(length, u32::from(d.length));
                            assert!(d.status & RX_EOP != 0 && d.errors & RX_ERRORS == 0, "an unterminated or errored frame accepted");
                        }
                        Ok(Err(())) => assert!(hostile, "an honest device's frame reported as an error"),
                        Err(_) => assert!(hostile, "an honest device given up on"),
                    }
                }
            }
            // The hostile device writes a byte anywhere in the ring.
            _ => {
                let (Some(lo), Some(hi), Some(value)) = (bytes.next(), bytes.next(), bytes.next()) else { break };
                let at = usize::from(u16::from_le_bytes([lo, hi])) % (RING * DESC);
                words.write8(at, value);
                hostile = true;
            }
        }
        assert!(ring.holding() < RING, "holding {} of a ring of {RING}", ring.holding());
        assert_eq!(ring.holding(), given.len(), "the driver and the record disagree about what the device holds");
    }
});
