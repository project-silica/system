//! What the e1000e driver reads from its device, as a library: a ring of
//! legacy descriptors (the device writes back each one's length and status)
//! and what a received descriptor says. The driver (`main.rs`) puts the
//! rings in DMA memory; the fuzz target (`fuzz/`) plays a hostile device
//! against them in host memory. Nothing here allocates device memory or
//! makes a system call.
//!
//! The device is not trusted: a descriptor is taken back only in the order
//! given and only once, and a received one is judged by [`receive`] before
//! anything is done with what it says.
#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use silica_driver::dma;
use silica_rt::mmio::Mmio;

/// Bytes of a legacy descriptor.
pub const DESC: usize = 16;
/// Descriptors in each ring (a multiple of 8; one page).
pub const RING: usize = 256;
/// What the device may write into each receive buffer (RCTL.BSIZE 2048).
pub const RECEIVE_BYTES: u32 = 2048;
/// The shortest frame: an Ethernet header.
pub const HEADER: u32 = 14;

/// Transmit command: end of packet, insert the frame check sequence, report
/// status (write the descriptor back when sent).
pub const TX_EOP: u8 = 1 << 0;
pub const TX_IFCS: u8 = 1 << 1;
pub const TX_RS: u8 = 1 << 3;
/// Status: the descriptor is done; (receive) it ends a frame.
pub const DD: u8 = 1 << 0;
pub const RX_EOP: u8 = 1 << 1;
/// Receive errors that make a frame no frame: CRC, symbol, sequence,
/// carrier extension, data.
pub const RX_ERRORS: u8 = 0x01 | 0x02 | 0x04 | 0x10 | 0x80;

/// One ring of descriptors in `words` and the requests in them (with when
/// each was given), the oldest at `next`.
pub struct Ring<T> {
    words: Mmio,
    slots: Vec<Option<(T, u64)>>,
    /// The next descriptor to fill (the tail the device is told).
    pub tail: usize,
    /// The oldest descriptor the device has.
    pub next: usize,
    /// Descriptors filled since the device was last told.
    pub added: bool,
}

/// A descriptor the device wrote back: its request, the length and the
/// status and error bytes it wrote.
#[derive(Clone, Copy, Debug)]
pub struct Done<T> {
    pub ticket: T,
    pub length: u16,
    pub status: u8,
    pub errors: u8,
}

/// Why a device cannot be relied on, from what it wrote back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    /// A frame that claims to continue past its buffer (long frames are off).
    Continues,
    /// A frame longer than its buffer.
    TooLong,
}

impl Broken {
    pub fn why(self) -> &'static str {
        match self {
            Broken::Continues => "a frame that continues past its buffer (long frames are off)",
            Broken::TooLong => "a frame longer than its buffer",
        }
    }
}

/// What a received descriptor says: the frame's length (`Ok(Ok)`), a frame
/// to be reported as an I/O error (`Ok(Err)`: receive errors, or shorter
/// than a header), or a device that broke its specification (`Err`).
pub fn receive<T>(d: &Done<T>) -> Result<Result<u32, ()>, Broken> {
    let length = u32::from(d.length);
    if d.status & RX_EOP == 0 {
        return Err(Broken::Continues);
    }
    if length > RECEIVE_BYTES {
        return Err(Broken::TooLong);
    }
    Ok(if d.errors & RX_ERRORS != 0 || length < HEADER { Err(()) } else { Ok(length) })
}

impl<T: Copy> Ring<T> {
    /// A ring in `words` (at least [`RING`] descriptors), empty.
    pub fn over(words: Mmio) -> Option<Ring<T>> {
        (words.len() >= RING * DESC).then(|| Ring { words, slots: (0..RING).map(|_| None).collect(), tail: 0, next: 0, added: false })
    }

    /// Descriptors the device has: given, not yet taken back.
    pub fn holding(&self) -> usize {
        (self.tail + RING - self.next) % RING
    }

    /// When the oldest request the device holds was given: the one at
    /// `next` (the device takes them in order), without a walk.
    pub fn oldest(&self) -> Option<u64> {
        (self.holding() != 0).then(|| self.slots[self.next].map(|(_, at)| at)).flatten()
    }

    /// When each request the device holds was given.
    pub fn given(&self) -> impl Iterator<Item = u64> + '_ {
        self.slots.iter().flatten().map(|(_, at)| *at)
    }

    /// Put a buffer in the next descriptor (given at `at`): `false` when
    /// every one but the last is in use (a full ring and an empty one look
    /// the same to the device: tail equal to head).
    pub fn add(&mut self, address: u64, length: u16, command: u8, ticket: T, at: u64) -> bool {
        if self.holding() == RING - 1 {
            return false;
        }
        let o = self.tail * DESC;
        self.words.write64(o, address);
        self.words.write16(o + 8, length);
        self.words.write8(o + 10, 0);
        self.words.write8(o + 11, command);
        // The status cleared: a done bit the device left in a descriptor it
        // did not have is never read.
        self.words.write32(o + 12, 0);
        self.slots[self.tail] = Some((ticket, at));
        self.tail = (self.tail + 1) % RING;
        self.added = true;
        true
    }

    /// The oldest descriptor, if the device has written it back.
    pub fn pop(&mut self) -> Option<Done<T>> {
        if self.next == self.tail {
            return None;
        }
        let o = self.next * DESC;
        let status = self.words.read8(o + 12);
        if status & DD == 0 {
            return None;
        }
        // The rest of the descriptor is read after its done bit.
        dma::read_barrier();
        let length = self.words.read16(o + 8);
        let errors = self.words.read8(o + 13);
        let (ticket, _) = self.slots[self.next].take()?;
        self.next = (self.next + 1) % RING;
        Some(Done { ticket, length, status, errors })
    }
}
