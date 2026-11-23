//! TCP for programs: the client of `silica.net.Tcp`, the network stack's
//! protocol.
//!
//! A program makes one [`Tcp`]: it lends the stack memory once, in which
//! each connection takes a block, and it has one notification, signalled
//! for every connection and listener, that the program waits on
//! ([`Tcp::wait`]). A connection is a [`Stream`]: bytes in and out through
//! shared memory, with no call to the stack while both sides are busy.
//!
//! An echo server, whole:
//!
//! ```no_run
//! use silica_net::tcp::{Failure, Read, Tcp};
//!
//! fn echo(stack: silica_rt::sys::Cap) -> Result<(), Failure> {
//!     let mut tcp = Tcp::new(stack, 20)?; // 1 MiB: 16 connections of 64 KiB
//!     let listener = tcp.listen(7, 16)?;
//!     let mut streams = Vec::new();
//!     let mut buf = [0u8; 4096];
//!     loop {
//!         while let Some(s) = tcp.accept(listener)? {
//!             streams.push(s);
//!         }
//!         let mut moved = false;
//!         for s in streams.iter_mut() {
//!             // (A real server keeps what did not fit and sends it later.)
//!             if let Ok(Read::Bytes(n)) = s.read(&mut buf) {
//!                 s.write(&buf[..n]);
//!                 moved = true;
//!             }
//!         }
//!         // Before waiting, each stream is told so, or its bytes would
//!         // not wake this program.
//!         if !moved && streams.iter_mut().all(|s| s.sleep_read()) {
//!             tcp.wait(None);
//!         }
//!     }
//! }
//! ```
//!
//! Reading takes bytes as they come ([`Stream::read`]: `Bytes`, `Empty` or
//! `Closed` with the reason the stack gave); writing takes what fits
//! ([`Stream::write`]). Before waiting, a program asks each stream it waits
//! for whether it may ([`Stream::sleep_read`], [`Stream::sleep_write`]), so
//! that the stack signals it when that stream changes.

use silica_protocols::net::tcp::{self as proto, Endpoint};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::{Memory, Object};
use silica_rt::ring::{STREAM_HEADER, StreamConsumer, StreamProducer};
use silica_rt::sys::{self, Cap, ObjectType, Rights, Wait};

pub use proto::{Endpoint as Peer, Error, Reason};
pub use silica_rt::ring::{Broken, Read};

/// Why a call to the stack failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The stack refused, saying why.
    Refused(Error),
    /// The stack did not answer as its protocol says (or is gone).
    Stack,
    /// This program has no memory or capability slots left for it, or
    /// every block of its memory is in use.
    NoRoom,
}

impl From<silica_idl_rt::CallError<Error>> for Failure {
    fn from(e: silica_idl_rt::CallError<Error>) -> Failure {
        match e {
            silica_idl_rt::CallError::Error(e) => Failure::Refused(e),
            silica_idl_rt::CallError::Transport(_) => Failure::Stack,
        }
    }
}

/// A program's TCP: its memory lent to the stack, cut in blocks, and its
/// notification.
pub struct Tcp {
    stack: proto::Client<Channel, Handle>,
    memory: Memory,
    /// Each block's size in bits, and which are free.
    block_bits: u8,
    free: Vec<u64>,
    note: Object,
}

/// A connection.
pub struct Stream {
    id: u32,
    offset: u64,
    rx: StreamConsumer,
    tx: StreamProducer,
    /// What signals the stack for this connection.
    requests: Handle,
    /// The peer, for an accepted connection.
    pub peer: Option<Endpoint>,
}

impl Tcp {
    /// TCP through the stack behind `stack` (a capability to its
    /// endpoint), with 2^`memory_bits` bytes of memory (16 to 28) cut in
    /// blocks of 64 KiB: a connection each, with a little under 32 KiB of
    /// stream each way.
    pub fn new(stack: Cap, memory_bits: u8) -> Result<Tcp, Failure> {
        Tcp::with_blocks(stack, memory_bits, 16)
    }

    /// As [`Tcp::new`], blocks of 2^`block_bits` bytes (12 to 24, at most
    /// `memory_bits`).
    pub fn with_blocks(stack: Cap, memory_bits: u8, block_bits: u8) -> Result<Tcp, Failure> {
        if !(12..=24).contains(&block_bits) || block_bits > memory_bits {
            return Err(Failure::Refused(Error::BadMemory));
        }
        let mut stack = proto::Client::<Channel, Handle>::from(Channel::new(stack));
        let memory = Memory::new(memory_bits).map_err(|_| Failure::NoRoom)?;
        let note = Object::new(ObjectType::Notification, 0).map_err(|_| Failure::NoRoom)?;
        stack.add_memory(lend(memory.frame(), Rights(Rights::READ.0 | Rights::WRITE.0), 0)?)?;
        let blocks = 1usize << (memory_bits - block_bits);
        let mut free = silica_rt::alloc::vec![0u64; blocks.div_ceil(64)];
        for b in 0..blocks {
            free[b / 64] |= 1 << (b % 64);
        }
        Ok(Tcp { stack, memory, block_bits, free, note })
    }

    /// Listen on `port`, keeping up to `backlog` connections waiting to be
    /// accepted. The listener's number.
    pub fn listen(&mut self, port: u16, backlog: u32) -> Result<u32, Failure> {
        let ready = lend(self.note.cap(), Rights::WRITE, 1)?;
        Ok(self.stack.listen(port, backlog, ready)?.listener)
    }

    /// The next connection waiting on `listener`, if one is.
    pub fn accept(&mut self, listener: u32) -> Result<Option<Stream>, Failure> {
        let (block, offset) = self.block()?;
        let wake = lend(self.note.cap(), Rights::WRITE, 1 << (1 + block % 63))?;
        match self.stack.accept(listener, offset, self.block_bits, wake) {
            Ok(r) => {
                let peer = r.peer;
                self.stream(r.connection, offset, r.requests, Some(peer)).map(Some)
            }
            Err(e) => {
                self.give_back(offset);
                match Failure::from(e) {
                    Failure::Refused(Error::WouldBlock) => Ok(None),
                    f => Err(f),
                }
            }
        }
    }

    /// Connect to `peer`; the stream may be written at once.
    pub fn connect(&mut self, peer: Endpoint) -> Result<Stream, Failure> {
        let (block, offset) = self.block()?;
        let wake = lend(self.note.cap(), Rights::WRITE, 1 << (1 + block % 63))?;
        match self.stack.connect(peer, offset, self.block_bits, wake) {
            Ok(r) => self.stream(r.connection, offset, r.requests, None),
            Err(e) => {
                self.give_back(offset);
                Err(e.into())
            }
        }
    }

    /// Let go of a connection: reset unless both ends finished in order.
    /// Its block is free again.
    pub fn close(&mut self, s: Stream) -> Result<(), Failure> {
        let r = self.stack.close(s.id);
        self.give_back(s.offset);
        r.map(|_| ()).map_err(Into::into)
    }

    /// Wait until the stack signals (a connection changed, or one is
    /// waiting to be accepted), or until `deadline` (monotonic ns).
    pub fn wait(&mut self, deadline: Option<u64>) {
        let _ = sys::recv(self.note.cap(), deadline.map_or(Wait::Forever, Wait::Until));
    }

    /// A free block: its number and offset, zeroed.
    fn block(&mut self) -> Result<(usize, u64), Failure> {
        let w = self.free.iter().position(|w| *w != 0).ok_or(Failure::NoRoom)?;
        let b = w * 64 + self.free[w].trailing_zeros() as usize;
        self.free[w] &= !(1 << (b % 64));
        let offset = (b as u64) << self.block_bits;
        let m = self.memory.shared();
        for at in (offset as usize..(offset as usize + (1 << self.block_bits))).step_by(8) {
            m.write64(at, 0);
        }
        Ok((b, offset))
    }

    fn give_back(&mut self, offset: u64) {
        let b = (offset >> self.block_bits) as usize;
        self.free[b / 64] |= 1 << (b % 64);
    }

    fn stream(&mut self, id: u32, offset: u64, requests: Handle, peer: Option<Endpoint>) -> Result<Stream, Failure> {
        let size = 1usize << self.block_bits;
        let m = self.memory.shared();
        let c = (size - 2 * STREAM_HEADER) / 2;
        let at = offset as usize;
        let part = |o: usize, n: usize| m.part(at + o, n).ok_or(Failure::Stack);
        let rx = StreamConsumer::new(part(0, STREAM_HEADER)?, part(2 * STREAM_HEADER, c)?).ok_or(Failure::Stack)?;
        let tx = StreamProducer::new(part(STREAM_HEADER, STREAM_HEADER)?, part(2 * STREAM_HEADER + c, c)?).ok_or(Failure::Stack)?;
        Ok(Stream { id, offset, rx, tx, requests, peer })
    }
}

impl Stream {
    /// Take bytes that arrived: `Bytes(n)`, `Empty` (nothing yet) or
    /// `Closed` (nothing more will come; `Reason::Finished.raw()` when the
    /// peer finished in order).
    pub fn read(&mut self, out: &mut [u8]) -> Result<Read, Broken> {
        let r = self.rx.read(out)?;
        if matches!(r, Read::Bytes(_)) && self.rx.room_needed() {
            let _ = sys::signal(self.requests.cap());
        }
        Ok(r)
    }

    /// Send what fits of `bytes`; returns how much did (0: wait for room).
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        let n = self.tx.write(bytes);
        if n > 0 && self.tx.wake_needed() {
            let _ = sys::signal(self.requests.cap());
        }
        n
    }

    /// Nothing more will be sent: a FIN follows what was.
    pub fn finish(&mut self) {
        self.tx.close(0);
        if self.tx.wake_needed() {
            let _ = sys::signal(self.requests.cap());
        }
    }

    /// Before waiting for bytes to read: `false` when some are there now.
    pub fn sleep_read(&mut self) -> bool {
        self.rx.sleep()
    }

    /// Before waiting for room to write: `false` when there is some now.
    pub fn sleep_write(&mut self) -> bool {
        self.tx.sleep_for_room()
    }
}

fn lend(cap: Cap, rights: Rights, badge: u64) -> Result<Handle, Failure> {
    let slot = silica_rt::ipc::free_slot().ok_or(Failure::NoRoom)?;
    sys::cap_derive(silica_rt::slots::SPACE, slot, cap, rights, badge).map_err(|_| {
        silica_rt::ipc::release_slot(slot);
        Failure::NoRoom
    })?;
    Ok(Handle::new(Cap(slot)))
}
