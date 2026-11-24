//! TCP for programs: the client of `silica.net.Tcp`, the network stack's
//! protocol.
//!
//! A program makes one [`Tcp`]: it lends the stack memory once, in which
//! each connection takes a block, and it waits on one notification,
//! signalled for every connection and listener ([`Tcp::wait`]). A
//! connection is a [`Stream`]: bytes in and out through shared memory,
//! with no call to the stack while both sides are busy.
//!
//! An echo server, whole:
//!
//! ```no_run
//! use silica_net::tcp::{Failure, Read, Tcp};
//!
//! fn echo(stack: silica_rt::sys::Cap) -> Result<(), Failure> {
//!     // 1 MiB: 16 connections of 64 KiB. On the program's own events, so
//!     // that a restart of the stack is seen (bit 0: the stack is need 0).
//!     let mut tcp = Tcp::on(stack, 20, silica_rt::slots::EVENTS, 32, 1)?;
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
//!                 let _ = s.write(&buf[..n]);
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
//! ([`Stream::write`]), or says that the connection failed. Before
//! waiting, a program asks each stream it waits for whether it may
//! ([`Stream::sleep_read`], [`Stream::sleep_write`]), so that the stack
//! signals it when that stream changes.
//!
//! **The stack started again.** A stack that ends takes its connections
//! with it. A [`Tcp`] made on the program's events ([`Tcp::on`]) is told
//! when the service manager starts the stack again, and in its next
//! [`Tcp::wait`] it lends its memory to the new one and listens again on
//! every port it listened on, under the same listener numbers; every
//! connection it had ends as reset (its reads say `Closed(reset)`, its
//! writes fail). The program carries on accepting.

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

/// What a [`Tcp`] waits on: a notification of its own, or bits of the
/// program's.
enum Note {
    Own(Object),
    Shared(Cap),
}

impl Note {
    fn cap(&self) -> Cap {
        match self {
            Note::Own(o) => o.cap(),
            Note::Shared(c) => *c,
        }
    }
}

/// A port listened on: what to listen with again after the stack's
/// restart, and the stack's number for it now.
struct Listening {
    port: u16,
    backlog: u32,
    id: u32,
}

/// A program's TCP: its memory lent to the stack, cut in blocks, and the
/// notification it waits on.
pub struct Tcp {
    stack: proto::Client<Channel, Handle>,
    memory: Memory,
    /// Each block's size in bits, and which are free.
    block_bits: u8,
    free: Vec<u64>,
    note: Note,
    /// The notification's bits: the first is the listeners', the rest
    /// (to 63) the connections'; and the bit that says the stack was
    /// started again (0: none).
    first: u32,
    restarted: u64,
    /// How many times the stack was started again: a stream of an earlier
    /// stack is not its to close.
    generation: u32,
    listening: Vec<Listening>,
    /// Streams closed while the stack still had bytes of theirs to take
    /// (`close`): kept, their blocks with them, until it took them.
    closing: Vec<Stream>,
}

/// A connection.
pub struct Stream {
    id: u32,
    generation: u32,
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
    /// stream each way. On a notification of its own: the stack's restart
    /// is not seen (see [`Tcp::on`]).
    pub fn new(stack: Cap, memory_bits: u8) -> Result<Tcp, Failure> {
        let note = Object::new(ObjectType::Notification, 0).map_err(|_| Failure::NoRoom)?;
        Tcp::make(stack, memory_bits, 16, Note::Own(note), 0, 0)
    }

    /// As [`Tcp::new`], waiting on the program's notification `note` (its
    /// events, `silica_rt::slots::EVENTS`), using its bits from `first`
    /// (at most 62) to 63, and taking `restarted` (a bit below `first`:
    /// the stack's need's bit) to mean that the stack was started again.
    pub fn on(stack: Cap, memory_bits: u8, note: Cap, first: u32, restarted: u64) -> Result<Tcp, Failure> {
        if first > 62 || restarted >> first != 0 {
            return Err(Failure::Refused(Error::BadArgument));
        }
        Tcp::make(stack, memory_bits, 16, Note::Shared(note), first, restarted)
    }

    fn make(stack: Cap, memory_bits: u8, block_bits: u8, note: Note, first: u32, restarted: u64) -> Result<Tcp, Failure> {
        if !(12..=24).contains(&block_bits) || block_bits > memory_bits {
            return Err(Failure::Refused(Error::BadMemory));
        }
        let stack = proto::Client::<Channel, Handle>::from(Channel::new(stack));
        let memory = Memory::new(memory_bits).map_err(|_| Failure::NoRoom)?;
        let blocks = 1usize << (memory_bits - block_bits);
        let mut free = silica_rt::alloc::vec![0u64; blocks.div_ceil(64)];
        for b in 0..blocks {
            free[b / 64] |= 1 << (b % 64);
        }
        let mut tcp =
            Tcp { stack, memory, block_bits, free, note, first, restarted, generation: 0, listening: Vec::new(), closing: Vec::new() };
        tcp.lend_memory()?;
        Ok(tcp)
    }

    fn lend_memory(&mut self) -> Result<(), Failure> {
        let frame = lend(self.memory.frame(), Rights(Rights::READ.0 | Rights::WRITE.0), 0)?;
        self.stack.add_memory(frame)?;
        Ok(())
    }

    fn ready_bit(&self) -> u64 {
        1 << self.first
    }

    fn wake_bit(&self, block: usize) -> u64 {
        let span = 63 - self.first;
        1 << (self.first + 1 + (block as u32) % span)
    }

    /// Listen on `port`, keeping up to `backlog` connections waiting to be
    /// accepted. The listener's number.
    pub fn listen(&mut self, port: u16, backlog: u32) -> Result<u32, Failure> {
        let ready = lend(self.note.cap(), Rights::WRITE, self.ready_bit())?;
        let id = self.stack.listen(port, backlog, ready)?.listener;
        self.listening.push(Listening { port, backlog, id });
        Ok(self.listening.len() as u32 - 1)
    }

    /// The next connection waiting on `listener`, if one is.
    pub fn accept(&mut self, listener: u32) -> Result<Option<Stream>, Failure> {
        match self.accept_once(listener) {
            // A listener this program has, unknown to the stack: the stack
            // was started again before its notice was seen.
            Err(Failure::Refused(Error::NoSuch)) if (listener as usize) < self.listening.len() && self.recover() => {
                self.accept_once(listener)
            }
            r => r,
        }
    }

    fn accept_once(&mut self, listener: u32) -> Result<Option<Stream>, Failure> {
        let id = self.listening.get(listener as usize).ok_or(Failure::Refused(Error::NoSuch))?.id;
        let (block, offset) = self.block()?;
        let wake = lend(self.note.cap(), Rights::WRITE, self.wake_bit(block))?;
        match self.stack.accept(id, offset, self.block_bits, wake) {
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
        let wake = lend(self.note.cap(), Rights::WRITE, self.wake_bit(block))?;
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
        if s.generation != self.generation {
            // The stack it was made on is gone, and its connections with it.
            self.give_back(s.offset);
            return Ok(());
        }
        match self.stack.close(s.id) {
            // The stack has bytes of it still to take (a program that
            // finished and closed at once): its block stays this stream's
            // until the stack took them, and the close is made again then
            // (`wait`).
            Err(silica_idl_rt::CallError::Error(Error::WouldBlock)) => {
                self.closing.push(s);
                Ok(())
            }
            r => {
                self.give_back(s.offset);
                r.map(|_| ()).map_err(Into::into)
            }
        }
    }

    /// Close again what the stack could not let go of yet (it signals the
    /// stream's bit when it has taken the last of a finished stream's bytes).
    fn close_pending(&mut self) {
        for s in core::mem::take(&mut self.closing) {
            let _ = self.close(s);
        }
    }

    /// Wait until the stack signals (a connection changed, or one is
    /// waiting to be accepted), or until `deadline` (monotonic ns).
    /// Returns the notification's bits that were signalled (the program's
    /// own among them, on a shared notification). When the stack was
    /// started again, the new one is set up first (see the module's
    /// documentation).
    pub fn wait(&mut self, deadline: Option<u64>) -> u64 {
        self.close_pending();
        let bits = match sys::recv(self.note.cap(), deadline.map_or(Wait::Forever, Wait::Until)) {
            Ok(m) => m.badge,
            Err(_) => 0,
        };
        if bits & self.restarted != 0 {
            self.recover();
        }
        bits
    }

    /// If the stack is a new one (it takes this program's memory: one that
    /// already has it refuses it again), set it up: every connection of the
    /// last one ends as reset, and every port is listened on again under
    /// the same listener number. Whether it was new. Seen by its notice or
    /// by a call it did not know, whichever comes first; the other finds
    /// nothing to do.
    fn recover(&mut self) -> bool {
        // The new stack may still be starting: its first call is waited for
        // by the kernel, as any call is.
        if self.lend_memory().is_err() {
            return false;
        }
        self.generation = self.generation.wrapping_add(1);
        // Every block in use is a connection of the stack that ended: its
        // receive stream ends, reset, which its reads and writes then say.
        let size = 1usize << self.block_bits;
        let m = self.memory.shared();
        let c = (size - 2 * STREAM_HEADER) / 2;
        for b in 0..(m.len() >> self.block_bits) {
            if self.free[b / 64] & (1 << (b % 64)) != 0 {
                continue;
            }
            let at = b << self.block_bits;
            if let (Some(h), Some(d)) = (m.part(at, STREAM_HEADER), m.part(at + 2 * STREAM_HEADER, c))
                && let Some(mut rx) = StreamProducer::new(h, d)
            {
                rx.close(Reason::Reset.raw());
            }
        }
        for i in 0..self.listening.len() {
            let (port, backlog) = (self.listening[i].port, self.listening[i].backlog);
            if let Ok(ready) = lend(self.note.cap(), Rights::WRITE, self.ready_bit())
                && let Ok(r) = self.stack.listen(port, backlog, ready)
            {
                self.listening[i].id = r.listener;
            }
        }
        true
    }

    /// A free block: its number and offset, zeroed.
    fn block(&mut self) -> Result<(usize, u64), Failure> {
        let w = self.free.iter().position(|w| *w != 0).ok_or(Failure::NoRoom)?;
        let b = w * 64 + self.free[w].trailing_zeros() as usize;
        self.free[w] &= !(1 << (b % 64));
        let offset = (b as u64) << self.block_bits;
        // The two headers start the streams at position 0; the data areas
        // are read only up to the positions published (the protocol's
        // rule). Zeroing the whole block was 2^k stores on every accept
        // that found nothing waiting, which is most of a server's calls.
        let m = self.memory.shared();
        for at in (offset as usize..offset as usize + 2 * STREAM_HEADER).step_by(8) {
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
        Ok(Stream { id, generation: self.generation, offset, rx, tx, requests, peer })
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

    /// Send what fits of `bytes`; returns how much did (0: wait for room,
    /// [`Stream::sleep_write`]), or the reason the connection failed (as
    /// sending on a reset connection fails anywhere).
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, Reason> {
        if let Some(r) = self.failed() {
            return Err(r);
        }
        let n = self.tx.write(bytes);
        if n > 0 && self.tx.wake_needed() {
            let _ = sys::signal(self.requests.cap());
        }
        Ok(n)
    }

    /// Why the connection failed, if it did (the receive stream ended
    /// otherwise than by the peer finishing).
    pub fn failed(&self) -> Option<Reason> {
        self.rx.ended().map(Reason::from_raw).filter(|r| *r != Reason::Finished)
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

    /// Before waiting for room to write: `false` when there is some now,
    /// or the connection failed (see [`Stream::write`]).
    pub fn sleep_write(&mut self) -> bool {
        self.failed().is_none() && self.tx.sleep_for_room()
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
