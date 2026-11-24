//! TCP for programs (`silica.net.Tcp`, spec/ARCHITECTURE.md section 9).
//!
//! Each connection is a `silica_inet::tcp_conn::Connection` with buffers of
//! the stack's own, and, once a program has it, two byte streams in a block
//! of the program's memory (`silica_rt::ring`'s streams; the protocol's
//! documentation gives the layout). Bytes are copied once each way between
//! the two: the program may go on writing its memory, so the stack never
//! sends from it in place, and a connection's state is the stack's alone.
//! A program's memory is mapped once, when it adds it: a connection costs
//! no mapping.
//!
//! The stack completes a listener's handshakes itself and keeps the
//! connections until the program accepts them (what arrives meanwhile waits
//! in the connection's buffer, and its window tells the peer so).
//!
//! Programs signal the stack's notification for their connections on bits
//! from [`FIRST_BIT`] up, one per connection number modulo the bits there
//! are; every connection is looked at after any signal (a few hundred
//! connections are a few microseconds of looking).
//!
//! Each connection has a record in the page the service manager keeps
//! across the stack's restarts (`slots::KEEP`, after the lease): its peer,
//! its ports and how far each side has sent, so that a stack started again
//! resets every connection the last one had at once ([`kept_connections`])
//! rather than leave each peer waiting for an answer that will not come (a
//! peer that is waiting sends nothing, so it would not learn otherwise).
//! The reset acknowledges what the peer sent, which a peer still waiting
//! for the answer to its SYN needs to take it. 248 records fit; a
//! connection past them is not recorded.
//!
//! What it does not do yet: IPv6, more than one address, a connection's
//! memory taken back while it runs other than by the program ending, and
//! sending from the program's memory in place (G14).

use silica_inet::Ipv4;
use silica_inet::tcp::{ACK, Header, Options, RST, SYN, Segment};
use silica_inet::tcp_conn::{Buffers, Connection, Endpoints, Error as Failure, State};
use silica_protocols::net::tcp::{self as proto, Endpoint, Error, Reason};
use silica_rt::alloc::vec;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Handle, free_slot, release_slot};
use silica_rt::mmio::Mmio;
use silica_rt::ring::{Read, STREAM_HEADER, StreamConsumer, StreamProducer};
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{mem, slots};

/// The first bit of the stack's notification that programs signal for
/// their connections; the bits below are the interface's.
pub const FIRST_BIT: u32 = 8;
const BITS: u32 = 64 - FIRST_BIT;
/// The most listeners, connections and programs with memory at once.
const LISTENERS: usize = 32;
const CONNECTIONS: usize = 256;
const CLIENTS: usize = 32;
/// Each connection's own buffers: bytes sent and not acknowledged, and
/// bytes received and not yet in the program's stream.
const BUFFER: usize = 32 << 10;
/// Sizes of a program's memory, and of a connection's block, in bits.
const MEMORY_BITS: core::ops::RangeInclusive<u8> = 16..=28;
const BLOCK_BITS: core::ops::RangeInclusive<u8> = 12..=24;
/// Local ports for connections made from here (RFC 6335's dynamic range).
const EPHEMERAL: core::ops::Range<u16> = 49152..65535;

/// A program that added memory: the badge it calls with, its memory.
struct Client {
    badge: u64,
    memory: Mmio,
    /// The capability to the memory, kept while it is mapped.
    _frame: Handle,
}

/// A connection's two streams in its program's memory.
struct Streams {
    rx: StreamProducer,
    tx: StreamConsumer,
    /// The program's notification for this connection.
    wake: Handle,
    /// Where the block is in the program's memory, and its size in bits.
    offset: u64,
    bits: u8,
    /// The receive stream was ended, and the transmit stream's end taken.
    rx_closed: bool,
    tx_closed: bool,
}

struct Conn {
    id: u32,
    /// Its record in the kept page, if it has one.
    record: Option<usize>,
    /// The badge of the program it is, or of the listener's program while
    /// it waits to be accepted.
    owner: u64,
    tcp: Connection<Vec<u8>>,
    streams: Option<Streams>,
    /// The listener it waits on, until accepted, and whether that
    /// listener's program was told it is there.
    listener: Option<u32>,
    announced: bool,
    /// The program let go of it: it goes once TCP is done with it.
    released: bool,
}

struct Listener {
    id: u32,
    owner: u64,
    port: u16,
    backlog: u32,
    ready: Handle,
}

/// Where a connection's segments go: the stack's IP layer.
pub trait Out {
    /// Whether a packet can be sent now (a transmit slot is free).
    fn room(&self) -> bool;
    /// Send TCP segment `segment` to `remote`.
    fn send(&mut self, remote: Ipv4, segment: &[u8]);
}

pub struct Tcp {
    /// The records of connections in the kept page, and which are used.
    records: Option<Mmio>,
    recorded: Vec<bool>,
    clients: Vec<Client>,
    listeners: Vec<Listener>,
    conns: Vec<Conn>,
    next: u32,
    /// The stack's notification, to give programs a way to signal it.
    note: Cap,
    /// The interface's largest payload.
    mtu: u16,
    scratch: Vec<u8>,
    segment: Vec<u8>,
}

/// Bytes of a connection's record in the kept page: its peer's address
/// (never 0.0.0.0; 0 marks a record not in use, and it is written last),
/// the two ports, how far it sent, and how far the peer sent.
pub const RECORD: usize = 16;

/// The mark of records in that layout, kept beside them (`netd`'s page).
/// Records without it are another version's, or none: they are cleared and
/// reset nothing.
pub const RECORDS_MARK: u64 = 0x3253_4e4e_4f43_5f44; // "D_CONNS2"

/// A connection an earlier stack had, from its record: its peer, its
/// ports, and the sequence and acknowledgement numbers a reset of it carries.
pub struct Kept {
    pub remote: Ipv4,
    pub remote_port: u16,
    pub local_port: u16,
    pub sequence: u32,
    pub acknowledges: u32,
}

/// The connections an earlier stack recorded in `records`, taken out (the
/// records are cleared for this stack's own).
pub fn kept_connections(records: &Mmio) -> Vec<Kept> {
    let mut kept = Vec::new();
    for i in 0..records.len() / RECORD {
        let at = i * RECORD;
        let remote = records.read32(at);
        if remote == 0 {
            continue;
        }
        let ports = records.read32(at + 4);
        kept.push(Kept {
            remote: Ipv4::from_u32(remote),
            remote_port: ports as u16,
            local_port: (ports >> 16) as u16,
            sequence: records.read32(at + 8),
            acknowledges: records.read32(at + 12),
        });
        records.write32(at, 0);
    }
    kept
}

/// Every record in `records` cleared: another layout's, or memory never
/// used for records.
pub fn clear_records(records: &Mmio) {
    for i in 0..records.len() / RECORD {
        records.write32(i * RECORD, 0);
    }
}

/// The block of 2^`bits` bytes at `offset` in `memory`, as its two streams.
fn streams_in(memory: &Mmio, offset: u64, bits: u8) -> Option<(StreamProducer, StreamConsumer)> {
    let size = 1usize << bits;
    let at = usize::try_from(offset).ok()?;
    let block = memory.part(at, size)?;
    let c = (size - 2 * STREAM_HEADER) / 2;
    let rx = StreamProducer::new(block.part(0, STREAM_HEADER)?, block.part(2 * STREAM_HEADER, c)?)?;
    let tx = StreamConsumer::new(block.part(STREAM_HEADER, STREAM_HEADER)?, block.part(2 * STREAM_HEADER + c, c)?)?;
    Some((rx, tx))
}

/// A connection's two buffers, or `None` when the stack has no memory for
/// them: a peer that opens connections can make the stack refuse more,
/// never fail.
fn buffers() -> Option<Buffers<Vec<u8>>> {
    let one = || {
        let mut v = Vec::new();
        v.try_reserve_exact(BUFFER).ok()?;
        v.extend(core::iter::repeat_n(0u8, BUFFER));
        Some(v)
    };
    Some(Buffers { send: one()?, receive: one()? })
}

fn reason(e: Option<Failure>) -> u32 {
    match e {
        None => Reason::Finished,
        Some(Failure::Refused) => Reason::Refused,
        Some(Failure::Reset) | Some(Failure::Aborted) => Reason::Reset,
        Some(Failure::TimedOut) => Reason::TimedOut,
    }
    .raw()
}

impl Tcp {
    pub fn new(note: Cap, mtu: u16, records: Option<Mmio>) -> Tcp {
        let slots = records.as_ref().map_or(0, |r| r.len() / RECORD);
        Tcp {
            records,
            recorded: vec![false; slots],
            clients: Vec::new(),
            listeners: Vec::new(),
            conns: Vec::new(),
            next: 1,
            note,
            mtu,
            scratch: vec![0; 16 << 10],
            segment: vec![0; 1600],
        }
    }

    /// A record for a new connection `c`, if one is free.
    fn record(&mut self, c: &Connection<Vec<u8>>) -> Option<usize> {
        let r = self.records.as_ref()?;
        let i = self.recorded.iter().position(|u| !u)?;
        self.recorded[i] = true;
        let e = c.endpoints();
        let at = i * RECORD;
        // The peer's address last: a stack that ends half way leaves no
        // half a record.
        r.write32(at, 0);
        r.write32(at + 4, e.remote_port as u32 | (e.local_port as u32) << 16);
        r.write32(at + 8, c.sent_to());
        r.write32(at + 12, c.received_to());
        r.write32(at, e.remote.to_u32());
        Some(i)
    }

    fn number(&mut self) -> u32 {
        loop {
            let n = self.next;
            self.next = self.next.wrapping_add(1).max(1);
            if !self.conns.iter().any(|c| c.id == n) && !self.listeners.iter().any(|l| l.id == n) {
                return n;
            }
        }
    }

    /// A segment for `local`, from `remote`: given to its connection, or
    /// a new one a listener takes. Returns the reset to answer with when
    /// nothing takes it.
    pub fn segment(&mut self, now: u64, local: Ipv4, remote: Ipv4, s: &Segment<'_>) -> Option<Header> {
        let h = &s.header;
        let ends = Endpoints { local, local_port: h.dst_port, remote, remote_port: h.src_port };
        if let Some(c) = self.conns.iter_mut().find(|c| c.tcp.endpoints() == ends) {
            c.tcp.on_segment(now, s);
            return None;
        }
        if s.has(SYN)
            && !s.has(ACK)
            && !s.has(RST)
            && let Some(l) = self.listeners.iter().find(|l| l.port == h.dst_port)
        {
            let (lid, owner) = (l.id, l.owner);
            let waiting = self.conns.iter().filter(|c| c.listener == Some(lid)).count();
            if waiting < l.backlog as usize
                && self.conns.len() < CONNECTIONS
                && let Some(buffers) = buffers()
            {
                let tcp = Connection::accept(ends, s, silica_rt::random::u64() as u32, self.mtu, buffers);
                let id = self.number();
                let record = self.record(&tcp);
                self.conns.push(Conn { id, record, owner, tcp, streams: None, listener: Some(lid), announced: false, released: false });
                return None;
            }
        }
        silica_inet::tcp::reset_reply(s)
    }

    /// The soonest time a connection waits for.
    pub fn deadline(&self) -> Option<u64> {
        self.conns.iter().filter_map(|c| c.tcp.deadline()).min()
    }

    pub fn on_time(&mut self, now: u64) {
        for c in &mut self.conns {
            if c.tcp.deadline().is_some_and(|d| d <= now) {
                c.tcp.on_time(now);
            }
        }
    }

    /// Move bytes between every connection and its program, send what
    /// the connections have to send while `out` has room, tell programs
    /// and listeners what changed, and forget connections that are done.
    /// Returns whether a connection still has something to send (`out`
    /// had no room).
    pub fn pump(&mut self, now: u64, out: &mut dyn Out) -> bool {
        let mut more = false;
        let (scratch, segment) = (&mut self.scratch, &mut self.segment);
        for c in &mut self.conns {
            if let Some(s) = c.streams.as_mut() {
                // The program's bytes to TCP.
                let mut took = false;
                while !s.tx_closed {
                    let room = c.tcp.writable().min(scratch.len());
                    if room == 0 {
                        break;
                    }
                    match s.tx.read(&mut scratch[..room]) {
                        Ok(Read::Bytes(n)) => {
                            c.tcp.send(&scratch[..n]);
                            took = true;
                        }
                        Ok(Read::Empty) => break,
                        Ok(Read::Closed(_)) => {
                            c.tcp.close();
                            s.tx_closed = true;
                        }
                        Err(_) => {
                            // A broken stream: the connection cannot go on.
                            c.tcp.abort();
                            s.tx_closed = true;
                            if !s.rx_closed {
                                s.rx.close(Reason::Broken.raw());
                                s.rx_closed = true;
                            }
                        }
                    }
                }
                // TCP's bytes to the program.
                loop {
                    let room = s.rx.room().min(scratch.len()).min(c.tcp.readable());
                    if room == 0 {
                        break;
                    }
                    let n = c.tcp.recv(&mut scratch[..room]);
                    s.rx.write(&scratch[..n]);
                }
                if !s.rx_closed && (c.tcp.at_end() || (c.tcp.state() == State::Closed && c.tcp.readable() == 0)) {
                    s.rx.close(reason(c.tcp.error()));
                    s.rx_closed = true;
                }
                let woken = (took && s.tx.room_needed()) | s.rx.wake_needed();
                if woken {
                    let _ = sys::signal(s.wake.cap());
                }
            }
            // A connection waiting to be accepted, ready: its listener's
            // program is told, once.
            if let Some(l) = c.listener
                && !c.announced
                && matches!(c.tcp.state(), State::Established | State::CloseWait)
            {
                c.announced = true;
                if let Some(l) = self.listeners.iter().find(|x| x.id == l) {
                    let _ = sys::signal(l.ready.cap());
                }
            }
            // Its segments, while there is room for them.
            while out.room() {
                match c.tcp.poll(now, segment) {
                    Some(n) => out.send(c.tcp.endpoints().remote, &segment[..n]),
                    None => break,
                }
            }
            if !out.room() {
                more = true;
            }
            // How far each side has sent, for a reset of it by the next stack.
            if let (Some(i), Some(r)) = (c.record, self.records.as_ref()) {
                r.write32(i * RECORD + 8, c.tcp.sent_to());
                r.write32(i * RECORD + 12, c.tcp.received_to());
            }
        }
        // Done: closed, and let go of (or never accepted).
        let mut i = 0;
        while i < self.conns.len() {
            let c = &self.conns[i];
            if c.tcp.is_closed() && (c.released || (c.listener.is_some() && c.streams.is_none())) {
                if let (Some(r), Some(records)) = (c.record, self.records.as_ref()) {
                    records.write32(r * RECORD, 0);
                    self.recorded[r] = false;
                }
                self.conns.swap_remove(i);
            } else {
                i += 1;
            }
        }
        more
    }

    /// Before the stack waits: says in every stream the stack waits on
    /// that it sleeps, so that the program signals it: a transmit stream
    /// it could take bytes from now, and a receive stream it holds bytes
    /// for that did not fit. `false`: do not wait, something arrived
    /// meanwhile. Without this, a program's write after the stack last
    /// looked woke nobody, and with nothing else in flight a transfer
    /// stalled (30 s once in 10,000 answers under load).
    pub fn sleep(&mut self) -> bool {
        let mut sleep = true;
        for c in &mut self.conns {
            let Some(s) = c.streams.as_mut() else { continue };
            if !s.tx_closed && c.tcp.writable() > 0 && !s.tx.sleep() {
                sleep = false;
            }
            if !s.rx_closed && c.tcp.readable() > 0 && !s.rx.sleep_for_room() {
                sleep = false;
            }
        }
        sleep
    }

    fn client(&self, badge: u64) -> Option<&Client> {
        self.clients.iter().find(|c| c.badge == badge)
    }

    /// A program's notification capability, for its connection `id` to
    /// signal the stack.
    fn requests(&self, id: u32) -> Result<Handle, Error> {
        let slot = free_slot().ok_or(Error::NoRoom)?;
        let bit = 1u64 << (FIRST_BIT + id % BITS);
        if sys::cap_derive(slots::SPACE, slot, self.note, Rights::WRITE, bit).is_err() {
            release_slot(slot);
            return Err(Error::NoRoom);
        }
        Ok(Handle::new(Cap(slot)))
    }

    /// The block a program names for a connection, checked, as streams.
    fn block(&self, badge: u64, offset: u64, bits: u8) -> Result<(StreamProducer, StreamConsumer), Error> {
        let client = self.client(badge).ok_or(Error::BadMemory)?;
        if !BLOCK_BITS.contains(&bits) || !offset.is_multiple_of(1 << bits) {
            return Err(Error::BadMemory);
        }
        let end = offset + (1 << bits);
        let overlaps = self.conns.iter().filter(|c| c.owner == badge).filter_map(|c| c.streams.as_ref()).any(|s| {
            let (start, stop) = (s.offset, s.offset + (1 << s.bits));
            offset < stop && start < end
        });
        if overlaps {
            return Err(Error::BadMemory);
        }
        streams_in(&client.memory, offset, bits).ok_or(Error::BadMemory)
    }

    pub fn add_memory(&mut self, badge: u64, memory: Handle) -> Result<proto::AddMemoryReply, Error> {
        if self.client(badge).is_some() || self.clients.len() >= CLIENTS {
            return Err(Error::BadMemory);
        }
        let Ok(Some(info)) = sys::inspect_slot(slots::SPACE, memory.cap().0) else { return Err(Error::BadMemory) };
        if info.ty != ObjectType::Frame || !MEMORY_BITS.contains(&info.bits) {
            return Err(Error::BadMemory);
        }
        let region = mem::peer(memory.cap(), info.bits, Rights(Rights::READ.0 | Rights::WRITE.0)).map_err(|_| Error::BadMemory)?;
        self.clients.push(Client { badge, memory: region, _frame: memory });
        Ok(proto::AddMemoryReply {})
    }

    pub fn listen(&mut self, badge: u64, port: u16, backlog: u32, ready: Handle) -> Result<proto::ListenReply, Error> {
        if port == 0 || backlog == 0 {
            return Err(Error::BadArgument);
        }
        if self.listeners.iter().any(|l| l.port == port) {
            return Err(Error::InUse);
        }
        if self.listeners.len() >= LISTENERS {
            return Err(Error::NoRoom);
        }
        let id = self.number();
        self.listeners.push(Listener { id, owner: badge, port, backlog: backlog.min(CONNECTIONS as u32), ready });
        Ok(proto::ListenReply { listener: id })
    }

    pub fn accept(&mut self, badge: u64, listener: u32, offset: u64, bits: u8, wake: Handle) -> Result<proto::AcceptReply<Handle>, Error> {
        if !self.listeners.iter().any(|l| l.id == listener && l.owner == badge) {
            return Err(Error::NoSuch);
        }
        let i =
            self.conns.iter().position(|c| c.listener == Some(listener) && c.announced && c.streams.is_none()).ok_or(Error::WouldBlock)?;
        let (rx, tx) = self.block(badge, offset, bits)?;
        let id = self.conns[i].id;
        let requests = self.requests(id)?;
        let c = &mut self.conns[i];
        c.listener = None;
        c.owner = badge;
        c.streams = Some(Streams { rx, tx, wake, offset, bits, rx_closed: false, tx_closed: false });
        let remote = c.tcp.endpoints();
        Ok(proto::AcceptReply { connection: id, peer: Endpoint { address: remote.remote.to_u32(), port: remote.remote_port }, requests })
    }

    pub fn connect(
        &mut self,
        badge: u64,
        local: Option<Ipv4>,
        peer: Endpoint,
        offset: u64,
        bits: u8,
        wake: Handle,
    ) -> Result<proto::ConnectReply<Handle>, Error> {
        let local = local.ok_or(Error::NoAddress)?;
        if peer.port == 0 || peer.address == 0 {
            return Err(Error::BadArgument);
        }
        if self.conns.len() >= CONNECTIONS {
            return Err(Error::NoRoom);
        }
        let (rx, tx) = self.block(badge, offset, bits)?;
        let remote = Ipv4::from_u32(peer.address);
        // A local port no connection to the same peer uses, from a random start.
        let span = (EPHEMERAL.end - EPHEMERAL.start) as u32;
        let start = silica_rt::random::u64() as u32 % span;
        let port = (0..span)
            .map(|k| EPHEMERAL.start + ((start + k) % span) as u16)
            .find(|p| !self.conns.iter().any(|c| c.tcp.endpoints().local_port == *p && c.tcp.endpoints().remote == remote))
            .ok_or(Error::NoRoom)?;
        let ends = Endpoints { local, local_port: port, remote, remote_port: peer.port };
        let buffers = buffers().ok_or(Error::NoRoom)?;
        let tcp = Connection::connect(ends, silica_rt::random::u64() as u32, self.mtu, buffers);
        let id = self.number();
        let requests = self.requests(id)?;
        let streams = Streams { rx, tx, wake, offset, bits, rx_closed: false, tx_closed: false };
        let record = self.record(&tcp);
        self.conns.push(Conn { id, record, owner: badge, tcp, streams: Some(streams), listener: None, announced: true, released: false });
        Ok(proto::ConnectReply { connection: id, requests })
    }

    pub fn close(&mut self, badge: u64, connection: u32) -> Result<proto::CloseReply, Error> {
        let c = self.conns.iter_mut().find(|c| c.id == connection && c.owner == badge && !c.released).ok_or(Error::NoSuch)?;
        // Ended in order both ways: TCP finishes on its own (its last
        // acknowledgements, TIME-WAIT). Otherwise a reset.
        let orderly = c.streams.as_ref().is_some_and(|s| s.tx_closed && s.rx_closed) && c.tcp.error().is_none();
        if !orderly {
            c.tcp.abort();
        }
        c.released = true;
        c.streams = None;
        Ok(proto::CloseReply {})
    }

    pub fn unlisten(&mut self, badge: u64, listener: u32) -> Result<proto::UnlistenReply, Error> {
        let at = self.listeners.iter().position(|l| l.id == listener && l.owner == badge).ok_or(Error::NoSuch)?;
        self.listeners.remove(at);
        for c in self.conns.iter_mut().filter(|c| c.listener == Some(listener)) {
            c.tcp.abort();
        }
        Ok(proto::UnlistenReply {})
    }

    /// A segment of `segment`, from `local` to `remote`: the reset that
    /// answers one nothing took.
    pub fn reset(&mut self, local: Ipv4, remote: Ipv4, h: &Header, out: &mut dyn Out) {
        if !out.room() {
            return;
        }
        if let Some(n) = silica_inet::tcp::build(&mut self.segment, local, remote, h, &Options::default(), &[]) {
            let seg = core::mem::take(&mut self.segment);
            out.send(remote, &seg[..n]);
            self.segment = seg;
        }
    }
}
