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
//! are. A pass looks only at the connections something reached since the
//! last (a segment, found through an index of their addresses and ports;
//! one of their bits signalled; a call on them; their timer; work the last
//! pass could not finish): a program that calls or signals in a loop, or a
//! table full of TIME-WAIT, no longer costs every call a walk over every
//! connection.
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
//! A program that ends, or takes back the memory it lent, is told to the
//! stack by the kernel (`cap_notice` on the notifications it gave for its
//! listeners and connections, [`GONE`]): its
//! listeners and connections are let go of at once, so its ports are free
//! and its peers reset, and the next instance of the service starts clean.
//!
//! Whose a connection is. A program has as many connections as the memory
//! it lent pays for (`Tcp::add_memory`), whatever their state: waiting on
//! its listener, accepted, or let go of in order while TCP still has the
//! rest to send or its peer's end to hear. There is no connection that is
//! nobody's: one let go of ends with its program, gives its place to its
//! program's next when the program has no other, and is given up on when
//! its peer keeps its window shut (`silica_inet`'s `release`). A listener's
//! unfinished handshakes are its own too: a flood of them evicts only
//! that listener's, and the peer of each one evicted is told by a reset.
//!
//! What it does not do yet: IPv6, more than one address, and sending from
//! the program's memory in place (G14).

use silica_inet::Ipv4;
use silica_inet::tcp::{ACK, Header, Options, RST, SYN, Segment};
use silica_inet::tcp_conn::{Buffers, Connection, Endpoints, Error as Failure, State};
use silica_protocols::net::tcp::{self as proto, Endpoint, Error, Reason};
use silica_protocols::scope;
use silica_rt::alloc::collections::BTreeMap;
use silica_rt::alloc::vec;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Handle, free_slot, release_slot};
use silica_rt::mmio::Mmio;
use silica_rt::ring::{Read, STREAM_HEADER, StreamConsumer, StreamProducer};
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{mem, slots};

/// The bit of the stack's notification the kernel signals when a program
/// that lent the stack memory ends (`cap_notice` on its notifications, `Watched`): its
/// listeners and connections are let go of at once ([`Tcp::forget_ended`]).
/// The bits below are the interface's.
pub const GONE: u64 = 1 << 8;
/// The first bit of the stack's notification that programs signal for
/// their connections.
pub const FIRST_BIT: u32 = 10;
const BITS: u32 = 64 - FIRST_BIT;
/// The most listeners and programs with memory at once, and the
/// connections the stack's own memory holds: each has `2 * BUFFER` bytes
/// of the stack's buffers (16 MiB for all of them, of the 32 MiB the stack
/// is declared, beside `GROWN_MOST`). No program has a share of them by
/// default: a program has as many as the memory it lent pays for, one for
/// every `2 * BUFFER` bytes (`Tcp::add_memory`), kept for it from then on,
/// so that what one program holds is never another's to take.
const LISTENERS: usize = 32;
const CONNECTIONS: usize = 256;
/// Connections in TIME-WAIT, kept beside those: their buffers shed, each
/// a few hundred bytes, so the side that closes first can open more than
/// four connections a second for a minute. Past this many the one nearest
/// its end goes first (as Linux's `tcp_max_tw_buckets`).
const TIME_WAITING: usize = 1024;
const CLIENTS: usize = 32;
/// Each connection's own buffers: bytes sent and not acknowledged, and
/// bytes received and not yet in the program's stream.
const BUFFER: usize = 32 << 10;
/// A send buffer doubles when it is what holds its connection back
/// (`Connection::buffer_limited`: all of it in flight, the windows open)
/// and its program has more to send, up to `SEND_MOST`. TCP's scoreboard
/// keeps at most 64 segments in flight (92 KiB at a 1448-byte MSS), so a
/// larger buffer would never be in flight whole. The bytes added beyond
/// `BUFFER` across all connections stay under `GROWN_MOST`: peers that
/// open windows on many connections cost the stack a bounded amount, and
/// a connection past the bound keeps the buffer it has.
const SEND_MOST: usize = 128 << 10;
const GROWN_MOST: usize = 4 << 20;
/// Sizes of a program's memory, and of a connection's block, in bits.
const MEMORY_BITS: core::ops::RangeInclusive<u8> = 16..=28;
const BLOCK_BITS: core::ops::RangeInclusive<u8> = 12..=24;
/// Local ports for connections made from here (RFC 6335's dynamic range).
const EPHEMERAL: core::ops::Range<u16> = 49152..65535;

/// A program that added memory: the badge it calls with, its memory.
struct Client {
    badge: u64,
    /// Where its memory is mapped: its connections' streams are parts of
    /// it, let go of (`forget`) before it is.
    memory: mem::Lent,
    /// The capability to the memory, kept while it is mapped: its slot is
    /// empty once the program ended. (A mapped Frame cannot be watched:
    /// its slot links its mappings. The program's notifications, which
    /// go with it too, are watched instead: `Watched`.)
    frame: Handle,
    /// How many connections it may have: one for every `2 * BUFFER` bytes
    /// it lent (what a connection costs the stack in buffers of its own),
    /// within what the stack's own memory had left when it lent them.
    most: usize,
}

/// A connection's two streams in its program's memory.
struct Streams {
    rx: StreamProducer,
    tx: StreamConsumer,
    /// The program's notification for this connection, watched: the
    /// program's end signals [`GONE`].
    wake: Watched,
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
    /// Something reached it since the last pass looked (a segment, its
    /// program's signal, a call, its timer) or that pass left it work:
    /// `pump` looks at it. The rest are passed over, so a pass costs what
    /// changed, not the table (a program calling in a loop made the stack
    /// look at every connection on every call).
    due: bool,
}

struct Listener {
    id: u32,
    owner: u64,
    port: u16,
    /// The program's notification for the listener, watched as `wake` is.
    ready: Watched,
}

/// A capability of a program's that the kernel watches for the stack: it
/// goes when its object does (the program ended), which signals [`GONE`].
struct Watched {
    /// Declared first, so it goes first: letting go of `cap` here signals
    /// nothing.
    _notice: Handle,
    cap: Handle,
}

impl Watched {
    fn new(cap: Handle, note: Cap) -> Result<Watched, Error> {
        let Some(slot) = free_slot() else {
            silica_rt::println!("netd: no capability slot left to watch a program's notification");
            return Err(Error::NoRoom);
        };
        let notice = Handle::new(Cap(slot));
        if let Err(e) = sys::cap_notice(cap.cap(), note, notice.cap(), GONE) {
            silica_rt::println!("netd: cannot watch a program's notification (slot {}): {e:?}", cap.cap().0);
            return Err(Error::NoRoom);
        }
        Ok(Watched { _notice: notice, cap })
    }
}

/// Where a connection's segments go: the stack's IP layer.
pub trait Out {
    /// Whether a packet can be sent now (a transmit slot is free).
    fn room(&self) -> bool;
    /// Send TCP segment `segment` to `remote`. `partial`: its checksum
    /// holds only the pseudo-header's sum, for the interface to finish, and
    /// one carrying more than `mss` bytes of data is for it to cut.
    fn send(&mut self, remote: Ipv4, segment: &[u8], partial: bool, mss: u16);
}

pub struct Tcp {
    /// The records of connections in the kept page, and which are used.
    records: Option<Mmio>,
    recorded: Vec<bool>,
    clients: Vec<Client>,
    listeners: Vec<Listener>,
    conns: Vec<Conn>,
    /// Where each connection is in `conns`, by its four addresses and
    /// ports: a segment finds its connection in a lookup, not a walk over
    /// the table (TIME-WAIT included, over a thousand).
    index: BTreeMap<Key, usize>,
    /// Where the next pass starts (`pump`).
    rotor: usize,
    next: u32,
    /// The stack's notification, to give programs a way to signal it.
    note: Cap,
    /// The interface's largest payload.
    mtu: u16,
    /// What the interface does for TCP's segments, given to every
    /// connection (`Connection::set_offloads`): sums their checksums, and
    /// cuts ones of up to this much data (0: none).
    checksum_offload: bool,
    most_payload: u32,
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
    let kept = left_connections(records);
    clear_records(records);
    kept
}

/// The connections `records` name, the records left as they are: those of
/// the program before this one, in a page this one may only read (the
/// service manager hands it over when a stack's program is replaced). Any
/// bytes decode: each record is at most one reset, to an address a
/// connection can be with (not none, a group's or the broadcast address)
/// and from and to a port that is one, which is no more than the program
/// that wrote them could have sent itself.
pub fn left_connections(records: &Mmio) -> Vec<Kept> {
    let mut kept = Vec::new();
    for i in 0..records.len() / RECORD {
        let at = i * RECORD;
        let remote = Ipv4::from_u32(records.read32(at));
        let ports = records.read32(at + 4);
        let (remote_port, local_port) = (ports as u16, (ports >> 16) as u16);
        if remote == Ipv4::UNSPECIFIED || remote == Ipv4::BROADCAST || remote.is_multicast() || remote_port == 0 || local_port == 0 {
            continue;
        }
        kept.push(Kept { remote, remote_port, local_port, sequence: records.read32(at + 8), acknowledges: records.read32(at + 12) });
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

/// A connection's place in the index: its local and remote address and port.
type Key = (u32, u16, u32, u16);

fn key(e: &Endpoints) -> Key {
    (e.local.to_u32(), e.local_port, e.remote.to_u32(), e.remote_port)
}

/// A connection's two buffers, or `None` when the stack has no memory for
/// them: a peer that opens connections can make the stack refuse more,
/// never fail.
fn buffers() -> Option<Buffers<Vec<u8>>> {
    Some(Buffers { send: buffer(BUFFER)?, receive: buffer(BUFFER)? })
}

/// Send-buffer bytes beyond `BUFFER` that connections hold now (a buffer
/// shed in TIME-WAIT holds none).
fn grown(conns: &[Conn]) -> usize {
    conns.iter().map(|c| c.tcp.send_capacity().saturating_sub(BUFFER)).sum()
}

/// Whether a connection's send buffer may double now (`SEND_MOST`).
fn may_grow(tcp: &Connection<Vec<u8>>, grown: usize) -> bool {
    let capacity = tcp.send_capacity();
    tcp.buffer_limited() && capacity < SEND_MOST && grown + capacity <= GROWN_MOST
}

fn buffer(bytes: usize) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes).ok()?;
    v.resize(bytes, 0);
    Some(v)
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
    pub fn new(note: Cap, mtu: u16, records: Option<Mmio>, checksum_offload: bool, most_payload: u32) -> Tcp {
        let slots = records.as_ref().map_or(0, |r| r.len() / RECORD);
        // A segment's TCP header and data: the most the interface cuts, else
        // the MTU's worth.
        let segment = 60 + (most_payload as usize).max(usize::from(mtu));
        Tcp {
            records,
            recorded: vec![false; slots],
            clients: Vec::new(),
            listeners: Vec::new(),
            conns: Vec::new(),
            index: BTreeMap::new(),
            rotor: 0,
            next: 1,
            note,
            mtu,
            checksum_offload,
            most_payload,
            scratch: vec![0; 16 << 10],
            segment: vec![0; segment],
        }
    }

    /// Connections of program `owner` that hold a place: all but those in
    /// TIME-WAIT (a small record, [`TIME_WAITING`]) and those it let go of
    /// that have ended and only wait to be forgotten.
    fn held(&self, owner: u64) -> usize {
        self.conns.iter().filter(|c| c.owner == owner && c.tcp.state() != State::TimeWait && !(c.released && c.tcp.is_closed())).count()
    }

    /// How many connections program `owner` may have: what it paid for when
    /// it lent its memory ([`Tcp::add_memory`]); none before it lent any.
    fn most(&self, owner: u64) -> usize {
        self.client(owner).map_or(0, |c| c.most)
    }

    /// Whether program `owner` may have one more connection. At its bound,
    /// a connection it let go of that TCP is not done with (its peer has
    /// not taken or acknowledged the rest, or has not finished) gives its
    /// place, the oldest first, reset: such a connection is its program's
    /// to pay for until it is done, so a peer that never lets one finish
    /// (a window kept shut, every probe answered) holds a place only
    /// until its program needs it. Before, they were nobody's to give up
    /// and counted all the same: 128 of them shut a server for good.
    fn make_room(&mut self, owner: u64) -> bool {
        let most = self.most(owner);
        if self.held(owner) < most {
            return true;
        }
        let lingering = |c: &Conn| c.owner == owner && c.released && !c.tcp.is_closed() && c.tcp.state() != State::TimeWait;
        let Some(c) = self.conns.iter_mut().filter(|c| lingering(c)).min_by_key(|c| c.id) else { return false };
        c.tcp.abort();
        c.due = true;
        self.held(owner) < most
    }

    /// Forget connection `i` (closed, or never to be), and its record.
    fn drop_conn(&mut self, i: usize) {
        if let (Some(r), Some(records)) = (self.conns[i].record, self.records.as_ref()) {
            records.write32(r * RECORD, 0);
            self.recorded[r] = false;
        }
        self.index.remove(&key(&self.conns[i].tcp.endpoints()));
        self.conns.swap_remove(i);
        // The last one took its place.
        if let Some(moved) = self.conns.get(i) {
            self.index.insert(key(&moved.tcp.endpoints()), i);
        }
    }

    /// Add connection `c` to the table and its index.
    fn add_conn(&mut self, c: Conn) {
        self.index.insert(key(&c.tcp.endpoints()), self.conns.len());
        self.conns.push(c);
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
        if let Some(&i) = self.index.get(&key(&ends)) {
            let c = &mut self.conns[i];
            c.tcp.on_segment(now, s);
            c.due = true;
            return None;
        }
        if s.has(SYN)
            && !s.has(ACK)
            && !s.has(RST)
            && let Some(l) = self.listeners.iter().find(|l| l.port == h.dst_port)
        {
            let (lid, owner) = (l.id, l.owner);
            // What waits to be accepted is its program's, paid for by the
            // memory it lent, as its connections are: no number of its own
            // (before, a backlog the program named, which the remote
            // service set to eight, and a burst of ten handshakes, nine
            // strangers' and an owner's, lost two places to it, on a hosted
            // runner, 2026-11-26). A handshake that never finishes (a SYN
            // from an address that never answers: spoofed) holds its place
            // and 64 KiB until its SYN-ACKs give up, minutes later; a real
            // one finishes within a round trip. So a listener whose program
            // has every connection it pays for gives the place of its own
            // oldest unfinished handshake to this one: a flood of spoofed
            // SYNs does not shut it to the peers that answer, and costs no
            // other listener anything (before, the machine kept 64
            // unfinished handshakes between all listeners, and a flood on
            // one evicted another's). The one evicted is told, by a reset,
            // rather than left to wait for SYN-ACKs that never come.
            let unfinished = |c: &Conn| c.listener == Some(lid) && c.tcp.state() == State::SynReceived;
            if self.held(owner) >= self.most(owner)
                && let Some(c) = self.conns.iter_mut().filter(|c| unfinished(c)).min_by_key(|c| c.id)
            {
                c.tcp.abort();
                c.listener = None;
                c.released = true;
                c.due = true;
            }
            if self.make_room(owner)
                && let Some(buffers) = buffers()
            {
                let r = silica_rt::random::u64();
                let mut tcp = Connection::accept(ends, s, r as u32, (r >> 32) as u32, self.mtu, buffers);
                tcp.set_offloads(self.checksum_offload, self.most_payload);
                let id = self.number();
                let record = self.record(&tcp);
                self.add_conn(Conn {
                    id,
                    record,
                    owner,
                    tcp,
                    streams: None,
                    listener: Some(lid),
                    announced: false,
                    released: false,
                    due: true,
                });
                return None;
            }
        }
        silica_inet::tcp::reset_reply(s)
    }

    /// A router said the path from `local`:`local_port` to
    /// `remote`:`remote_port` carries at most `mtu` bytes, quoting the
    /// segment that began at `seq` (`Connection::path_mtu` decides whether
    /// to believe it). Whether that connection's segments got smaller.
    pub fn path_mtu(&mut self, local: Ipv4, local_port: u16, remote: Ipv4, remote_port: u16, mtu: u16, seq: u32) -> bool {
        let ends = Endpoints { local, local_port, remote, remote_port };
        let Some(&i) = self.index.get(&key(&ends)) else { return false };
        let c = &mut self.conns[i];
        let smaller = c.tcp.path_mtu(mtu, seq);
        if smaller {
            c.due = true;
        }
        smaller
    }

    /// The soonest time a connection waits for.
    pub fn deadline(&self) -> Option<u64> {
        self.conns.iter().filter_map(|c| c.tcp.deadline()).min()
    }

    pub fn on_time(&mut self, now: u64) {
        for c in &mut self.conns {
            if c.tcp.deadline().is_some_and(|d| d <= now) {
                c.tcp.on_time(now);
                c.due = true;
            }
        }
    }

    /// Programs signalled `bits` of the stack's notification: the
    /// connections those bits stand for ([`FIRST_BIT`] and up, one per
    /// connection number modulo the bits there are) are due.
    pub fn signalled(&mut self, bits: u64) {
        let ours = bits >> FIRST_BIT;
        if ours == 0 {
            return;
        }
        for c in self.conns.iter_mut() {
            if ours & (1 << (c.id % BITS)) != 0 {
                c.due = true;
            }
        }
    }

    /// Move bytes between every connection that is due and its program,
    /// send what they have to send while `out` has room, tell programs
    /// and listeners what changed, and forget connections that are done.
    /// Returns whether a connection still has something to send (`out`
    /// had no room).
    pub fn pump(&mut self, now: u64, out: &mut dyn Out) -> bool {
        let mut more = false;
        let mut grown = grown(&self.conns);
        let (scratch, segment) = (&mut self.scratch, &mut self.segment);
        // Each pass starts at the next connection: one with much to send
        // near the front does not take the interface's room from the rest
        // every time.
        let n = self.conns.len();
        let first = if n == 0 { 0 } else { self.rotor % n };
        self.rotor = self.rotor.wrapping_add(1);
        for k in 0..n {
            let c = &mut self.conns[(first + k) % n];
            if !c.due {
                continue;
            }
            c.due = false;
            if let Some(s) = c.streams.as_mut() {
                // The program's bytes to TCP.
                let mut took = false;
                // Bytes put in the program's receive stream, or its end.
                let mut gave = false;
                while !s.tx_closed {
                    if may_grow(&c.tcp, grown) && s.tx.available().is_ok_and(|n| n > 0) {
                        let capacity = c.tcp.send_capacity();
                        // Refused memory leaves the buffer as it was.
                        if let Some(bytes) = buffer(2 * capacity)
                            && c.tcp.grow_send_buffer(bytes)
                        {
                            grown += capacity;
                        }
                    }
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
                                gave = true;
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
                    gave |= n > 0;
                }
                if !s.rx_closed && (c.tcp.at_end() || (c.tcp.state() == State::Closed && c.tcp.readable() == 0)) {
                    s.rx.close(reason(c.tcp.error()));
                    s.rx_closed = true;
                    gave = true;
                }
                // The last of a finished stream taken: its program may be
                // waiting to close it (`close` answered `would_block`).
                let drained = took && s.tx.ended().is_some() && s.tx.available() == Ok(0);
                // Each side's flag is asked only after this pass changed that
                // stream: asking takes the flag, so asking on every pass woke
                // a program waiting for its next request every time the stack
                // looked, and its wake-up made the stack look again (httpd and
                // netd kept a processor busy between them while a connection
                // was open and quiet, 2026-11-24).
                let woken = (took && (s.tx.room_needed() || drained)) | (gave && s.rx.wake_needed());
                if woken {
                    let _ = sys::signal(s.wake.cap.cap());
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
                    let _ = sys::signal(l.ready.cap.cap());
                }
            }
            // Its segments, while there is room for them.
            while out.room() {
                match c.tcp.poll(now, segment) {
                    Some(n) => out.send(c.tcp.endpoints().remote, &segment[..n], self.checksum_offload, c.tcp.mss() as u16),
                    None => break,
                }
            }
            if !out.room() {
                // What it could not send waits for the next pass.
                more = true;
                c.due = true;
            }
            // How far each side has sent, for a reset of it by the next stack.
            if let (Some(i), Some(r)) = (c.record, self.records.as_ref()) {
                r.write32(i * RECORD + 8, c.tcp.sent_to());
                r.write32(i * RECORD + 12, c.tcp.received_to());
            }
            // In TIME-WAIT nothing more is sent or read: a connection's
            // buffers go now, not a minute later when it ends
            // (`Connection::shed`), unless its program has still to read
            // what arrived. (A connection gets there, and its program
            // reads the rest, only by what makes it due.)
            if c.released || c.tcp.readable() == 0 {
                let _ = c.tcp.shed();
            }
        }
        // Done: closed, and let go of (or never accepted).
        let mut i = 0;
        while i < self.conns.len() {
            let c = &self.conns[i];
            if c.tcp.is_closed() && (c.released || (c.listener.is_some() && c.streams.is_none())) {
                self.drop_conn(i);
            } else {
                i += 1;
            }
        }
        // Too many in TIME-WAIT (and let go of): the nearest its end goes.
        // (Counted only when the table holds more than that many at all.)
        let waiting = |c: &Conn| c.released && c.tcp.state() == State::TimeWait;
        while self.conns.len() > TIME_WAITING && self.conns.iter().filter(|c| waiting(c)).count() > TIME_WAITING {
            let Some(i) = self.conns.iter().enumerate().filter(|(_, c)| waiting(c)).min_by_key(|(_, c)| c.tcp.deadline()).map(|(i, _)| i)
            else {
                break;
            };
            self.drop_conn(i);
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
        let grown = grown(&self.conns);
        for c in &mut self.conns {
            let Some(s) = c.streams.as_mut() else { continue };
            let can_take = c.tcp.writable() > 0 || may_grow(&c.tcp, grown);
            if !s.tx_closed && can_take && !s.tx.sleep() {
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
        let Some(slot) = free_slot() else {
            silica_rt::println!("netd: no capability slot left for connection {id}");
            return Err(Error::NoRoom);
        };
        let bit = 1u64 << (FIRST_BIT + id % BITS);
        if let Err(e) = sys::cap_derive(slots::SPACE, slot, self.note, Rights::WRITE, bit) {
            silica_rt::println!("netd: cannot make connection {id}'s capability in slot {slot}: {e:?}");
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
        // An offset at the top of the range would wrap past it.
        let end = offset.checked_add(1 << bits).ok_or(Error::BadMemory)?;
        let overlaps = self.conns.iter().filter(|c| c.owner == badge).filter_map(|c| c.streams.as_ref()).any(|s| {
            let (start, stop) = (s.offset, s.offset + (1 << s.bits));
            offset < stop && start < end
        });
        if overlaps {
            return Err(Error::BadMemory);
        }
        streams_in(&client.memory.region(), offset, bits).ok_or(Error::BadMemory)
    }

    /// A program lends its memory once. A second `add_memory` from the same
    /// badge is a new instance of the same service (the service manager
    /// badges a service's capability, and runs one instance at a time),
    /// which may call before the kernel's notice of the last one's end has
    /// been looked at: what the last instance had is let go of first.
    ///
    /// What it lends says how many connections it may have: one for every
    /// `2 * BUFFER` bytes, the stack's own cost of a connection, so that a
    /// program holds places in proportion to what it gave and none by
    /// default. They are kept for it out of the [`CONNECTIONS`] the stack's
    /// memory holds, never taken by a later lender; a program that lends
    /// when none are left is refused, and told so (`no_room`).
    pub fn add_memory(&mut self, badge: u64, memory: Handle) -> Result<proto::AddMemoryReply, Error> {
        if self.client(badge).is_some() {
            self.forget(badge);
        }
        if self.clients.len() >= CLIENTS {
            return Err(Error::BadMemory);
        }
        let Ok(Some(info)) = sys::inspect_slot(slots::SPACE, memory.cap().0) else { return Err(Error::BadMemory) };
        if info.ty != ObjectType::Frame || !MEMORY_BITS.contains(&info.bits) {
            return Err(Error::BadMemory);
        }
        let region = mem::Lent::map(memory.cap(), info.bits, Rights(Rights::READ.0 | Rights::WRITE.0)).map_err(|_| Error::BadMemory)?;
        let kept: usize = self.clients.iter().map(|c| c.most).sum();
        let most = ((1usize << info.bits) / (2 * BUFFER)).min(CONNECTIONS.saturating_sub(kept));
        if most == 0 {
            silica_rt::println!(
                "netd: a program lent memory for connections, and the stack's own memory holds no more than the {kept} kept for others"
            );
            return Err(Error::NoRoom);
        }
        self.clients.push(Client { badge, memory: region, frame: memory, most });
        Ok(proto::AddMemoryReply {})
    }

    /// Let go of the programs that ended (or took back the memory they
    /// lent): the kernel signalled [`GONE`] when a notification of one went,
    /// and a program that ended has its memory's capability gone from its
    /// slot too. (A program that never listened nor connected has nothing
    /// watched; it is found here at the next [`GONE`], or let go of when its
    /// service lends memory again.)
    pub fn forget_ended(&mut self) {
        let gone: Vec<u64> = self
            .clients
            .iter()
            .filter(|c| !matches!(sys::inspect_slot(slots::SPACE, c.frame.cap().0), Ok(Some(_))))
            .map(|c| c.badge)
            .collect();
        for badge in gone {
            self.forget(badge);
        }
    }

    /// Let go of everything the program behind `badge` had: its listeners
    /// (their ports free for any program), its connections (reset: no
    /// program reads them any more), and its memory.
    fn forget(&mut self, badge: u64) {
        let listeners: Vec<u32> = self.listeners.iter().filter(|l| l.owner == badge).map(|l| l.id).collect();
        self.listeners.retain(|l| l.owner != badge);
        for c in self.conns.iter_mut() {
            let waiting = c.listener.is_some_and(|l| listeners.contains(&l));
            if !(c.owner == badge || waiting) {
                continue;
            }
            if !c.released {
                c.tcp.abort();
                c.released = true;
                c.due = true;
                c.streams = None;
            } else if !c.tcp.is_closed() && c.tcp.state() != State::TimeWait {
                // One it had let go of that TCP was not done with: it was
                // its program's to pay for, and ends with it (before, it
                // outlived its program for as long as its peer liked).
                c.tcp.abort();
                c.due = true;
            }
        }
        self.clients.retain(|c| c.badge != badge);
    }

    pub fn listen(&mut self, badge: u64, ready: Handle) -> Result<proto::ListenGrantedReply, Error> {
        // The port is the one the caller's capability carries, never one it
        // names or claims first (before: any holder could take any port, the
        // remote service's included, while that service started again). The
        // service manager gives a port to one declaration only, so `in_use`
        // is this caller listening on it already.
        let port = scope::tcp_listen(badge).ok_or(Error::NotGranted)?;
        if self.listeners.iter().any(|l| l.port == port) {
            return Err(Error::InUse);
        }
        if self.listeners.len() >= LISTENERS {
            return Err(Error::NoRoom);
        }
        let id = self.number();
        let ready = Watched::new(ready, self.note)?;
        self.listeners.push(Listener { id, owner: badge, port, ready });
        Ok(proto::ListenGrantedReply { listener: id, port })
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
        let wake = Watched::new(wake, self.note)?;
        let c = &mut self.conns[i];
        c.listener = None;
        c.due = true;
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
        if !scope::has(badge, scope::TCP_CONNECT) {
            return Err(Error::NotGranted);
        }
        let local = local.ok_or(Error::NoAddress)?;
        if peer.port == 0 || peer.address == 0 {
            return Err(Error::BadArgument);
        }
        if !self.make_room(badge) {
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
        let r = silica_rt::random::u64();
        let mut tcp = Connection::connect(ends, r as u32, (r >> 32) as u32, self.mtu, buffers);
        tcp.set_offloads(self.checksum_offload, self.most_payload);
        let id = self.number();
        let requests = self.requests(id)?;
        let wake = Watched::new(wake, self.note)?;
        let streams = Streams { rx, tx, wake, offset, bits, rx_closed: false, tx_closed: false };
        let record = self.record(&tcp);
        self.add_conn(Conn {
            id,
            record,
            owner: badge,
            tcp,
            streams: Some(streams),
            listener: None,
            announced: true,
            released: false,
            due: true,
        });
        Ok(proto::ConnectReply { connection: id, requests })
    }

    pub fn close(&mut self, badge: u64, connection: u32) -> Result<proto::CloseReply, Error> {
        let c = self.conns.iter_mut().find(|c| c.id == connection && c.owner == badge && !c.released).ok_or(Error::NoSuch)?;
        // What the program wrote and has not been taken yet is taken now:
        // a program that finishes and closes at once must not lose its last
        // bytes (httpd did, under a small window: the interop suite). What
        // does not fit TCP's buffer yet waits, and the program with it.
        if let Some(s) = c.streams.as_mut()
            && !s.tx_closed
        {
            let mut scratch = [0u8; 2048];
            loop {
                match s.tx.available() {
                    // Only its end may be left: taken, the FIN follows the data.
                    Ok(0) => {
                        if let Ok(Read::Closed(_)) = s.tx.read(&mut scratch) {
                            c.tcp.close();
                            s.tx_closed = true;
                        }
                        break;
                    }
                    Ok(_) => {
                        let room = c.tcp.writable().min(scratch.len());
                        if room == 0 {
                            // Worth waiting for only if the program finished
                            // (else it is reset anyway) and TCP can still send.
                            if s.tx.ended().is_some() && c.tcp.error().is_none() {
                                return Err(Error::WouldBlock);
                            }
                            break;
                        }
                        let Ok(Read::Bytes(n)) = s.tx.read(&mut scratch[..room]) else { break };
                        c.tcp.send(&scratch[..n]);
                    }
                    // A broken stream: a reset, below.
                    Err(_) => break,
                }
            }
        }
        // Ended in order on this side, with nothing received left unread:
        // TCP finishes on its own (its FIN after the data, its last
        // acknowledgements, TIME-WAIT). Until it has, the connection is
        // still its program's: counted among its connections, ended when
        // it ends, and giving its place when it needs one (`make_room`).
        // Otherwise (the program never finished, or left bytes unread: RFC
        // 9293 section 3.6, RFC 1122 4.2.2.13) a reset.
        let unread = c.tcp.readable() > 0 || c.streams.as_ref().is_some_and(|s| s.rx.unread() > 0);
        let orderly = c.streams.as_ref().is_some_and(|s| s.tx_closed) && !unread && c.tcp.error().is_none();
        if !orderly {
            c.tcp.abort();
        }
        c.tcp.release(silica_rt::clock().now());
        c.released = true;
        c.due = true;
        c.streams = None;
        Ok(proto::CloseReply {})
    }

    /// Reset a connection now and let go of it, whatever it had still to
    /// send (`reset`): one its program closed and will not wait for.
    pub fn reset_conn(&mut self, badge: u64, connection: u32) -> Result<proto::ResetReply, Error> {
        let c = self.conns.iter_mut().find(|c| c.id == connection && c.owner == badge && !c.released).ok_or(Error::NoSuch)?;
        c.tcp.abort();
        c.released = true;
        c.due = true;
        c.streams = None;
        Ok(proto::ResetReply {})
    }

    /// The machine's address went (its lease ended): every connection on it
    /// ends now, its program told at once, rather than lingering until its
    /// retransmissions give up some ten minutes later, holding its place
    /// and buffers, its segments dropped or sent with the wrong checksum.
    pub fn address_gone(&mut self) {
        for c in self.conns.iter_mut().filter(|c| !c.tcp.is_closed()) {
            c.tcp.abort();
            c.due = true;
        }
    }

    pub fn unlisten(&mut self, badge: u64, listener: u32) -> Result<proto::UnlistenReply, Error> {
        let at = self.listeners.iter().position(|l| l.id == listener && l.owner == badge).ok_or(Error::NoSuch)?;
        self.listeners.remove(at);
        for c in self.conns.iter_mut().filter(|c| c.listener == Some(listener)) {
            c.tcp.abort();
            c.due = true;
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
            out.send(remote, &seg[..n], false, 0);
            self.segment = seg;
        }
    }
}
