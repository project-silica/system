//! One TCP connection (RFC 9293), as a state machine that is given the time
//! and what arrived, and asked what to send. It does no input or output of
//! its own and keeps no clock, so every path is tested on the host and the
//! stack decides when to run it.
//!
//! The stack hands it each segment for its four-tuple ([`Connection::on_segment`]),
//! then asks it for segments until it has none ([`Connection::poll`]), and
//! wakes it at [`Connection::deadline`]. The application's side is
//! [`Connection::send`], [`Connection::recv`] and [`Connection::close`].
//!
//! What it implements: the states and the acceptability rules of RFC 9293;
//! retransmission with RFC 6298's timer (Karn's rule; a 200 ms floor, as
//! Linux; doubling to 60 s); NewReno congestion control (RFC 5681 and RFC
//! 6582: slow start from ten segments (RFC 6928), fast retransmit on the
//! third duplicate acknowledgement, recovery until everything sent before it
//! is acknowledged); window scaling and timestamps (RFC 7323: round-trip
//! times from echoed timestamps, old segments refused by PAWS); SACK and
//! DSACK feedback, time-based loss detection and tail probes (RFCs 2018,
//! 2883 and 8985); a zero window probed; and the
//! defences of RFC 5961 against blind resets and SYNs (a reset or SYN that
//! is not exactly where it must be only draws a challenge acknowledgement).
//!
//! Open features include CUBIC, BBR, ECN, keepalive and path MTU discovery.
//!
//! Its buffers are given to it ([`Buffers`]); it does not allocate.

use crate::tcp::{ACK, FIN, Header, Options, PSH, RST, SACK_BLOCKS, SYN, Segment};
use crate::{Ipv4, tcp};

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000 * MS;
/// The retransmission timer before a round trip is measured (RFC 6298).
const RTO_INITIAL: u64 = SECOND;
/// Its floor and ceiling.
const RTO_MIN: u64 = 200 * MS;
const RTO_MAX: u64 = 60 * SECOND;
/// The smallest packet a path is taken to carry (RFC 1191: 576 bytes, what
/// every IPv4 host takes whole); a router's word for less is not believed.
pub const MTU_FLOOR: u32 = 576;
/// How long PAWS keeps the newest timestamp it saw (RFC 7323 5.5: less
/// than the 24.8 days a 1 kHz clock takes to run half its range).
const PAWS_IDLE: u64 = 24 * 24 * 3600 * SECOND;
/// Retransmissions of one segment before the connection is given up:
/// about 15 minutes at the ceiling for data, as Linux's default; a SYN is
/// given up sooner (about two minutes).
const RETRIES: u32 = 15;
const SYN_RETRIES: u32 = 6;
/// How long a connection closed from this side stays to answer its peer's
/// last segments (twice the maximum segment lifetime, as Linux).
const TIME_WAIT: u64 = 60 * SECOND;
/// The longest a connection stays in TIME-WAIT, however often the peer's
/// FIN comes again.
const TIME_WAIT_MOST: u64 = 4 * TIME_WAIT;
/// How long a connection in FIN-WAIT-2 (this side has finished, the peer
/// has not) that its program has let go of waits with nothing from the
/// peer before it is ended ([`Connection::release`]).
const FIN_WAIT_2_IDLE: u64 = 60 * SECOND;
/// The segment size assumed of a peer that names none (RFC 9293).
const DEFAULT_MSS: u16 = 536;
/// Least time between answers to segments outside the window, challenges
/// included (RFC 5961 section 7; Linux's tcp_invalid_ratelimit): two ends
/// that each find the other's segments out of window would otherwise
/// answer each other for ever, and a blind sender could make this end
/// send an ACK for every segment it forges.
const INVALID_ANSWER_GAP: u64 = 500 * MS;
/// Ranges held beyond a gap that a connection keeps track of; SACK reports
/// the newest [`SACK_BLOCKS`] (three beside timestamps). Fewer, as when it
/// kept only what one SACK option holds, and data it had SACKed was
/// forgotten with more holes than that (reneging, RFC 2018 section 8): a
/// sender that trusts SACKs then waits for its timeout to send it again.
const HOLES: usize = 32;
/// Segments in flight a connection keeps track of (RACK's scoreboard): new
/// data waits while it is full. 64 segments of 1,448 bytes is more than a
/// 64 KiB window.
const SEGS: usize = 64;
/// Recoveries a grown reordering window outlasts the last sign of
/// reordering (RFC 8985 section 6.2.4).
const REO_PERSIST: u8 = 16;
/// The shortest wait for a tail loss probe (RFC 8985 section 7.2 asks for
/// two round trips; on a path of a few hundred microseconds that is shorter
/// than a peer's acknowledgement takes to come).
const PTO_MIN: u64 = 2 * MS;

/// One segment sent and not yet acknowledged: where it ends (it starts
/// where the one before it ends), when it last went, and what is known of
/// it (RFC 8985's per-segment state).
#[derive(Clone, Copy, Default)]
struct Sent {
    end: u32,
    at: u64,
    flags: u8,
}

/// The peer SACKed it.
const SACKED: u8 = 1;
/// Taken for lost: it goes again as soon as the window allows.
const LOST: u8 = 2;
/// It went more than once.
const RETRANS: u8 = 4;

/// Where the connection is (RFC 9293's states; LISTEN is the stack's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// Why a connection ended other than by both sides closing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer refused the connection (a reset to the SYN).
    Refused,
    /// The peer reset the connection.
    Reset,
    /// The peer stopped acknowledging.
    TimedOut,
    /// This side reset it ([`Connection::abort`]).
    Aborted,
}

/// A connection's state as [`Connection::info`] reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub state: State,
    /// The first byte not acknowledged, the next to send and the highest
    /// sent, from the initial sequence number.
    pub unacked: u32,
    pub next: u32,
    pub highest: u32,
    /// Where the FIN went, once sent.
    pub fin: Option<u32>,
    /// The peer's window, the congestion window and its threshold (bytes).
    pub peer_window: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
    /// Window reductions undone, shown needless by the peer's DSACKs.
    pub undone: u32,
    /// The retransmission timer and the smoothed round trip (ns).
    pub rto: u64,
    pub srtt: u64,
    /// Retransmissions since the last acknowledgement.
    pub retries: u32,
    /// Bytes held to send (not acknowledged), and to read.
    pub queued: u32,
    pub readable: u32,
}

/// A connection's two ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoints {
    pub local: Ipv4,
    pub local_port: u16,
    pub remote: Ipv4,
    pub remote_port: u16,
}

/// The memory a connection's data waits in: bytes sent and not yet
/// acknowledged, and bytes received and not yet read.
pub struct Buffers<S> {
    pub send: S,
    pub receive: S,
}

/// A window reduction that may prove needless (RFC 3708; Linux's
/// `undo_marker` and `undo_retrans`): segments taken for lost that had
/// only been overtaken by later ones, as reordering does, are sent again and
/// the peer then reports each twice (a DSACK). When it has so reported every
/// segment sent again since the reduction, nothing was lost, and the window
/// and threshold go back to what they were.
#[derive(Clone, Copy)]
struct Undo {
    /// `snd_una` when the reduction was made: a DSACK below it is of an
    /// older episode's segment.
    from: u32,
    cwnd: u32,
    ssthresh: u32,
    /// Segments sent again since, that no DSACK has reported yet.
    resent: u32,
}

/// A byte ring over storage the caller gave.
struct Ring<S> {
    buf: S,
    start: usize,
    len: usize,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Ring<S> {
    fn cap(&self) -> usize {
        self.buf.as_ref().len()
    }

    fn free(&self) -> usize {
        self.cap() - self.len
    }

    /// Copy `data` in at `at` bytes past the end of what it holds (which
    /// stays as it was), as far as it fits; returns how much did.
    fn write_beyond(&mut self, at: usize, data: &[u8]) -> usize {
        let cap = self.cap();
        if at >= self.free() {
            return 0;
        }
        let n = data.len().min(self.free() - at);
        let mut pos = (self.start + self.len + at) % cap;
        let mut done = 0;
        while done < n {
            let run = (n - done).min(cap - pos);
            self.buf.as_mut()[pos..pos + run].copy_from_slice(&data[done..done + run]);
            done += run;
            pos = (pos + run) % cap;
        }
        n
    }

    /// Append what fits of `data`; returns how much did.
    fn push(&mut self, data: &[u8]) -> usize {
        let n = self.write_beyond(0, data);
        self.len += n;
        n
    }

    /// Copy out up to `out.len()` bytes from `at` bytes in, leaving them.
    fn peek(&self, at: usize, out: &mut [u8]) -> usize {
        let cap = self.cap();
        let n = out.len().min(self.len.saturating_sub(at));
        let mut pos = (self.start + at) % cap.max(1);
        let mut done = 0;
        while done < n {
            let run = (n - done).min(cap - pos);
            out[done..done + run].copy_from_slice(&self.buf.as_ref()[pos..pos + run]);
            done += run;
            pos = (pos + run) % cap;
        }
        n
    }

    /// Drop `n` bytes from the front.
    fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.start = (self.start + n) % self.cap().max(1);
        self.len -= n;
    }
}

/// Whether sequence number `a` comes before `b` (RFC 9293's modular order).
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn before_eq(a: u32, b: u32) -> bool {
    !before(b, a)
}

/// One connection.
pub struct Connection<S> {
    ends: Endpoints,
    state: State,
    error: Option<Error>,

    // Sending: everything from `snd_una` to `snd_max` has been sent once;
    // `snd_nxt` is where the next segment starts (behind `snd_max` while
    // going back over a loss). The send ring holds the data from the first
    // byte not acknowledged.
    iss: u32,
    /// The SYN occupies the first sequence number until its ACK arrives.
    syn_unacked: bool,
    snd_una: u32,
    snd_nxt: u32,
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_scale: u8,
    mss: u32,
    /// The segment this side takes: what it offers in its SYN.
    own_mss: u32,
    send: Ring<S>,
    /// The application has closed its side: a FIN follows the data.
    fin_queued: bool,
    /// Where the FIN went, once it was sent: it stays there.
    fin_sent: Option<u32>,
    /// The segments in flight, oldest first: `segs_len` of them in a ring
    /// from `segs_head`, the first starting at `segs_start` (each where the
    /// one before it ends).
    segs: [Sent; SEGS],
    segs_head: usize,
    segs_len: usize,
    segs_start: u32,

    // Receiving: the receive ring holds what arrived in order and was not
    // read; what arrived beyond a gap lies past it, in `holes`' ranges.
    rcv_nxt: u32,
    rcv_scale: u8,
    receive: Ring<S>,
    holes: [(u32, u32); HOLES],
    holes_len: usize,
    /// Where the peer's FIN is, when it arrived beyond a gap.
    fin_at: Option<u32>,
    /// The right edge of the window last advertised.
    rcv_adv: u32,
    ack_due: bool,

    // Timers.
    rto: u64,
    srtt: u64,
    rttvar: u64,
    /// A segment being timed (Karn: only one sent once): its end, when.
    timing: Option<(u32, u64)>,
    /// The timestamp of the latest retransmission while one is
    /// unacknowledged: an echo older than it may be of the first sending,
    /// and a round trip from it would count the wait for the timeout.
    resent_ts: Option<u32>,
    retransmit_at: Option<u64>,
    retries: u32,
    time_wait_until: Option<u64>,
    /// When TIME-WAIT must end however often the peer's FIN comes again.
    time_wait_most: Option<u64>,
    /// Its program let go of it ([`Connection::release`]).
    released: bool,

    // Congestion: RFC 5681's window, halved once a round trip of losses;
    // `recover` is where the recovery from them ends. Duplicates count
    // only with a peer that does not SACK.
    cwnd: u32,
    /// Bytes acknowledged toward one window of congestion avoidance.
    avoidance_bytes: u32,
    ssthresh: u32,
    dupacks: u32,
    recover: Option<u32>,
    first_repair: bool,
    /// What the interface does for this connection's segments
    /// (`set_offloads`): sums their checksums, and the most payload one
    /// segment it is given may carry (the MSS when it cuts nothing).
    checksum_offload: bool,
    most_payload: u32,
    /// The last reduction, while it can still be shown needless.
    undo: Option<Undo>,
    /// Reductions undone so far.
    undone: u32,

    // RACK (RFC 8985): the newest-sent segment the peer has (when it went,
    // where it ends) and its round trip, the smallest round trip seen,
    // reordering windows to wait (grown by DSACKs), when to look again for
    // losses a reordering window still hides; and the tail loss probe's
    // time and whether it is due.
    rack_at: u64,
    rack_end: u32,
    rack_rtt: u64,
    min_rtt: u64,
    reo_mult: u32,
    /// How late, past RACK's expectation, a segment that was sent once
    /// arrived behind one sent after it: reordering the path has shown,
    /// measured, which the window covers without a resent segment's DSACK
    /// first having to show it.
    reo_seen: u64,
    /// Recoveries left before a reordering window grown and not shown
    /// again goes back to its start (RFC 8985 6.2.4's 16).
    reo_persist: u8,
    reorder_at: Option<u64>,
    probe_at: Option<u64>,
    tlp_due: bool,

    // Timestamps: the offset this connection's are taken from, and the
    // peer's latest (RFC 7323), when both sides use them.
    timestamps: bool,
    ts_offset: u32,
    ts_recent: u32,
    /// When `ts_recent` was last set: PAWS forgets it after [`PAWS_IDLE`].
    ts_recent_at: Option<u64>,
    /// The first and the newest timestamp this side has sent: an echo is
    /// believed only between them (a peer cannot make the round trip look
    /// shorter by echoing a value never sent).
    ts_sent: Option<(u32, u32)>,
    /// Peer understands SACK blocks.
    sack: bool,
    /// The peer's SYN carried a window scale (so both sides scale).
    scaling: bool,
    /// A reset to send, at this sequence number, with an ACK or without.
    reset: Option<(u32, bool)>,
    /// When a segment outside the window was last answered.
    answered_invalid_at: Option<u64>,
    /// The persist timer fired: probe the shut window.
    probe_due: bool,
    /// A segment that arrived again, all of it already in order: reported
    /// first in the next acknowledgement's SACK blocks (a DSACK, RFC 2883),
    /// which tells the peer its retransmission was not needed.
    dsack: Option<(u32, u32)>,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Connection<S> {
    fn new(ends: Endpoints, state: State, iss: u32, ts_offset: u32, mtu: u16, buffers: Buffers<S>) -> Connection<S> {
        let cap = buffers.receive.as_ref().len().min(1 << 30);
        // The smallest shift that lets the whole receive buffer be offered.
        let mut scale = 0u8;
        while scale < 14 && (cap >> scale) > u16::MAX as usize {
            scale += 1;
        }
        let mss = u32::from(mtu.saturating_sub(40).max(64));
        Connection {
            ends,
            state,
            error: None,
            iss,
            syn_unacked: true,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_scale: 0,
            mss,
            own_mss: mss,
            send: Ring { buf: buffers.send, start: 0, len: 0 },
            fin_queued: false,
            fin_sent: None,
            segs: [Sent::default(); SEGS],
            segs_head: 0,
            segs_len: 0,
            segs_start: iss,
            rcv_nxt: 0,
            rcv_scale: scale,
            receive: Ring { buf: buffers.receive, start: 0, len: 0 },
            holes: [(0, 0); HOLES],
            holes_len: 0,
            fin_at: None,
            rcv_adv: 0,
            ack_due: false,
            rto: RTO_INITIAL,
            srtt: 0,
            rttvar: 0,
            timing: None,
            resent_ts: None,
            retransmit_at: None,
            retries: 0,
            time_wait_until: None,
            time_wait_most: None,
            released: false,
            cwnd: 10 * mss,
            avoidance_bytes: 0,
            ssthresh: u32::MAX,
            dupacks: 0,
            recover: None,
            first_repair: false,
            checksum_offload: false,
            most_payload: 0,
            undo: None,
            undone: 0,
            rack_at: 0,
            rack_end: iss,
            rack_rtt: 0,
            min_rtt: u64::MAX,
            reo_mult: 1,
            reo_seen: 0,
            reo_persist: 0,
            reorder_at: None,
            probe_at: None,
            tlp_due: false,
            timestamps: true,
            ts_offset,
            ts_recent: 0,
            ts_recent_at: None,
            ts_sent: None,
            sack: true,
            scaling: false,
            reset: None,
            answered_invalid_at: None,
            probe_due: false,
            dsack: None,
        }
    }

    /// Open a connection to `ends.remote`: its SYN goes out on the next
    /// [`Connection::poll`]. `iss` is its initial sequence number and
    /// `ts_offset` what its timestamps count from, each unpredictable and
    /// unrelated to the other (RFC 6528, RFC 7323 section 5.4: with the one
    /// derived from the other, as they once were, a peer that sees both in
    /// the SYN learns the machine's uptime); `mtu` the interface's.
    pub fn connect(ends: Endpoints, iss: u32, ts_offset: u32, mtu: u16, buffers: Buffers<S>) -> Connection<S> {
        Connection::new(ends, State::SynSent, iss, ts_offset, mtu, buffers)
    }

    /// Answer `syn`, which arrived for a listening port: the SYN-ACK goes
    /// out on the next [`Connection::poll`].
    pub fn accept(ends: Endpoints, syn: &Segment<'_>, iss: u32, ts_offset: u32, mtu: u16, buffers: Buffers<S>) -> Connection<S> {
        let mut c = Connection::new(ends, State::SynReceived, iss, ts_offset, mtu, buffers);
        c.take_syn(syn);
        c
    }

    /// What a SYN says about its sender.
    fn take_syn(&mut self, syn: &Segment<'_>) {
        self.rcv_nxt = syn.header.seq.wrapping_add(1);
        self.rcv_adv = self.rcv_nxt;
        let o = &syn.options;
        self.mss = self.mss.min(u32::from(o.mss.unwrap_or(DEFAULT_MSS).max(64)));
        match o.window_scale {
            Some(s) => {
                self.snd_scale = s;
                self.scaling = true;
            }
            // Either side not scaling: neither does (RFC 7323).
            None => self.rcv_scale = 0,
        }
        self.sack = o.sack_permitted;
        match o.timestamps {
            Some((val, _)) => self.ts_recent = val,
            None => self.timestamps = false,
        }
        if self.timestamps {
            self.mss -= 12;
        }
        self.cwnd = 10 * self.mss;
        // The SYN's own window is never scaled.
        self.snd_wnd = u32::from(syn.header.window);
        self.snd_wl1 = syn.header.seq;
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Give back the buffers once nothing can go into or out of them: in
    /// TIME-WAIT, and once closed, a connection does no more than answer a
    /// peer's repeated FIN, which takes no data. A server that closes first
    /// keeps each connection there for a minute (RFC 9293 section 3.6.1),
    /// so its buffers must not stay with it: a server answering a thousand
    /// connections a second would hold four gigabytes in buffers nobody can
    /// use (Linux keeps a small time-wait record for the same reason).
    /// Returns them for the caller to free; `None` in any other state, or
    /// when they were given back already.
    pub fn shed(&mut self) -> Option<Buffers<S>>
    where
        S: Default + AsRef<[u8]>,
    {
        if !matches!(self.state, State::TimeWait | State::Closed)
            || self.send.buf.as_ref().is_empty() && self.receive.buf.as_ref().is_empty()
        {
            return None;
        }
        let send = core::mem::take(&mut self.send.buf);
        let receive = core::mem::take(&mut self.receive.buf);
        for r in [&mut self.send, &mut self.receive] {
            r.start = 0;
            r.len = 0;
        }
        self.holes_len = 0;
        Some(Buffers { send, receive })
    }

    pub fn endpoints(&self) -> Endpoints {
        self.ends
    }

    /// The sequence number past everything sent: what a reset of this
    /// connection carries when the stack that had it is gone and the next
    /// one resets it from its record (`netd`'s kept page). A peer that
    /// finds it outside its window answers with a challenge ACK (RFC
    /// 5961), whose acknowledgement the reset to an unknown connection
    /// then carries exactly.
    pub fn sent_to(&self) -> u32 {
        self.snd_max
    }

    /// The sequence number the peer sends next (0 before its SYN is seen):
    /// what that reset acknowledges, so that a peer still waiting for the
    /// answer to its SYN takes it. In SYN-SENT a peer drops a reset that
    /// does not acknowledge its SYN (RFC 9293 section 3.10.7.3), and then
    /// waits for its own retransmission instead (5.9 s, QEMU's user-mode
    /// network, 2026-11-24).
    pub fn received_to(&self) -> u32 {
        self.rcv_nxt
    }

    /// Why the connection ended, if it did otherwise than by closing.
    pub fn error(&self) -> Option<Error> {
        self.error
    }

    /// Whether the stack may forget it: closed, nothing left to send.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed && self.reset.is_none()
    }

    /// Bytes waiting to be read.
    pub fn readable(&self) -> usize {
        self.receive.len
    }

    /// Whether the peer has finished sending and everything it sent was read.
    pub fn at_end(&self) -> bool {
        self.receive.len == 0 && self.peer_finished()
    }

    fn peer_finished(&self) -> bool {
        matches!(self.state, State::CloseWait | State::LastAck | State::Closing | State::TimeWait)
            || (self.state == State::Closed && self.error.is_none())
    }

    /// Room for more data to send.
    pub fn writable(&self) -> usize {
        if self.fin_queued || !self.can_send_data() { 0 } else { self.send.free() }
    }

    /// The send buffer is what holds the connection back: every byte in it
    /// has been sent and awaits acknowledgement, and the peer's window, the
    /// congestion window and the scoreboard would each let more go now.
    /// A larger buffer (`grow_send_buffer`) lets it send at the rate the
    /// path allows; in loss recovery it also lets new data go behind a
    /// repair, whose delivery is what shows a lost repair without waiting
    /// for the retransmission timeout (RFC 8985 section 6.2).
    pub fn buffer_limited(&self) -> bool {
        !self.fin_queued
            && self.can_send_data()
            && self.send.free() == 0
            && self.snd_nxt == self.send_base().wrapping_add(self.send.len as u32)
            && self.segs_len < SEGS
            && before(self.snd_nxt, self.snd_una.wrapping_add(self.snd_wnd))
            && self.pipe() < self.cwnd
    }

    /// What the interface does for this connection's segments: sum their
    /// checksums (each segment then carries only the pseudo-header's sum,
    /// `tcp::seal_partial`), and take segments of up to `most_payload`
    /// bytes of data, which it cuts into MSS-sized ones (TCP segmentation
    /// offload; at most the MSS for an interface that does not). The
    /// caller asks the interface for what it said, for every segment
    /// `poll` gives, and segmentation only with the checksum.
    pub fn set_offloads(&mut self, checksum: bool, most_payload: u32) {
        self.checksum_offload = checksum;
        self.most_payload = if checksum { most_payload } else { 0 };
    }

    /// The most data one segment `poll` gives may carry: the MSS, or as many
    /// MSS as the interface cuts and the scoreboard has records for.
    fn burst(&self) -> u32 {
        let mss = self.mss.max(1);
        if self.most_payload <= mss {
            return mss;
        }
        let records = (SEGS - self.segs_len) as u32;
        (self.most_payload / mss).min(records).max(1) * mss
    }

    /// Bytes the send buffer holds at most (0 once shed).
    pub fn send_capacity(&self) -> usize {
        self.send.cap()
    }

    /// Supply a larger send buffer. Bytes already queued, including those
    /// still needed for retransmission, keep their sequence numbers.
    /// Refused (false, the buffer handed back dropped) unless it is larger.
    pub fn grow_send_buffer(&mut self, mut buffer: S) -> bool {
        let capacity = buffer.as_ref().len();
        if !self.can_send_data() || capacity <= self.send.cap() || capacity > i32::MAX as usize {
            return false;
        }
        self.send.peek(0, buffer.as_mut());
        self.send.buf = buffer;
        self.send.start = 0;
        true
    }

    fn can_send_data(&self) -> bool {
        matches!(self.state, State::SynSent | State::SynReceived | State::Established | State::CloseWait)
    }

    /// The largest segment's payload, after options.
    pub fn mss(&self) -> u32 {
        self.mss
    }

    /// A router says the path to the peer carries at most `mtu` bytes a
    /// packet (ICMP fragmentation needed, RFC 1191), quoting the segment
    /// that did not fit, which began at `seq`. Believed only if `seq` is in
    /// flight (RFC 5927 5.1: a blind sender does not know it); then segments
    /// are cut to fit, and what is in flight goes again in pieces that do:
    /// a lost segment, not congestion. A size below [`MTU_FLOOR`] is not
    /// taken. Returns whether the segment size went down.
    pub fn path_mtu(&mut self, mtu: u16, seq: u32) -> bool {
        if !matches!(self.state, State::Established | State::CloseWait | State::FinWait1 | State::Closing | State::LastAck)
            || before(seq, self.snd_una)
            || !before(seq, self.snd_max)
        {
            return false;
        }
        let mss = self.mss_for(u32::from(mtu).max(MTU_FLOOR));
        if mss >= self.mss {
            return false;
        }
        self.mss = mss;
        self.cwnd = self.cwnd.max(self.mss);
        for k in 0..self.segs_len {
            if self.seg(k).flags & SACKED == 0 {
                self.seg_mut(k).flags |= LOST;
            }
        }
        true
    }

    /// The segment data a packet of `mtu` bytes carries: IPv4 and TCP
    /// headers and the timestamps option taken off.
    fn mss_for(&self, mtu: u32) -> u32 {
        mtu - 40 - if self.timestamps { 12 } else { 0 }
    }

    /// Take what fits of `data` to send; returns how much it took.
    pub fn send(&mut self, data: &[u8]) -> usize {
        if self.fin_queued || !self.can_send_data() {
            return 0;
        }
        self.send.push(data)
    }

    /// Read up to `out.len()` bytes in order; returns how many.
    pub fn recv(&mut self, out: &mut [u8]) -> usize {
        let n = self.receive.peek(0, out);
        self.receive.consume(n);
        // Tell the peer of the room made once it is worth a segment (no
        // silly window: RFC 9293 3.8.6.2.2), so that a sender stopped by a
        // full window starts again.
        let room = self.rcv_nxt.wrapping_add(self.receive.free() as u32).wrapping_sub(self.rcv_adv);
        if n > 0 && room as i32 > 0 && room as usize >= (self.receive.cap() / 2).min(self.mss as usize) {
            self.ack_due = true;
        }
        n
    }

    /// Nothing more will be sent: a FIN follows what was. Reading goes on.
    /// Before the connection is open this waits for it (data written and
    /// closed at once is still delivered); [`Connection::abort`] cancels.
    pub fn close(&mut self) {
        if self.can_send_data() {
            self.fin_queued = true;
        }
    }

    /// Its program has let go of it (after [`Connection::close`]): nothing
    /// more is read from it, so in FIN-WAIT-2 a peer that sends nothing for
    /// `FIN_WAIT_2_IDLE` ends it, as an orphaned socket's on Linux. While
    /// a program holds it, FIN-WAIT-2 is a half-close and lasts as long as
    /// the peer likes; once nobody does, a peer that goes silent no longer
    /// holds it for ever.
    pub fn release(&mut self, now: u64) {
        self.released = true;
        if self.state == State::FinWait2 && self.time_wait_until.is_none() {
            self.time_wait_until = Some(now + FIN_WAIT_2_IDLE);
        }
    }

    /// End the connection now with a reset; what was not sent is dropped.
    pub fn abort(&mut self) {
        let synchronized = !matches!(self.state, State::SynSent | State::Closed | State::TimeWait);
        let seq = self.snd_nxt;
        self.end(Some(Error::Aborted));
        if synchronized {
            self.reset = Some((seq, true));
        }
    }

    fn end(&mut self, error: Option<Error>) {
        self.state = State::Closed;
        self.error = self.error.or(error);
        self.retransmit_at = None;
        self.reorder_at = None;
        self.probe_at = None;
        self.time_wait_until = None;
        self.send.consume(self.send.len);
    }

    /// When [`Connection::on_time`] wants to run next.
    pub fn deadline(&self) -> Option<u64> {
        [self.retransmit_at, self.time_wait_until, self.reorder_at, self.probe_at].into_iter().flatten().min()
    }

    /// The time is `now`: retransmit, probe or give up if it is time.
    pub fn on_time(&mut self, now: u64) {
        if self.time_wait_until.is_some_and(|t| now >= t) {
            // TIME-WAIT is over; or FIN-WAIT-2 heard nothing from the peer
            // for `FIN_WAIT_2_IDLE`, and gives up on its FIN.
            let silent = self.state == State::FinWait2;
            self.end(silent.then_some(Error::TimedOut));
            return;
        }
        if self.reorder_at.is_some_and(|t| now >= t) && self.detect_losses(now) {
            self.losses_found();
        }
        if self.probe_at.is_some_and(|t| now >= t) {
            self.probe_at = None;
            if self.snd_max != self.snd_una && self.recover.is_none() {
                // The tail went unanswered for two round trips: a probe
                // (`poll_data`), and the timeout after it (RFC 8985 7.3).
                self.tlp_due = true;
                self.retransmit_at = Some(now + self.rto);
            }
        }
        let Some(at) = self.retransmit_at else { return };
        if now < at {
            return;
        }
        self.retransmit_at = None;
        let limit = if matches!(self.state, State::SynSent | State::SynReceived) { SYN_RETRIES } else { RETRIES };
        if self.retries >= limit {
            self.end(Some(Error::TimedOut));
            return;
        }
        self.retries += 1;
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        // Full-size segments unanswered twice in a row on a path that says
        // nothing (its routers' ICMP filtered): try smaller ones (RFC 4821
        // section 7.7's black hole), down to what any path carries.
        if self.retries >= 2 && flight > self.mss && self.mss > self.mss_for(MTU_FLOOR) {
            self.mss = (self.mss / 2).max(self.mss_for(MTU_FLOOR));
        }
        if flight == 0 {
            // The persist timer: the peer's window is shut and nothing is
            // in flight; the next poll probes it.
            self.probe_due = true;
            self.rto = (self.rto * 2).min(RTO_MAX);
            return;
        }
        // RFC 5681 on a timeout: half what was in flight is the threshold,
        // one segment the window; everything not acknowledged or SACKed is
        // taken for lost and goes again as the window grows (RFC 8985 6.3).
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.first_repair = false;
        // A timeout's reduction is not undone (no F-RTO, RFC 5682).
        self.undo = None;
        self.avoidance_bytes = 0;
        self.dupacks = 0;
        self.timing = None;
        self.tlp_due = false;
        self.probe_at = None;
        self.rto = (self.rto * 2).min(RTO_MAX);
        if matches!(self.state, State::SynSent | State::SynReceived) {
            // The SYN goes again (`poll`).
            self.recover = None;
            self.snd_nxt = self.snd_una;
            return;
        }
        self.recover = Some(self.snd_max);
        // A receiver may let go of what it SACKed (RFC 2018 section 8: after
        // a timeout the SACKed marks are cleared): everything goes again.
        for k in 0..self.segs_len {
            self.seg_mut(k).flags = (self.seg(k).flags & !SACKED) | LOST;
        }
    }

    /// The window to advertise, and keep its right edge from moving left.
    fn window(&mut self) -> u16 {
        let free = self.receive.free() as u32;
        let wnd = (free >> self.rcv_scale).min(u16::MAX as u32);
        let edge = self.rcv_nxt.wrapping_add(wnd << self.rcv_scale);
        if before(self.rcv_adv, edge) {
            self.rcv_adv = edge;
        }
        wnd as u16
    }

    fn ts_now(&self, now: u64) -> u32 {
        ((now / MS) as u32).wrapping_add(self.ts_offset)
    }

    /// Timestamp `val` goes out in a segment.
    fn note_ts_sent(&mut self, val: u32) {
        self.ts_sent = Some(match self.ts_sent {
            Some((first, _)) => (first, val),
            None => (val, val),
        });
    }

    /// The options of a segment that is not a SYN.
    fn options(&mut self, now: u64) -> Options {
        let mut o = Options::default();
        if self.timestamps {
            let val = self.ts_now(now);
            self.note_ts_sent(val);
            o.timestamps = Some((val, self.ts_recent));
        }
        let dsack = self.dsack.take().filter(|_| self.sack);
        if self.sack && (self.holes_len > 0 || dsack.is_some()) {
            let room = if self.timestamps { 3 } else { 4 };
            let blocks = dsack.into_iter().chain(self.holes[..self.holes_len].iter().copied()).take(room);
            for (i, b) in blocks.enumerate() {
                o.sack[i] = b;
                o.sack_len = i as u8 + 1;
            }
        }
        o
    }

    fn syn_options(&self, now: u64, answer: bool) -> Options {
        Options {
            mss: Some(self.own_mss.min(u16::MAX as u32) as u16),
            // An answer scales only if the peer offered to.
            window_scale: (!answer || self.scaling).then_some(self.rcv_scale),
            sack_permitted: self.sack,
            timestamps: self.timestamps.then(|| (self.ts_now(now), if answer { self.ts_recent } else { 0 })),
            ..Options::default()
        }
    }

    /// The sequence number of the first byte in the send ring.
    fn send_base(&self) -> u32 {
        self.snd_una.wrapping_add(u32::from(self.syn_unacked))
    }

    /// Where the FIN goes once queued: after all the data.
    fn fin_seq(&self) -> u32 {
        self.fin_sent.unwrap_or_else(|| self.send_base().wrapping_add(self.send.len as u32))
    }

    /// Whether the FIN was acknowledged.
    fn fin_acked(&self) -> bool {
        self.fin_sent.is_some_and(|f| before(f, self.snd_una))
    }

    /// Write the next segment due into `out` (whole, checksum included)
    /// and return its length, or `None` when nothing is due. Called until
    /// it says `None`; `out` must hold a header of 60 bytes and a segment.
    pub fn poll(&mut self, now: u64, out: &mut [u8]) -> Option<usize> {
        if let Some((seq, with_ack)) = self.reset.take() {
            let mut h = self.header(seq, if with_ack { RST | ACK } else { RST });
            if !with_ack {
                h.ack = 0;
            }
            h.window = 0;
            return self.emit(out, h, &Options::default(), None);
        }
        match self.state {
            State::Closed => return None,
            State::SynSent | State::SynReceived if self.snd_nxt == self.iss => {
                let answer = self.state == State::SynReceived;
                let flags = if answer { SYN | ACK } else { SYN };
                let mut h = self.header(self.iss, flags);
                if !answer {
                    h.ack = 0;
                }
                // A SYN's window is never scaled (RFC 7323).
                h.window = self.receive.free().min(u16::MAX as usize) as u16;
                self.rcv_adv = self.rcv_nxt.wrapping_add(u32::from(h.window));
                let o = self.syn_options(now, answer);
                if let Some((val, _)) = o.timestamps {
                    self.note_ts_sent(val);
                }
                self.sent(now, 1);
                return self.emit(out, h, &o, None);
            }
            State::SynSent | State::SynReceived => {
                // Nothing goes before the handshake is done but its acks.
                return self.pure_ack(now, out);
            }
            _ => {}
        }
        if let Some(n) = self.poll_data(now, out) {
            return Some(n);
        }
        // Whatever is in flight is timed, always.
        if self.snd_una != self.snd_max && self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
        }
        self.pure_ack(now, out)
    }

    fn pure_ack(&mut self, now: u64, out: &mut [u8]) -> Option<usize> {
        if !self.ack_due || self.state == State::SynSent {
            return None;
        }
        // A pure acknowledgement goes at the highest point sent (as
        // Linux): after a timeout snd_nxt goes back, and an ACK from there
        // would be behind the peer's window and refused.
        let h = self.header(self.snd_max, ACK);
        let o = self.options(now);
        self.emit(out, h, &o, None)
    }

    /// The next data or FIN segment allowed, if any: a segment taken for
    /// lost first, then a tail loss probe that is due, then new data, each
    /// as the windows allow.
    fn poll_data(&mut self, now: u64, out: &mut [u8]) -> Option<usize> {
        let pipe = self.pipe();
        if let Some(k) = (0..self.segs_len).find(|&k| self.seg(k).flags & LOST != 0)
            && (self.first_repair || pipe < self.cwnd)
        {
            self.first_repair = false;
            return self.resend(now, out, k);
        }
        let start = self.snd_nxt;
        let base = self.send_base();
        let offset = start.wrapping_sub(base) as usize;
        let waiting = self.send.len.saturating_sub(offset);
        let fin_seq = self.fin_seq();
        let fin_waits = self.fin_queued && !self.fin_acked() && before_eq(start, fin_seq);
        let peer_room = self.snd_una.wrapping_add(self.snd_wnd).wrapping_sub(start);
        let peer_room = if (peer_room as i32) < 0 { 0 } else { peer_room };
        let probing = core::mem::take(&mut self.tlp_due);
        if probing {
            // RFC 8985 section 7.3: new data if the peer's window takes it,
            // else the last segment again; either draws an acknowledgement
            // that shows what was lost at the tail.
            let new = (waiting > 0 || fin_waits) && peer_room > 0 && self.segs_len < SEGS;
            if !new && self.segs_len > 0 {
                return self.resend(now, out, self.segs_len - 1);
            }
        }
        if waiting == 0 && !fin_waits {
            return None;
        }
        if self.segs_len == SEGS {
            // The scoreboard is full: what is in flight must be heard of first.
            return None;
        }
        // What the peer's window and the congestion window allow (a probe:
        // the peer's alone).
        let room = if probing { peer_room } else { peer_room.min(self.cwnd.saturating_sub(pipe)) };
        if room == 0 && self.snd_wnd == 0 && self.snd_max == self.snd_una {
            // A shut window with nothing in flight: the persist timer
            // probes it with a segment just behind the window (as Linux),
            // which the peer answers with its window.
            if self.retransmit_at.is_none() {
                self.retransmit_at = Some(now + self.rto);
            }
            if !self.probe_due {
                return None;
            }
            self.probe_due = false;
            self.retransmit_at = Some(now + self.rto);
            let h = self.header(self.snd_una.wrapping_sub(1), ACK);
            let o = self.options(now);
            return self.emit(out, h, &o, None);
        }
        // What the caller's buffer holds behind the longest TCP header, too:
        // the segment is counted as sent before it is written.
        let fits = out.len().saturating_sub(60) as u32;
        let n = (waiting as u32).min(self.burst()).min(room).min(fits);
        let fin = fin_waits && n as usize == waiting && (n < room || waiting == 0);
        if n == 0 && !fin {
            return None;
        }
        let mut flags = ACK;
        if fin {
            flags |= FIN;
        }
        if n as usize == waiting && n > 0 {
            flags |= PSH;
        }
        let h = self.header(start, flags);
        let o = self.options(now);
        let len = n + fin as u32;
        if fin {
            self.fin_sent = Some(fin_seq);
        }
        // One record a segment as it goes on the wire, so that SACK and
        // RACK judge each one the interface cuts from a longer segment.
        // The FIN goes with the last of them.
        let mut at = start;
        let data_end = start.wrapping_add(n);
        loop {
            let piece = data_end.wrapping_sub(at).min(self.mss.max(1));
            let last = at.wrapping_add(piece) == data_end;
            let piece_end = at.wrapping_add(piece + u32::from(last && fin));
            self.record(at, piece_end, now);
            at = piece_end;
            if last {
                break;
            }
        }
        self.sent(now, len);
        self.emit(out, h, &o, Some((offset, n as usize)))
    }

    /// Send segment `k` of the scoreboard again, as it went the first time.
    fn resend(&mut self, now: u64, out: &mut [u8], k: usize) -> Option<usize> {
        let start = self.seg_start(k);
        // Larger than segments are now (the path said so): cut, the rest
        // left as its own record, lost too.
        if self.seg(k).end.wrapping_sub(start) > self.mss {
            self.split(k, start.wrapping_add(self.mss));
        }
        let seg = *self.seg(k);
        let fin = self.fin_sent.is_some() && seg.end == self.fin_seq().wrapping_add(1);
        // A record that could not be split (the scoreboard is full) goes a
        // piece at a time: the peer acknowledges inside it.
        let n = (seg.end.wrapping_sub(start) - fin as u32).min(self.mss);
        let fin = fin && n == seg.end.wrapping_sub(start) - 1;
        let offset = start.wrapping_sub(self.send_base()) as usize;
        let mut flags = ACK;
        if fin {
            flags |= FIN;
        }
        if k + 1 == self.segs_len && n > 0 {
            flags |= PSH;
        }
        let h = self.header(start, flags);
        let o = self.options(now);
        let s = self.seg_mut(k);
        s.flags = (s.flags | RETRANS) & !LOST;
        s.at = now;
        if let Some(u) = self.undo.as_mut() {
            u.resent += 1;
        }
        // An echo older than this may be of the first sending (Karn).
        self.resent_ts = Some(self.ts_now(now));
        self.timing = None;
        if self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
        }
        self.emit(out, h, &o, Some((offset, n as usize)))
    }

    fn seg(&self, k: usize) -> &Sent {
        &self.segs[(self.segs_head + k) % SEGS]
    }

    fn seg_mut(&mut self, k: usize) -> &mut Sent {
        &mut self.segs[(self.segs_head + k) % SEGS]
    }

    /// Where segment `k` of the scoreboard starts.
    fn seg_start(&self, k: usize) -> u32 {
        if k == 0 { self.segs_start } else { self.seg(k - 1).end }
    }

    /// Split scoreboard record `k` at `at` into two records alike (when
    /// there is room for one more).
    fn split(&mut self, k: usize, at: u32) {
        if self.segs_len == SEGS {
            return;
        }
        for j in (k + 1..=self.segs_len).rev() {
            let s = *self.seg(j - 1);
            *self.seg_mut(j) = s;
        }
        self.segs_len += 1;
        self.seg_mut(k).end = at;
    }

    /// Put a segment just sent on the scoreboard.
    fn record(&mut self, start: u32, end: u32, now: u64) {
        if self.segs_len == 0 {
            self.segs_start = start;
        }
        let i = (self.segs_head + self.segs_len) % SEGS;
        self.segs[i] = Sent { end, at: now, flags: 0 };
        self.segs_len += 1;
    }

    /// Bytes in flight as RFC 6675 counts them: sent, and neither
    /// acknowledged, SACKed nor taken for lost.
    fn pipe(&self) -> u32 {
        (0..self.segs_len)
            .filter(|&k| self.seg(k).flags & (SACKED | LOST) == 0)
            .map(|k| self.seg(k).end.wrapping_sub(self.seg_start(k)))
            .sum()
    }

    /// Everything before `ack` arrived: those segments leave the
    /// scoreboard, each delivered. Returns a round trip from the oldest of
    /// them first heard of now, unless one of them went more than once
    /// (Karn: the ACK may be of either sending), as Linux's
    /// `tcp_clean_rtx_queue`: the clock's own resolution, where an echoed
    /// timestamp has a millisecond's.
    fn acked_to(&mut self, now: u64, ack: u32) -> Option<u64> {
        let mut oldest = None;
        let mut resent = false;
        while self.segs_len > 0 {
            let s = *self.seg(0);
            if before(ack, s.end) {
                // Part of it (a peer that acknowledges inside a segment).
                if before(self.segs_start, ack) {
                    self.segs_start = ack;
                }
                break;
            }
            resent |= s.flags & RETRANS != 0;
            if s.flags & SACKED == 0 {
                oldest = Some(oldest.unwrap_or(s.at));
                self.delivered(now, s);
            }
            self.segs_start = s.end;
            self.segs_head = (self.segs_head + 1) % SEGS;
            self.segs_len -= 1;
        }
        oldest.filter(|_| !resent).map(|at| now.saturating_sub(at))
    }

    /// The SACK blocks of `s`: each segment one covers whole is SACKed, and
    /// delivered. A block wholly below what is acknowledged is a DSACK (RFC
    /// 2883): the peer had a segment twice, so a retransmission was not
    /// needed and reordering is wider than the window waited; it widens.
    /// Whether any segment was SACKed now.
    fn sacked(&mut self, now: u64, s: &Segment<'_>) -> bool {
        if !self.sack {
            return false;
        }
        let mut any = false;
        for &(l, r) in &s.options.sack[..usize::from(s.options.sack_len).min(SACK_BLOCKS)] {
            if !before(l, r) || before(self.snd_max, r) {
                continue;
            }
            if before_eq(r, s.header.ack) {
                self.reo_mult = (self.reo_mult + 1).min(255);
                self.reo_persist = REO_PERSIST;
                self.needless(l, r);
                continue;
            }
            let mut start = self.segs_start;
            for k in 0..self.segs_len {
                let seg = *self.seg(k);
                if seg.flags & SACKED == 0 && before_eq(l, start) && before_eq(seg.end, r) {
                    self.seg_mut(k).flags = (seg.flags | SACKED) & !LOST;
                    self.delivered(now, seg);
                    any = true;
                }
                start = seg.end;
            }
        }
        any
    }

    /// A DSACK of `l..r`: segments the peer had twice. Each that the last
    /// reduction resent counts off. One below where that reduction began is
    /// of an older episode, and one with none of its segments outstanding
    /// is a duplicate the network made, not a resent segment; neither
    /// counts.
    fn needless(&mut self, l: u32, r: u32) {
        let Some(u) = self.undo.as_mut() else { return };
        if before(l, u.from) || u.resent == 0 {
            return;
        }
        u.resent = u.resent.saturating_sub(r.wrapping_sub(l).div_ceil(self.mss.max(1)));
        self.try_undo();
    }

    /// Once its recovery is over, a reduction all of whose resent segments
    /// the peer reported having already is undone: the window and threshold
    /// it had before (slow start goes on if it was in it), as Linux's.
    fn try_undo(&mut self) {
        let Some(u) = self.undo else { return };
        if u.resent > 0 || self.recover.is_some() {
            return;
        }
        self.undo = None;
        self.cwnd = self.cwnd.max(u.cwnd);
        self.ssthresh = self.ssthresh.max(u.ssthresh);
        self.undone += 1;
    }

    /// Segment `s` reached the peer: the newest-sent one that did is what
    /// RACK judges the others by (RFC 8985 section 6.2).
    fn delivered(&mut self, now: u64, s: Sent) {
        let rtt = now.saturating_sub(s.at);
        if s.flags & RETRANS != 0 {
            // Faster than any round trip: this was the first sending.
            if rtt < self.min_rtt {
                return;
            }
        } else if rtt != 0 {
            // A send and its ACK in the same clock tick give no measurable
            // round trip. A zero minimum would disable DSACK adaptation
            // for the rest of the connection.
            self.min_rtt = self.min_rtt.min(rtt);
        }
        let newer = s.at > self.rack_at || (s.at == self.rack_at && before(self.rack_end, s.end));
        if !newer && s.flags & RETRANS == 0 && self.rack_at != 0 {
            // Sent once, and heard of after one sent later than it: the
            // path reordered it, this late past what RACK would wait for.
            let late = now.saturating_sub(s.at.saturating_add(self.rack_rtt));
            if late > 0 {
                self.reo_seen = self.reo_seen.max(late);
                self.reo_persist = REO_PERSIST;
            }
        }
        if newer {
            self.rack_at = s.at;
            self.rack_end = s.end;
            // Two events with the same clock reading still establish
            // delivery order. Keep the last measurable duration for the
            // loss timer when this ACK supplies only that order.
            if rtt != 0 {
                self.rack_rtt = rtt;
            }
        }
    }

    /// RACK's loss detection (RFC 8985 section 6.2): a segment sent before
    /// one the peer has, longer ago than that one's round trip and the
    /// reordering window, is lost. Arms the timer for those the window
    /// still covers. Whether any was newly taken for lost.
    fn detect_losses(&mut self, now: u64) -> bool {
        self.reorder_at = None;
        if self.rack_at == 0 {
            return false;
        }
        let reo = if self.min_rtt == u64::MAX {
            0
        } else {
            (self.min_rtt / 4 * u64::from(self.reo_mult)).max(self.reo_seen).min(self.srtt.max(1))
        };
        let mut lost = false;
        for k in 0..self.segs_len {
            let s = *self.seg(k);
            let older = s.at < self.rack_at || (s.at == self.rack_at && before(s.end, self.rack_end));
            if s.flags & (SACKED | LOST) != 0 || !older {
                continue;
            }
            let due = s.at + self.rack_rtt + reo;
            if now >= due {
                self.seg_mut(k).flags |= LOST;
                lost = true;
            } else {
                // RFC 8985 section 6.4 waits until the whole group is
                // due. Each intervening ACK can still reveal losses.
                self.reorder_at = Some(self.reorder_at.map_or(due, |t| t.max(due)));
            }
        }
        lost
    }

    /// Losses were found: the window is halved, once a round trip (RFC
    /// 5681, RFC 6675): `recover` is where that round trip ends.
    fn losses_found(&mut self) {
        if self.recover.is_none() {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            self.undo = Some(Undo { from: self.snd_una, cwnd: self.cwnd, ssthresh: self.ssthresh, resent: 0 });
            // Reordering not shown again for REO_PERSIST recoveries is
            // taken to be gone (RFC 8985 6.2.4): losses are found sooner.
            if self.reo_persist == 0 {
                self.reo_mult = 1;
                self.reo_seen = 0;
            } else {
                self.reo_persist -= 1;
            }
            self.ssthresh = (flight / 2).max(2 * self.mss);
            self.cwnd = self.ssthresh;
            self.avoidance_bytes = 0;
            self.recover = Some(self.snd_max);
            // RFC 6675 section 5, step 4.3: the first repair goes upon
            // entering recovery. Packets still counted in flight may
            // exceed the reduced window and draw no further ACK.
            self.first_repair = true;
            self.timing = None;
        }
    }

    /// The tail loss probe's time: two round trips after the last thing
    /// heard or sent, while data is in flight outside a recovery (RFC
    /// 8985 section 7.2), once a round trip was measured.
    fn arm_probe(&mut self, now: u64) {
        self.probe_at = (self.sack && self.snd_max != self.snd_una && self.recover.is_none() && self.srtt != 0)
            .then(|| now + (2 * self.srtt).max(PTO_MIN));
    }

    /// `len` of sequence space went out at snd_nxt.
    fn sent(&mut self, now: u64, len: u32) {
        let end = self.snd_nxt.wrapping_add(len);
        if self.timing.is_none() && !before(self.snd_nxt, self.snd_max) && !self.timestamps {
            self.timing = Some((end, now));
        }
        self.snd_nxt = end;
        if before(self.snd_max, end) {
            self.snd_max = end;
        }
        if self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
        }
        if self.probe_at.is_none() {
            self.arm_probe(now);
        }
        if self.state == State::Established && self.fin_queued && end == self.fin_seq().wrapping_add(1) {
            self.state = State::FinWait1;
        } else if self.state == State::CloseWait && self.fin_queued && end == self.fin_seq().wrapping_add(1) {
            self.state = State::LastAck;
        }
    }

    fn header(&mut self, seq: u32, flags: u8) -> Header {
        let window = self.window();
        Header { src_port: self.ends.local_port, dst_port: self.ends.remote_port, seq, ack: self.rcv_nxt, flags, window }
    }

    fn emit(&mut self, out: &mut [u8], h: Header, o: &Options, data: Option<(usize, usize)>) -> Option<usize> {
        if h.flags & ACK != 0 {
            self.ack_due = false;
        }
        let n = tcp::header(out, &h, o)?;
        let (offset, len) = data.unwrap_or((0, 0));
        let end = n + len;
        let copied = self.send.peek(offset, out.get_mut(n..end)?);
        debug_assert_eq!(copied, len);
        if self.checksum_offload {
            tcp::seal_partial(&mut out[..end], self.ends.local, self.ends.remote);
        } else {
            tcp::seal(&mut out[..end], self.ends.local, self.ends.remote);
        }
        Some(end)
    }

    /// A segment for this connection arrived at `now`.
    pub fn on_segment(&mut self, now: u64, s: &Segment<'_>) {
        // The peer's first timestamp (taken with its SYN) dates from now.
        if self.ts_recent_at.is_none() {
            self.ts_recent_at = Some(now);
        }
        match self.state {
            State::Closed => {}
            State::SynSent => self.on_syn_sent(now, s),
            _ => self.on_synchronized(now, s),
        }
    }

    fn on_syn_sent(&mut self, now: u64, s: &Segment<'_>) {
        let h = &s.header;
        let ack_ok = s.has(ACK) && before(self.iss, h.ack) && before_eq(h.ack, self.snd_max);
        if s.has(ACK) && !ack_ok {
            // Not for this attempt; a reset tells its sender (not to a reset).
            if !s.has(RST) {
                self.reset = Some((h.ack, false));
            }
            return;
        }
        if s.has(RST) {
            if ack_ok {
                self.end(Some(Error::Refused));
            }
            return;
        }
        if !s.has(SYN) {
            return;
        }
        self.take_syn(s);
        self.ack_due = true;
        if ack_ok {
            self.state = State::Established;
            self.acknowledged(now, s);
            // The SYN-ACK's window is not scaled.
            self.snd_wnd = u32::from(h.window);
            self.snd_wl1 = h.seq;
            self.snd_wl2 = h.ack;
            self.take_data(now, s);
        } else {
            // Both opened at once: answer with a SYN-ACK.
            self.state = State::SynReceived;
            self.snd_nxt = self.iss;
        }
    }

    fn on_synchronized(&mut self, now: u64, s: &Segment<'_>) {
        let h = &s.header;
        if self.state == State::TimeWait && s.has(FIN) && !s.has(RST) {
            // Its FIN again (it ends where what it sent ended): our
            // acknowledgement was lost; acknowledged again, and the wait
            // starts again, no more than a challenge is answered, and never
            // past [`TIME_WAIT_MOST`] in all. Any other FIN (a guess at the
            // ports, not the sequence) is a segment outside the window: a
            // spoofer kept the entry, and drew acknowledgements, for ever.
            let again = s.header.seq.wrapping_add(s.len()) == self.rcv_nxt;
            let answered = self.answered_invalid_at;
            self.answer_invalid(now);
            if again && self.answered_invalid_at != answered {
                let most = self.time_wait_most.get_or_insert(now + TIME_WAIT_MOST);
                self.time_wait_until = Some((now + TIME_WAIT).min(*most));
            }
            return;
        }
        // PAWS (RFC 7323): a segment whose timestamp is older than the
        // newest seen is an old duplicate, unless the newest is so old
        // that the peer's clock may have run half its range since (5.5):
        // then it is forgotten, or a connection idle for 24.8 days at a
        // millisecond a tick would refuse its peer for good.
        let recent_at = self.ts_recent_at.unwrap_or(now);
        if self.timestamps
            && now.saturating_sub(recent_at) < PAWS_IDLE
            && !s.has(RST)
            && let Some((val, _)) = s.options.timestamps
            && before(val, self.ts_recent)
        {
            self.answer_invalid(now);
            return;
        }
        if self.state == State::SynReceived && s.has(SYN) && !s.has(RST) && h.seq.wrapping_add(1) == self.rcv_nxt {
            // Its SYN again: the SYN-ACK was lost.
            self.snd_nxt = self.iss;
            return;
        }
        if !self.acceptable(s) {
            let len = s.data.len() as u32;
            if !s.has(RST) {
                if self.sack && !s.has(SYN) && len > 0 && before_eq(h.seq.wrapping_add(len), self.rcv_nxt) {
                    // Report the duplicate on the next ACK (RFC 2883).
                    // The existing rate limit also covers these replies.
                    self.dsack = Some((h.seq, h.seq.wrapping_add(len)));
                }
                self.answer_invalid(now);
            }
            return;
        }
        if s.has(RST) {
            // RFC 5961: only a reset exactly at the next expected byte
            // counts; one elsewhere in the window gets a challenge.
            if h.seq == self.rcv_nxt {
                // After both sides closed, a reset loses nothing when only
                // this side's FIN was unacknowledged (RFC 9293: closed).
                let lost = self.send.len > 0 || !matches!(self.state, State::Closing | State::LastAck | State::TimeWait);
                self.end(lost.then_some(Error::Reset));
            } else {
                self.answer_invalid(now);
            }
            return;
        }
        if s.has(SYN) {
            // RFC 5961: a SYN on a synchronized connection is challenged.
            self.answer_invalid(now);
            return;
        }
        if !s.has(ACK) {
            return;
        }
        if self.state == State::SynReceived {
            if before(self.snd_una, h.ack) && before_eq(h.ack, self.snd_max) {
                self.state = State::Established;
                self.snd_wnd = u32::from(h.window) << self.snd_scale;
                self.snd_wl1 = h.seq;
                self.snd_wl2 = h.ack;
            } else {
                self.reset = Some((h.ack, false));
                return;
            }
        }
        if before(self.snd_max, h.ack) {
            // It acknowledges what was never sent.
            self.answer_invalid(now);
            return;
        }
        if let Some((val, _)) = s.options.timestamps
            && self.timestamps
            && before_eq(h.seq, self.rcv_nxt)
        {
            self.ts_recent = val;
            self.ts_recent_at = Some(now);
        }
        self.acknowledged(now, s);
        if self.state == State::Closed {
            return;
        }
        self.take_data(now, s);
    }

    /// Answer a segment outside the window (or a challenge) with an ACK,
    /// no more often than [`INVALID_ANSWER_GAP`].
    fn answer_invalid(&mut self, now: u64) {
        if self.answered_invalid_at.is_none_or(|t| now >= t + INVALID_ANSWER_GAP) {
            self.answered_invalid_at = Some(now);
            self.ack_due = true;
        }
    }

    /// RFC 9293 3.10.7.4: whether any of the segment lies in the window.
    fn acceptable(&self, s: &Segment<'_>) -> bool {
        let seq = s.header.seq;
        let len = s.len();
        // The room left: never less than what was advertised.
        let wnd = self.receive.free() as u32;
        let in_window = |x: u32| before_eq(self.rcv_nxt, x) && before(x, self.rcv_nxt.wrapping_add(wnd));
        match (len, wnd) {
            (0, 0) => seq == self.rcv_nxt,
            (0, _) => in_window(seq),
            (_, 0) => false,
            _ => in_window(seq) || in_window(seq.wrapping_add(len - 1)),
        }
    }

    /// The acknowledgement and window of `s` (whose ACK is no further than
    /// what was sent).
    fn acknowledged(&mut self, now: u64, s: &Segment<'_>) {
        let h = &s.header;
        let ack = h.ack;
        if before(ack, self.snd_una) {
            return;
        }
        let window = u32::from(h.window) << self.snd_scale;
        let acked = ack.wrapping_sub(self.snd_una);
        // With SACK, losses are found by time (RACK, RFC 8985): a segment
        // sent before one the peer has, and longer ago than that one's round
        // trip and a reordering window. Counting duplicates, as RFC 5681
        // does, missed a loss with fewer than three segments after it (a
        // small window, the tail) and one whose duplicates each carried a
        // new window (Linux's grows with nearly every acknowledgement), and
        // either waited for the 200 ms timer: 67 times in 16 MiB on the
        // interop suite's lossy path. A peer without SACK is still judged
        // by duplicates.
        let sacked = self.sacked(now, s);
        if acked == 0 {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            let duplicate = s.data.is_empty() && !s.has(SYN | FIN) && flight > 0 && window == self.snd_wnd;
            if duplicate && !self.sack {
                self.duplicate_ack();
            }
        } else {
            self.new_ack(now, s, acked);
        }
        if self.sack && (sacked || acked > 0) {
            if self.detect_losses(now) {
                self.losses_found();
            }
            self.tlp_due = false;
            self.arm_probe(now);
        }
        // The window comes from the newest segment (RFC 9293 3.10.7.4).
        if before(self.snd_wl1, h.seq) || (self.snd_wl1 == h.seq && before_eq(self.snd_wl2, ack)) {
            self.snd_wnd = window;
            self.snd_wl1 = h.seq;
            self.snd_wl2 = ack;
            if self.snd_max == self.snd_una && self.retransmit_at.is_some() {
                // Nothing is in flight. A current window report answers the
                // persist probe even when the receiver still has no room.
                self.retries = 0;
                if window > 0 {
                    self.retransmit_at = None;
                    self.probe_due = false;
                }
            }
        }
    }

    /// A duplicate from a peer without SACK: the third takes the first
    /// segment for lost (RFC 5681 fast retransmit).
    fn duplicate_ack(&mut self) {
        self.dupacks = self.dupacks.saturating_add(1);
        if self.dupacks == 3 && self.recover.is_none() && self.segs_len > 0 {
            self.seg_mut(0).flags |= LOST;
            self.losses_found();
        }
    }

    fn new_ack(&mut self, now: u64, s: &Segment<'_>, acked: u32) {
        let ack = s.header.ack;
        // The SYN and FIN take a number each and no byte of the ring.
        let syn = u32::from(core::mem::take(&mut self.syn_unacked));
        let fin = (self.fin_sent.is_some() && !self.fin_acked() && before(self.fin_seq(), ack)) as u32;
        self.send.consume((acked - syn - fin) as usize);
        self.snd_una = ack;
        let sent_at = self.acked_to(now, ack);
        if before(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        self.retries = 0;
        // A round trip: from when the scoreboard says the acknowledged data
        // went, else from the echoed timestamp, or the timed segment.
        let sample = match (self.timestamps, s.options.timestamps) {
            _ if sent_at.is_some() => sent_at,
            (true, Some((_, ecr)))
                if ecr != 0
                    && self.resent_ts.is_none_or(|r| !before(ecr, r))
                    && self.ts_sent.is_some_and(|(first, last)| !before(ecr, first) && !before(last, ecr)) =>
            {
                Some(u64::from(self.ts_now(now).wrapping_sub(ecr)) * MS).filter(|&r| r < RTO_MAX)
            }
            (true, _) => None,
            (false, _) => match self.timing {
                Some((end, at)) if before_eq(end, ack) => {
                    self.timing = None;
                    Some(now - at)
                }
                _ => None,
            },
        };
        if let Some(r) = sample {
            self.measured(r);
        }
        if self.snd_una == self.snd_max {
            self.resent_ts = None;
        }
        self.retransmit_at = (self.snd_una != self.snd_max).then(|| now + self.rto);
        // Congestion.
        match self.recover {
            Some(r) if before(ack, r) => {
                // A partial acknowledgement from a peer without SACK: the
                // next hole is the next segment (RFC 6582).
                if !self.sack && self.segs_len > 0 {
                    self.seg_mut(0).flags |= LOST;
                }
            }
            Some(_) => {
                self.cwnd = self.ssthresh;
                self.recover = None;
                self.first_repair = false;
                self.try_undo();
            }
            None if self.cwnd < self.ssthresh => self.cwnd += acked.min(self.mss),
            None => {
                // RFC 5681 section 3.1: one MSS per window of bytes
                // delivered, independent of how the peer groups its ACKs.
                self.avoidance_bytes = self.avoidance_bytes.saturating_add(acked);
                if self.avoidance_bytes >= self.cwnd {
                    self.avoidance_bytes -= self.cwnd;
                    self.cwnd = self.cwnd.saturating_add(self.mss);
                }
            }
        }
        self.dupacks = 0;
        if fin == 1 {
            match self.state {
                State::FinWait1 => {
                    self.state = State::FinWait2;
                    if self.released {
                        self.time_wait_until = Some(now + FIN_WAIT_2_IDLE);
                    }
                }
                State::Closing => self.enter_time_wait(now),
                State::LastAck => self.end(None),
                _ => {}
            }
        }
    }

    /// RFC 6298's estimator, from one round trip of `r` ns.
    fn measured(&mut self, r: u64) {
        if self.srtt == 0 {
            self.srtt = r.max(1);
            self.rttvar = r / 2;
        } else {
            let diff = self.srtt.abs_diff(r);
            self.rttvar = (3 * self.rttvar + diff) / 4;
            self.srtt = (7 * self.srtt + r) / 8;
        }
        self.rto = (self.srtt + (4 * self.rttvar).max(MS)).clamp(RTO_MIN, RTO_MAX);
    }

    /// The smoothed round trip, once one was measured (ns).
    pub fn srtt(&self) -> Option<u64> {
        (self.srtt != 0).then_some(self.srtt)
    }

    /// What the connection's sending side is doing, for the owner to look
    /// at (sequence numbers relative to the initial one).
    pub fn info(&self) -> Info {
        Info {
            state: self.state,
            unacked: self.snd_una.wrapping_sub(self.iss),
            next: self.snd_nxt.wrapping_sub(self.iss),
            highest: self.snd_max.wrapping_sub(self.iss),
            fin: self.fin_sent.map(|f| f.wrapping_sub(self.iss)),
            peer_window: self.snd_wnd,
            cwnd: self.cwnd,
            ssthresh: self.ssthresh,
            undone: self.undone,
            rto: self.rto,
            srtt: self.srtt,
            retries: self.retries,
            queued: self.send.len as u32,
            readable: self.receive.len as u32,
        }
    }

    fn enter_time_wait(&mut self, now: u64) {
        self.state = State::TimeWait;
        self.retransmit_at = None;
        self.time_wait_until = Some(now + TIME_WAIT);
    }

    /// The data and FIN of an acceptable segment.
    fn take_data(&mut self, now: u64, s: &Segment<'_>) {
        if !matches!(self.state, State::Established | State::FinWait1 | State::FinWait2) {
            return;
        }
        let mut seq = s.header.seq.wrapping_add(s.has(SYN) as u32);
        let mut data = s.data;
        if !data.is_empty() {
            self.ack_due = true;
        }
        // All of it arrived before: the peer is told (a DSACK).
        if !data.is_empty() && before_eq(seq.wrapping_add(data.len() as u32), self.rcv_nxt) {
            self.dsack = Some((seq, seq.wrapping_add(data.len() as u32)));
        }
        // Trim what already arrived.
        if before(seq, self.rcv_nxt) {
            let skip = (self.rcv_nxt.wrapping_sub(seq) as usize).min(data.len());
            data = &data[skip..];
            seq = seq.wrapping_add(skip as u32);
        }
        if self.state == State::FinWait2 && self.released && !data.is_empty() {
            // The peer is still sending: FIN-WAIT-2 waits on.
            self.time_wait_until = Some(now + FIN_WAIT_2_IDLE);
        }
        if seq == self.rcv_nxt {
            let n = self.receive.push(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
            self.fill_holes();
            if n == data.len() && s.has(FIN) {
                self.fin_at = Some(seq.wrapping_add(n as u32));
            }
        } else if !data.is_empty() {
            let at = seq.wrapping_sub(self.rcv_nxt) as usize;
            let n = self.receive.write_beyond(at, data);
            if n > 0 {
                self.hold(seq, seq.wrapping_add(n as u32));
            }
            if n == data.len() && s.has(FIN) {
                self.fin_at = Some(seq.wrapping_add(n as u32));
            }
        } else if s.has(FIN) {
            self.fin_at = Some(seq);
        }
        if self.fin_at == Some(self.rcv_nxt) {
            self.fin_at = None;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.ack_due = true;
            match self.state {
                State::Established => self.state = State::CloseWait,
                State::FinWait1 => self.state = State::Closing,
                State::FinWait2 => self.enter_time_wait(now),
                _ => {}
            }
        }
    }

    /// Remember `[start, end)` as held beyond a gap, joined with what
    /// touches it; the newest first, as SACK reports them (RFC 2018).
    fn hold(&mut self, mut start: u32, mut end: u32) {
        let mut kept = [(0u32, 0u32); HOLES];
        let mut k = 0;
        for &(s, e) in &self.holes[..self.holes_len] {
            if before_eq(s, end) && before_eq(start, e) {
                if before(s, start) {
                    start = s;
                }
                if before(end, e) {
                    end = e;
                }
            } else {
                kept[k] = (s, e);
                k += 1;
            }
            if k == HOLES {
                // Full: the range furthest from what is in order is let go
                // of (its bytes come again; the one just arrived is kept).
                let far = (0..k).max_by_key(|&j| kept[j].0.wrapping_sub(self.rcv_nxt)).unwrap_or(0);
                kept.copy_within(far + 1..k, far);
                k -= 1;
            }
        }
        self.holes[0] = (start, end);
        self.holes[1..=k].copy_from_slice(&kept[..k]);
        self.holes_len = k + 1;
    }

    /// Take in order what lay beyond a gap that is now filled.
    fn fill_holes(&mut self) {
        loop {
            let Some(i) = self.holes[..self.holes_len].iter().position(|&(s, _)| before_eq(s, self.rcv_nxt)) else {
                return;
            };
            let (_, e) = self.holes[i];
            if before(self.rcv_nxt, e) {
                let n = e.wrapping_sub(self.rcv_nxt);
                // The bytes are already in place past the end.
                self.receive.len += n as usize;
                self.rcv_nxt = e;
            }
            self.holes.copy_within(i + 1..self.holes_len, i);
            self.holes_len -= 1;
        }
    }
}
