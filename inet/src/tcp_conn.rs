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
//! times from echoed timestamps, old segments refused by PAWS); SACK blocks
//! for what arrived out of order (RFC 2018); a zero window probed; and the
//! defences of RFC 5961 against blind resets and SYNs (a reset or SYN that
//! is not exactly where it must be only draws a challenge acknowledgement).
//!
//! What it does not do yet: SACK-based loss recovery (RFC 6675), CUBIC and
//! BBR, ECN, keepalive, path MTU discovery.
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
/// Retransmissions of one segment before the connection is given up:
/// about 15 minutes at the ceiling for data, as Linux's default; a SYN is
/// given up sooner (about two minutes).
const RETRIES: u32 = 15;
const SYN_RETRIES: u32 = 6;
/// How long a connection closed from this side stays to answer its peer's
/// last segments (twice the maximum segment lifetime, as Linux).
const TIME_WAIT: u64 = 60 * SECOND;
/// The segment size assumed of a peer that names none (RFC 9293).
const DEFAULT_MSS: u16 = 536;
/// Least time between answers to segments outside the window, challenges
/// included (RFC 5961 section 7; Linux's tcp_invalid_ratelimit): two ends
/// that each find the other's segments out of window would otherwise
/// answer each other for ever, and a blind sender could make this end
/// send an ACK for every segment it forges.
const INVALID_ANSWER_GAP: u64 = 500 * MS;
/// Ranges held beyond a gap in what arrived.
const HOLES: usize = SACK_BLOCKS;

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
    /// Send one segment from `snd_una` without going back (fast retransmit).
    resend_first: bool,

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

    // Congestion (NewReno).
    cwnd: u32,
    ssthresh: u32,
    dupacks: u32,
    recover: Option<u32>,

    // Timestamps: the offset this connection's are taken from, and the
    // peer's latest (RFC 7323), when both sides use them.
    timestamps: bool,
    ts_offset: u32,
    ts_recent: u32,
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
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Connection<S> {
    fn new(ends: Endpoints, state: State, iss: u32, mtu: u16, buffers: Buffers<S>) -> Connection<S> {
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
            resend_first: false,
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
            cwnd: 10 * mss,
            ssthresh: u32::MAX,
            dupacks: 0,
            recover: None,
            timestamps: true,
            ts_offset: iss,
            ts_recent: 0,
            sack: true,
            scaling: false,
            reset: None,
            answered_invalid_at: None,
            probe_due: false,
        }
    }

    /// Open a connection to `ends.remote`: its SYN goes out on the next
    /// [`Connection::poll`]. `iss` is its initial sequence number (the
    /// stack's, from a keyed hash: RFC 6528); `mtu` the interface's.
    pub fn connect(ends: Endpoints, iss: u32, mtu: u16, buffers: Buffers<S>) -> Connection<S> {
        Connection::new(ends, State::SynSent, iss, mtu, buffers)
    }

    /// Answer `syn`, which arrived for a listening port: the SYN-ACK goes
    /// out on the next [`Connection::poll`].
    pub fn accept(ends: Endpoints, syn: &Segment<'_>, iss: u32, mtu: u16, buffers: Buffers<S>) -> Connection<S> {
        let mut c = Connection::new(ends, State::SynReceived, iss, mtu, buffers);
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

    fn can_send_data(&self) -> bool {
        matches!(self.state, State::SynSent | State::SynReceived | State::Established | State::CloseWait)
    }

    /// The largest segment's payload, after options.
    pub fn mss(&self) -> u32 {
        self.mss
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
        self.time_wait_until = None;
        self.send.consume(self.send.len);
    }

    /// When [`Connection::on_time`] wants to run next.
    pub fn deadline(&self) -> Option<u64> {
        match (self.retransmit_at, self.time_wait_until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The time is `now`: retransmit, probe or give up if it is time.
    pub fn on_time(&mut self, now: u64) {
        if self.time_wait_until.is_some_and(|t| now >= t) {
            self.end(None);
            return;
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
        if flight == 0 {
            // The persist timer: the peer's window is shut and nothing is
            // in flight; the next poll probes it.
            self.probe_due = true;
            self.rto = (self.rto * 2).min(RTO_MAX);
            return;
        }
        // RFC 5681 on a timeout: half what was in flight is the threshold,
        // one segment the window; everything not acknowledged goes again.
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.recover = None;
        self.dupacks = 0;
        self.snd_nxt = self.snd_una;
        self.timing = None;
        self.rto = (self.rto * 2).min(RTO_MAX);
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

    /// The options of a segment that is not a SYN.
    fn options(&self, now: u64) -> Options {
        let mut o = Options::default();
        if self.timestamps {
            o.timestamps = Some((self.ts_now(now), self.ts_recent));
        }
        if self.sack && self.holes_len > 0 {
            let room = if self.timestamps { 3 } else { 4 };
            for (i, h) in self.holes[..self.holes_len.min(room)].iter().enumerate() {
                o.sack[i] = *h;
            }
            o.sack_len = self.holes_len.min(room) as u8;
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

    /// The first byte of data's sequence number: just after the SYN.
    fn data_start(&self) -> u32 {
        self.iss.wrapping_add(1)
    }

    /// The sequence number of the first byte in the send ring.
    fn send_base(&self) -> u32 {
        if before(self.snd_una, self.data_start()) { self.data_start() } else { self.snd_una }
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

    /// The next data or FIN segment allowed, if any.
    fn poll_data(&mut self, now: u64, out: &mut [u8]) -> Option<usize> {
        let (start, resend) = if self.resend_first { (self.snd_una, true) } else { (self.snd_nxt, false) };
        let base = self.send_base();
        let offset = start.wrapping_sub(base) as usize;
        let waiting = self.send.len.saturating_sub(offset);
        let fin_seq = self.fin_seq();
        let fin_waits = self.fin_queued && !self.fin_acked() && before_eq(start, fin_seq);
        if waiting == 0 && !fin_waits {
            self.resend_first = false;
            return None;
        }
        // What the peer's window and the congestion window allow, from
        // snd_una; a retransmission of the first segment goes regardless.
        let flight = start.wrapping_sub(self.snd_una);
        let limit = self.snd_wnd.min(self.cwnd);
        let mut room = if resend { self.mss } else { limit.saturating_sub(flight) };
        if room == 0 && start == self.snd_una && self.snd_max != self.snd_una {
            // Going back after a timeout: the first segment not
            // acknowledged goes whatever the window says (as Linux). A
            // stale window (a zero reordered behind the update that
            // reopened it) would otherwise leave data in flight with
            // nothing to send it again.
            room = self.mss;
        }
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
        let n = (waiting as u32).min(self.mss).min(room);
        let fin = fin_waits && n as usize == waiting && (n < room || waiting == 0);
        // A retransmission carries what was sent and nothing new: a byte
        // (or FIN) past snd_max that went out here would be acknowledged by
        // the peer, and that acknowledgement refused as one for data never
        // sent, both ends then waiting on each other until they time out
        // (seed 113 of the loss test). New data goes through `sent`.
        let (n, fin) = if resend {
            let fin_sent = self.fin_sent.is_some();
            let data = self.snd_max.wrapping_sub(start).saturating_sub(fin_sent as u32);
            let n = n.min(data);
            (n, fin && fin_sent && n as usize == waiting)
        } else {
            (n, fin)
        };
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
        if resend || before(start, self.snd_max) {
            self.resent_ts = Some(self.ts_now(now));
        }
        if resend {
            self.resend_first = false;
            self.timing = None;
            if self.retransmit_at.is_none() {
                self.retransmit_at = Some(now + self.rto);
            }
        } else {
            self.sent(now, len);
        }
        self.emit(out, h, &o, Some((offset, n as usize)))
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
        tcp::seal(&mut out[..end], self.ends.local, self.ends.remote);
        Some(end)
    }

    /// A segment for this connection arrived at `now`.
    pub fn on_segment(&mut self, now: u64, s: &Segment<'_>) {
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
            // Its FIN again: our acknowledgement was lost.
            self.ack_due = true;
            self.time_wait_until = Some(now + TIME_WAIT);
            return;
        }
        // PAWS (RFC 7323): a segment whose timestamp is older than the
        // newest seen is an old duplicate.
        if self.timestamps
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
            if !s.has(RST) {
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
        if acked == 0 {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            let duplicate = s.data.is_empty() && !s.has(SYN | FIN) && flight > 0 && window == self.snd_wnd;
            if duplicate {
                self.duplicate_ack();
            }
        } else {
            self.new_ack(now, s, acked);
        }
        // The window comes from the newest segment (RFC 9293 3.10.7.4).
        if before(self.snd_wl1, h.seq) || (self.snd_wl1 == h.seq && before_eq(self.snd_wl2, ack)) {
            self.snd_wnd = window;
            self.snd_wl1 = h.seq;
            self.snd_wl2 = ack;
        }
        if self.snd_wnd > 0 && self.snd_max == self.snd_una && self.send.len > 0 {
            // The window opened after a probe: stop probing.
            self.retransmit_at = None;
            self.retries = 0;
        }
    }

    fn duplicate_ack(&mut self) {
        self.dupacks += 1;
        if self.recover.is_some() {
            // Each one is a segment that left the network (RFC 6582).
            self.cwnd += self.mss;
        } else if self.dupacks == 3 {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            self.ssthresh = (flight / 2).max(2 * self.mss);
            self.cwnd = self.ssthresh + 3 * self.mss;
            self.recover = Some(self.snd_max);
            self.resend_first = true;
            self.timing = None;
        }
    }

    fn new_ack(&mut self, now: u64, s: &Segment<'_>, acked: u32) {
        let ack = s.header.ack;
        // The SYN and FIN take a number each and no byte of the ring.
        let syn = before(self.snd_una, self.data_start()) as u32;
        let fin = (self.fin_sent.is_some() && !self.fin_acked() && before(self.fin_seq(), ack)) as u32;
        self.send.consume((acked - syn - fin) as usize);
        self.snd_una = ack;
        if before(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        self.retries = 0;
        // A round trip: from the echoed timestamp, or the timed segment.
        let sample = match (self.timestamps, s.options.timestamps) {
            (true, Some((_, ecr))) if ecr != 0 && self.resent_ts.is_none_or(|r| !before(ecr, r)) => {
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
                // A partial acknowledgement: the next hole goes at once,
                // and the window deflates by what was acknowledged.
                self.cwnd = self.cwnd.saturating_sub(acked).max(self.mss) + self.mss;
                self.resend_first = true;
            }
            Some(_) => {
                self.cwnd = self.ssthresh.min(self.snd_max.wrapping_sub(self.snd_una).max(self.mss) + self.mss);
                self.recover = None;
            }
            None if self.cwnd < self.ssthresh => self.cwnd += acked.min(self.mss),
            None => self.cwnd += (self.mss * self.mss / self.cwnd).max(1),
        }
        self.dupacks = 0;
        if fin == 1 {
            match self.state {
                State::FinWait1 => self.state = State::FinWait2,
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
        // Trim what already arrived.
        if before(seq, self.rcv_nxt) {
            let skip = (self.rcv_nxt.wrapping_sub(seq) as usize).min(data.len());
            data = &data[skip..];
            seq = seq.wrapping_add(skip as u32);
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
            } else if k < HOLES - 1 {
                kept[k] = (s, e);
                k += 1;
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
