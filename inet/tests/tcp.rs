//! TCP connections against each other through a simulated network: the
//! time is virtual, and the network delays, drops and reorders segments on
//! request. Each test drives the public interface as the stack does.

use silica_inet::Ipv4;
use silica_inet::tcp::{self, ACK, FIN, Header, Options, RST, SYN, Segment};
use silica_inet::tcp_conn::{Buffers, Connection, Endpoints, Error, State};

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000 * MS;
const A: Ipv4 = Ipv4([10, 0, 2, 15]);
const B: Ipv4 = Ipv4([10, 0, 2, 2]);

type Conn = Connection<Vec<u8>>;

fn ends(a: Ipv4, ap: u16, b: Ipv4, bp: u16) -> Endpoints {
    Endpoints { local: a, local_port: ap, remote: b, remote_port: bp }
}

fn buffers(send: usize, receive: usize) -> Buffers<Vec<u8>> {
    Buffers { send: vec![0; send], receive: vec![0; receive] }
}

/// A segment on its way: when it arrives, to which side, its bytes.
struct Flight {
    at: u64,
    /// Not yet delayed or copied by a test that disturbs the wire: each
    /// segment is disturbed once (picking them by their arrival time
    /// copied the copies again for as long as time stood still, without
    /// end, when the jitter was 0).
    fresh: bool,
    to_b: bool,
    bytes: Vec<u8>,
}

/// Whether to lose a segment: given its number (from 1) and the segment.
type Dropper = Box<dyn FnMut(u64, &Segment<'_>) -> bool>;

/// Two connections and the wire between them.
struct Net {
    sender_timeouts: usize,
    window_reductions: usize,
    now: u64,
    a: Conn,
    b: Option<Conn>,
    wire: Vec<Flight>,
    /// One way's delay.
    delay: u64,
    /// Drop the nth segment sent (counting from 1) when `drop(n)` says so.
    drop: Dropper,
    /// A segment's way, when a test varies it: its one-way delay, and
    /// whether it arrives twice.
    vary: Option<Box<dyn FnMut() -> (u64, bool)>>,
    sent: u64,
    /// Every segment sent, to look at afterwards: (to B, header, data length).
    log: Vec<(bool, Header, Options, usize)>,
    b_buffers: (usize, usize),
    /// A's send buffer doubles, up to this many bytes, whenever it is what
    /// holds A back and A has more to send (netd's policy).
    grow_to: usize,
    /// A's interface sums checksums and cuts segments into pieces of this
    /// many bytes of data (`device_cuts`), as `silica.net.Device`'s offloads.
    device: Option<usize>,
    /// Everything due at one instant is delivered before anyone sends.
    batch: bool,
    /// Segments A's `poll` gave (before any cutting).
    a_polls: usize,
}

/// What a device with the checksum and TCP segmentation offloads sends for
/// one segment it is given: pieces of at most `mss` bytes of data behind
/// copies of its header, their sequence numbers advanced, FIN and PSH on the
/// last only, each checksum summed (the given segment's field holds only
/// the pseudo-header's sum).
fn device_cuts(seg: &[u8], mss: usize) -> Vec<Vec<u8>> {
    let header = usize::from(seg[12] >> 4) * 4;
    let data = &seg[header..];
    let seq = u32::from_be_bytes(seg[4..8].try_into().unwrap());
    let mut pieces = Vec::new();
    let mut at = 0;
    loop {
        let n = (data.len() - at).min(mss);
        let last = at + n == data.len();
        let mut p = seg[..header].to_vec();
        p[4..8].copy_from_slice(&seq.wrapping_add(at as u32).to_be_bytes());
        if !last {
            p[13] &= !(0x01 | 0x08);
        }
        p.extend_from_slice(&data[at..at + n]);
        tcp::seal(&mut p, A, B);
        pieces.push(p);
        at += n;
        if last {
            return pieces;
        }
    }
}

impl Net {
    fn new(a_buffers: (usize, usize), b_buffers: (usize, usize)) -> Net {
        let a = Connection::connect(ends(A, 40000, B, 80), 0xFFFF_FF00, 0x1234_5678, 1500, buffers(a_buffers.0, a_buffers.1));
        Net {
            sender_timeouts: 0,
            window_reductions: 0,
            now: 0,
            a,
            b: None,
            wire: Vec::new(),
            delay: 5 * MS,
            drop: Box::new(|_, _| false),
            vary: None,
            sent: 0,
            log: Vec::new(),
            b_buffers,
            grow_to: 0,
            device: None,
            a_polls: 0,
            batch: false,
        }
    }

    /// Everything each side has to send goes on the wire.
    fn flush(&mut self) {
        // More segments at one instant than any window holds: a connection
        // that never stops sending fails here, with what it sent, instead
        // of growing the log until the host runs out of memory.
        const BURST: usize = 10_000;
        let stuck = |who: &str, sent: &[Vec<u8>], src: Ipv4, dst: Ipv4| -> ! {
            let last: Vec<_> = sent[sent.len() - 4..].iter().map(|b| tcp::parse(b, src, dst).map(|s| (s.header, s.data.len()))).collect();
            panic!("{who} sent {BURST} segments at one instant; the last: {last:?}");
        };
        let mut out = vec![0u8; 1 << 16];
        let mut sent = Vec::new();
        while let Some(n) = self.a.poll(self.now, &mut out) {
            match self.device {
                Some(mss) => sent.extend(device_cuts(&out[..n], mss)),
                None => sent.push(out[..n].to_vec()),
            }
            self.a_polls += 1;
            if sent.len() >= BURST {
                stuck("A", &sent, A, B);
            }
        }
        for s in sent {
            self.put(true, s);
        }
        if let Some(b) = self.b.as_mut() {
            let mut sent = Vec::new();
            while let Some(n) = b.poll(self.now, &mut out) {
                sent.push(out[..n].to_vec());
                if sent.len() == BURST {
                    stuck("B", &sent, B, A);
                }
            }
            for s in sent {
                self.put(false, s);
            }
        }
    }

    fn put(&mut self, to_b: bool, bytes: Vec<u8>) {
        let (src, dst) = if to_b { (A, B) } else { (B, A) };
        let s = tcp::parse(&bytes, src, dst).expect("a connection sent a segment that does not parse");
        self.sent += 1;
        self.log.push((to_b, s.header, s.options, s.data.len()));
        if (self.drop)(self.sent, &s) {
            return;
        }
        let (delay, twice) = self.vary.as_mut().map_or((self.delay, false), |v| v());
        if twice {
            self.wire.push(Flight { at: self.now + delay + self.delay, fresh: false, to_b, bytes: bytes.clone() });
        }
        self.wire.push(Flight { at: self.now + delay, fresh: true, to_b, bytes });
    }

    /// Deliver what arrives next, or fire the next timer; false when
    /// nothing is left to happen.
    fn step(&mut self) -> bool {
        self.flush();
        let next_wire = self.wire.iter().map(|f| f.at).min();
        let next_timer = [self.a.deadline(), self.b.as_ref().and_then(|b| b.deadline())].into_iter().flatten().min();
        let Some(t) = [next_wire, next_timer].into_iter().flatten().min() else { return false };
        self.now = self.now.max(t);
        let previous_window = self.a.info().cwnd;
        if next_wire == Some(t) {
            // With `batch`, everything due now arrives before either side
            // sends again, as a stack takes in what its device delivered
            // before it sends (what lets segments to cut gather).
            loop {
                let i = self.wire.iter().position(|f| f.at == t).unwrap();
                let f = self.wire.remove(i);
                self.deliver(f);
                if !self.batch || !self.wire.iter().any(|f| f.at == t) {
                    break;
                }
            }
        } else {
            let retries = self.a.info().retries;
            self.a.on_time(self.now);
            self.sender_timeouts += usize::from(self.a.info().retries > retries);
            if let Some(b) = self.b.as_mut() {
                b.on_time(self.now);
            }
        }
        self.window_reductions += usize::from(self.a.info().cwnd < previous_window);
        self.flush();
        true
    }

    fn deliver(&mut self, f: Flight) {
        let (src, dst) = if f.to_b { (A, B) } else { (B, A) };
        let s = tcp::parse(&f.bytes, src, dst).unwrap();
        if f.to_b {
            match self.b.as_mut() {
                Some(b) if !b.is_closed() => b.on_segment(self.now, &s),
                // The listener: a SYN makes the connection.
                _ if s.has(SYN) && !s.has(ACK) => {
                    let (sb, rb) = self.b_buffers;
                    self.b = Some(Connection::accept(ends(B, 80, A, 40000), &s, 0x7000_0000, 0x0BAD_F00D, 1500, buffers(sb, rb)));
                }
                // No connection: the stack answers with a reset.
                _ => self.reset(false, &s),
            }
        } else if self.a.is_closed() {
            self.reset(true, &s);
        } else {
            self.a.on_segment(self.now, &s);
        }
    }

    /// What a stack sends back for a segment that reaches no connection.
    fn reset(&mut self, to_b: bool, s: &Segment<'_>) {
        let Some(h) = tcp::reset_reply(s) else { return };
        let (src, dst) = if to_b { (A, B) } else { (B, A) };
        let mut b = [0u8; 64];
        let n = tcp::build(&mut b, src, dst, &h, &Options::default(), &[]).unwrap();
        self.put(to_b, b[..n].to_vec());
    }

    /// Run until `done` holds or nothing is left to happen, at most `limit`.
    fn run_until(&mut self, limit: u64, mut done: impl FnMut(&mut Net) -> bool) {
        let end = self.now + limit;
        while !done(self) && self.now < end {
            if !self.step() {
                break;
            }
        }
    }

    fn b(&mut self) -> &mut Conn {
        self.b.as_mut().expect("B was never made")
    }
}

/// A sends `data` to B, which reads it all, through whatever the network
/// does; then both close.
fn transfer(net: &mut Net, data: &[u8], limit: u64) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    let mut closed = false;
    let mut buf = vec![0u8; 3000];
    let end = net.now + limit;
    while net.now < end {
        if sent < data.len() {
            let capacity = net.a.send_capacity();
            if net.a.buffer_limited() && capacity < net.grow_to {
                assert!(net.a.grow_send_buffer(vec![0; 2 * capacity]));
            }
            sent += net.a.send(&data[sent..]);
        } else if !closed {
            net.a.close();
            closed = true;
        }
        if let Some(b) = net.b.as_mut() {
            loop {
                let n = b.recv(&mut buf);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            if b.at_end() && b.state() == State::CloseWait {
                b.close();
            }
        }
        if closed && net.b.as_ref().is_some_and(|b| b.is_closed()) && got.len() == data.len() {
            break;
        }
        if !net.step() {
            break;
        }
    }
    got
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

#[test]
fn a_connection_opens_carries_data_both_ways_and_closes() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.a.state() == State::Established && n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    assert_eq!(net.a.state(), State::Established);
    assert_eq!(net.b().state(), State::Established);
    assert_eq!(net.log.len(), 3, "a three-way handshake: {:?}", net.log);
    let (syn, synack) = (&net.log[0], &net.log[1]);
    assert_eq!(syn.1.flags, SYN);
    assert_eq!(synack.1.flags, SYN | ACK);
    assert_eq!(syn.2.mss, Some(1460), "the MSS offered is the interface's");
    assert!(syn.2.timestamps.is_some() && syn.2.sack_permitted && syn.2.window_scale.is_some());
    assert_eq!(net.a.mss(), 1448, "the timestamps' 12 bytes come off each segment");

    assert_eq!(net.a.send(b"GET / HTTP/1.1\r\n\r\n"), 18);
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.readable() == 18));
    let mut buf = [0u8; 64];
    assert_eq!(net.b().recv(&mut buf), 18);
    assert_eq!(&buf[..18], b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(net.b().send(b"HTTP/1.1 200 OK\r\n\r\nhi"), 21);
    net.b().close();
    net.run_until(SECOND, |n| n.a.state() == State::CloseWait && n.b.as_ref().is_some_and(|b| b.state() == State::FinWait2));
    assert_eq!(net.a.recv(&mut buf), 21);
    assert!(net.a.at_end(), "B's FIN read as the end");
    assert_eq!(net.a.state(), State::CloseWait);
    assert_eq!(net.b().state(), State::FinWait2);
    net.a.close();
    net.run_until(SECOND, |n| n.a.is_closed());
    assert!(net.a.is_closed() && net.a.error().is_none(), "A closed second: no TIME-WAIT, no error");
    assert_eq!(net.b().state(), State::TimeWait, "B closed first and waits");
    let shed = net.b().shed().expect("TIME-WAIT gives its buffers back");
    assert_eq!((shed.send.len(), shed.receive.len()), (4096, 4096));
    assert!(net.b().shed().is_none(), "once");
    assert!(net.a.shed().is_some(), "and so does a closed connection");
    assert_eq!(net.a.send(b"x"), 0, "nothing is taken after closing");
    net.run_until(120 * SECOND, |n| n.b.as_ref().is_some_and(|b| b.is_closed()));
    assert!(net.b().is_closed() && net.b().error().is_none(), "TIME-WAIT ends");
}

#[test]
fn a_megabyte_arrives_whole_through_a_clean_network_with_a_full_window() {
    let mut net = Net::new((256 << 10, 64 << 10), (64 << 10, 256 << 10));
    let data = pattern(1 << 20);
    let start = net.now;
    let got = transfer(&mut net, &data, 60 * SECOND);
    assert!(
        got == data,
        "{} of {} bytes, first difference at {:?}",
        got.len(),
        data.len(),
        got.iter().zip(&data).position(|(a, b)| a != b)
    );
    let synack = net.log.iter().find(|l| l.1.flags == SYN | ACK).unwrap();
    assert!(synack.2.window_scale.unwrap() >= 2, "B's 256 KiB of receive buffer is offered with a scaled window");
    // Without loss the transfer is limited by the window, not by timeouts:
    // 1 MiB through a 256 KiB window over a 10 ms round trip is about 40 ms.
    let took = net.now - start;
    assert!(took < 200 * MS, "took {} ms", took / MS);
    let largest = net.log.iter().filter(|l| l.0).map(|l| l.3).max().unwrap();
    assert_eq!(largest, 1448, "full segments");
    assert!(net.b().is_closed() || net.b().state() == State::TimeWait);
}

#[test]
fn data_survives_loss_and_reordering() {
    for (name, every) in [("every 7th lost", 7u64), ("every 3rd lost", 3), ("every 20th lost", 20)] {
        let mut net = Net::new((64 << 10, 64 << 10), (64 << 10, 64 << 10));
        net.drop = Box::new(move |n, s| n % every == 0 && !s.has(SYN));
        let data = pattern(300_000);
        let got = transfer(&mut net, &data, 600 * SECOND);
        assert!(got == data, "{name}: {} of {} bytes", got.len(), data.len());
    }
    // Reordering: every segment from A is delayed by an amount that varies.
    let mut net = Net::new((64 << 10, 64 << 10), (64 << 10, 64 << 10));
    let data = pattern(200_000);
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut k = 0u64;
    while got.len() < data.len() && net.now < 60 * SECOND {
        sent += net.a.send(&data[sent..]);
        if let Some(b) = net.b.as_mut() {
            let n = b.recv(&mut buf);
            got.extend_from_slice(&buf[..n]);
        }
        net.flush();
        for f in net.wire.iter_mut() {
            if f.to_b && f.at == net.now + net.delay {
                k += 1;
                f.at += (k * 7919) % 13 * MS;
            }
        }
        if !net.step() {
            break;
        }
    }
    assert!(got == data, "reordered: {} of {} bytes", got.len(), data.len());
    assert!(net.log.iter().any(|l| !l.0 && l.2.sack_len > 0), "B reported what it held beyond a gap in SACK blocks");
}

#[test]
fn a_lost_segment_is_resent_on_the_third_duplicate_not_the_timer() {
    let mut net = Net::new((64 << 10, 64 << 10), (64 << 10, 64 << 10));
    net.run_until(SECOND, |n| n.b.is_some() && n.a.state() == State::Established);
    let data = pattern(20 * 1448);
    // Lose the second data segment A sends.
    let mut data_seen = 0;
    net.drop = Box::new(move |_, s| {
        if !s.data.is_empty() && s.header.dst_port == 80 {
            data_seen += 1;
            return data_seen == 2;
        }
        false
    });
    let start = net.now;
    let got = transfer(&mut net, &data, 10 * SECOND);
    assert_eq!(got.len(), data.len());
    assert!(got == data);
    // Fast retransmit: well inside the first timeout of 1 s.
    let lost_seq = net.log.iter().filter(|l| l.0 && l.3 > 0).nth(1).unwrap().1.seq;
    let resent = net.log.iter().filter(|l| l.0 && l.3 > 0 && l.1.seq == lost_seq).count();
    assert_eq!(resent, 2, "the lost segment went twice");
    assert!(net.now - start < 500 * MS, "recovered by fast retransmit: {} ms", (net.now - start) / MS);
}

#[test]
fn a_connection_to_nobody_times_out_and_a_refused_one_says_so() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.drop = Box::new(|_, _| true);
    net.run_until(600 * SECOND, |n| n.a.is_closed());
    assert_eq!(net.a.error(), Some(Error::TimedOut));
    let syns = net.log.iter().filter(|l| l.1.flags == SYN).count();
    assert_eq!(syns, 7, "the SYN and six retransmissions");
    assert!(net.now < 200 * SECOND && net.now > 60 * SECOND, "given up after {} s", net.now / SECOND);

    // A refusal: a reset that acknowledges the SYN.
    let mut a: Conn = Connection::connect(ends(A, 40001, B, 81), 1000, 77, 1500, buffers(4096, 4096));
    let mut out = [0u8; 1600];
    let n = a.poll(0, &mut out).unwrap();
    let syn = tcp::parse(&out[..n], A, B).unwrap();
    let r = tcp::reset_reply(&syn).unwrap();
    let mut rb = [0u8; 64];
    let n = tcp::build(&mut rb, B, A, &r, &Options::default(), &[]).unwrap();
    a.on_segment(MS, &tcp::parse(&rb[..n], B, A).unwrap());
    assert!(a.is_closed());
    assert_eq!(a.error(), Some(Error::Refused));
}

/// A segment from B to A, as if from the network, built by hand.
fn forge(net: &mut Net, seq: u32, ack: u32, flags: u8, data: &[u8]) {
    let h = Header { src_port: 80, dst_port: 40000, seq, ack, flags, window: 1000 };
    let mut b = [0u8; 1600];
    let n = tcp::build(&mut b, B, A, &h, &Options::default(), data).unwrap();
    net.log.clear();
    let s = tcp::parse(&b[..n], B, A).unwrap();
    net.a.on_segment(net.now, &s);
    net.flush();
}

#[test]
fn a_blind_reset_or_syn_draws_a_challenge_and_only_an_exact_reset_ends_it() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.wire.clear();
    // What A expects next from B, and what A has sent.
    let rcv_nxt = net.log.iter().rev().find(|l| l.0).unwrap().1.ack;
    let snd = net.log.iter().rev().find(|l| l.0).unwrap().1.seq;
    // Timestamps are on: a forged segment without them is still judged by
    // its sequence number.
    forge(&mut net, rcv_nxt.wrapping_add(100), 0, RST, b"");
    assert_eq!(net.a.state(), State::Established, "a reset inside the window but not at its edge");
    assert_eq!(net.log.len(), 1, "draws one challenge ACK");
    assert_eq!((net.log[0].1.flags, net.log[0].1.ack), (ACK, rcv_nxt));
    forge(&mut net, rcv_nxt.wrapping_add(1 << 30), 0, RST, b"");
    assert_eq!(net.a.state(), State::Established, "a reset outside the window");
    assert!(net.log.is_empty(), "is dropped silently");
    // Challenges are answers to invalid segments, at most one per 500 ms
    // (RFC 5961 section 7): a blind sender cannot make A send one per forgery.
    forge(&mut net, rcv_nxt, snd, SYN, b"");
    assert_eq!(net.a.state(), State::Established, "a SYN");
    assert!(net.log.is_empty(), "within 500 ms of the last challenge draws none");
    net.now += 500 * MS;
    forge(&mut net, rcv_nxt, snd, SYN, b"");
    assert_eq!(net.a.state(), State::Established, "a SYN");
    assert_eq!(net.log.len(), 1, "draws a challenge ACK");
    forge(&mut net, rcv_nxt, snd.wrapping_add(5000), ACK, b"data");
    assert_eq!(net.a.readable(), 0, "data acknowledging what was never sent is not taken");
    forge(&mut net, rcv_nxt, 0, RST, b"");
    assert!(net.a.is_closed(), "a reset exactly at the next byte ends it");
    assert_eq!(net.a.error(), Some(Error::Reset));
    assert_eq!(net.a.send(b"x"), 0);
}

#[test]
fn a_shut_window_is_probed_and_the_transfer_resumes_when_it_opens() {
    // B's receive buffer is small and B does not read for a while.
    let mut net = Net::new((64 << 10, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    let data = pattern(40_000);
    let mut sent = net.a.send(&data);
    net.run_until(30 * SECOND, |_| false);
    assert_eq!(net.b().readable(), 4096, "B's buffer filled");
    let probes = net.log.iter().filter(|l| l.0 && l.3 == 0 && l.1.flags == ACK).count();
    assert!(probes >= 3, "the shut window was probed while it stayed shut ({probes})");
    assert!(!net.a.is_closed(), "probing a shut window does not give up within 30 s");
    net.run_until(3600 * SECOND, |_| false);
    assert_eq!(net.a.state(), State::Established, "B kept answering probes for an hour");
    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    let deadline = net.now + 90 * SECOND;
    while got.len() < data.len() && net.now < deadline {
        sent += net.a.send(&data[sent..]);
        let n = net.b().recv(&mut buf);
        got.extend_from_slice(&buf[..n]);
        if !net.step() {
            break;
        }
    }
    assert!(got == data, "{} of {} after the window opened", got.len(), data.len());
}

#[test]
fn a_silent_receiver_with_a_shut_window_times_out() {
    let mut net = Net::new((64 << 10, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.a.send(&pattern(40_000));
    net.run_until(30 * SECOND, |_| false);
    assert_eq!(net.b().readable(), 4096);
    net.drop = Box::new(|_, _| true);
    net.run_until(3600 * SECOND, |n| n.a.is_closed());
    assert_eq!(net.a.error(), Some(Error::TimedOut));
}

#[test]
fn closing_at_once_from_both_sides_ends_both() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.a.send(b"bye");
    net.b().send(b"ciao");
    net.a.close();
    net.b().close();
    net.run_until(200 * SECOND, |n| n.a.is_closed() && n.b.as_ref().is_some_and(|b| b.is_closed()));
    let mut buf = [0u8; 8];
    assert_eq!(net.a.recv(&mut buf), 4);
    assert_eq!(&buf[..4], b"ciao");
    assert_eq!(net.b().recv(&mut buf), 3);
    assert!(net.a.is_closed() && net.b().is_closed());
    assert!(net.a.error().is_none() && net.b().error().is_none());
    assert!(net.log.iter().filter(|l| l.1.flags & FIN != 0).count() >= 2);
}

#[test]
fn an_abort_sends_a_reset_the_peer_takes() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.a.send(b"in flight");
    net.flush();
    assert!(net.a.deadline().is_some());
    net.a.abort();
    assert_eq!(net.a.deadline(), None);
    assert_eq!(net.a.error(), Some(Error::Aborted));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.is_closed()));
    assert_eq!(net.b().error(), Some(Error::Reset), "B took A's reset");
    assert!(net.log.iter().any(|l| l.1.flags & RST != 0));
    assert!(net.a.is_closed());
}

#[test]
fn a_lost_syn_ack_is_answered_when_the_syn_comes_again() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    let mut first = true;
    net.drop = Box::new(move |_, s| {
        let lose = first && s.has(SYN | ACK);
        if lose {
            first = false;
        }
        lose
    });
    net.run_until(10 * SECOND, |n| n.a.state() == State::Established && n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    assert_eq!(net.a.state(), State::Established);
    assert_eq!(net.b().state(), State::Established);
    assert!(net.now < 2 * SECOND, "the handshake finished after one SYN timeout ({} ms)", net.now / MS);
}

/// A small deterministic generator for the randomized test.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn both_ways_through_random_loss_duplication_and_reordering_every_byte_arrives_in_order() {
    let mut resets = 0;
    let only: Option<u64> = std::env::var("TCP_SEED").ok().and_then(|s| s.parse().ok());
    for seed in 0..300u64 {
        if only.is_some_and(|o| o != seed) {
            continue;
        }
        let mut rng = Rng(seed * 2654435761 + 1);
        let sizes = [700usize, 2000, 4096, 9000, 65536, 200_000];
        let a_buf = (sizes[rng.below(6) as usize], sizes[rng.below(6) as usize]);
        let b_buf = (sizes[rng.below(6) as usize], sizes[rng.below(6) as usize]);
        let mut net = Net::new(a_buf, b_buf);
        let loss = rng.below(30);
        let back_loss = rng.below(30);
        let dup = rng.below(10);
        let jitter = rng.below(20) * MS;
        let mut drops = Rng(seed ^ 0x5EED);
        net.drop = Box::new(move |_, s| drops.below(100) < if s.header.dst_port == 80 { loss } else { back_loss });
        let to_b = pattern(rng.below(150_000) as usize);
        let to_a: Vec<u8> = pattern(rng.below(50_000) as usize + 7).into_iter().rev().collect();
        let (mut sa, mut sb) = (0, 0);
        let (mut got_b, mut got_a) = (Vec::new(), Vec::new());
        let mut buf = vec![0u8; 5000];
        let (mut a_closed, mut b_closed) = (false, false);
        while net.now < 3600 * SECOND {
            if sa < to_b.len() {
                sa += net.a.send(&to_b[sa..]);
            } else if !a_closed {
                net.a.close();
                a_closed = true;
            }
            let n = net.a.recv(&mut buf);
            got_a.extend_from_slice(&buf[..n]);
            if let Some(b) = net.b.as_mut() {
                if sb < to_a.len() {
                    sb += b.send(&to_a[sb..]);
                } else if !b_closed && b.state() != State::SynReceived {
                    b.close();
                    b_closed = true;
                }
                let n = b.recv(&mut buf);
                got_b.extend_from_slice(&buf[..n]);
            }
            if net.a.is_closed() && net.b.as_ref().is_some_and(|b| b.is_closed()) {
                break;
            }
            net.flush();
            // Duplicate and delay what was just put on the wire.
            let fresh: Vec<usize> = (0..net.wire.len()).filter(|&i| net.wire[i].fresh).collect();
            for i in fresh {
                net.wire[i].fresh = false;
                net.wire[i].at += rng.below(jitter.max(1));
                if rng.below(100) < dup {
                    let copy = Flight {
                        at: net.wire[i].at + rng.below(jitter.max(1)),
                        fresh: false,
                        to_b: net.wire[i].to_b,
                        bytes: net.wire[i].bytes.clone(),
                    };
                    net.wire.push(copy);
                }
            }
            let before_len = net.log.len();
            let stepped = net.step();
            if std::env::var("TCP_DEBUG").is_ok() {
                for l in &net.log[before_len..] {
                    eprintln!(
                        "  t={} {} flags={} seq={} ack={} wnd={} len={} ts={:?}",
                        net.now / MS,
                        if l.0 { "A>" } else { "<B" },
                        l.1.flags,
                        l.1.seq,
                        l.1.ack,
                        l.1.window,
                        l.3,
                        l.2.timestamps
                    );
                }
                eprintln!(
                    "t={} A deadline {:?} srtt {:?} {:?} B {:?} wire {:?}",
                    net.now / MS,
                    net.a.deadline(),
                    net.a.srtt().map(|r| r / MS),
                    net.a.info(),
                    net.b.as_ref().map(|b| (b.state(), b.deadline())),
                    net.wire.iter().map(|f| (f.at / MS, f.to_b)).collect::<Vec<_>>()
                );
            }
            if !stepped {
                if std::env::var("TCP_DEBUG").is_ok() {
                    eprintln!(
                        "stall at {} ms: A deadline {:?} writable {} {:?} B {:?} sent {sa} got_b {}; last {:?}",
                        net.now / MS,
                        net.a.deadline(),
                        net.a.writable(),
                        net.a.state(),
                        net.b.as_ref().map(|b| b.state()),
                        got_b.len(),
                        net.log[net.log.len().saturating_sub(8)..]
                            .iter()
                            .map(|l| (l.0, l.1.flags, l.1.seq, l.1.ack, l.1.window, l.3))
                            .collect::<Vec<_>>()
                    );
                }
                break;
            }
        }
        let what = format!("seed {seed}: buffers {a_buf:?} {b_buf:?}, loss {loss}%/{back_loss}%, dup {dup}%, jitter {} ms", jitter / MS);
        assert!(got_b == to_b, "{what}: B got {} of {} bytes", got_b.len(), to_b.len());
        assert!(got_a == to_a, "{what}: A got {} of {} bytes", got_a.len(), to_a.len());
        assert!(net.a.is_closed() && net.b().is_closed(), "{what}: states {:?} {:?}", net.a.state(), net.b().state());
        // Closing can fail where TCP itself cannot help it: when every
        // retransmission of the last FIN and every answer to it is lost
        // until the other side's TIME-WAIT is over, the answer is a reset
        // (the data had all arrived: checked above). Nothing else may fail.
        for e in [net.a.error(), net.b().error()].into_iter().flatten() {
            assert_eq!(e, Error::Reset, "{what}");
            resets += 1;
        }
    }
    assert!(resets <= 3, "{resets} of 300 connections ended in a reset after their data");
}

#[test]
fn time_wait_without_its_buffers_still_answers_a_repeated_fin() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    assert_eq!(net.b().send(b"bye"), 3);
    net.b().close();
    net.run_until(SECOND, |n| n.a.state() == State::CloseWait);
    let mut buf = [0u8; 8];
    assert_eq!(net.a.recv(&mut buf), 3);
    // A's FIN arrives at B, and B's acknowledgement of it is lost once: A
    // sends its FIN again into B's TIME-WAIT, whose buffers are gone.
    let mut dropped = false;
    net.drop = Box::new(move |_, seg| {
        let from_b = seg.header.src_port == 80;
        let lose = from_b && !dropped && seg.header.flags == ACK && seg.data.is_empty();
        dropped |= lose;
        lose
    });
    net.a.close();
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::TimeWait));
    assert!(net.b().shed().is_some());
    net.run_until(10 * SECOND, |n| n.a.is_closed());
    let fins = net.log.iter().filter(|(to_b, h, _, _)| *to_b && h.flags & FIN != 0).count();
    assert_eq!(fins, 2, "A sent its FIN again after the lost acknowledgement");
    assert!(net.a.is_closed() && net.a.error().is_none(), "the repeated FIN was acknowledged from TIME-WAIT");
    assert_eq!(net.b().state(), State::TimeWait);
}

/// Like `forge`, an acknowledgement from B with a window and SACK blocks.
fn forge_sack(net: &mut Net, seq: u32, ack: u32, window: u16, sack: &[(u32, u32)]) {
    let h = Header { src_port: 80, dst_port: 40000, seq, ack, flags: ACK, window };
    let mut o = Options::default();
    o.sack[..sack.len()].copy_from_slice(sack);
    o.sack_len = sack.len() as u8;
    let mut b = [0u8; 1600];
    let n = tcp::build(&mut b, B, A, &h, &o, &[]).unwrap();
    net.log.clear();
    let s = tcp::parse(&b[..n], B, A).unwrap();
    net.a.on_segment(net.now, &s);
    net.flush();
}

#[test]
fn a_loss_is_found_by_time_from_one_sack_whatever_the_window() {
    for segments in [2, 8] {
        first_loss_from_one_sack(segments);
    }
}

fn first_loss_from_one_sack(segments: usize) {
    // Linux's receive window grows with almost every acknowledgement, and a
    // small window leaves fewer than three segments after a loss: counting
    // duplicates (RFC 5681) waited for the 200 ms timer, 67 times in the
    // interop suite's 16 MiB on its lossy path. RACK (RFC 8985): once a
    // segment sent after it is SACKed, a segment not heard of for that
    // one's round trip and a reordering window is lost.
    let mut net = Net::new((64 << 10, 64 << 10), (64 << 10, 64 << 10));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.wire.clear();
    let rcv_nxt = net.log.iter().rev().find(|l| l.0).unwrap().1.ack;
    // Only the second will be SACKed. With eight segments, six unmarked
    // segments still count in flight when the window falls to four.
    net.drop = Box::new(|_, s| !s.data.is_empty());
    let mss = net.a.mss();
    let size = segments * mss as usize;
    assert_eq!(net.a.send(&pattern(size)), size);
    net.log.clear();
    net.flush();
    let first = net.log.iter().find(|l| l.0 && l.3 > 0).unwrap().1.seq;
    // A round trip later B SACKs the second, with a window of its own.
    net.now += 2 * MS;
    forge_sack(&mut net, rcv_nxt, first, 1001, &[(first.wrapping_add(mss), first.wrapping_add(2 * mss))]);
    let resent = |net: &Net| net.log.iter().any(|l| l.0 && l.3 > 0 && l.1.seq == first);
    if !resent(&net) {
        // The reordering window: the first goes when it has passed.
        let at = net.a.deadline().expect("a timer for the reordering window");
        assert!(at < net.now + 2 * MS, "the reordering window is a fraction of a round trip, not the timeout");
        net.now = at;
        net.a.on_time(net.now);
        net.log.clear();
        net.flush();
    }
    assert!(resent(&net), "the first segment resent within a round trip of the SACK: {:?}", net.log);
}

#[test]
fn a_lost_repair_is_found_by_new_data_sent_behind_it() {
    // Lose the first data segment twice, so its first repair is lost too.
    // A repair is found lost when something sent after it is delivered
    // (RFC 8985): a sender whose whole buffer is already in flight has
    // nothing to send after it and waits for the retransmission timeout;
    // one whose buffer grows when it is what holds the sender back does not.
    let mut times = Vec::new();
    for grow_to in [0, 128 << 10] {
        let mut net = Net::new((8 * 1448, 64 << 10), (64 << 10, 64 << 10));
        net.delay = MS;
        net.grow_to = grow_to;
        net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
        let mut first = None;
        let mut lost = 0;
        net.drop = Box::new(move |_, s| {
            if !s.data.is_empty() && s.header.seq == *first.get_or_insert(s.header.seq) && lost < 2 {
                lost += 1;
                return true;
            }
            false
        });
        let data = pattern(128 << 10);
        let start = net.now;
        assert_eq!(transfer(&mut net, &data, SECOND), data);
        let timeouts = net.sender_timeouts;
        eprintln!("grow to {grow_to}: {} ms, {timeouts} timeouts, send buffer {}", (net.now - start) / MS, net.a.send_capacity());
        if grow_to == 0 {
            assert!(timeouts > 0, "the fixed buffer's case is the one this test is about");
        } else {
            assert_eq!(timeouts, 0, "the lost repair was found by the data sent after it");
        }
        times.push(net.now - start);
    }
    assert!(times[1] * 4 < times[0], "{times:?}");
}

#[test]
fn a_send_buffer_grows_to_what_the_path_carries() {
    // 4 MiB over a 10 ms round trip: a fixed 32 KiB send buffer sends 32
    // KiB a round trip whatever the windows allow; growing, the sender is
    // held by the congestion window and the scoreboard instead. Growth
    // copies what is in flight and changes no byte (the data is checked),
    // and it stops at the bound it was given.
    let mut times = Vec::new();
    for grow_to in [0, 128 << 10] {
        let mut net = Net::new((32 << 10, 64 << 10), (64 << 10, 256 << 10));
        net.grow_to = grow_to;
        let data = pattern(4 << 20);
        assert_eq!(transfer(&mut net, &data, 10 * SECOND), data);
        assert_eq!(net.a.send_capacity(), (32 << 10).max(grow_to));
        eprintln!("grow to {grow_to}: {} ms", net.now / MS);
        times.push(net.now);
    }
    assert!(times[1] * 2 < times[0], "{times:?}");
}

#[test]
fn a_send_buffer_is_only_replaced_by_a_larger_one_while_data_can_go() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    assert!(!net.a.grow_send_buffer(vec![0; 4096]), "not larger");
    assert!(net.a.grow_send_buffer(vec![0; 8192]), "SYN-SENT: data may be queued");
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    assert_eq!(transfer(&mut net, &pattern(20_000), SECOND), pattern(20_000));
    assert!(net.a.is_closed() || net.a.state() == State::TimeWait);
    assert!(!net.a.grow_send_buffer(vec![0; 16384]), "nothing more will be sent");
}

/// One 4 MiB transfer through `time_through_loss`'s path: its simulated
/// seconds, the segments sent again whose first copy had arrived, and the
/// window reductions that stood (not undone).
#[derive(Debug, Clone, Copy)]
struct Run {
    secs: f64,
    redundant: usize,
    reductions: usize,
    /// Segments A's `poll` gave.
    polls: usize,
}

/// Moves 4 MiB from A to B over a 2 ms round trip with 64 KiB buffers,
/// when `loss` percent of segments are lost each way and, with `rough`,
/// the path the interop suite's netem makes: 10% of segments overtake the
/// others (no delay instead of 1 ms) and 1% arrive twice; for each of five
/// seeds.
fn time_through_loss(loss: u64, rough: bool) -> Vec<Run> {
    time_through(loss, rough, false, false)
}

/// As `time_through_loss`, A's interface with the offloads when `cut`.
fn time_through(loss: u64, rough: bool, cut: bool, batch: bool) -> Vec<Run> {
    (1..=5u64)
        .map(|seed| {
            let mut net = Net::new((65536, 65536), (65536, 65536));
            net.delay = MS;
            net.batch = batch;
            if cut {
                net.a.set_offloads(true, 44 * 1448);
                net.device = Some(1448);
            }
            let mut drops = Rng(seed * 7919);
            // The first copy that survived the drop decision will arrive, even
            // if its ACK is lost. Count retries of those ranges separately.
            let redundant = std::rc::Rc::new(std::cell::Cell::new(0));
            let count = redundant.clone();
            let mut on_wire = std::collections::HashSet::new();
            net.drop = Box::new(move |_, s| {
                let lost = drops.below(100) < loss;
                if !s.data.is_empty() {
                    let range = (s.header.seq, s.data.len());
                    if on_wire.contains(&range) {
                        count.set(count.get() + 1);
                    }
                    if !lost {
                        on_wire.insert(range);
                    }
                }
                lost
            });
            if rough {
                let mut r = Rng(seed * 104729);
                net.vary = Some(Box::new(move || (if r.below(100) < 10 { 0 } else { MS }, r.below(100) < 1)));
            }
            let data = pattern(4 << 20);
            let start = net.now;
            let got = transfer(&mut net, &data, 600 * SECOND);
            let mut sent = std::collections::HashSet::new();
            let repeats = net.log.iter().filter(|(to_b, h, _, len)| *to_b && *len > 0 && !sent.insert((h.seq, *len))).count();
            let dsacks = net.log.iter().filter(|(to_b, h, opt, _)| {
                !to_b && opt.sack_len > 0 && (opt.sack[0].1.wrapping_sub(h.ack) as i32) <= 0
            }).count();
            let undone = net.a.info().undone as usize;
            eprintln!("seed {seed}, {loss}% loss, reordered {rough}: {repeats} retransmissions ({} redundant), {dsacks} DSACKs, {} window reductions ({undone} undone), {} timeouts",
                redundant.get(), net.window_reductions, net.sender_timeouts);
            assert!(got == data, "seed {seed}: {} of {} bytes arrived in order", got.len(), data.len());
            Run {
                secs: (net.now - start) as f64 / SECOND as f64,
                redundant: redundant.get(),
                reductions: net.window_reductions.saturating_sub(undone),
                polls: net.a_polls,
            }
        })
        .collect()
}

#[test]
fn loss_is_repaired_without_waiting_for_the_timer() {
    // The interop suite's lossy path (2% each way, 2 ms) moved 16 MiB in 22 s
    // under NewReno, where Linux takes 0.1 to 1.1 s: a hole a round trip, and
    // the 200 ms timer whenever a repair was lost. A clean path takes about
    // 0.13 s here (the window over the round trip). Reordered, the sender
    // once took overtaken segments for lost: 63 to 511 of a run's
    // retransmissions were of segments that had arrived, and 4 MiB took up
    // to 0.8 s. The window RACK waits now covers the reordering the path
    // has shown, measured (2026-11-24: 0.26 to 0.41 s, 3 to 45).
    let secs = |runs: &[Run]| runs.iter().map(|r| r.secs).collect::<Vec<_>>();
    let clean = time_through_loss(0, false);
    let lossy = time_through_loss(2, false);
    let rough = time_through_loss(2, true);
    eprintln!(
        "4 MiB: clean {:.3?} s; 2% loss each way {:.3?} s; and reordered, duplicated {:.3?} s",
        secs(&clean),
        secs(&lossy),
        secs(&rough)
    );
    for (what, runs, bound) in [("2% loss", &lossy, 0.7), ("2% loss, reordering and duplication", &rough, 0.45)] {
        let worst = secs(runs).into_iter().fold(0.0, f64::max);
        assert!(worst < bound, "4 MiB through {what} took up to {worst:.2} s");
    }
    for r in &rough {
        assert!(r.redundant <= 50, "{r:?}: segments that had arrived were sent again");
    }
}

#[test]
fn reordering_alone_is_learned_not_paid_for() {
    // The interop path without its loss: 10% of segments overtake the rest
    // by a millisecond of a 2 ms round trip, 1% arrive twice. Nothing is
    // lost, so every reduction is a mistake; each overtaking seen shows how
    // far the path reorders, and the window covers that from then on.
    // Still paid (2026-11-24): while slow start doubles the window, a wider
    // burst meets reordering not yet seen, and 8 to 46 segments a run went
    // again in the first 51 ms of about 130 (5 reductions at most stood).
    // The time is a clean path's: 0.110 to 0.143 s against 0.135.
    let clean = time_through_loss(0, false);
    for (r, c) in time_through_loss(0, true).iter().zip(&clean) {
        assert!(r.reductions <= 6 && r.redundant <= 50, "{r:?}");
        assert!(r.secs < c.secs * 1.1, "{r:?} against {c:?} on a clean path");
    }
}

#[test]
fn an_interface_that_cuts_and_sums_carries_the_same_bytes_in_fewer_segments() {
    // Every byte arrives (checked inside), in the same time or less, on a
    // clean path, with 2% loss, and on the interop path's impairments,
    // when A gives its interface segments of up to 44 MSS to cut and only
    // the pseudo-header's sum to finish.
    for (loss, rough) in [(0, false), (2, false), (2, true)] {
        let whole = time_through(loss, rough, false, true);
        let cut = time_through(loss, rough, true, true);
        let worst = |runs: &[Run]| runs.iter().map(|r| r.secs).fold(0.0, f64::max);
        eprintln!(
            "{loss}% loss, reordered {rough}: {:.3} s and {} segments given, cut: {:.3} s and {} given",
            worst(&whole),
            whole[0].polls,
            worst(&cut),
            cut[0].polls
        );
        assert!(worst(&cut) <= worst(&whole) * 1.1, "{whole:?} against {cut:?}");
        if loss == 0 {
            assert!(cut[0].polls * 8 < whole[0].polls, "{} segments given, {} without the offload", cut[0].polls, whole[0].polls);
        }
    }
}

// The hostile paths the 2026-11-24 audit found untested: a peer (or anyone
// who knows the ports) holding a connection for ever, drawing answers
// without limit, or learning the machine's uptime.

/// RFC 1122 4.2.2.17: a peer that answers every probe of its shut window
/// is there, and keeps the connection as long as it likes. Before, answered
/// probes counted toward giving up, and a live peer that kept its window
/// shut some ten to fifteen minutes was reset.
#[test]
fn a_live_peer_may_keep_its_window_shut_for_as_long_as_it_answers() {
    let mut net = Net::new((64 << 10, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    let data = pattern(40_000);
    net.a.send(&data);
    net.run_until(45 * 60 * SECOND, |n| n.a.is_closed());
    assert!(!net.a.is_closed(), "A gave up on a peer that answered every probe: {:?}", net.a.error());
    assert_eq!(net.b().readable(), 4096);
    let probes = net.log.iter().filter(|l| l.0 && l.3 == 0 && l.1.flags == ACK).count();
    assert!(probes >= 20, "the window was probed all along ({probes})");
}

/// A peer that stops answering the probes is given up on, as before.
#[test]
fn a_peer_that_stops_answering_a_shut_window_is_given_up_on() {
    let mut net = Net::new((64 << 10, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.a.send(&pattern(40_000));
    net.run_until(30 * SECOND, |_| false);
    net.drop = Box::new(|_, seg| seg.header.src_port == 80);
    net.run_until(4 * 3600 * SECOND, |n| n.a.is_closed());
    assert_eq!(net.a.error(), Some(Error::TimedOut));
}

/// A connection A has closed first, in TIME-WAIT.
fn in_time_wait() -> Net {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.a.close();
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::CloseWait));
    net.b().close();
    net.run_until(SECOND, |n| n.a.state() == State::TimeWait && n.b.as_ref().is_some_and(|b| b.is_closed()));
    assert_eq!(net.a.state(), State::TimeWait);
    net
}

/// Only the peer's own FIN sent again restarts TIME-WAIT, no more often
/// than a challenge is answered and never past four times its length. A
/// FIN anyone could send knowing the ports (any sequence number) is an
/// out-of-window segment: answered at most twice a second, the wait not
/// restarted. Before, any FIN restarted it and drew an acknowledgement,
/// so a spoofer kept the entry for ever and drew answers without limit.
#[test]
fn time_wait_is_restarted_only_by_the_peers_own_fin_and_not_for_ever() {
    let mut net = in_time_wait();
    let (entered, rcv_nxt) = (net.now, net.log.iter().rev().find(|l| l.0).unwrap().1.ack);
    let mut answers = 0;
    // A spoofer's FINs, a hundred a second for two minutes.
    while net.now < entered + 120 * SECOND && net.a.state() == State::TimeWait {
        forge(&mut net, rcv_nxt.wrapping_add(7777), 0, FIN | ACK, b"");
        answers += net.log.len();
        net.now += 10 * MS;
        net.a.on_time(net.now);
    }
    assert!(net.a.is_closed(), "TIME-WAIT outlived its minute under spoofed FINs");
    assert!(net.now <= entered + 61 * SECOND, "ended {} ms after it began", (net.now - entered) / MS);
    assert!(answers <= 125, "{answers} answers to spoofed FINs in a minute");

    // The peer's own FIN, again and again: acknowledged, the wait restarted,
    // and still over within four minutes.
    let mut net = in_time_wait();
    let entered = net.now;
    let fin = net.log.iter().rev().find(|l| l.0).unwrap().1.ack.wrapping_sub(1);
    while net.now < entered + 600 * SECOND && net.a.state() == State::TimeWait {
        forge(&mut net, fin, 0, FIN | ACK, b"");
        net.now += SECOND;
        net.a.on_time(net.now);
    }
    assert!(net.a.is_closed(), "the peer's repeated FIN held TIME-WAIT for ever");
    assert!(net.now <= entered + 241 * SECOND, "TIME-WAIT lasted {} s", (net.now - entered) / SECOND);
}

/// Blind resets (and SYNs) in TIME-WAIT, from anyone who knows the ports:
/// spread over the sequence space, a thousand in ten seconds. None ends it
/// early or makes it last longer, and the answers they draw are the
/// challenge rate's, not one each. Only the peer's exact reset, at the
/// byte it is owed, ends it (as Linux's default; RFC 5961 makes a blind
/// one a one-in-a-window guess).
#[test]
fn blind_resets_and_syns_in_time_wait_neither_end_it_nor_draw_answers_each() {
    let mut net = in_time_wait();
    let (entered, rcv_nxt) = (net.now, net.log.iter().rev().find(|l| l.0).unwrap().1.ack);
    let mut answers = 0;
    let mut x: u32 = 0x2545_F491;
    for _ in 0..1000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let seq = if x == rcv_nxt { x.wrapping_add(1) } else { x };
        forge(&mut net, seq, x.rotate_left(7), if x & 1 == 0 { RST } else { RST | ACK }, b"");
        answers += net.log.len();
        forge(&mut net, seq.wrapping_add(9), 0, SYN, b"");
        answers += net.log.len();
        assert_eq!(net.a.state(), State::TimeWait, "a blind reset or SYN ended TIME-WAIT");
        net.now += 10 * MS;
        net.a.on_time(net.now);
    }
    assert!(answers <= 25, "{answers} answers to 2,000 blind segments in ten seconds");
    // The wait ends when it would have.
    while net.a.state() == State::TimeWait && net.now < entered + 120 * SECOND {
        net.now += SECOND;
        net.a.on_time(net.now);
    }
    assert!(net.a.is_closed() && net.now <= entered + 61 * SECOND, "TIME-WAIT ended {} s after it began", (net.now - entered) / SECOND);
    // The peer's own reset, exactly where it is owed, ends it at once.
    let mut net = in_time_wait();
    forge(&mut net, rcv_nxt, 0, RST, b"");
    assert!(net.a.is_closed(), "the peer's exact reset did not end TIME-WAIT");
    assert_eq!(net.a.error(), None, "ending TIME-WAIT loses nothing");
}

/// A connection its program has let go of, closed on this side, whose
/// peer neither closes nor sends: ended a minute after it last heard from
/// the peer. One its program still holds is a half-close and waits on.
#[test]
fn fin_wait_2_ends_when_nobody_holds_it_and_the_peer_is_silent() {
    for released in [false, true] {
        let mut net = Net::new((4096, 4096), (4096, 4096));
        net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
        net.a.close();
        net.run_until(SECOND, |n| n.a.state() == State::FinWait2);
        assert_eq!(net.a.state(), State::FinWait2);
        if released {
            net.a.release(net.now);
        }
        // B sends a little at first, then nothing at all.
        net.b().send(b"still here");
        net.run_until(20 * SECOND, |_| false);
        let heard = net.now;
        net.drop = Box::new(|_, seg| seg.header.src_port == 80);
        net.run_until(10 * 60 * SECOND, |n| n.a.is_closed());
        if released {
            assert_eq!(net.a.error(), Some(Error::TimedOut), "a silent peer held a connection nobody holds");
            assert!(net.now <= heard + 61 * SECOND);
        } else {
            assert_eq!(net.a.state(), State::FinWait2, "a held half-close was ended");
        }
    }
}

/// The timestamps a connection sends do not tell its peer the machine's
/// uptime: the offset they count from is not the initial sequence number
/// (which the peer sees in the same SYN), so the clock cannot be read back
/// from the two.
#[test]
fn timestamps_do_not_reveal_uptime() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.now = 3 * 3600 * SECOND;
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    let (_, syn, o, _) = net.log.iter().find(|l| l.0 && l.1.flags == SYN).unwrap();
    let (val, _) = o.timestamps.expect("timestamps on");
    let read_back = val.wrapping_sub(syn.seq) as u64;
    assert!(read_back.abs_diff(net.now / MS) > 1000, "the SYN's timestamp minus its sequence number is the clock");
}

/// SACK blocks that name nothing this side sent (beyond what was sent,
/// before what was acknowledged, the wrong way round, wrapped) change
/// nothing: no segment taken for received or lost, and the transfer
/// finishes with every byte.
#[test]
fn bogus_sack_blocks_change_nothing() {
    let mut net = Net::new((64 << 10, 64 << 10), (64 << 10, 64 << 10));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    let data = pattern(30_000);
    let mut sent = net.a.send(&data);
    net.wire.clear();
    let una = net.a.sent_to();
    let max = net.log.iter().filter(|l| l.0).map(|l| l.1.seq.wrapping_add(l.3 as u32)).max().unwrap();
    let ack = net.log.iter().rev().find(|l| l.0).unwrap().1.ack;
    for blocks in [
        &[(max.wrapping_add(1000), max.wrapping_add(5000))][..],
        &[(una.wrapping_sub(9000), una.wrapping_sub(100))],
        &[(una.wrapping_add(4000), una.wrapping_add(1000))],
        &[(max.wrapping_sub(10), una.wrapping_add(10))],
        &[(0, u32::MAX), (u32::MAX - 5, 3), (una, una)],
    ] {
        forge_sack(&mut net, ack, una, 1000, blocks);
        assert!(!net.a.is_closed(), "bogus SACK blocks {blocks:x?} ended the connection");
    }
    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    while got.len() < data.len() && net.now < 60 * SECOND {
        sent += net.a.send(&data[sent..]);
        let n = net.b().recv(&mut buf);
        got.extend_from_slice(&buf[..n]);
        if !net.step() {
            break;
        }
    }
    assert!(got == data, "{} of {} bytes after bogus SACK blocks", got.len(), data.len());
}

/// A segment from B to A carrying timestamps `ts` (its value, its echo),
/// built by hand.
fn forge_ts(net: &mut Net, seq: u32, ack: u32, flags: u8, data: &[u8], ts: (u32, u32)) {
    let h = Header { src_port: 80, dst_port: 40000, seq, ack, flags, window: 1000 };
    let o = Options { timestamps: Some(ts), ..Options::default() };
    let mut b = [0u8; 1600];
    let n = tcp::build(&mut b, B, A, &h, &o, data).unwrap();
    net.log.clear();
    let s = tcp::parse(&b[..n], B, A).unwrap();
    net.a.on_segment(net.now, &s);
    net.flush();
}

/// PAWS keeps the peer's newest timestamp only as long as it can mean
/// anything (RFC 7323 5.5): a connection idle for 25 days, whose peer's
/// millisecond clock has since run more than half its range, takes the
/// peer's next segment. Before, the old timestamp was kept for ever, every
/// new segment looked older than it, and the connection was wedged.
#[test]
fn paws_forgets_a_timestamp_older_than_24_days() {
    let mut net = Net::new((4096, 4096), (4096, 4096));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    let b_val = net.log.iter().rev().find_map(|l| (!l.0).then_some(l.2.timestamps).flatten()).expect("B sent a timestamp").0;
    let (seq, ack) = (net.a.received_to(), net.a.sent_to());
    net.wire.clear();
    net.now += 25 * 24 * 3600 * SECOND;
    // The peer's clock ran on by more than half its range: its value now
    // compares as older than the one A kept.
    forge_ts(&mut net, seq, ack, ACK, b"after a long idle", (b_val.wrapping_add(0x8000_0001), 0));
    assert_eq!(net.a.readable(), 17, "a connection idle 25 days refused its peer's next segment (PAWS kept a stale timestamp)");
}

/// A round trip is measured from an echoed timestamp only when the echo is
/// one this side sent: a peer that echoes a value never sent (newer than
/// anything this side sent) cannot make the round trip look shorter and
/// the retransmission timer fire early.
#[test]
fn a_forged_timestamp_echo_measures_nothing() {
    let mut net = Net::new((8192, 8192), (8192, 8192));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    net.a.send(&pattern(1000));
    for _ in 0..200 {
        if !net.step() || net.a.srtt().is_some() && net.wire.is_empty() {
            break;
        }
    }
    let before_srtt = net.a.srtt().expect("a round trip was measured");
    // A segment that is lost, then resent on the timer: its acknowledgement
    // has no send time on the scoreboard (Karn), so an echo is all there is.
    net.a.send(&pattern(500));
    net.flush();
    net.wire.clear();
    let due = net.a.deadline().expect("a retransmission timer");
    net.now = due;
    net.a.on_time(net.now);
    net.flush();
    net.wire.clear();
    let (val, end, b_ack) = net
        .log
        .iter()
        .rev()
        .find(|l| l.0 && l.3 > 0)
        .map(|l| (l.2.timestamps.unwrap().0, l.1.seq.wrapping_add(l.3 as u32), l.1.ack))
        .expect("the resent segment");
    let b_val = net.log.iter().rev().find_map(|l| (!l.0).then_some(l.2.timestamps).flatten()).map_or(1, |t| t.0);
    net.now += 500 * MS;
    // The echo of A's clock now, a value A never sent: the round trip it
    // claims is nothing.
    forge_ts(&mut net, b_ack, end, ACK, b"", (b_val.wrapping_add(500), val.wrapping_add(500)));
    assert_eq!(net.a.srtt(), Some(before_srtt), "a forged echo changed the measured round trip");
}

/// A path that carries packets of at most `mtu` bytes: A's larger segments
/// are dropped, and with `say` each drop's sequence number is kept for a
/// router's "fragmentation needed" (RFC 1191), which the test hands A.
fn narrow_path(net: &mut Net, mtu: usize, say: bool) -> std::rc::Rc<std::cell::RefCell<Vec<u32>>> {
    let said = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let keep = said.clone();
    // IPv4 header, TCP header and the timestamps option.
    let most = mtu - 20 - 20 - 12;
    net.drop = Box::new(move |_, s| {
        let big = s.header.dst_port == 80 && s.data.len() > most;
        if big && say {
            keep.borrow_mut().push(s.header.seq);
        }
        big
    });
    said
}

/// Send `data` from A over a narrow path to the end: whether every byte
/// arrived, and when.
fn over_narrow_path(net: &mut Net, data: &[u8], said: &std::rc::Rc<std::cell::RefCell<Vec<u32>>>, limit: u64) -> Option<u64> {
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    let start = net.now;
    while got.len() < data.len() && net.now < start + limit {
        sent += net.a.send(&data[sent..]);
        let n = net.b().recv(&mut buf);
        got.extend_from_slice(&buf[..n]);
        for seq in said.borrow_mut().drain(..) {
            net.a.path_mtu(1400, seq);
        }
        if !net.step() {
            break;
        }
    }
    (got == data).then(|| net.now - start)
}

/// A path whose MTU is 1,400 bytes: a router says so for each packet too
/// large (ICMP fragmentation needed, quoting the segment): segments are cut
/// to fit and what was in flight goes again, at once. And on a path whose
/// routers say nothing (their ICMP filtered: a black hole), full-size
/// segments that go unanswered twice in a row are tried smaller (RFC 4821).
/// Before, every segment went at the full size the peer's MSS allowed with
/// "don't fragment" set, nothing heard a router, and a connection on such a
/// path sent its small segments and hung on its large ones until it gave up.
#[test]
fn a_narrow_path_is_found_whether_its_routers_say_so_or_not() {
    let data = pattern(64 << 10);
    for say in [true, false] {
        let mut net = Net::new((64 << 10, 64 << 10), (64 << 10, 64 << 10));
        net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
        let said = narrow_path(&mut net, 1400, say);
        let took = over_narrow_path(&mut net, &data, &said, 120 * SECOND);
        let how = if say { "whose routers say so" } else { "whose routers say nothing" };
        let took = took.unwrap_or_else(|| panic!("64 KiB over a 1,400-byte path {how} did not arrive"));
        assert!(net.a.mss() <= 1400 - 52, "segments still larger than the path carries");
        if say {
            assert!(took < SECOND, "the router's word took {} ms to act on", took / MS);
        }
    }
}

/// A router's word is believed only for a segment in flight (RFC 5927): a
/// blind sender's message quoting any other sequence number changes
/// nothing, and no message makes segments smaller than any path carries.
#[test]
fn only_a_message_quoting_a_segment_in_flight_shrinks_segments() {
    let mut net = Net::new((64 << 10, 64 << 10), (64 << 10, 64 << 10));
    net.run_until(SECOND, |n| n.b.as_ref().is_some_and(|b| b.state() == State::Established));
    let before = net.a.mss();
    net.a.send(&pattern(8000));
    net.flush();
    let una = net.a.received_to(); // B's side: not a sequence of A's
    assert!(!net.a.path_mtu(1000, una.wrapping_add(12345)), "a message quoting nothing in flight was believed");
    assert!(!net.a.path_mtu(1000, net.a.sent_to()), "the next byte to send is not in flight");
    assert_eq!(net.a.mss(), before);
    let in_flight = net.log.iter().find(|l| l.0 && l.3 > 0).map(|l| l.1.seq).unwrap();
    assert!(net.a.path_mtu(100, in_flight), "a message quoting a segment in flight");
    assert_eq!(net.a.mss(), 576 - 52, "no path is taken to carry less than 576 bytes");
}
