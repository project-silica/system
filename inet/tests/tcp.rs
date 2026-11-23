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
    now: u64,
    a: Conn,
    b: Option<Conn>,
    wire: Vec<Flight>,
    /// One way's delay.
    delay: u64,
    /// Drop the nth segment sent (counting from 1) when `drop(n)` says so.
    drop: Dropper,
    sent: u64,
    /// Every segment sent, to look at afterwards: (to B, header, data length).
    log: Vec<(bool, Header, Options, usize)>,
    b_buffers: (usize, usize),
}

impl Net {
    fn new(a_buffers: (usize, usize), b_buffers: (usize, usize)) -> Net {
        let a = Connection::connect(ends(A, 40000, B, 80), 0xFFFF_FF00, 1500, buffers(a_buffers.0, a_buffers.1));
        Net { now: 0, a, b: None, wire: Vec::new(), delay: 5 * MS, drop: Box::new(|_, _| false), sent: 0, log: Vec::new(), b_buffers }
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
        let mut out = [0u8; 1600];
        let mut sent = Vec::new();
        while let Some(n) = self.a.poll(self.now, &mut out) {
            sent.push(out[..n].to_vec());
            if sent.len() == BURST {
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
        self.wire.push(Flight { at: self.now + self.delay, fresh: true, to_b, bytes });
    }

    /// Deliver what arrives next, or fire the next timer; false when
    /// nothing is left to happen.
    fn step(&mut self) -> bool {
        self.flush();
        let next_wire = self.wire.iter().map(|f| f.at).min();
        let next_timer = [self.a.deadline(), self.b.as_ref().and_then(|b| b.deadline())].into_iter().flatten().min();
        let Some(t) = [next_wire, next_timer].into_iter().flatten().min() else { return false };
        self.now = self.now.max(t);
        if next_wire == Some(t) {
            let i = self.wire.iter().position(|f| f.at == t).unwrap();
            let f = self.wire.remove(i);
            self.deliver(f);
        } else {
            self.a.on_time(self.now);
            if let Some(b) = self.b.as_mut() {
                b.on_time(self.now);
            }
        }
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
                    self.b = Some(Connection::accept(ends(B, 80, A, 40000), &s, 0x7000_0000, 1500, buffers(sb, rb)));
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
    net.run_until(SECOND, |n| n.a.at_end());
    assert_eq!(net.a.recv(&mut buf), 21);
    assert!(net.a.at_end(), "B's FIN read as the end");
    assert_eq!(net.a.state(), State::CloseWait);
    assert_eq!(net.b().state(), State::FinWait2);
    net.a.close();
    net.run_until(SECOND, |n| n.a.is_closed());
    assert!(net.a.is_closed() && net.a.error().is_none(), "A closed second: no TIME-WAIT, no error");
    assert_eq!(net.b().state(), State::TimeWait, "B closed first and waits");
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
    let mut a: Conn = Connection::connect(ends(A, 40001, B, 81), 1000, 1500, buffers(4096, 4096));
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
    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    while got.len() < data.len() && net.now < 120 * SECOND {
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
    net.a.send(b"unsent");
    net.a.abort();
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
