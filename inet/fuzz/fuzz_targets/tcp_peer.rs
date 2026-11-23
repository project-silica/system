//! A TCP connection with a hostile peer. The connection is opened (from
//! this side, or accepted), then the input is a script: segments whose
//! every field the peer chooses, the clock moving, and the application
//! sending, reading, closing and aborting. Nothing may panic or overflow,
//! every segment the connection sends must parse, what it says is readable
//! must be readable, and its buffers' bounds must hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_inet::Ipv4;
use silica_inet::tcp::{self, Header, Options, Segment};
use silica_inet::tcp_conn::{Buffers, Connection, Endpoints};

const US: Ipv4 = Ipv4([10, 0, 2, 15]);
const PEER: Ipv4 = Ipv4([10, 0, 2, 2]);
const SEND: usize = 3000;
const RECEIVE: usize = 2000;

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes([self.u8()?, self.u8()?, self.u8()?, self.u8()?]))
    }
    fn bytes(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (b, rest) = self.0.split_at(n);
        self.0 = rest;
        b
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(first) = input.u8() else { return };
    let ends = Endpoints { local: US, local_port: 80, remote: PEER, remote_port: 4000 };
    let buffers = Buffers { send: vec![0u8; SEND], receive: vec![0u8; RECEIVE] };
    let iss = 0xFFFF_FF00u32.wrapping_add(first as u32);
    let mut now = 0u64;
    // The peer's sequence numbers, so that a script can follow them or not.
    let mut peer_seq = input.u32().unwrap_or(0);
    let mut c = if first & 1 == 0 {
        Connection::connect(ends, iss, 1500, buffers)
    } else {
        let syn = Segment {
            header: Header { src_port: 4000, dst_port: 80, seq: peer_seq, ack: 0, flags: tcp::SYN, window: input.u16().unwrap_or(0) },
            options: options(&mut input),
            data: &[],
        };
        peer_seq = peer_seq.wrapping_add(1);
        Connection::accept(ends, &syn, iss, 1500, buffers)
    };
    let mut out = vec![0u8; 1600];
    let mut sent_by_us: Vec<(u32, u32)> = Vec::new();
    let mut steps = 0;
    while let Some(op) = input.u8() {
        steps += 1;
        if steps > 400 {
            break;
        }
        match op % 8 {
            // A segment from the peer.
            0..=2 => {
                let follow = op & 0x80 != 0;
                let seq = if follow { peer_seq } else { input.u32().unwrap_or(0) };
                let ack = if op & 0x40 != 0 {
                    // Acknowledge something we sent, so the script gets far.
                    let i = input.u8().unwrap_or(0) as usize;
                    sent_by_us.get(i % sent_by_us.len().max(1)).map_or(iss, |&(s, l)| s.wrapping_add(l))
                } else {
                    input.u32().unwrap_or(0)
                };
                let flags = input.u8().unwrap_or(tcp::ACK);
                let window = input.u16().unwrap_or(u16::MAX);
                let options = options(&mut input);
                let len = input.u16().unwrap_or(0) as usize % 1600;
                let payload = input.bytes(len).to_vec();
                let s = Segment { header: Header { src_port: 4000, dst_port: 80, seq, ack, flags, window }, options, data: &payload };
                if follow {
                    peer_seq = peer_seq.wrapping_add(s.len());
                }
                c.on_segment(now, &s);
            }
            3 => now += u64::from(input.u16().unwrap_or(0)) * 1_000_000,
            4 => {
                let n = input.u16().unwrap_or(0) as usize % 4000;
                let d = input.bytes(n).to_vec();
                let took = c.send(&d);
                assert!(took <= d.len());
            }
            5 => {
                let readable = c.readable();
                let mut buf = vec![0u8; input.u16().unwrap_or(0) as usize % 3000];
                let n = c.recv(&mut buf);
                assert_eq!(n, readable.min(buf.len()), "readable says what recv gives");
                assert!(c.readable() <= RECEIVE);
            }
            6 => c.close(),
            _ => {
                if op & 0x10 != 0 {
                    c.abort();
                }
            }
        }
        if c.deadline().is_some_and(|d| d <= now) {
            c.on_time(now);
        }
        let mut polls = 0;
        while let Some(n) = c.poll(now, &mut out) {
            polls += 1;
            assert!(polls < 1000, "poll goes on giving segments");
            let s = tcp::parse(&out[..n], US, PEER).expect("a segment the connection built does not parse");
            assert!(s.data.len() as u32 <= c.mss().max(1), "a segment larger than the MSS");
            sent_by_us.push((s.header.seq, s.len()));
        }
        assert!(c.readable() <= RECEIVE);
        assert!(c.writable() <= SEND);
    }
});

fn options(input: &mut Input<'_>) -> Options {
    let bits = input.u8().unwrap_or(0);
    let mut o = Options::default();
    if bits & 1 != 0 {
        o.mss = input.u16();
    }
    if bits & 2 != 0 {
        o.window_scale = input.u8().map(|s| s.min(14));
    }
    o.sack_permitted = bits & 4 != 0;
    if bits & 8 != 0 {
        o.timestamps = Some((input.u32().unwrap_or(0), input.u32().unwrap_or(0)));
    }
    if bits & 16 != 0 {
        let n = (bits >> 5) as usize % 4 + 1;
        for i in 0..n {
            o.sack[i] = (input.u32().unwrap_or(0), input.u32().unwrap_or(0));
        }
        o.sack_len = n as u8;
    }
    o
}
