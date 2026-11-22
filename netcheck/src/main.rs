//! Checks every network interface the device manager has a driver for,
//! against QEMU's user-mode network (the interface is 10.0.2.15 there and
//! the gateway 10.0.2.2): an ARP request for the gateway must be answered,
//! then ICMP echo requests to it. The frames are built by hand, with no
//! network stack: this is the driver's and the data path's test, sending
//! from and receiving into the program's own memory. Prints `TEST
//! <driver>.<name> PASS` for each check and the round trip of a ping as a
//! `BENCH` line (the user-mode network's, not a gate: it answers in the
//! emulator's own time).
//!
//! Where the host's benchmark echo answers (`os/bench/net/echo.c`, on a tap
//! interface: frames of EtherType 0x88B5 come back, 0x88B6 are dropped),
//! it then measures what `tools/bench.sh` compares with Linux: the round
//! trip of a 60-byte frame (`net_rtt`, median and p99 of 20,000 after 2,000
//! to warm up), and how many 1514-byte frames a second the interface sends
//! with 128 in flight (`net_tx`). On the user-mode network there is no echo,
//! and no benchmark.

#![no_std]
#![no_main]

use silica_net::client::Interface;
use silica_net::{Completion, LINK, Op, Request};
use silica_protocols::device::manager;
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::mmio::Mmio;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

const SECOND: u64 = 1_000_000_000;
/// Receive buffers kept offered, each `BUFFER` bytes, at the start of memory.
const BUFFERS: u64 = 16;
const BUFFER: u32 = 2048;
/// Where frames to send are built.
const OUT: u32 = 48 * 1024;
const ME: [u8; 4] = [10, 0, 2, 15];
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
/// Tags of transmits: from here up (receives are 1 to `BUFFERS`).
const SENT: u64 = 1 << 32;
/// The benchmark echo's EtherTypes: sent back, and dropped.
const ECHO: [u8; 2] = [0x88, 0xB5];
const SINK: [u8; 2] = [0x88, 0xB6];

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            println!("ERROR: netcheck: {e}");
            1
        }
    }
}

fn why<E: core::fmt::Debug>(e: E, what: &'static str) -> &'static str {
    println!("netcheck: {what}: {e:?}");
    what
}

fn interfaces(devices: &mut manager::Client<Channel, Handle>) -> Result<Vec<(u32, String)>, &'static str> {
    let deadline = silica_rt::clock().now() + 10 * SECOND;
    loop {
        let listed = devices.list(manager::Class::Network).map_err(|e| why(e, "the device manager does not answer"))?;
        let found: Vec<_> = listed.devices.iter().map(|d| (d.id, String::from(d.driver))).collect();
        if !found.is_empty() {
            return Ok(found);
        }
        if silica_rt::clock().now() > deadline {
            return Err("no network interface has a driver after 10 s");
        }
        silica_rt::sys::yield_now();
    }
}

fn run() -> Result<(), &'static str> {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT)));
    for (id, driver) in interfaces(&mut devices)? {
        println!("netcheck: interface {id:#x}, driven by {driver}");
        let nic = Interface::open(Cap(slots::FIRST_GRANT), id).map_err(|e| why(e, "cannot open the interface"))?;
        check(nic, &driver)?;
    }
    Ok(())
}

/// The internet checksum of `bytes` in `m` from `at`.
fn checksum(m: &Mmio, at: usize, len: usize) -> u16 {
    let mut sum = 0u32;
    for i in (0..len).step_by(2) {
        let hi = m.read8(at + i) as u32;
        let lo = if i + 1 < len { m.read8(at + i + 1) as u32 } else { 0 };
        sum += hi << 8 | lo;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

struct Check {
    nic: Interface,
    m: Mmio,
    mac: [u8; 6],
    sent: u64,
}

impl Check {
    fn put(&self, at: usize, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.m.write8(at + i, *b);
        }
    }

    fn get(&self, at: usize, n: usize) -> Vec<u8> {
        (0..n).map(|i| self.m.read8(at + i)).collect()
    }

    fn offer(&mut self, tag: u64) -> Result<(), &'static str> {
        let r = Request { op: Op::Receive, memory: 0, offset: (tag as u32 - 1) * BUFFER, length: BUFFER, tag };
        self.nic.submit(&r).map_err(|e| why(e, "cannot offer a receive buffer"))
    }

    /// Send the `len` bytes built at `OUT`.
    fn send(&mut self, len: u32) -> Result<(), &'static str> {
        self.sent += 1;
        let r = Request { op: Op::Transmit, memory: 0, offset: OUT, length: len.max(60), tag: SENT + self.sent };
        self.nic.submit(&r).map_err(|e| why(e, "cannot send"))?;
        self.nic.kick();
        Ok(())
    }

    /// Wait for a received frame `wanted` accepts (it is given the frame's
    /// offset and length), offering every buffer again; until `deadline`.
    fn receive(&mut self, deadline: u64, wanted: &mut dyn FnMut(&Check, usize, usize) -> bool) -> Result<(), &'static str> {
        loop {
            let c: Completion = self.nic.wait(Some(deadline)).map_err(|e| why(e, "nothing arrived in time"))?;
            if c.tag == LINK || c.tag >= SENT {
                if let Err(e) = c.result {
                    return Err(why(e, "a frame could not be sent"));
                }
                continue;
            }
            let n = c.result.map_err(|e| why(e, "a receive failed"))? as usize;
            let at = (c.tag as usize - 1) * BUFFER as usize;
            let ok = wanted(self, at, n);
            self.offer(c.tag)?;
            self.nic.kick();
            if ok {
                return Ok(());
            }
        }
    }
}

fn check(mut nic: Interface, driver: &str) -> Result<(), &'static str> {
    let pass = |name: &str| println!("TEST {driver}.{name} PASS");
    let info = nic.info().map_err(|e| why(e, "no info"))?;
    let a = info.address.to_le_bytes();
    let mac = [a[0], a[1], a[2], a[3], a[4], a[5]];
    println!("netcheck: MTU {}, link {}", info.mtu, if info.link_up { "up" } else { "down" });
    let memory = Memory::new(16).map_err(|e| why(e, "no memory"))?;
    nic.add_memory(0, &memory, true).map_err(|e| why(e, "cannot register memory with the driver"))?;
    let mut c = Check { nic, m: memory.shared(), mac, sent: 0 };
    for tag in 1..=BUFFERS {
        c.offer(tag)?;
    }
    c.nic.kick();
    let o = OUT as usize;

    // ARP: who has the gateway's address? The answer names its Ethernet address.
    c.put(o, &[0xFF; 6]);
    c.put(o + 6, &c.mac);
    c.put(o + 12, &[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    c.put(o + 22, &c.mac);
    c.put(o + 28, &ME);
    c.put(o + 32, &[0; 6]);
    c.put(o + 38, &GATEWAY);
    c.put(o + 42, &[0; 18]);
    c.send(42)?;
    let mut gateway = [0u8; 6];
    let answered = c.receive(silica_rt::clock().now() + 2 * SECOND, &mut |c, at, n| {
        let f = c.get(at, n.min(42));
        let reply = n >= 42 && f[12..14] == [0x08, 0x06] && f[20..22] == [0, 2] && f[28..32] == GATEWAY && f[0..6] == c.mac;
        if reply {
            gateway.copy_from_slice(&f[22..28]);
        }
        reply
    });
    if answered.is_err() {
        // Not the user-mode network (a tap): no gateway, no ARP or ping.
        println!("netcheck: no gateway answers on this network");
        return bench(&mut c, driver);
    }
    println!(
        "netcheck: the gateway is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        gateway[0], gateway[1], gateway[2], gateway[3], gateway[4], gateway[5]
    );
    pass("arp");

    // Ping the gateway: ICMP echo requests, each answered with its own
    // sequence number.
    let clock = silica_rt::clock();
    let mut times = Vec::new();
    for seq in 0..200u16 {
        c.put(o, &gateway);
        c.put(o + 6, &c.mac);
        c.put(o + 12, &[0x08, 0x00]);
        // IPv4: 20 bytes of header, then 8 of ICMP and 32 of payload.
        c.put(o + 14, &[0x45, 0, 0, 60, (seq >> 8) as u8, seq as u8, 0, 0, 64, 1, 0, 0]);
        c.put(o + 26, &ME);
        c.put(o + 30, &GATEWAY);
        let sum = checksum(&c.m, o + 14, 20);
        c.put(o + 24, &sum.to_be_bytes());
        c.put(o + 34, &[8, 0, 0, 0, 0x51, 0x1C, (seq >> 8) as u8, seq as u8]);
        for i in 0..32 {
            c.m.write8(o + 42 + i, i as u8);
        }
        let sum = checksum(&c.m, o + 34, 40);
        c.put(o + 36, &sum.to_be_bytes());
        let t = clock.now();
        c.send(74)?;
        c.receive(clock.now() + 5 * SECOND, &mut |c, at, n| {
            let f = c.get(at, n.min(74));
            n >= 74
                && f[12..14] == [0x08, 0x00]
                && f[23] == 1
                && f[26..30] == GATEWAY
                && f[34] == 0
                && f[38..40] == [0x51, 0x1C]
                && f[40..42] == [(seq >> 8) as u8, seq as u8]
                && (0..32).all(|i| f[42 + i] == i as u8)
        })?;
        times.push(clock.now() - t);
    }
    pass("ping");
    times.sort_unstable();
    println!("BENCH {driver}_ping_user_mode {} ns", times[times.len() / 2]);
    bench(&mut c, driver)
}

/// The benchmarks, where the host's echo answers.
fn bench(c: &mut Check, driver: &str) -> Result<(), &'static str> {
    let o = OUT as usize;
    let clock = silica_rt::clock();
    // virtio-net's are the gated `net_*`; another driver's are named after it.
    let prefix = if driver == "virtio-net" { "net" } else { driver };
    let echo = |c: &mut Check, seq: u32| -> Result<(), &'static str> {
        c.put(o, &[0xFF; 6]);
        c.put(o + 6, &c.mac);
        c.put(o + 12, &ECHO);
        c.put(o + 14, &seq.to_le_bytes());
        c.send(60)
    };
    let back = |seq: u32| {
        move |c: &Check, at: usize, n: usize| -> bool {
            let f = c.get(at, n.min(18));
            n >= 18 && f[0..6] == c.mac && f[12..14] == ECHO && f[14..18] == seq.to_le_bytes()
        }
    };
    echo(c, 0)?;
    if c.receive(clock.now() + SECOND / 4, &mut back(0)).is_err() {
        println!("netcheck: no benchmark echo on this network");
        return Ok(());
    }
    let mut times = Vec::new();
    for seq in 1..=22_000u32 {
        let t = clock.now();
        echo(c, seq)?;
        c.receive(clock.now() + SECOND, &mut back(seq))?;
        if seq > 2000 {
            times.push(clock.now() - t);
        }
    }
    times.sort_unstable();
    println!("BENCH {prefix}_rtt {} ns", times[times.len() / 2]);
    println!("BENCH {prefix}_rtt_p99 {} ns", times[times.len() * 99 / 100]);

    // Transmit: the same 1514-byte frame, 128 in flight, for a second.
    c.put(o, &[0xFF; 6]);
    c.put(o + 6, &c.mac);
    c.put(o + 12, &SINK);
    let (mut sent, mut done) = (0u64, 0u64);
    let start = clock.now();
    let end = start + SECOND;
    while clock.now() < end || done < sent {
        while sent - done < 128 && clock.now() < end {
            sent += 1;
            let r = Request { op: Op::Transmit, memory: 0, offset: OUT, length: 1514, tag: SENT + c.sent + sent };
            c.nic.submit(&r).map_err(|e| why(e, "cannot send"))?;
        }
        c.nic.kick();
        let got = c.nic.wait(Some(end + SECOND)).map_err(|e| why(e, "a frame was not sent in time"))?;
        if got.tag > SENT + c.sent {
            got.result.map_err(|e| why(e, "a frame could not be sent"))?;
            done += 1;
        } else if got.tag <= BUFFERS {
            c.offer(got.tag)?;
        }
    }
    let ns = clock.now() - start;
    println!("BENCH {prefix}_tx {} frames/s", done * SECOND / ns.max(1));
    Ok(())
}
