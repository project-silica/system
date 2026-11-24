//! The network path under load while its driver is restarted (the M3 exit
//! test's recovery item for networking, `spec/MILESTONES.md`).
//!
//! On QEMU's user-mode network, it pings the gateway with [`DEPTH`] echo
//! requests in flight for [`RUN_NS`], answering each reply with the next
//! request, while asking the device manager to restart the interface's
//! driver every [`KILL_EVERY_NS`] (an abrupt end). The client
//! (`silica_net::client`) offers its receive buffers to the next driver and
//! sends again the frames the last one had not sent. A frame lost while no
//! driver runs is the network's to lose: a request unanswered for
//! [`RETRY_NS`] is sent again. It fails if a transmit fails, if a recovery
//! took longer than [`RECOVERY_NS`], or if, after the restarts stop, the
//! last [`CLEAN`] pings are not all answered at once.
//!
//! Built a second time as `netfault` (the package beside this one), it
//! restarts nothing: the load under which an injected device fault
//! (`silica_driver::inject`) must cost no more than a delay.
#![no_std]
#![no_main]

use silica_net::client::Interface;
use silica_net::{LINK, Op, Request};
use silica_protocols::device::manager;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::mmio::Mmio;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

const SECOND: u64 = 1_000_000_000;
const DEPTH: usize = 8;
const RUN_NS: u64 = 3 * SECOND;
const KILL_EVERY_NS: u64 = 200_000_000;
/// Whether this build restarts the driver (`netload`) or not (`netfault`).
const KILL: bool = !matches!(env!("CARGO_BIN_NAME").as_bytes(), b"netfault");
const RECOVERY_NS: u64 = 250_000_000;
const RETRY_NS: u64 = 100_000_000;
/// Pings after the restarts stop, every one of which must be answered.
const CLEAN: u32 = 100;
const BUFFERS: u64 = 32;
const BUFFER: u32 = 2048;
/// Frames to send are built from here, one 128-byte place per request in flight.
const OUT: u32 = 64 * 1024;
const SENT: u64 = 1 << 32;
const ME: [u8; 4] = [10, 0, 2, 15];
const GATEWAY: [u8; 4] = [10, 0, 2, 2];

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => {
            println!("{} OK", if KILL { "NETLOAD" } else { "NETFAULT" });
            0
        }
        Err(e) => {
            println!("ERROR: {}: {e}", env!("CARGO_BIN_NAME"));
            1
        }
    }
}

fn checksum(m: &Mmio, at: usize, len: usize) -> u16 {
    let mut sum = 0u32;
    for i in (0..len).step_by(2) {
        sum += (m.read8(at + i) as u32) << 8 | if i + 1 < len { m.read8(at + i + 1) as u32 } else { 0 };
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

struct Load {
    nic: Interface,
    m: Mmio,
    mac: [u8; 6],
    gateway: [u8; 6],
    tx: u64,
}

impl Load {
    fn put(&self, at: usize, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.m.write8(at + i, *b);
        }
    }

    fn offer(&mut self, tag: u64) -> Result<(), &'static str> {
        let r = Request { op: Op::Receive, memory: 0, offset: (tag as u32 - 1) * BUFFER, length: BUFFER, tag };
        self.nic.submit(&r).map_err(|_| "cannot offer a receive buffer")
    }

    /// Send echo request `seq` from place `slot`.
    fn ping(&mut self, slot: usize, seq: u16) -> Result<(), &'static str> {
        let o = OUT as usize + slot * 128;
        self.put(o, &self.gateway);
        self.put(o + 6, &self.mac);
        self.put(o + 12, &[0x08, 0x00, 0x45, 0, 0, 28, (seq >> 8) as u8, seq as u8, 0, 0, 64, 1, 0, 0]);
        self.put(o + 26, &ME);
        self.put(o + 30, &GATEWAY);
        let sum = checksum(&self.m, o + 14, 20);
        self.put(o + 24, &sum.to_be_bytes());
        self.put(o + 34, &[8, 0, 0, 0, 0x10, 0xAD, (seq >> 8) as u8, seq as u8]);
        let sum = checksum(&self.m, o + 34, 8);
        self.put(o + 36, &sum.to_be_bytes());
        self.tx += 1;
        let r = Request { op: Op::Transmit, memory: 0, offset: o as u32, length: 60, tag: SENT + self.tx };
        self.nic.submit(&r).map_err(|_| "cannot send")?;
        self.nic.kick();
        Ok(())
    }
}

fn run() -> Result<(), &'static str> {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(Cap(slots::FIRST_GRANT)));
    let deadline = silica_rt::clock().now() + 10 * SECOND;
    let id = loop {
        let listed = devices.list(manager::Class::Network).map_err(|_| "the device manager does not answer")?;
        if let Some(d) = listed.devices.iter().next() {
            break d.id;
        }
        if silica_rt::clock().now() > deadline {
            return Err("no network interface has a driver after 10 s");
        }
        silica_rt::sys::yield_now();
    };
    let mut nic = Interface::open(Cap(slots::FIRST_GRANT), id).map_err(|_| "cannot open the interface")?;
    let info = nic.info().map_err(|_| "no info")?;
    if info.receive_bytes > BUFFER {
        return Err("the interface needs larger receive buffers than netload offers");
    }
    let a = info.address.to_le_bytes();
    let memory = Memory::new(17).map_err(|_| "no memory")?;
    nic.add_memory(0, &memory, true).map_err(|_| "cannot register memory")?;
    let mut l = Load { nic, m: memory.shared(), mac: [a[0], a[1], a[2], a[3], a[4], a[5]], gateway: [0; 6], tx: 0 };
    for tag in 1..=BUFFERS {
        l.offer(tag)?;
    }
    // The gateway's address, by ARP.
    let o = OUT as usize;
    l.put(o, &[0xFF; 6]);
    l.put(o + 6, &l.mac);
    l.put(o + 12, &[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    l.put(o + 22, &l.mac);
    l.put(o + 28, &ME);
    l.put(o + 32, &[0; 6]);
    l.put(o + 38, &GATEWAY);
    l.tx += 1;
    l.nic.submit(&Request { op: Op::Transmit, memory: 0, offset: OUT, length: 60, tag: SENT + l.tx }).map_err(|_| "cannot send")?;
    l.nic.kick();
    let clock = silica_rt::clock();
    loop {
        let c = l.nic.wait(Some(clock.now() + 5 * SECOND)).map_err(|_| "no answer to ARP")?;
        if c.tag == LINK || c.tag > SENT {
            continue;
        }
        let at = (c.tag as usize - 1) * BUFFER as usize;
        let f: Vec<u8> = (0..42).map(|i| l.m.read8(at + i)).collect();
        l.offer(c.tag)?;
        l.nic.kick();
        if c.result.is_ok_and(|n| n >= 42) && f[12..14] == [0x08, 0x06] && f[20..22] == [0, 2] && f[28..32] == GATEWAY {
            l.gateway.copy_from_slice(&f[22..28]);
            break;
        }
    }

    // The load: DEPTH pings in flight, each answered by the next.
    let mut flight: Vec<Option<(u16, u64)>> = (0..DEPTH).map(|_| None).collect();
    let (mut seq, mut answered, mut resent) = (0u16, 0u64, 0u64);
    let (start, mut next_kill, mut restarts, mut worst) = (clock.now(), clock.now() + KILL_EVERY_NS, 0u32, 0u64);
    let mut clean = 0u32;
    // After the last restart, a recovery's time; then every ping counts.
    let settled = start + RUN_NS + RECOVERY_NS;
    while clock.now() < settled || clean < CLEAN {
        let now = clock.now();
        let killing = now < settled;
        if KILL && now < start + RUN_NS && now >= next_kill {
            devices.restart(id).map_err(|_| "the device manager would not restart the driver")?;
            restarts += 1;
            next_kill = now + KILL_EVERY_NS;
        }
        for (slot, f) in flight.iter_mut().enumerate() {
            let due = match f {
                None => true,
                Some((_, t)) => now > *t + RETRY_NS,
            };
            if due {
                if f.is_some() {
                    resent += 1;
                    if !killing {
                        return Err("a ping went unanswered after the restarts stopped");
                    }
                }
                seq = seq.wrapping_add(1);
                *f = Some((seq, now));
                l.ping(slot, seq)?;
            }
        }
        let c = match l.nic.wait(Some(now + RETRY_NS)) {
            Ok(c) => c,
            Err(silica_net::client::Error::Timeout) => continue,
            Err(_) => return Err("the interface is gone"),
        };
        if let Some(r) = l.nic.take_recovery() {
            worst = worst.max(r.total);
            if r.total > RECOVERY_NS {
                // Where it went: until the next driver took the connection
                // (the device manager restarting it, and its start-up), and
                // from there to the first answer.
                println!(
                    "netload: a recovery took {} ms: {} ms until the next driver took the connection ({} tries), {} ms from there to the first completion",
                    r.total / 1_000_000,
                    r.reconnecting / 1_000_000,
                    r.tries,
                    (r.total - r.reconnecting) / 1_000_000
                );
                return Err("a recovery took longer than 250 ms");
            }
        }
        if c.tag == LINK {
            continue;
        }
        if c.tag > SENT {
            c.result.map_err(|_| "a transmit failed")?;
            continue;
        }
        let n = c.result.map_err(|_| "a receive failed")? as usize;
        let at = (c.tag as usize - 1) * BUFFER as usize;
        let f: Vec<u8> = (0..n.min(42)).map(|i| l.m.read8(at + i)).collect();
        l.offer(c.tag)?;
        l.nic.kick();
        if n < 42 || f[12..14] != [0x08, 0x00] || f[23] != 1 || f[34] != 0 || f[38..40] != [0x10, 0xAD] {
            continue;
        }
        let got = u16::from_be_bytes([f[40], f[41]]);
        if let Some(slot) = flight.iter().position(|x| x.is_some_and(|(s, _)| s == got)) {
            flight[slot] = None;
            answered += 1;
            if clock.now() >= settled {
                clean += 1;
            }
        }
    }
    println!("netload: {answered} pings answered, {resent} sent again, {restarts} restarts, the slowest recovery {} ms", worst / 1_000_000);
    if KILL && restarts < 10 {
        return Err("the driver was restarted fewer than 10 times");
    }
    Ok(())
}
