//! The network stack, first slice: it takes the machine's network interface
//! (waiting for one to have a driver, without waking until one does), gets
//! it an IPv4 address by DHCP and keeps it (renewing, rebinding, starting
//! over when it is lost), answers ARP for that address and pings to it,
//! and checks once bound that the router answers a ping.
//!
//! Frames arrive in buffers the device writes. Each is copied once into the
//! stack's own memory and parsed there (`silica_inet`): the device, which a
//! driver the stack does not trust controls, may go on writing the buffer,
//! and reading it in place twice could see two different packets. What is
//! malformed or not for this host is dropped and counted by reason.
//!
//! It sets the wall clock from a time server (SNTP: the `ntp` boot option,
//! `netd.ntp=<address>[:<port>]`, else the server the lease names), when
//! bound and then every 64 s doubling to 1,024 s; an answer is taken only
//! from that server, to the port asked from, echoing the question's time.
//!
//! It provides TCP to programs (`silica.net.Tcp`, the `tcp` module), in the
//! same thread and the same wait as its interface: one notification, the
//! interface's bits below `tcp::FIRST_BIT` and the programs' above.
//!
//! What it does not do yet (spec/MILESTONES.md, M4): UDP for programs,
//! IPv6, more than one interface, reassembly; a program's call made before
//! the machine has an interface is answered once it has one.

#![no_std]
#![no_main]

use silica_idl_rt::CapList;
use silica_inet::dhcp_client::{self, Client, Event, Lease, To};
use silica_inet::{Ipv4, Mac, Malformed, arp, dhcp, ether, icmp, ipv4, ntp, udp};
use silica_net::client::Interface;
use silica_net::{Completion, LINK, Op, Request};
use silica_protocols::device::manager;
use silica_protocols::net::tcp as proto;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::Events;
use silica_rt::ipc::{Channel, Handle, free_slot, release_slot};
use silica_rt::mem::{self, Memory, Object};
use silica_rt::mmio::Mmio;
use silica_rt::sys::{self, Cap, ObjectType, Rights, Wait};
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

mod tcp;

const SECOND: u64 = 1_000_000_000;
/// The endpoint it provides `silica.net.Tcp` on: its first grant; the
/// device manager: its second.
const ENDPOINT: Cap = Cap(slots::FIRST_GRANT);
const DEVICES: Cap = Cap(slots::FIRST_GRANT + 1);
/// Receive buffers kept offered (tags 1 to `BUFFERS`), each `BUFFER` bytes
/// from the start of the memory; then `SLOTS` transmit buffers.
const BUFFERS: u64 = 16;
const BUFFER: usize = 2048;
const SLOTS: usize = 8;
/// Transmit tags: `SENT + slot`.
const SENT: u64 = 1 << 32;
/// Neighbours remembered, and for how long.
const NEIGHBOURS: usize = 16;
const NEIGHBOUR_LIFE: u64 = 300 * SECOND;
/// How long an address is asked for before what waits for it is dropped.
const RESOLVE_WAIT: u64 = 3 * SECOND;

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: netd: {e}");
            1
        }
    }
}

/// A copy of `cap` in a free slot of this program, with `rights`, to hand
/// to another program in a call.
fn lend(cap: Cap, rights: Rights) -> Result<Handle, &'static str> {
    let slot = free_slot().ok_or("no free capability slot")?;
    if sys::cap_derive(slots::SPACE, slot, cap, rights, 0).is_err() {
        release_slot(slot);
        return Err("cannot lend a capability");
    }
    Ok(Handle::new(Cap(slot)))
}

/// The device manager, watched for network interfaces gaining or losing
/// their drivers.
struct Devices {
    client: manager::Client<Channel, Handle>,
    changed: Object,
}

impl Devices {
    fn new() -> Result<Devices, &'static str> {
        let mut client = manager::Client::<Channel, Handle>::from(Channel::new(DEVICES));
        let changed = Object::new(ObjectType::Notification, 0).map_err(|_| "no memory for a notification")?;
        client.watch(manager::Class::Network, lend(changed.cap(), Rights::WRITE)?).map_err(|_| "the device manager does not answer")?;
        Ok(Devices { client, changed })
    }

    /// The first network interface with a driver, waited for (no wake-ups
    /// while there is none).
    fn interface(&mut self) -> Result<u32, &'static str> {
        let mut said = false;
        loop {
            let listed = self.client.list(manager::Class::Network).map_err(|_| "the device manager does not answer")?;
            if let Some(d) = listed.devices.iter().next() {
                println!("netd: interface {:#x}, driven by {}", d.id, d.driver);
                return Ok(d.id);
            }
            if !said {
                println!("netd: no network interface yet; waiting for one");
                said = true;
            }
            self.wait()?;
        }
    }

    /// Until an interface gains or loses a driver.
    fn wait(&mut self) -> Result<(), &'static str> {
        sys::recv(self.changed.cap(), Wait::Forever).map(|_| ()).map_err(|_| "cannot wait for an interface")
    }
}

fn run() -> Result<core::convert::Infallible, &'static str> {
    let mut devices = Devices::new()?;
    loop {
        let id = devices.interface()?;
        // An interface whose driver cannot be talked to (failing, or not
        // keeping to its protocol) is not the stack's to give up on: the
        // device manager restarts a failing driver, and a change is waited
        // for before the interface is tried again.
        let Err(why) = use_interface(id);
        println!("netd: interface {id:#x}: {why}; waiting for its driver to change");
        devices.wait()?;
    }
}

/// Run the stack on the interface `id` until it cannot be used.
fn use_interface(id: u32) -> Result<core::convert::Infallible, &'static str> {
    // One notification for everything: the interface's bits, then the
    // programs' (`tcp`).
    let note = Object::new(ObjectType::Notification, 0).map_err(|_| "no memory for a notification")?;
    let mut nic = Interface::open_on(DEVICES, id, note.cap(), 0).map_err(|e| match e {
        silica_net::client::Error::Refused(silica_queue::Refused::Busy) => "another program has it",
        silica_net::client::Error::Gone => "its driver ended",
        _ => "it cannot be opened (its driver does not keep to the protocol)",
    })?;
    let info = nic.info().map_err(|_| "the interface says nothing about itself")?;
    let a = info.address.to_le_bytes();
    let mac = Mac([a[0], a[1], a[2], a[3], a[4], a[5]]);
    println!("netd: {mac}, MTU {}, link {}", info.mtu, if info.link_up { "up" } else { "down" });
    if info.receive_bytes as usize > BUFFER {
        println!("netd: the interface needs receive buffers of {} bytes; netd's are {BUFFER}", info.receive_bytes);
        return Err("the interface needs larger receive buffers than netd offers");
    }
    let memory = Memory::new(16).map_err(|_| "no memory for frames")?;
    nic.add_memory(0, &memory, true).map_err(|_| "cannot register memory with the driver")?;
    let now = silica_rt::clock().now();
    // The lease an earlier instance held on this boot, if it is this
    // interface's and has not ended: held again at once (`Client::resume`).
    let keep = mem::peer(slots::KEEP, 12, Rights(Rights::READ.0 | Rights::WRITE.0)).ok();
    let kept = keep.as_ref().and_then(|k| kept_lease(k, mac));
    let dhcp = match kept {
        Some(l) => Client::resume(mac, l, now),
        None => Client::new(mac, now),
    };
    let lease = dhcp.lease().copied();
    let clock = mem::peer(slots::TIME, 12, Rights(Rights::READ.0 | Rights::WRITE.0)).ok();
    // Connection records after the lease (`tcp`): the last stack's, reset,
    // if they are in this stack's layout (their mark just before them).
    let records = keep.as_ref().and_then(|k| k.part(128, 4096 - 128));
    let resets = match (&keep, &records) {
        (Some(k), Some(r)) if k.read64(120) == tcp::RECORDS_MARK => tcp::kept_connections(r),
        (Some(k), Some(r)) => {
            tcp::clear_records(r);
            k.write64(120, tcp::RECORDS_MARK);
            Vec::new()
        }
        _ => Vec::new(),
    };
    let mut s = Stack {
        nic,
        m: memory.shared(),
        mac,
        free: (1 << SLOTS) - 1,
        dhcp,
        lease,
        keep,
        neighbours: [Neighbour::EMPTY; NEIGHBOURS],
        held: None,
        ip_id: (silica_rt::random::u64() & 0xFFFF) as u16,
        frame: [0; BUFFER],
        out: [0; BUFFER],
        probe: None,
        dropped: Dropped::default(),
        tcp: Some(tcp::Tcp::new(note.cap(), info.mtu.min(1500) as u16, records)),
        resets,
        time: TimeClient::new(clock, now),
        caller: 0,
        more: true,
    };
    for tag in 1..=BUFFERS {
        s.offer(tag)?;
    }
    if let Some(l) = lease {
        println!(
            "netd: {}/{} kept from before it started again; {} connections of the stack before it to reset",
            l.address,
            l.prefix,
            s.resets.len()
        );
        // Its router's Ethernet address, before the first answer needs it.
        if let Some(r) = l.router {
            s.ping(now, r);
        }
    }
    silica_rt::ipc::serve_events(ENDPOINT, note.cap(), &mut s)
}

/// The port the time-server client asks from.
const TIME_PORT: u16 = 50123;

/// The time-server client's state (SNTP to one server).
struct TimeClient {
    /// The time page, writable (this service `sets_time`); none: no clock
    /// to set, and no question asked.
    page: Option<Mmio>,
    /// The server the boot options name (`ntp=<address>[:<port>]`).
    configured: Option<(Ipv4, u16)>,
    /// The question in flight: its transmit timestamp, and its time (ns
    /// since 1970 by this clock).
    asked: Option<(u64, u64)>,
    /// When to ask next, questions sent since the last answer, seconds
    /// between answers, and whether the clock was ever set.
    next: u64,
    tries: u32,
    poll: u64,
    set: bool,
}

impl TimeClient {
    fn new(page: Option<Mmio>, now: u64) -> TimeClient {
        let configured = silica_rt::option("ntp").and_then(|v| {
            let (a, port) = v.split_once(':').unwrap_or((v, "123"));
            Some((a.parse::<Ipv4>().ok()?, port.parse::<u16>().ok()?))
        });
        if silica_rt::option("ntp").is_some() && configured.is_none() {
            println!("ERROR: netd: the ntp option is not <address>[:<port>]");
        }
        TimeClient { page, configured, asked: None, next: now, tries: 0, poll: 64, set: false }
    }

    /// The server to ask: the configured one, else the lease's.
    fn server(&self, lease: Option<&Lease>) -> Option<(Ipv4, u16)> {
        self.configured.or_else(|| lease?.ntp.map(|a| (a, ntp::PORT)))
    }
}

/// The mark of a lease in the page kept across restarts.
const KEPT_LEASE: u64 = 0x4553_4145_4c5f_4454; // "TD_LEASE"

/// The lease an earlier instance kept in `k`, if there is one, for the
/// interface `mac`.
fn kept_lease(k: &Mmio, mac: Mac) -> Option<Lease> {
    if k.read64(0) != KEPT_LEASE {
        return None;
    }
    let m = k.read64(8).to_le_bytes();
    if m[..6] != mac.0 {
        return None;
    }
    let lo = |w: u64| Ipv4::from_u32(w as u32);
    let hi = |w: u64| Ipv4::from_u32((w >> 32) as u32);
    let (a, r, d, e) = (k.read64(16), k.read64(24), k.read64(32), k.read64(40));
    let prefix = (a >> 32) as u8;
    if prefix > 32 {
        return None;
    }
    Some(Lease {
        address: lo(a),
        prefix,
        router: ((a >> 40) & 1 != 0).then(|| lo(r)),
        dns: [lo(d), hi(d), lo(e)],
        ntp: ((k.read64(72) >> 32) & 1 != 0).then(|| lo(k.read64(72))),
        server: hi(r),
        seconds: (e >> 32) as u32,
        renew_at: k.read64(48),
        rebind_at: k.read64(56),
        expires_at: k.read64(64),
    })
}

#[derive(Clone, Copy)]
struct Neighbour {
    ip: Ipv4,
    mac: Mac,
    expires: u64,
}

impl Neighbour {
    const EMPTY: Neighbour = Neighbour { ip: Ipv4::UNSPECIFIED, mac: Mac::ZERO, expires: 0 };
}

/// A packet waiting for its next hop's Ethernet address.
struct Held {
    hop: Ipv4,
    since: u64,
    asked: u64,
    len: usize,
    packet: [u8; BUFFER],
}

/// Frames dropped, by why.
#[derive(Default)]
struct Dropped {
    malformed: [u64; 5],
    not_ours: u64,
    unresolved: u64,
    no_slot: u64,
}

impl Dropped {
    fn malformed(&mut self, m: Malformed) {
        self.malformed[m as usize] += 1;
    }
}

/// The ping to the router once bound: its sequence number and when it left.
struct Probe {
    router: Ipv4,
    sent: u64,
    until: u64,
}

struct Stack {
    nic: Interface,
    m: Mmio,
    mac: Mac,
    /// Free transmit slots, a bit each.
    free: u32,
    dhcp: Client,
    lease: Option<Lease>,
    /// The page kept across restarts (`slots::KEEP`), the lease in it.
    keep: Option<Mmio>,
    neighbours: [Neighbour; NEIGHBOURS],
    held: Option<Held>,
    ip_id: u16,
    /// The frame being read (copied out of its buffer) and the one being built.
    frame: [u8; BUFFER],
    out: [u8; BUFFER],
    probe: Option<Probe>,
    dropped: Dropped,
    /// TCP; out of its place only while it sends through the stack.
    tcp: Option<tcp::Tcp>,
    /// The badge of the call being answered.
    caller: u64,
    /// Resets owed to the peers of the last stack's connections, sent once
    /// their next hop's address is known.
    resets: Vec<tcp::Kept>,
    time: TimeClient,
    /// Work is left (a completion there, segments with no transmit slot):
    /// look again at once rather than wait.
    more: bool,
}

impl Stack {
    fn offer(&mut self, tag: u64) -> Result<(), &'static str> {
        let r = Request { op: Op::Receive, memory: 0, offset: (tag as usize - 1) as u32 * BUFFER as u32, length: BUFFER as u32, tag };
        self.nic.submit(&r).map_err(|_| "cannot offer a receive buffer")
    }

    /// Send the `len` bytes built in `out`: copied into a free transmit
    /// slot, padded to the shortest frame. With every slot busy the frame
    /// is dropped and counted (the next one is sent when one completes).
    fn transmit(&mut self, len: usize) {
        if self.free == 0 {
            self.dropped.no_slot += 1;
            return;
        }
        let slot = self.free.trailing_zeros() as usize;
        self.free &= !(1 << slot);
        let len = ether::pad(&mut self.out, len);
        let at = (BUFFERS as usize + slot) * BUFFER;
        self.m.write_bytes(at, &self.out[..len]);
        let r = Request { op: Op::Transmit, memory: 0, offset: at as u32, length: len as u32, tag: SENT + slot as u64 };
        if self.nic.submit(&r).is_err() {
            self.free |= 1 << slot;
            self.dropped.no_slot += 1;
        }
    }

    /// Everything there is to do now: timers, the interface's completions
    /// (frames in, transmit slots back), and TCP's connections. Then
    /// whether to look again before waiting.
    fn work(&mut self) {
        let now = silica_rt::clock().now();
        if now >= self.dhcp.deadline() {
            let step = self.dhcp.step(now, None, silica_rt::random::u64());
            self.dhcp_step(now, step);
        }
        self.timers(now);
        if self.nic.deadline().is_some_and(|d| d <= now) {
            self.nic.tick();
        }
        let mut tcp = self.tcp.take().expect("TCP is in its place between turns");
        tcp.on_time(now);
        self.tcp = Some(tcp);
        loop {
            let c: Completion = match self.nic.poll() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(_) => {
                    // The queue gave its driver its time to come back: the
                    // service is started again with the interface as it is.
                    println!("ERROR: netd: the interface failed");
                    silica_rt::exit(1);
                }
            };
            if c.tag == LINK {
                println!("netd: link {}", if c.result == Ok(1) { "up" } else { "down" });
                continue;
            }
            if c.tag >= SENT {
                // A failed send is the network's to lose, as a dropped frame is.
                self.free |= 1 << (c.tag - SENT);
                continue;
            }
            if let Ok(n) = c.result {
                let n = (n as usize).min(BUFFER);
                self.m.read_bytes((c.tag as usize - 1) * BUFFER, &mut self.frame[..n]);
                if self.offer(c.tag).is_err() {
                    println!("ERROR: netd: the interface takes no more receive buffers");
                    silica_rt::exit(1);
                }
                self.receive(n);
            } else if self.offer(c.tag).is_err() {
                println!("ERROR: netd: the interface takes no more receive buffers");
                silica_rt::exit(1);
            }
        }
        self.send_resets(now);
        self.ask_time(now);
        let mut tcp = self.tcp.take().expect("TCP is in its place between turns");
        let blocked = tcp.pump(now, self);
        let asleep = tcp.sleep();
        self.tcp = Some(tcp);
        self.more = (blocked && self.free != 0) || !asleep || !self.nic.sleep();
    }

    /// The soonest of what waits for a time.
    fn deadline(&self) -> u64 {
        let mut d = self.dhcp.deadline();
        if let Some(t) = self.tcp.as_ref().and_then(|t| t.deadline()) {
            d = d.min(t);
        }
        if let Some(n) = self.nic.deadline() {
            d = d.min(n);
        }
        if let Some(h) = &self.held {
            d = d.min(h.asked + SECOND).min(h.since + RESOLVE_WAIT);
        }
        if let Some(p) = &self.probe {
            d = d.min(p.until);
        }
        if self.time.server(self.lease.as_ref()).is_some() && self.time.page.is_some() {
            d = d.min(self.time.next);
        }
        d
    }

    fn timers(&mut self, now: u64) {
        if let Some(h) = &self.held {
            if now >= h.since + RESOLVE_WAIT {
                println!("netd: {} does not answer ARP; what was for it is dropped", h.hop);
                self.held = None;
                self.dropped.unresolved += 1;
            } else if now >= h.asked + SECOND {
                let hop = h.hop;
                self.ask(hop);
                if let Some(h) = self.held.as_mut() {
                    h.asked = now;
                }
            }
        }
        if let Some(p) = &self.probe
            && now >= p.until
        {
            println!("netd: the router {} does not answer a ping", p.router);
            self.probe = None;
        }
    }

    fn dhcp_step(&mut self, now: u64, step: dhcp_client::Step) {
        match step.event {
            Some(Event::Bound(l)) => {
                let dns = l.dns.iter().filter(|d| **d != Ipv4::UNSPECIFIED);
                let mut servers = silica_rt::alloc::string::String::new();
                for d in dns {
                    use core::fmt::Write;
                    let _ = write!(servers, "{}{d}", if servers.is_empty() { "" } else { ", " });
                }
                let router = l.router.map(|r| silica_rt::alloc::format!("{r}")).unwrap_or_else(|| "none".into());
                let lease = if l.seconds == u32::MAX { "for ever".into() } else { silica_rt::alloc::format!("{} s", l.seconds) };
                println!("netd: {}/{} from DHCP server {}, router {router}, DNS {servers}, lease {lease}", l.address, l.prefix, l.server);
                self.lease = Some(l);
                self.keep_lease();
                if let Some(r) = l.router {
                    self.ping(now, r);
                }
            }
            Some(Event::Renewed(l)) => {
                self.lease = Some(l);
                self.keep_lease();
            }
            Some(Event::Lost) => {
                if let Some(l) = self.lease.take() {
                    println!("netd: the lease of {} ended; asking again", l.address);
                }
                self.keep_lease();
            }
            None => {}
        }
        if let Some(m) = step.send {
            self.send_dhcp(m);
        }
    }

    /// Reset the connections the last stack had (`tcp::kept_connections`),
    /// once the lease is held and the first hop's Ethernet address known.
    fn send_resets(&mut self, now: u64) {
        let Some(l) = self.lease else { return };
        if self.resets.is_empty() {
            return;
        }
        let hop = |r: Ipv4| if l.address.same_subnet(r, l.prefix) { Some(r) } else { l.router };
        let mut sent = 0;
        while let Some(k) = self.resets.last() {
            let Some(h) = hop(k.remote) else { break };
            if self.neighbour(h, now).is_none() || self.free == 0 {
                break;
            }
            let k = self.resets.pop().expect("looked at");
            let header = silica_inet::tcp::Header {
                src_port: k.local_port,
                dst_port: k.remote_port,
                seq: k.sequence,
                ack: k.acknowledges,
                flags: silica_inet::tcp::RST | silica_inet::tcp::ACK,
                window: 0,
            };
            let mut seg = [0u8; 64];
            if let Some(n) = silica_inet::tcp::build(&mut seg, l.address, k.remote, &header, &silica_inet::tcp::Options::default(), &[]) {
                self.send_ip(k.remote, ipv4::TCP, &seg[..n]);
                sent += 1;
            }
        }
        if sent > 0 && self.resets.is_empty() {
            println!("netd: the connections of the stack before it are reset");
        }
    }

    /// Ask the time server, when it is time to (and the clock is ours to set).
    fn ask_time(&mut self, now: u64) {
        let Some((server, port)) = self.time.server(self.lease.as_ref()) else { return };
        let Some(page) = self.time.page else { return };
        if now < self.time.next {
            return;
        }
        // The question's time, by this clock (the firmware's, or none yet:
        // the offset is relative to whatever it says).
        let (offset, _) = silica_rt::time::read(&page);
        let t1 = offset.wrapping_add(now);
        let transmit = ntp::from_unix_ns(t1);
        let mut q = [0u8; ntp::LEN];
        ntp::request(&mut q, transmit);
        self.time.asked = Some((transmit, t1));
        self.time.tries += 1;
        self.time.next = if self.time.tries < 3 { now + 2 * SECOND } else { now + self.time.poll * SECOND };
        if self.time.tries >= 3 {
            self.time.tries = 0;
        }
        self.send_udp(server, TIME_PORT, port, &q);
    }

    /// The time server answered: set the clock if it answers our question.
    fn time_answer(&mut self, now: u64, r: &ntp::Reply) {
        let Some(page) = self.time.page else { return };
        let Some((transmit, t1)) = self.time.asked else { return };
        // Only the answer to the question in flight: a blind sender does
        // not know its time.
        if r.originate != transmit {
            return;
        }
        let (Some(t2), Some(t3)) = (ntp::to_unix_ns(r.receive), ntp::to_unix_ns(r.transmit)) else { return };
        self.time.asked = None;
        let (offset, _) = silica_rt::time::read(&page);
        let t4 = offset.wrapping_add(now);
        let (shift, delay) = ntp::offset(t1, t2, t3, t4);
        let wall = t4.wrapping_add_signed(shift);
        silica_rt::time::set(&page, wall, now, silica_rt::time::Source::Network);
        if !self.time.set || shift.unsigned_abs() > SECOND {
            let (server, port) = self.time.server(self.lease.as_ref()).unwrap_or((Ipv4::UNSPECIFIED, 0));
            println!(
                "netd: the wall clock is {} from {server}:{port} (moved {:+} ms, round trip {} us)",
                silica_rt::time::Civil::from_unix(wall / SECOND),
                shift / 1_000_000,
                delay / 1000
            );
        }
        self.time.set = true;
        self.time.tries = 0;
        self.time.next = now + self.time.poll * SECOND;
        self.time.poll = (self.time.poll * 2).min(1024);
    }

    /// Put the lease held (or none) in the page kept across restarts.
    fn keep_lease(&mut self) {
        let Some(k) = self.keep else { return };
        // The mark first out and last in: a lease half written is no lease.
        k.write64(0, 0);
        let Some(l) = self.lease else { return };
        let ip = |a: Ipv4| a.to_u32() as u64;
        k.write64(8, u64::from_le_bytes([self.mac.0[0], self.mac.0[1], self.mac.0[2], self.mac.0[3], self.mac.0[4], self.mac.0[5], 0, 0]));
        k.write64(16, ip(l.address) | (l.prefix as u64) << 32 | (l.router.is_some() as u64) << 40);
        k.write64(24, ip(l.router.unwrap_or(Ipv4::UNSPECIFIED)) | ip(l.server) << 32);
        k.write64(32, ip(l.dns[0]) | ip(l.dns[1]) << 32);
        k.write64(40, ip(l.dns[2]) | (l.seconds as u64) << 32);
        k.write64(48, l.renew_at);
        k.write64(56, l.rebind_at);
        k.write64(64, l.expires_at);
        k.write64(72, ip(l.ntp.unwrap_or(Ipv4::UNSPECIFIED)) | (l.ntp.is_some() as u64) << 32);
        k.write64(0, KEPT_LEASE);
    }

    fn send_dhcp(&mut self, m: dhcp_client::Send) {
        let mut msg = [0u8; 300];
        let Some(n) = dhcp::build(&mut msg, m.ask, self.mac, m.xid, m.secs) else { return };
        match m.to {
            To::Broadcast => {
                // From the address held, when rebinding; from none before.
                let src = match m.ask {
                    dhcp::Ask::Renew { address } => address,
                    _ => Ipv4::UNSPECIFIED,
                };
                self.send_udp_raw(Mac::BROADCAST, src, Ipv4::BROADCAST, dhcp::CLIENT_PORT, dhcp::SERVER_PORT, &msg[..n]);
            }
            To::Server(server) => self.send_udp(server, dhcp::CLIENT_PORT, dhcp::SERVER_PORT, &msg[..n]),
        }
    }

    /// A UDP datagram straight to an Ethernet address (DHCP before the
    /// client has an address, and broadcasts).
    fn send_udp_raw(&mut self, dst_mac: Mac, src: Ipv4, dst: Ipv4, src_port: u16, dst_port: u16, data: &[u8]) {
        let mac = self.mac;
        let id = self.next_id();
        let Some(payload) = ether::header(&mut self.out, dst_mac, mac, ether::IPV4) else { return };
        let Some(seg) = ipv4::header(payload, src, dst, ipv4::UDP, id, udp::HEADER + data.len()) else { return };
        if udp::build(seg, src, src_port, dst, dst_port, data).is_none() {
            return;
        }
        self.transmit(ether::HEADER + ipv4::HEADER + udp::HEADER + data.len());
    }

    /// A UDP datagram from the leased address, routed.
    fn send_udp(&mut self, dst: Ipv4, src_port: u16, dst_port: u16, data: &[u8]) {
        let Some(l) = self.lease else { return };
        let mut seg = [0u8; BUFFER];
        let Some(n) = udp::build(&mut seg, l.address, src_port, dst, dst_port, data) else { return };
        self.send_ip(dst, ipv4::UDP, &seg[..n]);
    }

    fn next_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }

    /// An IPv4 packet from the leased address to `dst`, through the router
    /// when `dst` is off the subnet; held while its next hop is resolved.
    fn send_ip(&mut self, dst: Ipv4, protocol: u8, payload: &[u8]) {
        let Some(l) = self.lease else { return };
        let hop = if l.address.same_subnet(dst, l.prefix) {
            dst
        } else if let Some(r) = l.router {
            r
        } else {
            self.dropped.unresolved += 1;
            return;
        };
        let id = self.next_id();
        let mut packet = [0u8; BUFFER];
        let Some(p) = ipv4::header(&mut packet, l.address, dst, protocol, id, payload.len()) else { return };
        p.copy_from_slice(payload);
        let len = ipv4::HEADER + payload.len();
        let now = silica_rt::clock().now();
        match self.neighbour(hop, now) {
            Some(mac) => self.frame_out(mac, &packet[..len]),
            None => {
                // One packet waits for an address at a time: a newer one
                // replaces it (what is sent before the router answers is
                // DHCP's and a ping's, each sent again if lost).
                if self.held.is_some() {
                    self.dropped.unresolved += 1;
                }
                self.held = Some(Held { hop, since: now, asked: now, len, packet });
                self.ask(hop);
            }
        }
    }

    fn frame_out(&mut self, dst: Mac, packet: &[u8]) {
        let mac = self.mac;
        let Some(p) = ether::header(&mut self.out, dst, mac, ether::IPV4) else { return };
        let Some(p) = p.get_mut(..packet.len()) else { return };
        p.copy_from_slice(packet);
        self.transmit(ether::HEADER + packet.len());
    }

    fn neighbour(&self, ip: Ipv4, now: u64) -> Option<Mac> {
        self.neighbours.iter().find(|n| n.ip == ip && n.expires > now).map(|n| n.mac)
    }

    /// Remember that `ip` is at `mac`: in its old place, else the oldest.
    fn learn(&mut self, ip: Ipv4, mac: Mac, now: u64) {
        if ip == Ipv4::UNSPECIFIED || mac.is_group() {
            return;
        }
        let at = self.neighbours.iter().position(|n| n.ip == ip).unwrap_or_else(|| {
            let mut oldest = 0;
            for (i, n) in self.neighbours.iter().enumerate() {
                if n.expires < self.neighbours[oldest].expires {
                    oldest = i;
                }
            }
            oldest
        });
        self.neighbours[at] = Neighbour { ip, mac, expires: now + NEIGHBOUR_LIFE };
        if let Some(h) = self.held.take() {
            if h.hop == ip {
                self.frame_out(mac, &h.packet[..h.len]);
            } else {
                self.held = Some(h);
            }
        }
    }

    /// Ask who has `ip`.
    fn ask(&mut self, ip: Ipv4) {
        let Some(l) = self.lease else { return };
        let a = arp::Arp { op: arp::REQUEST, sender_mac: self.mac, sender_ip: l.address, target_mac: Mac::ZERO, target_ip: ip };
        let mac = self.mac;
        let Some(p) = ether::header(&mut self.out, Mac::BROADCAST, mac, ether::ARP) else { return };
        if arp::build(p, &a).is_some() {
            self.transmit(ether::HEADER + arp::LEN);
        }
    }

    fn ping(&mut self, now: u64, router: Ipv4) {
        let mut m = [0u8; 64];
        let data: [u8; 32] = core::array::from_fn(|i| i as u8);
        let Some(n) = icmp::echo(&mut m, icmp::ECHO_REQUEST, 0x5E71, 1, &data) else { return };
        self.probe = Some(Probe { router, sent: now, until: now + RESOLVE_WAIT + SECOND });
        self.send_ip(router, ipv4::ICMP, &m[..n]);
    }

    /// A frame of `n` bytes in `frame`.
    fn receive(&mut self, n: usize) {
        let frame = self.frame;
        let f = match ether::parse(&frame[..n]) {
            Ok(f) => f,
            Err(e) => return self.dropped.malformed(e),
        };
        if f.dst != self.mac && !f.dst.is_group() {
            self.dropped.not_ours += 1;
            return;
        }
        let now = silica_rt::clock().now();
        match f.ethertype {
            ether::ARP => match arp::parse(f.payload) {
                Ok(a) => self.arp(now, &a),
                Err(e) => self.dropped.malformed(e),
            },
            ether::IPV4 => match ipv4::parse(f.payload) {
                Ok(p) => self.ip(now, f.src, &p),
                Err(e) => self.dropped.malformed(e),
            },
            _ => self.dropped.not_ours += 1,
        }
    }

    fn arp(&mut self, now: u64, a: &arp::Arp) {
        let Some(l) = self.lease else { return };
        if a.target_ip != l.address {
            // Not about us: only an answer to our own question teaches.
            if a.op == arp::REPLY && self.held.as_ref().is_some_and(|h| h.hop == a.sender_ip) {
                self.learn(a.sender_ip, a.sender_mac, now);
            }
            return;
        }
        // Someone who asks for us, or answers us, is a neighbour.
        self.learn(a.sender_ip, a.sender_mac, now);
        if a.op == arp::REQUEST {
            let r =
                arp::Arp { op: arp::REPLY, sender_mac: self.mac, sender_ip: l.address, target_mac: a.sender_mac, target_ip: a.sender_ip };
            let mac = self.mac;
            let Some(p) = ether::header(&mut self.out, a.sender_mac, mac, ether::ARP) else { return };
            if arp::build(p, &r).is_some() {
                self.transmit(ether::HEADER + arp::LEN);
            }
        }
    }

    fn ip(&mut self, now: u64, from: Mac, p: &ipv4::Packet<'_>) {
        let ours = self.lease.is_some_and(|l| p.dst == l.address);
        let broadcast = p.dst == Ipv4::BROADCAST || self.lease.is_some_and(|l| p.dst.to_u32() | silica_inet::mask(l.prefix) == u32::MAX);
        // Before an address, a DHCP answer may come to the one offered.
        let offered = self.lease.is_none() && p.protocol == ipv4::UDP;
        if !ours && !broadcast && !offered {
            self.dropped.not_ours += 1;
            return;
        }
        match p.protocol {
            ipv4::ICMP if ours => match icmp::parse(p.payload) {
                Ok(m) => self.icmp(now, from, p, &m),
                Err(e) => self.dropped.malformed(e),
            },
            ipv4::UDP => match udp::parse(p.payload, p.src, p.dst) {
                Ok(d) if d.dst_port == dhcp::CLIENT_PORT && d.src_port == dhcp::SERVER_PORT => match dhcp::parse(d.data) {
                    Ok(r) => {
                        let step = self.dhcp.step(now, Some(&r), silica_rt::random::u64());
                        self.dhcp_step(now, step);
                    }
                    Err(e) => self.dropped.malformed(e),
                },
                Ok(d) if ours && d.dst_port == TIME_PORT && self.time.server(self.lease.as_ref()) == Some((p.src, d.src_port)) => {
                    match ntp::parse(d.data) {
                        Ok(r) => self.time_answer(now, &r),
                        Err(e) => self.dropped.malformed(e),
                    }
                }
                Ok(_) => self.dropped.not_ours += 1,
                Err(e) => self.dropped.malformed(e),
            },
            ipv4::TCP if ours => match silica_inet::tcp::parse(p.payload, p.src, p.dst) {
                Ok(seg) => {
                    let Some(l) = self.lease else { return };
                    let mut tcp = self.tcp.take().expect("TCP is in its place between turns");
                    if let Some(reset) = tcp.segment(now, l.address, p.src, &seg) {
                        tcp.reset(l.address, p.src, &reset, self);
                    }
                    self.tcp = Some(tcp);
                }
                Err(e) => self.dropped.malformed(e),
            },
            _ => self.dropped.not_ours += 1,
        }
    }

    fn icmp(&mut self, now: u64, from: Mac, p: &ipv4::Packet<'_>, m: &icmp::Message<'_>) {
        match m.kind {
            icmp::ECHO_REQUEST => {
                // The asker is a neighbour, or behind one: answer the way it came.
                let mut reply = [0u8; BUFFER];
                let Some(n) = icmp::echo(&mut reply, icmp::ECHO_REPLY, m.id(), m.seq(), m.data) else { return };
                let Some(l) = self.lease else { return };
                let id = self.next_id();
                let mut packet = [0u8; BUFFER];
                let Some(body) = ipv4::header(&mut packet, l.address, p.src, ipv4::ICMP, id, n) else { return };
                body.copy_from_slice(&reply[..n]);
                self.frame_out(from, &packet[..ipv4::HEADER + n]);
            }
            icmp::ECHO_REPLY => {
                if let Some(probe) = &self.probe
                    && p.src == probe.router
                    && m.id() == 0x5E71
                {
                    println!("netd: the router {} answers a ping in {} us", probe.router, (now - probe.sent) / 1000);
                    self.probe = None;
                }
            }
            _ => {}
        }
    }
}

impl tcp::Out for Stack {
    fn room(&self) -> bool {
        self.free != 0
    }

    fn send(&mut self, remote: Ipv4, segment: &[u8]) {
        self.send_ip(remote, ipv4::TCP, segment);
    }
}

impl Events for Stack {
    fn call(&mut self, badge: u64, request: &[u8], caps: CapList<Handle>, reply: &mut [u8], reply_caps: &mut CapList<Handle>) -> usize {
        self.caller = badge;
        let n = proto::dispatch(self, request, caps, reply, reply_caps);
        // What the call changed (a connection made) goes now.
        self.work();
        n
    }

    fn signals(&mut self, signals: u64) {
        self.nic.signalled(signals);
        self.work();
    }

    fn deadline(&self) -> Option<u64> {
        if self.more {
            return Some(0);
        }
        let d = Stack::deadline(self);
        (d != u64::MAX).then_some(d)
    }

    fn timer(&mut self) {
        self.work();
    }
}

impl proto::Server<Handle> for Stack {
    fn add_memory(&mut self, memory: Handle) -> Result<proto::AddMemoryReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.add_memory(badge, memory)
    }

    fn listen(&mut self, port: u16, backlog: u32, ready: Handle) -> Result<proto::ListenReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.listen(badge, port, backlog, ready)
    }

    fn accept(&mut self, listener: u32, offset: u64, bits: u8, wake: Handle) -> Result<proto::AcceptReply<Handle>, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.accept(badge, listener, offset, bits, wake)
    }

    fn connect(&mut self, peer: proto::Endpoint, offset: u64, bits: u8, wake: Handle) -> Result<proto::ConnectReply<Handle>, proto::Error> {
        let (badge, local) = (self.caller, self.lease.map(|l| l.address));
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.connect(badge, local, peer, offset, bits, wake)
    }

    fn close(&mut self, connection: u32) -> Result<proto::CloseReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.close(badge, connection)
    }

    fn unlisten(&mut self, listener: u32) -> Result<proto::UnlistenReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.unlisten(badge, listener)
    }
}
