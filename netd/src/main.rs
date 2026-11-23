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
//! What it does not do yet (spec/MILESTONES.md, M4): sockets for programs,
//! TCP, IPv6, more than one interface, reassembly.

#![no_std]
#![no_main]

use silica_inet::dhcp_client::{self, Client, Event, Lease, To};
use silica_inet::{Ipv4, Mac, Malformed, arp, dhcp, ether, icmp, ipv4, udp};
use silica_net::client::Interface;
use silica_net::{Completion, LINK, Op, Request};
use silica_protocols::device::manager;
use silica_rt::ipc::{Channel, Handle, free_slot, release_slot};
use silica_rt::mem::{Memory, Object};
use silica_rt::mmio::Mmio;
use silica_rt::sys::{self, Cap, ObjectType, Rights, Wait};
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

const SECOND: u64 = 1_000_000_000;
/// The device manager: the service's first grant.
const DEVICES: Cap = Cap(slots::FIRST_GRANT);
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
    let mut nic = Interface::open(DEVICES, id).map_err(|e| match e {
        silica_net::client::Error::Refused(silica_queue::Refused::Busy) => "another program has it",
        silica_net::client::Error::Gone => "its driver ended",
        _ => "it cannot be opened (its driver does not keep to the protocol)",
    })?;
    let info = nic.info().map_err(|_| "the interface says nothing about itself")?;
    let a = info.address.to_le_bytes();
    let mac = Mac([a[0], a[1], a[2], a[3], a[4], a[5]]);
    println!("netd: {mac}, MTU {}, link {}", info.mtu, if info.link_up { "up" } else { "down" });
    let memory = Memory::new(16).map_err(|_| "no memory for frames")?;
    nic.add_memory(0, &memory, true).map_err(|_| "cannot register memory with the driver")?;
    let now = silica_rt::clock().now();
    let mut s = Stack {
        nic,
        m: memory.shared(),
        mac,
        free: (1 << SLOTS) - 1,
        dhcp: Client::new(mac, now),
        lease: None,
        neighbours: [Neighbour::EMPTY; NEIGHBOURS],
        held: None,
        ip_id: (silica_rt::random::u64() & 0xFFFF) as u16,
        frame: [0; BUFFER],
        out: [0; BUFFER],
        probe: None,
        dropped: Dropped::default(),
    };
    for tag in 1..=BUFFERS {
        s.offer(tag)?;
    }
    s.serve()
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
    neighbours: [Neighbour; NEIGHBOURS],
    held: Option<Held>,
    ip_id: u16,
    /// The frame being read (copied out of its buffer) and the one being built.
    frame: [u8; BUFFER],
    out: [u8; BUFFER],
    probe: Option<Probe>,
    dropped: Dropped,
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

    fn serve(&mut self) -> Result<core::convert::Infallible, &'static str> {
        loop {
            let now = silica_rt::clock().now();
            if now >= self.dhcp.deadline() {
                let step = self.dhcp.step(now, None, silica_rt::random::u64());
                self.dhcp_step(now, step);
            }
            self.timers(now);
            let deadline = self.deadline();
            let c: Completion = match self.nic.kick_wait((deadline != u64::MAX).then_some(deadline)) {
                Ok(c) => c,
                Err(silica_net::client::Error::Timeout) => continue,
                Err(_) => return Err("the interface failed"),
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
                self.offer(c.tag)?;
                self.receive(n);
            } else {
                self.offer(c.tag)?;
            }
        }
    }

    /// The soonest of what waits for a time.
    fn deadline(&self) -> u64 {
        let mut d = self.dhcp.deadline();
        if let Some(h) = &self.held {
            d = d.min(h.asked + SECOND).min(h.since + RESOLVE_WAIT);
        }
        if let Some(p) = &self.probe {
            d = d.min(p.until);
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
                if let Some(r) = l.router {
                    self.ping(now, r);
                }
            }
            Some(Event::Renewed(l)) => self.lease = Some(l),
            Some(Event::Lost) => {
                if let Some(l) = self.lease.take() {
                    println!("netd: the lease of {} ended; asking again", l.address);
                }
            }
            None => {}
        }
        if let Some(m) = step.send {
            self.send_dhcp(m);
        }
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
                Ok(_) => self.dropped.not_ours += 1,
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
