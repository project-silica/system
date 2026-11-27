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
//! It sets the wall clock from up to three time servers named by the lease.
//! A test image can select a server with `netd.ntp=<address>[:<port>]`.
//! It asks when bound and then every 64 s doubling to 1,024 s. An answer is
//! taken only from the server asked, to the port asked from, echoing the
//! question's random number. A step past 1,000 s waits for a second answer
//! that agrees, from another server where one is known: where only one is,
//! that guards against a wrong answer, not against the server (or anyone on
//! the path to it) answering both; authenticated time (NTS) is owed.
//!
//! It provides TCP to programs (`silica.net.Tcp`, the `tcp` module), in the
//! same thread and the same wait as its interface: one notification, the
//! interface's bits below `tcp::GONE`, then the kernel's notice that a
//! program using TCP ended, the device manager's word that an interface
//! gained or lost its driver ([`DEVICES_CHANGED`]), then the programs' bits.
//!
//! What it does not do yet (spec/MILESTONES.md, M4): UDP for programs,
//! IPv6, more than one interface, reassembly; a program's call made before
//! the machine has an interface is answered once it has one.

#![no_std]
#![no_main]

use silica_idl_rt::CapList;
use silica_inet::dhcp_client::{self, Client, Event, Lease, To};
use silica_inet::neighbours::{NEIGHBOURS, Neighbours};
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
/// Transmit tags: `SENT + slot`, then `SENT + SLOTS + burst`.
const SENT: u64 = 1 << 32;
/// Transmit buffers for TCP segments the interface cuts (its segmentation
/// offload): `BURSTS` of `BURST` bytes in memory 1, registered only with an
/// interface that cuts. A frame of 64 KiB holds 45 segments of 1448 bytes.
const BURSTS: usize = 4;
const BURST: usize = 1 << 16;
/// Packets waiting for their next hop's address: one for each hop asked
/// about at once (a newer one for the same hop replaces it).
const HELD: usize = 4;
/// How long an address is asked for before what waits for it is dropped.
const RESOLVE_WAIT: u64 = 3 * SECOND;

fn main(info: &'static ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: netd: {e}");
            1
        }
    }
}

/// A copy of `cap` in a free slot of this program, with `rights` and
/// `badge`, to hand to another program in a call.
fn lend(cap: Cap, rights: Rights, badge: u64) -> Result<Handle, &'static str> {
    let slot = free_slot().ok_or("no free capability slot")?;
    if sys::cap_derive(slots::SPACE, slot, cap, rights, badge).is_err() {
        release_slot(slot);
        return Err("cannot lend a capability");
    }
    Ok(Handle::new(Cap(slot)))
}

/// The bit of the stack's notification the device manager signals when a
/// network interface gains or loses its driver (its `watch`): how the stack
/// hears that the driver of the interface it uses is back, and that there
/// is an interface at all. Between `tcp::GONE` and the programs' bits.
const DEVICES_CHANGED: u64 = 1 << 9;

/// The device manager, watched for network interfaces gaining or losing
/// their drivers.
struct Devices {
    client: manager::Client<Channel, Handle>,
    changed: Cap,
}

impl Devices {
    /// Watching on `note`, the stack's one notification, bit [`DEVICES_CHANGED`].
    fn new(note: Cap) -> Result<Devices, &'static str> {
        let mut client = manager::Client::<Channel, Handle>::from(Channel::new(DEVICES));
        client
            .watch(manager::Class::Network, lend(note, Rights::WRITE, DEVICES_CHANGED)?)
            .map_err(|_| "the device manager does not answer")?;
        Ok(Devices { client, changed: note })
    }

    /// The first network interface with a driver, waited for (no wake-ups
    /// while there is none).
    fn interface(&mut self) -> Result<u32, &'static str> {
        let mut said = false;
        loop {
            let listed = self.client.list(manager::Class::Network, 0).map_err(|_| "the device manager does not answer")?;
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

    /// Until an interface gains or loses a driver (whatever else signals
    /// the notification meanwhile is nothing to wait for here).
    fn wait(&mut self) -> Result<(), &'static str> {
        loop {
            let m = sys::recv(self.changed, Wait::Forever).map_err(|_| "cannot wait for an interface")?;
            if m.badge & DEVICES_CHANGED != 0 {
                return Ok(());
            }
        }
    }
}

fn run(start: &ProcessInfo) -> Result<core::convert::Infallible, &'static str> {
    // Options that do not parse stop the stack, rather than have it guess.
    let fixed = fixed_lease()?;
    // One notification for everything, for as long as the stack runs: the
    // interface's bits, the device manager's, then the programs' (`tcp`).
    let note = Object::new(ObjectType::Notification, 0).map_err(|_| "no memory for a notification")?;
    let mut devices = Devices::new(note.cap())?;
    // The page the program before this one left, when this is the first
    // instance of a new one: the service manager's last grant, beyond the
    // two every instance has. Looked at once.
    let mut left = (start.grants > 2).then(|| Cap(slots::FIRST_GRANT + start.grants - 1));
    loop {
        let id = devices.interface()?;
        // An interface whose driver cannot be talked to (failing, or not
        // keeping to its protocol) is not the stack's to give up on: the
        // device manager restarts a failing driver, and a change is waited
        // for before the interface is tried again.
        let Err(why) = use_interface(id, fixed, left.take(), note.cap());
        println!("netd: interface {id:#x}: {why}; waiting for its driver to change");
        devices.wait()?;
    }
}

/// Run the stack on the interface `id` until it cannot be used.
fn use_interface(id: u32, fixed: Option<Lease>, left: Option<Cap>, note: Cap) -> Result<core::convert::Infallible, &'static str> {
    let mut nic = Interface::open_on(DEVICES, id, note, 0).map_err(|e| match e {
        silica_net::client::Error::Refused(silica_queue::Refused::Busy) => "another program has it",
        silica_net::client::Error::Gone => "its driver ended",
        _ => "it cannot be opened (its driver does not keep to the protocol)",
    })?;
    // The device manager says when the interface's driver changes: its next
    // driver is tried then, not by the clock.
    nic.provider_changed();
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
    // The interface's offloads: TCP's checksums summed by it, and segments
    // of up to a burst buffer cut by it.
    let checksum_offload = info.offloads & silica_net::OFFLOAD_CHECKSUM != 0;
    let cuts = checksum_offload && info.offloads & silica_net::OFFLOAD_TCP4_SEGMENT != 0 && info.segment_bytes as usize >= 2 * BUFFER;
    let burst_memory = if cuts {
        let m = Memory::new(BURST.trailing_zeros() as u8 + BURSTS.trailing_zeros() as u8).map_err(|_| "no memory for frames")?;
        nic.add_memory(1, &m, false).map_err(|_| "cannot register memory with the driver")?;
        Some(m)
    } else {
        None
    };
    // Data a cut segment may carry: its frame within a burst buffer and
    // the interface's most, behind Ethernet, IPv4 and the longest TCP header.
    let most_payload = if cuts { (info.segment_bytes as usize).min(BURST) - ether::HEADER - ipv4::HEADER - 60 } else { 0 };
    println!(
        "netd: offloads: checksums {}, TCP segmentation {}",
        if checksum_offload { "on" } else { "off" },
        if cuts { "on" } else { "off" }
    );
    let now = silica_rt::clock().now();
    // The lease an earlier instance held on this boot, if it is this
    // interface's and has not ended: held again at once (`Client::resume`).
    let keep = mem::peer(slots::KEEP, 12, Rights(Rights::READ.0 | Rights::WRITE.0)).ok();
    let kept = keep.as_ref().and_then(|k| kept_lease(k, mac));
    // An address the owner configured comes before DHCP: held for ever, and
    // no DHCP message is sent.
    let dhcp = match (fixed, kept) {
        (Some(l), _) | (None, Some(l)) => Client::resume(mac, l, now),
        (None, None) => Client::new(mac, now),
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
    // What the program before this one left, when this is the first
    // instance of a new one (the service manager's last grant, read-only):
    // another program's page, of which only its connections are taken, to
    // reset them as a stack that was killed resets its own, and the
    // address they were on, to compare with the one this stack comes to
    // hold. Its lease is not taken: this program asks for its own.
    let left = left.and_then(|c| mem::peer(c, 12, Rights::READ).ok());
    let (left_resets, resets_from) = match left.as_ref().and_then(|k| Some((k, k.part(128, 4096 - 128)?))) {
        Some((k, r)) if k.read64(120) == tcp::RECORDS_MARK => {
            (tcp::left_connections(&r), (k.read64(0) == KEPT_LEASE).then(|| Ipv4::from_u32(k.read64(16) as u32)))
        }
        _ => (Vec::new(), None),
    };
    if !left_resets.is_empty() {
        println!("netd: {} connections of the program before this one to reset", left_resets.len());
    }
    let resets_from = if resets.is_empty() { resets_from } else { None };
    let resets = if resets.is_empty() { left_resets } else { resets };
    let mut s = Stack {
        nic,
        id,
        devices: manager::Client::<Channel, Handle>::from(Channel::new(DEVICES)),
        m: memory.shared(),
        mac,
        free: (1 << SLOTS) - 1,
        bursts: burst_memory.as_ref().map(|m| m.shared()),
        bursts_free: (1 << BURSTS) - 1,
        dhcp,
        lease,
        keep,
        neighbours: Neighbours::new(),
        defended: 0,
        held: [const { None }; HELD],
        ip_id: (silica_rt::random::u64() & 0xFFFF) as u16,
        frame: [0; BUFFER],
        out: [0; BUFFER],
        probe: None,
        dropped: Dropped::default(),
        tcp: Some(tcp::Tcp::new(note, info.mtu.min(1500) as u16, records, checksum_offload, most_payload as u32)),
        resets,
        resets_until: 0,
        resets_next: 0,
        resets_from,
        time: TimeClient::new(clock, now),
        caller: 0,
        more: true,
    };
    for tag in 1..=BUFFERS {
        s.offer(tag)?;
    }
    if let Some(l) = lease {
        if fixed.is_some() {
            println!(
                "netd: {}/{} as the boot options say{}",
                l.address,
                l.prefix,
                l.router.map(|r| silica_rt::alloc::format!(", router {r}")).unwrap_or_default()
            );
        } else {
            println!(
                "netd: {}/{} kept from before it started again; {} connections of the stack before it to reset",
                l.address,
                l.prefix,
                s.resets.len()
            );
        }
        // Its router's Ethernet address, before the first answer needs it.
        if let Some(r) = l.router {
            s.ping(now, r);
        }
    }
    silica_rt::ipc::serve_events(ENDPOINT, note, &mut s)
}

/// The ports the time-server client asks from: a random one of these for
/// each question, so that an answer must reach the one it was asked from.
const TIME_PORTS: core::ops::Range<u16> = 50_000..60_000;

/// The time-server client's state (SNTP to the servers it knows, one at a
/// time).
struct TimeClient {
    /// The time page, writable (this service `sets_time`); none: no clock
    /// to set, and no question asked.
    page: Option<Mmio>,
    /// The server the boot options name (`ntp=<address>[:<port>]`).
    configured: Option<(Ipv4, u16)>,
    /// The question in flight: the random number it carried as its
    /// transmit timestamp, its time (ns since 1970 by this clock), and
    /// the port it was asked from, and the server asked (`server_key`).
    asked: Option<(u64, u64, u16, (Ipv4, u16))>,
    /// When to ask next, questions sent since the last answer, seconds
    /// between answers, and whether the clock was set: by the firmware, by
    /// this instance, or by one before it (the time page says which), for
    /// what is said of a step (the step limit holds whether or not).
    next: u64,
    tries: u32,
    poll: u64,
    set: bool,
    /// Steps past the limit, taken only when answers agree.
    steps: ntp::Steps,
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
        let set = page.as_ref().is_some_and(|p| silica_rt::time::read(p).1 != silica_rt::time::Source::None);
        TimeClient { page, configured, asked: None, next: now, tries: 0, poll: 64, set, steps: ntp::Steps::new() }
    }

    /// The servers that may be asked: the configured one, else the lease's
    /// (up to three), and how many there are.
    fn servers(&self, lease: Option<&Lease>) -> ([(Ipv4, u16); 3], usize) {
        let mut out = [(Ipv4::UNSPECIFIED, 0); 3];
        if let Some(c) = self.configured {
            out[0] = c;
            return (out, 1);
        }
        let mut n = 0;
        for a in lease.map_or(&[][..], |l| &l.ntp[..]).iter().filter(|a| **a != Ipv4::UNSPECIFIED) {
            out[n] = (*a, ntp::PORT);
            n += 1;
        }
        (out, n)
    }

    /// The server to ask: the first, or, while a step waits to be
    /// confirmed, another than the one that asked for it, where there is
    /// one (`ntp::Steps`).
    fn server(&self, lease: Option<&Lease>) -> Option<(Ipv4, u16)> {
        let (list, n) = self.servers(lease);
        let list = &list[..n];
        let waiting = self.steps.waiting_on();
        list.iter().find(|s| n > 1 && waiting.is_some_and(|w| w != server_key(**s))).or(list.first()).copied()
    }
}

/// The mark of a lease in the page kept across restarts.
const KEPT_LEASE: u64 = 0x4553_4145_4c5f_4454; // "TD_LEASE"

/// The address this program's options give it, as a lease that never
/// ends: `address=<address>/<prefix>`, with `router=<address>` and
/// `dns=<address>,...` (at most three) if the network has them. Only a test
/// image's service manager gives a service options from the boot command
/// line (`netd.address=...`); a machine's gives none, so there the address
/// comes from DHCP. (A server on a network without DHCP is owed its address
/// as a provisioned file of its own, as the remote service is given its
/// owners, never the unsigned line.) `Err` for options that do not parse,
/// which stops the stack rather than guess.
fn fixed_lease() -> Result<Option<Lease>, &'static str> {
    let Some(a) = silica_rt::option("address") else {
        if silica_rt::option("router").is_some() || silica_rt::option("dns").is_some() {
            return Err("the router and dns options need an address option");
        }
        return Ok(None);
    };
    let (address, prefix) = a.split_once('/').ok_or("the address option is not <address>/<prefix>")?;
    let address = address.parse::<Ipv4>().map_err(|_| "the address option is not <address>/<prefix>")?;
    let prefix = prefix.parse::<u8>().ok().filter(|p| (1..=32).contains(p)).ok_or("the address option's prefix is not 1 to 32")?;
    let router = match silica_rt::option("router") {
        Some(r) => Some(r.parse::<Ipv4>().map_err(|_| "the router option is not an address")?),
        None => None,
    };
    let mut dns = [Ipv4::from_u32(0); 3];
    for (k, d) in silica_rt::option("dns").unwrap_or("").split(',').filter(|d| !d.is_empty()).enumerate() {
        *dns.get_mut(k).ok_or("the dns option names more than three servers")? =
            d.parse::<Ipv4>().map_err(|_| "the dns option is not addresses")?;
    }
    Ok(Some(Lease {
        address,
        prefix,
        router,
        dns,
        ntp: [Ipv4::UNSPECIFIED; 3],
        server: Ipv4::from_u32(0),
        seconds: u32::MAX,
        renew_at: u64::MAX,
        rebind_at: u64::MAX,
        expires_at: u64::MAX,
    }))
}

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
        ntp: [if (k.read64(72) >> 32) & 1 != 0 { lo(k.read64(72)) } else { Ipv4::UNSPECIFIED }, lo(k.read64(80)), hi(k.read64(80))],
        server: hi(r),
        seconds: (e >> 32) as u32,
        renew_at: k.read64(48),
        rebind_at: k.read64(56),
        expires_at: k.read64(64),
    })
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
    /// The interface's identity, and the device manager to ask about it.
    id: u32,
    devices: manager::Client<Channel, Handle>,
    m: Mmio,
    mac: Mac,
    /// Free transmit slots, a bit each.
    free: u32,
    /// The burst buffers (memory 1) and which are free, with an interface
    /// that cuts TCP segments.
    bursts: Option<Mmio>,
    bursts_free: u32,
    dhcp: Client,
    lease: Option<Lease>,
    /// The page kept across restarts (`slots::KEEP`), the lease in it.
    keep: Option<Mmio>,
    /// Who is where on the link, and the questions in flight.
    neighbours: Neighbours<NEIGHBOURS>,
    /// When another host was last told this address is ours (a conflict).
    defended: u64,
    held: [Option<Held>; HELD],
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
    /// The last stack's connections whose peers have not yet said they no
    /// longer hold them (`send_resets`).
    resets: Vec<tcp::Kept>,
    /// When those still unanswered are given up (their peers, or their
    /// hops, never answered); set when the first is asked.
    resets_until: u64,
    /// When they are asked again.
    resets_next: u64,
    /// The address those connections were on, when another program's
    /// page says so: they are reset only from that address.
    resets_from: Option<Ipv4>,
    time: TimeClient,
    /// Work is left (a completion there, segments with no transmit slot):
    /// look again at once rather than wait.
    more: bool,
}

impl Stack {
    fn offer(&mut self, tag: u64) -> Result<(), &'static str> {
        let r = Request {
            op: Op::Receive,
            memory: 0,
            offset: (tag as usize - 1) as u32 * BUFFER as u32,
            length: BUFFER as u32,
            tag,
            offload: silica_net::Offload::NONE,
        };
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
        let r = Request {
            op: Op::Transmit,
            memory: 0,
            offset: at as u32,
            length: len as u32,
            tag: SENT + slot as u64,
            offload: silica_net::Offload::NONE,
        };
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
                let k = c.tag - SENT;
                if k < SLOTS as u64 {
                    self.free |= 1 << k;
                } else if k - (SLOTS as u64) < BURSTS as u64 {
                    self.bursts_free |= 1 << (k - SLOTS as u64);
                }
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
        // Blocked for want of a buffer: look again only if one is free now,
        // else wait for the interface to give one back (looking again at
        // once, with only burst buffers short, kept a processor from the
        // driver that was to give them back).
        self.more = (blocked && tcp::Out::room(self)) || !asleep || !self.nic.sleep();
    }

    /// The soonest of what waits for a time.
    fn deadline(&self) -> u64 {
        let mut d = self.dhcp.deadline();
        if let Some(t) = self.tcp.as_ref().and_then(|t| t.deadline()) {
            d = d.min(t);
        }
        for h in self.held.iter().flatten() {
            d = d.min(h.asked + SECOND).min(h.since + RESOLVE_WAIT);
        }
        // A neighbour in use, asked again before its entry ends.
        d = d.min(self.neighbours.refresh_at());
        if let Some(p) = &self.probe {
            d = d.min(p.until);
        }
        // The last stack's peers, asked again.
        if !self.resets.is_empty() && self.lease.is_some() && self.resets_until != 0 {
            d = d.min(self.resets_next).min(self.resets_until);
        }
        if self.time.server(self.lease.as_ref()).is_some() && self.time.page.is_some() {
            d = d.min(self.time.next);
        }
        // The interface's driver is restarting: its next try.
        if let Some(t) = self.nic.retry_at() {
            d = d.min(t);
        }
        d
    }

    fn timers(&mut self, now: u64) {
        for k in 0..HELD {
            let Some(h) = &self.held[k] else { continue };
            if now >= h.since + RESOLVE_WAIT {
                println!("netd: {} does not answer ARP; what was for it is dropped", h.hop);
                self.held[k] = None;
                self.dropped.unresolved += 1;
            } else if now >= h.asked + SECOND {
                let hop = h.hop;
                self.ask(hop);
                if let Some(h) = self.held[k].as_mut() {
                    h.asked = now;
                }
            }
        }
        // Neighbours in use whose entries end soon: asked again, so what
        // is sent to them never waits for an answer.
        while let Some(ip) = self.neighbours.refresh(now) {
            self.arp_request(ip);
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
                // A new address (the old lease ended while the stack was not
                // running, or another was given): nothing on the old one lives.
                if self.lease.is_some_and(|old| old.address != l.address)
                    && let Some(tcp) = self.tcp.as_mut()
                {
                    tcp.address_gone();
                }
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
                    println!("netd: the lease of {} ended; its connections end, and the stack asks again", l.address);
                    if let Some(tcp) = self.tcp.as_mut() {
                        tcp.address_gone();
                    }
                }
                self.keep_lease();
            }
            None => {}
        }
        if let Some(m) = step.send {
            self.send_dhcp(m);
        }
    }

    /// The interface's driver is away and the device manager says the
    /// machine's interfaces changed. A driver being started again is
    /// waited for, for as long as the device manager takes: it signals
    /// again when there is one, and the connections wait as they do for a
    /// cable put back. If the device itself is gone and the machine has
    /// another interface, the stack starts again on that one. (Before, the
    /// stack looked every 50 us to 4 ms for 5 s and then ended, whatever
    /// the device manager knew.)
    fn interface_away(&mut self) {
        let Ok(listed) = self.devices.list(manager::Class::Network, 0) else { return };
        let mut others = listed.devices.iter().filter(|d| d.id != self.id);
        if listed.devices.iter().all(|d| d.id != self.id)
            && let Some(other) = others.next()
        {
            println!("netd: interface {:#x} is gone and {:#x} is there: starting again on it", self.id, other.id);
            silica_rt::exit(1);
        }
    }

    /// Reset the connections the last stack had (`tcp::kept_connections`),
    /// once the lease is held and each first hop's Ethernet address known.
    /// What the last stack wrote down (how far each side had sent) is not
    /// what a peer expects when segments were in flight, and a reset at
    /// another number is dropped without a word (RFC 5961): sent once at
    /// that number, a session's peer waited for an answer that would never
    /// come (the `remote` test, 2026-11-26). So each peer is asked
    /// (`tcp::reset_probe`) once a second: while it holds the connection it
    /// answers with the byte it expects, and the reset to that answer
    /// (`Tcp::segment`, as to any segment no connection takes) ends it;
    /// once it does not, it answers with a reset, and that connection is
    /// done ([`Stack::reset_answered`]). A peer that answers nothing is a
    /// network peer: given up on after `2 * RESOLVE_WAIT`.
    fn send_resets(&mut self, now: u64) {
        let Some(l) = self.lease else { return };
        if self.resets.is_empty() {
            return;
        }
        if let Some(from) = self.resets_from.take()
            && from != l.address
        {
            println!("netd: {} connections of the program before this one were on {from}, not {}: not reset", self.resets.len(), l.address);
            self.resets.clear();
            return;
        }
        let hop = |r: Ipv4| if l.address.same_subnet(r, l.prefix) { Some(r) } else { l.router };
        if self.resets_until == 0 {
            self.resets_until = now + 2 * RESOLVE_WAIT;
        }
        if now >= self.resets_until {
            println!(
                "netd: {} connections of the stack before it are not known to be reset: their peers did not answer",
                self.resets.len()
            );
            self.resets.clear();
            return;
        }
        if now < self.resets_next {
            return;
        }
        // Every peer whose next hop is known is asked; one whose hop is
        // not waits, its hop asked for (once while it is unanswered).
        let mut asked_all = true;
        let mut i = self.resets.len();
        while i > 0 {
            i -= 1;
            let Some(h) = hop(self.resets[i].remote) else {
                self.resets.swap_remove(i);
                continue;
            };
            if self.neighbour(h, now).is_none() {
                if !self.neighbours.asking(h) {
                    self.ask(h);
                }
                continue;
            }
            if self.free == 0 {
                asked_all = false;
                break;
            }
            let k = &self.resets[i];
            let header = silica_inet::tcp::reset_probe(k.local_port, k.remote_port, k.sequence, k.acknowledges);
            let remote = k.remote;
            let mut seg = [0u8; 64];
            if let Some(n) = silica_inet::tcp::build(&mut seg, l.address, remote, &header, &silica_inet::tcp::Options::default(), &[]) {
                self.send_ip(remote, ipv4::TCP, &seg[..n]);
            }
        }
        // Those not asked for want of a transmit buffer are asked on the
        // next turn, the rest in a second.
        self.resets_next = if asked_all { now + SECOND } else { now };
    }

    /// A segment `s` from `remote` that no connection took: if it is the
    /// answer of a peer of the last stack's connections that it no longer
    /// holds one (a reset), that connection is done; when the last is, the
    /// stack says so.
    fn reset_answered(&mut self, remote: Ipv4, s: &silica_inet::tcp::Segment<'_>) {
        if self.resets.is_empty() || !s.has(silica_inet::tcp::RST) {
            return;
        }
        let h = &s.header;
        let before = self.resets.len();
        self.resets.retain(|k| !(k.remote == remote && k.remote_port == h.src_port && k.local_port == h.dst_port));
        if self.resets.len() < before && self.resets.is_empty() {
            println!("netd: the connections of the stack before it are reset");
        }
    }

    /// Ask the time server, when it is time to (and the clock is ours to set).
    fn ask_time(&mut self, now: u64) {
        let Some((server, port)) = self.time.server(self.lease.as_ref()) else { return };
        let Some(page) = self.time.page else { return };
        // Not before the address: a question sent without one goes nowhere
        // and used up one of the quick tries.
        if now < self.time.next || self.lease.is_none() {
            return;
        }
        // The question's time, by this clock (the firmware's, or none yet:
        // the offset is relative to whatever it says).
        let (offset, _) = silica_rt::time::read(&page);
        let t1 = offset.wrapping_add(now);
        // Not the clock (anyone can guess it) but a random number, and a
        // random port: an answer comes from whoever got the question.
        let r = silica_rt::random::u64();
        let nonce = r | 1 << 63;
        let from = TIME_PORTS.start + (r as u32 % TIME_PORTS.len() as u32) as u16;
        let mut q = [0u8; ntp::LEN];
        ntp::request(&mut q, nonce);
        self.time.asked = Some((nonce, t1, from, (server, port)));
        self.time.tries += 1;
        self.time.next = if self.time.tries < 3 { now + 2 * SECOND } else { now + self.time.poll * SECOND };
        if self.time.tries >= 3 {
            self.time.tries = 0;
        }
        self.send_udp(server, from, port, &q);
    }

    /// The time server answered: set the clock if it answers our question.
    fn time_answer(&mut self, now: u64, r: &ntp::Reply) {
        let Some(page) = self.time.page else { return };
        let Some((nonce, t1, _, asked_of)) = self.time.asked else { return };
        // Only the answer to the question in flight: a blind sender does
        // not know its number.
        if r.originate != nonce {
            return;
        }
        let (Some(t2), Some(t3)) = (ntp::to_unix_ns(r.receive), ntp::to_unix_ns(r.transmit)) else { return };
        self.time.asked = None;
        let (offset, _) = silica_rt::time::read(&page);
        let t4 = offset.wrapping_add(now);
        let alone = self.time.servers(self.lease.as_ref()).1 <= 1;
        let (shift, delay) = match self.time.steps.judge([t1, t2, t3, t4], now, server_key(asked_of), alone) {
            Ok(j) => j,
            Err(ntp::Refused::Impossible) => {
                println!("netd: a time server's answer gives times that cannot be; not believed");
                return;
            }
            Err(ntp::Refused::Slow(delay)) => {
                println!("netd: a time server's answer took {} ms; not believed", delay / 1_000_000);
                return;
            }
            Err(ntp::Refused::Step(shift)) => {
                println!("netd: a time server would move the clock by {} s; not believed", shift / SECOND as i64);
                return;
            }
            Err(ntp::Refused::Unconfirmed(shift)) => {
                // Asked again soon, from another port with another number:
                // a second answer that agrees takes the step.
                println!(
                    "netd: a time server would move the clock by {} s; not believed until another answer agrees",
                    shift / SECOND as i64
                );
                self.time.next = now + 2 * SECOND;
                return;
            }
        };
        let Some(wall) = t4.checked_add_signed(shift) else { return };
        silica_rt::time::set(&page, wall, now, silica_rt::time::Source::Network);
        if !self.time.set || shift.unsigned_abs() > SECOND {
            let (server, port) = asked_of;
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
        k.write64(72, ip(l.ntp[0]) | ((l.ntp[0] != Ipv4::UNSPECIFIED) as u64) << 32);
        k.write64(80, ip(l.ntp[1]) | ip(l.ntp[2]) << 32);
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
                // One packet waits for each hop asked about: a newer one
                // for the same hop replaces it, and with every place taken
                // the oldest goes (each is sent again if lost).
                let k = self
                    .held
                    .iter()
                    .position(|h| h.as_ref().is_some_and(|h| h.hop == hop))
                    .or_else(|| self.held.iter().position(Option::is_none))
                    .unwrap_or_else(|| (0..HELD).min_by_key(|&k| self.held[k].as_ref().map_or(0, |h| h.since)).unwrap_or(0));
                if self.held[k].is_some() {
                    self.dropped.unresolved += 1;
                }
                self.held[k] = Some(Held { hop, since: now, asked: now, len, packet });
                self.ask(hop);
            }
        }
    }

    /// A TCP segment whose checksum the interface finishes (it holds the
    /// pseudo-header's sum), and that it cuts when it carries more than
    /// `mss` bytes of data: its Ethernet and IPv4 headers and the segment
    /// written straight into a transmit buffer, a burst buffer for one to
    /// cut. A segment whose next hop is not known yet is finished here and
    /// held as any packet; one to cut is dropped and counted (TCP sends it
    /// again), as is one with no buffer free.
    fn send_tcp(&mut self, dst: Ipv4, segment: &[u8], mss: u16) {
        let Some(l) = self.lease else { return };
        let hop = if l.address.same_subnet(dst, l.prefix) {
            dst
        } else if let Some(r) = l.router {
            r
        } else {
            self.dropped.unresolved += 1;
            return;
        };
        let header = usize::from(segment[12] >> 4) * 4;
        let cut = segment.len() - header > usize::from(mss);
        let Some(mac) = self.neighbour(hop, silica_rt::clock().now()) else {
            if cut || segment.len() > BUFFER - ether::HEADER - ipv4::HEADER {
                self.dropped.unresolved += 1;
                return;
            }
            let mut whole = [0u8; BUFFER];
            let s = &mut whole[..segment.len()];
            s.copy_from_slice(segment);
            silica_inet::tcp::seal(s, l.address, dst);
            return self.send_ip(dst, ipv4::TCP, s);
        };
        let mut head = [0u8; ether::HEADER + ipv4::HEADER];
        let id = self.next_id();
        let _ = ether::header(&mut head, mac, self.mac, ether::IPV4);
        if ipv4::header_only(&mut head[ether::HEADER..], l.address, dst, ipv4::TCP, id, segment.len()).is_none() {
            return;
        }
        let len = head.len() + segment.len();
        let (memory, at, tag, m) = if len <= BUFFER && !cut {
            if self.free == 0 {
                self.dropped.no_slot += 1;
                return;
            }
            let slot = self.free.trailing_zeros() as usize;
            self.free &= !(1 << slot);
            (0, (BUFFERS as usize + slot) * BUFFER, SENT + slot as u64, &self.m)
        } else {
            let Some(m) = self.bursts.as_ref().filter(|_| self.bursts_free != 0 && len <= BURST) else {
                self.dropped.no_slot += 1;
                return;
            };
            let burst = self.bursts_free.trailing_zeros() as usize;
            self.bursts_free &= !(1 << burst);
            (1, burst * BURST, SENT + (SLOTS + burst) as u64, m)
        };
        m.write_bytes(at, &head);
        m.write_bytes(at + head.len(), segment);
        // The shortest frame: zeros behind, which add nothing to the sum.
        let length = len.max(ether::MIN_FRAME);
        if length > len {
            m.write_bytes(at + len, &[0u8; ether::MIN_FRAME][..length - len]);
        }
        let start = head.len() as u16;
        let offload = silica_net::Offload {
            checksum: true,
            segmentation: cut,
            checksum_start: start,
            checksum_offset: 16,
            segment: if cut { mss } else { 0 },
            header_bytes: if cut { start + header as u16 } else { 0 },
        };
        let r = Request { op: Op::Transmit, memory, offset: at as u32, length: length as u32, tag, offload };
        if self.nic.submit(&r).is_err() {
            if memory == 0 {
                self.free |= 1 << (tag - SENT);
            } else {
                self.bursts_free |= 1 << (tag - SENT - SLOTS as u64);
            }
            self.dropped.no_slot += 1;
        }
    }

    fn frame_out(&mut self, dst: Mac, packet: &[u8]) {
        let mac = self.mac;
        let Some(p) = ether::header(&mut self.out, dst, mac, ether::IPV4) else { return };
        let Some(p) = p.get_mut(..packet.len()) else { return };
        p.copy_from_slice(packet);
        self.transmit(ether::HEADER + packet.len());
    }

    fn neighbour(&mut self, ip: Ipv4, now: u64) -> Option<Mac> {
        self.neighbours.lookup(ip, now)
    }

    /// `ip` was learned to be at `mac`: what waited for it goes.
    fn learned(&mut self, ip: Ipv4, mac: Mac) {
        for k in 0..HELD {
            if self.held[k].as_ref().is_some_and(|h| h.hop == ip)
                && let Some(h) = self.held[k].take()
            {
                self.frame_out(mac, &h.packet[..h.len]);
            }
        }
    }

    /// Ask who has `ip`: its answer is believed (`Neighbours`).
    fn ask(&mut self, ip: Ipv4) {
        self.neighbours.asked(ip);
        self.arp_request(ip);
    }

    /// Send an ARP request for `ip` from the leased address (for our own
    /// address: an announcement that it is ours).
    fn arp_request(&mut self, ip: Ipv4) {
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
        // What the packet teaches is the table's to say: only answers to
        // our questions and strangers asking for us (one unsolicited packet
        // redirected all our traffic for a host, the router's included).
        let h = self.neighbours.heard(a, (l.address, self.mac), l.router, now);
        if let Some(other) = h.conflict {
            // Another host says our address is its: a conflict. Said, and
            // our claim announced, no more than every ten seconds.
            if now >= self.defended + 10 * SECOND {
                self.defended = now;
                println!("netd: {other} says {} is its address too", l.address);
                self.arp_request(l.address);
            }
            return;
        }
        if let Some((ip, mac)) = h.learned {
            self.learned(ip, mac);
        }
        if let Some(ip) = h.ask {
            self.ask(ip);
        }
        if h.answer {
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
                Ok(d)
                    if ours
                        && self.time.asked.is_some_and(|(_, _, from, _)| from == d.dst_port)
                        && self.time.asked.is_some_and(|(_, _, _, s)| s == (p.src, d.src_port)) =>
                {
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
                    if let Some(reset) = tcp.segment(now, l.address, p.src, &seg, self) {
                        tcp.reset(l.address, p.src, &reset, self);
                    }
                    self.tcp = Some(tcp);
                    self.reset_answered(p.src, &seg);
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
            icmp::UNREACHABLE => {
                // A router says a segment was too large for the path: the
                // connection it quotes cuts smaller, if it is ours and the
                // segment is one in flight (`Connection::path_mtu`).
                let (Some((mtu, q)), Some(l), Some(t)) = (icmp::too_big(m), self.lease, self.tcp.as_mut()) else { return };
                if q.src == l.address {
                    t.path_mtu(q.src, q.src_port, q.dst, q.dst_port, mtu, q.seq);
                }
            }
            _ => {}
        }
    }
}

impl tcp::Out for Stack {
    fn room(&self) -> bool {
        // A connection polled may give a segment to cut: a burst buffer must
        // be free too, or it waits (dropping it here was TCP's loss to
        // repair: 64 connections at once took 444 ms, not 37).
        self.free != 0 && (self.bursts.is_none() || self.bursts_free != 0)
    }

    fn send(&mut self, remote: Ipv4, segment: &[u8], partial: bool, mss: u16) {
        if partial {
            self.send_tcp(remote, segment, mss);
        } else {
            self.send_ip(remote, ipv4::TCP, segment);
        }
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
        let changed = signals & DEVICES_CHANGED != 0;
        if changed {
            self.nic.provider_changed();
        }
        if let Some(t) = self.tcp.as_mut() {
            if signals & tcp::GONE != 0 {
                t.forget_ended();
            }
            // The connections whose programs signalled.
            t.signalled(signals);
        }
        self.work();
        if changed && self.nic.away() {
            self.interface_away();
        }
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

    /// Retired: naming a port is never the authority to listen on it.
    fn listen(&mut self, _port: u16, _backlog: u32, _ready: Handle) -> Result<proto::ListenReply, proto::Error> {
        Err(proto::Error::NotGranted)
    }

    /// Retired: a backlog is a second bound beside the memory the caller lent.
    fn listen_given(&mut self, _backlog: u32, _ready: Handle) -> Result<proto::ListenGivenReply, proto::Error> {
        Err(proto::Error::NotGranted)
    }

    fn listen_granted(&mut self, ready: Handle) -> Result<proto::ListenGrantedReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.listen(badge, ready)
    }

    fn accept(&mut self, listener: u32, offset: u64, bits: u8, wake: Handle) -> Result<proto::AcceptReply<Handle>, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.accept(badge, listener, offset, bits, wake)
    }

    fn connect(&mut self, peer: proto::Endpoint, offset: u64, bits: u8, wake: Handle) -> Result<proto::ConnectReply<Handle>, proto::Error> {
        let (badge, local) = (self.caller, self.lease.map(|l| l.address));
        let mut tcp = self.tcp.take().ok_or(proto::Error::NoRoom)?;
        let result = tcp.connect(badge, local, peer, (offset, bits), wake, self);
        self.tcp = Some(tcp);
        result
    }

    fn close(&mut self, connection: u32) -> Result<proto::CloseReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.close(badge, connection)
    }

    fn reset(&mut self, connection: u32) -> Result<proto::ResetReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.reset_conn(badge, connection)
    }

    fn unlisten(&mut self, listener: u32) -> Result<proto::UnlistenReply, proto::Error> {
        let badge = self.caller;
        self.tcp.as_mut().ok_or(proto::Error::NoRoom)?.unlisten(badge, listener)
    }
}

/// How a time server is named to `ntp::Steps`: its address and port.
fn server_key((a, port): (Ipv4, u16)) -> u64 {
    u64::from(a.to_u32()) << 16 | u64::from(port)
}
