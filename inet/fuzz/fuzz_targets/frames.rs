//! A frame from the wire, through every parser the stack chains: Ethernet,
//! then ARP or IPv4, then ICMP, UDP or TCP, then DHCP. Nothing may panic, and
//! every view a parser returns must lie inside the bytes it was given.
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_inet::{arp, dhcp, ether, icmp, ipv4, ntp, tcp, udp};

fn inside(outer: &[u8], inner: &[u8]) {
    let (o, i) = (outer.as_ptr() as usize, inner.as_ptr() as usize);
    assert!(i >= o && i + inner.len() <= o + outer.len(), "a view outside its input");
}

fuzz_target!(|frame: &[u8]| {
    let Ok(f) = ether::parse(frame) else { return };
    inside(frame, f.payload);
    // Each parser sees the payload whatever the EtherType says: a hostile
    // peer chooses it.
    let _ = arp::parse(f.payload);
    let Ok(p) = ipv4::parse(f.payload) else { return };
    inside(f.payload, p.payload);
    if let Ok(m) = icmp::parse(p.payload) {
        inside(p.payload, m.data);
    }
    if let Ok(s) = tcp::parse(p.payload, p.src, p.dst) {
        inside(p.payload, s.data);
        let _ = tcp::reset_reply(&s);
    }
    if let Ok(d) = udp::parse(p.payload, p.src, p.dst) {
        inside(p.payload, d.data);
        let _ = dhcp::parse(d.data);
        if let Ok(reply) = ntp::parse(d.data) {
            for stamp in [reply.receive, reply.transmit] {
                if let Some(ns) = ntp::to_unix_ns(stamp) {
                    // Truncation to a nanosecond loses less than five
                    // binary fraction ticks, including at an era boundary.
                    assert!(stamp.wrapping_sub(ntp::from_unix_ns(ns)) <= 5);
                }
            }
        }
    }
    // A UDP payload taken straight as DHCP too: the option walk is the
    // deepest parser and the checksum would hide it from most inputs.
    let _ = dhcp::parse(p.payload);
});
