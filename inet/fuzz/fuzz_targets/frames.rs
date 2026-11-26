//! A frame from the wire, through every parser the stack chains: Ethernet,
//! then ARP or IPv4, then ICMP, UDP or TCP, then DHCP. Nothing may panic, and
//! every view a parser returns must lie inside the bytes it was given.
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_inet::neighbours::Neighbours;
use silica_inet::{Ipv4, Mac};
use silica_inet::{arp, dhcp, ether, icmp, ipv4, ntp, tcp, udp};

const ME: (Ipv4, Mac) = (Ipv4([10, 0, 2, 15]), Mac([2, 0, 0, 0, 0, 1]));
const ROUTER: Ipv4 = Ipv4([10, 0, 2, 2]);
const ROUTER_MAC: Mac = Mac([0x52, 0x55, 10, 0, 2, 2]);

fn inside(outer: &[u8], inner: &[u8]) {
    let (o, i) = (outer.as_ptr() as usize, inner.as_ptr() as usize);
    assert!(i >= o && i + inner.len() <= o + outer.len(), "a view outside its input");
}

fuzz_target!(|frame: &[u8]| {
    let Ok(f) = ether::parse(frame) else { return };
    inside(frame, f.payload);
    // Each parser sees the payload whatever the EtherType says: a hostile
    // peer chooses it.
    // A hostile ARP packet through the neighbour table: whatever it says,
    // the router's entry, never asked about again here, keeps its address,
    // and a claim on our own address is a conflict, never a neighbour.
    if let Ok(a) = arp::parse(f.payload) {
        let mut t = Neighbours::<4>::new();
        t.asked(ROUTER);
        let _ = t.heard(
            &arp::Arp { op: arp::REPLY, sender_mac: ROUTER_MAC, sender_ip: ROUTER, target_mac: ME.1, target_ip: ME.0 },
            ME,
            Some(ROUTER),
            0,
        );
        let h = t.heard(&a, ME, Some(ROUTER), 1);
        assert_eq!(t.lookup(ROUTER, 2), Some(ROUTER_MAC), "an unsolicited packet moved the router");
        assert!(t.lookup(ME.0, 2).is_none() && h.learned.is_none_or(|(ip, _)| ip != ME.0 && ip != ROUTER));
    }
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
            // Whatever times a hostile server sends, an answer believed has
            // a round trip within the bound and moves a set clock no more
            // than the step allowed (the client's times from the frame too).
            if let (Some(t2), Some(t3), Some(t1)) =
                (ntp::to_unix_ns(reply.receive), ntp::to_unix_ns(reply.transmit), ntp::to_unix_ns(reply.originate))
            {
                let t4 = t1.wrapping_add(u64::from(d.src_port) << 20);
                if let Ok((shift, delay)) = ntp::judge(t1, t2, t3, t4, true) {
                    assert!((0..=ntp::DELAY_MOST).contains(&delay) && shift.unsigned_abs() <= ntp::STEP_MOST);
                }
            }
        }
    }
    // A UDP payload taken straight as DHCP too: the option walk is the
    // deepest parser and the checksum would hide it from most inputs.
    let _ = dhcp::parse(p.payload);
});
