//! The fuzzer's seed frames (fuzz/corpus/frames, built by a separate
//! program from the RFCs' layouts) parse all the way down: the corpus stays
//! one that reaches the deepest parsers, and the parsers agree with bytes
//! they did not build.

use silica_inet::{Ipv4, Mac, arp, dhcp, ether, icmp, ipv4, udp};

const ME: Mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);

fn frame(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fuzz/corpus/frames/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn arp_seeds() {
    let f = frame("arp_request");
    let e = ether::parse(&f).unwrap();
    assert_eq!((e.dst, e.src, e.ethertype), (Mac::BROADCAST, ME, ether::ARP));
    let a = arp::parse(e.payload).unwrap();
    assert_eq!((a.op, a.target_ip), (arp::REQUEST, Ipv4([10, 0, 2, 2])));
    let f = frame("arp_reply");
    let a = arp::parse(ether::parse(&f).unwrap().payload).unwrap();
    assert_eq!((a.op, a.sender_ip, a.target_mac), (arp::REPLY, Ipv4([10, 0, 2, 2]), ME));
}

#[test]
fn echo_seed() {
    let f = frame("echo_request");
    let p = ipv4::parse(ether::parse(&f).unwrap().payload).unwrap();
    assert_eq!((p.src, p.dst, p.protocol), (Ipv4([10, 0, 2, 2]), Ipv4([10, 0, 2, 15]), ipv4::ICMP));
    let m = icmp::parse(p.payload).unwrap();
    assert_eq!((m.kind, m.id(), m.seq(), m.data.len()), (icmp::ECHO_REQUEST, 0x511C, 1, 32));
}

#[test]
fn dhcp_seeds() {
    for (name, kind) in [("dhcp_offer", dhcp::Kind::Offer), ("dhcp_ack", dhcp::Kind::Ack)] {
        let f = frame(name);
        let p = ipv4::parse(ether::parse(&f).unwrap().payload).unwrap();
        let d = udp::parse(p.payload, p.src, p.dst).unwrap();
        assert_eq!((d.src_port, d.dst_port), (dhcp::SERVER_PORT, dhcp::CLIENT_PORT));
        let r = dhcp::parse(d.data).unwrap();
        assert_eq!(
            (r.kind, r.address, r.prefix, r.router, r.lease),
            (kind, Ipv4([10, 0, 2, 15]), Some(24), Some(Ipv4([10, 0, 2, 2])), Some(86_400))
        );
        assert_eq!(r.renew, Some(43_200), "{name}");
    }
}
