//! DHCPv4 for a client (RFC 2131, options RFC 2132): the messages it sends
//! to obtain and keep a lease, and what it reads in a server's answers.
//!
//! A message is the BOOTP header (236 bytes), the magic cookie, then
//! options, each a code, a length and that many bytes, up to the End
//! option. Options carried in the header's `sname` and `file` fields
//! (option 52) are not read: a server that needs them for what a lease is
//! made of is not supported, and its answer lacks what the stack needs.

use crate::{Ipv4, Mac, Malformed, be32};

/// The server's port.
pub const SERVER_PORT: u16 = 67;
/// The client's port.
pub const CLIENT_PORT: u16 = 68;
/// The fixed header before the magic cookie.
const FIXED: usize = 236;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
/// The options the client asks for: netmask, router, DNS servers, lease
/// time, server identifier, renewal and rebinding times.
const WANTED: [u8; 7] = [1, 3, 6, 51, 54, 58, 59];

/// A message's kind (option 53).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Kind> {
        Some(match v {
            1 => Kind::Discover,
            2 => Kind::Offer,
            3 => Kind::Request,
            4 => Kind::Decline,
            5 => Kind::Ack,
            6 => Kind::Nak,
            7 => Kind::Release,
            8 => Kind::Inform,
            _ => return None,
        })
    }
}

/// What a server's answer says, as far as the client uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub kind: Kind,
    /// The transaction it answers.
    pub xid: u32,
    /// The client it is for.
    pub chaddr: Mac,
    /// The address offered or given (`yiaddr`).
    pub address: Ipv4,
    /// The server that answers (option 54).
    pub server: Option<Ipv4>,
    /// Seconds the lease lasts (option 51; `u32::MAX`: for ever).
    pub lease: Option<u32>,
    /// Seconds until the client renews (58) and rebinds (59).
    pub renew: Option<u32>,
    pub rebind: Option<u32>,
    /// The subnet's prefix length (from the netmask, option 1).
    pub prefix: Option<u8>,
    /// The first router (option 3).
    pub router: Option<Ipv4>,
    /// Up to three DNS servers (option 6), unused ones unspecified.
    pub dns: [Ipv4; 3],
}

/// Read a server's answer (a UDP payload from port 67).
pub fn parse(p: &[u8]) -> Result<Reply, Malformed> {
    if p.len() < FIXED + COOKIE.len() {
        return Err(Malformed::Truncated);
    }
    // A reply, about Ethernet, six-byte addresses.
    if p[0] != 2 || p[1] != 1 || p[2] != 6 {
        return Err(Malformed::BadHeader);
    }
    if p[FIXED..FIXED + 4] != COOKIE {
        return Err(Malformed::BadHeader);
    }
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&p[28..34]);
    let mut r = Reply {
        kind: Kind::Offer,
        xid: be32(p, 4),
        chaddr: Mac(chaddr),
        address: Ipv4([p[16], p[17], p[18], p[19]]),
        server: None,
        lease: None,
        renew: None,
        rebind: None,
        prefix: None,
        router: None,
        dns: [Ipv4::UNSPECIFIED; 3],
    };
    let mut kind = None;
    let mut at = FIXED + 4;
    loop {
        let Some(&code) = p.get(at) else { return Err(Malformed::BadOptions) };
        match code {
            0 => {
                at += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let len = *p.get(at + 1).ok_or(Malformed::BadOptions)? as usize;
        let v = p.get(at + 2..at + 2 + len).ok_or(Malformed::BadOptions)?;
        let ip = |v: &[u8], i: usize| Ipv4([v[i], v[i + 1], v[i + 2], v[i + 3]]);
        match (code, len) {
            (53, 1) => kind = Some(Kind::from_u8(v[0]).ok_or(Malformed::BadOptions)?),
            (54, 4) => r.server = Some(ip(v, 0)),
            (51, 4) => r.lease = Some(be32(v, 0)),
            (58, 4) => r.renew = Some(be32(v, 0)),
            (59, 4) => r.rebind = Some(be32(v, 0)),
            (1, 4) => r.prefix = Some(crate::prefix_of(ip(v, 0)).ok_or(Malformed::BadOptions)?),
            (3, n) if n >= 4 && n % 4 == 0 => r.router = Some(ip(v, 0)),
            (6, n) if n >= 4 && n % 4 == 0 => {
                for (i, d) in r.dns.iter_mut().enumerate().take(n / 4) {
                    *d = ip(v, i * 4);
                }
            }
            // A known option of a length it cannot have.
            (53 | 54 | 51 | 58 | 59 | 1, _) | (3 | 6, _) => return Err(Malformed::BadOptions),
            _ => {}
        }
        at += 2 + len;
    }
    r.kind = kind.ok_or(Malformed::BadOptions)?;
    Ok(r)
}

/// What the client sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    /// Is there a server with an address for this client?
    Discover,
    /// Take the address `address` from `server` (answering its offer).
    Select { address: Ipv4, server: Ipv4 },
    /// Keep the address `address` the client already holds (renewing, to
    /// its server; rebinding, to any).
    Renew { address: Ipv4 },
}

/// Write the message `ask` for the client `mac`, transaction `xid`,
/// `secs` seconds into its attempt; returns its length (a UDP payload).
pub fn build(out: &mut [u8], ask: Ask, mac: Mac, xid: u32, secs: u16) -> Option<usize> {
    // Header, cookie, then at most 3 + 3 + 6 + 6 + 2 + 7 + 9 + 1 bytes of
    // options; padded to the 300 bytes BOOTP relays and old servers expect.
    const LEN: usize = 300;
    let m = out.get_mut(..LEN)?;
    m.fill(0);
    m[0] = 1; // a request
    m[1] = 1; // Ethernet
    m[2] = 6;
    m[4..8].copy_from_slice(&xid.to_be_bytes());
    m[8..10].copy_from_slice(&secs.to_be_bytes());
    if let Ask::Renew { address } = ask {
        m[12..16].copy_from_slice(&address.0); // ciaddr
    }
    m[28..34].copy_from_slice(&mac.0);
    m[FIXED..FIXED + 4].copy_from_slice(&COOKIE);
    let mut at = FIXED + 4;
    let mut put = |bytes: &[u8]| {
        m[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    let kind = match ask {
        Ask::Discover => Kind::Discover,
        Ask::Select { .. } | Ask::Renew { .. } => Kind::Request,
    };
    put(&[53, 1, kind as u8]);
    // The client identifier: hardware type and address (RFC 2132 9.14).
    put(&[61, 7, 1]);
    put(&mac.0);
    if let Ask::Select { address, server } = ask {
        put(&[50, 4]);
        put(&address.0);
        put(&[54, 4]);
        put(&server.0);
    }
    // The largest message the client takes: an Ethernet MTU's worth.
    put(&[57, 2, 0x05, 0xDC]);
    put(&[55, WANTED.len() as u8]);
    put(&WANTED);
    put(&[255]);
    Some(LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);

    /// A server's answer as QEMU's user-mode network sends it.
    fn answer(kind: u8, xid: u32, options: &[u8]) -> [u8; 400] {
        let mut b = [0u8; 400];
        b[0] = 2;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&xid.to_be_bytes());
        b[16..20].copy_from_slice(&[10, 0, 2, 15]);
        b[28..34].copy_from_slice(&MAC.0);
        b[FIXED..FIXED + 4].copy_from_slice(&COOKIE);
        let mut o = FIXED + 4;
        b[o..o + 3].copy_from_slice(&[53, 1, kind]);
        o += 3;
        b[o..o + options.len()].copy_from_slice(options);
        o += options.len();
        b[o] = 255;
        b
    }

    #[test]
    fn an_offer_and_its_options_are_read() {
        let b = answer(
            2,
            0xC0FFEE,
            &[54, 4, 10, 0, 2, 2, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 2, 2, 6, 8, 10, 0, 2, 3, 1, 1, 1, 1, 51, 4, 0, 1, 0x51, 0x80, 0, 0],
        );
        let r = parse(&b).unwrap();
        assert_eq!(r.kind, Kind::Offer);
        assert_eq!((r.xid, r.chaddr, r.address), (0xC0FFEE, MAC, Ipv4([10, 0, 2, 15])));
        assert_eq!((r.server, r.prefix, r.router), (Some(Ipv4([10, 0, 2, 2])), Some(24), Some(Ipv4([10, 0, 2, 2]))));
        assert_eq!(r.dns, [Ipv4([10, 0, 2, 3]), Ipv4([1, 1, 1, 1]), Ipv4::UNSPECIFIED]);
        assert_eq!(r.lease, Some(86_400), "pads between options are skipped");
        assert_eq!((r.renew, r.rebind), (None, None));
    }

    #[test]
    fn options_that_run_off_the_end_or_lie_about_lengths_are_refused() {
        let mut b = answer(5, 1, &[]);
        assert_eq!(parse(&b).unwrap().kind, Kind::Ack);
        // No End before the packet ends.
        let mut short = b;
        short[FIXED + 7] = 0x77;
        assert_eq!(parse(&short[..FIXED + 9]).unwrap_err(), Malformed::BadOptions);
        // An option whose length passes the end.
        let o = FIXED + 7;
        b[o..o + 3].copy_from_slice(&[12, 200, 0]);
        assert_eq!(parse(&b[..o + 20]).unwrap_err(), Malformed::BadOptions);
        // A lease time of three bytes.
        let b = answer(5, 1, &[51, 3, 0, 0, 1]);
        assert_eq!(parse(&b).unwrap_err(), Malformed::BadOptions);
        // A netmask that is not one.
        let b = answer(5, 1, &[1, 4, 255, 0, 255, 0]);
        assert_eq!(parse(&b).unwrap_err(), Malformed::BadOptions);
        // No message type at all.
        let mut b = answer(5, 1, &[]);
        b[FIXED + 4] = 0;
        b[FIXED + 5] = 0;
        b[FIXED + 6] = 0;
        assert_eq!(parse(&b).unwrap_err(), Malformed::BadOptions);
        // A request, not a reply; another cookie.
        let mut b = answer(5, 1, &[]);
        b[0] = 1;
        assert_eq!(parse(&b).unwrap_err(), Malformed::BadHeader);
        let mut b = answer(5, 1, &[]);
        b[FIXED] = 0;
        assert_eq!(parse(&b).unwrap_err(), Malformed::BadHeader);
        assert_eq!(parse(&b[..100]).unwrap_err(), Malformed::Truncated);
    }

    #[test]
    fn what_the_client_sends_says_what_it_asks() {
        let mut b = [0u8; 300];
        let n = build(&mut b, Ask::Discover, MAC, 7, 0).unwrap();
        assert_eq!(n, 300);
        assert_eq!((b[0], b[1], b[2], &b[28..34]), (1, 1, 6, &MAC.0[..]));
        assert_eq!(&b[FIXED..FIXED + 7], &[99, 130, 83, 99, 53, 1, 1]);
        let n = build(&mut b, Ask::Select { address: Ipv4([10, 0, 2, 15]), server: Ipv4([10, 0, 2, 2]) }, MAC, 7, 3).unwrap();
        let o = &b[FIXED + 4..n];
        assert_eq!(&o[..3], &[53, 1, 3]);
        let find = |code: u8| {
            let mut at = 0;
            while o[at] != 255 {
                if o[at] == code {
                    return Some(&o[at + 2..at + 2 + o[at + 1] as usize]);
                }
                at += 2 + o[at + 1] as usize;
            }
            None
        };
        assert_eq!(find(50), Some(&[10, 0, 2, 15][..]), "the address asked for");
        assert_eq!(find(54), Some(&[10, 0, 2, 2][..]), "the server chosen");
        assert_eq!(find(55), Some(&WANTED[..]));
        assert_eq!(u16::from_be_bytes([b[8], b[9]]), 3, "secs");
        build(&mut b, Ask::Renew { address: Ipv4([10, 0, 2, 15]) }, MAC, 8, 0).unwrap();
        assert_eq!(&b[12..16], &[10, 0, 2, 15], "a renewal names its address as ciaddr");
        assert!(build(&mut [0u8; 299], Ask::Discover, MAC, 1, 0).is_none());
    }
}
