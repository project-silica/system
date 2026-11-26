//! Who is where on the link: the neighbour table ARP (RFC 826) fills.
//!
//! ARP has no authentication, and anyone on the link can send any ARP
//! packet. A table that believes every packet that names a host lets one
//! unsolicited packet redirect every frame for that host, the router's
//! included, and a stream of requests from new addresses push the router
//! out. So this table learns:
//!
//! - from an answer to a question it asked (whatever it knew before: the
//!   host it asked about may have moved);
//! - from a host that asks for this machine's address and is not known
//!   yet (it is about to be answered, and will be talked to);
//!
//! and nothing else. A packet that says a host it knows is now at another
//! hardware address is not believed: the host is asked again, and its own
//! answer decides. A new host never takes the router's place while the
//! router's entry lives. A packet that says this machine's own address is
//! another's is a conflict, reported and not learned.
//!
//! Someone who sees the question on the link can still answer it first
//! (no ARP table can tell who answered); what this rules out is the blind
//! and unsolicited packet.

use crate::arp::{self, Arp};
use crate::{Ipv4, Mac};

/// How long a neighbour is believed without hearing from it again.
pub const LIFE: u64 = 300_000_000_000;
/// How long before its entry ends a neighbour in use is asked again, so
/// traffic to it never waits for an answer: frames to the router through a
/// long transfer were dropped every [`LIFE`] while it was asked anew.
pub const REFRESH_AHEAD: u64 = 30_000_000_000;
/// Neighbours a machine remembers: as many as the peers its connection table
/// holds (one table for the machine, bounded per program), so a server with
/// many clients on its link does not push them out of each other's place.
pub const NEIGHBOURS: usize = 256;
/// Questions remembered while unanswered.
const ASKING: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    ip: Ipv4,
    mac: Mac,
    expires: u64,
    /// Sent to since it was last learned or answered: worth asking again
    /// before it ends (an entry nobody uses is left to end: an idle machine
    /// asks nothing).
    used: bool,
}

const EMPTY: Entry = Entry { ip: Ipv4::UNSPECIFIED, mac: Mac::ZERO, expires: 0, used: false };

/// The table: `N` neighbours, and the questions in flight.
pub struct Neighbours<const N: usize> {
    entries: [Entry; N],
    asking: [Ipv4; ASKING],
    /// The entry the last lookup found: most frames go to one hop.
    last: usize,
}

/// What an ARP packet means to the machine that heard it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Heard {
    /// A neighbour learned (or confirmed at a new address): what waited for
    /// it can go.
    pub learned: Option<(Ipv4, Mac)>,
    /// Ask who has this address (a claim not believed).
    pub ask: Option<Ipv4>,
    /// Answer the request: this machine has the address asked for.
    pub answer: bool,
    /// Another host says this machine's address is its own.
    pub conflict: Option<Mac>,
}

impl<const N: usize> Default for Neighbours<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Neighbours<N> {
    pub const fn new() -> Self {
        Neighbours { entries: [EMPTY; N], asking: [Ipv4::UNSPECIFIED; ASKING], last: 0 }
    }

    /// Where `ip` is, if known and not expired at `now`: what a frame to it
    /// is sent to, which marks the entry in use.
    pub fn lookup(&mut self, ip: Ipv4, now: u64) -> Option<Mac> {
        let at = match self.entries.get(self.last) {
            Some(n) if n.ip == ip => self.last,
            _ => self.entries.iter().position(|n| n.ip == ip)?,
        };
        self.last = at;
        let n = &mut self.entries[at];
        (n.expires > now).then(|| {
            n.used = true;
            n.mac
        })
    }

    /// A neighbour in use whose entry ends within [`REFRESH_AHEAD`], not
    /// answered since: ask it again now (the caller sends the request; its
    /// answer is believed as any to a question asked). One at a time.
    pub fn refresh(&mut self, now: u64) -> Option<Ipv4> {
        let ip = self.entries.iter().find(|n| n.used && n.expires > now && n.expires - now <= REFRESH_AHEAD && !self.asking(n.ip))?.ip;
        self.asked(ip);
        Some(ip)
    }

    /// When [`Neighbours::refresh`] has something to ask (`u64::MAX`: never).
    pub fn refresh_at(&self) -> u64 {
        self.entries
            .iter()
            .filter(|n| n.used && !self.asking(n.ip))
            .map(|n| n.expires.saturating_sub(REFRESH_AHEAD))
            .min()
            .unwrap_or(u64::MAX)
    }

    /// Whether a question about `ip` is in flight.
    pub fn asking(&self, ip: Ipv4) -> bool {
        ip != Ipv4::UNSPECIFIED && self.asking.contains(&ip)
    }

    /// This machine asked who has `ip`: its answer will be believed.
    pub fn asked(&mut self, ip: Ipv4) {
        if !self.asking(ip) {
            self.asking.rotate_right(1);
            self.asking[0] = ip;
        }
    }

    /// Take in `a`, heard at `now` by the machine at `me` (address and
    /// hardware address), whose router is `router`.
    pub fn heard(&mut self, a: &Arp, me: (Ipv4, Mac), router: Option<Ipv4>, now: u64) -> Heard {
        let (address, mac) = me;
        let mut h = Heard::default();
        if a.sender_mac == mac || a.sender_mac.is_group() {
            return h;
        }
        if a.sender_ip == address {
            h.conflict = Some(a.sender_mac);
            return h;
        }
        // An answer to our own question teaches, whatever was known.
        if a.op == arp::REPLY && self.asking(a.sender_ip) {
            for x in self.asking.iter_mut().filter(|x| **x == a.sender_ip) {
                *x = Ipv4::UNSPECIFIED;
            }
            self.learn(a.sender_ip, a.sender_mac, router, now);
            h.learned = Some((a.sender_ip, a.sender_mac));
            return h;
        }
        if a.target_ip != address || a.sender_ip == Ipv4::UNSPECIFIED {
            return h;
        }
        // Only a request for us makes a stranger a neighbour (a reply to a
        // question we did not ask is nobody's answer).
        let request = a.op == arp::REQUEST;
        h.answer = request;
        match self.entries.iter_mut().find(|n| n.ip == a.sender_ip && n.expires > now) {
            Some(n) if n.mac != a.sender_mac => h.ask = Some(a.sender_ip),
            Some(n) if request => n.expires = now + LIFE,
            Some(_) => {}
            None if !request => {}
            None => {
                self.learn(a.sender_ip, a.sender_mac, router, now);
                h.learned = Some((a.sender_ip, a.sender_mac));
            }
        }
        h
    }

    /// Remember that `ip` is at `mac`: in its old place, else the oldest
    /// that is not the router's live entry.
    fn learn(&mut self, ip: Ipv4, mac: Mac, router: Option<Ipv4>, now: u64) {
        let at = self.entries.iter().position(|n| n.ip == ip).or_else(|| {
            let mut oldest: Option<usize> = None;
            for (i, n) in self.entries.iter().enumerate() {
                if Some(n.ip) == router && n.expires > now {
                    continue;
                }
                if oldest.is_none_or(|o| n.expires < self.entries[o].expires) {
                    oldest = Some(i);
                }
            }
            oldest
        });
        if let Some(at) = at {
            self.entries[at] = Entry { ip, mac, expires: now + LIFE, used: false };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: (Ipv4, Mac) = (Ipv4([10, 0, 2, 15]), Mac([2, 0, 0, 0, 0, 1]));
    const ROUTER: Ipv4 = Ipv4([10, 0, 2, 2]);
    const ROUTER_MAC: Mac = Mac([0x52, 0x55, 10, 0, 2, 2]);
    const EVIL: Mac = Mac([2, 0xde, 0xad, 0xbe, 0xef, 0]);

    fn reply(ip: Ipv4, mac: Mac, to: Ipv4) -> Arp {
        Arp { op: arp::REPLY, sender_mac: mac, sender_ip: ip, target_mac: ME.1, target_ip: to }
    }
    fn request(ip: Ipv4, mac: Mac, for_ip: Ipv4) -> Arp {
        Arp { op: arp::REQUEST, sender_mac: mac, sender_ip: ip, target_mac: Mac::ZERO, target_ip: for_ip }
    }

    /// The router, asked for and answered.
    fn with_router() -> Neighbours<16> {
        let mut t = Neighbours::<16>::new();
        t.asked(ROUTER);
        let h = t.heard(&reply(ROUTER, ROUTER_MAC, ME.0), ME, Some(ROUTER), 0);
        assert_eq!(h.learned, Some((ROUTER, ROUTER_MAC)));
        assert_eq!(t.lookup(ROUTER, 1), Some(ROUTER_MAC));
        t
    }

    /// Unsolicited replies and requests that name the router at another
    /// hardware address (to us, or as a gratuitous ARP) do not move it:
    /// one packet redirected every frame for the router before.
    #[test]
    fn an_unsolicited_claim_does_not_move_a_known_host() {
        let mut t = with_router();
        let h = t.heard(&reply(ROUTER, EVIL, ME.0), ME, Some(ROUTER), 5);
        assert_eq!((h.learned, h.answer), (None, false));
        assert_eq!(t.lookup(ROUTER, 6), Some(ROUTER_MAC), "an unsolicited reply moved the router");
        let h = t.heard(&request(ROUTER, EVIL, ME.0), ME, Some(ROUTER), 7);
        assert_eq!(h.ask, Some(ROUTER), "a known host at a new address is asked again");
        assert!(h.answer, "a request for us is still answered");
        assert_eq!(t.lookup(ROUTER, 8), Some(ROUTER_MAC), "a request moved the router");
        let h = t.heard(&request(ROUTER, EVIL, ROUTER), ME, Some(ROUTER), 9);
        assert_eq!(h, Heard::default(), "a gratuitous ARP for another host");
        assert_eq!(t.lookup(ROUTER, 10), Some(ROUTER_MAC));
        // Asked again, its own answer decides (it did move).
        t.asked(ROUTER);
        let h = t.heard(&reply(ROUTER, Mac([0x52, 0x55, 1, 1, 1, 1]), ME.0), ME, Some(ROUTER), 11);
        assert!(h.learned.is_some());
        assert_eq!(t.lookup(ROUTER, 12), Some(Mac([0x52, 0x55, 1, 1, 1, 1])));
    }

    /// Requests from more new hosts than the table holds never push the
    /// router's live entry out.
    #[test]
    fn strangers_do_not_push_the_router_out() {
        let mut t = with_router();
        for i in 0..100u8 {
            let h = t.heard(&request(Ipv4([10, 0, 2, 100 + i]), Mac([2, 1, 0, 0, 0, i]), ME.0), ME, Some(ROUTER), 100 + i as u64);
            assert!(h.answer && h.learned.is_some());
        }
        assert_eq!(t.lookup(ROUTER, 1000), Some(ROUTER_MAC));
        assert_eq!(t.lookup(Ipv4([10, 0, 2, 199]), 1000), Some(Mac([2, 1, 0, 0, 0, 99])), "the newest stranger is known");
        // Once the router's entry has expired, its place is like any.
        assert_eq!(t.lookup(ROUTER, LIFE + 1), None);
    }

    /// A reply nobody asked for teaches nothing, even about a stranger.
    #[test]
    fn replies_to_questions_not_asked_teach_nothing() {
        let mut t = Neighbours::<16>::new();
        let other = Ipv4([10, 0, 2, 7]);
        assert_eq!(t.heard(&reply(other, EVIL, ME.0), ME, Some(ROUTER), 0), Heard::default());
        assert_eq!(t.lookup(other, 1), None);
        // Asked, answered once: a second answer is no longer to a question.
        t.asked(other);
        assert!(t.heard(&reply(other, Mac([2, 7, 7, 7, 7, 7]), ME.0), ME, Some(ROUTER), 2).learned.is_some());
        assert_eq!(t.heard(&reply(other, EVIL, ME.0), ME, Some(ROUTER), 3).learned, None);
        assert_eq!(t.lookup(other, 4), Some(Mac([2, 7, 7, 7, 7, 7])));
    }

    /// Another host that says our address is its own is a conflict, not a
    /// neighbour; our own packets reflected and group senders are nothing.
    #[test]
    fn our_own_address_claimed_is_a_conflict() {
        let mut t = with_router();
        let h = t.heard(&request(ME.0, EVIL, ME.0), ME, Some(ROUTER), 5);
        assert_eq!(h, Heard { conflict: Some(EVIL), ..Heard::default() });
        assert_eq!(t.lookup(ME.0, 6), None);
        assert_eq!(t.heard(&request(ME.0, ME.1, ME.0), ME, Some(ROUTER), 7), Heard::default());
        assert_eq!(t.heard(&request(Ipv4([10, 0, 2, 9]), Mac::BROADCAST, ME.0), ME, Some(ROUTER), 8), Heard::default());
    }

    /// A neighbour in use never lapses: the router through a transfer, and a
    /// peer that is only sent to, are asked again before their entries end, and twenty hosts on the link stay
    /// known together. Before, every entry ended after [`LIFE`] whatever its
    /// traffic (frames to it dropped while it was asked anew, each a
    /// retransmission and a smaller window), and sixteen entries thrashed
    /// with more peers on the link.
    #[test]
    fn a_neighbour_in_use_never_lapses() {
        const S: u64 = 1_000_000_000;
        let mut t = Neighbours::<NEIGHBOURS>::new();
        t.asked(ROUTER);
        t.heard(&reply(ROUTER, ROUTER_MAC, ME.0), ME, Some(ROUTER), 0);
        // A transfer through the router: a frame to it each second; asked
        // again before its entry ends, it answers.
        for s in 1..=301 {
            if let Some(ip) = t.refresh(s * S) {
                assert_eq!(ip, ROUTER);
                t.heard(&reply(ROUTER, ROUTER_MAC, ME.0), ME, Some(ROUTER), s * S + S / 100);
            }
            assert_eq!(t.lookup(ROUTER, s * S), Some(ROUTER_MAC), "the router was unknown at {s} s of a transfer through it");
        }
        // A peer that is sent to and never heard from: asked again before
        // its entry ends, and its answer renews it.
        let (peer, peer_mac) = (Ipv4([10, 0, 2, 7]), Mac([2, 0, 0, 0, 0, 7]));
        let start = 1000 * S;
        t.heard(&request(peer, peer_mac, ME.0), ME, Some(ROUTER), start);
        let mut asked = 0;
        for s in 1..=301 {
            let now = start + s * S;
            if let Some(ip) = t.refresh(now) {
                assert_eq!(ip, peer);
                asked += 1;
                t.heard(&reply(peer, peer_mac, ME.0), ME, Some(ROUTER), now + S / 100);
            }
            assert_eq!(t.lookup(peer, now), Some(peer_mac), "a peer in use was unknown at {s} s");
        }
        assert_eq!(asked, 1, "asked again once, shortly before its entry ended");
        // Nobody uses it: never asked again (an idle machine asks nothing).
        let later = start + 2000 * S;
        assert_eq!(t.refresh(later), None);
        // Twenty hosts on the link, each known from its own request.
        let hosts: [(Ipv4, Mac); 20] = core::array::from_fn(|i| (Ipv4([10, 0, 3, i as u8]), Mac([2, 0, 0, 0, 3, i as u8])));
        for (k, (ip, mac)) in hosts.iter().enumerate() {
            t.heard(&request(*ip, *mac, ME.0), ME, Some(ROUTER), later + k as u64);
        }
        for (ip, mac) in &hosts {
            assert_eq!(t.lookup(*ip, later + 100), Some(*mac), "{ip:?} was pushed out by the hosts after it");
        }
    }
}
