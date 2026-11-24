//! A DHCPv4 client's state machine (RFC 2131 section 4.4): obtaining a
//! lease, keeping it, and giving it up when it ends. It sends nothing and
//! reads no clock itself: the stack gives it the time and what arrived,
//! and sends what it asks for, so every path (a lost offer, a renewal, a
//! server that went away, a lease that ran out) is tested without waiting
//! for one.
//!
//! Times are monotonic nanoseconds. Retransmissions follow the RFC:
//! 4 s, doubling to 64 s, each a second earlier or later at random; a
//! request goes unanswered four times before the client starts over.

use crate::dhcp::{Ask, Kind, Reply};
use crate::{Ipv4, Mac};

const SECOND: u64 = 1_000_000_000;
/// How often a request to take an offer is sent before starting over.
const SELECT_TRIES: u32 = 4;
/// The shortest wait between renewal (and rebinding) messages.
const MIN_RETRY: u64 = 60 * SECOND;

/// An address held, and until when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4,
    pub prefix: u8,
    pub router: Option<Ipv4>,
    pub dns: [Ipv4; 3],
    /// The network's time server, if it names one (option 42).
    pub ntp: Option<Ipv4>,
    /// The server that gave it, which renewals go to.
    pub server: Ipv4,
    /// How long it was given for, in seconds (`u32::MAX`: for ever).
    pub seconds: u32,
    /// When to renew with the server, rebind with any, and let it go
    /// (`u64::MAX`: never).
    pub renew_at: u64,
    pub rebind_at: u64,
    pub expires_at: u64,
}

/// Where a message goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum To {
    /// Every host on the link (from the unspecified address while the
    /// client has none).
    Broadcast,
    /// The server, from the leased address.
    Server(Ipv4),
}

/// A message for the stack to send (`dhcp::build` makes it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Send {
    pub ask: Ask,
    pub to: To,
    pub xid: u32,
    pub secs: u16,
}

/// What changed for the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// An address to use, from now.
    Bound(Lease),
    /// The same address, for longer.
    Renewed(Lease),
    /// The address must no longer be used.
    Lost,
}

/// What one step of the client asks of the stack.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub send: Option<Send>,
    pub event: Option<Event>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Asking for offers.
    Selecting,
    /// Taking `offer` from its server.
    Requesting {
        address: Ipv4,
        server: Ipv4,
    },
    Bound,
    /// Asking the lease's server for more time.
    Renewing,
    /// Asking any server for more time.
    Rebinding,
}

/// The client of one interface.
#[derive(Clone, Debug)]
pub struct Client {
    mac: Mac,
    state: State,
    xid: u32,
    /// Messages sent in this state, and when the first of them was.
    tries: u32,
    since: u64,
    /// When to act next without being asked (`u64::MAX`: never).
    deadline: u64,
    lease: Option<Lease>,
}

impl Client {
    /// A client for the interface `mac` that has no address. Call
    /// [`Client::step`] at once: its deadline is now.
    pub fn new(mac: Mac, now: u64) -> Client {
        Client { mac, state: State::Selecting, xid: 0, tries: 0, since: now, deadline: now, lease: None }
    }

    /// When [`Client::step`] must be called next if nothing arrives.
    /// A client for `mac` that holds `lease`, given to an earlier instance
    /// of the stack on this boot (its times are this boot's clock): bound
    /// at once, renewing when the lease says, as if it had never stopped. A
    /// lease that has expired is not held: the client starts with none.
    /// What a network stack started again does, so that it answers on its
    /// address at once instead of after a new exchange, while peers back
    /// off their retransmissions.
    pub fn resume(mac: Mac, lease: Lease, now: u64) -> Client {
        if now >= lease.expires_at {
            return Client::new(mac, now);
        }
        Client { mac, state: State::Bound, xid: 0, tries: 0, since: now, deadline: lease.renew_at, lease: Some(lease) }
    }

    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// The lease held, if any.
    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// The transaction a server's answer must carry to be heard.
    pub fn xid(&self) -> u32 {
        self.xid
    }

    /// Act on `reply` (a server's answer, already parsed), or on the time
    /// if there is none: called with `None` at or after the deadline.
    /// `random` is 64 fresh random bits for transaction numbers and timing.
    pub fn step(&mut self, now: u64, reply: Option<&Reply>, random: u64) -> Step {
        match reply {
            Some(r) => self.answer(now, r, random),
            None if now >= self.deadline => self.timeout(now, random),
            None => Step::default(),
        }
    }

    fn answer(&mut self, now: u64, r: &Reply, random: u64) -> Step {
        // Another client's, or another transaction's: not for us.
        if r.chaddr != self.mac || r.xid != self.xid {
            return Step::default();
        }
        match (self.state, r.kind) {
            (State::Selecting, Kind::Offer) => {
                let Some(server) = r.server else { return Step::default() };
                if r.address == Ipv4::UNSPECIFIED || r.address == Ipv4::BROADCAST || r.address.is_multicast() {
                    return Step::default();
                }
                self.state = State::Requesting { address: r.address, server };
                self.tries = 0;
                self.since = now;
                self.request(now, random)
            }
            (State::Requesting { address, server }, Kind::Ack) if r.address == address => match lease_of(now, r, server) {
                Some(l) => self.bind(l, Event::Bound(l)),
                None => Step::default(),
            },
            (State::Renewing | State::Rebinding, Kind::Ack) => {
                let Some(held) = self.lease else { return Step::default() };
                if r.address != held.address {
                    return Step::default();
                }
                match lease_of(now, r, r.server.unwrap_or(held.server)) {
                    Some(l) => self.bind(l, Event::Renewed(l)),
                    None => Step::default(),
                }
            }
            (State::Requesting { .. } | State::Renewing | State::Rebinding, Kind::Nak) => {
                let lost = self.lease.take().is_some();
                let mut s = self.restart(now, random);
                if lost {
                    s.event = Some(Event::Lost);
                }
                s
            }
            _ => Step::default(),
        }
    }

    fn timeout(&mut self, now: u64, random: u64) -> Step {
        match self.state {
            State::Selecting => {
                if self.tries == 0 {
                    self.since = now;
                }
                self.xid = (random >> 32) as u32;
                self.tries += 1;
                self.deadline = now + backoff(self.tries, random);
                Step { send: Some(self.message(Ask::Discover, To::Broadcast, now)), event: None }
            }
            State::Requesting { .. } if self.tries >= SELECT_TRIES => self.restart(now, random),
            State::Requesting { .. } => self.request(now, random),
            State::Bound | State::Renewing | State::Rebinding => {
                let Some(l) = self.lease else { return self.restart(now, random) };
                if now >= l.expires_at {
                    self.lease = None;
                    let mut s = self.restart(now, random);
                    s.event = Some(Event::Lost);
                    return s;
                }
                let (to, until) = if now >= l.rebind_at { (To::Broadcast, l.expires_at) } else { (To::Server(l.server), l.rebind_at) };
                let state = if now >= l.rebind_at { State::Rebinding } else { State::Renewing };
                if self.state != state {
                    self.state = state;
                    self.tries = 0;
                    self.since = now;
                    self.xid = (random >> 32) as u32;
                }
                self.tries += 1;
                // Half the time left before the next stage, no less often
                // than a minute (RFC 2131 4.4.5), never past that stage.
                self.deadline = (now + ((until - now) / 2).max(MIN_RETRY)).min(until);
                Step { send: Some(self.message(Ask::Renew { address: l.address }, to, now)), event: None }
            }
        }
    }

    /// Ask to take the offer, once more.
    fn request(&mut self, now: u64, random: u64) -> Step {
        let State::Requesting { address, server } = self.state else { return Step::default() };
        self.tries += 1;
        self.deadline = now + backoff(self.tries, random);
        // Taking an offer is broadcast: the other servers learn theirs was not.
        Step { send: Some(self.message(Ask::Select { address, server }, To::Broadcast, now)), event: None }
    }

    fn bind(&mut self, l: Lease, event: Event) -> Step {
        self.lease = Some(l);
        self.state = State::Bound;
        self.tries = 0;
        self.deadline = l.renew_at;
        Step { send: None, event: Some(event) }
    }

    /// From the beginning: ask for offers at once.
    fn restart(&mut self, now: u64, random: u64) -> Step {
        self.state = State::Selecting;
        self.tries = 0;
        self.deadline = now;
        self.timeout(now, random)
    }

    fn message(&self, ask: Ask, to: To, now: u64) -> Send {
        let secs = ((now - self.since) / SECOND).min(u16::MAX as u64) as u16;
        Send { ask, to, xid: self.xid, secs }
    }
}

/// The wait after the `tries`th message of a stage: 4 s doubling to 64 s,
/// a second either way at random.
fn backoff(tries: u32, random: u64) -> u64 {
    let base = (4 * SECOND) << (tries.saturating_sub(1)).min(4);
    base - SECOND + (random & 0xFFFF_FFFF) % (2 * SECOND)
}

/// The lease an acknowledgement gives, or `None` when it says too little
/// to use (no lease time: RFC 2131 requires one in an answer to a request).
fn lease_of(now: u64, r: &Reply, server: Ipv4) -> Option<Lease> {
    let seconds = r.lease?;
    if seconds == 0 {
        return None;
    }
    let (renew_at, rebind_at, expires_at) = if seconds == u32::MAX {
        (u64::MAX, u64::MAX, u64::MAX)
    } else {
        let l = u64::from(seconds) * SECOND;
        let default_rebind = l - l / 8;
        let mut renew = r.renew.map_or(l / 2, |t| u64::from(t) * SECOND);
        let mut rebind = r.rebind.map_or(default_rebind, |t| u64::from(t) * SECOND);
        // Times out of order are a server's mistake: use the RFC's.
        if !(0 < renew && renew < rebind && rebind < l) {
            renew = l / 2;
            rebind = default_rebind;
        }
        (now.saturating_add(renew), now.saturating_add(rebind), now.saturating_add(l))
    };
    let prefix = r.prefix.unwrap_or(match r.address.0[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    });
    Some(Lease { address: r.address, prefix, router: r.router, dns: r.dns, ntp: r.ntp, server, seconds, renew_at, rebind_at, expires_at })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    const SERVER: Ipv4 = Ipv4([10, 0, 2, 2]);
    const ADDRESS: Ipv4 = Ipv4([10, 0, 2, 15]);

    fn reply(kind: Kind, xid: u32, lease: Option<u32>) -> Reply {
        Reply {
            kind,
            xid,
            chaddr: MAC,
            address: ADDRESS,
            server: Some(SERVER),
            lease,
            renew: None,
            rebind: None,
            prefix: Some(24),
            router: Some(SERVER),
            dns: [Ipv4([10, 0, 2, 3]), Ipv4::UNSPECIFIED, Ipv4::UNSPECIFIED],
            ntp: None,
        }
    }

    /// A client bound at time 0 to a lease of `seconds`.
    fn bound(seconds: u32) -> Client {
        let mut c = Client::new(MAC, 0);
        let s = c.step(0, None, 7 << 32);
        assert_eq!(s.send.unwrap().ask, Ask::Discover);
        assert_eq!(s.send.unwrap().to, To::Broadcast);
        let s = c.step(1, Some(&reply(Kind::Offer, 7, Some(seconds))), 0);
        assert_eq!(s.send.unwrap().ask, Ask::Select { address: ADDRESS, server: SERVER });
        let s = c.step(2, Some(&reply(Kind::Ack, 7, Some(seconds))), 0);
        assert!(matches!(s.event, Some(Event::Bound(l)) if l.address == ADDRESS && l.prefix == 24 && l.server == SERVER));
        c
    }

    #[test]
    fn a_resumed_lease_is_held_and_renewed_on_time_and_an_expired_one_is_not() {
        let l = *bound(600).lease().unwrap();
        let mut c = Client::resume(MAC, l, 10 * SECOND);
        assert_eq!(c.lease(), Some(&l), "held at once");
        assert_eq!(c.deadline(), l.renew_at, "nothing to do until renewal");
        let s = c.step(l.renew_at, None, 9 << 32);
        assert!(matches!(s.send.unwrap().ask, Ask::Renew { address } if address == ADDRESS), "renewed with its server");
        assert_eq!(s.send.unwrap().to, To::Server(SERVER));
        let mut c = Client::resume(MAC, l, l.expires_at);
        assert_eq!(c.lease(), None, "an expired lease is not held");
        assert_eq!(c.step(l.expires_at, None, 7 << 32).send.unwrap().ask, Ask::Discover, "and the client asks anew");
    }

    #[test]
    fn a_short_lease_renews_before_rebinding_and_ignores_zero_length_extensions() {
        let mut c = bound(1);
        let held = *c.lease().unwrap();
        assert_eq!(held.rebind_at - held.renew_at, 375_000_000);
        assert_eq!(held.expires_at - held.renew_at, 500_000_000);
        let xid = c.step(held.renew_at, None, 12 << 32).send.unwrap().xid;
        assert_eq!(c.step(held.renew_at + 1, Some(&reply(Kind::Ack, xid, Some(0))), 0), Step::default());
        assert_eq!(c.lease(), Some(&held));
        assert_eq!(c.deadline(), held.rebind_at);
        assert_eq!(c.step(held.rebind_at, None, 13 << 32).send.unwrap().to, To::Broadcast);
        assert_eq!(c.step(held.expires_at, None, 14 << 32).event, Some(Event::Lost));
    }

    #[test]
    fn discover_offer_request_ack_binds() {
        let c = bound(86_400);
        let l = c.lease().unwrap();
        assert_eq!((l.renew_at, l.rebind_at, l.expires_at), (2 + 43_200 * SECOND, 2 + 75_600 * SECOND, 2 + 86_400 * SECOND));
        assert_eq!(c.deadline(), l.renew_at, "nothing to do until renewal");
    }

    #[test]
    fn answers_to_others_are_ignored() {
        let mut c = Client::new(MAC, 0);
        c.step(0, None, 7 << 32);
        assert_eq!(c.step(1, Some(&reply(Kind::Offer, 8, Some(60))), 0), Step::default(), "another transaction");
        let mut r = reply(Kind::Offer, 7, Some(60));
        r.chaddr = Mac([2; 6]);
        assert_eq!(c.step(1, Some(&r), 0), Step::default(), "another client");
        let mut r = reply(Kind::Offer, 7, Some(60));
        r.server = None;
        assert_eq!(c.step(1, Some(&r), 0), Step::default(), "an offer from nobody");
        assert_eq!(c.step(1, Some(&reply(Kind::Ack, 7, Some(60))), 0), Step::default(), "an ack before any request");
    }

    #[test]
    fn unanswered_discovers_back_off_to_a_minute() {
        let mut c = Client::new(MAC, 0);
        let mut now = 0;
        let mut waits = [0u64; 7];
        for w in waits.iter_mut() {
            let s = c.step(now, None, ((SECOND / 2) << 32) | SECOND);
            assert_eq!(s.send.unwrap().ask, Ask::Discover);
            assert_eq!(s.send.unwrap().secs as u64, now / SECOND, "secs counts from the first discover");
            *w = c.deadline() - now;
            now = c.deadline();
        }
        // Random part: SECOND % (2 * SECOND) = one second, so exactly the base.
        assert_eq!(waits.map(|w| w / SECOND), [4, 8, 16, 32, 64, 64, 64]);
    }

    #[test]
    fn an_unanswered_request_starts_over_and_a_nak_does_at_once() {
        let mut c = Client::new(MAC, 0);
        c.step(0, None, 7 << 32);
        c.step(1, Some(&reply(Kind::Offer, 7, Some(60))), 0);
        for _ in 1..SELECT_TRIES {
            let s = c.step(c.deadline(), None, 0);
            assert!(matches!(s.send.unwrap().ask, Ask::Select { .. }));
        }
        let s = c.step(c.deadline(), None, 9 << 32);
        assert_eq!(s.send.unwrap().ask, Ask::Discover, "four requests unanswered: start over");
        assert_eq!(c.xid(), 9);
        c.step(2, Some(&reply(Kind::Offer, 9, Some(60))), 0);
        let s = c.step(3, Some(&reply(Kind::Nak, 9, None)), 11 << 32);
        assert_eq!((s.send.unwrap().ask, s.event), (Ask::Discover, None), "refused before bound: nothing was lost");
    }

    #[test]
    fn an_ack_without_a_lease_time_is_not_taken() {
        let mut c = Client::new(MAC, 0);
        c.step(0, None, 7 << 32);
        c.step(1, Some(&reply(Kind::Offer, 7, Some(60))), 0);
        assert_eq!(c.step(2, Some(&reply(Kind::Ack, 7, None)), 0), Step::default());
        assert!(c.lease().is_none());
    }

    #[test]
    fn renewal_goes_to_the_server_then_rebinding_to_anyone_then_the_lease_ends() {
        let mut c = bound(1000);
        let l = *c.lease().unwrap();
        // Renewal at half the lease, to the server, with the address held.
        let s = c.step(l.renew_at, None, 21 << 32);
        let m = s.send.unwrap();
        assert_eq!((m.ask, m.to, m.xid), (Ask::Renew { address: ADDRESS }, To::Server(SERVER), 21));
        assert!(c.deadline() <= l.rebind_at);
        // Unanswered until rebinding: broadcast, a new transaction.
        let mut now = c.deadline();
        while now < l.rebind_at {
            assert_eq!(c.step(now, None, 21 << 32).send.unwrap().to, To::Server(SERVER));
            now = c.deadline();
        }
        let s = c.step(now, None, 33 << 32);
        assert_eq!((s.send.unwrap().to, s.send.unwrap().xid), (To::Broadcast, 33));
        // Unanswered until the end: the address is lost, discovery starts.
        let mut now = c.deadline();
        let mut last = Step::default();
        while last.event.is_none() {
            last = c.step(now, None, 44 << 32);
            now = c.deadline();
        }
        assert_eq!(last.event, Some(Event::Lost));
        assert_eq!(last.send.unwrap().ask, Ask::Discover);
        assert!(c.lease().is_none());
    }

    #[test]
    fn a_renewal_answered_extends_the_lease_and_a_nak_loses_it() {
        let mut c = bound(1000);
        let t = c.lease().unwrap().renew_at;
        let xid = c.step(t, None, 21 << 32).send.unwrap().xid;
        let s = c.step(t + 1, Some(&reply(Kind::Ack, xid, Some(1000))), 0);
        let Some(Event::Renewed(l)) = s.event else { panic!("{s:?}") };
        assert_eq!(l.expires_at, t + 1 + 1000 * SECOND);
        assert_eq!(c.deadline(), l.renew_at);
        let t = l.renew_at;
        let xid = c.step(t, None, 22 << 32).send.unwrap().xid;
        let s = c.step(t + 1, Some(&reply(Kind::Nak, xid, None)), 23 << 32);
        assert_eq!(s.event, Some(Event::Lost));
        assert_eq!(s.send.unwrap().ask, Ask::Discover);
    }

    #[test]
    fn a_lease_for_ever_is_never_renewed_and_odd_times_are_corrected() {
        let c = bound(u32::MAX);
        assert_eq!(c.deadline(), u64::MAX);
        let mut r = reply(Kind::Ack, 1, Some(100));
        r.renew = Some(90);
        r.rebind = Some(50);
        let l = lease_of(0, &r, SERVER).unwrap();
        assert_eq!((l.renew_at, l.rebind_at), (50 * SECOND, 87 * SECOND + SECOND / 2), "rebinding before renewal: the RFC's times");
        r.prefix = None;
        assert_eq!(lease_of(0, &r, SERVER).unwrap().prefix, 8, "10/8 when the server gives no netmask");
    }
}
