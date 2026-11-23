//! The client's half: a connection to a device's provider that outlives
//! the provider.
//!
//! A driver can end at any moment: it fails, or its owner restarts it. The
//! client hears of it at once (the device manager signals the client's
//! notification, `open`'s `gone`) or, when the device manager ended too and
//! its notice with it, within [`Queue::LIVENESS_NS`] of a request waiting
//! (the client's capability to the driver is gone), opens the driver that replaces it,
//! registers its memory again, and sends again every request that had not
//! completed. Completions the old driver had already written are still
//! delivered. To the program, a driver's end is a delay; a request is never
//! lost, and is never completed twice. (Requests sent again may be carried
//! out twice: a class whose requests may not be says so.)
//!
//! A class's client (`silica_block::client::Disk`) wraps a [`Queue`] with
//! its control protocol ([`Control`]) and its records.

use crate::{COMPLETION_BYTES, COMPLETIONS_AT, Completion, MEMORIES, QUEUE, REQUEST_BYTES, RINGS_BITS, Raw, Refused, tag_of};
use silica_idl_rt::{CallError, TransportError};
use silica_protocols::device::manager;
use silica_ring::{Consumer, Producer};
use silica_rt::alloc::boxed::Box;
use silica_rt::alloc::collections::VecDeque;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle, free_slot, release_slot};
use silica_rt::mem::{Memory, Object};
use silica_rt::slots;
use silica_rt::sys::{self, Cap, ObjectType, Rights, Wait};

/// Why something a client asked for did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The provider refused.
    Refused(Refused),
    /// The device has no driver, and none came back within
    /// [`Queue::RECONNECT_NS`].
    Gone,
    /// The provider broke the protocol (a malformed reply, a ring that
    /// makes no sense).
    Protocol,
    /// This program has no memory or capability slots left for it.
    NoMemory,
    /// [`QUEUE`] requests are in progress, or the tag is in use.
    Full,
    /// No completion arrived before the deadline.
    Timeout,
}

impl<E> From<CallError<E>> for Error
where
    Error: From<E>,
{
    fn from(e: CallError<E>) -> Error {
        match e {
            CallError::Error(e) => e.into(),
            CallError::Transport(TransportError::PeerGone | TransportError::Revoked) => Error::Gone,
            CallError::Transport(_) => Error::Protocol,
        }
    }
}

impl From<manager::Error> for Error {
    fn from(_: manager::Error) -> Error {
        Error::Gone
    }
}

impl From<core::convert::Infallible> for Error {
    fn from(e: core::convert::Infallible) -> Error {
        match e {}
    }
}

impl From<sys::Error> for Error {
    fn from(_: sys::Error) -> Error {
        Error::NoMemory
    }
}

impl From<Refused> for Error {
    fn from(r: Refused) -> Error {
        Error::Refused(r)
    }
}

/// Where a client finds its device's provider: the device manager, or
/// another provider of devices (the partitions of disks).
pub trait Opener {
    /// A capability to the provider of device `id`, which signals `gone`
    /// when it ends.
    fn open(&mut self, id: u32, gone: Handle) -> Result<Handle, Error>;
}

impl Opener for manager::Client<Channel, Handle> {
    fn open(&mut self, id: u32, gone: Handle) -> Result<Handle, Error> {
        Ok(manager::Client::open(self, id, Some(gone))?.driver)
    }
}

/// A class's control protocol, as the queue uses it: normally a thin
/// wrapper of the generated client of `silica.<class>.Device`.
pub trait Control: Sized {
    /// The control protocol through `provider`, the capability an
    /// [`Opener`] gave; it also learns what the device is.
    fn open(provider: Handle) -> Result<Self, Error>;
    /// The class's `connect`: returns what wakes the provider.
    fn connect(&mut self, rings: Handle, completions: Handle) -> Result<Handle, Error>;
    /// The class's `add_memory`.
    fn add_memory(&mut self, id: u32, frame: Handle, writable: bool) -> Result<(), Error>;
    /// The class's `remove_memory`.
    fn remove_memory(&mut self, id: u32) -> Result<(), Error>;
}

/// Bit of the client's notification the driver signals for completions;
/// the death notice of the connection numbered `g` is [`gone_bit`]`(g)`, so
/// a late notice about a driver already replaced is told apart.
const COMPLETED: u64 = 1;

fn gone_bit(generation: u32) -> u64 {
    1 << (1 + generation % 63)
}

/// Tags from here up are a provider's events (`provider::Session::event`),
/// not completions: a client's own tags are below it.
pub const EVENTS: u64 = 1 << 63;

/// The requests in flight, by tag: an open-addressed table with twice the
/// most there can be, so a lookup is a probe or two (a `BTreeMap` here cost
/// a tenth of the throughput at depth 32).
struct InFlight {
    slots: Vec<Option<Raw>>,
    len: usize,
}

impl InFlight {
    const SIZE: usize = 2 * QUEUE as usize;

    fn new() -> Result<InFlight, Error> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(Self::SIZE).map_err(|_| Error::NoMemory)?;
        slots.resize(Self::SIZE, None);
        Ok(InFlight { slots, len: 0 })
    }

    fn home(tag: u64) -> usize {
        (tag.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 55) as usize & (Self::SIZE - 1)
    }

    fn find(&self, tag: u64) -> Option<usize> {
        let mut at = Self::home(tag);
        loop {
            match &self.slots[at] {
                Some(r) if tag_of(r) == tag => return Some(at),
                Some(_) => at = (at + 1) & (Self::SIZE - 1),
                None => return None,
            }
        }
    }

    fn contains(&self, tag: u64) -> bool {
        self.find(tag).is_some()
    }

    /// Insert `r`; its tag is not in the table and the table is not full.
    fn insert(&mut self, r: Raw) {
        let mut at = Self::home(tag_of(&r));
        while self.slots[at].is_some() {
            at = (at + 1) & (Self::SIZE - 1);
        }
        self.slots[at] = Some(r);
        self.len += 1;
    }

    fn remove(&mut self, tag: u64) -> Option<Raw> {
        let mut hole = self.find(tag)?;
        let removed = self.slots[hole].take();
        self.len -= 1;
        // Shift later entries of the run back, so no probe stops early.
        let mut at = (hole + 1) & (Self::SIZE - 1);
        while let Some(r) = self.slots[at] {
            let home = Self::home(tag_of(&r));
            // Whether `home` lies cyclically in (hole, at]: if not, the
            // entry may move into the hole.
            let stays = if hole <= at { hole < home && home <= at } else { hole < home || home <= at };
            if !stays {
                self.slots[hole] = self.slots[at].take();
                hole = at;
            }
            at = (at + 1) & (Self::SIZE - 1);
        }
        removed
    }

    fn iter(&self) -> impl Iterator<Item = &Raw> {
        self.slots.iter().flatten()
    }
}

/// One connection to one driver.
struct Link<C> {
    control: C,
    requests: Producer<REQUEST_BYTES>,
    completions: Consumer<COMPLETION_BYTES>,
    /// Signalled when the driver must look at the request ring.
    wake: Handle,
}

/// A connection to a device that outlives its driver.
pub struct Queue<C: Control> {
    // The generated clients carry their message buffers (4 KB each): boxed,
    // so a queue is small to keep and to move.
    devices: Box<dyn Opener>,
    id: u32,
    /// The frame of the two rings, reused (cleared) for each driver.
    rings: Memory,
    link: Option<Box<Link<C>>>,
    /// What the driver signals (bit COMPLETED) and the device manager
    /// signals when the driver ends (`gone_bit(generation)`).
    note: Object,
    /// Counts connections.
    generation: u32,
    /// Registered memory: the frame and whether the device may write it.
    memories: Vec<Option<(Cap, bool)>>,
    /// Requests sent and not yet completed, by tag.
    in_flight: InFlight,
    /// Completions taken from a driver's ring and not yet returned.
    ready: VecDeque<Completion>,
    /// When the driver last ended (monotonic ns; 0: not since connecting),
    /// and how long the last recovery took.
    lost_at: u64,
    recovered_in: Option<u64>,
    /// When the driver was last looked for (`LIVENESS_NS`).
    checked_at: u64,
}

/// A capability of this program's own, derived from `cap` with `rights`
/// and `badge`, to give away.
pub fn lend(cap: Cap, rights: Rights, badge: u64) -> Result<Handle, Error> {
    let slot = free_slot().ok_or(Error::NoMemory)?;
    sys::cap_derive(slots::SPACE, slot, cap, rights, badge).inspect_err(|_| release_slot(slot))?;
    Ok(Handle::new(Cap(slot)))
}

impl<C: Control> Queue<C> {
    /// The most requests in progress at once.
    pub const QUEUE: u32 = QUEUE;
    /// How long a driver that ended has to come back before requests fail
    /// with [`Error::Gone`].
    pub const RECONNECT_NS: u64 = 5_000_000_000;
    /// How often a client with requests in flight and none completing
    /// looks whether its driver is still there, for the end no notice
    /// reports: the device manager's own, which takes its drivers with it.
    pub const LIVENESS_NS: u64 = 10_000_000;

    /// Open the device with identity `id` through the device manager behind
    /// `devices` (a capability to its endpoint; the queue keeps it to find
    /// the next driver when this one ends).
    pub fn open(devices: Cap, id: u32) -> Result<Queue<C>, Error> {
        Queue::open_with(Box::new(manager::Client::<Channel, Handle>::from(Channel::new(devices))), id)
    }

    /// Open device `id` through `opener` (which the queue keeps, to find
    /// the next provider when this one ends).
    pub fn open_with(devices: Box<dyn Opener>, id: u32) -> Result<Queue<C>, Error> {
        let mut memories = Vec::new();
        memories.try_reserve_exact(MEMORIES as usize).map_err(|_| Error::NoMemory)?;
        memories.resize(MEMORIES as usize, None);
        let mut q = Queue {
            devices,
            id,
            rings: Memory::new(RINGS_BITS)?,
            link: None,
            note: Object::new(ObjectType::Notification, 0)?,
            generation: 0,
            memories,
            in_flight: InFlight::new()?,
            ready: VecDeque::new(),
            lost_at: 0,
            recovered_in: None,
            checked_at: 0,
        };
        q.connect()?;
        Ok(q)
    }

    /// Open the current driver and set the connection up: rings, memory,
    /// and every request still in flight sent again.
    fn connect(&mut self) -> Result<(), Error> {
        self.generation = self.generation.wrapping_add(1);
        let gone = lend(self.note.cap(), Rights::WRITE, gone_bit(self.generation))?;
        let mut control = C::open(self.devices.open(self.id, gone)?)?;
        // The rings start empty: the last driver can no longer touch them.
        let region = self.rings.shared();
        for at in (0..region.len()).step_by(8) {
            region.write64(at, 0);
        }
        let wake = control.connect(lend(self.rings.frame(), Rights(3), 0)?, lend(self.note.cap(), Rights::WRITE, COMPLETED)?)?;
        let (Some(req), Some(cpl)) = (region.part(0, COMPLETIONS_AT), region.part(COMPLETIONS_AT, region.len() - COMPLETIONS_AT)) else {
            return Err(Error::Protocol);
        };
        let (Some(requests), Some(completions)) = (Producer::new(req, QUEUE), Consumer::new(cpl, QUEUE)) else {
            return Err(Error::Protocol);
        };
        let mut link = Box::new(Link { control, requests, completions, wake });
        for (id, m) in self.memories.iter().enumerate() {
            if let Some((frame, writable)) = *m {
                let rights = Rights(Rights::READ.0 | if writable { Rights::WRITE.0 } else { 0 });
                link.control.add_memory(id as u32, lend(frame, rights, 0)?, writable)?;
            }
        }
        for r in self.in_flight.iter() {
            link.requests.push(r).map_err(|_| Error::Protocol)?;
        }
        self.link = Some(link);
        self.kick();
        Ok(())
    }

    /// With requests in flight, every [`Self::LIVENESS_NS`]: whether the
    /// driver is still there. A driver's objects go with it, and with them
    /// every capability the client was given to them (the slot empties).
    fn look(&mut self) {
        let now = silica_rt::clock().now();
        if self.in_flight.len == 0 || now - self.checked_at < Self::LIVENESS_NS {
            return;
        }
        self.checked_at = now;
        if self.link.as_ref().is_some_and(|l| !matches!(sys::inspect_slot(slots::SPACE, l.wake.cap().0), Ok(Some(_)))) {
            self.link = None;
        }
    }

    /// The deadline of a wait: the caller's, or sooner while requests are
    /// in flight, so that a driver's unannounced end is seen.
    fn until(&self, deadline: Option<u64>) -> (Wait, bool) {
        if self.in_flight.len == 0 {
            return (deadline.map_or(Wait::Forever, Wait::Until), false);
        }
        let look = silica_rt::clock().now() + Self::LIVENESS_NS;
        match deadline {
            Some(d) if d <= look => (Wait::Until(d), false),
            _ => (Wait::Until(look), true),
        }
    }

    /// The driver ended: take what it completed, and connect to the next.
    fn recover(&mut self) -> Result<(), Error> {
        let clock = silica_rt::clock();
        if self.lost_at == 0 {
            self.lost_at = clock.now();
        }
        if let Some(mut link) = self.link.take() {
            // Completions it wrote before it ended are as good as any.
            while let Ok(Some(raw)) = link.completions.pop() {
                let c = Completion::decode(&raw);
                if c.tag >= EVENTS || self.in_flight.remove(c.tag).is_some() {
                    self.ready.push_back(c);
                }
            }
        }
        let deadline = self.lost_at + Self::RECONNECT_NS;
        loop {
            match self.connect() {
                Ok(()) => return Ok(()),
                // Not back yet: the device manager is starting it again.
                Err(Error::Gone) if clock.now() < deadline => sys::yield_now(),
                Err(e) => return Err(e),
            }
        }
    }

    /// The link to the driver, connecting again first if the last one ended.
    fn link(&mut self) -> Result<&mut Box<Link<C>>, Error> {
        if self.link.is_none() {
            self.recover()?;
        }
        self.link.as_mut().ok_or(Error::Gone)
    }

    /// The class's control protocol of the current driver, connecting again
    /// first if the last one ended.
    pub fn control(&mut self) -> Result<&mut C, Error> {
        Ok(&mut self.link()?.control)
    }

    /// How long the last recovery from a driver's end took, from the end
    /// being noticed to the first completion after it (ns), once: the next
    /// call says `None` until there is another.
    pub fn take_recovery(&mut self) -> Option<u64> {
        self.recovered_in.take()
    }

    /// Register `memory` under the number `id` (below [`MEMORIES`]):
    /// requests may name data in it from then on, for as long as it stays
    /// registered (the caller keeps `memory` alive until
    /// [`Queue::remove_memory`]). With `writable` the device may write it.
    pub fn add_memory(&mut self, id: u32, memory: &Memory, writable: bool) -> Result<(), Error> {
        let slot = self.memories.get(id as usize).ok_or(Error::Refused(Refused::BadMemory))?;
        if slot.is_some() {
            return Err(Error::Refused(Refused::BadMemory));
        }
        let rights = Rights(Rights::READ.0 | if writable { Rights::WRITE.0 } else { 0 });
        loop {
            let lent = lend(memory.frame(), rights, 0)?;
            match self.link()?.control.add_memory(id, lent, writable) {
                Ok(()) => break,
                Err(Error::Gone) => self.link = None,
                Err(e) => return Err(e),
            }
        }
        self.memories[id as usize] = Some((memory.frame(), writable));
        Ok(())
    }

    /// Withdraw the registration `id`.
    pub fn remove_memory(&mut self, id: u32) -> Result<(), Error> {
        match self.link()?.control.remove_memory(id) {
            Ok(()) => {}
            // The next driver is not told about it at all.
            Err(Error::Gone) => self.link = None,
            Err(e) => return Err(e),
        }
        if let Some(m) = self.memories.get_mut(id as usize) {
            *m = None;
        }
        Ok(())
    }

    /// How many requests are in progress.
    pub fn in_progress(&self) -> u32 {
        self.in_flight.len as u32
    }

    /// Put a request record in the ring. The driver is told by
    /// [`Queue::kick`], once for any number of requests. Its tag must be
    /// below [`EVENTS`] and not in use.
    pub fn submit(&mut self, request: &Raw) -> Result<(), Error> {
        let tag = tag_of(request);
        if self.in_flight.len as u32 >= QUEUE || tag >= EVENTS || self.in_flight.contains(tag) {
            return Err(Error::Full);
        }
        self.link()?.requests.push(request).map_err(|_| Error::Full)?;
        self.in_flight.insert(*request);
        Ok(())
    }

    /// Tell the driver about submitted requests, if it sleeps.
    pub fn kick(&mut self) {
        let Some(link) = self.link.as_mut() else { return };
        if link.requests.wake_needed() && sys::signal(link.wake.cap()).is_err() {
            // Its notification is gone with it: the death notice follows.
            self.link = None;
        }
    }

    /// The next completion (or provider's event: a tag from [`EVENTS`]
    /// up), if one is there.
    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        if let Some(c) = self.ready.pop_front() {
            return Ok(Some(c));
        }
        let Some(link) = self.link.as_mut() else {
            self.recover()?;
            return Ok(self.ready.pop_front());
        };
        loop {
            match link.completions.pop() {
                Ok(Some(raw)) => {
                    let c = Completion::decode(&raw);
                    if c.tag >= EVENTS {
                        return Ok(Some(c));
                    }
                    // Only a request in flight completes, and only once.
                    if self.in_flight.remove(c.tag).is_none() {
                        continue;
                    }
                    if self.lost_at != 0 {
                        self.recovered_in = Some(silica_rt::clock().now() - self.lost_at);
                        self.lost_at = 0;
                    }
                    return Ok(Some(c));
                }
                Ok(None) => break,
                Err(_) => return Err(Error::Protocol),
            }
        }
        self.look();
        Ok(None)
    }

    /// [`Queue::kick`] and [`Queue::wait`] together: when the client has
    /// to sleep, the driver's wake-up and the client's wait are one system
    /// call (`libsys::signal_recv`), so a driver on the same processor runs
    /// at once, and the processor is not shared with a client about to
    /// wait. What a request and its answer cost the processor.
    pub fn kick_wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        let mut wake = self.link.as_mut().filter(|l| l.requests.wake_needed()).map(|l| l.wake.cap());
        loop {
            if let Some(c) = self.poll()? {
                if let Some(w) = wake
                    && sys::signal(w).is_err()
                {
                    self.link = None;
                }
                return Ok(c);
            }
            let asleep = self.link.as_mut().is_some_and(|l| l.completions.sleep());
            if !asleep {
                continue;
            }
            let w = wake.take().unwrap_or(Cap::NONE);
            let (until, mine) = self.until(deadline);
            match sys::signal_recv(w, self.note.cap(), Cap::NONE, until) {
                Ok(m) if m.badge & gone_bit(self.generation) != 0 => self.link = None,
                Ok(_) => {}
                Err(sys::Error::Timeout) if mine => self.look(),
                // The wake-up failed, and nothing was received: the
                // driver's notification is gone with it (its death notice
                // follows).
                Err(e) if w != Cap::NONE && e != sys::Error::Timeout && sys::signal(w).is_err() => self.link = None,
                Err(_) => return Err(Error::Timeout),
            }
        }
    }

    /// The next completion, waiting for it until the monotonic time
    /// `deadline` (nanoseconds; `None`: for ever).
    pub fn wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        loop {
            if let Some(c) = self.poll()? {
                return Ok(c);
            }
            let asleep = self.link.as_mut().is_some_and(|l| l.completions.sleep());
            if !asleep {
                continue;
            }
            let (until, mine) = self.until(deadline);
            match sys::recv(self.note.cap(), until) {
                Ok(m) if m.badge & gone_bit(self.generation) != 0 => self.link = None,
                Ok(_) => {}
                Err(sys::Error::Timeout) if mine => self.look(),
                Err(_) => return Err(Error::Timeout),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(tag: u64) -> Raw {
        let mut raw = [0u8; REQUEST_BYTES];
        raw[24..32].copy_from_slice(&tag.to_le_bytes());
        raw
    }

    /// Against a plain list: every insert and removal, in a mixed order,
    /// leaves the table holding exactly what the list holds.
    #[test]
    fn the_in_flight_table_holds_what_was_put_in_and_not_taken_out() {
        let mut t = InFlight::new().unwrap();
        let mut model: Vec<u64> = Vec::new();
        let mut x = 12345u64;
        for step in 0..200_000u64 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            // Tags that collide in the table's home slots on purpose.
            let tag = (x >> 33) % 600 * if step % 3 == 0 { 512 } else { 1 };
            if model.contains(&tag) {
                assert_eq!(t.remove(tag).map(|r| tag_of(&r)), Some(tag));
                model.retain(|m| *m != tag);
            } else if model.len() < QUEUE as usize {
                t.insert(r(tag));
                model.push(tag);
            }
            assert_eq!(t.len, model.len());
            if step % 1000 == 0 {
                for m in &model {
                    assert!(t.contains(*m));
                }
                assert_eq!(t.iter().count(), model.len());
            }
        }
    }
}
