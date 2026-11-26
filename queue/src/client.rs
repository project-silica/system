//! The client's half: a connection to a device's provider that outlives
//! the provider.
//!
//! A driver can end at any moment: it fails, or its owner restarts it. The
//! client hears of it at once: the device manager signals the client's
//! notification (`open`'s `gone`), and so does the kernel when the client's
//! capability to the driver's wake-up goes with the driver's objects
//! (`libsys::cap_notice`), which covers the device manager ending too and
//! taking its drivers with it. Nothing is polled: a client waiting for
//! frames that may never come wakes for nothing else. It opens the driver that replaces it,
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
    /// [`QUEUE`] requests are in progress, the tag is in use, or a
    /// ringful of saved results must be polled before reconnecting.
    Full,
    /// No completion arrived before the deadline.
    Timeout,
    /// An argument the caller gave cannot be used (bits of a notification
    /// past its 64: [`Queue::open_on`]).
    BadArgument,
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

/// The bits of the client's notification the queue uses: the first is
/// what the driver signals for completions, and the death notice of the
/// connection numbered `g` is [`Bits::gone`]`(g)`, one of the rest by turns,
/// so a late notice about a driver already replaced is told apart. A queue
/// with a notification of its own uses all 64; one that shares its
/// client's ([`Queue::open_on`]) uses [`SHARED_BITS`] of them.
#[derive(Clone, Copy, Debug)]
struct Bits {
    first: u32,
    count: u32,
}

impl Bits {
    const OWN: Bits = Bits { first: 0, count: 64 };

    fn completed(self) -> u64 {
        1 << self.first
    }

    fn gone(self, generation: u32) -> u64 {
        1 << (self.first + 1 + generation % (self.count - 1))
    }

    fn all(self) -> u64 {
        if self.count == 64 { u64::MAX } else { ((1u64 << self.count) - 1) << self.first }
    }
}

/// Bits of a shared notification a queue uses ([`Queue::open_on`]).
pub const SHARED_BITS: u32 = 8;

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
    /// The kernel's notice of `wake` going (`cap_notice`). Declared before
    /// `wake`, so dropped first: a link the client ends is no driver's end,
    /// and deleting `wake` while watched would wake the client for nothing.
    /// (Already empty when the driver's end fired it.)
    _notice: Handle,
    /// Signalled when the driver must look at the request ring.
    wake: Handle,
}

/// How a recovery from a driver's end went, in monotonic nanoseconds from
/// the client noticing the end: until the next driver took the connection
/// (the device manager stopping the old one and starting the next, and the
/// next starting up), and in all, to the first completion after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub total: u64,
    pub reconnecting: u64,
    /// Connections tried before one was taken.
    pub tries: u32,
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
    /// What the driver signals (`bits.completed()`) and the device manager
    /// signals when the driver ends (`bits.gone(generation)`): the queue's
    /// own, or its client's (`open_on`), which then owns it.
    note: Cap,
    /// The queue's own notification, kept while the queue lives.
    _own_note: Option<Object>,
    bits: Bits,
    /// Counts connections.
    generation: u32,
    /// Registered memory: the frame and whether the device may write it.
    memories: Vec<Option<(Cap, bool)>>,
    /// Requests sent and not yet completed, by tag.
    in_flight: InFlight,
    /// Completions taken from a driver's ring and not yet returned.
    ready: VecDeque<Completion>,
    /// When the driver last ended (monotonic ns; 0: not since connecting),
    /// when the next one took the connection and after how many tries, and
    /// how the last recovery went.
    lost_at: u64,
    reconnected_at: u64,
    tries: u32,
    recovered_in: Option<Recovery>,
    /// While there is no driver: when to try the next one, and the wait
    /// before that (doubling from [`FIRST_TRY_NS`] to [`LAST_TRY_NS`]).
    next_try: u64,
    backoff: u64,
    /// What a call that cannot go on without a driver sleeps on between
    /// tries: signalled by nobody.
    nap: Object,
}

/// How long after a failed try to connect again, at first and at most: a
/// driver takes from a millisecond to some tens to come back, and nothing
/// tells the queue when it has (the waiting is a sleep, not a spin).
const FIRST_TRY_NS: u64 = 50_000;
const LAST_TRY_NS: u64 = 4_000_000;

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

    /// Open the device with identity `id` through the device manager behind
    /// `devices` (a capability to its endpoint; the queue keeps it to find
    /// the next driver when this one ends).
    pub fn open(devices: Cap, id: u32) -> Result<Queue<C>, Error> {
        Queue::open_with(Box::new(manager::Client::<Channel, Handle>::from(Channel::new(devices))), id)
    }

    /// Open device `id` through `opener` (which the queue keeps, to find
    /// the next provider when this one ends).
    pub fn open_with(devices: Box<dyn Opener>, id: u32) -> Result<Queue<C>, Error> {
        let note = Object::new(ObjectType::Notification, 0)?;
        Queue::open_noting(devices, id, note.cap(), Some(note), Bits::OWN)
    }

    /// Open device `id` through the device manager behind `devices`,
    /// signalled on the caller's notification `note`, bits `first` to
    /// `first + SHARED_BITS - 1` (from 0 to 56): for a program that waits
    /// for more than this queue at once (a server that is also a driver's
    /// client), in its own wait. It hands the queue every signal on those
    /// bits ([`Queue::signalled`], which is how it hears of a driver's end)
    /// and asks it before waiting ([`Queue::sleep`]); [`Queue::wait`] and
    /// [`Queue::kick_wait`] are not for such a queue.
    pub fn open_on(devices: Cap, id: u32, note: Cap, first: u32) -> Result<Queue<C>, Error> {
        if first > 64 - SHARED_BITS {
            return Err(Error::BadArgument);
        }
        let opener = Box::new(manager::Client::<Channel, Handle>::from(Channel::new(devices)));
        Queue::open_noting(opener, id, note, None, Bits { first, count: SHARED_BITS })
    }

    fn open_noting(devices: Box<dyn Opener>, id: u32, note: Cap, own_note: Option<Object>, bits: Bits) -> Result<Queue<C>, Error> {
        let mut memories = Vec::new();
        memories.try_reserve_exact(MEMORIES as usize).map_err(|_| Error::NoMemory)?;
        memories.resize(MEMORIES as usize, None);
        let mut q = Queue {
            devices,
            id,
            rings: Memory::new(RINGS_BITS)?,
            link: None,
            note,
            _own_note: own_note,
            bits,
            generation: 0,
            memories,
            in_flight: InFlight::new()?,
            ready: VecDeque::new(),
            lost_at: 0,
            reconnected_at: 0,
            tries: 0,
            recovered_in: None,
            next_try: 0,
            backoff: 0,
            nap: Object::new(ObjectType::Notification, 0)?,
        };
        q.connect()?;
        Ok(q)
    }

    /// Open the current driver and set the connection up: rings, memory,
    /// and every request still in flight sent again.
    fn connect(&mut self) -> Result<(), Error> {
        self.generation = self.generation.wrapping_add(1);
        let gone = lend(self.note, Rights::WRITE, self.bits.gone(self.generation))?;
        let mut control = C::open(self.devices.open(self.id, gone)?)?;
        // The rings start empty: the last driver can no longer touch them.
        let region = self.rings.shared();
        for at in (0..region.len()).step_by(8) {
            region.write64(at, 0);
        }
        let wake = control.connect(lend(self.rings.frame(), Rights(3), 0)?, lend(self.note, Rights::WRITE, self.bits.completed())?)?;
        let (Some(req), Some(cpl)) = (region.part(0, COMPLETIONS_AT), region.part(COMPLETIONS_AT, region.len() - COMPLETIONS_AT)) else {
            return Err(Error::Protocol);
        };
        let (Some(requests), Some(completions)) = (Producer::new(req, QUEUE), Consumer::new(cpl, QUEUE)) else {
            return Err(Error::Protocol);
        };
        // The kernel says when the driver's wake-up goes (the driver ended,
        // or the device manager and every driver with it), with this
        // connection's death notice.
        let notice = Handle::new(Cap(free_slot().ok_or(Error::NoMemory)?));
        sys::cap_notice(wake.cap(), self.note, notice.cap(), self.bits.gone(self.generation))?;
        let mut link = Box::new(Link { control, requests, completions, _notice: notice, wake });
        for (id, m) in self.memories.iter().enumerate() {
            if let Some((frame, writable)) = *m {
                let rights = Rights(Rights::READ.0 | if writable { Rights::WRITE.0 } else { 0 });
                link.control.add_memory(id as u32, lend(frame, rights, 0)?, writable)?;
            }
        }
        for r in self.in_flight.iter() {
            if !self.ready.iter().any(|c| c.tag == tag_of(r)) {
                link.requests.push(r).map_err(|_| Error::Protocol)?;
            }
        }
        self.link = Some(link);
        self.kick();
        Ok(())
    }

    /// Keep published results before dropping the consumer. Their tags
    /// remain in use until the caller takes them, including across reconnect.
    fn disconnect(&mut self) {
        if let Some(mut link) = self.link.take() {
            if self.lost_at == 0 {
                self.lost_at = silica_rt::clock().now();
            }
            for _ in 0..QUEUE {
                let Ok(Some(raw)) = link.completions.pop() else { break };
                let c = Completion::decode(&raw);
                if c.tag >= EVENTS || (self.in_flight.contains(c.tag) && !self.ready.iter().any(|r| r.tag == c.tag)) {
                    self.ready.push_back(c);
                }
            }
        }
    }

    /// One try to connect to the next driver, if one is due: `true` once
    /// connected (or never disconnected), `false` when the next try is at
    /// [`Queue::retry_at`], `Gone` once [`Queue::RECONNECT_NS`] have passed
    /// without one. Never waits: a service that is also a driver's client
    /// goes on serving its own clients while the driver restarts.
    fn try_recover(&mut self) -> Result<bool, Error> {
        if self.link.is_some() {
            return Ok(true);
        }
        // Keep room for the next driver's entire completion ring. An
        // application doing only control calls across repeated restarts
        // must consume queued events before they grow without bound.
        if self.ready.len() >= QUEUE as usize {
            return Err(Error::Full);
        }
        let now = silica_rt::clock().now();
        if self.lost_at == 0 {
            self.lost_at = now;
        }
        if now < self.next_try {
            return Ok(false);
        }
        self.tries += 1;
        match self.connect() {
            Ok(()) => {
                let now = silica_rt::clock().now();
                self.reconnected_at = now;
                (self.next_try, self.backoff) = (0, 0);
                // Nothing was sent to the new driver again (every
                // request in flight had its result saved): there is no
                // completion to wait for, so the recovery ends here.
                if self.in_flight.iter().all(|r| self.ready.iter().any(|c| c.tag == tag_of(r))) {
                    self.recovered(now);
                }
                Ok(true)
            }
            // Not back yet: the device manager is starting it again.
            Err(Error::Gone) if now < self.lost_at + Self::RECONNECT_NS => {
                self.backoff = (self.backoff * 2).clamp(FIRST_TRY_NS, LAST_TRY_NS);
                self.next_try = now + self.backoff;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Wait for the next driver: for what cannot go on without one (a
    /// control call, registering memory). Sleeps between tries.
    fn recover(&mut self) -> Result<(), Error> {
        while !self.try_recover()? {
            let _ = sys::recv(self.nap.cap(), Wait::Until(self.next_try));
        }
        Ok(())
    }

    /// With no driver: sleep until the next try, or `deadline` (then
    /// `Timeout`), whichever comes first.
    fn nap_until(&mut self, deadline: Option<u64>) -> Result<(), Error> {
        let until = deadline.map_or(self.next_try, |d| d.min(self.next_try));
        if deadline.is_some_and(|d| silica_rt::clock().now() >= d) {
            return Err(Error::Timeout);
        }
        let _ = sys::recv(self.nap.cap(), Wait::Until(until));
        Ok(())
    }

    /// While the driver is away and its successor not yet connected: when
    /// to look again ([`Queue::poll`] tries then). A client on its own
    /// notification ([`Queue::open_on`]) waits no later than this.
    pub fn retry_at(&self) -> Option<u64> {
        self.link.is_none().then_some(self.next_try)
    }

    /// A recovery in progress ended at `now`: keep how it went.
    fn recovered(&mut self, now: u64) {
        if self.lost_at != 0 {
            let reconnected = self.reconnected_at.max(self.lost_at);
            self.recovered_in = Some(Recovery { total: now - self.lost_at, reconnecting: reconnected - self.lost_at, tries: self.tries });
            self.lost_at = 0;
            self.tries = 0;
        }
    }

    /// The link to the driver, connecting again first if the last one ended.
    fn link(&mut self) -> Result<&mut Box<Link<C>>, Error> {
        if self.link.is_none() {
            self.recover()?;
        }
        self.link.as_mut().ok_or(Error::Gone)
    }

    /// How many drivers this queue has connected to: it changes when a
    /// driver ended and the next took the connection (a client that must
    /// know whether a reset came between two of its requests compares it).
    pub fn connections(&self) -> u32 {
        self.generation
    }

    /// The class's control protocol of the current driver, connecting again
    /// first if the last one ended.
    pub fn control(&mut self) -> Result<&mut C, Error> {
        Ok(&mut self.link()?.control)
    }

    /// How the last recovery from a driver's end went, once: the next call
    /// says `None` until there is another.
    pub fn take_recovery(&mut self) -> Option<Recovery> {
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
                Err(Error::Gone) => self.disconnect(),
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
            Err(Error::Gone) => self.disconnect(),
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
        if !self.try_recover()? {
            // The next driver is on its way: the request waits with those
            // in flight, all sent to it when it connects.
            self.in_flight.insert(*request);
            return Ok(());
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
            self.disconnect();
        }
    }

    /// For a queue on its client's notification ([`Queue::open_on`]):
    /// the client received `bits` on it; the queue takes what is its own (a
    /// driver's death notice). Completions are then taken with
    /// [`Queue::poll`].
    pub fn signalled(&mut self, bits: u64) {
        if bits & self.bits.all() & self.bits.gone(self.generation) != 0 {
            self.disconnect();
        }
    }

    /// Before its client waits: wakes the driver if it has requests to
    /// look at, and says that the client sleeps. `false`: do not wait,
    /// something is there already (take it with [`Queue::poll`]).
    pub fn sleep(&mut self) -> bool {
        self.kick();
        if !self.ready.is_empty() {
            return false;
        }
        match self.link.as_mut() {
            Some(link) => link.completions.sleep(),
            // Connecting again happens in `poll`, at `retry_at`, which the
            // client waits no later than.
            None => true,
        }
    }

    /// The next completion (or provider's event: a tag from [`EVENTS`]
    /// up), if one is there.
    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        if let Some(c) = self.take()? {
            return Ok(Some(c));
        }
        // Nothing completed: a driver's end may have been noticed meanwhile.
        // A queue with a notification of its own takes what is there without
        // waiting (a client that only polls hears of the end here); one that
        // shares its caller's is told by the caller (`signalled`). (Not in
        // `wait` and `kick_wait`, which receive from it themselves: there it
        // was a system call more per request, 147 ns of a 3.8 us block read.)
        if self._own_note.is_some()
            && let Ok(m) = sys::recv(self.note, Wait::Poll)
            && m.badge & self.bits.gone(self.generation) != 0
        {
            self.disconnect();
        }
        Ok(None)
    }

    /// The next completion if one is there, connecting again first if the
    /// driver ended.
    fn take(&mut self) -> Result<Option<Completion>, Error> {
        if let Some(c) = self.ready.pop_front() {
            if c.tag < EVENTS {
                self.in_flight.remove(c.tag);
            }
            return Ok(Some(c));
        }
        if !self.try_recover()? {
            return Ok(None);
        }
        let Some(link) = self.link.as_mut() else { return Ok(None) };
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
                    self.recovered(silica_rt::clock().now());
                    return Ok(Some(c));
                }
                Ok(None) => break,
                Err(_) => return Err(Error::Protocol),
            }
        }
        Ok(None)
    }

    /// [`Queue::kick`] and [`Queue::wait`] together: when the client has
    /// to sleep, the driver's wake-up and the client's wait are one system
    /// call (`libsys::signal_recv`), so a driver on the same processor runs
    /// at once, and the processor is not shared with a client about to
    /// wait. What a request and its answer cost the processor.
    pub fn kick_wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        let mut kick = true;
        loop {
            if let Some(c) = self.take()? {
                if kick {
                    self.kick();
                }
                return Ok(c);
            }
            if self.link.is_none() {
                self.nap_until(deadline)?;
                continue;
            }
            let asleep = self.link.as_mut().is_some_and(|l| l.completions.sleep());
            if !asleep {
                continue;
            }
            let w = self.link.as_ref().filter(|l| kick && l.requests.wake_needed()).map_or(Cap::NONE, |l| l.wake.cap());
            kick = false;
            match sys::signal_recv(w, self.note, Cap::NONE, deadline.map_or(Wait::Forever, Wait::Until)) {
                Ok(m) if m.badge & self.bits.gone(self.generation) != 0 => self.disconnect(),
                Ok(_) => {}
                // The wake-up failed, and nothing was received: the
                // driver's notification is gone with it (its death notice
                // follows).
                Err(e) if w != Cap::NONE && e != sys::Error::Timeout && sys::signal(w).is_err() => self.disconnect(),
                Err(_) => return Err(Error::Timeout),
            }
        }
    }

    /// The next completion, waiting for it until the monotonic time
    /// `deadline` (nanoseconds; `None`: for ever).
    pub fn wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        loop {
            if let Some(c) = self.take()? {
                return Ok(c);
            }
            if self.link.is_none() {
                self.nap_until(deadline)?;
                continue;
            }
            let asleep = self.link.as_mut().is_some_and(|l| l.completions.sleep());
            if !asleep {
                continue;
            }
            match sys::recv(self.note, deadline.map_or(Wait::Forever, Wait::Until)) {
                Ok(m) if m.badge & self.bits.gone(self.generation) != 0 => self.disconnect(),
                Ok(_) => {}
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
