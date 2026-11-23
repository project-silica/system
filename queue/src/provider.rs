//! The provider's half: the connections a class's service keeps for its
//! clients (up to [`CONNECTIONS`] at once, each through a capability of its
//! own: a disk's partitions, say, each a client). A [`Session`] owns each
//! connection's rings, its table of registered memory, the wake-ups and the
//! connection's life; the class's service decides what a request means
//! (and what a client may reach) and starts it on its device.
//!
//! The service implements its class protocol's calls by passing them on
//! ([`Session::connect`], [`Session::add_memory`], [`Session::remove_memory`]),
//! and on each wake-up takes requests with [`Session::take`], reports
//! finished ones with [`Session::complete`], and tells the client with
//! [`Session::flush`].

use crate::{
    COMPLETION_BYTES, COMPLETIONS_AT, Completion, MEMORIES, NO_MEMORY, QUEUE, REQUEST_BYTES, RINGS_BITS, Raw, Refused, memory_of, tag_of,
};
use silica_ring::{Consumer, Producer};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::Handle;
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{mem, slots};

/// What lets the device reach a client's frame: the driver's part of
/// registering memory (normally `silica_driver::dma::Dma::share`).
pub trait Mapper {
    /// What a mapping is to the driver.
    type Mapping;
    /// Let the device reach `frame` (`2^bits` bytes), for writing too with
    /// `writable`. Returns the address the device uses for its first byte.
    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, Self::Mapping), Refused>;
    /// The device no longer reaches that frame.
    fn unmap(&mut self, mapping: Self::Mapping);
}

/// Most clients connected at once.
pub const CONNECTIONS: usize = 16;

/// A request a service has handed to its device: given back to
/// [`Session::complete`] when the device has finished it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    tag: u64,
    memory: u32,
    /// The connection's slot, and which connection in it (its generation).
    slot: u16,
    connection: u32,
}

impl Ticket {
    /// The client's tag.
    pub fn tag(&self) -> u64 {
        self.tag
    }

    /// The same ticket for a request that uses no registered memory.
    pub fn without_memory(self) -> Ticket {
        Ticket { memory: NO_MEMORY, ..self }
    }
}

/// Why a service did not start a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The device is full: offer the request again after a completion.
    Busy,
    /// Complete it now with this status (the class's, not 0).
    Fail(u32),
}

/// A registered frame, as a service checks a request against it.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    /// Its size in bytes.
    pub bytes: u64,
    /// Whether the device may write it.
    pub writable: bool,
    /// The device address of its first byte.
    pub address: u64,
}

struct Memory<M> {
    frame: Handle,
    region: Region,
    /// Requests in progress that use it.
    busy: u32,
    mapping: M,
}

struct Connection<M> {
    /// Which connection this is: a late completion is not given to the
    /// next one in the same slot.
    generation: u32,
    /// The badge of the capability the client calls through.
    client: u64,
    /// The frame of the rings: gone when the client is.
    rings: Handle,
    requests: Consumer<REQUEST_BYTES>,
    completions: Producer<COMPLETION_BYTES>,
    /// What to signal when completions were added and the client sleeps.
    done: Handle,
    memories: Vec<Option<Memory<M>>>,
    /// A request the device had no room for yet.
    stalled: Option<Raw>,
    /// Completions were added since the client was last told.
    completed: bool,
}

impl<M> Connection<M> {
    /// Whether the client is still there: it is while the frame of its
    /// rings is (a client that ends, or takes the rings back, takes the
    /// capability with it).
    fn alive(&self) -> bool {
        matches!(sys::inspect_slot(slots::SPACE, self.rings.cap().0), Ok(Some(_)))
    }
}

/// A service's connections to its clients.
pub struct Session<M> {
    connections: Vec<Option<Connection<M>>>,
    /// Counts connections.
    generation: u32,
    /// The capability clients are given to wake the service.
    wake: Cap,
    /// Where `take` starts, so no client's ring is always looked at last.
    next: usize,
    /// One client at a time ([`Session::exclusive`]).
    exclusive: bool,
}

impl<M> Session<M> {
    /// No connection yet. `wake` signals the notification the service
    /// listens on with its client bit; each client is given a copy.
    pub fn new(wake: Cap) -> Session<M> {
        let mut connections = Vec::new();
        connections.resize_with(CONNECTIONS, || None);
        Session { connections, generation: 0, wake, next: 0, exclusive: false }
    }

    /// As [`Session::new`], for a device that serves one client at a time:
    /// another client's `connect` is refused (`Busy`) while the first is
    /// there. A network interface is one: the device puts each frame that
    /// arrives into whichever client's buffer comes next, so two clients
    /// would each lose what the other was given, silently.
    pub fn exclusive(wake: Cap) -> Session<M> {
        Session { exclusive: true, ..Session::new(wake) }
    }

    /// End connection `slot`: the device loses the client's memory.
    fn close_slot(&mut self, slot: usize, mapper: &mut impl Mapper<Mapping = M>) {
        if let Some(c) = self.connections.get_mut(slot).and_then(Option::take) {
            for m in c.memories.into_iter().flatten() {
                mapper.unmap(m.mapping);
            }
        }
    }

    /// End every connection whose bit is set in `broken` (from `take`).
    pub fn close(&mut self, broken: u64, mapper: &mut impl Mapper<Mapping = M>) {
        for slot in 0..CONNECTIONS {
            if broken & 1 << slot != 0 {
                self.close_slot(slot, mapper);
            }
        }
    }

    fn of(&mut self, caller: u64) -> Option<&mut Connection<M>> {
        self.connections.iter_mut().flatten().find(|c| c.client == caller)
    }

    /// The class's `connect` from the client calling with badge `caller`:
    /// returns the capability the client wakes the service with. A client
    /// connects once; another client with a capability of its own connects
    /// beside it.
    pub fn connect(
        &mut self,
        caller: u64,
        rings: Handle,
        completions: Handle,
        mapper: &mut impl Mapper<Mapping = M>,
    ) -> Result<Handle, Refused> {
        if let Some(slot) = self.connections.iter().position(|c| c.as_ref().is_some_and(|c| c.client == caller)) {
            if self.connections[slot].as_ref().is_some_and(Connection::alive) {
                return Err(Refused::Busy);
            }
            self.close_slot(slot, mapper);
        }
        if self.exclusive && self.connections.iter().flatten().any(|c| c.client != caller && c.alive()) {
            return Err(Refused::Busy);
        }
        // A free slot, or one whose client has gone.
        let slot = match self.connections.iter().position(Option::is_none) {
            Some(s) => s,
            None => {
                let dead = self.connections.iter().position(|c| c.as_ref().is_some_and(|c| !c.alive())).ok_or(Refused::NoRoom)?;
                self.close_slot(dead, mapper);
                dead
            }
        };
        match sys::inspect_slot(slots::SPACE, rings.cap().0) {
            Ok(Some(s)) if s.bits == RINGS_BITS && s.rights.has(Rights(3)) => {}
            _ => return Err(Refused::BadMemory),
        }
        // If the client takes it back, the range reads as zeros, which the
        // rings report as a broken ring.
        let region = mem::peer(rings.cap(), RINGS_BITS, Rights(3)).map_err(|_| Refused::NoRoom)?;
        let (Some(req), Some(cpl)) = (region.part(0, COMPLETIONS_AT), region.part(COMPLETIONS_AT, region.len() - COMPLETIONS_AT)) else {
            return Err(Refused::BadMemory);
        };
        let (Some(mut requests), Some(completions_ring)) = (Consumer::new(req, QUEUE), Producer::new(cpl, QUEUE)) else {
            return Err(Refused::BadMemory);
        };
        // Until it is signalled the provider is asleep, and says so: the
        // client's first requests must wake it.
        let _ = requests.sleep();
        let mut memories = Vec::new();
        memories.try_reserve_exact(MEMORIES as usize).map_err(|_| Refused::NoRoom)?;
        memories.resize_with(MEMORIES as usize, || None);
        let wake = silica_rt::ipc::free_slot().ok_or(Refused::NoRoom)?;
        if sys::cap_derive(slots::SPACE, wake, self.wake, Rights::WRITE, 0).is_err() {
            silica_rt::ipc::release_slot(wake);
            return Err(Refused::NoRoom);
        }
        self.generation = self.generation.wrapping_add(1);
        self.connections[slot] = Some(Connection {
            generation: self.generation,
            client: caller,
            rings,
            requests,
            completions: completions_ring,
            done: completions,
            memories,
            stalled: None,
            completed: false,
        });
        Ok(Handle::new(Cap(wake)))
    }

    /// The class's `add_memory` from `caller`.
    pub fn add_memory(
        &mut self,
        caller: u64,
        id: u32,
        frame: Handle,
        writable: bool,
        mapper: &mut impl Mapper<Mapping = M>,
    ) -> Result<(), Refused> {
        let c = self.of(caller).ok_or(Refused::NotConnected)?;
        let slot = c.memories.get_mut(id as usize).filter(|m| m.is_none()).ok_or(Refused::BadMemory)?;
        let need = Rights(Rights::READ.0 | if writable { Rights::WRITE.0 } else { 0 });
        let bits = match sys::inspect_slot(slots::SPACE, frame.cap().0) {
            Ok(Some(s)) if s.ty == ObjectType::Frame && s.rights.has(need) && s.bits <= 32 => s.bits,
            _ => return Err(Refused::BadMemory),
        };
        let (address, mapping) = mapper.map(frame.cap(), bits, writable)?;
        *slot = Some(Memory { frame, region: Region { bytes: 1 << bits, writable, address }, busy: 0, mapping });
        Ok(())
    }

    /// The class's `remove_memory` from `caller`.
    pub fn remove_memory(&mut self, caller: u64, id: u32, mapper: &mut impl Mapper<Mapping = M>) -> Result<(), Refused> {
        let c = self.of(caller).ok_or(Refused::NotConnected)?;
        let slot = c.memories.get_mut(id as usize).filter(|m| m.is_some()).ok_or(Refused::BadMemory)?;
        if slot.as_ref().is_some_and(|m| m.busy != 0) {
            return Err(Refused::InUse);
        }
        if let Some(m) = slot.take() {
            mapper.unmap(m.mapping);
            drop(m.frame);
        }
        Ok(())
    }

    /// Take requests from every client's ring and start each with `start`,
    /// until the rings are empty (and their clients told this side sleeps)
    /// or `start` says the device is full. `start` is given the record,
    /// its ticket, the registered frame it names (`None`: no such frame,
    /// or a request with no data) and the badge of the client it came from
    /// (what the client may reach is the class's to know); it returns the
    /// ticket it handed to the device, with its memory dropped
    /// (`Ticket::without_memory`) when the request does not use it. A
    /// refused request is completed here. Returns the connections whose
    /// client broke its ring (or took it back), one bit each: the service
    /// closes them (`close`).
    #[must_use]
    pub fn take(&mut self, mut start: impl FnMut(&Raw, Ticket, Option<Region>, u64) -> Result<Ticket, Refusal>) -> u64 {
        let mut broken = 0u64;
        let first = self.next;
        self.next = (self.next + 1) % CONNECTIONS;
        for k in 0..CONNECTIONS {
            let slot = (first + k) % CONNECTIONS;
            let Some(c) = self.connections[slot].as_mut() else { continue };
            loop {
                let raw = match c.stalled.take() {
                    Some(r) => r,
                    None => match c.requests.pop() {
                        Ok(Some(raw)) => raw,
                        Ok(None) => {
                            if c.requests.sleep() {
                                break;
                            }
                            continue;
                        }
                        // The ring makes no sense: the client broke the
                        // protocol, or is gone and its memory with it.
                        Err(_) => {
                            broken |= 1 << slot;
                            break;
                        }
                    },
                };
                let memory = memory_of(&raw);
                let ticket = Ticket { tag: tag_of(&raw), memory, slot: slot as u16, connection: c.generation };
                let region = c.memories.get(memory as usize).and_then(Option::as_ref).map(|m| m.region);
                match start(&raw, ticket, region, c.client) {
                    Ok(t) => {
                        if let Some(m) = c.memories.get_mut(t.memory as usize).and_then(Option::as_mut) {
                            m.busy += 1;
                        }
                    }
                    Err(Refusal::Busy) => {
                        // The device is full: the rest waits for a completion.
                        c.stalled = Some(raw);
                        return broken;
                    }
                    Err(Refusal::Fail(status)) => {
                        let _ = c.completions.push(&Completion { tag: ticket.tag, status, value: 0 }.encode());
                        c.completed = true;
                    }
                }
            }
        }
        broken
    }

    /// The device finished the request of `ticket` with `status` (0:
    /// success) and `value`: complete it to the client, if it is still the
    /// client the request came from.
    pub fn complete(&mut self, ticket: Ticket, status: u32, value: u32) {
        let Some(c) = self.connections.get_mut(ticket.slot as usize).and_then(Option::as_mut).filter(|c| c.generation == ticket.connection)
        else {
            return;
        };
        if let Some(m) = c.memories.get_mut(ticket.memory as usize).and_then(Option::as_mut) {
            m.busy = m.busy.saturating_sub(1);
        }
        // The client keeps no more in progress than the ring holds; one
        // that does loses the completions that do not fit.
        let _ = c.completions.push(&Completion { tag: ticket.tag, status, value }.encode());
        c.completed = true;
    }

    /// Add a record that answers no request (a class's event, such as a
    /// link coming up) for every client, with `tag` a value no request uses.
    pub fn event(&mut self, tag: u64, status: u32, value: u32) {
        for c in self.connections.iter_mut().flatten() {
            let _ = c.completions.push(&Completion { tag, status, value }.encode());
            c.completed = true;
        }
    }

    /// Wake the clients completions were added for, those that sleep: all
    /// but one, whose notification is returned for the caller to signal as
    /// it waits (`silica_rt::ipc::Events::take_wake`), in one system call
    /// with its wait. The caller must signal what it is given.
    #[must_use]
    pub fn flush(&mut self) -> Option<Cap> {
        let mut last = None;
        for c in self.connections.iter_mut().flatten().filter(|c| c.completed) {
            c.completed = false;
            if c.completions.wake_needed()
                && let Some(w) = last.replace(c.done.cap())
            {
                let _ = sys::signal(w);
            }
        }
        last
    }
}
