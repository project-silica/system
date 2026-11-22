//! The service a block driver provides: everything about
//! `silica.block.Device` that is the same for every block device.
//!
//! A driver implements [`Device`] (what the device is, how to let it reach
//! a client's frame, how to start a request, what its interrupts mean) and
//! runs [`Service`] with `silica_rt::ipc::serve_events`. The service owns
//! the connection: it checks every request against the device and the
//! registered memory before the driver sees it, so a driver's `start` is
//! only ever asked for something the device can do; it keeps the rings, the
//! wake-ups and the memory table; and it notices a client that has gone.
//!
//! # A block driver's shape
//!
//! ```text
//! use silica_block::device::{Error, Info};
//! use silica_block::service::{Busy, CLIENT, Completions, Device, Service, Ticket};
//! use silica_block::{Request, Status};
//! use silica_driver::dma::{Dma, Shared};
//! use silica_driver::irq::{Interrupt, Signals};
//!
//! struct Disk { dma: Dma, info: Info, /* the device's queues, its registers */ }
//!
//! impl Device for Disk {
//!     type Mapping = Shared;
//!     fn info(&self) -> Info { self.info.clone() }
//!     // Let the device reach a client's frame: where it reaches its first byte.
//!     fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, Shared), Error> {
//!         let s = self.dma.share(frame, bits, writable).map_err(|_| Error::NoRoom)?;
//!         Ok((s.address, s))
//!     }
//!     fn unmap(&mut self, m: Shared) { self.dma.unshare(m) }
//!     // Put the request on the device's queue; keep `ticket` until it is done.
//!     fn start(&mut self, r: &Request, address: u64, ticket: Ticket) -> Result<(), Busy> { /* ... */ }
//!     // Tell the device about requests started since the last call.
//!     fn kick(&mut self) { /* ring the doorbell once */ }
//!     // An interrupt (the bits its Signals sender carries): report every finished request.
//!     fn signals(&mut self, bits: u64, done: &mut Completions<'_>) {
//!         /* for each completion the device reports: */ done(ticket, Ok(()));
//!     }
//! }
//!
//! fn run(info: &silica_rt::ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
//!     let device = silica_driver::Device::take(info)?;
//!     let dma = Dma::new(&device)?;
//!     let signals = Signals::new()?;
//!     // Interrupt n of the device signals the value 2 << n (CLIENT is 1).
//!     let _irq = Interrupt::bind_to(&device, 0, signals.sender(2)?)?;
//!     // ... bring the device up, then:
//!     let disk = Disk { dma, info: /* ... */ };
//!     let mut service = Service::new(disk, signals.sender(CLIENT)?);
//!     silica_rt::ipc::serve_events(silica_driver::granted(silica_driver::grant::SERVICE), signals.listen(), &mut service)
//! }
//! ```
//!
//! `start` is called with a request the device can do; return [`Busy`] when
//! the device's queue is full (the request is offered again after the next
//! completion). Every ticket `start` accepted must reach `done` exactly
//! once: with `Ok`, or an error [`Status`] (`Io` for a device error,
//! `Aborted` when the driver gives up on the device). Keep the interrupt
//! objects alive for as long as the driver runs.

use crate::device::{self, AddMemoryReply, ConnectReply, Error, Info, InfoReply, RemoveMemoryReply};
use crate::{COMPLETION_BYTES, COMPLETIONS_AT, Completion, MEMORIES, Op, QUEUE, REQUEST_BYTES, RINGS_BITS, Request, Status};
use silica_idl_rt::CapList;
use silica_ring::{Consumer, Producer};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Events, Handle};
use silica_rt::mmio::Mmio;
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{mem, slots};

/// The bit of the driver's notification that clients signal: "look at the
/// request ring".
pub const CLIENT: u64 = 1;

/// The device's queue is full: offer the request again after a completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy;

/// A request the service has handed to the driver: given back through the
/// `done` of [`Device::signals`] when the device has finished it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    tag: u64,
    memory: u32,
    connection: u32,
}

/// What a block driver supplies.
pub trait Device {
    /// What a mapping of a client's frame is to the driver.
    type Mapping;

    /// What the device is.
    fn info(&self) -> Info;

    /// Let the device reach `frame` (`2^bits` bytes of a client's memory),
    /// for writing too with `writable`. Returns the address the device
    /// uses for its first byte.
    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, Self::Mapping), Error>;

    /// The device no longer reaches that frame.
    fn unmap(&mut self, mapping: Self::Mapping);

    /// Start `request` (already checked: its blocks are on the device, its
    /// data inside a registered frame the device may use that way), whose
    /// data the device finds at `address`. `ticket` is handed to the
    /// `done` of [`Device::signals`] when the device has finished it.
    fn start(&mut self, request: &Request, address: u64, ticket: Ticket) -> Result<(), Busy>;

    /// The driver's notification was signalled with `bits` (other than
    /// [`CLIENT`]): report every request the device has finished.
    fn signals(&mut self, bits: u64, done: &mut Completions<'_>);

    /// Requests were started since the last call: tell the device, once.
    fn kick(&mut self);
}

/// Where a driver reports a finished request: the ticket it was started
/// with, and how it ended.
pub type Completions<'a> = dyn FnMut(Ticket, Result<(), Status>) + 'a;

struct Memory<M> {
    frame: Handle,
    bytes: u64,
    writable: bool,
    address: u64,
    /// Requests in progress that use it.
    busy: u32,
    mapping: M,
}

struct Connection<M> {
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
    stalled: Option<Request>,
    in_progress: u32,
    /// Completions were added since the client was last told.
    completed: bool,
}

/// A block device's service: the provider of `silica.block.Device`.
pub struct Service<D: Device> {
    /// The driver's part.
    pub device: D,
    connection: Option<Connection<D::Mapping>>,
    /// Counts connections, so a late completion is not given to a new client.
    generation: u32,
    /// The capability clients are given to wake the driver with.
    wake: Cap,
    /// The badge of the call being served.
    caller: u64,
}

impl<D: Device> Service<D> {
    /// A service for `device`. `wake` is a capability that signals the
    /// notification the driver listens on with the bit [`CLIENT`]; each
    /// client is given a copy.
    pub fn new(device: D, wake: Cap) -> Service<D> {
        Service { device, connection: None, generation: 0, wake, caller: 0 }
    }

    /// End the connection: the device loses the client's memory.
    fn close(&mut self) {
        if let Some(c) = self.connection.take() {
            for m in c.memories.into_iter().flatten() {
                self.device.unmap(m.mapping);
            }
            self.generation = self.generation.wrapping_add(1);
        }
    }

    /// Whether the connected client is still there: it is while the frame
    /// of its rings is (a client that ends, or takes the rings back, takes
    /// the capability with it).
    fn alive(&self) -> bool {
        self.connection.as_ref().is_some_and(|c| matches!(sys::inspect_slot(slots::SPACE, c.rings.cap().0), Ok(Some(_))))
    }

    /// Check `r` against the device and the memory, and start it.
    fn start(&mut self, r: Request) -> Result<(), Result<Busy, Status>> {
        let info = self.device.info();
        let Some(c) = self.connection.as_mut() else { return Err(Err(Status::Aborted)) };
        // A flush uses no memory.
        let ticket = Ticket { tag: r.tag, memory: if r.op == Op::Flush { u32::MAX } else { r.memory }, connection: self.generation };
        let address = if r.op == Op::Flush {
            0
        } else {
            let bytes = r.blocks as u64 * info.block_size as u64;
            let m = c.memories.get(r.memory as usize).and_then(Option::as_ref).ok_or(Err(Status::Invalid))?;
            let on_device =
                r.blocks != 0 && r.blocks <= info.max_blocks && r.block.checked_add(r.blocks as u64).is_some_and(|e| e <= info.blocks);
            let in_memory = r.offset.is_multiple_of(512) && r.offset as u64 + bytes <= m.bytes;
            let allowed = match r.op {
                Op::Read => m.writable,
                _ => !info.read_only,
            };
            if !(on_device && in_memory && allowed) {
                return Err(Err(Status::Invalid));
            }
            m.address + r.offset as u64
        };
        self.device.start(&r, address, ticket).map_err(Ok)?;
        if let Some(m) = c.memories.get_mut(r.memory as usize).and_then(Option::as_mut).filter(|_| r.op != Op::Flush) {
            m.busy += 1;
        }
        c.in_progress += 1;
        Ok(())
    }

    /// Take requests from the ring and start them, until the ring is empty
    /// (and the client has been told this side sleeps) or the device is full.
    fn pump(&mut self) {
        self.take_requests();
        self.device.kick();
    }

    fn take_requests(&mut self) {
        loop {
            let Some(c) = self.connection.as_mut() else { return };
            let next = match c.stalled.take() {
                Some(r) => Some(Ok(r)),
                None => match c.requests.pop() {
                    Ok(Some(raw)) => Some(Request::decode(&raw).ok_or(raw)),
                    Ok(None) => None,
                    // The ring makes no sense: the client broke the
                    // protocol, or is gone and its memory with it.
                    Err(_) => return self.close(),
                },
            };
            match next {
                Some(Ok(r)) => match self.start(r) {
                    Ok(()) => {}
                    Err(Ok(Busy)) => {
                        if let Some(c) = self.connection.as_mut() {
                            c.stalled = Some(r);
                        }
                        return;
                    }
                    Err(Err(status)) => self.refuse(r.tag, status),
                },
                // Not a request at all: its tag is still where a tag is.
                Some(Err(raw)) => self
                    .refuse(u64::from_le_bytes([raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31]]), Status::Invalid),
                None => {
                    if self.connection.as_mut().is_none_or(|c| c.requests.sleep()) {
                        return;
                    }
                }
            }
        }
    }

    /// Complete a request that was never started.
    fn refuse(&mut self, tag: u64, status: Status) {
        if let Some(c) = self.connection.as_mut() {
            let _ = c.completions.push(&Completion { tag, status: Err(status) }.encode());
            c.completed = true;
        }
    }

    /// Wake the client if completions were added and it sleeps.
    fn flush(&mut self) {
        if let Some(c) = self.connection.as_mut().filter(|c| c.completed) {
            c.completed = false;
            if c.completions.wake_needed() {
                let _ = sys::signal(c.done.cap());
            }
        }
    }
}

impl<D: Device> device::Server<Handle> for Service<D> {
    fn info(&mut self) -> InfoReply {
        InfoReply { info: self.device.info() }
    }

    fn connect(&mut self, rings: Handle, completions: Handle) -> Result<ConnectReply<Handle>, Error> {
        if self.connection.is_some() {
            if self.alive() {
                return Err(Error::Busy);
            }
            self.close();
        }
        let size = match sys::inspect_slot(slots::SPACE, rings.cap().0) {
            Ok(Some(s)) if s.bits == RINGS_BITS && s.rights.has(Rights(3)) => 1usize << s.bits,
            _ => return Err(Error::BadMemory),
        };
        let at = mem::map_peer(rings.cap(), RINGS_BITS, Rights(3)).map_err(|_| Error::NoRoom)?;
        // SAFETY: the client's frame, just mapped where lent memory goes:
        // if the client takes it back, the range reads as zeros (the
        // supervisor's answer to a fault there), and the rings report that
        // as a broken ring.
        #[allow(unsafe_code)]
        let region = unsafe { Mmio::new(at, size) };
        let (Some(req), Some(cpl)) = (region.part(0, COMPLETIONS_AT), region.part(COMPLETIONS_AT, size - COMPLETIONS_AT)) else {
            return Err(Error::BadMemory);
        };
        let (Some(mut requests), Some(completions_ring)) = (Consumer::new(req, QUEUE), Producer::new(cpl, QUEUE)) else {
            return Err(Error::BadMemory);
        };
        // Until it is signalled the provider is asleep, and says so: the
        // client's first requests must wake it.
        let _ = requests.sleep();
        let mut memories = Vec::new();
        memories.try_reserve_exact(MEMORIES as usize).map_err(|_| Error::NoRoom)?;
        memories.resize_with(MEMORIES as usize, || None);
        // The client's own capability to wake the driver.
        let wake = silica_rt::ipc::free_slot().ok_or(Error::NoRoom)?;
        if sys::cap_derive(slots::SPACE, wake, self.wake, Rights::WRITE, 0).is_err() {
            silica_rt::ipc::release_slot(wake);
            return Err(Error::NoRoom);
        }
        self.connection = Some(Connection {
            client: self.caller,
            rings,
            requests,
            completions: completions_ring,
            done: completions,
            memories,
            stalled: None,
            in_progress: 0,
            completed: false,
        });
        Ok(ConnectReply { requests: Handle::new(Cap(wake)) })
    }

    fn add_memory(&mut self, id: u32, frame: Handle, writable: bool) -> Result<AddMemoryReply, Error> {
        let caller = self.caller;
        let c = self.connection.as_mut().filter(|c| c.client == caller).ok_or(Error::NotConnected)?;
        let slot = c.memories.get_mut(id as usize).filter(|m| m.is_none()).ok_or(Error::BadMemory)?;
        let need = Rights(Rights::READ.0 | if writable { Rights::WRITE.0 } else { 0 });
        let bits = match sys::inspect_slot(slots::SPACE, frame.cap().0) {
            Ok(Some(s)) if s.ty == ObjectType::Frame && s.rights.has(need) && s.bits <= 32 => s.bits,
            _ => return Err(Error::BadMemory),
        };
        let (address, mapping) = self.device.map(frame.cap(), bits, writable)?;
        *slot = Some(Memory { frame, bytes: 1 << bits, writable, address, busy: 0, mapping });
        Ok(AddMemoryReply {})
    }

    fn remove_memory(&mut self, id: u32) -> Result<RemoveMemoryReply, Error> {
        let caller = self.caller;
        let c = self.connection.as_mut().filter(|c| c.client == caller).ok_or(Error::NotConnected)?;
        let slot = c.memories.get_mut(id as usize).filter(|m| m.is_some()).ok_or(Error::BadMemory)?;
        if slot.as_ref().is_some_and(|m| m.busy != 0) {
            return Err(Error::InUse);
        }
        if let Some(m) = slot.take() {
            self.device.unmap(m.mapping);
            drop(m.frame);
        }
        Ok(RemoveMemoryReply {})
    }
}

impl<D: Device> Events for Service<D> {
    fn call(&mut self, badge: u64, request: &[u8], caps: CapList<Handle>, reply: &mut [u8], reply_caps: &mut CapList<Handle>) -> usize {
        self.caller = badge;
        device::dispatch(self, request, caps, reply, reply_caps)
    }

    fn signals(&mut self, bits: u64) {
        if bits & !CLIENT != 0 {
            let (connection, generation) = (&mut self.connection, self.generation);
            self.device.signals(bits & !CLIENT, &mut |ticket: Ticket, status| {
                // A request of a connection that has ended has nobody to tell.
                let Some(c) = connection.as_mut().filter(|_| ticket.connection == generation) else { return };
                if let Some(m) = c.memories.get_mut(ticket.memory as usize).and_then(Option::as_mut) {
                    m.busy = m.busy.saturating_sub(1);
                }
                c.in_progress = c.in_progress.saturating_sub(1);
                // The client keeps no more in progress than the ring
                // holds; one that does loses the completions that do not fit.
                let _ = c.completions.push(&Completion { tag: ticket.tag, status }.encode());
                c.completed = true;
            });
        }
        self.pump();
        self.flush();
    }
}
