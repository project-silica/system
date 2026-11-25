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
//! use silica_block::service::{CLIENT, Completions, Device, Refusal, Service, Ticket};
//! use silica_block::{Request, Status};
//! use silica_driver::dma::{Dma, Shared};
//! use silica_driver::irq::{Interrupt, Signals};
//! use silica_driver::DeviceError;
//! use silica_rt::sys::Cap;
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
//!     fn start(&mut self, r: &Request, address: u64, ticket: Ticket) -> Result<(), Refusal> { /* ... */ }
//!     // Tell the device about requests started since the last call.
//!     fn kick(&mut self) { /* ring the doorbell once */ }
//!     // An interrupt (the bits its Signals sender carries): report every finished request.
//!     fn signals(&mut self, bits: u64, done: &mut Completions<'_>) {
//!         /* for each completion the device reports: */ done(ticket, Ok(()));
//!     }
//! }
//!
//! silica_rt::main!(main);
//!
//! fn main(info: &'static silica_rt::ProcessInfo) -> i64 {
//!     match run(info) {
//!         Ok(never) => match never {},
//!         // A failure: the device manager starts the driver again (section
//!         // "Ending" below).
//!         Err(e) => { silica_rt::println!("mydisk: {e:?}"); 1 }
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
//! `start` is called only with a request the service has checked: `blocks`
//! is at least 1 and at most [`Info::max_blocks`](crate::device::Info),
//! the blocks lie on the device, the data (`blocks` times the block size,
//! from `offset`, a multiple of 512) lies inside a registered frame, and
//! the frame may be used that way (written by the device for a read; no
//! write or flush to a read-only device). `address` is the device address
//! of the data's first byte: the frame's address plus `offset`, so the
//! data lies at consecutive device addresses. A flush has no data: its
//! `address` is 0, and its other fields are whatever the client wrote.
//!
//! Return [`Refusal::Busy`] when the device's queue is full (the request is
//! offered again after the next completion), or [`Refusal::Fail`] for a
//! request this device cannot do (it completes at once with that status).
//! Every ticket `start` accepted must reach `done` exactly once: with `Ok`,
//! or an error [`Status`] (`Io` for a device error, `Aborted` when the
//! driver gives up on the device). Keep the interrupt objects alive for as
//! long as the driver runs.
//!
//! # Timeouts
//!
//! A device can accept a request and never finish it. A driver that returns
//! a time from [`Device::deadline`] (the monotonic clock, `silica_rt::clock`)
//! has [`Device::timeout`] called when it passes with nothing else
//! happening: complete what the device has not finished (normally by
//! resetting it, or by ending the driver), or move the deadline on.
//!
//! # Ending
//!
//! A driver that cannot go on (a device that answers nonsense or reports a
//! fatal error) ends with a nonzero status from `main`, or with
//! `silica_rt::exit` from anywhere, `signals` included: the device manager
//! silences the device and starts the driver again, which resets it, and
//! each client sends again what was in flight. After three such failures
//! the device is left alone and its owner told. A driver for a device it
//! will never support (a namespace format it does not know) should end
//! with status 0 after saying why: ending well is not a failure, and the
//! device is left alone at once.

use crate::device::{self, AddMemoryReply, ConnectReply, Error, Info, InfoReply, NarrowReply, RemoveMemoryReply, TraceReply};
use crate::{Op, Request, Status};
use silica_idl_rt::CapList;
use silica_queue::Refused;
use silica_queue::provider::{self, Mapper, Session};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Events, Handle, free_slot, release_slot};
use silica_rt::slots;
use silica_rt::sys::{self, Cap, Rights};

pub use silica_queue::provider::Ticket;

/// The bit of the driver's notification that clients signal: "look at the
/// request ring".
pub const CLIENT: u64 = 1;

/// Why a driver did not start a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The device's queue is full: offer the request again after a completion.
    Busy,
    /// The device cannot do this request: complete it now with this status.
    Fail(Status),
}

impl From<Refusal> for provider::Refusal {
    fn from(r: Refusal) -> provider::Refusal {
        match r {
            Refusal::Busy => provider::Refusal::Busy,
            Refusal::Fail(s) => provider::Refusal::Fail(s as u32),
        }
    }
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

    /// Start `request` (already checked, as the module says), whose data
    /// the device finds at `address` (the first byte's device address,
    /// `offset` included). `ticket` is handed to the `done` of
    /// [`Device::signals`] when the device has finished it.
    fn start(&mut self, request: &Request, address: u64, ticket: Ticket) -> Result<(), Refusal>;

    /// The driver's notification was signalled with `bits` (other than
    /// [`CLIENT`]): report every request the device has finished.
    fn signals(&mut self, bits: u64, done: &mut Completions<'_>);

    /// Requests were started since the last call: tell the device, once.
    fn kick(&mut self);

    /// When [`Device::timeout`] is to be called if nothing else happens
    /// first (monotonic nanoseconds); `None` (the default): never. Asked
    /// before every wait, so it can follow the oldest request in flight.
    fn deadline(&self) -> Option<u64> {
        None
    }

    /// The deadline passed: report what the device has finished, and deal
    /// with what it has not (see the module's "Timeouts").
    fn timeout(&mut self, _done: &mut Completions<'_>) {}
}

/// Where a driver reports a finished request: the ticket it was started
/// with, and how it ended.
pub type Completions<'a> = dyn FnMut(Ticket, Result<(), Status>) + 'a;

/// The driver's mapping, as the session asks for it.
struct Map<'a, D>(&'a mut D);

impl<D: Device> Mapper for Map<'_, D> {
    type Mapping = D::Mapping;
    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, D::Mapping), Refused> {
        self.0.map(frame, bits, writable).map_err(|e| match e {
            Error::Busy => Refused::Busy,
            Error::NotConnected => Refused::NotConnected,
            Error::BadMemory => Refused::BadMemory,
            Error::InUse => Refused::InUse,
            Error::Outside => Refused::Outside,
            Error::NoRoom | Error::NoSuchRequest | Error::Unknown(_) => Refused::NoRoom,
        })
    }
    fn unmap(&mut self, mapping: D::Mapping) {
        self.0.unmap(mapping)
    }
}

fn error(r: Refused) -> Error {
    match r {
        Refused::Busy => Error::Busy,
        Refused::NotConnected => Error::NotConnected,
        Refused::BadMemory => Error::BadMemory,
        Refused::NoRoom => Error::NoRoom,
        Refused::InUse => Error::InUse,
        Refused::Outside => Error::Outside,
    }
}

fn status(s: Result<(), Status>) -> u32 {
    s.map_or_else(|s| s as u32, |()| 0)
}

/// Badges of the capabilities `narrow` makes start here, above any the
/// device manager gives clients.
const NARROWED: u64 = 1 << 48;
/// Most narrowed capabilities one run of a driver makes.
const WINDOWS: usize = 256;

/// A request's tag with this bit set asks for its way through the provider
/// to be kept (`trace`).
pub const TRACED: u64 = 1 << 62;
/// Traced requests kept.
const TRACES: usize = 16;

/// Where a traced request went: when it was taken from the ring, when the
/// device accepted it, when it completed (monotonic ns; 0: not yet).
#[derive(Clone, Copy, Debug, Default)]
struct Trace {
    client: u64,
    tag: u64,
    taken: u64,
    started: u64,
    done: u64,
}

/// The blocks a capability reaches.
#[derive(Clone, Copy, Debug)]
struct Window {
    badge: u64,
    first: u64,
    blocks: u64,
}

/// A block device's service: the provider of `silica.block.Device`.
pub struct Service<D: Device> {
    /// The driver's part.
    pub device: D,
    session: Session<D::Mapping>,
    /// The endpoint clients call on, from which `narrow` makes capabilities.
    endpoint: Cap,
    /// What narrowed capabilities reach; any other reaches the whole device.
    windows: Vec<Window>,
    /// The most recent traced requests, the next to be replaced at `next_trace`.
    traces: [Trace; TRACES],
    next_trace: usize,
    /// The badge of the call being served.
    caller: u64,
    /// A client to wake as the driver next waits (`Session::flush`).
    wake: Option<Cap>,
}

impl<D: Device> Service<D> {
    /// A service for `device`, whose clients call it on `endpoint` (the
    /// driver's grant: it narrows capabilities from it). `wake` is a
    /// capability that signals the notification the driver listens on with
    /// the bit [`CLIENT`]; each client is given a copy.
    pub fn new(device: D, wake: Cap, endpoint: Cap) -> Service<D> {
        Service {
            device,
            session: Session::new(wake),
            endpoint,
            windows: Vec::new(),
            traces: [Trace::default(); TRACES],
            next_trace: 0,
            caller: 0,
            wake: None,
        }
    }

    /// What the capability with `badge` reaches: its first block and how many.
    fn window(windows: &[Window], badge: u64, info: &Info) -> (u64, u64) {
        windows.iter().find(|w| w.badge == badge).map_or((0, info.blocks), |w| (w.first, w.blocks))
    }

    /// Take requests from the rings, check each against the device, the
    /// memory and what its client may reach, and start them, until the
    /// rings are empty (and their clients told this side sleeps) or the
    /// device is full; then tell the device.
    fn pump(&mut self) {
        let (session, device, windows) = (&mut self.session, &mut self.device, &self.windows);
        let (traces, next_trace) = (&mut self.traces, &mut self.next_trace);
        let info = device.info();
        let clock = silica_rt::clock();
        let broken = session.take(|raw, ticket, region, client| {
            let traced = ticket.tag() & TRACED != 0;
            if traced {
                traces[*next_trace] = Trace { client, tag: ticket.tag(), taken: clock.now(), started: 0, done: 0 };
            }
            let r = Service::<D>::check_and_start(device, windows, &info, raw, ticket, region, client);
            if traced {
                if r.is_ok() {
                    traces[*next_trace].started = clock.now();
                }
                *next_trace = (*next_trace + 1) % TRACES;
            }
            r
        });
        if broken != 0 {
            // Clients that broke their rings, or are gone with their memory.
            self.session.close(broken, &mut Map(&mut self.device));
        }
        self.device.kick();
    }

    /// Check one request against the device, the memory and what its
    /// client may reach, and start it.
    fn check_and_start(
        device: &mut D,
        windows: &[Window],
        info: &Info,
        raw: &silica_queue::Raw,
        ticket: Ticket,
        region: Option<provider::Region>,
        client: u64,
    ) -> Result<Ticket, provider::Refusal> {
        {
            let invalid = provider::Refusal::Fail(Status::Invalid as u32);
            let r = Request::decode(raw).ok_or(invalid)?;
            if r.op == Op::Flush {
                // A flush uses no memory, and reaches the whole device's cache.
                let ticket = ticket.without_memory();
                device.start(&r, 0, ticket)?;
                return Ok(ticket);
            }
            let m = region.ok_or(invalid)?;
            let (first, blocks) = Service::<D>::window(windows, client, info);
            let bytes = r.blocks as u64 * info.block_size as u64;
            let within = r.blocks != 0 && r.blocks <= info.max_blocks && r.block.checked_add(r.blocks as u64).is_some_and(|e| e <= blocks);
            let in_memory = r.offset.is_multiple_of(512) && r.offset as u64 + bytes <= m.bytes;
            let allowed = match r.op {
                Op::Read => m.writable,
                _ => !info.read_only,
            };
            if !(within && in_memory && allowed) {
                return Err(invalid);
            }
            // The device's own numbering.
            let on_device = Request { block: first + r.block, ..r };
            device.start(&on_device, m.address + r.offset as u64, ticket)?;
            Ok(ticket)
        }
    }

    /// The device's signals (`Some`), or its deadline passing (`None`):
    /// what it reports finished goes to the client.
    fn device_event(&mut self, bits: Option<u64>) {
        let (session, traces) = (&mut self.session, &mut self.traces);
        let clock = silica_rt::clock();
        let mut done = |ticket: Ticket, s: Result<(), Status>| {
            if ticket.tag() & TRACED != 0
                && let Some(t) = traces.iter_mut().find(|t| t.tag == ticket.tag() && t.done == 0 && t.taken != 0)
            {
                t.done = clock.now();
            }
            session.complete(ticket, status(s), 0)
        };
        match bits {
            Some(bits) => self.device.signals(bits, &mut done),
            None => self.device.timeout(&mut done),
        }
        // Memory of ended connections whose last request has completed.
        self.session.unmap_finished(&mut Map(&mut self.device));
    }
}

impl<D: Device> device::Server<Handle> for Service<D> {
    fn info(&mut self) -> InfoReply {
        let mut info = self.device.info();
        info.blocks = Service::<D>::window(&self.windows, self.caller, &info).1;
        InfoReply { info }
    }

    fn trace(&mut self, tag: u64) -> Result<TraceReply, Error> {
        let t = self.traces.iter().find(|t| t.tag == tag && t.client == self.caller && t.taken != 0).ok_or(Error::NoSuchRequest)?;
        Ok(TraceReply { taken: t.taken, started: t.started, done: t.done })
    }

    fn narrow(&mut self, first: u64, blocks: u64) -> Result<NarrowReply<Handle>, Error> {
        let info = self.device.info();
        let (base, reach) = Service::<D>::window(&self.windows, self.caller, &info);
        if blocks == 0 || first.checked_add(blocks).is_none_or(|end| end > reach) {
            return Err(Error::Outside);
        }
        if self.windows.len() >= WINDOWS {
            return Err(Error::NoRoom);
        }
        let badge = NARROWED + self.windows.len() as u64;
        let slot = free_slot().ok_or(Error::NoRoom)?;
        if sys::cap_derive(slots::SPACE, slot, self.endpoint, Rights(Rights::WRITE.0 | Rights::GRANT.0), badge).is_err() {
            release_slot(slot);
            return Err(Error::NoRoom);
        }
        self.windows.push(Window { badge, first: base + first, blocks });
        Ok(NarrowReply { device: Handle::new(Cap(slot)) })
    }

    fn connect(&mut self, rings: Handle, completions: Handle) -> Result<ConnectReply<Handle>, Error> {
        let requests = self.session.connect(self.caller, rings, completions, &mut Map(&mut self.device)).map_err(error)?;
        Ok(ConnectReply { requests })
    }

    fn add_memory(&mut self, id: u32, frame: Handle, writable: bool) -> Result<AddMemoryReply, Error> {
        self.session.add_memory(self.caller, id, frame, writable, &mut Map(&mut self.device)).map_err(error)?;
        Ok(AddMemoryReply {})
    }

    fn remove_memory(&mut self, id: u32) -> Result<RemoveMemoryReply, Error> {
        self.session.remove_memory(self.caller, id, &mut Map(&mut self.device)).map_err(error)?;
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
            self.device_event(Some(bits & !CLIENT));
        }
        self.pump();
        self.wake = self.session.flush();
    }

    fn deadline(&self) -> Option<u64> {
        self.device.deadline()
    }

    fn take_wake(&mut self) -> Option<Cap> {
        self.wake.take()
    }

    fn timer(&mut self) {
        self.device_event(None);
        self.pump();
        self.wake = self.session.flush();
    }
}
