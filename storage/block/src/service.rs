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
//! each client sends again what was in flight. A driver that keeps failing
//! is started again later each time (up to a minute apart), never left for
//! good. A driver for a device it will never support (a namespace format it
//! does not know) should end with status 0 after saying why: ending well is
//! not a failure, and the device is left alone at once.
//!
//! A driver asked to end by its parent ([`silica_rt::END`], as the machine
//! turns off) is ended here: the service flushes the device's write cache
//! with a request of its own, then calls [`Device::shutdown`] and exits 0.

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

    /// The driver is ending in order ([`silica_rt::END`]), after its cache was
    /// flushed: leave the device as its specification asks of a host that
    /// turns it off (an NVMe controller's normal shutdown), so it never
    /// records an unsafe shutdown. The default: nothing.
    fn shutdown(&mut self) {}
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

/// Badges of the capabilities `narrow` makes: this plus the window's index
/// in [`Windows`], so a request finds what its capability reaches in one
/// step. Above any badge the device manager gives clients.
const NARROWED: u64 = 1 << 48;
/// Most windows narrowed from capabilities to the whole device (a partition
/// each, as the partitions service opens them) that one consumer of the
/// device manager holds at once (`silica_protocols::driver_badge`): a
/// consumer that holds them all is refused more (`no_room`), and no other
/// consumer's window is touched.
const FIRST_PER_CLIENT: usize = 128;
/// Most windows narrowed (at any depth) under one first window, held at once.
const INNER_PER_FIRST: u32 = 4;
/// Most windows of every consumer together: the table's bound, far above
/// what the consumers a service manager declares hold.
const WINDOWS_MOST: usize = 1 << 16;

/// A request's tag with this bit set asks for its way through the provider
/// to be kept (`trace`).
pub const TRACED: u64 = 1 << 62;

/// The tag of the flush a driver makes as it ends (`Service::end`): no
/// client's ([`provider::Ticket::own`]).
const END_FLUSH_TAG: u64 = u64::MAX;
/// How long a driver that is ending waits for its flush.
const END_FLUSH_NS: u64 = 5_000_000_000;
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

/// The blocks a narrowed capability reaches, and how it came to be. Each
/// `narrow` makes one, for one holder: its badge is the holder's alone, so
/// no other holder of the same blocks can reach its connection, its memory
/// or its traces. (Every holder of a range once shared one window and its
/// badge: a second opener of a partition removed the first's memory and
/// read its traces.)
#[derive(Debug)]
struct Window {
    /// The consumer it is charged to: the one whose capability it was
    /// narrowed from (`silica_protocols::driver_badge`).
    owner: u64,
    first: u64,
    blocks: u64,
    /// The first window it lies under (`None`: it is one).
    under: Option<usize>,
    /// A first window: how many windows lie under it now.
    inner: u32,
    /// This service's capability with the window's badge: what its holder
    /// is given is derived from it, so deleting it takes that back, and
    /// while anything derived from it exists (`Inspect`'s
    /// `INSPECT_DERIVED`) somebody holds the window.
    keep: Handle,
}

/// Every window, by index ([`NARROWED`]). An index is used again only once
/// nothing derived from its window's capability exists and its client is
/// disconnected: then the window is nobody's.
struct Windows {
    all: Vec<Option<Window>>,
}

impl Windows {
    fn new() -> Windows {
        Windows { all: Vec::new() }
    }

    /// The consumer a capability with `badge` is charged to.
    fn owner(&self, badge: u64) -> u64 {
        if badge < NARROWED {
            return silica_protocols::driver_badge::consumer(badge);
        }
        let at = usize::try_from(badge - NARROWED).ok();
        // A window that is gone reaches nothing and is charged to nobody
        // who can be told apart: a consumer number no driver badge has.
        at.and_then(|k| self.all.get(k)).and_then(Option::as_ref).map_or(u64::MAX, |w| w.owner)
    }

    /// What the capability with `badge` reaches: its first block and how
    /// many. A capability the device manager gave reaches the whole
    /// device; a narrowed one whose window is gone, nothing.
    fn reach(&self, badge: u64, info: &Info) -> (u64, u64) {
        if badge < NARROWED {
            return (0, info.blocks);
        }
        let at = usize::try_from(badge - NARROWED).ok();
        at.and_then(|k| self.all.get(k)).and_then(Option::as_ref).map_or((0, 0), |w| (w.first, w.blocks))
    }
}

/// The state of the device's write cache, as flushes see it.
///
/// A flush makes durable every write that completed before it was asked
/// for; the device's flush covers what completed before it was issued.
/// So a device flush is needed only if a write completed since the last
/// one was issued: a flush asked for while one is on the device that no
/// write has completed since rides on it, and one asked for with nothing
/// written since the last successful flush is done at once. One device
/// flush is in flight at a time; those that need the next wait for it.
/// A client with nothing to flush cannot make the device flush, and no
/// client can make it flush more often than writes complete (a
/// partition's client could make the whole device flush at any rate).
struct Flushes {
    /// A write completed since the last device flush was issued. True at
    /// start: the driver before may have left writes in the cache.
    dirty: bool,
    /// The last device flush succeeded.
    ok: bool,
    /// The device flush in flight (its ticket: the request that issued it).
    on_device: Option<Ticket>,
    /// Requests that its completion answers.
    riding: Vec<Ticket>,
    /// Requests that need the next device flush.
    next: Vec<Ticket>,
}

/// A block device's service: the provider of `silica.block.Device`.
pub struct Service<D: Device> {
    /// The driver's part.
    pub device: D,
    session: Session<D::Mapping>,
    /// The endpoint clients call on, from which `narrow` makes capabilities.
    endpoint: Cap,
    /// What narrowed capabilities reach; any other reaches the whole device.
    windows: Windows,
    flushes: Flushes,
    /// The most recent traced requests, the next to be replaced at `next_trace`.
    traces: [Trace; TRACES],
    next_trace: usize,
    /// The badge of the call being served.
    caller: u64,
    /// A client to wake as the driver next waits (`Session::flush`).
    wake: Option<Cap>,
    /// The driver is ending in order (`Service::begin_end`).
    ending: Option<Ending>,
}

/// A driver ending in order: its last flush, heard of through the same wait
/// as everything else the device says.
struct Ending {
    /// The flush reached the device (it may have been full when asked).
    started: bool,
    /// How the flush ended, once the device said.
    result: Option<Result<(), Status>>,
    /// When the device is given up on (monotonic ns).
    deadline: u64,
}

/// A flush request, as the device is given one.
fn flush_request(ticket: Ticket) -> Request {
    Request { op: Op::Flush, memory: 0, block: 0, offset: 0, blocks: 0, tag: ticket.tag() }
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
            windows: Windows::new(),
            flushes: Flushes { dirty: true, ok: true, on_device: None, riding: Vec::new(), next: Vec::new() },
            traces: [Trace::default(); TRACES],
            next_trace: 0,
            caller: 0,
            wake: None,
            ending: None,
        }
    }

    /// Take requests from the rings, check each against the device, the
    /// memory and what its client may reach, and start them, until the
    /// rings are empty (and their clients told this side sleeps) or the
    /// device is full; then tell the device.
    fn pump(&mut self) {
        self.next_flush();
        let (session, device, windows, flushes) = (&mut self.session, &mut self.device, &self.windows, &mut self.flushes);
        let (traces, next_trace) = (&mut self.traces, &mut self.next_trace);
        let info = device.info();
        let clock = silica_rt::clock();
        let broken = session.take(|raw, ticket, region, client| {
            let traced = ticket.tag() & TRACED != 0;
            if traced {
                traces[*next_trace] = Trace { client, tag: ticket.tag(), taken: clock.now(), started: 0, done: 0 };
            }
            let r = Service::<D>::check_and_start(device, windows, flushes, &info, raw, ticket, region, client);
            if traced {
                if r.is_ok() {
                    traces[*next_trace].started = clock.now();
                }
                *next_trace = (*next_trace + 1) % TRACES;
            }
            r
        });
        if !broken.is_empty() {
            // Clients that broke their rings, or are gone with their memory.
            self.session.close(&broken, &mut Map(&mut self.device));
        }
        self.device.kick();
    }

    /// Check one request against the device, the memory and what its
    /// client may reach, and start it.
    #[allow(clippy::too_many_arguments)]
    fn check_and_start(
        device: &mut D,
        windows: &Windows,
        flushes: &mut Flushes,
        info: &Info,
        raw: &silica_queue::Raw,
        ticket: Ticket,
        region: Option<provider::Region>,
        client: u64,
    ) -> Result<Ticket, provider::Refusal> {
        let invalid = provider::Refusal::Fail(Status::Invalid as u32);
        let r = Request::decode(raw).ok_or(invalid)?;
        let (first, blocks) = windows.reach(client, info);
        if r.op == Op::Flush {
            // A flush uses no memory, and reaches the whole device's cache:
            // the device is asked only when a write needs it (`Flushes`).
            // Through a capability that reaches nothing, nothing.
            if blocks == 0 {
                return Err(invalid);
            }
            let ticket = ticket.without_memory();
            if !info.write_cache || (flushes.on_device.is_none() && !flushes.dirty && flushes.ok) {
                return Err(provider::Refusal::Fail(0));
            }
            if flushes.on_device.is_some() {
                if flushes.dirty {
                    flushes.next.push(ticket)
                } else {
                    flushes.riding.push(ticket)
                }
                return Ok(ticket);
            }
            device.start(&r, 0, ticket)?;
            flushes.on_device = Some(ticket);
            flushes.dirty = false;
            return Ok(ticket);
        }
        let m = region.ok_or(invalid)?;
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
        // Writes are marked: their completion is what makes a flush needed.
        let ticket = if r.op == Op::Write { ticket.marked() } else { ticket };
        // The device's own numbering.
        let on_device = Request { block: first + r.block, ..r };
        device.start(&on_device, m.address + r.offset as u64, ticket)?;
        Ok(ticket)
    }

    /// Issue the device flush that requests waiting for the next one need,
    /// if none is on the device. The device may be full: then after its
    /// next completion.
    fn next_flush(&mut self) {
        let f = &mut self.flushes;
        if f.on_device.is_some() || f.next.is_empty() {
            return;
        }
        let first = f.next[0];
        match self.device.start(&flush_request(first), 0, first) {
            Ok(()) => {
                f.on_device = Some(first);
                f.dirty = false;
                f.riding = f.next.split_off(1);
                f.next.clear();
            }
            Err(Refusal::Busy) => {}
            Err(Refusal::Fail(s)) => {
                for t in core::mem::take(&mut f.next) {
                    self.session.complete(t, s as u32, 0);
                }
            }
        }
    }

    /// The device's signals (`Some`), or its deadline passing (`None`):
    /// what it reports finished goes to the client.
    fn device_event(&mut self, bits: Option<u64>) {
        let (session, traces, flushes, ending) = (&mut self.session, &mut self.traces, &mut self.flushes, &mut self.ending);
        let clock = silica_rt::clock();
        let mut done = |ticket: Ticket, s: Result<(), Status>| {
            if ticket == provider::Ticket::own(END_FLUSH_TAG) {
                // The flush the driver made as it ends: no client's.
                if let Some(e) = ending.as_mut() {
                    e.result = Some(s);
                }
                return;
            }
            if ticket.tag() & TRACED != 0
                && let Some(t) = traces.iter_mut().find(|t| t.tag == ticket.tag() && t.done == 0 && t.taken != 0)
            {
                t.done = clock.now();
            }
            if ticket.is_marked() && s.is_ok() {
                flushes.dirty = true;
            }
            if flushes.on_device == Some(ticket) {
                // The flush answers every request that rode on it.
                flushes.on_device = None;
                flushes.ok = s.is_ok();
                flushes.dirty |= s.is_err();
                for t in core::mem::take(&mut flushes.riding) {
                    session.complete(t, status(s), 0);
                }
            }
            session.complete(ticket, status(s), 0)
        };
        match bits {
            Some(bits) => self.device.signals(bits, &mut done),
            None => self.device.timeout(&mut done),
        }
        self.next_flush();
        // Memory of ended connections whose last request has completed.
        self.session.unmap_finished(&mut Map(&mut self.device));
    }

    /// Whether nobody holds window `k` any more: nothing derived from its
    /// capability exists (the kernel says so: `Inspect`'s `INSPECT_DERIVED`),
    /// no client is connected through it, and no window lies under it.
    fn unheld(&self, k: usize) -> bool {
        let Some(w) = self.windows.all.get(k).and_then(Option::as_ref) else { return false };
        w.inner == 0
            && matches!(sys::inspect_slot(slots::SPACE, w.keep.cap().0), Ok(Some(s)) if !s.derived)
            && !self.session.connected(NARROWED + k as u64)
    }

    /// End every window `which` picks that nobody holds any more: what a
    /// consumer at its share gets back of its own. Looks only at the
    /// windows `which` picks (one consumer's, or one first window's).
    fn give_back(&mut self, which: impl Fn(&Window) -> bool) {
        for k in 0..self.windows.all.len() {
            if self.windows.all[k].as_ref().is_some_and(&which) && self.unheld(k) {
                self.end_window(k);
            }
        }
    }

    /// End window `k`: every capability to it goes, its client is
    /// disconnected, and so is every window under it; what it traced is
    /// forgotten, so a window given its index later sees none of it.
    fn end_window(&mut self, k: usize) {
        let Some(w) = self.windows.all[k].take() else { return };
        let badge = NARROWED + k as u64;
        for t in self.traces.iter_mut().filter(|t| t.client == badge) {
            *t = Trace::default();
        }
        self.session.disconnect(badge, &mut Map(&mut self.device));
        // Its capability goes, and with it every one derived from it (the
        // holders'), which is the point (`Handle` deletes it when dropped).
        let under = w.under;
        drop(w);
        match under {
            Some(f) => {
                if let Some(first) = self.windows.all[f].as_mut() {
                    first.inner = first.inner.saturating_sub(1);
                }
            }
            None => {
                for i in 0..self.windows.all.len() {
                    if self.windows.all[i].as_ref().is_some_and(|w| w.under == Some(k)) {
                        self.end_window(i);
                    }
                }
            }
        }
    }

    /// Its parent asked it to end ([`silica_rt::END`]): what was written is
    /// made durable (one flush, when the device has a write cache), the
    /// device is left as its specification asks ([`Device::shutdown`]), and
    /// the driver exits. Before, it was destroyed where it stood, a power
    /// cut for the device's cache. What clients still have on the device is
    /// theirs to lose: the service manager ends clients before the device
    /// manager, and the flush covers every write the device had finished.
    ///
    /// The flush is one more request on the device: its completion arrives
    /// as every completion does, on the driver's one wait (the device's
    /// interrupt, [`Events::signals`]), and the device's bound on it is that
    /// wait's deadline ([`Events::deadline`]). Nothing is looked at between
    /// the two (before, the driver woke every 100 us for up to 5 s to ask).
    fn begin_end(&mut self) {
        if self.ending.is_some() {
            return;
        }
        if !self.device.info().write_cache {
            self.finish_end("no write cache");
        }
        self.ending = Some(Ending { started: false, result: None, deadline: silica_rt::clock().now() + END_FLUSH_NS });
        self.end_step();
    }

    /// The ending driver's next step, after anything the device said: the
    /// flush offered (again, if the device was full), or the end itself
    /// once the flush is answered or the device's time for it is up.
    fn end_step(&mut self) {
        let (device, Some(e)) = (&mut self.device, self.ending.as_mut()) else { return };
        if !e.started && e.result.is_none() {
            let ticket = provider::Ticket::own(END_FLUSH_TAG);
            match device.start(&flush_request(ticket), 0, ticket) {
                Ok(()) => {
                    e.started = true;
                    device.kick();
                }
                // Offered again after the device's next completion.
                Err(Refusal::Busy) => {}
                Err(Refusal::Fail(_)) => e.result = Some(Err(Status::Io)),
            }
        }
        let (result, late) = (e.result, silica_rt::clock().now() >= e.deadline);
        match result {
            Some(Ok(())) => self.finish_end("its write cache flushed"),
            Some(Err(_)) => self.finish_end("its write cache's flush failed"),
            None if late => self.finish_end("its write cache's flush did not finish in time"),
            None => {}
        }
    }

    fn finish_end(&mut self, said: &str) -> ! {
        self.device.shutdown();
        silica_rt::println!("block: the driver ended in order, {said}");
        silica_rt::exit(0)
    }

    /// A capability derived from window `k`'s, for its next holder.
    fn give_window(&self, k: usize) -> Result<NarrowReply<Handle>, Error> {
        let keep = self.windows.all[k].as_ref().ok_or(Error::NoRoom)?.keep.cap();
        let slot = free_slot().ok_or(Error::NoRoom)?;
        if sys::cap_derive(slots::SPACE, slot, keep, Rights(Rights::WRITE.0 | Rights::GRANT.0), 0).is_err() {
            release_slot(slot);
            return Err(Error::NoRoom);
        }
        Ok(NarrowReply { device: Handle::new(Cap(slot)) })
    }
}

impl<D: Device> device::Server<Handle> for Service<D> {
    fn info(&mut self) -> InfoReply {
        let mut info = self.device.info();
        info.blocks = self.windows.reach(self.caller, &info).1;
        InfoReply { info }
    }

    fn trace(&mut self, tag: u64) -> Result<TraceReply, Error> {
        let t = self.traces.iter().find(|t| t.tag == tag && t.client == self.caller && t.taken != 0).ok_or(Error::NoSuchRequest)?;
        Ok(TraceReply { taken: t.taken, started: t.started, done: t.done })
    }

    /// Each `narrow` is a window of its own, for one holder (see
    /// `Window`), charged to the consumer whose capability it was narrowed
    /// from. A consumer holds at most `FIRST_PER_CLIENT` windows of the
    /// whole device, and under one first window there are at most
    /// `INNER_PER_FIRST`; past either, the consumer's own windows that
    /// nobody holds any more (the kernel says when: `Service::unheld`) make
    /// room, and else it is refused (`no_room`). No window anyone holds is
    /// ever taken to make room: before, past 128 windows the oldest ended,
    /// so any holder of the whole disk could narrow 128 ranges and cut off
    /// every partition's holder, the root filesystem's among them.
    fn narrow(&mut self, first: u64, blocks: u64) -> Result<NarrowReply<Handle>, Error> {
        let info = self.device.info();
        let caller = self.caller;
        let (base, reach) = self.windows.reach(caller, &info);
        if blocks == 0 || first.checked_add(blocks).is_none_or(|end| end > reach) {
            return Err(Error::Outside);
        }
        let first = base + first;
        let owner = self.windows.owner(caller);
        // Under which first window it lies, if the caller's is narrowed.
        let under = (caller >= NARROWED).then(|| {
            let k = (caller - NARROWED) as usize;
            self.windows.all[k].as_ref().and_then(|w| w.under).unwrap_or(k)
        });
        let full = |s: &Self| match under {
            Some(f) => s.windows.all[f].as_ref().is_none_or(|w| w.inner >= INNER_PER_FIRST),
            None => s.windows.all.iter().flatten().filter(|w| w.owner == owner && w.under.is_none()).count() >= FIRST_PER_CLIENT,
        };
        if full(self) {
            match under {
                Some(f) => self.give_back(|w| w.under == Some(f)),
                None => self.give_back(|w| w.owner == owner && w.under.is_none()),
            }
            if full(self) {
                return Err(Error::NoRoom);
            }
        }
        // A free index, else a new one.
        let k = match self.windows.all.iter().position(Option::is_none) {
            Some(k) => k,
            None if self.windows.all.len() < WINDOWS_MOST => {
                self.windows.all.try_reserve(1).map_err(|_| Error::NoRoom)?;
                self.windows.all.push(None);
                self.windows.all.len() - 1
            }
            None => return Err(Error::NoRoom),
        };
        let badge = NARROWED + k as u64;
        let keep = free_slot().ok_or(Error::NoRoom)?;
        if sys::cap_derive(slots::SPACE, keep, self.endpoint, Rights(Rights::WRITE.0 | Rights::GRANT.0), badge).is_err() {
            release_slot(keep);
            return Err(Error::NoRoom);
        }
        self.windows.all[k] = Some(Window { owner, first, blocks, under, inner: 0, keep: Handle::new(Cap(keep)) });
        if let Some(f) = under
            && let Some(w) = self.windows.all[f].as_mut()
        {
            w.inner += 1;
        }
        self.give_window(k)
    }

    fn connect(&mut self, rings: Handle, completions: Handle) -> Result<ConnectReply<Handle>, Error> {
        let owner = self.windows.owner(self.caller);
        let requests = self.session.connect(self.caller, owner, rings, completions, &mut Map(&mut self.device)).map_err(error)?;
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
        // The device's bits: not the clients', not the parent's.
        let device = bits & !(CLIENT | silica_rt::END);
        if device != 0 {
            self.device_event(Some(device));
        }
        if bits & silica_rt::END != 0 {
            self.begin_end();
        }
        self.after_event();
    }

    fn deadline(&self) -> Option<u64> {
        // The device's deadline for its requests; and, ending, its time for
        // the last flush.
        match (self.device.deadline(), self.ending.as_ref().map(|e| e.deadline)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn take_wake(&mut self) -> Option<Cap> {
        self.wake.take()
    }

    fn timer(&mut self) {
        self.device_event(None);
        self.after_event();
    }
}

impl<D: Device> Service<D> {
    /// After the device spoke or a deadline passed: an ending driver takes
    /// its next step and no new request; any other takes what its clients
    /// have ready.
    fn after_event(&mut self) {
        if self.ending.is_some() {
            self.end_step();
        } else {
            self.pump();
        }
        self.wake = self.session.flush();
    }
}
