//! The service a network driver provides: everything about
//! `silica.net.Device` that is the same for every network interface.
//!
//! A driver implements [`Device`] (what the interface is, how to let it
//! reach a client's frame, how to start a request, what its interrupts
//! mean) and runs [`Service`] with `silica_rt::ipc::serve_events`, as a
//! block driver does with `silica_block::service`. The service checks every
//! request before the driver sees it: a transmit's frame lies in a
//! registered frame and is from [`HEADER`] bytes to the MTU plus 14; a
//! receive's buffer lies in writable registered memory and holds the
//! largest frame. `address` is the device address of the first byte.
//!
//! `start` returns [`Refusal::Busy`] when the device's queue is full (the
//! request is offered again after the next completion). Every ticket it
//! accepted reaches `done` exactly once: a receive with the length of the
//! frame that arrived, a transmit with 0, or an error [`Status`]. A driver
//! that cannot go on ends (`silica_rt::exit`), leaving what was in flight
//! to the client, which offers it again to the next driver. A change of the
//! link is reported with [`Service::link`].

use crate::device::{self, AddMemoryReply, ConnectReply, Error, Info, InfoReply, RemoveMemoryReply};
use crate::{HEADER, LINK, Op, Request, Status};
use silica_idl_rt::CapList;
use silica_queue::Refused;
use silica_queue::provider::{self, Mapper, Session};
use silica_rt::ipc::{Events, Handle};
use silica_rt::sys::Cap;

pub use silica_queue::provider::Ticket;

/// The bit of the driver's notification that clients signal.
pub const CLIENT: u64 = 1;

/// Why a driver did not start a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The device's queue is full: offer the request again after a completion.
    Busy,
    /// Complete it now with this status.
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

/// What a network driver supplies.
pub trait Device {
    /// What a mapping of a client's frame is to the driver.
    type Mapping;

    /// What the interface is (its link state as last seen).
    fn info(&self) -> Info;

    /// Let the device reach `frame` (`2^bits` bytes of a client's memory),
    /// for writing too with `writable`. Returns the device address of its
    /// first byte.
    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, Self::Mapping), Error>;

    /// The device no longer reaches that frame.
    fn unmap(&mut self, mapping: Self::Mapping);

    /// Start `request` (already checked), whose bytes the device finds at
    /// `address`. `ticket` goes to `done` when the device has finished it.
    fn start(&mut self, request: &Request, address: u64, ticket: Ticket) -> Result<(), Refusal>;

    /// The driver's notification was signalled with `bits` (other than
    /// [`CLIENT`]): report every request the device has finished (a
    /// receive's value is the frame's length), and say whether the link
    /// changed (`link`, as [`Service::link`] does).
    fn signals(&mut self, bits: u64, done: &mut Completions<'_>, link: &mut dyn FnMut(bool));

    /// Requests were started since the last call: tell the device, once.
    fn kick(&mut self);

    /// When [`Device::timeout`] is to be called if nothing else happens.
    fn deadline(&self) -> Option<u64> {
        None
    }

    /// The deadline passed.
    fn timeout(&mut self, _done: &mut Completions<'_>) {}

    /// How many requests the device holds: started, not finished.
    fn holding(&self) -> usize;

    /// The device holds requests of a client that has ended (receive
    /// buffers it would fill, its memory gone: each would swallow a frame
    /// meant for the next client). Take them back before another client
    /// is served. A device that can take back what it was given only by a
    /// reset (virtio without `RING_RESET`) ends its driver, so that the
    /// device manager resets it by starting the driver again.
    fn forget_client(&mut self) -> !;
}

/// Where a driver reports a finished request: its ticket, and the frame's
/// length (receive), 0 (transmit), or why not.
pub type Completions<'a> = dyn FnMut(Ticket, Result<u32, Status>) + 'a;

struct Map<'a, D>(&'a mut D);

impl<D: Device> Mapper for Map<'_, D> {
    type Mapping = D::Mapping;
    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, D::Mapping), Refused> {
        self.0.map(frame, bits, writable).map_err(|e| match e {
            Error::Busy => Refused::Busy,
            Error::NotConnected => Refused::NotConnected,
            Error::BadMemory => Refused::BadMemory,
            Error::InUse => Refused::InUse,
            Error::NoRoom | Error::Unknown(_) => Refused::NoRoom,
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
        Refused::Outside => Error::BadMemory,
    }
}

/// A network interface's service: the provider of `silica.net.Device`.
pub struct Service<D: Device> {
    /// The driver's part.
    pub device: D,
    session: Session<D::Mapping>,
    caller: u64,
    /// A client to wake as the driver next waits (`Session::flush`).
    wake: Option<Cap>,
}

impl<D: Device> Service<D> {
    /// A service for `device`; `wake` signals the driver's notification
    /// with [`CLIENT`].
    pub fn new(device: D, wake: Cap) -> Service<D> {
        // One client: the network stack (`Session::exclusive` says why).
        Service { device, session: Session::exclusive(wake), caller: 0, wake: None }
    }

    /// Tell the client the link went up or down.
    pub fn link(&mut self, up: bool) {
        self.session.event(LINK, 0, up as u32);
    }

    fn pump(&mut self) {
        let (session, device) = (&mut self.session, &mut self.device);
        let info = device.info();
        let largest = info.mtu.saturating_add(HEADER);
        let broken = session.take(|raw, ticket, region, _client| {
            let invalid = provider::Refusal::Fail(Status::Invalid as u32);
            let r = Request::decode(raw).ok_or(invalid)?;
            let m = region.ok_or(invalid)?;
            let fits = (r.offset as u64).checked_add(r.length as u64).is_some_and(|end| end <= m.bytes);
            let ok = match r.op {
                Op::Transmit => (HEADER..=largest).contains(&r.length),
                Op::Receive => m.writable && r.length >= largest,
            };
            if !(fits && ok) {
                return Err(invalid);
            }
            device.start(&r, m.address + r.offset as u64, ticket)?;
            Ok(ticket)
        });
        if broken != 0 {
            self.session.close(broken, &mut Map(&mut self.device));
        }
        self.device.kick();
    }

    fn device_event(&mut self, bits: Option<u64>) {
        let session = &mut self.session;
        let mut changed = None;
        {
            let mut done = |ticket: Ticket, r: Result<u32, Status>| match r {
                Ok(n) => session.complete(ticket, 0, n),
                Err(s) => session.complete(ticket, s as u32, 0),
            };
            match bits {
                Some(bits) => self.device.signals(bits, &mut done, &mut |up| changed = Some(up)),
                None => self.device.timeout(&mut done),
            }
        }
        if let Some(up) = changed {
            self.link(up);
        }
    }
}

impl<D: Device> device::Server<Handle> for Service<D> {
    fn info(&mut self) -> InfoReply {
        InfoReply { info: self.device.info() }
    }

    fn connect(&mut self, rings: Handle, completions: Handle) -> Result<ConnectReply<Handle>, Error> {
        // A client that ended left requests in the device: they go first
        // (a network stack started again would otherwise lose its first
        // frames to the buffers of the one that ended, its ARP answers
        // among them).
        if !self.session.has_client() && self.device.holding() > 0 {
            self.device.forget_client();
        }
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
