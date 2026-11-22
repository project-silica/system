//! A client of a block device: connects to a provider of
//! `silica.block.Device`, registers memory, and sends requests.

use crate::device::{self, Info};
use crate::{COMPLETION_BYTES, COMPLETIONS_AT, Completion, QUEUE, REQUEST_BYTES, RINGS_BITS, Request, Status};
use silica_idl_rt::{CallError, TransportError};
use silica_ring::{Consumer, Producer};
use silica_rt::ipc::{Channel, Handle, free_slot, release_slot};
use silica_rt::mem::{Memory, Object};
use silica_rt::mmio::Mmio;
use silica_rt::slots;
use silica_rt::sys::{self, Cap, ObjectType, Rights, Wait};

/// Why something a client asked for did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The provider refused (`silica.block.Device`'s own error).
    Refused(device::Error),
    /// The provider is gone, or its endpoint was taken away: connect again
    /// to the provider that replaces it and send unfinished requests again.
    Gone,
    /// The provider broke the protocol (a malformed reply, a ring that
    /// makes no sense).
    Protocol,
    /// This program has no memory or capability slots left for it.
    NoMemory,
    /// [`Disk::QUEUE`] requests are in progress: take completions first.
    Full,
    /// No completion arrived before the deadline.
    Timeout,
    /// The request itself failed.
    Request(Status),
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

impl From<device::Error> for Error {
    fn from(e: device::Error) -> Error {
        Error::Refused(e)
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

/// A connection to a block device.
pub struct Disk {
    control: device::Client<Channel, Handle>,
    info: Info,
    requests: Producer<REQUEST_BYTES>,
    completions: Consumer<COMPLETION_BYTES>,
    /// Signalled when the provider must look at the request ring.
    wake: Handle,
    /// What the provider signals when completions are there.
    done: Object,
    in_progress: u32,
}

/// A copy of `cap` to give away, with `rights`.
fn lend(cap: Cap, rights: Rights) -> Result<Handle, Error> {
    let slot = free_slot().ok_or(Error::NoMemory)?;
    sys::cap_derive(slots::SPACE, slot, cap, rights, 0).inspect_err(|_| release_slot(slot))?;
    Ok(Handle::new(Cap(slot)))
}

impl Disk {
    /// The most requests in progress at once.
    pub const QUEUE: u32 = QUEUE;

    /// Connect to the provider behind `endpoint` (a capability that may
    /// send, and pass capabilities).
    pub fn connect(endpoint: Cap) -> Result<Disk, Error> {
        let mut control = device::Client::<Channel, Handle>::from(Channel::new(endpoint));
        let info = control.info()?.info;
        let rings = Memory::new(RINGS_BITS)?;
        let done = Object::new(ObjectType::Notification, 0)?;
        let reply = control.connect(lend(rings.frame(), Rights(3))?, lend(done.cap(), Rights::WRITE)?)?;
        let wake = reply.requests;
        // SAFETY: the rings' frame, this program's own memory, mapped for
        // as long as the program runs (the `Memory` is never freed), holding
        // only the rings.
        #[allow(unsafe_code)]
        let region = unsafe { Mmio::new(rings.addr(), rings.len()) };
        let (Some(req), Some(cpl)) = (region.part(0, COMPLETIONS_AT), region.part(COMPLETIONS_AT, rings.len() - COMPLETIONS_AT)) else {
            return Err(Error::Protocol);
        };
        let (Some(requests), Some(completions)) = (Producer::new(req, QUEUE), Consumer::new(cpl, QUEUE)) else {
            return Err(Error::Protocol);
        };
        Ok(Disk { control, info, requests, completions, wake, done, in_progress: 0 })
    }

    /// What the device is.
    pub fn info(&self) -> &Info {
        &self.info
    }

    /// Register `memory` under the number `id` (below [`crate::MEMORIES`]):
    /// requests may name data in it from then on. With `writable` the device
    /// may write it (needed to read from the device into it).
    pub fn add_memory(&mut self, id: u32, memory: &Memory, writable: bool) -> Result<(), Error> {
        let rights = Rights(Rights::READ.0 | if writable { Rights::WRITE.0 } else { 0 });
        self.control.add_memory(id, lend(memory.frame(), rights)?, writable)?;
        Ok(())
    }

    /// Withdraw the registration `id`.
    pub fn remove_memory(&mut self, id: u32) -> Result<(), Error> {
        self.control.remove_memory(id)?;
        Ok(())
    }

    /// How many requests are in progress.
    pub fn in_progress(&self) -> u32 {
        self.in_progress
    }

    /// Put a request in the ring. The provider is told by [`Disk::kick`],
    /// once for any number of requests.
    pub fn submit(&mut self, request: &Request) -> Result<(), Error> {
        if self.in_progress >= QUEUE {
            return Err(Error::Full);
        }
        self.requests.push(&request.encode()).map_err(|_| Error::Full)?;
        self.in_progress += 1;
        Ok(())
    }

    /// Tell the provider about submitted requests, if it sleeps.
    pub fn kick(&mut self) {
        if self.requests.wake_needed() {
            let _ = sys::signal(self.wake.cap());
        }
    }

    /// The next completion, if one is there.
    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        match self.completions.pop() {
            Ok(Some(c)) => {
                self.in_progress = self.in_progress.saturating_sub(1);
                Ok(Some(Completion::decode(&c)))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(Error::Protocol),
        }
    }

    /// The next completion, waiting for it until the monotonic time
    /// `deadline` (nanoseconds; `None`: for ever).
    pub fn wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        loop {
            if let Some(c) = self.poll()? {
                return Ok(c);
            }
            if self.completions.sleep() && sys::recv(self.done.cap(), deadline.map_or(Wait::Forever, Wait::Until)).is_err() {
                return Err(Error::Timeout);
            }
        }
    }

    /// One request, start to finish: submit, kick, wait. For a program
    /// that does one thing at a time; nothing else may be in progress.
    pub fn run(&mut self, request: &Request, deadline: Option<u64>) -> Result<(), Error> {
        self.submit(request)?;
        self.kick();
        let c = self.wait(deadline)?;
        if c.tag != request.tag {
            return Err(Error::Protocol);
        }
        c.status.map_err(Error::Request)
    }
}
