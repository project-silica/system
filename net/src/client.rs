//! A client of a network interface: finds its driver through the device
//! manager, registers memory, sends frames and offers buffers for frames to
//! arrive in, and survives the driver (`silica_queue::client`): when the
//! driver ends, receive buffers it had not filled are offered to the next
//! one and frames it had not sent are sent by the next one.

use crate::device::{self, Info};
use crate::{Completion, QUEUE, Request};
use silica_queue::Refused;
use silica_queue::client::{self, Control, Queue};
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::sys::Cap;

pub use silica_queue::client::Error;

impl From<device::Error> for client::Error {
    fn from(e: device::Error) -> client::Error {
        client::Error::Refused(match e {
            device::Error::Busy => Refused::Busy,
            device::Error::NotConnected => Refused::NotConnected,
            device::Error::BadMemory => Refused::BadMemory,
            device::Error::NoRoom => Refused::NoRoom,
            device::Error::InUse => Refused::InUse,
            device::Error::Unknown(_) => return client::Error::Protocol,
        })
    }
}

/// `silica.net.Device` as the queue uses it.
pub struct Net {
    _endpoint: Handle,
    control: device::Client<Channel, Handle>,
    info: Info,
}

impl Control for Net {
    fn open(driver: Handle) -> Result<Net, client::Error> {
        let mut control = device::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
        let info = control.info()?.info;
        Ok(Net { _endpoint: driver, control, info })
    }

    fn connect(&mut self, rings: Handle, completions: Handle) -> Result<Handle, client::Error> {
        Ok(self.control.connect(rings, completions)?.requests)
    }

    fn add_memory(&mut self, id: u32, frame: Handle, writable: bool) -> Result<(), client::Error> {
        self.control.add_memory(id, frame, writable)?;
        Ok(())
    }

    fn remove_memory(&mut self, id: u32) -> Result<(), client::Error> {
        self.control.remove_memory(id)?;
        Ok(())
    }
}

/// A connection to a network interface that outlives its driver.
pub struct Interface {
    queue: Queue<Net>,
}

impl Interface {
    /// The most requests (frames being sent and buffers offered) at once.
    pub const QUEUE: u32 = QUEUE;

    /// Open the interface with identity `id` through the device manager
    /// behind `devices`.
    pub fn open(devices: Cap, id: u32) -> Result<Interface, Error> {
        Ok(Interface { queue: Queue::<Net>::open(devices, id)? })
    }

    /// What the interface is, as its current driver said when it was opened.
    pub fn info(&mut self) -> Result<Info, Error> {
        Ok(self.queue.control()?.info.clone())
    }

    /// Register `memory` under the number `id` (below [`crate::MEMORIES`]);
    /// with `writable` the device may write it (needed for receive buffers).
    pub fn add_memory(&mut self, id: u32, memory: &Memory, writable: bool) -> Result<(), Error> {
        self.queue.add_memory(id, memory, writable)
    }

    /// Withdraw the registration `id`.
    pub fn remove_memory(&mut self, id: u32) -> Result<(), Error> {
        self.queue.remove_memory(id)
    }

    /// How many requests are in progress.
    pub fn in_progress(&self) -> u32 {
        self.queue.in_progress()
    }

    /// Put a request in the ring; the driver is told by [`Interface::kick`].
    pub fn submit(&mut self, request: &Request) -> Result<(), Error> {
        self.queue.submit(&request.encode())
    }

    /// Tell the driver about submitted requests, if it sleeps.
    pub fn kick(&mut self) {
        self.queue.kick()
    }

    /// [`Interface::kick`] and [`Interface::wait`] in one system call when
    /// the client must sleep (`silica_queue::client::Queue::kick_wait`).
    pub fn kick_wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        Ok(self.queue.kick_wait(deadline)?.into())
    }

    /// The next completion or link record, if one is there.
    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        Ok(self.queue.poll()?.map(Completion::from))
    }

    /// The next completion or link record, waiting for it until the
    /// monotonic time `deadline` (nanoseconds; `None`: for ever).
    pub fn wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        Ok(self.queue.wait(deadline)?.into())
    }

    /// How long the last recovery from a driver's end took (ns), once.
    pub fn take_recovery(&mut self) -> Option<u64> {
        self.queue.take_recovery()
    }
}
