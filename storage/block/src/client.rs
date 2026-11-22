//! A client of a block device: finds its driver through the device manager,
//! registers memory, sends requests, and survives the driver.
//!
//! A driver can end at any moment: it fails, or its owner restarts it. The
//! client hears of it at once, opens the driver that replaces it, registers
//! its memory again, and sends again every request that had not completed
//! (`silica_queue::client`). To the program using a [`Disk`], a driver's end
//! is a delay; a request is never lost, and is never completed twice.
//! (Requests sent again may be carried out twice: reads and writes of
//! blocks may be.)

use crate::device::{self, Info};
use crate::partitions;
use crate::{Completion, QUEUE, Request, Status};
use silica_queue::Refused;
use silica_queue::client::{self, Control, Opener, Queue};
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;
use silica_rt::sys::Cap;

/// Why something a client asked for did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The provider refused (`silica.block.Device`'s own error).
    Refused(device::Error),
    /// The device has no driver, and none came back within
    /// [`Disk::RECONNECT_NS`].
    Gone,
    /// The provider broke the protocol (a malformed reply, a ring that
    /// makes no sense).
    Protocol,
    /// This program has no memory or capability slots left for it.
    NoMemory,
    /// [`Disk::QUEUE`] requests are in progress, or the tag is in use.
    Full,
    /// No completion arrived before the deadline.
    Timeout,
    /// The request itself failed.
    Request(Status),
}

impl From<client::Error> for Error {
    fn from(e: client::Error) -> Error {
        match e {
            client::Error::Refused(r) => Error::Refused(match r {
                Refused::Busy => device::Error::Busy,
                Refused::NotConnected => device::Error::NotConnected,
                Refused::BadMemory => device::Error::BadMemory,
                Refused::NoRoom => device::Error::NoRoom,
                Refused::InUse => device::Error::InUse,
                Refused::Outside => device::Error::Outside,
            }),
            client::Error::Gone => Error::Gone,
            client::Error::Protocol => Error::Protocol,
            client::Error::NoMemory => Error::NoMemory,
            client::Error::Full => Error::Full,
            client::Error::Timeout => Error::Timeout,
        }
    }
}

impl From<device::Error> for client::Error {
    fn from(e: device::Error) -> client::Error {
        client::Error::Refused(match e {
            device::Error::Busy => Refused::Busy,
            device::Error::NotConnected => Refused::NotConnected,
            device::Error::BadMemory => Refused::BadMemory,
            device::Error::NoRoom => Refused::NoRoom,
            device::Error::InUse => Refused::InUse,
            device::Error::Outside => Refused::Outside,
            device::Error::NoSuchRequest | device::Error::Unknown(_) => return client::Error::Protocol,
        })
    }
}

/// `silica.block.Device` as the queue uses it.
pub struct Block {
    /// The endpoint to the driver (deleted with the link).
    _endpoint: Handle,
    control: device::Client<Channel, Handle>,
    info: Info,
}

impl Control for Block {
    fn open(driver: Handle) -> Result<Block, client::Error> {
        let mut control = device::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
        let info = control.info()?.info;
        Ok(Block { _endpoint: driver, control, info })
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

/// Partitions are opened through the partitions service as disks are
/// through the device manager.
impl Opener for partitions::Client<Channel, Handle> {
    fn open(&mut self, id: u32, gone: Handle) -> Result<Handle, client::Error> {
        match partitions::Client::open(self, id, Some(gone)) {
            Ok(r) => Ok(r.device),
            Err(silica_idl_rt::CallError::Error(partitions::Error::Gone)) => Err(client::Error::Gone),
            Err(silica_idl_rt::CallError::Error(_)) => Err(client::Error::Refused(Refused::BadMemory)),
            Err(silica_idl_rt::CallError::Transport(_)) => Err(client::Error::Gone),
        }
    }
}

/// A connection to a block device that outlives its driver.
pub struct Disk {
    queue: Queue<Block>,
    info: Info,
}

impl Disk {
    /// The most requests in progress at once.
    pub const QUEUE: u32 = QUEUE;
    /// How long a driver that ended has to come back before requests fail
    /// with [`Error::Gone`].
    pub const RECONNECT_NS: u64 = Queue::<Block>::RECONNECT_NS;

    /// Open the disk with identity `id` through the device manager behind
    /// `devices` (a capability to its endpoint; the disk keeps it to find
    /// the next driver when this one ends).
    pub fn open(devices: Cap, id: u32) -> Result<Disk, Error> {
        let mut queue = Queue::<Block>::open(devices, id)?;
        let info = queue.control()?.info.clone();
        Ok(Disk { queue, info })
    }

    /// Open partition `id` through the partitions service behind
    /// `partitions` (`silica.block.Partitions`): a disk whose blocks are the
    /// partition's, from 0, that outlives its driver as a whole disk does.
    pub fn open_partition(partitions: Cap, id: u32) -> Result<Disk, Error> {
        let opener = silica_rt::alloc::boxed::Box::new(partitions::Client::<Channel, Handle>::from(Channel::new(partitions)));
        let mut queue = Queue::<Block>::open_with(opener, id)?;
        let info = queue.control()?.info.clone();
        Ok(Disk { queue, info })
    }

    /// What the device is.
    pub fn info(&self) -> &Info {
        &self.info
    }

    /// How long the last recovery from a driver's end took, from the end
    /// being noticed to the first completion after it (ns), once: the next
    /// call says `None` until there is another.
    pub fn take_recovery(&mut self) -> Option<u64> {
        self.queue.take_recovery()
    }

    /// Register `memory` under the number `id` (below [`crate::MEMORIES`]):
    /// requests may name data in it from then on, for as long as it stays
    /// registered (the caller keeps `memory` alive until
    /// [`Disk::remove_memory`]). With `writable` the device may write it
    /// (needed to read from the device into it).
    pub fn add_memory(&mut self, id: u32, memory: &Memory, writable: bool) -> Result<(), Error> {
        Ok(self.queue.add_memory(id, memory, writable)?)
    }

    /// Withdraw the registration `id`.
    pub fn remove_memory(&mut self, id: u32) -> Result<(), Error> {
        Ok(self.queue.remove_memory(id)?)
    }

    /// How many requests are in progress.
    pub fn in_progress(&self) -> u32 {
        self.queue.in_progress()
    }

    /// Put a request in the ring. The driver is told by [`Disk::kick`],
    /// once for any number of requests. Its tag must be below 2^63 and not
    /// in use.
    pub fn submit(&mut self, request: &Request) -> Result<(), Error> {
        Ok(self.queue.submit(&request.encode())?)
    }

    /// Tell the driver about submitted requests, if it sleeps.
    pub fn kick(&mut self) {
        self.queue.kick()
    }

    /// The next completion, if one is there.
    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        Ok(self.queue.poll()?.map(Completion::from))
    }

    /// The next completion, waiting for it until the monotonic time
    /// `deadline` (nanoseconds; `None`: for ever).
    pub fn wait(&mut self, deadline: Option<u64>) -> Result<Completion, Error> {
        Ok(self.queue.wait(deadline)?.into())
    }

    /// Where the traced request `tag` (bit [`crate::service::TRACED`] set)
    /// went in the driver: when it was taken, when the device accepted it,
    /// when it completed (monotonic ns; 0: not yet).
    pub fn trace(&mut self, tag: u64) -> Result<(u64, u64, u64), Error> {
        let r = self.queue.control()?.control.trace(tag).map_err(client::Error::from)?;
        Ok((r.taken, r.started, r.done))
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
