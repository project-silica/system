//! IDL calls over kernel IPC: the transport generated clients use, and the
//! loop a provider runs.
//!
//! One IDL message is one kernel message. Its bytes travel as message words
//! (the first 32 bytes in registers, the rest in the IPC buffer) and the
//! message label is its length in bytes. Its capabilities move with it: the
//! sender gives them away, and they arrive in fresh slots of the receiver's
//! CapSpace, owned by a [`Handle`] each.

use crate::sys::{self, Cap, Error, IpcBuffer, MsgInfo, Pass, Wait};
use core::sync::atomic::{AtomicU64, Ordering};
use silica_idl_rt::{CapList, Capability, MAX_CAPS, MAX_MESSAGE, Transport, TransportError};

static BUFFER: AtomicU64 = AtomicU64::new(0);
static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
static SLOT_END: AtomicU64 = AtomicU64::new(0);

/// Tell the transport where this thread's IPC buffer is mapped and which
/// slots of the CapSpace are free for received capabilities. Called by the
/// runtime's start-up.
pub(crate) fn init(buffer: u64, first_free: u64, slots: u64) {
    BUFFER.store(buffer, Ordering::Relaxed);
    NEXT_SLOT.store(first_free, Ordering::Relaxed);
    SLOT_END.store(slots, Ordering::Relaxed);
}

/// A slot of this program's CapSpace that nothing uses, or `None` when the
/// CapSpace is full. (Slots are not yet reused once given out.)
pub fn free_slot() -> Option<u64> {
    let s = NEXT_SLOT.fetch_add(1, Ordering::Relaxed);
    (s < SLOT_END.load(Ordering::Relaxed)).then_some(s)
}

fn buffer() -> IpcBuffer {
    // SAFETY: the address the parent mapped this program's first IPC buffer
    // at, taken from the start-up record; the mapping lasts as long as the program.
    #[allow(unsafe_code)]
    unsafe {
        IpcBuffer::new(BUFFER.load(Ordering::Relaxed) as usize)
    }
}

/// A capability that arrived in, or is to be sent in, an IDL message: the
/// program's own, in a slot of its CapSpace. Dropping it deletes the capability.
#[derive(Debug)]
pub struct Handle(Cap);

impl Handle {
    /// Take ownership of the capability in `cap`'s slot.
    pub fn new(cap: Cap) -> Handle {
        Handle(cap)
    }
    /// The slot, to use the capability with `sys` calls while the handle lives.
    pub fn cap(&self) -> Cap {
        self.0
    }
    /// Give up ownership without deleting: the capability stays in its slot.
    pub fn into_cap(self) -> Cap {
        let cap = self.0;
        core::mem::forget(self);
        cap
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle owns the capability and nothing else names its slot.
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::cap_delete(self.0);
        }
    }
}

impl Capability for Handle {}

/// The message words in registers for `bytes`; the rest goes to the buffer.
fn pack(buf: &IpcBuffer, bytes: &[u8]) -> [u64; 4] {
    let mut head = [0u8; 32];
    let n = bytes.len().min(32);
    head[..n].copy_from_slice(&bytes[..n]);
    if bytes.len() > 32 {
        buf.copy_in(32, &bytes[32..]);
    }
    core::array::from_fn(|i| u64::from_le_bytes(head[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8])))
}

/// The bytes of a received message of `len` bytes, into `out`. Returns how many.
fn unpack(buf: &IpcBuffer, words: [u64; 4], len: usize, out: &mut [u8]) -> usize {
    let len = len.min(out.len()).min(MAX_MESSAGE);
    let mut head = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        head[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    let n = len.min(32);
    out[..n].copy_from_slice(&head[..n]);
    if len > 32 {
        buf.copy_out(32, &mut out[32..len]);
    }
    len
}

/// List the capabilities of `caps` for sending (they move). Returns how many.
fn give(buf: &IpcBuffer, caps: &mut CapList<Handle>) -> usize {
    let n = caps.len();
    for i in 0..n {
        if let Some(h) = caps.take(i) {
            buf.pass(i, h.into_cap(), Pass::Give);
        }
    }
    n
}

/// Fresh slots for whatever capabilities the next message brings.
fn expect(buf: &IpcBuffer) -> [u64; MAX_CAPS] {
    let slots = core::array::from_fn(|_| free_slot().unwrap_or(0));
    for (i, s) in slots.iter().enumerate() {
        buf.accept(i, *s);
    }
    slots
}

/// The first `arrived` of `slots` now hold capabilities: hand them over.
fn collect(slots: [u64; MAX_CAPS], arrived: usize, into: &mut CapList<Handle>) {
    for s in slots.iter().take(arrived) {
        let _ = into.push(Handle(Cap(*s)));
    }
}

fn info(bytes: usize, caps: usize) -> MsgInfo {
    MsgInfo::with_caps(bytes as u64, bytes.div_ceil(8), caps)
}

/// The client side of a connection: an endpoint capability to a provider.
/// Generated clients wrap one (`Client::from(Channel::new(endpoint))`).
pub struct Channel {
    endpoint: Cap,
}

impl Channel {
    /// A channel through the endpoint capability `endpoint`, which must
    /// allow sending (and passing capabilities, if the protocol does).
    pub fn new(endpoint: Cap) -> Channel {
        Channel { endpoint }
    }
}

impl Transport<Handle> for Channel {
    fn call(
        &mut self,
        request: &[u8],
        mut caps: CapList<Handle>,
        reply: &mut [u8],
        reply_caps: &mut CapList<Handle>,
    ) -> Result<usize, TransportError> {
        let buf = buffer();
        let sent = give(&buf, &mut caps);
        let slots = expect(&buf);
        let words = pack(&buf, request);
        let m = sys::call(self.endpoint, info(request.len(), sent), words).map_err(|e| match e {
            // The endpoint, or the provider holding the call, went away.
            Error::Gone => TransportError::PeerGone,
            // BadCap, NoRights, WrongType: this capability does not reach a provider.
            _ => TransportError::Revoked,
        })?;
        collect(slots, m.info.caps(), reply_caps);
        Ok(unpack(&buf, m.words, m.info.label() as usize, reply))
    }
}

/// Provide a protocol on `endpoint` for ever: receive each request, hand it
/// to `handle` with the badge of the capability the caller used, and send
/// back the reply it wrote. `handle` is normally a call to a generated
/// `dispatch`:
///
/// ```text
/// serve(endpoint, |_badge, request, caps, reply, reply_caps| {
///     my_protocol::dispatch(&mut server, request, caps, reply, reply_caps)
/// })
/// ```
///
/// The request's capabilities are `handle`'s: what it does not move out of
/// the list is deleted when the list is dropped.
pub fn serve(endpoint: Cap, mut handle: impl FnMut(u64, &[u8], CapList<Handle>, &mut [u8], &mut CapList<Handle>) -> usize) -> ! {
    let buf = buffer();
    let mut request = [0u8; MAX_MESSAGE];
    let mut reply = [0u8; MAX_MESSAGE];
    let mut slots = expect(&buf);
    let mut next = sys::recv(endpoint, Wait::Forever);
    loop {
        let m = match next {
            Ok(m) => m,
            // The endpoint is gone: there is nobody left to provide for.
            Err(_) => crate::exit(-3),
        };
        let mut caps = CapList::new();
        collect(slots, m.info.caps(), &mut caps);
        let len = unpack(&buf, m.words, m.info.label() as usize, &mut request);
        let mut reply_caps = CapList::new();
        let n = handle(m.badge, &request[..len], caps, &mut reply, &mut reply_caps).min(MAX_MESSAGE);
        let sent = give(&buf, &mut reply_caps);
        slots = expect(&buf);
        let words = pack(&buf, &reply[..n]);
        next = sys::reply_recv(endpoint, info(n, sent), words);
    }
}
