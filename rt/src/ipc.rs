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
/// Slots the allocator manages: one bit each, set while the slot is in use.
/// A CapSpace larger than this has its further slots left to the program.
const MANAGED: usize = 4096;
static USED: [AtomicU64; MANAGED / 64] = [const { AtomicU64::new(u64::MAX) }; MANAGED / 64];
/// The slots registered in the IPC buffer for arriving capabilities.
static INCOMING: [AtomicU64; MAX_CAPS] = [const { AtomicU64::new(0) }; MAX_CAPS];

/// Tell the transport where this thread's IPC buffer is mapped and which
/// slots of the CapSpace are free. Called by the runtime's start-up.
pub(crate) fn init(buffer: u64, first_free: u64, slots: u64) {
    BUFFER.store(buffer, Ordering::Relaxed);
    for s in first_free..slots.min(MANAGED as u64) {
        release_slot(s);
    }
    let buf = self::buffer();
    for (i, slot) in INCOMING.iter().enumerate() {
        let s = free_slot().unwrap_or(0);
        slot.store(s, Ordering::Relaxed);
        buf.accept(i, s);
    }
}

/// A slot of this program's CapSpace that nothing uses, now reserved for
/// the caller, or `None` when the CapSpace is full. Give it back with
/// [`release_slot`], or by dropping the [`Handle`] of the capability put in it.
pub fn free_slot() -> Option<u64> {
    for (i, word) in USED.iter().enumerate() {
        let mut w = word.load(Ordering::Relaxed);
        while w != u64::MAX {
            let bit = (!w).trailing_zeros() as u64;
            match word.compare_exchange_weak(w, w | 1 << bit, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(i as u64 * 64 + bit),
                Err(now) => w = now,
            }
        }
    }
    None
}

/// Return the empty slot `slot` to the allocator.
pub fn release_slot(slot: u64) {
    if let Some(word) = USED.get(slot as usize / 64) {
        word.fetch_and(!(1 << (slot % 64)), Ordering::Relaxed);
    }
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
/// program's own, in a slot of its CapSpace. Dropping it deletes the
/// capability and returns the slot to the allocator.
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
        release_slot(self.0.0);
    }
}

impl Capability for Handle {
    /// What the kernel says the capability is, so generated decoding
    /// refuses a `cap<Frame>` that is not a frame.
    fn object_type(&self) -> Option<&str> {
        Some(match sys::inspect_slot(crate::slots::SPACE, self.0.0).ok()??.ty {
            sys::ObjectType::Untyped => "Untyped",
            sys::ObjectType::CapSpace => "CapSpace",
            sys::ObjectType::Thread => "Thread",
            sys::ObjectType::AddressSpace => "AddressSpace",
            sys::ObjectType::Frame => "Frame",
            sys::ObjectType::Endpoint => "Endpoint",
            sys::ObjectType::Notification => "Notification",
            sys::ObjectType::SchedContext => "SchedContext",
            sys::ObjectType::Hw => "Hw",
            sys::ObjectType::Vcpu => "Vcpu",
        })
    }
}

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

/// List the capabilities of `caps` for sending (they move). Returns the
/// slots they are in.
fn give(buf: &IpcBuffer, caps: &mut CapList<Handle>) -> ([u64; MAX_CAPS], usize) {
    let n = caps.len();
    let mut slots = [0; MAX_CAPS];
    for (i, slot) in slots.iter_mut().enumerate().take(n) {
        if let Some(h) = caps.take(i) {
            *slot = h.into_cap().0;
            buf.pass(i, Cap(*slot), Pass::Give);
        }
    }
    (slots, n)
}

/// The message that listed `given` has been sent, or could not be: the
/// slots are the allocator's again. A capability still there (the message
/// did not reach anyone) was the transport's to release.
fn given(slots: [u64; MAX_CAPS], n: usize) {
    for s in slots.iter().take(n).filter(|s| **s != 0) {
        drop(Handle(Cap(*s)));
    }
}

/// The first `arrived` incoming slots now hold capabilities: hand them
/// over and register fresh slots in their place.
fn collect(buf: &IpcBuffer, arrived: usize, into: &mut CapList<Handle>) {
    for (i, slot) in INCOMING.iter().enumerate().take(arrived) {
        let s = slot.load(Ordering::Relaxed);
        if s != 0 {
            let _ = into.push(Handle(Cap(s)));
        }
        let fresh = free_slot().unwrap_or(0);
        slot.store(fresh, Ordering::Relaxed);
        buf.accept(i, fresh);
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
        let (slots, sent) = give(&buf, &mut caps);
        let words = pack(&buf, request);
        let result = sys::call(self.endpoint, info(request.len(), sent), words);
        given(slots, sent);
        let m = result.map_err(|e| match e {
            // The endpoint, or the provider holding the call, went away.
            Error::Gone => TransportError::PeerGone,
            // BadCap, NoRights, WrongType: this capability does not reach a provider.
            _ => TransportError::Revoked,
        })?;
        collect(&buf, m.info.caps(), reply_caps);
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
/// A caller that has gone by the time its reply is ready is not an error
/// here: the reply is dropped and the loop takes the next request. The loop
/// ends (the program exits with status -3) only when the endpoint itself is
/// gone. Capabilities of a reply nobody received are deleted.
///
/// The request's capabilities are `handle`'s: what it does not move out of
/// the list is deleted when the list is dropped.
pub fn serve(endpoint: Cap, mut handle: impl FnMut(u64, &[u8], CapList<Handle>, &mut [u8], &mut CapList<Handle>) -> usize) -> ! {
    let buf = buffer();
    let mut request = [0u8; MAX_MESSAGE];
    let mut reply = [0u8; MAX_MESSAGE];
    let mut next = sys::recv(endpoint, Wait::Forever);
    loop {
        let m = match next {
            Ok(m) => m,
            // The endpoint is gone: there is nobody left to provide for.
            Err(_) => crate::exit(-3),
        };
        let mut caps = CapList::new();
        collect(&buf, m.info.caps(), &mut caps);
        let len = unpack(&buf, m.words, m.info.label() as usize, &mut request);
        let mut reply_caps = CapList::new();
        let n = handle(m.badge, &request[..len], caps, &mut reply, &mut reply_caps).min(MAX_MESSAGE);
        let (slots, sent) = give(&buf, &mut reply_caps);
        let words = pack(&buf, &reply[..n]);
        next = sys::reply_recv(endpoint, info(n, sent), words);
        given(slots, sent);
    }
}

/// What a provider that also hears signals does with each: the two halves
/// of the loop [`serve_events`] runs.
pub trait Events {
    /// A request arrived through a capability with `badge`: write the reply
    /// and return its length, as for [`serve`] (normally a call to a
    /// generated `dispatch`).
    fn call(&mut self, badge: u64, request: &[u8], caps: CapList<Handle>, reply: &mut [u8], reply_caps: &mut CapList<Handle>) -> usize;
    /// The notification was signalled: `signals` are the badges of the
    /// capabilities it was signalled through, ORed together (an interrupt's
    /// line, a client's wake-up).
    fn signals(&mut self, signals: u64);
}

/// Provide a protocol on `endpoint` and listen on `notification`, for ever,
/// in one thread and one wait: each request goes to [`Events::call`] and is
/// answered, each batch of signals to [`Events::signals`]. This is the loop
/// of a driver (its clients' calls, its device's interrupts, its clients'
/// wake-ups) and of any server with something to hear besides calls.
///
/// As for [`serve`], a caller that has gone is not an error, and the loop
/// ends (the program exits with status -3) only when the endpoint or the
/// notification is taken away.
pub fn serve_events(endpoint: Cap, notification: Cap, handler: &mut impl Events) -> ! {
    let buf = buffer();
    let mut request = [0u8; MAX_MESSAGE];
    let mut reply = [0u8; MAX_MESSAGE];
    let mut next = sys::recv_listening(endpoint, notification, Wait::Forever);
    loop {
        let m = match next {
            Ok(m) => m,
            Err(_) => crate::exit(-3),
        };
        if let Some(signals) = m.signals() {
            handler.signals(signals);
            next = sys::recv_listening(endpoint, notification, Wait::Forever);
            continue;
        }
        let mut caps = CapList::new();
        collect(&buf, m.info.caps(), &mut caps);
        let len = unpack(&buf, m.words, m.info.label() as usize, &mut request);
        let mut reply_caps = CapList::new();
        let n = handler.call(m.badge, &request[..len], caps, &mut reply, &mut reply_caps).min(MAX_MESSAGE);
        let (slots, sent) = give(&buf, &mut reply_caps);
        let words = pack(&buf, &reply[..n]);
        next = sys::reply_recv_listening(endpoint, notification, info(n, sent), words);
        given(slots, sent);
    }
}

/// Receiving for a program whose endpoint carries more than one kind of
/// message: IDL requests beside something else (a supervisor hears its
/// children's exits and faults on the endpoint it also serves a protocol
/// on). It receives plain kernel messages and answers the ones the program
/// says are requests.
pub struct Listener {
    endpoint: Cap,
    request: [u8; MAX_MESSAGE],
    reply: [u8; MAX_MESSAGE],
}

impl Listener {
    /// A listener on `endpoint`.
    pub fn new(endpoint: Cap) -> Listener {
        Listener { endpoint, request: [0; MAX_MESSAGE], reply: [0; MAX_MESSAGE] }
    }

    /// The next message, whatever it is.
    pub fn recv(&mut self, wait: Wait) -> Result<sys::Message, Error> {
        sys::recv(self.endpoint, wait)
    }

    /// The next message, or `notification`'s signals if they come first
    /// (`sys::Message::signals` says which).
    pub fn recv_listening(&mut self, notification: Cap, wait: Wait) -> Result<sys::Message, Error> {
        sys::recv_listening(self.endpoint, notification, wait)
    }

    /// `m`, just received, is an IDL request (a call): hand it to `handle`
    /// as [`serve`] would and send the reply.
    pub fn answer(&mut self, m: &sys::Message, handle: impl FnOnce(&[u8], CapList<Handle>, &mut [u8], &mut CapList<Handle>) -> usize) {
        let buf = buffer();
        let mut caps = CapList::new();
        collect(&buf, m.info.caps(), &mut caps);
        let len = unpack(&buf, m.words, m.info.label() as usize, &mut self.request);
        let mut reply_caps = CapList::new();
        let n = handle(&self.request[..len], caps, &mut self.reply, &mut reply_caps).min(MAX_MESSAGE);
        let (slots, sent) = give(&buf, &mut reply_caps);
        let words = pack(&buf, &self.reply[..n]);
        // A caller that has gone is nobody to answer.
        let _ = sys::reply(info(n, sent), words);
        given(slots, sent);
    }
}

/// Notifications calls are parked on, made as they are needed and kept
/// (`serve_parked`): one bit each, set while it holds a call.
const PARKS: usize = 32;
static PARK_SLOTS: [AtomicU64; PARKS] = [const { AtomicU64::new(0) }; PARKS];
static PARK_BUSY: AtomicU64 = AtomicU64::new(0);

/// A free parking notification and its index, made the first time it is used.
fn take_park() -> Option<(usize, Cap)> {
    for (i, slot) in PARK_SLOTS.iter().enumerate() {
        let bit = 1u64 << i;
        if PARK_BUSY.fetch_or(bit, Ordering::Acquire) & bit != 0 {
            continue;
        }
        let mut cap = slot.load(Ordering::Relaxed);
        if cap == 0 {
            match crate::mem::Object::new(sys::ObjectType::Notification, 0) {
                // It lives as long as the program (an Object is never
                // destroyed unless asked).
                Ok(o) => {
                    cap = o.cap().0;
                    slot.store(cap, Ordering::Relaxed);
                }
                Err(_) => {
                    PARK_BUSY.fetch_and(!bit, Ordering::Release);
                    return None;
                }
            }
        }
        return Some((i, Cap(cap)));
    }
    None
}

fn free_park(i: usize) {
    PARK_BUSY.fetch_and(!(1u64 << i), Ordering::Release);
}

/// A call kept waiting (`serve_parked`): its caller waits until it is
/// answered, which any thread of the program may do, at any later time.
/// Dropping it unanswered fails the caller's call (`peer_gone`).
#[derive(Debug)]
pub struct Parked {
    index: usize,
    note: Cap,
}

impl Parked {
    /// Answer with the reply message `reply` (as a generated reply type's
    /// `encode_message` writes it) and its capabilities.
    pub fn answer(self, reply: &[u8], mut caps: CapList<Handle>) {
        let buf = buffer();
        let (slots, sent) = give(&buf, &mut caps);
        let words = pack(&buf, reply);
        let _ = sys::answer(self.note, info(reply.len(), sent), words);
        given(slots, sent);
        free_park(self.index);
        core::mem::forget(self);
    }
}

impl Drop for Parked {
    fn drop(&mut self) {
        // Answered with nothing: the caller decodes no reply and fails.
        let _ = sys::answer(self.note, MsgInfo::new(0, 0), [0; 4]);
        free_park(self.index);
    }
}

/// What a provider whose calls may wait does with each call and signal: the
/// two halves of the loop [`serve_parked`] runs.
pub trait Waiting {
    /// A request arrived through a capability with `badge`. Write the reply
    /// and return its length to answer now; or take the call out of
    /// `parked` (`parked.take()`) to answer it later with
    /// [`Parked::answer`]: a long-poll method, one that waits for something
    /// to happen (the reply written now is then not sent). `parked` is
    /// `None` when this call could not be parked: it must be answered now.
    fn call(
        &mut self,
        badge: u64,
        request: &[u8],
        caps: CapList<Handle>,
        reply: &mut [u8],
        reply_caps: &mut CapList<Handle>,
        parked: &mut Option<Parked>,
    ) -> usize;
    /// The notification was signalled with `signals` (see [`Events::signals`]):
    /// often what a kept call was waiting for.
    fn signals(&mut self, signals: u64);
}

/// Provide a protocol on `endpoint` whose calls may wait, and listen on
/// `notification` (as [`serve_events`] does). Every call arrives parked on a
/// notification of the program's own, so the provider can keep any number
/// of callers waiting (up to 32) while it takes further calls and signals.
/// Costs a system call more per call than [`serve_events`]; for protocols
/// with long-poll methods.
pub fn serve_parked(endpoint: Cap, notification: Cap, handler: &mut impl Waiting) -> ! {
    let buf = buffer();
    let mut request = [0u8; MAX_MESSAGE];
    let mut reply = [0u8; MAX_MESSAGE];
    loop {
        let park = take_park();
        let park_cap = park.map_or(Cap::NONE, |(_, c)| c);
        let m = match sys::recv_with(endpoint, notification, Wait::Forever, park_cap) {
            Ok(m) => m,
            Err(_) => crate::exit(-3),
        };
        if let Some(signals) = m.signals() {
            if let Some((i, _)) = park {
                free_park(i);
            }
            handler.signals(signals);
            continue;
        }
        let mut caps = CapList::new();
        collect(&buf, m.info.caps(), &mut caps);
        let len = unpack(&buf, m.words, m.info.label() as usize, &mut request);
        // The call is parked when the kernel could park it (it can on the
        // receiving processor, which is where this thread's notifications
        // are); otherwise it waits on this thread and is answered now.
        let parked = park.filter(|(_, c)| sys::recv(*c, Wait::Poll) == Err(Error::InUse));
        if let (Some((i, _)), None) = (park, parked) {
            free_park(i);
        }
        let mut token = parked.map(|(index, note)| Parked { index, note });
        let mut reply_caps = CapList::new();
        let n = handler.call(m.badge, &request[..len], caps, &mut reply, &mut reply_caps, &mut token).min(MAX_MESSAGE);
        match (parked, token) {
            // Kept for later.
            (Some(_), None) => {}
            // Answered now, through the notification it is parked on.
            (Some(_), Some(t)) => t.answer(&reply[..n], reply_caps),
            // Not parked: it waits on this thread.
            (None, _) => {
                let (slots, sent) = give(&buf, &mut reply_caps);
                let words = pack(&buf, &reply[..n]);
                let _ = sys::reply(info(n, sent), words);
                given(slots, sent);
            }
        }
    }
}
