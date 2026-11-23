//! The log service (component D08): it provides `silica.log.Reader`.
//!
//! The service manager gives every other service a ring to print into
//! (`silica_rt::log`), creates the rings and the notification their writers
//! signal before it starts anything, and gives them all to this service:
//! grants 0 its endpoint, 1 the service manager's `silica.system.Manager`
//! (to learn the services' names), 2 the notification, 3 a notification of
//! the service manager's to answer flushes on, then one ring per declared
//! service, in the order the service manager lists them (an empty slot
//! where a service has none, as this one). A service that runs programs of
//! its own gives each a ring through the service manager too (the device
//! manager, one per device for its drivers: `add_log`); the service manager
//! signals [`ADDED`], and this service asks it for the new rings, which are
//! sources named `<service>/<name>`. A signal with [`FLUSH`] asks for
//! everything to be on the console now: the service manager's way to put a
//! service's last lines before its own verdict, without calling the log. On every wake-up it takes the
//! text out of every ring, keeps the last [`KEPT`] bytes of each service's,
//! and puts it on the console as it was written: another source's text
//! starts on a fresh line, and a line it cut short (a prompt, and what was
//! typed after it) is shown again below it, for its writer to go on.
//!
//! Nothing here waits on a writer, and the service manager never calls this
//! service: a log that stops costs the system its log, not its services.
#![no_std]
#![no_main]

use silica_idl_rt::{Array, CapList};
use silica_protocols::log::reader::{self as proto, Error, ReadReply, SourcesReply};
use silica_protocols::system::manager;
use silica_rt::alloc::collections::VecDeque;
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Events, Handle, serve_events};
use silica_rt::log::{BITS, RECORD, RECORDS};
use silica_rt::ring::Consumer;
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{ProcessInfo, mem, print, println, slots};

silica_rt::main!(main);

/// Bytes of each service's text kept for `read`.
const KEPT: usize = 32 * 1024;
/// The longest line put on the console in one piece; a longer one goes in parts.
const LINE: usize = 220;
/// The writer [`Log::emit`] knows this service's own lines by.
const OWN: usize = usize::MAX;
/// Rounds of taking text (a ring's worth of each source) between looking
/// at calls.
const ROUNDS: usize = 4;
/// The bit of the notification that asks for a flush (the service manager's).
const FLUSH: u64 = 2;
/// The bit of the notification that says services gave their programs logs
/// (`silica.system.Manager`'s `add_log`): this service asks for the rings.
const ADDED: u64 = 4;

struct Source {
    /// Made once, at start, and kept as long as the program runs.
    name: &'static str,
    ring: Consumer<RECORD>,
    kept: VecDeque<u8>,
    written: u64,
    /// Its ring made no sense, and that was said.
    broken: bool,
    /// Its text since its last newline: what is shown again when another
    /// source's line cut it short.
    partial: Vec<u8>,
    /// The frame of its ring, and for a program's log its place among the
    /// service manager's (`log_ring`), where a replacement ring appears
    /// when the service that made it restarts.
    cap: Cap,
    given: Option<u32>,
}

struct Log {
    sources: Vec<Source>,
    /// The service manager, which has the rings of programs' logs.
    system: manager::Client<Channel, Handle>,
    /// How many of those this service has.
    given: u32,
    /// Some ring had more than the last drain took.
    more: bool,
    /// The source whose unfinished line the console ends with.
    open: Option<usize>,
    /// The source whose unfinished line another's text cut short, until
    /// it is shown again.
    cut: Option<usize>,
    /// Signalled when a flush asked for is done.
    flushed: Cap,
    listed: Vec<proto::Source<'static>>,
    text: String,
}

impl Log {
    /// Take everything the rings hold, until each is empty and says this
    /// side sleeps, and put it on the console as it came: a line not yet
    /// finished goes out too (a prompt), and the next text of another
    /// service starts on a fresh line, as the kernel does for its writers
    /// (to the kernel, all of this is one writer).
    fn drain(&mut self) {
        // A round takes at most a ring's worth from each source, so one
        // that writes without pause cannot keep the others waiting, and a
        // few rounds at a time, so it cannot keep callers (a flush, the
        // shell) waiting either: what is left is taken at once after them
        // (`deadline`).
        for _ in 0..ROUNDS {
            let mut more = false;
            for i in 0..self.sources.len() {
                more |= self.drain_one(i);
            }
            self.more = more;
            if !more {
                return;
            }
        }
    }

    /// Take up to a ring's worth of source `i`'s text and put it on the
    /// console. Returns whether it has more.
    fn drain_one(&mut self, i: usize) -> bool {
        let s = &mut self.sources[i];
        let mut out: Vec<u8> = Vec::new();
        let (mut more, mut taken, mut notice) = (false, 0, None);
        let ring = &mut s.ring;
        loop {
            if taken == RECORDS {
                more = true;
                break;
            }
            match ring.pop() {
                Ok(Some(r)) => {
                    taken += 1;
                    s.broken = false;
                    let text = silica_rt::log::text(&r);
                    s.written += text.len() as u64;
                    for &b in text {
                        if s.kept.len() == KEPT {
                            s.kept.pop_front();
                        }
                        s.kept.push_back(b);
                    }
                    out.extend_from_slice(text);
                }
                Ok(None) => {
                    if ring.sleep() {
                        break;
                    }
                }
                Err(_) => {
                    // Its writer broke the ring: what it held is lost, and
                    // reading goes on from what the writer (or the next
                    // one: a driver started again) writes next. Said once
                    // until the ring makes sense again.
                    if !s.broken {
                        notice =
                            Some(silica_rt::alloc::format!("logd: the log ring of {} made no sense; what it held is skipped\n", s.name));
                        s.broken = true;
                    }
                    ring.skip();
                    taken += 1;
                }
            }
        }
        if let Some(n) = notice {
            self.emit(OWN, n.as_bytes());
        }
        self.emit(i, &out);
        more
    }

    /// Put `out`, text of source `from` (or [`OWN`]), on the console:
    /// another source's unfinished line ends first, and is shown again
    /// below once this text ends its line, for its writer to go on.
    fn emit(&mut self, from: usize, out: &[u8]) {
        if out.is_empty() {
            return;
        }
        if let Some(o) = self.open.filter(|o| *o != from) {
            print!("\n");
            // One line cut short is kept: the first, until shown again.
            self.cut.get_or_insert(o);
        }
        if self.cut == Some(from) {
            // This source's own line was cut short: it goes on where it was.
            self.cut = None;
            self.show_partial(from);
        }
        // In pieces of whole lines where it can, each written whole.
        for piece in out.split_inclusive(|b| *b == b'\n') {
            for part in piece.chunks(LINE) {
                print!("{}", String::from_utf8_lossy(part));
            }
        }
        if let Some(s) = self.sources.get_mut(from) {
            match out.iter().rposition(|b| *b == b'\n') {
                Some(n) => s.partial = out[n + 1..].to_vec(),
                None => s.partial.extend_from_slice(out),
            }
            // Longer than is shown again: only the length counts.
            s.partial.truncate(LINE + 1);
        }
        self.open = (out.last() != Some(&b'\n')).then_some(from);
        if self.open.is_none()
            && let Some(c) = self.cut.take()
        {
            // The line done, the one it cut short (a prompt and what was
            // typed after it) again below it, for its next text to continue.
            if self.show_partial(c) {
                self.open = Some(c);
            }
        }
    }

    /// Put source `i`'s unfinished line on the console again, if it was
    /// kept whole.
    fn show_partial(&self, i: usize) -> bool {
        let Some(s) = self.sources.get(i) else { return false };
        if s.partial.len() > LINE {
            return false;
        }
        print!("{}", String::from_utf8_lossy(&s.partial));
        true
    }

    /// Take the rings of programs' logs given since the last time.
    fn take_given(&mut self) {
        // A ring that is gone (the service that made it restarted): the
        // service manager holds its replacement in the same place, and the
        // source reads on from it, its text kept.
        for s in self.sources.iter_mut() {
            let Some(index) = s.given else { continue };
            if matches!(sys::inspect_slot(slots::SPACE, s.cap.0), Ok(Some(_))) {
                continue;
            }
            let Ok(r) = self.system.log_ring(index) else { continue };
            if let Some(ring) = ring_in(r.ring.cap()) {
                (s.ring, s.cap, s.broken) = (ring, r.ring.into_cap(), false);
            }
        }
        loop {
            let (name, ring) = match self.system.log_ring(self.given) {
                Ok(r) => (String::from(r.name), r.ring),
                Err(_) => return,
            };
            if let Some(mut source) = source(name, ring.cap()) {
                // Kept for as long as the program runs: the ring stays mapped.
                source.given = Some(self.given);
                let _ = ring.into_cap();
                self.sources.push(source);
            }
            self.given += 1;
        }
    }

    fn source(&self, name: &str) -> Result<&Source, Error> {
        self.sources.iter().find(|s| s.name == name).ok_or(Error::NoSuchSource)
    }
}

impl proto::Server<Handle> for Log {
    fn sources<'a>(&'a mut self) -> SourcesReply<'a, Handle> {
        self.drain();
        self.listed.clear();
        for s in &self.sources {
            self.listed.push(proto::Source { name: s.name, written: s.written });
        }
        SourcesReply { sources: Array::new(&self.listed) }
    }

    fn read<'a>(&'a mut self, name: &str, from: u64) -> Result<ReadReply<'a>, Error> {
        self.drain();
        let s = self.source(name)?;
        let oldest = s.written - s.kept.len() as u64;
        let start = from.clamp(oldest, s.written);
        let skip = (start - oldest) as usize;
        let bytes: Vec<u8> = s.kept.iter().skip(skip).take(3000).copied().collect();
        // Whole characters only: a part ends before a cut one.
        let text = match core::str::from_utf8(&bytes) {
            Ok(t) => t,
            Err(e) => core::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
        };
        let next = start + text.len() as u64;
        self.text = String::from(text);
        Ok(ReadReply { text: &self.text, next })
    }
}

impl Events for Log {
    fn call(&mut self, _badge: u64, request: &[u8], caps: CapList<Handle>, reply: &mut [u8], reply_caps: &mut CapList<Handle>) -> usize {
        proto::dispatch(self, request, caps, reply, reply_caps)
    }

    fn deadline(&self) -> Option<u64> {
        // Text left over: at once, after any calls waiting.
        self.more.then_some(0)
    }

    fn timer(&mut self) {
        self.drain();
    }

    fn signals(&mut self, bits: u64) {
        if bits & ADDED != 0 {
            self.take_given();
        }
        self.drain();
        if bits & FLUSH != 0 {
            // Everything written so far on the console before the answer
            // (within reason: a writer that never pauses is not waited for).
            for _ in 0..16 {
                if !self.more {
                    break;
                }
                self.drain();
            }
            let _ = sys::signal(self.flushed);
        }
    }
}

/// The log ring in the frame `cap`, mapped, if it is one.
fn ring_in(cap: Cap) -> Option<Consumer<RECORD>> {
    let Ok(Some(slot)) = sys::inspect_slot(slots::SPACE, cap.0) else { return None };
    if slot.ty != ObjectType::Frame || slot.bits != BITS {
        return None;
    }
    let region = mem::peer(cap, BITS, Rights(Rights::READ.0 | Rights::WRITE.0)).ok()?;
    let mut ring = Consumer::new(region, RECORDS)?;
    let _ = ring.sleep();
    Some(ring)
}

/// The source `name` reading the log ring in the frame `cap`, if it is one.
fn source(name: String, cap: Cap) -> Option<Source> {
    let ring = ring_in(cap)?;
    // Names last as long as the program: sources are never removed.
    let name: &'static str = silica_rt::alloc::boxed::Box::leak(name.into_boxed_str());
    Some(Source { name, ring, kept: VecDeque::new(), written: 0, broken: false, partial: Vec::new(), cap, given: None })
}

fn main(info: &'static ProcessInfo) -> i64 {
    let grant = |n: u64| Cap(slots::FIRST_GRANT + n);
    let mut system = manager::Client::<Channel, Handle>::from(Channel::new(grant(1)));
    let names: Vec<String> = match system.list() {
        Ok(r) => r.services.iter().map(|s| String::from(s.name)).collect(),
        Err(e) => {
            println!("ERROR: logd: the service manager does not answer: {e:?}");
            return 1;
        }
    };
    let rings = info.args[0] as usize;
    let mut sources = Vec::new();
    for (i, name) in names.into_iter().enumerate().take(rings) {
        sources.extend(source(name, grant(4 + i as u64)));
    }
    let mut log =
        Log { sources, system, given: 0, more: false, open: None, cut: None, flushed: grant(3), listed: Vec::new(), text: String::new() };
    // The programs' logs given so far, and what was written before this
    // service started (or before it last ended).
    log.take_given();
    log.drain();
    serve_events(grant(0), grant(2), &mut log)
}
