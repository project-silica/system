//! The log service (component D08): it provides `silica.log.Reader`.
//!
//! The service manager gives every other service a ring to print into
//! (`silica_rt::log`), creates the rings and the notification their writers
//! signal before it starts anything, and gives them all to this service:
//! grants 0 its endpoint, 1 the notification (its own events notification,
//! which the writers signal too), 2 the ring directory
//! (`silica_rt::log::directory`), then a slot per entry of the directory
//! (`args[0]` of them), holding that entry's ring. A service that runs
//! programs of its own gives each a ring through the service manager too
//! (the device manager, one per device for its drivers: `add_log`), which
//! puts it in the next slot, names it in the directory and signals
//! [`ADDED`]: those are sources named `<service>/<name>`. This service
//! never calls the service manager. Asked to end (`silica_rt::END`, as the
//! machine turns off, when every other service has ended), it puts
//! everything the rings hold on the console and exits: the service
//! manager hears of the exit from the kernel, so the services' last lines
//! are out before the power goes and nothing waits out a time for them.
//! On every wake-up it takes the
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
use silica_protocols::paging;
use silica_rt::alloc::collections::VecDeque;
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Events, Handle, serve_events};
use silica_rt::log::{BITS, RECORD, RECORDS, directory};
use silica_rt::ring::Consumer;
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{ProcessInfo, mem, print, println, slots};

silica_rt::main!(main);

/// Bytes of each service's text kept for `read`.
const KEPT: usize = 32 * 1024;
/// The longest line put on the console in one piece; a longer one goes in parts.
const LINE: usize = 220;
/// The kept page (`slots::KEEP`): a mark, then `open` and `cut`, each its
/// source's directory entry + 1 (0: none), its line's length and its line.
const KEPT_MAGIC: u64 = 0x3170_6565_6B64_676F; // "ogdkeep1"
const KEPT_OPEN: usize = 8;
const KEPT_CUT: usize = KEPT_OPEN + 8 + LINE;
/// The writer [`Log::emit`] knows this service's own lines by.
const OWN: usize = usize::MAX;
/// Rounds of taking text (a ring's worth of each source) between looking
/// at calls.
const ROUNDS: usize = 4;
/// The bit of the notification that says services gave their programs logs
/// (`silica.system.Manager`'s `add_log`): this service asks for the rings.
const ADDED: u64 = 4;

struct Source {
    /// As the directory names it; an entry reused for another name (a log
    /// whose maker ended for good gives its place to a new one) starts a
    /// new source in its place. Each name is kept once (`Log::names`):
    /// only the device manager names logs, from a bounded set.
    name: &'static str,
    ring: Consumer<RECORD>,
    /// Where the ring is mapped: replaced with it.
    _mapped: mem::Lent,
    kept: VecDeque<u8>,
    written: u64,
    /// Its ring made no sense, and that was said.
    broken: bool,
    /// Its text since its last newline: what is shown again when another
    /// source's line cut it short.
    partial: Vec<u8>,
    /// Its directory entry, and that entry's generation when its ring was
    /// taken: a new one names a replacement ring (the program that made
    /// the old one was started again), taken from the same slot.
    entry: usize,
    generation: u32,
}

struct Log {
    sources: Vec<Source>,
    /// The ring directory, and how many entries (and ring slots) there are.
    directory: silica_rt::mmio::Mmio,
    entries: usize,
    /// Some ring had more than the last drain took.
    more: bool,
    /// The source whose unfinished line the console ends with.
    open: Option<usize>,
    /// The source whose unfinished line another's text cut short, until
    /// it is shown again.
    cut: Option<usize>,
    /// The page the service manager keeps across this service's restarts
    /// (`slots::KEEP`), with `open` and `cut` and their lines in it.
    keep: Option<silica_rt::mmio::Mmio>,
    listed: Vec<proto::Source<'static>>,
    /// Every source name seen, each kept once.
    names: Vec<&'static str>,
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
        // few rounds at a time, so it cannot keep callers (the
        // shell) waiting either: what is left is taken at once after them
        // (`deadline`).
        for _ in 0..ROUNDS {
            let mut more = false;
            for i in 0..self.sources.len() {
                more |= self.drain_one(i);
            }
            self.more = more;
            if !more {
                break;
            }
        }
        self.save();
    }

    /// Keep `open` and `cut`, and their lines, in the kept page: what the
    /// console ends with is this service's to know, and a log service
    /// started again must not write after a prompt as if the line were
    /// empty (it did: `silica> remote: ...`, 2026-11-24). Sources are kept
    /// by their directory entry, which the next instance finds them by.
    fn save(&self) {
        let Some(k) = &self.keep else { return };
        for (at, which) in [(KEPT_OPEN, self.open), (KEPT_CUT, self.cut)] {
            let s = which.and_then(|i| self.sources.get(i));
            k.write32(at, s.map_or(0, |s| s.entry as u32 + 1));
            let line = s.map_or(&[][..], |s| &s.partial[..s.partial.len().min(LINE)]);
            k.write32(at + 4, line.len() as u32);
            k.write_bytes(at + 8, line);
        }
        k.write64(0, KEPT_MAGIC);
    }

    /// What the last instance kept (`save`), once its sources are taken
    /// again.
    fn restore(&mut self) {
        let Some(k) = &self.keep else { return };
        if k.read64(0) != KEPT_MAGIC {
            return;
        }
        let mut kept = [None, None];
        for (n, at) in [KEPT_OPEN, KEPT_CUT].into_iter().enumerate() {
            let entry = k.read32(at) as usize;
            let len = (k.read32(at + 4) as usize).min(LINE);
            let Some(i) = entry.checked_sub(1).and_then(|e| self.sources.iter().position(|s| s.entry == e)) else { continue };
            let mut line = silica_rt::alloc::vec![0u8; len];
            k.read_bytes(at + 8, &mut line);
            self.sources[i].partial = line;
            kept[n] = Some(i);
        }
        [self.open, self.cut] = kept;
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
                // Another program's text: shown, not obeyed
                // (`silica_rt::text`).
                print!("{}", silica_rt::text::printable(&String::from_utf8_lossy(part)));
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
        print!("{}", silica_rt::text::printable(&String::from_utf8_lossy(&s.partial)));
        true
    }

    /// Take the rings the directory names that are new, or replaced since
    /// they were taken.
    fn take_rings(&mut self) {
        let mut name = [0u8; directory::NAME];
        for entry in 0..self.entries {
            let (generation, n) = directory::read(&self.directory, entry, &mut name);
            if generation == 0 {
                continue;
            }
            let known = self.sources.iter().position(|s| s.entry == entry);
            if known.is_some_and(|i| self.sources[i].generation == generation) {
                continue;
            }
            // Not there (its maker already ended): looked at again with the
            // next change.
            let Some((ring, mapped)) = ring_in(ring_slot(entry)) else { continue };
            let name = String::from_utf8_lossy(&name[..n]);
            let name: &'static str = match self.names.iter().find(|k| **k == name) {
                Some(k) => k,
                None => {
                    let k: &'static str = silica_rt::alloc::boxed::Box::leak(name.into_owned().into_boxed_str());
                    self.names.push(k);
                    k
                }
            };
            match known {
                // Read on from the new ring under the same source, its text kept.
                Some(i) if self.sources[i].name == name => {
                    let s = &mut self.sources[i];
                    (s.ring, s._mapped, s.broken, s.generation) = (ring, mapped, false, generation);
                }
                // The entry is another log's now: a new source in its place.
                known => {
                    if let Some(i) = known {
                        self.sources.swap_remove(i);
                    }
                    self.sources.push(Source {
                        name,
                        ring,
                        _mapped: mapped,
                        kept: VecDeque::new(),
                        written: 0,
                        broken: false,
                        partial: Vec::new(),
                        entry,
                        generation,
                    });
                }
            }
        }
    }

    fn source(&self, name: &str) -> Result<&Source, Error> {
        self.sources.iter().find(|s| s.name == name).ok_or(Error::NoSuchSource)
    }
}

impl proto::Server<Handle> for Log {
    fn sources<'a>(&'a mut self, from: u32) -> SourcesReply<'a, Handle> {
        self.drain();
        self.listed.clear();
        let listed = &mut self.listed;
        let next = paging::part(
            &self.sources,
            from,
            |s| paging::record(paging::text(s.name.len()) + 8),
            |s| listed.push(proto::Source { name: s.name, written: s.written }),
        );
        SourcesReply { sources: Array::new(&self.listed), next }
    }

    fn read<'a>(&'a mut self, name: &str, from: u64) -> Result<ReadReply<'a>, Error> {
        self.drain();
        let s = self.source(name)?;
        let oldest = s.written - s.kept.len() as u64;
        let start = from.clamp(oldest, s.written);
        let skip = (start - oldest) as usize;
        const PAGE_BYTES: usize = 3000;
        let bytes: Vec<u8> = s.kept.iter().skip(skip).take(PAGE_BYTES + 3).copied().collect();
        silica_rt::log::read_text(&bytes, PAGE_BYTES, &mut self.text);
        let next = start + self.text.len() as u64;
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
            self.take_rings();
        }
        self.drain();
        if bits & silica_rt::END != 0 {
            // Everything written so far on the console, then the end
            // (within reason: a writer that never pauses is not waited for).
            for _ in 0..16 {
                if !self.more {
                    break;
                }
                self.drain();
            }
            self.save();
            silica_rt::exit(0);
        }
    }
}

/// The log ring in the frame `cap`, mapped, if it is one.
fn ring_in(cap: Cap) -> Option<(Consumer<RECORD>, mem::Lent)> {
    let Ok(Some(slot)) = sys::inspect_slot(slots::SPACE, cap.0) else { return None };
    if slot.ty != ObjectType::Frame || slot.bits != BITS {
        return None;
    }
    let mapped = mem::Lent::map(cap, BITS, Rights(Rights::READ.0 | Rights::WRITE.0)).ok()?;
    let mut ring = Consumer::new(mapped.region(), RECORDS)?;
    let _ = ring.sleep();
    Some((ring, mapped))
}

/// The slot holding directory entry `entry`'s ring.
fn ring_slot(entry: usize) -> Cap {
    Cap(slots::FIRST_GRANT + 3 + entry as u64)
}

fn main(info: &'static ProcessInfo) -> i64 {
    let grant = |n: u64| Cap(slots::FIRST_GRANT + n);
    let directory = match mem::peer(grant(2), directory::BITS, Rights::READ) {
        Ok(d) => d,
        Err(e) => {
            println!("ERROR: logd: no ring directory: {e:?}");
            return 1;
        }
    };
    let mut log = Log {
        sources: Vec::new(),
        directory,
        entries: (info.args[0] as usize).min(directory::ENTRIES),
        more: false,
        open: None,
        cut: None,
        keep: mem::peer(slots::KEEP, 12, Rights(Rights::READ.0 | Rights::WRITE.0)).ok(),
        listed: Vec::new(),
        names: Vec::new(),
        text: String::new(),
    };
    // Every ring there is, and what was written before this service
    // started (or before it last ended).
    log.take_rings();
    log.restore();
    log.drain();
    serve_events(grant(0), grant(1), &mut log)
}
