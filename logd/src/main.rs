//! The log service (component D08): it provides `silica.log.Reader`.
//!
//! The service manager gives every other service a ring to print into
//! (`silica_rt::log`), creates the rings and the notification their writers
//! signal before it starts anything, and gives them all to this service:
//! grants 0 its endpoint, 1 the service manager's `silica.system.Manager`
//! (to learn the services' names), 2 the notification, 3 a notification of
//! the service manager's to answer flushes on, then one ring per declared
//! service, in the order the service manager lists them (an empty slot
//! where a service has none, as this one). A signal with [`FLUSH`] asks for
//! everything to be on the console now: the service manager's way to put a
//! service's last lines before its own verdict, without calling the log. On every wake-up it takes the
//! text out of every ring, keeps the last [`KEPT`] bytes of each service's,
//! and puts each complete line on the console as it was written.
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
/// The bit of the notification that asks for a flush (the service manager's).
const FLUSH: u64 = 2;

struct Source {
    /// Made once, at start, and kept as long as the program runs.
    name: &'static str,
    ring: Option<Consumer<RECORD>>,
    kept: VecDeque<u8>,
    written: u64,
}

struct Log {
    sources: Vec<Source>,
    /// The source whose unfinished line the console ends with.
    open: Option<usize>,
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
        for (i, s) in self.sources.iter_mut().enumerate() {
            let mut out: Vec<u8> = Vec::new();
            while let Some(ring) = s.ring.as_mut() {
                match ring.pop() {
                    Ok(Some(r)) => {
                        let n = (r[0] as usize).min(RECORD - 1);
                        let text = &r[1..1 + n];
                        s.written += n as u64;
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
                        println!("logd: the log ring of {} makes no sense; nothing more is read from it", s.name);
                        s.ring = None;
                    }
                }
            }
            if out.is_empty() {
                continue;
            }
            if self.open.is_some_and(|o| o != i) {
                print!("\n");
            }
            // In pieces of whole lines where it can, each written whole.
            for piece in out.split_inclusive(|b| *b == b'\n') {
                for part in piece.chunks(LINE) {
                    print!("{}", String::from_utf8_lossy(part));
                }
            }
            self.open = (out.last() != Some(&b'\n')).then_some(i);
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

    fn signals(&mut self, bits: u64) {
        self.drain();
        if bits & FLUSH != 0 {
            let _ = sys::signal(self.flushed);
        }
    }
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
        let cap = grant(4 + i as u64);
        let Ok(Some(slot)) = sys::inspect_slot(slots::SPACE, cap.0) else { continue };
        if slot.ty != ObjectType::Frame || slot.bits != BITS {
            continue;
        }
        let Ok(region) = mem::peer(cap, BITS, Rights(Rights::READ.0 | Rights::WRITE.0)) else { continue };
        let Some(mut ring) = Consumer::new(region, RECORDS) else { continue };
        let _ = ring.sleep();
        let name: &'static str = silica_rt::alloc::boxed::Box::leak(name.into_boxed_str());
        sources.push(Source { name, ring: Some(ring), kept: VecDeque::new(), written: 0 });
    }
    let mut log = Log { sources, open: None, flushed: grant(3), listed: Vec::new(), text: String::new() };
    // What was written before this service started (or before it last ended).
    log.drain();
    serve_events(grant(0), grant(2), &mut log)
}
