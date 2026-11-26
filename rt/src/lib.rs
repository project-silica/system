//! The native runtime: what every Silica program starts with.
//!
//! A program is started by its parent (`silica-proc`) with one thread, its
//! own address space and its own CapSpace. The kernel knows nothing of
//! programs; this crate is the convention between a parent and its child:
//!
//! - the child's first argument is the address of a read-only
//!   [`ProcessInfo`];
//! - its CapSpace starts with the capabilities named in [`slots`], then the
//!   capabilities its parent granted, in the order the parent listed them,
//!   from [`slots::FIRST_GRANT`];
//! - when it is finished it tells its parent through [`slots::PARENT`] and
//!   stops ([`exit`]). The parent reclaims everything by revoking the
//!   Untyped the child was made from.
//!
//! # Writing a program
//!
//! A program is a `no_std`, `no_main` binary crate that depends on
//! `silica-rt` and declares its entry with [`main!`]. Its `Cargo.toml`, as a
//! member of the `system` workspace:
//!
//! ```text
//! [package]
//! name = "my-program"
//! version.workspace = true
//! edition.workspace = true
//! license.workspace = true
//! publish.workspace = true
//!
//! [[bin]]
//! name = "my-program"
//! path = "src/main.rs"
//! test = false
//! bench = false
//!
//! [dependencies]
//! silica-rt = { workspace = true }
//! silica-idl-rt = { workspace = true }    # if it calls or provides a protocol
//!
//! [build-dependencies]
//! silica-idlc = { workspace = true }      # if it calls or provides a protocol
//!
//! [lints]
//! workspace = true
//! ```
//!
//! and it is listed in `members` of the workspace's `Cargo.toml`. The
//! workshop's `tools/boot.sh --system` builds every program of the workspace
//! for the Silica target and puts each in the ramdisk under its binary name.
//!
//! A program that uses a protocol generates the protocol's Rust module in
//! its build script (`build.rs`) and includes it:
//!
//! ```text
//! // build.rs
//! use std::path::PathBuf;
//! fn main() {
//!     let idl = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../idl/protocols/sample/echo.idl");
//!     println!("cargo::rerun-if-changed={}", idl.display());
//!     let protocols = idlc::load(&[idl]).expect("the protocol does not compile");
//!     let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
//!     for p in &protocols {
//!         std::fs::write(out.join(idlc::rustgen::file_name(p)), idlc::rustgen::rust(p).expect("code generation")).unwrap();
//!     }
//! }
//!
//! // src/main.rs
//! include!(concat!(env!("OUT_DIR"), "/sample_echo.rs"));   // defines `pub mod echo`
//! ```
//!
//! The file is named after the protocol: `a.b.Name` gives `a_b_name.rs`
//! defining `pub mod name`. The protocol's reference page
//! (`silica-idlc docs`) lists the module's client calls and the trait a
//! provider implements; [`ipc`] connects them to the kernel.
//!
//! A program gets the capabilities it needs as grants from whoever starts
//! it: grant number `n` is in slot [`slots::FIRST_GRANT`]` + n`. What each
//! grant is, is between the program and its parent (for a program started
//! by `init`, see `init`'s source or the service manifest when there is one).
//!
//! The entry:
//!
//! ```text
//! #![no_std]
//! #![no_main]
//! silica_rt::main!(main);
//! fn main(info: &silica_rt::ProcessInfo) -> i64 {
//!     silica_rt::println!("hello, I was given {} capabilities", info.grants);
//!     0
//! }
//! ```
//!
//! `main` receives the start-up record ([`ProcessInfo`], which lives as long
//! as the program) and returns the exit status. The runtime supplies the
//! panic handler (a panic prints its message on the debug console and exits
//! with status -1), so a program defines none. [`print!`] and [`println!`]
//! take the same format strings and arguments as `core::format_args!`. A
//! grant is used as `sys::Cap(slots::FIRST_GRANT + n)`.
//!
//! A program has a heap: `silica_rt::alloc` is Rust's `alloc` crate
//! (`alloc::vec::Vec`, `alloc::boxed::Box`, `alloc::collections::BTreeMap`),
//! allocating from the program's own memory ([`heap`]). Memory that is
//! shared, handed to a device or given back is held as [`mem::Memory`];
//! device registers are reached through [`mmio::Mmio`].
#![no_std]
#![deny(unsafe_code)]

pub extern crate alloc;

pub mod heap;
pub mod ipc;
pub mod log;
pub mod mem;
pub mod mmio;
pub mod random;
pub mod ring;
pub mod text;
pub mod time;

pub use libsys as sys;

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use sys::{Cap, Clock, MsgInfo};

/// The capabilities every program starts with, by slot.
pub mod slots {
    use libsys::Cap;

    /// The program's own (first) thread.
    pub const THREAD: Cap = Cap(1);
    /// The program's CapSpace.
    pub const SPACE: Cap = Cap(2);
    /// The program's address space.
    pub const ASPACE: Cap = Cap(3);
    /// The Untyped the program may make objects and memory from.
    pub const UNTYPED: Cap = Cap(4);
    /// The frame of the first thread's IPC buffer.
    pub const IPC_BUFFER: Cap = Cap(5);
    /// An endpoint of the parent's, to send on: how the program reports
    /// that it has finished (and, later, asks for more).
    pub const PARENT: Cap = Cap(6);
    /// The debug console (a console capability: `sys::console_write`), when
    /// the parent grants one; otherwise empty and [`crate::print!`] discards.
    pub const DEBUG: Cap = Cap(7);
    /// The program's log ring, a frame of 16 KiB (`crate::log`), when the
    /// service manager gives it one; [`crate::print!`] writes there then.
    pub const LOG: Cap = Cap(8);
    /// What tells the log there is text in the ring.
    pub const LOG_WAKE: Cap = Cap(9);
    /// The program's own notification, made by its parent, when the
    /// parent gives one (the service manager gives every service one): the
    /// parent signals it, bit `n`, when the provider of the program's `n`th
    /// need was started again after it ended (whatever the program held of
    /// that provider's is gone with it). The bits from 32 up are never the
    /// parent's: the program and its libraries share them out (as
    /// `silica_net::tcp::Tcp::on` takes some).
    pub const EVENTS: Cap = Cap(10);
    /// A page of 4 KiB that outlives the program, when its parent gives one
    /// (a service that `keeps`: the service manager keeps it across the
    /// service's restarts, zeroed at boot): what the next instance needs to
    /// pick up where this one was.
    pub const KEEP: Cap = Cap(11);
    /// The time page (`crate::time`): what the wall clock reads, as an
    /// offset from the monotonic clock. Readable by every program the
    /// service manager or a service starts; writable only by a service
    /// that sets the time (`sets_time`).
    pub const TIME: Cap = Cap(12);
    /// The scheduling context the program runs on (readable): processor
    /// time is a capability, and this is the program's. A thread runs only
    /// once it is bound to a context (`sys::thread_bind`), so a thread the
    /// program makes is bound to this one, and a program it starts runs on
    /// it too unless it is given another (`silica_proc::Program::sched`):
    /// together they take the one share their parent gave.
    pub const SCHED: Cap = Cap(13);
    /// When the parent asked to hear that the program serves
    /// (`ProcessInfo::says_serving`): a capability to signal one bit of the
    /// parent's notification, which [`crate::serving`] signals once. A
    /// signal never waits, and the kernel keeps it until the parent looks.
    pub const SERVING: Cap = Cap(14);
    /// The first capability the parent granted beyond these. Slots from
    /// here to 64 that the parent did not fill are left empty, for
    /// capabilities the program is given later; the program's own
    /// allocations start above them.
    pub const FIRST_GRANT: u64 = 15;
}

/// `ProcessInfo::magic`.
pub const PROCESS_MAGIC: u64 = 0x4F46_4E49_434F_5250; // "PROCINFO"

/// Label of the message a program sends its parent when it finishes; word 0
/// is its exit status.
pub const EXIT_LABEL: u64 = 1;

/// Label of the message a program sends its parent in place of an exit
/// status when it ends to be started again at once ([`exit_again`]): a
/// driver whose device can be put back to its first state only by a reset
/// ends so when its client changes, and the device manager resets the
/// device by starting the driver again, as a fresh start and not a failure.
/// Its own message, not a status: every status is the program's to mean.
pub const AGAIN_LABEL: u64 = 4;

/// The bit of [`slots::EVENTS`] a parent signals to ask the program to end:
/// finish what must be finished (a block driver makes its device's write
/// cache durable and shuts the device down) and exit. A parent that asks
/// waits a while for the exit, then ends the program itself. The parent's
/// other bits (a need started again) are the ones below it.
pub const END: u64 = 1 << 31;

/// What a program is told when it starts. Read-only, mapped by the parent.
#[repr(C)]
pub struct ProcessInfo {
    /// [`PROCESS_MAGIC`].
    pub magic: u64,
    /// Address of the first thread's IPC buffer.
    pub ipc_buffer: u64,
    /// Number of slots in the CapSpace.
    pub capspace_slots: u64,
    /// The first slot nothing was put in.
    pub first_free_slot: u64,
    /// Size in bits of the Untyped at [`slots::UNTYPED`].
    pub untyped_bits: u64,
    /// How many capabilities were granted from [`slots::FIRST_GRANT`].
    pub grants: u64,
    /// Number of processors.
    pub cpus: u64,
    /// The timestamp counter's calibration, as in `RootInfo::clock`.
    pub clock: [u64; 3],
    /// Arguments from the parent; their meaning is between the two.
    pub args: [u64; 8],
    /// Not 0: the parent wants to hear when the program first waits for
    /// requests, on the capability in [`slots::SERVING`] ([`serving`]). The
    /// service manager asks this of a program an update installed, and
    /// keeps the program from then on (a new program that ends badly before
    /// it has served is the update's failure).
    pub says_serving: u64,
}

/// Where in the start-up page (after the [`ProcessInfo`] at its start) the
/// parent puts the program's options: two bytes of length, then the text
/// (`key=value` words, space-separated), at most [`OPTIONS_MAX`] bytes. The
/// service manager gives each service the boot command line's
/// `<service>.<key>=<value>` words, as `<key>=<value>`.
pub const OPTIONS_OFFSET: usize = 2560;
pub const OPTIONS_MAX: usize = 4096 - OPTIONS_OFFSET - 2;

/// The start-up page's address (0: none, as in the root task).
static INFO_PAGE: AtomicU64 = AtomicU64::new(0);

/// The program's options, as its parent gave them (see [`OPTIONS_OFFSET`]).
pub fn options() -> &'static str {
    let at = INFO_PAGE.load(Ordering::Relaxed) as usize;
    if at == 0 {
        return "";
    }
    // SAFETY: the start-up page is mapped read-write for the whole program
    // and nothing writes its options after the parent did; the length is
    // clamped to the space there is.
    #[allow(unsafe_code)]
    let bytes = unsafe {
        let p = core::ptr::with_exposed_provenance::<u8>(at + OPTIONS_OFFSET);
        let len = (u16::from_le_bytes([*p, *p.add(1)]) as usize).min(OPTIONS_MAX);
        core::slice::from_raw_parts(p.add(2), len)
    };
    core::str::from_utf8(bytes).unwrap_or("")
}

/// The value of option `key` (`key=value` among [`options`]).
pub fn option(key: &str) -> Option<&'static str> {
    options().split_ascii_whitespace().find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
}

static CLOCK: [AtomicU64; 3] = [const { AtomicU64::new(1) }; 3];
static DEBUG: AtomicU64 = AtomicU64::new(0);

/// Start the runtime in the root task, which has no [`ProcessInfo`]: where
/// the debug console is, how to read the clock, where the thread's IPC
/// buffer is mapped, and which slots of its CapSpace are free
/// (`first_free..slots`). `silica_proc::root` calls this, and then tells
/// [`mem`] which Untyped capabilities are the machine's memory.
pub fn start_root(debug: Cap, clock: [u64; 3], ipc_buffer: u64, first_free: u64, slots: u64, seed: &[u8; 32]) {
    init(debug, clock);
    random::seed(seed);
    ipc::init(ipc_buffer, first_free, slots);
}

fn init(debug: Cap, clock: [u64; 3]) {
    DEBUG.store(debug.0, Ordering::Relaxed);
    for (c, v) in CLOCK.iter().zip(clock) {
        c.store(v, Ordering::Relaxed);
    }
}

/// The monotonic clock.
pub fn clock() -> Clock {
    Clock::new([CLOCK[0].load(Ordering::Relaxed), CLOCK[1].load(Ordering::Relaxed), CLOCK[2].load(Ordering::Relaxed)])
}

/// What [`print!`] and [`println!`] write to: the program's log ring when
/// it has one ([`log`]), else the kernel's console, through a console
/// capability (bring-up, the root task, drivers). [`print!`] and [`println!`] format into
/// a [`Line`] of up to 224 bytes and write it once, which the kernel puts
/// on the console whole (`console_write`), so what one call prints is not
/// split by anyone else's output unless it is longer than that. The kernel
/// starts a fresh line for a writer that finds another's line unfinished,
/// so a line never begins with someone else's text.
pub struct Debug;

impl fmt::Write for Debug {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if log::write(s.as_bytes()) {
            return Ok(());
        }
        let console = Cap(DEBUG.load(Ordering::Relaxed));
        if console.0 != 0 {
            let _ = sys::console_write(console, s.as_bytes());
        }
        Ok(())
    }
}

/// Text gathered for [`Debug`](struct@Debug) and written in one piece: by [`flush`] or
/// when dropped, or when full.
///
/// [`flush`]: Line::flush
pub struct Line {
    buf: [u8; 224],
    len: usize,
}

impl Line {
    pub const fn new() -> Line {
        Line { buf: [0; 224], len: 0 }
    }

    /// Write out what has been gathered.
    pub fn flush(&mut self) {
        if self.len != 0 {
            // Whole `str`s, written back to back: always UTF-8.
            let _ = fmt::Write::write_str(&mut Debug, core::str::from_utf8(&self.buf[..self.len]).unwrap_or(""));
            self.len = 0;
        }
    }
}

impl Default for Line {
    fn default() -> Line {
        Line::new()
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.len + s.len() > self.buf.len() {
            self.flush();
            if s.len() > self.buf.len() {
                return Debug.write_str(s);
            }
        }
        self.buf[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
        self.len += s.len();
        Ok(())
    }
}

impl Drop for Line {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Write to the debug console, in one piece.
#[macro_export]
macro_rules! print {
    ($($a:tt)*) => {{ use core::fmt::Write as _; let mut l = $crate::Line::new(); let _ = write!(l, $($a)*); }};
}

/// Write a line to the debug console, in one piece.
#[macro_export]
macro_rules! println {
    ($($a:tt)*) => {{ use core::fmt::Write as _; let mut l = $crate::Line::new(); let _ = write!(l, $($a)*); let _ = l.write_str("\r\n"); }};
}

/// Finish the program: tell the parent the status and stop this thread. The
/// parent takes back the program's memory.
pub fn exit(status: i64) -> ! {
    let _ = sys::send(slots::PARENT, MsgInfo::new(EXIT_LABEL, 1), [status as u64, 0, 0, 0]);
    loop {
        let _ = sys::thread_suspend(slots::THREAD);
        sys::yield_now();
    }
}

/// End the program asking its parent to start it again at once
/// ([`AGAIN_LABEL`]).
pub fn exit_again() -> ! {
    let _ = sys::send(slots::PARENT, MsgInfo::new(AGAIN_LABEL, 0), [0; 4]);
    loop {
        let _ = sys::thread_suspend(slots::THREAD);
        sys::yield_now();
    }
}

/// Whether the parent is still to be told that this program serves.
static SAYS_SERVING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// This program now waits for requests: its parent is told, once, if it
/// asked to be ([`ProcessInfo::says_serving`]), by a signal on
/// [`slots::SERVING`]. A signal, not a message: the program never waits for
/// its parent to listen (a message did, and a new network stack's first
/// turn waited for the service manager, and every program's call to the
/// stack with it). The runtime's request loops call this as they first
/// wait (`ipc::serve`, `serve_events`, `serve_parked`, `Listener`); a
/// program with a loop of its own calls it there.
pub fn serving() {
    if SAYS_SERVING.load(Ordering::Relaxed) && SAYS_SERVING.swap(false, Ordering::Relaxed) {
        let _ = sys::signal(slots::SERVING);
    }
}

/// Start-up of an ordinary program; called by the code [`main!`] generates.
pub fn start(info: &'static ProcessInfo, main: fn(&'static ProcessInfo) -> i64) -> ! {
    if info.magic != PROCESS_MAGIC {
        exit(-1);
    }
    SAYS_SERVING.store(info.says_serving != 0, Ordering::Relaxed);
    INFO_PAGE.store(core::ptr::from_ref(info).expose_provenance() as u64, Ordering::Relaxed);
    init(slots::DEBUG, info.clock);
    // The seed the parent put after the record (`random::SEED_OFFSET`), in
    // the start-up page, which is the program's own and mapped read-write:
    // taken, then overwritten, so it is not there to be read later.
    let at = core::ptr::from_ref(info).expose_provenance() + random::SEED_OFFSET;
    // SAFETY: the start-up page is mapped read-write for the whole program,
    // `at` lies inside it (SEED_OFFSET + 32 <= 4096), nothing refers to
    // those bytes, and this is the only thread yet.
    #[allow(unsafe_code)]
    let mut seed = unsafe {
        let p = core::ptr::with_exposed_provenance_mut::<[u8; 32]>(at);
        let seed = core::ptr::read_volatile(p);
        core::ptr::write_volatile(p, [0; 32]);
        seed
    };
    random::seed(&seed);
    seed.fill(0);
    log::start();
    ipc::init(info.ipc_buffer, info.first_free_slot, info.capspace_slots);
    mem::add_source(slots::UNTYPED, info.untyped_bits as u8);
    exit(main(info))
}

/// Declare the program's entry: a `fn(&'static ProcessInfo) -> i64` whose
/// return value is the exit status.
#[macro_export]
macro_rules! main {
    ($main:path) => {
        /// Entered from `_start` in libsys with the start-up record.
        // SAFETY: the one definition of the symbol libsys's `_start` calls.
        #[unsafe(no_mangle)]
        extern "C" fn silica_main(info: &'static $crate::ProcessInfo) -> ! {
            $crate::start(info, $main)
        }
    };
}

/// The heap every program allocates from (`alloc`'s boxes, vectors and maps).
#[cfg(target_os = "silica")]
#[global_allocator]
static HEAP: heap::Heap = heap::Heap::new();

#[cfg(target_os = "silica")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("PANIC: {}", info.message());
    if let Some(l) = info.location() {
        println!("  at {}:{}", l.file(), l.line());
    }
    exit(-2)
}
