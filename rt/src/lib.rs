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
#![no_std]
#![deny(unsafe_code)]

pub mod ipc;
pub mod mem;

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
    /// The first capability the parent granted beyond these.
    pub const FIRST_GRANT: u64 = 8;
}

/// `ProcessInfo::magic`.
pub const PROCESS_MAGIC: u64 = 0x4F46_4E49_434F_5250; // "PROCINFO"

/// Label of the message a program sends its parent when it finishes; word 0
/// is its exit status.
pub const EXIT_LABEL: u64 = 1;

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
}

static CLOCK: [AtomicU64; 3] = [const { AtomicU64::new(1) }; 3];
static DEBUG: AtomicU64 = AtomicU64::new(0);

/// Start the runtime in the root task, which has no [`ProcessInfo`]: where
/// the debug console is, how to read the clock, where the thread's IPC
/// buffer is mapped, and which slots of its CapSpace are free
/// (`first_free..slots`). `silica_proc::root` calls this, and then tells
/// [`mem`] which Untyped capabilities are the machine's memory.
pub fn start_root(debug: Cap, clock: [u64; 3], ipc_buffer: u64, first_free: u64, slots: u64) {
    init(debug, clock);
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

/// The debug console: the kernel's console, through a console capability.
/// Unbuffered, for bring-up and panics; the logging service (D08) replaces
/// it for everything else. Each `write_str` is written whole (a few system
/// calls of 32 bytes), so lines from different programs do not tear within
/// a call.
pub struct Debug;

impl fmt::Write for Debug {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let console = Cap(DEBUG.load(Ordering::Relaxed));
        if console.0 != 0 {
            let _ = sys::console_write(console, s.as_bytes());
        }
        Ok(())
    }
}

/// Write to the debug console.
#[macro_export]
macro_rules! print {
    ($($a:tt)*) => {{ use core::fmt::Write as _; let _ = write!($crate::Debug, $($a)*); }};
}

/// Write a line to the debug console.
#[macro_export]
macro_rules! println {
    ($($a:tt)*) => {{ use core::fmt::Write as _; let _ = write!($crate::Debug, $($a)*); let _ = $crate::Debug.write_str("\r\n"); }};
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

/// Start-up of an ordinary program; called by the code [`main!`] generates.
pub fn start(info: &'static ProcessInfo, main: fn(&'static ProcessInfo) -> i64) -> ! {
    if info.magic != PROCESS_MAGIC {
        exit(-1);
    }
    init(slots::DEBUG, info.clock);
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

#[cfg(target_os = "silica")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("PANIC: {}", info.message());
    if let Some(l) = info.location() {
        println!("  at {}:{}", l.file(), l.line());
    }
    exit(-2)
}
