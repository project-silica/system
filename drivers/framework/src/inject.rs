//! Faults a device can commit, committed on purpose, to show that a
//! driver survives them and that nothing outside it notices more than a
//! delay (`spec/MILESTONES.md` M3; the `faults` guest test).
//!
//! The owner arms one with `inject=<driver>:<fault>@<n>` on the kernel
//! command line, and the device manager passes it to the first run of that
//! driver only (`Device::take` arms it), so the driver started in its place
//! runs clean. The fault happens at the `n`th request the driver offers its
//! device, at the boundary where the device would have committed it:
//!
//! | fault | what the device does |
//! | --- | --- |
//! | `garbage` | completes a request the driver never offered (its next completion names one) |
//! | `stuck` | never sees the request, and never completes it |
//! | `spurious` | interrupts with nothing completed |
//! | `missed` | completes the request without an interrupt |
//! | `reset` | resets itself: everything in flight is lost |
//! | `broken` | gives up and asks to be reset (virtio's DEVICE_NEEDS_RESET), as it must when the driver breaks the protocol |
//! | `admin_missed` | NVMe: completes the first admin command without an interrupt (the driver ignores the one it gets) |
//! | `tiny` | virtio: offers a queue of two descriptors, fewer than one request takes |
//! | `generation` | virtio: its configuration's generation changes on every read, from bring-up on |
//! | `short` | virtio-blk: completes a read saying it wrote only the status byte, not the data |
//! | `unplugged` | e1000e: holds every transmit while its link is down, as an 82574 does |
//! | `slow_start` | NVMe: answers the first admin command 3 s late, so whatever the driver is told while it comes up arrives during an admin wait |
//! | `end_faults` | virtio-rogue: does nothing until asked to end, then reads a page a peer took back, a new one each time, for ever: a driver the device manager must still end on its time |
//!
//! The virtio queue ([`crate::virtio`]) commits all six (`broken` by
//! offering the device a descriptor chain it must refuse, which a virtio
//! device answers by asking to be reset: the device does it, not the
//! driver); a driver of
//! another transport calls [`due`] and [`pending`] where its own device
//! would. While a fault is armed a driver's request timeout is
//! [`ARMED_TIMEOUT_NS`], so the test takes seconds rather than minutes.

use core::sync::atomic::{AtomicU64, Ordering};
use silica_rt::sys::{self, Cap};

/// A fault (see the module's table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fault {
    Garbage = 1,
    Stuck = 2,
    Spurious = 3,
    Missed = 4,
    Reset = 5,
    Broken = 6,
    AdminMissed = 7,
    Tiny = 8,
    Generation = 9,
    Short = 10,
    Unplugged = 11,
    SlowStart = 12,
    EndFaults = 13,
}

impl Fault {
    /// The fault named `name` on the command line.
    pub fn named(name: &[u8]) -> Option<Fault> {
        Some(match name {
            b"garbage" => Fault::Garbage,
            b"stuck" => Fault::Stuck,
            b"spurious" => Fault::Spurious,
            b"missed" => Fault::Missed,
            b"reset" => Fault::Reset,
            b"broken" => Fault::Broken,
            b"admin_missed" => Fault::AdminMissed,
            b"tiny" => Fault::Tiny,
            b"generation" => Fault::Generation,
            b"short" => Fault::Short,
            b"unplugged" => Fault::Unplugged,
            b"slow_start" => Fault::SlowStart,
            b"end_faults" => Fault::EndFaults,
            _ => return None,
        })
    }

    fn of(v: u64) -> Option<Fault> {
        Some(match v {
            1 => Fault::Garbage,
            2 => Fault::Stuck,
            3 => Fault::Spurious,
            4 => Fault::Missed,
            5 => Fault::Reset,
            6 => Fault::Broken,
            7 => Fault::AdminMissed,
            8 => Fault::Tiny,
            9 => Fault::Generation,
            10 => Fault::Short,
            11 => Fault::Unplugged,
            12 => Fault::SlowStart,
            13 => Fault::EndFaults,
            _ => return None,
        })
    }

    /// The plan as the device manager passes it (`ProcessInfo::args[4]`,
    /// high half): the fault in bits 24 to 31, `n` below.
    pub const fn plan(self, n: u32) -> u32 {
        (self as u32) << 24 | (n & 0xFF_FFFF)
    }
}

/// A driver's request timeout while a fault is armed.
pub const ARMED_TIMEOUT_NS: u64 = 1_000_000_000;

/// Fault << 56 | requests still to go before it (0: none armed).
static PLAN: AtomicU64 = AtomicU64::new(0);
/// The fault that has come due and waits for its moment (0: none).
static PENDING: AtomicU64 = AtomicU64::new(0);
/// What a spurious interrupt signals: the interrupt's own sender.
static SPURIOUS: AtomicU64 = AtomicU64::new(0);
/// A fault was armed for this run (1), committed or not.
static ARMED: AtomicU64 = AtomicU64::new(0);

/// Arm the fault of `plan` (as [`Fault::plan`] makes it).
pub fn arm(plan: u32) {
    if let Some(f) = Fault::of((plan >> 24) as u64) {
        PLAN.store((f as u64) << 56 | (plan & 0xFF_FFFF).max(1) as u64, Ordering::Relaxed);
        ARMED.store(1, Ordering::Relaxed);
        silica_rt::println!("inject: {:?} at request {}", f, (plan & 0xFF_FFFF).max(1));
    }
}

/// The fault armed and not yet due, if any: for a driver whose fault is
/// on a path other than its requests' (an NVMe admin command).
pub fn planned() -> Option<Fault> {
    Fault::of(PLAN.load(Ordering::Relaxed) >> 56)
}

/// Whether a fault was armed for this run, committed or not: a driver
/// shortens its timeout for the whole run.
pub fn armed() -> bool {
    ARMED.load(Ordering::Relaxed) != 0
}

/// Where a spurious interrupt goes: a sender of the driver's interrupt bit.
pub fn interrupts(sender: Cap) {
    SPURIOUS.store(sender.0, Ordering::Relaxed);
}

/// A request is being offered: the fault that comes due with it, if any.
/// A spurious interrupt is delivered here; the others wait for [`pending`].
pub fn due() -> Option<Fault> {
    let p = PLAN.load(Ordering::Relaxed);
    if p == 0 {
        return None;
    }
    let left = p & ((1 << 56) - 1);
    if left > 1 {
        PLAN.store(p - 1, Ordering::Relaxed);
        return None;
    }
    PLAN.store(0, Ordering::Relaxed);
    let f = Fault::of(p >> 56)?;
    silica_rt::println!("inject: {f:?} now");
    if f == Fault::Spurious {
        let _ = sys::signal(Cap(SPURIOUS.load(Ordering::Relaxed)));
        silica_rt::println!("inject: {f:?} committed");
    } else {
        PENDING.store(f as u64, Ordering::Relaxed);
    }
    Some(f)
}

/// Whether `f` came due and this is its moment: true once. The driver
/// commits the fault when this says so, and the log says it was committed
/// (`inject: <fault> committed`): a fault that came due and was never
/// taken was not committed, and the test of it shows nothing.
pub fn pending(f: Fault) -> bool {
    // Ordinary I/O only observes the plan. Claim a fault atomically once
    // the device model reaches the operation where it takes effect.
    if PENDING.load(Ordering::Relaxed) != f as u64 {
        return false;
    }
    let now = PENDING.compare_exchange(f as u64, 0, Ordering::Relaxed, Ordering::Relaxed).is_ok();
    if now {
        silica_rt::println!("inject: {f:?} committed");
    }
    now
}
