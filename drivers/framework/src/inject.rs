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
//!
//! The virtio queue ([`crate::virtio`]) commits all five; a driver of
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
    } else {
        PENDING.store(f as u64, Ordering::Relaxed);
    }
    Some(f)
}

/// Whether `f` came due and this is its moment: true once.
pub fn pending(f: Fault) -> bool {
    PENDING.compare_exchange(f as u64, 0, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}
