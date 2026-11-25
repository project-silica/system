//! Wall-clock time: what time it is in the world, beside the monotonic
//! clock (`crate::clock`), which only counts from boot.
//!
//! The service manager makes one page for the whole system, the time page
//! (`slots::TIME`), and every program it or a service starts can read it.
//! It holds the wall clock as an offset from the monotonic clock, so
//! reading the time is a few loads and the monotonic clock's own read: no
//! call. Written under a sequence word (odd while being written), so a
//! reader never sees half an update:
//!
//! | offset | what |
//! | --- | --- |
//! | 0 | sequence (u32) |
//! | 8 | nanoseconds since 1970-01-01T00:00:00Z at monotonic time 0 (u64) |
//! | 16 | where the time came from ([`Source`], u32) |
//! | 24 | monotonic nanoseconds when it was last set (u64) |
//!
//! At boot the service manager sets it from the firmware's clock (the
//! machine's battery-backed real-time clock, read by the loader). A
//! program given the page writable (a service declaring `sets_time`: the
//! network stack, for its time-server client) sets it later with [`set`].

use crate::mmio::Mmio;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Where the time came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Nowhere: the wall clock is not known.
    None,
    /// The firmware's clock, read at boot.
    Firmware,
    /// A time server.
    Network,
}

impl Source {
    fn from_raw(v: u32) -> Source {
        match v {
            1 => Source::Firmware,
            2 => Source::Network,
            _ => Source::None,
        }
    }

    fn raw(self) -> u32 {
        match self {
            Source::None => 0,
            Source::Firmware => 1,
            Source::Network => 2,
        }
    }
}

/// The wall clock as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wall {
    /// Nanoseconds since 1970-01-01T00:00:00Z (UTC, no leap seconds).
    pub ns: u64,
    pub source: Source,
}

/// Where this program mapped the time page (0: not yet, 1: it has none).
static MAPPED: AtomicUsize = AtomicUsize::new(0);

/// The time page, mapped read-only the first time it is asked for.
fn page() -> Option<Mmio> {
    let at = MAPPED.load(Ordering::Acquire);
    if at == 1 {
        return None;
    }
    if at != 0 {
        // SAFETY: mapped below, among lent memory, whose addresses are
        // never given to anything else (`crate::mem::peer`).
        #[allow(unsafe_code)]
        return Some(unsafe { Mmio::new(at, 4096) });
    }
    let mapped = crate::mem::peer(crate::slots::TIME, 12, crate::sys::Rights::READ).ok();
    MAPPED.store(mapped.map_or(1, |m| m.addr()), Ordering::Release);
    mapped
}

/// What time it is, when the program can know: `None` without a time page
/// or when the page has no consistent time.
pub fn now() -> Option<Wall> {
    let p = page()?;
    let (offset, source) = read(&p);
    if source == Source::None {
        return None;
    }
    Some(Wall { ns: offset.wrapping_add(crate::clock().now()), source })
}

/// The offset and source in a time page, read whole. Return the same
/// unknown time as an unset page if the writer cannot finish an update.
pub fn read(p: &Mmio) -> (u64, Source) {
    // Retry once for an update that overlapped the first sample. Readers
    // can run at higher priority than the writer, or outlive it.
    for _ in 0..2 {
        let before = p.load_acquire32(0);
        if before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let offset = p.read64(8);
        let source = p.read32(16);
        core::sync::atomic::fence(Ordering::Acquire);
        if p.load_acquire32(0) == before {
            return (offset, Source::from_raw(source));
        }
    }
    (0, Source::None)
}

/// Set the wall clock in a time page mapped writable: `wall_ns` is the
/// time at monotonic time `at`. One writer at a time.
pub fn set(p: &Mmio, wall_ns: u64, at: u64, source: Source) {
    let seq = p.read32(0);
    p.store_release32(0, seq.wrapping_add(1) | 1);
    core::sync::atomic::fence(Ordering::Release);
    p.write64(8, wall_ns.wrapping_sub(at));
    p.write32(16, source.raw());
    p.write64(24, at);
    p.store_release32(0, (seq | 1).wrapping_add(1));
}

/// A moment as the calendar says it (UTC, the proleptic Gregorian
/// calendar).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl Civil {
    /// The moment `seconds` after 1970-01-01T00:00:00Z.
    pub fn from_unix(seconds: u64) -> Civil {
        let days = (seconds / 86_400) as i64;
        let rest = seconds % 86_400;
        // Howard Hinnant's days-to-civil: exact for every day.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = yoe + era * 400 + i64::from(month <= 2);
        Civil { year, month, day, hour: (rest / 3600) as u8, minute: (rest / 60 % 60) as u8, second: (rest % 60) as u8 }
    }
}

impl core::fmt::Display for Civil {
    /// ISO 8601: `2026-11-24T01:23:45Z`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", self.year, self.month, self.day, self.hour, self.minute, self.second)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn dates_are_the_calendars() {
        assert_eq!(format!("{}", Civil::from_unix(0)), "1970-01-01T00:00:00Z");
        assert_eq!(format!("{}", Civil::from_unix(951_782_400)), "2000-02-29T00:00:00Z", "a leap day of a year divisible by 400");
        assert_eq!(format!("{}", Civil::from_unix(4_107_456_000)), "2100-02-28T00:00:00Z");
        assert_eq!(format!("{}", Civil::from_unix(4_107_542_400)), "2100-03-01T00:00:00Z", "no leap day in 2100");
        assert_eq!(format!("{}", Civil::from_unix(1_795_483_425)), "2026-11-24T01:23:45Z", "as Python's datetime says");
        // Every day of four centuries against counting days one by one.
        let (mut y, mut m, mut d) = (1970i64, 1u8, 1u8);
        for day in 0..146_097u64 {
            let c = Civil::from_unix(day * 86_400 + 86_399);
            assert_eq!((c.year, c.month, c.day, c.hour, c.minute, c.second), (y, m, d, 23, 59, 59));
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m as usize - 1];
            d += 1;
            if d > days {
                (d, m) = (1, m + 1);
                if m > 12 {
                    (m, y) = (1, y + 1);
                }
            }
        }
    }

    #[test]
    fn a_page_reads_what_was_set() {
        let words: &'static mut [u64] = std::vec::Vec::leak(std::vec![0u64; 512]);
        // SAFETY: leaked memory of the test's own, holding only integers.
        #[allow(unsafe_code)]
        let p = unsafe { Mmio::new(words.as_mut_ptr() as usize, 4096) };
        assert_eq!(read(&p), (0, Source::None));
        set(&p, 1_000_000_000_000, 400, Source::Firmware);
        assert_eq!(read(&p), (1_000_000_000_000 - 400, Source::Firmware));
        assert_eq!(p.read32(0) % 2, 0, "even once written");
        set(&p, 2_000, 1_000, Source::Network);
        assert_eq!(read(&p), (1_000, Source::Network));
        // The writer stopped after opening the next update. Its partial
        // offset must never escape, and readers must still return.
        p.store_release32(0, 5);
        p.write64(8, 999);
        assert_eq!(read(&p), (0, Source::None));
        set(&p, 7_000, 500, Source::Network);
        assert_eq!(read(&p), (6_500, Source::Network));
    }
}
