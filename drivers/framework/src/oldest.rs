//! The oldest of a driver's requests in flight, found without walking them.
//!
//! A driver times its requests out from when each was started, all with the
//! same limit, so the deadline it waits for is the oldest request's start
//! plus the limit. Asked before every wait, a walk over the request table
//! was O(queue depth) on the hottest path (85 to 256 slots, every wake-up).
//! Requests start in time order: kept in that order, the oldest still in
//! flight is at the front once the finished ones before it are dropped,
//! which each entry is once (amortized O(1)). Entries of finished requests
//! behind a stuck one are dropped when they reach four times the slots.

use core::cell::RefCell;
use silica_rt::alloc::collections::VecDeque;

/// Start times of requests by slot, in the order they were started.
#[derive(Debug, Default)]
pub struct Oldest {
    order: RefCell<VecDeque<(u32, u64)>>,
}

impl Oldest {
    /// None started yet.
    pub fn new() -> Oldest {
        Oldest::default()
    }

    /// The request in `slot` was started at `at` (monotonic ns, no earlier
    /// than any started before it). `slots`: how many there are, and
    /// `live(slot, at)`: whether `slot` still holds the request started at
    /// `at`, for dropping finished ones.
    pub fn started(&self, slot: u32, at: u64, slots: usize, live: impl Fn(u32, u64) -> bool) {
        let mut order = self.order.borrow_mut();
        order.push_back((slot, at));
        if order.len() > 4 * slots.max(1) {
            order.retain(|&(s, t)| live(s, t));
        }
    }

    /// When the oldest request still in flight was started (`None`: none).
    /// `live` as for [`Oldest::started`].
    pub fn oldest(&self, live: impl Fn(u32, u64) -> bool) -> Option<u64> {
        let mut order = self.order.borrow_mut();
        while let Some(&(s, t)) = order.front() {
            if live(s, t) {
                return Some(t);
            }
            order.pop_front();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Against a walk of the table, under random starts and completions,
    /// with one request stuck for a long time.
    #[test]
    fn the_oldest_in_flight_is_the_walk_s() {
        let slots = 64usize;
        let table: RefCell<Vec<Option<u64>>> = RefCell::new(std::vec![None; slots]);
        let o = Oldest::new();
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut now = 0u64;
        for step in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            now += 1;
            let s = (x % slots as u64) as usize;
            let live = |s: u32, t: u64| table.borrow()[s as usize] == Some(t);
            if table.borrow()[s].is_none() {
                table.borrow_mut()[s] = Some(now);
                o.started(s as u32, now, slots, live);
            } else if s != 0 || step > 90_000 {
                table.borrow_mut()[s] = None;
            }
            let walk = table.borrow().iter().flatten().min().copied();
            assert_eq!(o.oldest(live), walk);
            assert!(o.order.borrow().len() <= 4 * slots + 1);
        }
    }
}
