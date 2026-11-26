//! The smallest program: one line on the debug console, then exit with the
//! status its parent asked for in argument 0. With argument 1 set, it says
//! nothing and exits with the time its code started (the monotonic clock,
//! in nanoseconds): how long starting a program takes (`checks=spawn`).
//! With argument 1 set to 2, it exits with the first number its random
//! number generator gives (`checks=programs`: every program's is its own).
//! Given the option `fail_after=<seconds>` (installed as a service's
//! program by an update, in a test image), it waits that long, serving
//! nobody, and ends with status 1: a new program that fails before it ever
//! served.
#![no_std]
#![no_main]

use silica_rt::{ProcessInfo, println, slots, sys};

silica_rt::main!(main);

fn main(info: &'static ProcessInfo) -> i64 {
    if let Some(s) = silica_rt::option("fail_after").and_then(|v| v.parse::<u64>().ok()) {
        let until = silica_rt::clock().now() + s * 1_000_000_000;
        while silica_rt::clock().now() < until {
            // Nothing signals this program's events: the wait ends at its time.
            let _ = sys::recv(slots::EVENTS, sys::Wait::Until(until));
        }
        println!("hello: failing after {s} s, having served nobody");
        return 1;
    }
    if info.args[1] == 1 {
        return silica_rt::clock().now() as i64;
    }
    if info.args[1] == 2 {
        return silica_rt::random::u64() as i64;
    }
    println!("hello: a program in its own address space, with {} slots and 2^{} bytes to its name", info.capspace_slots, info.untyped_bits);
    info.args[0] as i64
}
