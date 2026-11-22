//! The smallest program: one line on the debug console, then exit with the
//! status its parent asked for in argument 0. With argument 1 set, it says
//! nothing and exits with the time its code started (the monotonic clock,
//! in nanoseconds): how long starting a program takes (`checks=spawn`).
#![no_std]
#![no_main]

use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

fn main(info: &'static ProcessInfo) -> i64 {
    if info.args[1] == 1 {
        return silica_rt::clock().now() as i64;
    }
    println!("hello: a program in its own address space, with {} slots and 2^{} bytes to its name", info.capspace_slots, info.untyped_bits);
    info.args[0] as i64
}
