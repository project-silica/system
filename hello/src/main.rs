//! The smallest program: one line on the debug console, then exit with the
//! status its parent asked for in argument 0.
#![no_std]
#![no_main]

use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

fn main(info: &'static ProcessInfo) -> i64 {
    println!("hello: a program in its own address space, with {} slots and 2^{} bytes to its name", info.capspace_slots, info.untyped_bits);
    info.args[0] as i64
}
