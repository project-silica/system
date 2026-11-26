//! Intel's 6300ESB watchdog (the 6300ESB I/O Controller Hub datasheet,
//! section 15; QEMU models it as `i6300esb`): a timer that resets the
//! machine unless it is reloaded in time.
//!
//! The device manager has set it up before this driver starts, from the
//! package's declared configuration writes (configuration space is the
//! device manager's): a reset when the second stage runs out, the 1 kHz
//! clock, no interrupt, and the timer enabled. So the watchdog runs from the
//! moment the machine's devices are found, and a machine that never comes
//! up far enough to pet it is reset as surely as one that stops later.
//!
//! The registers are 16 bytes in memory: the two stages' preloads (20 bits
//! each, in ticks of about a millisecond) and the reload register, each
//! written only after the two-write unlock sequence. A timeout is both
//! stages: [`STAGE_TICKS`] twice.
//!
//! It provides `silica.watchdog.Device` to the service manager alone (the
//! device manager gives a capability to it to nobody else): `info` says how
//! long the watchdog waits and whether it reset the machine last time,
//! `pet` starts the timer over.
#![no_std]
#![no_main]

use silica_driver::{Device, DeviceError, grant, granted};
use silica_idl_rt::CapList;
use silica_protocols::watchdog::device::{self, InfoReply, PetReply};
use silica_rt::ipc::{Handle, serve};
use silica_rt::mmio::Mmio;
use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

const TIMER1: usize = 0x00;
const TIMER2: usize = 0x04;
const RELOAD: usize = 0x0C;
/// Written to `RELOAD`: start the timer over.
const RELOAD_NOW: u16 = 1 << 8;
/// Read from `RELOAD`: the watchdog reset the machine (cleared by writing it).
const TIMED_OUT: u16 = 1 << 9;
/// Each stage in ticks of the 1 kHz clock (32,768 PCI clocks of 30 ns:
/// 0.983 ms), 15 s: the machine is reset 30 s after its last pet.
const STAGE_TICKS: u32 = 15_259;
const TIMEOUT_MS: u32 = 30_000;

struct Watchdog {
    registers: Mmio,
    reset_last_boot: bool,
}

impl Watchdog {
    /// The two writes that let the next write reach a protected register.
    fn unlock(&self) {
        self.registers.write16(RELOAD, 0x80);
        self.registers.write16(RELOAD, 0x86);
    }

    fn reload(&self) {
        self.unlock();
        self.registers.write16(RELOAD, RELOAD_NOW);
    }
}

impl device::Server<Handle> for Watchdog {
    fn info(&mut self) -> InfoReply {
        InfoReply { timeout_ms: TIMEOUT_MS, reset_last_boot: self.reset_last_boot }
    }

    fn pet(&mut self) -> PetReply {
        self.reload();
        PetReply {}
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: watchdog-esb: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
    let device = Device::take(info)?;
    let registers = device.bar(0).and_then(|b| b.part(0, 16)).ok_or(DeviceError::Missing("the watchdog's registers"))?;
    let dog = Watchdog { registers, reset_last_boot: registers.read16(RELOAD) & TIMED_OUT != 0 };
    // The stages, then the timer started over; the reset flag cleared once
    // read, so the next boot learns only of its own.
    dog.unlock();
    dog.registers.write32(TIMER1, STAGE_TICKS);
    dog.unlock();
    dog.registers.write32(TIMER2, STAGE_TICKS);
    dog.unlock();
    dog.registers.write16(RELOAD, TIMED_OUT | RELOAD_NOW);
    if dog.reset_last_boot {
        println!("watchdog-esb: this machine was reset by its watchdog");
    }
    println!("watchdog-esb: a watchdog resets this machine {} s after the service manager last pets it", TIMEOUT_MS / 1000);
    let mut dog = dog;
    serve(granted(grant::SERVICE), |_badge, request, caps: CapList<Handle>, reply, reply_caps| {
        device::dispatch(&mut dog, request, caps, reply, reply_caps)
    })
}
