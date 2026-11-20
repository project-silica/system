//! The other end of `systest`'s tests: one program whose first argument
//! picks its role.
//!
//! - [`SERVER`]: answers calls on its first grant for ever. Label
//!   [`PING`] is answered with word 0 plus one; label [`COUNT`] with how
//!   many pings it has answered.
//! - [`CLIENT`]: makes `args[1]` successful pings through its first grant
//!   slot, checking every answer. With `args[2]` set it expects its
//!   capability to be taken away and given back while it runs: a call that
//!   fails with `Gone` or `BadCap` is made again. It then asks the server
//!   for its count and exits 0 if nothing was lost: every ping the client
//!   saw answered was answered once, and the server answered no more than
//!   the client sent.
//! - [`REVOKER`]: grants a capability derived from its first grant into
//!   slot `FIRST_GRANT` of the CapSpace that is its second grant, leaves it
//!   there for `args[1]` nanoseconds, revokes it, and starts again.
//! - [`HOG`]: retypes its memory into frames until the kernel refuses, and
//!   exits 0 if the refusal was `NoMemory` and it could still work after.
//! - [`ONE_CALL`]: makes one call through its first grant and exits with
//!   the kernel's status of that call (0: answered).
#![no_std]
#![no_main]

use silica_rt::sys::{self, Cap, Error, MsgInfo, ObjectType, Rights, Wait};
use silica_rt::{ProcessInfo, println, slots};

pub const SERVER: u64 = 0;
pub const CLIENT: u64 = 1;
pub const REVOKER: u64 = 2;
pub const HOG: u64 = 3;
pub const ONE_CALL: u64 = 4;

const PING: u64 = 1;
const COUNT: u64 = 2;

silica_rt::main!(main);

fn main(info: &'static ProcessInfo) -> i64 {
    let grant = Cap(slots::FIRST_GRANT);
    match info.args[0] {
        SERVER => server(grant),
        CLIENT => client(grant, info.args[1], info.args[2] != 0),
        REVOKER => revoker(grant, Cap(slots::FIRST_GRANT + 1), info.args[1]),
        HOG => hog(),
        ONE_CALL => match sys::call(grant, MsgInfo::new(PING, 1), [41, 0, 0, 0]) {
            Ok(_) => 0,
            Err(e) => e as i64,
        },
        _ => -10,
    }
}

fn server(endpoint: Cap) -> i64 {
    let mut served = 0u64;
    let mut next = sys::recv(endpoint, Wait::Forever);
    loop {
        let Ok(m) = next else { return 1 };
        let answer = match m.info.label() {
            PING => {
                served += 1;
                m.words[0] + 1
            }
            _ => served,
        };
        next = sys::reply_recv(endpoint, MsgInfo::new(0, 1), [answer, 0, 0, 0]);
    }
}

fn client(endpoint: Cap, count: u64, expect_revocation: bool) -> i64 {
    let (mut answered, mut failed) = (0u64, 0u64);
    // A call that fails because the capability was away is made again.
    let call = |label: u64, word: u64, failed: &mut u64| loop {
        match sys::call(endpoint, MsgInfo::new(label, 1), [word, 0, 0, 0]) {
            Ok(m) => return Ok(m.words[0]),
            Err(Error::Gone | Error::BadCap) if expect_revocation => {
                *failed += 1;
                sys::yield_now();
            }
            Err(e) => return Err(e),
        }
    };
    while answered < count {
        match call(PING, answered, &mut failed) {
            Ok(v) if v == answered + 1 => answered += 1,
            Ok(v) => {
                println!("stress client: ping {answered} was answered with {v}");
                return 2;
            }
            Err(e) => {
                println!("stress client: ping {answered} failed: {e:?}");
                return 3;
            }
        }
    }
    let served = match call(COUNT, 0, &mut failed) {
        Ok(v) => v,
        Err(e) => {
            println!("stress client: cannot ask the server for its count: {e:?}");
            return 3;
        }
    };
    // Every answered ping was served once; a ping served but not seen
    // answered is one whose call was failed by a revocation.
    if served < answered || served > answered + failed {
        println!("stress client: {answered} pings answered, {failed} calls failed, but the server answered {served}");
        return 4;
    }
    if expect_revocation && failed == 0 {
        println!("stress client: the capability was never away during {answered} pings");
        return 5;
    }
    println!("stress client: {answered} pings answered, {failed} calls failed by revocation, server answered {served}");
    0
}

fn revoker(source: Cap, space: Cap, hold: u64) -> i64 {
    let Some(timer) = silica_rt::ipc::free_slot() else { return 1 };
    if sys::retype(slots::UNTYPED, ObjectType::Notification, 0, slots::SPACE, timer, 1).is_err() {
        return 1;
    }
    loop {
        if let Err(e) = sys::cap_derive(space, slots::FIRST_GRANT, source, Rights::WRITE, 9) {
            println!("stress revoker: cannot grant: {e:?}");
            return 2;
        }
        // Nobody signals the notification: this is a sleep.
        let _ = sys::recv(Cap(timer), Wait::Until(silica_rt::clock().now() + hold));
        // SAFETY: the only capabilities derived from `source` are the ones
        // this loop granted, which the client expects to lose.
        #[allow(unsafe_code)]
        if let Err(e) = unsafe { sys::cap_revoke(source) } {
            println!("stress revoker: cannot revoke: {e:?}");
            return 3;
        }
    }
}

fn hog() -> i64 {
    let mut frames = 0u64;
    let refusal = loop {
        let Some(slot) = silica_rt::ipc::free_slot() else { break None };
        match sys::retype(slots::UNTYPED, ObjectType::Frame, 12, slots::SPACE, slot, 1) {
            Ok(()) => frames += 1,
            Err(e) => break Some(e),
        }
    };
    // Out of memory is an error to this program and nothing else: it still runs.
    println!("stress hog: {frames} frames, then {refusal:?}");
    if refusal == Some(Error::NoMemory) && frames > 0 { 0 } else { 1 }
}
