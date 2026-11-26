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
//!   the client sent. With `args[3]` set, the grant `args[3]` slots after
//!   its first is a notification it signals every [`TOLD_EVERY`] answers:
//!   its progress, by which systest tells a slow run from a stuck one.
//! - [`REVOKER`]: grants a capability derived from its first grant into
//!   slot `FIRST_GRANT` of the CapSpace that is its second grant, leaves it
//!   there for `args[1]` nanoseconds, revokes it, and starts again.
//! - [`HOG`]: retypes its memory into frames until the kernel refuses, and
//!   exits 0 if the refusal was `NoMemory` and it could still work after.
//! - [`ONE_CALL`]: makes one call through its first grant and exits with
//!   the kernel's status of that call (0: answered).
//! - `BORROWER`: maps `args[1]` frames of `2^args[2]` bytes one after
//!   another as lent memory (`silica_rt::mem::Lent`), each taken away while
//!   mapped, every page then touched (its supervisor answers with zeros),
//!   and let go of; exits 0 if every page read zeros and every frame after
//!   the first was mapped where the first was.
//! - `BLOCKS`: takes blocks of `2^args[1]` bytes from its memory (`silica_rt::mem`) until
//!   refused, gives them all back, then takes blocks of `2^args[2]` bytes until refused; exits 0
//!   if the large blocks hold what the small ones did (memory given back at one size serves another).
//! - `CHURN`: `args[1]` rounds of `args[2]` bytes (0: 45% of its free memory) of the heap at a time,
//!   as 2 KiB pieces, then 32 KiB blocks, then 256 KiB blocks, each
//!   written and checked and given back; exits 0 if every request was
//!   served and the program's free memory after the last round is what
//!   it was after the first (the heap reuses what it freed at one size for
//!   another), else the round and size that failed (its line says how).
#![no_std]
#![no_main]

use silica_rt::sys::{self, Cap, Error, MsgInfo, ObjectType, Rights, Wait};
use silica_rt::{ProcessInfo, println, slots};

pub const SERVER: u64 = 0;
pub const CLIENT: u64 = 1;
pub const REVOKER: u64 = 2;
pub const HOG: u64 = 3;
pub const ONE_CALL: u64 = 4;
const TIME_WRITER: u64 = 5;
const TIME_READER: u64 = 6;
const BORROWER: u64 = 7;
const CHURN: u64 = 8;
const BLOCKS: u64 = 9;

const PING: u64 = 1;
const COUNT: u64 = 2;
/// How many answers a client gets between signals of its progress.
pub const TOLD_EVERY: u64 = 4096;

silica_rt::main!(main);

fn main(info: &'static ProcessInfo) -> i64 {
    let grant = Cap(slots::FIRST_GRANT);
    match info.args[0] {
        SERVER => server(grant),
        CLIENT => client(grant, info.args[1], info.args[2] != 0, (info.args[3] != 0).then(|| Cap(slots::FIRST_GRANT + info.args[3]))),
        REVOKER => revoker(grant, Cap(slots::FIRST_GRANT + 1), info.args[1]),
        HOG => hog(),
        TIME_WRITER => {
            let Ok(page) = silica_rt::mem::peer(grant, 12, Rights(Rights::READ.0 | Rights::WRITE.0)) else { return -1 };
            page.store_release32(0, 1);
            page.write32(16, 2);
            0
        }
        TIME_READER => {
            let Ok(page) = silica_rt::mem::peer(grant, 12, Rights::READ) else { return -1 };
            i64::from(silica_rt::time::read(&page) != (0, silica_rt::time::Source::None))
        }
        BORROWER => borrower(info.args[1], info.args[2] as u8),
        CHURN => churn(info.args[1], info.args[2] as usize),
        BLOCKS => blocks(info.args[1] as u8, info.args[2] as u8),
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
        let m = match next {
            Ok(m) => m,
            Err(e) => {
                println!("stress server: receive failed after {served} pings: {e:?}");
                return 1;
            }
        };
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

fn client(endpoint: Cap, count: u64, expect_revocation: bool, progress: Option<Cap>) -> i64 {
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
            Ok(v) if v == answered + 1 => {
                answered += 1;
                if answered % TOLD_EVERY == 0
                    && let Some(p) = progress
                    && sys::signal(p).is_err()
                {
                    println!("stress client: cannot signal its progress after {answered} pings");
                    return 6;
                }
            }
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

/// See [`BORROWER`] in the module's documentation.
fn borrower(cycles: u64, bits: u8) -> i64 {
    use silica_rt::mem::{Lent, Object};
    let mut first = None;
    for cycle in 0..cycles {
        let Ok(frame) = Object::new(ObjectType::Frame, bits) else { return 10 };
        let Ok(lent) = Lent::map(frame.cap(), bits, Rights(Rights::READ.0 | Rights::WRITE.0)) else { return 11 };
        let region = lent.region();
        if *first.get_or_insert(region.addr()) != region.addr() {
            println!("stress borrower: cycle {cycle} mapped at {:#x}, not where the first was", region.addr());
            return 12;
        }
        region.write64(8, cycle + 1);
        if region.read64(8) != cycle + 1 {
            return 13;
        }
        // The lender takes it back: the mapping goes with the frame.
        // SAFETY: nothing but `region` refers to it, and that reads zeros now.
        #[allow(unsafe_code)]
        unsafe {
            frame.destroy()
        };
        for page in (0..region.len()).step_by(4096) {
            if region.read64(page + 8) != 0 {
                println!("stress borrower: cycle {cycle} read lent memory after it was taken back");
                return 14;
            }
        }
        drop(lent);
    }
    0
}

/// See `CHURN` in the module's documentation.
fn churn(rounds: u64, bytes: usize) -> i64 {
    use silica_rt::alloc::vec::Vec;
    // 0: 45% of what the program has free, so that three sizes each
    // keeping their own would need more than it has.
    let bytes = if bytes == 0 { (silica_rt::mem::available() as usize / 100 * 45) & !0xFFFF } else { bytes };
    let mut first = 0;
    for round in 0..rounds {
        for (n, size) in [2048usize, 32 << 10, 256 << 10].into_iter().enumerate() {
            let mut blocks: Vec<Vec<u8>> = Vec::new();
            if blocks.try_reserve_exact(bytes / size).is_err() {
                return 100;
            }
            for k in 0..bytes / size {
                let mut b = Vec::new();
                if b.try_reserve_exact(size).is_err() {
                    println!(
                        "stress churn: round {round}: {size}-byte block {k} refused, {} bytes of memory free",
                        silica_rt::mem::available()
                    );
                    return 10 * (round as i64 + 1) + n as i64;
                }
                b.resize(size, k as u8);
                blocks.push(b);
            }
            for (k, b) in blocks.iter().enumerate() {
                if b[0] != k as u8 || b[size - 1] != k as u8 {
                    return 99;
                }
            }
        }
        let free = silica_rt::mem::available();
        if round == 0 {
            first = free;
        } else if free < first {
            println!("stress churn: round {round}: {free} bytes of memory free, {first} after the first round: the heap grew");
            return 98;
        }
    }
    println!("stress churn: {rounds} rounds of {bytes} bytes at three sizes; the heap kept what it freed for the next size");
    0
}

/// See `BLOCKS` in the module's documentation.
fn blocks(small: u8, large: u8) -> i64 {
    use silica_rt::mem;
    let mut held: [Option<sys::Cap>; 512] = [None; 512];
    let take = |bits: u8, held: &mut [Option<sys::Cap>; 512]| {
        let mut n = 0;
        while n < held.len() {
            match mem::alloc(bits) {
                Ok(b) => {
                    held[n] = Some(b);
                    n += 1;
                }
                Err(_) => break,
            }
        }
        n
    };
    let give_back = |bits: u8, held: &mut [Option<sys::Cap>; 512]| {
        for b in held.iter_mut().filter_map(Option::take) {
            // SAFETY: nothing was made from these blocks.
            #[allow(unsafe_code)]
            unsafe {
                mem::free(b, bits)
            };
        }
    };
    // The heap first: 45% of the program's memory in 256 KiB blocks, then
    // dropped. Its chunks go back to the program's memory but for one
    // spare chunk and its records (512 KiB, here): before, the heap kept
    // every chunk it made.
    let start = mem::available();
    {
        use silica_rt::alloc::vec::Vec;
        let mut v: Vec<Vec<u8>> = Vec::new();
        for _ in 0..(start as usize / 100 * 45) / (256 << 10) {
            let mut b = Vec::new();
            if b.try_reserve_exact(256 << 10).is_err() {
                return 2;
            }
            b.resize(256 << 10, 1);
            v.push(b);
        }
    }
    let after = mem::available();
    println!("stress blocks: {start} bytes free, {after} after 45% of them were the heap's and given back");
    if after + (512 << 10) < start {
        return 3;
    }
    let n = take(small, &mut held);
    give_back(small, &mut held);
    let m = take(large, &mut held);
    give_back(large, &mut held);
    let (small_bytes, large_bytes) = ((n as u64) << small, (m as u64) << large);
    println!("stress blocks: {n} of 2^{small} bytes taken and given back, then {m} of 2^{large}");
    // The large blocks hold what the small did, but for what the program's
    // own heap and the alignment of the large ones take.
    if n == 0 || m == 0 || large_bytes + (1u64 << large) < small_bytes { 1 } else { 0 }
}
