//! The entropy service, checked (`checks=entropy`; the machine has a virtio
//! entropy device): it says a device was mixed in; its answers are never
//! all zeros, never repeat, and over 64 KiB have a share of one bits within
//! six standard deviations of a half; a request for more than 256 bytes
//! gets 256; and after the service is restarted (a new start, a new seed)
//! nothing it answers repeats anything from before. Prints `TEST
//! entropy.<name> PASS` per check and `ENTROPY OK`.
#![no_std]
#![no_main]

use silica_protocols::entropy::source;
use silica_protocols::system::manager as system;
use silica_rt::alloc::collections::BTreeSet;
use silica_rt::alloc::format;
use silica_rt::alloc::string::String;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

fn main(_info: &'static ProcessInfo) -> i64 {
    match run() {
        Ok(()) => {
            println!("ENTROPY OK");
            0
        }
        Err(e) => {
            println!("ERROR: entropycheck: {e}");
            1
        }
    }
}

type Source = source::Client<Channel, Handle>;

/// 32 bytes from the service.
fn block(s: &mut Source) -> Result<[u8; 32], String> {
    let r = s.fill(32).map_err(|e| format!("fill: {e:?}"))?;
    r.data.try_into().map_err(|_| format!("asked for 32 bytes, got {}", r.data.len()))
}

fn run() -> Result<(), String> {
    let grant = |n: u64| Channel::new(Cap(slots::FIRST_GRANT + n));
    let mut s = Source::from(grant(0));
    let mut system = system::Client::<Channel, Handle>::from(grant(1));

    let st = s.status().map_err(|e| format!("status: {e:?}"))?.status;
    // On a machine with no trusted boot source whose randomness device is
    // broken (constant bytes: `entropycheck.expect=unseeded`), the service
    // must refuse to answer: what it would give is guessable. It said it
    // was seeded after any 32 bytes of the device.
    if silica_rt::option("expect") == Some("unseeded") {
        if st.boot || st.mixes == 0 {
            return Err(format!("not the machine this check is for (boot sources trusted: {}, {} mixes)", st.boot, st.mixes));
        }
        return match s.fill(32) {
            Err(silica_idl_rt::CallError::Error(source::Error::NotSeeded)) if st.device_bytes == 0 => {
                println!("TEST entropy.a_broken_device_does_not_seed PASS");
                Ok(())
            }
            r => Err(format!(
                "with only a broken device, the service counted {} of its bytes and answered {:?}",
                st.device_bytes,
                r.map(|r| r.data.len())
            )),
        };
    }
    if st.device_bytes == 0 || st.mixes == 0 {
        return Err(format!("no device bytes went in ({} bytes, {} mixes)", st.device_bytes, st.mixes));
    }
    println!("entropycheck: boot sources trusted: {}, {} device bytes in {} mixes", st.boot, st.device_bytes, st.mixes);
    println!("TEST entropy.seeded_from_the_device PASS");

    let mut seen = BTreeSet::new();
    let mut ones = 0u64;
    for _ in 0..2048 {
        let b = block(&mut s)?;
        if b == [0; 32] {
            return Err(String::from("an answer of zeros"));
        }
        if !seen.insert(b) {
            return Err(String::from("an answer repeated"));
        }
        ones += b.iter().map(|x| x.count_ones() as u64).sum::<u64>();
    }
    // 2048 blocks of 256 bits: a half is 262144, a standard deviation 362.
    let bits = 2048 * 256u64;
    if ones.abs_diff(bits / 2) > 6 * 362 {
        return Err(format!("{ones} one bits in {bits}"));
    }
    println!("TEST entropy.answers_are_not_lopsided_and_never_repeat PASS");

    let r = s.fill(1000).map_err(|e| format!("fill 1000: {e:?}"))?;
    if r.data.len() != 256 {
        return Err(format!("asked for 1000 bytes, got {} (256 is the most)", r.data.len()));
    }
    println!("TEST entropy.a_large_request_gets_the_most_there_is PASS");

    system.restart("entropy").map_err(|e| format!("restarting the entropy service: {e:?}"))?;
    for _ in 0..256 {
        if !seen.insert(block(&mut s)?) {
            return Err(String::from("after a restart, an answer from before came again"));
        }
    }
    println!("TEST entropy.a_restarted_service_repeats_nothing PASS");

    // Its `control` reaches the service its declaration names (`controls=`)
    // and no other: before, any service by name (the audit's M1).
    match system.restart("netd") {
        Err(silica_idl_rt::CallError::Error(system::Error::Refused)) => {}
        other => return Err(format!("restarting netd, which this check's declaration does not name, was not refused: {other:?}")),
    }
    println!("TEST entropy.control_reaches_only_the_services_declared PASS");

    // The machine's service is never updated or reverted, though this
    // check's declaration names it (`controls=`): no program a caller sends
    // is given the machine. The update is refused before its bytes are
    // looked at (one byte, no program: before, `NotAProgram`; a revert of a
    // program never updated was `Ok`).
    system.program(1).map_err(|e| format!("asking for memory for a program: {e:?}"))?;
    match system.update("devmgr", 1) {
        Err(silica_idl_rt::CallError::Error(system::Error::Refused)) => {}
        other => return Err(format!("updating devmgr, the machine's service, was not refused: {other:?}")),
    }
    match system.revert("devmgr") {
        Err(silica_idl_rt::CallError::Error(system::Error::Refused)) => {}
        other => return Err(format!("reverting devmgr, the machine's service, was not refused: {other:?}")),
    }
    println!("TEST entropy.the_machine_is_never_updated PASS");
    Ok(())
}
