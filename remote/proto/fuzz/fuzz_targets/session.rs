//! The remote management session as a hostile connection drives it: bytes
//! on TCP before any handshake (anyone on the network), and, after an
//! honest handshake, messages that are forged or that are sealed honestly
//! around a hostile plaintext (an owner's client that is broken). Nothing
//! may panic; a forged message never opens, an honest one always does, and
//! every view a parser returns lies inside its input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_crypto::noise::{self, Initiator, Keypair, Responder};
use silica_remote::{Frames, MAX_FRAME, PROLOGUE, TAG};

fn inside(outer: &[u8], inner: &[u8]) {
    let (o, i) = (outer.as_ptr() as usize, inner.as_ptr() as usize);
    assert!(i >= o && i + inner.len() <= o + outer.len(), "a view outside its input");
}

/// Every whole message in `input`, as the machine's service finds them.
fn frames(mut input: &[u8], mut each: impl FnMut(&[u8])) {
    loop {
        match Frames::next(input) {
            Ok(Some((range, used))) => {
                assert!(range.end <= input.len() && used == range.end && range.len() <= MAX_FRAME);
                each(&input[range]);
                input = &input[used..];
            }
            Ok(None) | Err(_) => return,
        }
    }
}

fn plaintext(plain: &[u8]) {
    if let Some((_, request)) = silica_remote::call(plain) {
        inside(plain, request);
    }
    if let Some((_, _, reply)) = silica_remote::answer(plain) {
        inside(plain, reply);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let machine = Keypair::new([7; 32]);
    let owner = Keypair::new([9; 32]);
    match mode % 3 {
        // Before a handshake: whatever arrives is a first message.
        0 => frames(rest, |f| {
            let mut m = f.to_vec();
            if let Ok((r, n)) = Responder::read(PROLOGUE, &machine, &mut m) {
                // Only the owner's key, sealed to this machine, opens; the
                // fuzzer holds neither secret.
                assert!(n <= m.len());
                let _ = r.peer();
                let _ = silica_remote::stamp_of(&m[..n]);
            }
            // The time a payload carries, on anything.
            if let Some(t) = silica_remote::stamp_of(f) {
                assert_eq!(silica_remote::stamp(t)[..], f[..]);
            }
        }),
        // An open session, then frames: an even first byte is sealed by the
        // honest owner around the rest, an odd one is sent as it is.
        1 => {
            let mut first = [0u8; noise::FIRST + silica_remote::STAMP];
            let made = silica_remote::stamp(u64::from(mode));
            let (init, n) = Initiator::start(PROLOGUE, &owner, &machine.public, [3; 32], &made, &mut first).unwrap();
            let (resp, p) = Responder::read(PROLOGUE, &machine, &mut first[..n]).unwrap();
            assert_eq!((silica_remote::stamp_of(&first[..p]), resp.peer()), (Some(u64::from(mode)), &owner.public));
            let mut second = [0u8; noise::SECOND];
            let (mut machine_side, n) = resp.answer([4; 32], &[], &mut second).unwrap();
            let (mut owner_side, _) = init.finish(&mut second[..n]).unwrap();
            frames(rest, |f| {
                let Some((&kind, body)) = f.split_first() else { return };
                if kind % 2 == 0 && body.len() + TAG <= MAX_FRAME {
                    let mut m = body.to_vec();
                    m.extend_from_slice(&[0; TAG]);
                    owner_side.seal(&mut m).unwrap();
                    let n = machine_side.open(&mut m).expect("an honest message opens");
                    assert_eq!(&m[..n], body);
                    plaintext(&m[..n]);
                } else {
                    let mut m = body.to_vec();
                    assert!(machine_side.open(&mut m).is_err(), "a forged message opened");
                }
            });
        }
        // The parsers of a plaintext, on anything.
        _ => plaintext(rest),
    }
});
