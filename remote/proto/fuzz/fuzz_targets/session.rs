//! The remote management session as a hostile connection drives it: bytes
//! on TCP before any handshake (anyone on the network), and, after an
//! honest handshake, messages that are forged or that are sealed honestly
//! around a hostile plaintext (an owner's client that is broken). Nothing
//! may panic; a forged message never opens, an honest one always does, and
//! every view a parser returns lies inside its input. With wire version 2
//! it also makes honest handshakes carrying the fuzzer's payloads (a
//! stamp, or anything else) and ones the network changed on the way: a
//! payload arrives whole, a changed message never opens.
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

/// An honest handshake whose two payloads the fuzzer chooses (a first
/// message's stamp, or anything an owner's client might put there): both
/// arrive whole, the stamp parser takes exactly what a stamp is, and the
/// session's keys agree both ways.
fn payloads(machine: &Keypair, owner: &Keypair, rest: &[u8]) {
    let [a, b, rest @ ..] = rest else { return };
    let (n1, n2) = (usize::from(*a) % 129, usize::from(*b) % 65);
    let (p1, rest) = rest.split_at(n1.min(rest.len()));
    let (p2, rest) = rest.split_at(n2.min(rest.len()));
    let mut first = [0u8; noise::FIRST + 128];
    let (init, n) = Initiator::start(PROLOGUE, owner, &machine.public, [3; 32], p1, &mut first).unwrap();
    let (resp, p) = Responder::read(PROLOGUE, machine, &mut first[..n]).unwrap();
    assert_eq!(&first[..p], p1, "a first message's payload arrives as sent");
    match silica_remote::stamp_of(p1) {
        Some(t) => assert_eq!((p1.len(), &silica_remote::stamp(t)[..]), (silica_remote::STAMP, p1)),
        None => assert_ne!(p1.len(), silica_remote::STAMP),
    }
    let mut second = [0u8; noise::SECOND + 64];
    let (mut machine_side, n) = resp.answer(&mut [4; 32], p2, &mut second).unwrap();
    let (mut owner_side, q) = init.finish(&mut second[..n]).unwrap();
    assert_eq!(&second[..q], p2, "an answer's payload arrives as sent");
    let mut m = rest.to_vec();
    m.extend_from_slice(&[0; TAG]);
    machine_side.seal(&mut m).unwrap();
    assert_eq!(owner_side.open(&mut m).map(|n| &m[..n]), Ok(rest), "the machine's message opens for the owner");
}

/// An honest handshake whose first or second message the network changes
/// (the fuzzer's bytes XORed in at the positions it names): a changed
/// message never opens, an unchanged one always does.
fn tampered(machine: &Keypair, owner: &Keypair, rest: &[u8]) {
    let [which, rest @ ..] = rest else { return };
    let mut first = [0u8; noise::FIRST + silica_remote::STAMP];
    let (init, n1) = Initiator::start(PROLOGUE, owner, &machine.public, [3; 32], &silica_remote::stamp(5), &mut first).unwrap();
    // Flips that cancel out change nothing: what changed is compared.
    let flip = |m: &mut [u8]| {
        for pair in rest.chunks_exact(2) {
            let at = usize::from(pair[0]) % m.len();
            m[at] ^= pair[1];
        }
    };
    if which % 2 == 0 {
        let before = first;
        flip(&mut first[..n1]);
        let changed = first[..n1] != before[..n1];
        match Responder::read(PROLOGUE, machine, &mut first[..n1]) {
            Ok((r, p)) => {
                assert!(!changed, "a changed first message opened");
                assert_eq!((silica_remote::stamp_of(&first[..p]), r.peer()), (Some(5), &owner.public));
            }
            Err(_) => assert!(changed, "an unchanged first message did not open"),
        }
        return;
    }
    let (resp, _) = Responder::read(PROLOGUE, machine, &mut first[..n1]).unwrap();
    let mut second = [0u8; noise::SECOND];
    let (_, n2) = resp.answer(&mut [4; 32], &[], &mut second).unwrap();
    let before = second;
    flip(&mut second[..n2]);
    let changed = second[..n2] != before[..n2];
    match init.finish(&mut second[..n2]) {
        Ok(_) => assert!(!changed, "a changed answer opened"),
        Err(_) => assert!(changed, "an unchanged answer did not open"),
    }
}

/// The hash the handshake is built on, as the fuzzer feeds it: BLAKE2s
/// over the fuzzer's bytes in the pieces it chooses (each boundary a
/// different path through the block buffer) gives the one-shot digest;
/// keyed and as HMAC and HKDF under a key of the fuzzer's, it is a
/// function of its inputs (computed twice, the same).
fn hashes(rest: &[u8]) {
    use silica_crypto::blake2s::{Blake2s, hash, hkdf2, hmac};
    let [k, cut, rest @ ..] = rest else { return };
    let mut key = [0u8; 32];
    let n = usize::from(*k) % 33;
    key[..n.min(rest.len())].copy_from_slice(&rest[..n.min(rest.len())]);
    let whole = hash(&[rest]);
    let mut b = Blake2s::new();
    let step = usize::from(*cut).max(1);
    for piece in rest.chunks(step) {
        b.update(piece);
    }
    assert_eq!(b.finish(), whole, "a hash fed in pieces is the hash of the whole");
    let keyed = Blake2s::keyed(&key[..n]).update(rest).finish();
    assert_eq!(Blake2s::keyed(&key[..n]).update(rest).finish(), keyed);
    let (a1, b1) = hkdf2(&key, rest);
    assert_eq!(hkdf2(&key, rest), (a1, b1));
    assert_eq!(hmac(&key, &[rest]), hmac(&key, &[&rest[..rest.len() / 2], &rest[rest.len() / 2..]]));
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let machine = Keypair::new([7; 32]);
    let owner = Keypair::new([9; 32]);
    match mode {
        // Modes added with wire version 2 take the top nine values, so the
        // seeds made before keep their meaning (mode % 3).
        247..=249 => hashes(rest),
        250..=252 => payloads(&machine, &owner, rest),
        253..=255 => tampered(&machine, &owner, rest),
        _ => {}
    }
    match mode % 3 {
        _ if mode >= 247 => {}
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
            let (mut machine_side, n) = resp.answer(&mut [4; 32], &[], &mut second).unwrap();
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
