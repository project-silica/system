//! A client of `sample.Echo`: calls the provider behind the endpoint it was
//! granted (its first grant) and checks every answer. Exit status 0 means
//! every call came back as the protocol says.
#![no_std]
#![no_main]

use silica_idl_rt::CallError;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::sys::{self, Cap, ObjectType};
use silica_rt::{ProcessInfo, println, slots};

include!(concat!(env!("OUT_DIR"), "/sample_echo.rs"));

silica_rt::main!(main);

fn main(_info: &'static ProcessInfo) -> i64 {
    let endpoint = Cap(slots::FIRST_GRANT);
    // A complete header for an unknown method, accompanied by a word
    // outside its declared byte length. The transport must reject the
    // envelope before method lookup, then serve the ordinary calls below.
    let ordinal = u32::MAX;
    let malformed = sys::call(endpoint, sys::MsgInfo::new(16, 3), [ordinal.into(), 1, 0, 0]);
    if !malformed.is_ok_and(|m| {
        m.info == sys::MsgInfo::new(16, 2)
            && m.words[0] == u64::from(ordinal) | (1 << 32) | ((silica_idl_rt::Status::MalformedRequest as u64) << 48)
    }) {
        println!("echo-client: the provider did not reject an inconsistent word count");
        return 9;
    }
    let mut client = echo::Client::<Channel, Handle>::from(Channel::new(endpoint));

    // Bytes of every length that matters: empty, inside the registers, across
    // into the buffer, and the largest a message can carry.
    let mut data = [0u8; 3900];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    for len in [0usize, 1, 16, 17, 100, 3900] {
        match client.echo(&data[..len]) {
            Ok(r) if r.data == &data[..len] => {}
            Ok(_) => {
                println!("echo-client: {len} bytes came back changed");
                return 1;
            }
            Err(e) => {
                println!("echo-client: echo of {len} bytes failed: {e:?}");
                return 2;
            }
        }
    }

    // The method's own error arrives as the method's own error.
    match client.echo_records(silica_idl_rt::Array::new(&[])) {
        Err(CallError::Error(echo::EchoError::Empty)) => {}
        other => {
            println!("echo-client: an empty record list should fail with `empty`, got {:?}", other.map(|_| ()));
            return 3;
        }
    }

    // Capabilities move there and back: a frame, no peer, a notification.
    let (Some(frame), Some(note)) = (silica_rt::ipc::free_slot(), silica_rt::ipc::free_slot()) else { return 4 };
    if sys::retype(slots::UNTYPED, ObjectType::Frame, 12, slots::SPACE, frame, 1).is_err()
        || sys::retype(slots::UNTYPED, ObjectType::Notification, 0, slots::SPACE, note, 1).is_err()
    {
        println!("echo-client: cannot make the capabilities to send");
        return 4;
    }
    let returned = match client.echo_caps(Handle::new(Cap(frame)), None, Handle::new(Cap(note))) {
        Ok(r) => r,
        Err(e) => {
            println!("echo-client: echo_caps failed: {e:?}");
            return 5;
        }
    };
    // What came back are working capabilities of the kinds that were sent,
    // and the ones sent are gone from where they were.
    let came_back = sys::inspect_slot(slots::SPACE, returned.frame.cap().0).ok().flatten().map(|i| i.ty) == Some(ObjectType::Frame)
        && sys::signal(returned.any.cap()).is_ok()
        && returned.peer.is_none();
    let moved = sys::inspect_slot(slots::SPACE, frame) == Ok(None) && sys::inspect_slot(slots::SPACE, note) == Ok(None);
    if !came_back || !moved {
        println!("echo-client: capabilities did not move there and back (came back: {came_back}, moved: {moved})");
        return 6;
    }
    // Far more round trips than the CapSpace has slots: every slot a
    // capability leaves or is deleted from is used again.
    let (mut frame, mut any) = (returned.frame, returned.any);
    for round in 0..5000 {
        match client.echo_caps(frame, None, any) {
            Ok(r) => (frame, any) = (r.frame, r.any),
            Err(e) => {
                println!("echo-client: echo_caps failed in round {round}: {e:?}");
                return 7;
            }
        }
    }
    if sys::signal(any.cap()).is_err() {
        println!("echo-client: the notification stopped working after 5000 round trips");
        return 8;
    }
    println!("echo-client: bytes, records and capabilities all came back as sent");
    0
}
