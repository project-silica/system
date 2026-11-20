//! trial-client: calls the protocol `sample.Echo` through the endpoint
//! capability it is granted as grant number 0, checks three replies, prints
//! one line on the debug console and exits.
//!
//! Exit status: 0 every check passed; 1 the 5-byte `echo` failed; 2 the
//! 2000-byte `echo` failed; 3 `echo_records` with no record did not fail
//! with `empty`; 4 no capability was granted.

#![no_std]
#![no_main]

use silica_idl_rt::{Array, CallError};
use silica_rt::ipc::{Channel, Handle};
use silica_rt::sys::Cap;

include!(concat!(env!("OUT_DIR"), "/sample_echo.rs")); // defines `pub mod echo`

silica_rt::main!(main);

/// Length of the large `echo` request's data.
const BIG_LEN: usize = 2000;

/// The large `echo` request's data: byte `i` is `i % 251`.
static BIG: [u8; BIG_LEN] = big();

const fn big() -> [u8; BIG_LEN] {
    let mut bytes = [0u8; BIG_LEN];
    let mut i = 0;
    while i < BIG_LEN {
        bytes[i] = (i % 251) as u8;
        i += 1;
    }
    bytes
}

/// Calls `echo` with `data` and checks that the reply is the same bytes.
/// On failure prints the line saying why and returns false.
fn check_echo(client: &mut echo::Client<Channel, Handle>, what: &str, data: &[u8]) -> bool {
    match client.echo(data) {
        Ok(reply) => {
            if reply.data == data {
                true
            } else {
                silica_rt::println!(
                    "trial-client: FAILED: {}: the reply differs from the request ({} bytes sent, {} received)",
                    what,
                    data.len(),
                    reply.data.len()
                );
                false
            }
        }
        Err(CallError::Transport(failure)) => {
            silica_rt::println!("trial-client: FAILED: {}: the call failed: {}", what, failure);
            false
        }
        Err(CallError::Error(never)) => match never {},
    }
}

/// Calls `echo_records` with no record and checks that it fails with the
/// protocol's own error `empty`. On failure prints the line saying why and
/// returns false.
fn check_empty(client: &mut echo::Client<Channel, Handle>) -> bool {
    match client.echo_records(Array::new(&[])) {
        Err(CallError::Error(echo::EchoError::Empty)) => true,
        Err(CallError::Error(_)) => {
            silica_rt::println!(
                "trial-client: FAILED: echo_records with no record failed with another error than `empty`"
            );
            false
        }
        Err(CallError::Transport(failure)) => {
            silica_rt::println!(
                "trial-client: FAILED: echo_records with no record: the call failed: {}",
                failure
            );
            false
        }
        Ok(_) => {
            silica_rt::println!(
                "trial-client: FAILED: echo_records with no record succeeded; expected the error `empty`"
            );
            false
        }
    }
}

fn main(info: &silica_rt::ProcessInfo) -> i64 {
    if info.grants < 1 {
        silica_rt::println!("trial-client: FAILED: no endpoint was granted (grant 0 is missing)");
        return 4;
    }
    let endpoint = Cap(silica_rt::slots::FIRST_GRANT);
    let mut client: echo::Client<Channel, Handle> = echo::Client::from(Channel::new(endpoint));

    if !check_echo(&mut client, "echo of 5 bytes", b"hello") {
        return 1;
    }
    if !check_echo(&mut client, "echo of 2000 bytes", &BIG) {
        return 2;
    }
    if !check_empty(&mut client) {
        return 3;
    }
    silica_rt::println!(
        "trial-client: ok: echo returned 5 and 2000 bytes unchanged, echo_records with no record failed with `empty`"
    );
    0
}
