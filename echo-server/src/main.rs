//! A provider of `sample.Echo`: answers every call on the endpoint it was
//! granted (its first grant) with what it was sent.
#![no_std]
#![no_main]

use silica_idl_rt::Array;
use silica_rt::ipc::{Handle, serve};
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, slots};

include!(concat!(env!("OUT_DIR"), "/sample_echo.rs"));

struct Echo;

impl echo::Server<Handle> for Echo {
    fn echo<'a>(&'a mut self, data: &'a [u8]) -> echo::EchoReply<'a> {
        echo::EchoReply { data }
    }

    fn echo_records<'a>(
        &'a mut self,
        records: Array<'a, echo::Record<'a, Handle>, Handle>,
    ) -> Result<echo::EchoRecordsReply<'a, Handle>, echo::EchoError> {
        match records.len() {
            0 => Err(echo::EchoError::Empty),
            1..=8 => Ok(echo::EchoRecordsReply { records }),
            _ => Err(echo::EchoError::TooMany),
        }
    }

    fn echo_caps(&mut self, frame: Handle, peer: Option<Handle>, any: Handle) -> echo::EchoCapsReply<Handle> {
        echo::EchoCapsReply { frame, peer, any }
    }
}

silica_rt::main!(main);

fn main(_info: &'static ProcessInfo) -> i64 {
    let mut server = Echo;
    serve(Cap(slots::FIRST_GRANT), |_badge, request, caps, reply, reply_caps| echo::dispatch(&mut server, request, caps, reply, reply_caps))
}
