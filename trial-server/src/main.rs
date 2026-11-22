//! trial-server: provides the protocol `sample.Echo` on the endpoint
//! capability it is granted as grant number 0, for ever.

#![no_std]
#![no_main]

use silica_idl_rt::Array;
use silica_rt::ipc::Handle;
use silica_rt::sys::Cap;

include!(concat!(env!("OUT_DIR"), "/sample_echo.rs")); // defines `pub mod echo`

silica_rt::main!(main);

/// Most records `echo_records` accepts in one request.
const MAX_RECORDS: usize = 4;

/// The provider: it keeps no state.
struct Provider;

impl echo::Server<Handle> for Provider {
    fn echo<'a>(&'a mut self, data: &'a [u8]) -> echo::EchoReply<'a> {
        echo::EchoReply { data }
    }

    fn echo_records<'a>(
        &'a mut self,
        records: Array<'a, echo::Record<'a, Handle>, Handle>,
    ) -> Result<echo::EchoRecordsReply<'a, Handle>, echo::EchoError> {
        if records.is_empty() {
            return Err(echo::EchoError::Empty);
        }
        if records.len() > MAX_RECORDS {
            return Err(echo::EchoError::TooMany);
        }
        Ok(echo::EchoRecordsReply { records })
    }

    fn echo_caps(
        &mut self,
        frame: Handle,
        peer: Option<Handle>,
        any: Handle,
    ) -> echo::EchoCapsReply<Handle> {
        echo::EchoCapsReply { frame, peer, any }
    }
}

fn main(info: &silica_rt::ProcessInfo) -> i64 {
    if info.grants < 1 {
        silica_rt::println!("trial-server: no endpoint was granted (grant 0 is missing)");
        return 1;
    }
    let endpoint = Cap(silica_rt::slots::FIRST_GRANT);
    let mut server = Provider;
    silica_rt::ipc::serve(endpoint, |_badge, request, caps, reply, reply_caps| {
        echo::dispatch(&mut server, request, caps, reply, reply_caps)
    })
}
