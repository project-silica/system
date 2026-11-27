//! The entropy service (component D14): provides `silica.entropy.Source`.
//!
//! Its seed comes from the service manager (the `seed` declaration):
//! `args[4..8]`, a key derived from the boot's entropy for this start of
//! this service, and `args[3]`, which trusted sources went into the boot's
//! (`RootInfo::entropy_sources`). Every randomness device the device
//! manager has a driver for (`silica.entropy.Device`) is mixed in at start,
//! and again before an answer when the last mixing is older than
//! [`REMIX_NS`]; a device that fails is left until the next time. With no
//! trusted boot source and no device answering yet, `fill` is refused
//! (`not_seeded`): the bytes would be guessable.
//!
//! Grants: 0 its endpoint, 1 the device manager.
#![no_std]
#![no_main]

use entropy::Pool;
use silica_idl_rt::CapList;
use silica_protocols::device::manager;
use silica_protocols::entropy::device as rng;
use silica_protocols::entropy::source::{self, Error, FillReply, Status, StatusReply};
use silica_rt::ipc::{Channel, Handle, serve_secret};
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

/// Bytes asked of each device when mixing.
const FROM_DEVICE: u32 = 64;
/// How old the last mixing may be before an answer mixes again.
const REMIX_NS: u64 = 60_000_000_000;
/// The most bytes one `fill` gives.
const MOST: u32 = 256;

struct Service {
    pool: Pool,
    devices: manager::Client<Channel, Handle>,
    /// The boot's entropy came from a source the system trusts.
    boot: bool,
    device_bytes: u64,
    mixes: u32,
    /// Each device's last read (its identity, the read's digest), for the
    /// health tests.
    last: [(u32, [u8; 32]); 4],
    /// When devices were last mixed in (0: never asked).
    mixed_at: u64,
    out: [u8; MOST as usize],
}

impl Service {
    /// Mix in what every randomness device gives now.
    fn mix_devices(&mut self) {
        self.mixed_at = silica_rt::clock().now().max(1);
        let Ok(listed) = self.devices.list(manager::Class::Entropy, 0) else { return };
        let ids: [Option<u32>; 4] = core::array::from_fn(|i| listed.devices.iter().nth(i).map(|d| d.id));
        for id in ids.into_iter().flatten() {
            let Ok(opened) = self.devices.open(id, None) else { continue };
            let mut device = rng::Client::<Channel, Handle>::from(Channel::within(opened.driver.cap(), silica_rt::ipc::DRIVER_CALL_LIMIT));
            if let Ok(r) = device.read(FROM_DEVICE) {
                // Mixed in whatever they are; counted towards being seeded
                // only if they pass the health tests (`entropy::healthy`): a
                // broken device's constant or repeated bytes made the
                // service say it was seeded after any 32 of them.
                self.pool.mix(r.data);
                let k = self
                    .last
                    .iter()
                    .position(|(d, _)| *d == id)
                    .or_else(|| self.last.iter().position(|(d, _)| *d == u32::MAX))
                    .unwrap_or(0);
                let verdict = entropy::healthy(r.data, &self.last[k].1);
                self.last[k] = (id, entropy::digest(r.data));
                match verdict {
                    Ok(()) => self.device_bytes += r.data.len() as u64,
                    Err(why) => println!("entropy: device {id:#x}'s bytes failed a health test ({why}); not counted"),
                }
                self.mixes += 1;
            }
            // The device's bytes went into the pool: neither the client's
            // message buffer nor the IPC buffer keeps them (a later, shorter
            // reply would have left them there).
            device.core.wipe();
            silica_rt::ipc::wipe_message_words();
        }
    }

    fn seeded(&self) -> bool {
        self.boot || self.device_bytes >= 32
    }
}

impl source::Server<Handle> for Service {
    fn fill<'a>(&'a mut self, count: u32) -> Result<FillReply<'a>, Error> {
        if self.mixed_at == 0 || silica_rt::clock().now() - self.mixed_at > REMIX_NS || !self.seeded() {
            self.mix_devices();
        }
        if !self.seeded() {
            return Err(Error::NotSeeded);
        }
        let n = count.min(MOST) as usize;
        self.pool.fill(&mut self.out[..n]);
        Ok(FillReply { data: &self.out[..n] })
    }

    fn status(&mut self) -> StatusReply {
        StatusReply { status: Status { boot: self.boot, device_bytes: self.device_bytes, mixes: self.mixes } }
    }
}

fn main(info: &'static ProcessInfo) -> i64 {
    let mut seed = [0u8; 32];
    for (i, word) in info.args[4..8].iter().enumerate() {
        seed[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    let grant = |n: u64| Cap(slots::FIRST_GRANT + n);
    let mut service = Service {
        pool: Pool::new(seed),
        devices: manager::Client::from(Channel::new(grant(1))),
        boot: info.args[3] != 0,
        device_bytes: 0,
        mixes: 0,
        mixed_at: 0,
        last: [(u32::MAX, [0; 32]); 4],
        out: [0; MOST as usize],
    };
    seed.fill(0);
    core::hint::black_box(&seed);
    service.mix_devices();
    println!(
        "entropy: seeded from {}{}",
        if service.boot { "the boot's trusted sources" } else { "the boot's timing alone" },
        if service.device_bytes > 0 { " and a device" } else { "; no device" }
    );
    // An answer is what a client makes its keys from: once it is sent, no
    // copy of it stays here (`serve_secret` wipes the loop's; `out` is
    // wiped as soon as the reply is written). Kept, the last answer stayed
    // in this service's memory until the next (the audit of 2026-11-27).
    serve_secret(grant(0), |_badge, request, caps: CapList<Handle>, reply, reply_caps| {
        let n = source::dispatch(&mut service, request, caps, reply, reply_caps);
        service.out.fill(0);
        core::hint::black_box(&service.out);
        n
    })
}
