//! The shell (component D20): reads a command a line at a time from the
//! console and runs it. Its commands look at and steer the system through
//! the service manager and the device manager:
//!
//! - `services`: every service, what it does, how often it failed;
//! - `stop <service>`, `start <service>`;
//! - `devices`: the devices with a running driver, by class;
//! - `restart-driver <device>`: end a device's driver and start it again;
//! - `shutdown`, `reboot`;
//! - `echo <text>`, `help`.
//!
//! Typed pipelines between programs (component D20's other half) come later.
#![no_std]
#![no_main]

use core::fmt::Write;
use silica_protocols::console::terminal;
use silica_protocols::device::manager as devices;
use silica_protocols::system::manager as system;
use silica_rt::alloc::string::String;
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, slots};

silica_rt::main!(main);

struct Shell {
    term: terminal::Client<Channel, Handle>,
    system: system::Client<Channel, Handle>,
    devices: devices::Client<Channel, Handle>,
    out: String,
}

const HELP: &str =
    "commands: services, stop <service>, start <service>, devices, restart-driver <device>, shutdown, reboot, echo <text>, help\n";

impl Shell {
    fn say(&mut self) {
        let text = core::mem::take(&mut self.out);
        let _ = self.term.write(&text);
    }

    fn run(&mut self, line: &str) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(&command) = words.first() else { return };
        let arg = words.get(1).copied().unwrap_or("");
        match command {
            "help" => self.out.push_str(HELP),
            "echo" => {
                let _ = writeln!(self.out, "{}", line.trim_start().strip_prefix("echo").unwrap_or("").trim());
            }
            "services" => match self.system.list() {
                Ok(r) => {
                    for s in r.services.iter() {
                        let state = match s.state {
                            system::State::Running => "running",
                            system::State::Stopped => "stopped",
                            system::State::Failed => "failed",
                            system::State::Unknown(_) => "?",
                        };
                        let _ = writeln!(self.out, "  {:<12} {:<8} failures {:<2} {}", s.name, state, s.failures, s.provides);
                    }
                }
                Err(e) => {
                    let _ = writeln!(self.out, "services: {e:?}");
                }
            },
            "stop" | "start" if !arg.is_empty() => {
                let r = if command == "stop" { self.system.stop(arg).map(|_| ()) } else { self.system.start(arg).map(|_| ()) };
                match r {
                    Ok(()) => {
                        let _ = writeln!(self.out, "{command}: {arg}: done");
                    }
                    Err(e) => {
                        let _ = writeln!(self.out, "{command}: {arg}: {e:?}");
                    }
                }
            }
            "devices" => {
                for (class, name) in
                    [(devices::Class::Block, "block"), (devices::Class::Display, "display"), (devices::Class::Input, "input")]
                {
                    if let Ok(r) = self.devices.list(class) {
                        for d in r.devices.iter() {
                            let _ = writeln!(
                                self.out,
                                "  {:02x}:{:02x}.{} {:<8} {}",
                                d.id >> 8 & 0xFF,
                                d.id >> 3 & 31,
                                d.id & 7,
                                name,
                                d.driver
                            );
                        }
                    }
                }
            }
            "restart-driver" if !arg.is_empty() => {
                // A device as `bus:device.function`, hexadecimal.
                let id = parse_bdf(arg);
                match id.map(|id| self.devices.restart(id)) {
                    Some(Ok(_)) => {
                        let _ = writeln!(self.out, "restart-driver: {arg}: done");
                    }
                    Some(Err(e)) => {
                        let _ = writeln!(self.out, "restart-driver: {arg}: {e:?}");
                    }
                    None => self.out.push_str("restart-driver: name a device as bus:device.function\n"),
                }
            }
            "shutdown" | "reboot" => {
                let _ = self.term.write("shutting down\n");
                if let Err(e) = self.system.shutdown(command == "reboot") {
                    let _ = writeln!(self.out, "{command}: {e:?}");
                }
            }
            _ => {
                let _ = writeln!(self.out, "{command}: no such command (help lists them)");
            }
        }
        self.say();
    }
}

fn parse_bdf(s: &str) -> Option<u32> {
    let (bus, rest) = s.split_once(':')?;
    let (dev, func) = rest.split_once('.')?;
    let (b, d, f) = (u32::from_str_radix(bus, 16).ok()?, u32::from_str_radix(dev, 16).ok()?, u32::from_str_radix(func, 16).ok()?);
    (b < 256 && d < 32 && f < 8).then_some(b << 8 | d << 3 | f)
}

fn main(_info: &'static ProcessInfo) -> i64 {
    let grant = |n| Channel::new(Cap(slots::FIRST_GRANT + n));
    let mut shell = Shell {
        term: terminal::Client::from(grant(0)),
        system: system::Client::from(grant(1)),
        devices: devices::Client::from(grant(2)),
        out: String::new(),
    };
    let _ = shell.term.write("Silica. Type help for the commands.\n");
    loop {
        if shell.term.write("silica> ").is_err() {
            return 1;
        }
        let line = match shell.term.read_line() {
            Ok(r) => String::from(r.line),
            Err(_) => return 1,
        };
        shell.run(&line);
    }
}
