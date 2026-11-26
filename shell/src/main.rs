//! The shell (component D20): reads a command a line at a time from the
//! console and runs it. Its commands look at and steer the system through
//! the service manager and the device manager:
//!
//! - `services`: every service, what it does, how often it failed;
//! - `stop <service>`, `start <service>`, `restart <service>` (ended at once
//!   and started again, its clients carrying on);
//! - `devices`: the devices with a running driver, by class;
//! - `restart-driver <device>`: end a device's driver and start it again;
//! - `caps <service>` or `caps <device>`: what a running service, or a
//!   device's driver, holds and what its threads do;
//! - `log <service>`: what a service printed (the last 32 KiB);
//! - `trace`: one read of the first partition's block 0, traced through the
//!   block server, the client and the driver;
//! - `shutdown`, `reboot`;
//! - `echo <text>`, `help`.
//!
//! Typed pipelines between programs (component D20's other half) come later.
#![no_std]
#![no_main]

use core::fmt::Write;
use silica_idl_rt::{CallError, TransportError};
use silica_protocols::console::terminal;
use silica_protocols::device::{PciAddress, manager as devices};
use silica_protocols::log::reader as log;
use silica_protocols::system::manager as system;
use silica_rt::alloc::format;
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
    log: log::Client<Channel, Handle>,
    out: String,
}

const HELP: &str = "commands: services, stop <service>, start <service>, restart <service>, caps <service|device>, log <service>, trace, devices, restart-driver <device>, shutdown, reboot, date, echo <text>, help\n";

impl Shell {
    fn say(&mut self) -> Result<(), CallError<core::convert::Infallible>> {
        let result = self.term.write_all(&self.out);
        self.out.clear();
        result
    }

    fn run(&mut self, line: &str) -> Result<(), CallError<core::convert::Infallible>> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(&command) = words.first() else { return Ok(()) };
        let arg = words.get(1).copied().unwrap_or("");
        match command {
            "help" => self.out.push_str(HELP),
            "date" => match silica_rt::time::now() {
                Some(w) => {
                    let from = match w.source {
                        silica_rt::time::Source::Network => "a time server",
                        _ => "the firmware's clock",
                    };
                    let _ = writeln!(self.out, "{} (from {from})", silica_rt::time::Civil::from_unix(w.ns / 1_000_000_000));
                }
                None => self.out.push_str("date: the wall clock is not known\n"),
            },
            "echo" => {
                let _ = writeln!(self.out, "{}", line.trim_start().strip_prefix("echo").unwrap_or("").trim());
            }
            "services" => {
                // Part after part, as the service manager gives them.
                let mut from = 0;
                loop {
                    match self.system.list(from) {
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
                            if r.next <= from {
                                break;
                            }
                            from = r.next;
                        }
                        Err(e) => {
                            let _ = writeln!(self.out, "services: {e:?}");
                            break;
                        }
                    }
                }
            }
            "stop" | "start" | "restart" if !arg.is_empty() => {
                let r = match command {
                    "stop" => self.system.stop(arg).map(|_| ()),
                    "start" => self.system.start(arg).map(|_| ()),
                    _ => self.system.restart(arg).map(|_| ()),
                };
                match r {
                    Ok(()) => {
                        let _ = writeln!(self.out, "{command}: {arg}: done");
                    }
                    Err(e) => {
                        let _ = writeln!(self.out, "{command}: {arg}: {e:?}");
                    }
                }
            }
            "caps" if !arg.is_empty() => {
                // A device (its address, or its driver's log name,
                // devmgr/<driver>@<address>) is the device manager's to
                // describe; any other name is a service's. The report comes
                // part by part; each part is written out before the next is
                // asked for.
                let device = arg.rsplit_once('@').map_or(arg, |(_, a)| a).parse::<PciAddress>().ok();
                let mut from = 0;
                loop {
                    let part = match device {
                        Some(id) => self.devices.describe(id.0, from).map(|r| (String::from(r.text), r.next)).map_err(|e| format!("{e:?}")),
                        None => self.system.describe(arg, from).map(|r| (String::from(r.text), r.next)).map_err(|e| format!("{e:?}")),
                    };
                    match part {
                        Ok((text, next)) => {
                            self.out.push_str(&text);
                            self.say()?;
                            if next == 0 {
                                break;
                            }
                            from = next;
                        }
                        Err(e) => {
                            let _ = writeln!(self.out, "caps: {arg}: {e}");
                            break;
                        }
                    }
                }
            }
            "log" if !arg.is_empty() => {
                // Stop at the writer's current position. In particular,
                // displaying the console's own log writes more of that log.
                let mut part = 0;
                let end = loop {
                    match self.log.sources(part) {
                        Ok(r) => {
                            let found = r.sources.iter().find(|s| s.name == arg).map(|s| s.written);
                            if found.is_some() || r.next <= part {
                                break found;
                            }
                            part = r.next;
                        }
                        Err(e) => {
                            let _ = writeln!(self.out, "log: {arg}: {e:?}");
                            return self.say();
                        }
                    }
                };
                let Some(end) = end else {
                    let _ = writeln!(self.out, "log: {arg}: no such log source");
                    return self.say();
                };
                let (mut from, mut fresh) = (0, true);
                while from < end {
                    match self.log.read(arg, from) {
                        Ok(r) if !r.text.is_empty() => {
                            // read can start later than requested after eviction.
                            let start = r.next.saturating_sub(r.text.len() as u64);
                            let len = end.saturating_sub(start).min(r.text.len() as u64) as usize;
                            for c in r.text[..r.text.floor_char_boundary(len)].chars() {
                                if fresh {
                                    self.out.push_str("  ");
                                }
                                self.out.push(c);
                                fresh = c == '\n';
                            }
                            from = r.next;
                            self.say()?;
                        }
                        Ok(_) => break,
                        Err(e) => {
                            let _ = writeln!(self.out, "log: {arg}: {e:?}");
                            break;
                        }
                    }
                }
            }
            "trace" => {
                if let Err(e) = self.trace() {
                    let _ = writeln!(self.out, "trace: {e}");
                }
            }
            "devices" => {
                for (class, name) in [
                    (devices::Class::Block, "block"),
                    (devices::Class::Network, "network"),
                    (devices::Class::Display, "display"),
                    (devices::Class::Input, "input"),
                    (devices::Class::Entropy, "entropy"),
                    (devices::Class::Port, "port"),
                ] {
                    let mut from = 0;
                    while let Ok(r) = self.devices.list(class, from) {
                        for d in r.devices.iter() {
                            let _ = writeln!(self.out, "  {} {name:<8} {}", PciAddress(d.id), d.driver);
                        }
                        if r.next <= from {
                            break;
                        }
                        from = r.next;
                    }
                }
            }
            "restart-driver" if !arg.is_empty() => match arg.parse::<PciAddress>().ok().map(|id| self.devices.restart(id.0)) {
                Some(Ok(_)) => {
                    let _ = writeln!(self.out, "restart-driver: {arg}: done");
                }
                Some(Err(e)) => {
                    let _ = writeln!(self.out, "restart-driver: {arg}: {e:?}");
                }
                None => self.out.push_str("restart-driver: name a device as [segment:]bus:device.function\n"),
            },
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
        self.say()
    }
}

impl Shell {
    /// Read block 0 of the first partition with a traced request (its tag's
    /// bit 62 set), and say where it went: opened through the block server,
    /// taken, accepted and finished by the disk's driver, seen by this client.
    fn trace(&mut self) -> Result<(), &'static str> {
        let server = Cap(slots::FIRST_GRANT + 4);
        let mut parts = silica_block::partitions::Client::<Channel, Handle>::from(Channel::new(server));
        let listed = parts.list(0).map_err(|_| "the block server does not answer")?;
        let p = listed.partitions.iter().next().ok_or("the block server lists no partition")?;
        let (id, name) = (p.id, String::from(p.name));
        let clock = silica_rt::clock();
        let opening = clock.now();
        let mut disk = silica_block::client::Disk::open_partition(server, id).map_err(|_| "the partition cannot be opened")?;
        let opened = clock.now();
        let memory = silica_rt::mem::Memory::new(12).map_err(|_| "no memory")?;
        disk.add_memory(0, &memory, true).map_err(|_| "the driver takes no memory")?;
        let tag = silica_block::service::TRACED | 1;
        let r = silica_block::Request { op: silica_block::Op::Read, memory: 0, block: 0, offset: 0, blocks: 1, tag };
        let t0 = clock.now();
        disk.submit(&r).map_err(|_| "the request cannot be sent")?;
        disk.kick();
        let c = disk.wait(Some(t0 + 5_000_000_000)).map_err(|_| "no answer within 5 s")?;
        let seen = clock.now();
        c.status.map_err(|_| "the read failed")?;
        let (taken, started, done) = disk.trace(tag).map_err(|_| "the driver kept no trace of it")?;
        let at = |t: u64| t.saturating_sub(t0);
        let _ = writeln!(self.out, "  partition {id:#x} ({name}) opened through the block server in {} ns", opened - opening);
        let _ = writeln!(self.out, "  block 0: sent by this client      0 ns");
        let _ = writeln!(self.out, "           taken by the driver      {} ns", at(taken));
        let _ = writeln!(self.out, "           accepted by the device   {} ns", at(started));
        let _ = writeln!(self.out, "           finished                 {} ns", at(done));
        let _ = writeln!(self.out, "           seen by this client      {} ns", at(seen));
        Ok(())
    }
}

fn main(_info: &'static ProcessInfo) -> i64 {
    let grant = |n| Channel::new(Cap(slots::FIRST_GRANT + n));
    let mut shell = Shell {
        term: terminal::Client::from(grant(0)),
        system: system::Client::from(grant(1)),
        devices: devices::Client::from(grant(2)),
        log: log::Client::from(grant(3)),
        out: String::new(),
    };
    let _ = shell.term.write("Silica. Type help for the commands.\n");
    'prompt: loop {
        // The console restarted under a call (`peer_gone`): its endpoint is
        // the service manager's, so calling again reaches the new one, and
        // the prompt is shown again on its fresh screen.
        match shell.term.write("silica> ") {
            Ok(_) | Err(CallError::Transport(TransportError::PeerGone)) => {}
            Err(_) => return 1,
        }
        let line = match shell.term.read_line() {
            Ok(r) if !r.busy => String::from(r.line),
            // The console keeps one waiting read a holder and answers
            // them in turn, so busy means it had no place to keep this
            // one: said, and the shell ends to be started again.
            Ok(_) => {
                silica_rt::println!("shell: the console could not keep a read waiting");
                return 1;
            }
            Err(CallError::Transport(TransportError::PeerGone)) => continue 'prompt,
            Err(_) => return 1,
        };
        match shell.run(&line) {
            Ok(()) | Err(CallError::Transport(TransportError::PeerGone)) => {}
            Err(e) => {
                silica_rt::println!("shell: console output failed: {e:?}");
                return 1;
            }
        }
    }
}
