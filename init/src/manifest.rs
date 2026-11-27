//! The boot archive's `services` list: what the system runs, as declared
//! by each program's `Cargo.toml` (`[package.metadata.silica.service]`) and
//! collected by the image build. One service per line:
//!
//! ```text
//! <name> [program=<binary>] [memory=<bits>] [provides=<protocol>]
//!        [needs=<protocol>,<protocol>...] [machine] [start=boot|check:<check>]
//!        [restart=always|never] [seed] [keeps] [ends] [sets_time] [secrets] [files=<name>,...]
//!        [logs=<n>] [controls=<service>,...|*]
//! ```
//!
//! - `provides`: the protocol it serves; the service manager makes its
//!   endpoint and keeps it across restarts, so a client's capability to it
//!   outlives the service's instances. It is the service's first grant.
//! - `needs`: protocols it calls, each a grant in that order, after its own
//!   endpoint if it has one (a capability to the provider's endpoint,
//!   badged for this service, from 2^32 up). `silica.system.Manager` is the
//!   service manager's own. A protocol with scopes
//!   (`silica_protocols::scope`) is needed as `<protocol>:<scope>+<scope>`:
//!   what of it the service may call, carried in the capability's badge.
//! - `machine`: it is given the machine, as grants after those: its
//!   description, the device authority, the interrupt lines, the I/O ports
//!   (an empty slot where there are none), a capability that signals the
//!   service manager's watchdog notification, the boot archive's frames, and
//!   the device and firmware memory, given outright; `args[0]` and `args[1]`
//!   count the last two. The device manager alone; when it ends, the
//!   service manager takes the memory given outright back first, emptied,
//!   for its next start.
//! - `start=boot` runs at every boot; `start=check:<c>` only in a test
//!   image, when its command line's `checks=` names `c`, and the boot
//!   waits for it to end with status 0.
//! - `cpu=<n>`: it runs on processor `n` (a machine without one runs it on
//!   processor 0, and says so); `cpu=any`: the service manager chooses, spreading
//!   such services over the processors after the first. Without the word it runs
//!   on processor 0, where every service ran before declarations said where.
//! - `restart=always`: started again when it fails (`silica_proc::Restarts`:
//!   at once the first time, then backing off to a try a minute; never given
//!   up on for good).
//! - `seed`: it is given a secret of its own for every start, derived from
//!   the boot's entropy (`silica_proc::seed` over its name and the start):
//!   `args[4..8]`, with `args[3]` saying which trusted sources went into
//!   the boot's (`RootInfo::entropy_sources`; 0: timing jitter alone). The
//!   entropy service is seeded so.
//! - `keeps`: it is given a page of 4 KiB (`slots::KEEP`), zeroed at boot,
//!   that the service manager keeps across its restarts: what a service
//!   started again needs to pick up where the last one was (the network
//!   stack's lease, so that it answers on its address at once). When its
//!   program is replaced (`update`, `revert`) the page starts empty, and
//!   the old one is the new program's last grant, read-only, for its first
//!   instance: another program's bytes (the network stack takes from it the
//!   connections to reset, and nothing else).
//! - `ends`: it has something to finish before it is let go of (the device
//!   manager: its disks' caches; the log service: the text still in the
//!   rings). When the machine is turned off it is asked to end
//!   (`silica_rt::END` on its events notification) and its exit, which the
//!   kernel delivers, is waited for; one that never exits is ended where
//!   it stands after a while, and said to have failed to end. Every other
//!   service is ended at once, last started first. A service stopped,
//!   restarted, updated or reverted while the machine runs is ended at
//!   once, whatever it declares.
//! - `sets_time`: its time page (`slots::TIME`, which every service can
//!   read) is writable: it may set the wall clock (the network stack's
//!   time-server client).
//! - `secrets`: it holds keys or other secrets: its address space is
//!   isolated against speculative execution (`libsys::ASPACE_ISOLATED`), so
//!   no other program can train predictors against it or read through them.
//! - `files=<name>,<name>...`: files of the boot archive it is given, each
//!   read-only in a frame of its own (the smallest power of two that holds
//!   it, at least a page, zeros after it), as grants after its needs, in
//!   that order; a file the archive lacks is an empty slot, and the log
//!   says so. How an image gives a service what was provisioned for that
//!   machine: the remote management service's key and its owners.
//! - `logs=<n>`: it may give `n` programs of its own a log each
//!   (`silica.system.Manager`'s `add_log`, with the `logs` scope): the
//!   device manager, one per device it starts a driver for. Those places
//!   are its own; without the word it has none, and past `n` it is
//!   refused.
//! - `controls=<service>,<service>...`: the services its
//!   `silica.system.Manager` `control` (start, stop, restart) and `update`
//!   (update, revert) reach; `*` names every service that is neither the
//!   machine's (`machine`) nor holding secrets (`secrets`), which only
//!   their own names reach. A service given either scope names them, or
//!   the list is refused. A `machine` service is never updated or
//!   reverted, whoever names it: no program a caller sends is given the
//!   machine.

use silica_rt::alloc::vec::Vec;

/// The protocol the service manager itself provides: a service that needs
/// it is given a capability to the root task.
pub const ROOT_PROTOCOL: &str = "silica.system.Manager";

/// When a service runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Boot,
    Check(&'static str),
}

/// Where a service runs (`cpu=`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cpu {
    Fixed(u32),
    Any,
}

/// One declared service.
#[derive(Clone, Debug)]
pub struct Service {
    pub name: &'static str,
    pub program: &'static str,
    pub memory: u8,
    pub provides: Option<&'static str>,
    pub needs: Vec<&'static str>,
    /// For each need, the scopes its capability carries (`silica_protocols::scope`).
    pub scopes: Vec<u64>,
    pub machine: bool,
    pub seed: bool,
    pub keeps: bool,
    pub ends: bool,
    pub sets_time: bool,
    /// It holds secrets: its address space is isolated against speculation.
    pub secrets: bool,
    pub files: Vec<&'static str>,
    /// How many logs it may give its programs (`logs=`).
    pub logs: u32,
    pub start: Start,
    pub restart: bool,
    /// Where it runs.
    pub cpu: Cpu,
    /// The services its `silica.system.Manager` `control` and `update`
    /// reach (`controls=`): names, and `*` for every service that is
    /// neither the machine's (`machine`) nor holding secrets (`secrets`).
    /// None: they reach no service.
    pub controls: Option<&'static str>,
}

/// The services the list declares, or what is wrong with a line.
pub fn parse(text: &'static str) -> Result<Vec<Service>, &'static str> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut words = line.split_ascii_whitespace();
        let name = words.next().ok_or("a service line without a name")?;
        let mut s = Service {
            name,
            program: name,
            memory: 22,
            provides: None,
            needs: Vec::new(),
            scopes: Vec::new(),
            machine: false,
            seed: false,
            keeps: false,
            ends: false,
            sets_time: false,
            secrets: false,
            files: Vec::new(),
            logs: 0,
            start: Start::Boot,
            restart: false,
            cpu: Cpu::Fixed(0),
            controls: None,
        };
        for w in words {
            let (key, value) = w.split_once('=').unwrap_or((w, ""));
            match (key, value) {
                ("program", p) if !p.is_empty() => s.program = p,
                ("memory", m) => {
                    s.memory = m.parse().ok().filter(|b| (20..=40).contains(b)).ok_or("a service's memory is not 20 to 40 bits")?
                }
                ("provides", p) if !p.is_empty() => s.provides = Some(p),
                ("needs", n) => {
                    for need in n.split(',').filter(|p| !p.is_empty()) {
                        let (protocol, spec) = need.split_once(':').unwrap_or((need, ""));
                        let scopes = match (silica_protocols::scope::names(protocol), spec) {
                            (None, "") => 0,
                            (None, _) => return Err("a need gives scopes to a protocol that has none"),
                            (Some(_), "") => {
                                return Err("a need of a protocol with scopes does not say which (`<protocol>:<scope>+<scope>`)");
                            }
                            (Some(_), spec) => silica_protocols::scope::parse(protocol, spec)
                                .map_err(|_| "a need names a scope its protocol does not have")?,
                        };
                        // A need's restart is bit n of the events notification,
                        // below `silica_rt::END`.
                        if s.needs.len() == 31 {
                            return Err("a service needs more than 31 protocols");
                        }
                        s.needs.push(protocol);
                        s.scopes.push(scopes);
                    }
                }
                ("machine", "") => s.machine = true,
                ("seed", "") => s.seed = true,
                ("keeps", "") => s.keeps = true,
                ("ends", "") => s.ends = true,
                ("sets_time", "") => s.sets_time = true,
                ("secrets", "") => s.secrets = true,
                ("controls", c) if !c.is_empty() => s.controls = Some(c),
                ("files", f) => s.files = f.split(',').filter(|n| !n.is_empty()).collect(),
                ("logs", n) => s.logs = n.parse().ok().filter(|n| *n <= 64).ok_or("a service's logs is not a number up to 64")?,
                ("start", "boot") => s.start = Start::Boot,
                ("start", c) if c.starts_with("check:") => s.start = Start::Check(&c[6..]),
                ("restart", "always") => s.restart = true,
                ("restart", "never") => s.restart = false,
                ("cpu", "any") => s.cpu = Cpu::Any,
                ("cpu", n) => s.cpu = Cpu::Fixed(n.parse().map_err(|_| "a service's cpu is not a processor number or `any`")?),
                _ => return Err("a service line has a word the service manager does not know"),
            }
        }
        if out.iter().any(|o: &Service| o.name == s.name) {
            return Err("two services have one name");
        }
        // Each has a bit of the service manager's notification to say it
        // serves after an update (bit 0 is the watchdog's).
        if out.len() == 63 {
            return Err("more than 63 services");
        }
        out.push(s);
    }
    // Every protocol needed has a provider, and none is provided twice.
    for s in &out {
        for n in &s.needs {
            if *n != ROOT_PROTOCOL && !out.iter().any(|p| p.provides == Some(*n)) {
                return Err("a service needs a protocol no service provides");
            }
        }
        if let Some(p) = s.provides
            && out.iter().filter(|o| o.provides == Some(p)).count() > 1
        {
            return Err("two services provide one protocol");
        }
    }
    // Authority over other services names them: a service whose service
    // manager capability may control or update says which services
    // (`controls=`), and each name is a service here. (Before, those scopes
    // reached every service by name, the machine's among them, and an
    // `update` gave a program of the caller's choosing the target's grants:
    // the audit's M1.)
    for s in &out {
        let reaching = silica_protocols::scope::SYSTEM_CONTROL | silica_protocols::scope::SYSTEM_UPDATE;
        let manager = s.needs.iter().zip(&s.scopes).filter(|(n, _)| **n == ROOT_PROTOCOL).fold(0, |a, (_, b)| a | b);
        if manager & reaching != 0 && s.controls.is_none() {
            return Err("a service that may control or update services does not name them (`controls=`)");
        }
        if let Some(c) = s.controls
            && c.split(',').any(|n| n != "*" && !out.iter().any(|o| o.name == n))
        {
            return Err("a service's `controls=` names a service that is not declared");
        }
    }
    // A TCP port is given to one service: the second declaration that names
    // it is the owner's mistake, said here, not a race the first to listen
    // wins at run time.
    let port = |s: &Service| {
        s.needs
            .iter()
            .zip(&s.scopes)
            .filter(|(n, _)| **n == "silica.net.Tcp")
            .find_map(|(_, b)| silica_protocols::scope::tcp_listen(b << silica_protocols::scope::SHIFT))
    };
    for (i, s) in out.iter().enumerate() {
        if let Some(p) = port(s)
            && out[..i].iter().any(|o| port(o) == Some(p))
        {
            return Err("two services are given one TCP port to listen on");
        }
    }
    Ok(out)
}

/// The order to start `services` in: providers before what needs them.
/// `Err` when the needs go round in a circle.
pub fn order(services: &[Service]) -> Result<Vec<usize>, &'static str> {
    let mut done = Vec::new();
    while done.len() < services.len() {
        let before = done.len();
        for (i, s) in services.iter().enumerate() {
            if done.contains(&i) {
                continue;
            }
            let ready = s
                .needs
                .iter()
                .all(|n| *n == ROOT_PROTOCOL || services.iter().enumerate().any(|(j, p)| p.provides == Some(*n) && done.contains(&j)));
            if ready {
                done.push(i);
            }
        }
        if done.len() == before {
            return Err("services need each other in a circle");
        }
    }
    Ok(done)
}
