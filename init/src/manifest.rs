//! The boot archive's `services` list: what the system runs, as declared
//! by each program's `Cargo.toml` (`[package.metadata.silica.service]`) and
//! collected by the image build. One service per line:
//!
//! ```text
//! <name> [program=<binary>] [memory=<bits>] [provides=<protocol>]
//!        [needs=<protocol>,<protocol>...] [machine] [start=boot|check:<check>]
//!        [restart=always|never] [seed] [keeps] [sets_time] [secrets] [files=<name>,...]
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
//!   (an empty slot where there are none), the boot archive's frames, and
//!   the device and firmware memory, given outright; `args[0]` and `args[1]`
//!   count the last two. The device manager alone; when it ends, the
//!   service manager takes the memory given outright back first, emptied,
//!   for its next start.
//! - `start=boot` runs at every boot; `start=check:<c>` only when the
//!   command line's `checks=` names `c`, and the boot waits for it to end
//!   with status 0.
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
//!   stack's lease, so that it answers on its address at once).
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
    pub sets_time: bool,
    /// It holds secrets: its address space is isolated against speculation.
    pub secrets: bool,
    pub files: Vec<&'static str>,
    pub start: Start,
    pub restart: bool,
    /// Where it runs.
    pub cpu: Cpu,
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
            sets_time: false,
            secrets: false,
            files: Vec::new(),
            start: Start::Boot,
            restart: false,
            cpu: Cpu::Fixed(0),
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
                        s.needs.push(protocol);
                        s.scopes.push(scopes);
                    }
                }
                ("machine", "") => s.machine = true,
                ("seed", "") => s.seed = true,
                ("keeps", "") => s.keeps = true,
                ("sets_time", "") => s.sets_time = true,
                ("secrets", "") => s.secrets = true,
                ("files", f) => s.files = f.split(',').filter(|n| !n.is_empty()).collect(),
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
