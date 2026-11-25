//! The system's own protocols, generated from `idl/protocols/silica`:
//!
//! - [`device::manager`]: `silica.device.Manager`, how a program finds the
//!   devices of a class that have a running driver and opens one's driver;
//! - [`system::manager`]: `silica.system.Manager`, the services of the
//!   system and the machine's power, provided by the service manager;
//! - [`input::device`]: `silica.input.Device`, the input device class;
//! - [`display::device`]: `silica.display.Device`, the display device
//!   class;
//! - [`console::terminal`]: `silica.console.Terminal`, the local console;
//! - [`console::port`]: `silica.console.Port`, the class of console ports;
//! - [`log::reader`]: `silica.log.Reader`, the system's log, read;
//! - [`entropy::device`]: `silica.entropy.Device`, the class of devices
//!   that produce random bits;
//! - [`entropy::source`]: `silica.entropy.Source`, the entropy service;
//! - [`net::tcp`]: `silica.net.Tcp`, TCP connections, provided by the
//!   network stack;
//! - [`remote::session`]: `silica.remote.Session`, the remote management
//!   session, which carries the others to another machine.
//!
//! Each module's reference page is `silica-idlc docs`'s page for the
//! protocol. A program wraps a capability it was granted to a provider as
//! `manager::Client::<Channel, Handle>::from(Channel::new(cap))`.
#![no_std]

/// `silica.device.Manager`.
pub mod device {
    include!(concat!(env!("OUT_DIR"), "/silica_device_manager.rs"));
    mod address;
    pub use address::PciAddress;
}

/// `silica.system.Manager`.
pub mod system {
    include!(concat!(env!("OUT_DIR"), "/silica_system_manager.rs"));
}

/// `silica.input.Device`.
pub mod input {
    include!(concat!(env!("OUT_DIR"), "/silica_input_device.rs"));
}

/// `silica.display.Device`.
pub mod display {
    include!(concat!(env!("OUT_DIR"), "/silica_display_device.rs"));
}

/// `silica.console.Terminal` and `silica.console.Port`.
pub mod console {
    include!(concat!(env!("OUT_DIR"), "/silica_console_terminal.rs"));
    include!(concat!(env!("OUT_DIR"), "/silica_console_port.rs"));
    mod output;
}

/// `silica.log.Reader`.
pub mod log {
    include!(concat!(env!("OUT_DIR"), "/silica_log_reader.rs"));
}

/// `silica.entropy.Device` and `silica.entropy.Source`.
pub mod entropy {
    include!(concat!(env!("OUT_DIR"), "/silica_entropy_device.rs"));
    include!(concat!(env!("OUT_DIR"), "/silica_entropy_source.rs"));
}

/// `silica.net.Tcp`.
pub mod net {
    include!(concat!(env!("OUT_DIR"), "/silica_net_tcp.rs"));
}

/// `silica.remote.Session`.
pub mod remote {
    include!(concat!(env!("OUT_DIR"), "/silica_remote_session.rs"));
}

/// What a service's capability to a provider lets it do. A declaration
/// says it for each protocol it needs, `needs=<protocol>:<scope>+<scope>`
/// (a protocol listed below must be given at least one), and the service
/// manager puts those bits in the badge of the capability it hands out
/// (from [`scope::SHIFT`] up, beside the consumer's number). The provider
/// reads them from the badge of each call and refuses a method the
/// caller's capability was not given for: the endpoint is the protocol,
/// the scope is how much of it. (Before, every holder of an endpoint could
/// call every method: the device manager, which parses hostile device
/// data, could replace any service's program.)
pub mod scope {
    /// The scopes' first bit in a consumer's badge, and how many there are.
    pub const SHIFT: u32 = 40;
    const COUNT: u32 = 22;

    /// The scopes in a caller's `badge`.
    pub const fn of(badge: u64) -> u64 {
        (badge >> SHIFT) & ((1 << COUNT) - 1)
    }

    /// Whether `badge` carries every scope in `want`.
    pub const fn has(badge: u64, want: u64) -> bool {
        of(badge) & want == want
    }

    /// `silica.system.Manager`: `list`, `describe` and `memory`.
    pub const SYSTEM_OBSERVE: u64 = 1 << 0;
    /// `silica.system.Manager`: `start`, `stop` and `restart`.
    pub const SYSTEM_CONTROL: u64 = 1 << 1;
    /// `silica.system.Manager`: `stage`, `update` and `revert`.
    pub const SYSTEM_UPDATE: u64 = 1 << 2;
    /// `silica.system.Manager`: `shutdown`.
    pub const SYSTEM_POWER: u64 = 1 << 3;
    /// `silica.system.Manager`: `add_log`.
    pub const SYSTEM_LOGS: u64 = 1 << 4;

    /// `silica.device.Manager`: `list`, `open` and `watch` of one class.
    pub const DEVICE_BLOCK: u64 = 1 << 0;
    pub const DEVICE_NETWORK: u64 = 1 << 1;
    pub const DEVICE_DISPLAY: u64 = 1 << 2;
    pub const DEVICE_PORT: u64 = 1 << 3;
    pub const DEVICE_INPUT: u64 = 1 << 4;
    pub const DEVICE_ENTROPY: u64 = 1 << 5;
    /// `silica.device.Manager`: `restart` and `describe` of any device.
    pub const DEVICE_CONTROL: u64 = 1 << 6;

    /// `silica.block.Partitions`: `list`.
    pub const PARTITIONS_LIST: u64 = 1 << 0;
    /// `silica.block.Partitions`: `open`, of any partition of any disk (a
    /// program that needs one partition is given the block capability
    /// `open` returns, not this).
    pub const PARTITIONS_OPEN: u64 = 1 << 1;

    /// The scopes protocol `protocol` defines, by the names declarations
    /// use; `None` for a protocol without scopes (a capability to it
    /// allows all of it).
    pub fn names(protocol: &str) -> Option<&'static [(&'static str, u64)]> {
        Some(match protocol {
            "silica.system.Manager" => &[
                ("observe", SYSTEM_OBSERVE),
                ("control", SYSTEM_CONTROL),
                ("update", SYSTEM_UPDATE),
                ("power", SYSTEM_POWER),
                ("logs", SYSTEM_LOGS),
            ],
            "silica.device.Manager" => &[
                ("block", DEVICE_BLOCK),
                ("network", DEVICE_NETWORK),
                ("display", DEVICE_DISPLAY),
                ("port", DEVICE_PORT),
                ("input", DEVICE_INPUT),
                ("entropy", DEVICE_ENTROPY),
                ("control", DEVICE_CONTROL),
            ],
            "silica.block.Partitions" => &[("list", PARTITIONS_LIST), ("open", PARTITIONS_OPEN)],
            _ => return None,
        })
    }

    /// The bits of `spec`, a `+`-separated list of scope names of
    /// `protocol`, or the first name it does not define.
    pub fn parse<'a>(protocol: &str, spec: &'a str) -> Result<u64, &'a str> {
        let known = names(protocol).unwrap_or(&[]);
        let mut bits = 0;
        for name in spec.split('+') {
            bits |= known.iter().find(|(n, _)| *n == name).ok_or(name)?.1;
        }
        Ok(bits)
    }
}
