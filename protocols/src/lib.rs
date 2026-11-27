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

/// The machine's hardware watchdog, petted by the service manager.
pub mod watchdog {
    include!(concat!(env!("OUT_DIR"), "/silica_watchdog_device.rs"));
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
    /// `silica.device.Manager`: `list`, `open` and `watch` of the watchdog.
    /// No declaration can name it: the service manager alone holds it, so
    /// nothing else can pet the watchdog of a hung machine.
    pub const DEVICE_WATCHDOG: u64 = 1 << 7;

    /// `silica.block.Partitions`: `list`.
    pub const PARTITIONS_LIST: u64 = 1 << 0;
    /// `silica.block.Partitions`: `open`, of any partition of any disk (a
    /// program that needs one partition is given the block capability
    /// `open` returns, not this).
    pub const PARTITIONS_OPEN: u64 = 1 << 1;

    /// `silica.net.Tcp`: `connect`, to any address and port.
    pub const TCP_CONNECT: u64 = 1 << 0;
    /// `silica.net.Tcp`: the one port a capability names, in these 16 bits
    /// (0: none): the port it may `listen` on (`listen=<port>` in a
    /// declaration), or with [`TCP_PORT_IS_PEER`] the one port of a peer it
    /// may `connect` to (`connect=<port>`). A port is the owner's to give,
    /// never the first claimant's: no holder listens on a port its
    /// capability does not carry, nor connects, without `connect`, to one
    /// it does not.
    const TCP_PORT_SHIFT: u32 = 1;
    /// `silica.net.Tcp`: the port a capability names is a peer's to connect
    /// to, not its own to listen on.
    const TCP_PORT_IS_PEER: u64 = 1 << 17;

    /// The port `badge`'s `silica.net.Tcp` capability names, whichever use.
    const fn tcp_port(badge: u64) -> Option<u16> {
        match (of(badge) >> TCP_PORT_SHIFT) as u16 {
            0 => None,
            port => Some(port),
        }
    }

    /// The port `badge`'s `silica.net.Tcp` capability may listen on.
    pub const fn tcp_listen(badge: u64) -> Option<u16> {
        if of(badge) & TCP_PORT_IS_PEER != 0 { None } else { tcp_port(badge) }
    }

    /// Whether `badge`'s `silica.net.Tcp` capability may connect to a peer's
    /// `port`: any port with `connect`, else only the one `connect=<port>`
    /// names. (Before, `connect` was the only way to connect at all, to any
    /// address and port: a program that needed one service elsewhere
    /// could reach every one; the audit of 2026-11-27, M8.)
    pub const fn tcp_connect(badge: u64, port: u16) -> bool {
        has(badge, TCP_CONNECT) || (of(badge) & TCP_PORT_IS_PEER != 0 && matches!(tcp_port(badge), Some(p) if p == port))
    }

    /// The scopes protocol `protocol` defines, by the names declarations
    /// use; `None` for a protocol without scopes (a capability to it
    /// allows all of it). `silica.net.Tcp` also takes `listen=<port>` or
    /// `connect=<port>`, one port a capability ([`parse`]).
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
            "silica.net.Tcp" => &[("connect", TCP_CONNECT)],
            _ => return None,
        })
    }

    /// The bits of `spec`, a `+`-separated list of scope names of
    /// `protocol`, or the first name it does not define (for
    /// `silica.net.Tcp`, also a `listen=<port>` or `connect=<port>` that is
    /// not one port from 1 to 65535, or a second port of either kind: a
    /// capability names one port).
    pub fn parse<'a>(protocol: &str, spec: &'a str) -> Result<u64, &'a str> {
        let known = names(protocol).unwrap_or(&[]);
        let mut bits = 0;
        for name in spec.split('+') {
            if protocol == "silica.net.Tcp" {
                let (port, peer) = match (name.strip_prefix("listen="), name.strip_prefix("connect=")) {
                    (Some(p), _) => (Some(p), false),
                    (_, Some(p)) => (Some(p), true),
                    _ => (None, false),
                };
                if let Some(port) = port {
                    let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or(name)?;
                    if tcp_port(bits << SHIFT).is_some() {
                        return Err(name);
                    }
                    bits |= (port as u64) << TCP_PORT_SHIFT | if peer { TCP_PORT_IS_PEER } else { 0 };
                    continue;
                }
            }
            bits |= known.iter().find(|(n, _)| *n == name).ok_or(name)?.1;
        }
        Ok(bits)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_tcp_capability_carries_one_port_and_connect_only_when_given() {
            let b = |spec| parse("silica.net.Tcp", spec).map(|s| s << SHIFT);
            assert_eq!(b("listen=22").map(tcp_listen), Ok(Some(22)));
            assert_eq!(b("listen=65535+connect").map(tcp_listen), Ok(Some(65535)));
            assert!(has(b("connect+listen=80").unwrap(), TCP_CONNECT));
            assert!(!has(b("listen=80").unwrap(), TCP_CONNECT));
            assert_eq!(b("connect").map(tcp_listen), Ok(None));
            // Not a port, or a second one: refused by name.
            for bad in ["listen=0", "listen=65536", "listen=", "listen=x", "listen=22+listen=80", "listen"] {
                assert!(parse("silica.net.Tcp", bad).is_err(), "{bad}");
            }
            // The other protocols take no port.
            assert!(parse("silica.system.Manager", "listen=22").is_err());
        }

        /// A capability to connect can name the one peer port it may reach
        /// (`connect=<port>`); it reaches no other, listens on none, and is
        /// one port, not two; `connect` alone still reaches any.
        #[test]
        fn a_tcp_capability_can_connect_to_one_port_only() {
            let b = |spec| parse("silica.net.Tcp", spec).map(|s| s << SHIFT);
            let one = b("connect=443").expect("connect=443 is a scope");
            assert!(tcp_connect(one, 443));
            for other in [80, 444, 22, 1, 65535] {
                assert!(!tcp_connect(one, other), "connect=443 reached port {other}");
            }
            assert_eq!(tcp_listen(one), None, "a peer's port is not one to listen on");
            assert!(!has(one, TCP_CONNECT));
            let any = b("connect").unwrap();
            assert!(tcp_connect(any, 80) && tcp_connect(any, 443));
            let listener = b("listen=443").unwrap();
            assert!(!tcp_connect(listener, 443), "a port to listen on is not one to connect to");
            assert!(tcp_connect(b("connect+listen=22").unwrap(), 9));
            for bad in
                ["connect=0", "connect=65536", "connect=", "connect=443+connect=80", "listen=22+connect=443", "connect=443+listen=22"]
            {
                assert!(parse("silica.net.Tcp", bad).is_err(), "{bad}");
            }
        }
    }
}

/// Lists answered a part at a time (`from` in, `next` out), so a list
/// longer than a message is never refused (`reply_too_large`) to every
/// caller: the service manager's services, the device manager's devices,
/// the block server's partitions and the log's sources (the 2026-11-24
/// audit: one full GPT, some 40 services or 70 log sources were enough). A
/// list that changes between parts may show an item twice or not at all;
/// the next call from 0 sees it as it is.
pub mod paging {
    /// The bytes of items one part holds at most: a reply's 4000 bytes
    /// less its header, the array's length and `next`, with room to spare
    /// for an estimate that is a few bytes short.
    pub const PART_BYTES: usize = 3200;

    /// Give `push` the items from the `from`th on whose encoded sizes, as
    /// `size` estimates them, total no more than [`PART_BYTES`] (always at
    /// least one); returns `next`, the index of the first not given, or 0
    /// when none is left.
    pub fn part<T>(items: impl IntoIterator<Item = T>, from: u32, size: impl Fn(&T) -> usize, mut push: impl FnMut(T)) -> u32 {
        let mut used = 0;
        for (i, item) in items.into_iter().enumerate().skip(from as usize) {
            let n = size(&item);
            if used > 0 && used + n > PART_BYTES {
                return i as u32;
            }
            used += n;
            push(item);
        }
        0
    }

    /// The encoded size of a `string` or `bytes` field of `len` bytes.
    pub const fn text(len: usize) -> usize {
        4 + len
    }

    /// The encoded size of a struct whose fields take `fields` bytes.
    pub const fn record(fields: usize) -> usize {
        4 + fields
    }

    #[cfg(test)]
    mod tests {
        extern crate std;
        use super::*;
        use std::vec::Vec;

        #[test]
        fn parts_cover_a_long_list_once_in_order() {
            let items: Vec<usize> = (0..1000).collect();
            let (mut seen, mut from) = (Vec::new(), 0);
            loop {
                let mut this = Vec::new();
                let next = part(items.iter().copied(), from, |_| 100, |i| this.push(i));
                assert!(!this.is_empty() && this.len() * 100 <= PART_BYTES);
                seen.extend(this);
                if next == 0 {
                    break;
                }
                assert_eq!(next as usize, seen.len());
                from = next;
            }
            assert_eq!(seen, items);
            // Past the end: nothing, and done. One item larger than a part
            // is still given.
            let mut none = Vec::new();
            assert_eq!(part(items.iter().copied(), 5000, |_| 1, |i| none.push(i)), 0);
            assert!(none.is_empty());
            let mut big = Vec::new();
            assert_eq!(part([1, 2], 0, |_| 5000, |i| big.push(i)), 1);
            assert_eq!(big, [1]);
        }
    }
}
