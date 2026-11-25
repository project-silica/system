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
