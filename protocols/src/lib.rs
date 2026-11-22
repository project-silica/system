//! The system's own protocols, generated from `idl/protocols/silica`:
//!
//! - [`device::manager`]: `silica.device.Manager`, how a program finds the
//!   devices of a class that have a running driver and opens one's driver;
//! - [`system::manager`]: `silica.system.Manager`, the services of the
//!   system and the machine's power, provided by the service manager.
//!
//! Each module's reference page is `silica-idlc docs`'s page for the
//! protocol. A program wraps a capability it was granted to a provider as
//! `manager::Client::<Channel, Handle>::from(Channel::new(cap))`.
#![no_std]

/// `silica.device.Manager`.
pub mod device {
    include!(concat!(env!("OUT_DIR"), "/silica_device_manager.rs"));
}

/// `silica.system.Manager`.
pub mod system {
    include!(concat!(env!("OUT_DIR"), "/silica_system_manager.rs"));
}
