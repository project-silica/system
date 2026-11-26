//! A virtio device says where its registers are: the capability list in its
//! PCI configuration space names a BAR, an offset and a length for each of
//! its structures, and its MSI-X capability a BAR and an offset for its
//! table. Every one of those numbers is the device's, and a driver follows
//! them before it has agreed on anything (`Transport::new`,
//! `Device::msix_entry`, `pci::Config`). The fuzzer plays the device: the
//! first 256 bytes of the input are its configuration space, the rest its
//! BAR 0 (up to a page). Given any device:
//!
//! - nothing panics, and nothing is read or written outside the
//!   configuration space or the BAR (`Mmio` panics on an access outside its
//!   range, so a structure accepted where it does not fit is found by using
//!   it, which the target does with every register the transport reads);
//! - the capability list ends: no more capabilities than the space holds,
//!   each inside it;
//! - an MSI-X entry handed out is one of the driver's lines, 16 bytes
//!   inside the BAR;
//! - a device-specific configuration that does not change reads the same
//!   under one generation at the first attempt (`Transport::read_config`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use silica_driver::Device;
use silica_driver::virtio::Transport;
use silica_rt::mmio::Mmio;

/// Memory a device's registers live in, 8-byte aligned.
struct Area(Vec<u64>);

impl Area {
    fn of(bytes: &[u8], len: usize) -> Area {
        let mut words = vec![0u64; len.div_ceil(8)];
        for (i, b) in bytes.iter().take(len).enumerate() {
            words[i / 8] |= (*b as u64) << (8 * (i % 8));
        }
        Area(words)
    }
    fn mmio(&self, len: usize) -> Mmio {
        // SAFETY: this value's own heap memory, holding no Rust object but
        // the integers it was made of, alive until the end of the input
        // (everything made over it is dropped first).
        unsafe { Mmio::new(self.0.as_ptr() as usize, len) }
    }
}

const CONFIG_BYTES: usize = 256;
const BAR_BYTES: usize = 4096;
/// The interrupt lines the driver was given.
const LINES: u32 = 4;

fuzz_target!(|data: &[u8]| {
    let (config_bytes, bar_bytes) = data.split_at(data.len().min(CONFIG_BYTES));
    let config = Area::of(config_bytes, CONFIG_BYTES);
    // A BAR as long as the device made it, a multiple of 8 bytes; none at
    // all for a device that gave only its configuration space.
    let bar_len = bar_bytes.len().min(BAR_BYTES) & !7;
    let bar = Area::of(bar_bytes, bar_len);
    let mut bars = [None; 6];
    if bar_len != 0 {
        bars[0] = Some(bar.mmio(bar_len));
    }
    let device = Device::over(config.mmio(CONFIG_BYTES), bars, LINES);

    // The configuration space itself.
    let c = device.config();
    let _ = (c.vendor(), c.device(), c.class(), c.header(), c.multifunction(), c.secondary_bus());
    let mut seen = 0;
    for (_, at) in c.capabilities() {
        assert!((0x40..=0xFC).contains(&at), "a capability outside configuration space");
        seen += 1;
        assert!(seen <= 48, "a capability list that does not end");
    }
    for index in 0..7 {
        let _ = c.bar_address(index);
    }

    // The MSI-X table: an entry handed out is a line of the driver's and 16
    // bytes of the BAR, which are then read and written as binding one does.
    let msix = c.msix();
    for index in [0u16, 1, LINES as u16 - 1, LINES as u16, 0x7FF] {
        match device.msix_entry(index) {
            Ok((line, entry)) => {
                assert!(line < LINES && index < msix.expect("an entry of a table the device does not have").vectors);
                entry.write32(12, 1);
                entry.write32(0, 0xFEE0_0000);
                entry.write32(8, line);
                assert_eq!(entry.read32(12), 1);
            }
            // No such entry, no such line, or a table the BAR does not hold.
            Err(_) => {}
        }
    }
    let vector = Transport::config_vector(&device, 1);
    assert!(vector <= 1);

    // The transport: every register it reads, wherever the device put it.
    let Ok(t) = Transport::new(&device) else { return };
    let _ = (t.status(), t.needs_reset(), t.queues());
    let generation = t.config_generation();
    fn sum(s: Mmio) -> u64 {
        (0..s.len()).map(|i| s.read8(i) as u64).sum()
    }
    let specific = t.read_config(|| t.device_config().map(sum));
    assert_eq!(specific.ok(), Some(t.device_config().map(sum)), "a configuration that does not change did not read at once");
    assert_eq!(t.config_generation(), generation);
    // Memory holds what is written: the vector reads back, the device is
    // marked failed.
    assert!(t.config_interrupt(vector).is_ok());
    t.fail();
    assert!(t.status() & 0x80 != 0);
});
