//! A PCI function's configuration space is written by the device: its IDs,
//! BARs, capability list, MSI-X table location, a bridge's windows and a
//! hot-plug port's slot registers. The device manager reads it to find
//! devices, place their BARs and arm hot-plug ports, and a driver reads it
//! to find its MSI-X table and its virtio structures. The device manager
//! cannot be restarted, so nothing a device writes there may panic it.
//! Given any two functions' configuration spaces (a port, and a device
//! arriving behind it):
//!
//! - nothing panics or reads outside a function's 4 KiB or a BAR;
//! - the capability list ends, at no more than 48 entries, every one at a
//!   dword-aligned offset in 0x40..=0xFC, whatever loops it makes;
//! - a BAR the device manager places lies inside one of the port's windows
//!   (a 32-bit BAR below 4 GiB), at a multiple of its size;
//! - an MSI-X entry a driver is given lies inside the BAR that holds the
//!   table;
//! - a virtio transport found through the capabilities has registers inside
//!   the device's BARs.
//!
//! Input: 256 bytes of the port's configuration space, then 256 of the
//! device's (the rest of each 4 KiB reads as zeros), each shorter input
//! padded with zeros.
#![no_main]

use devmgr::hotplug::Port;
use libfuzzer_sys::fuzz_target;
use silica_driver::Device;
use silica_driver::pci::Config;
use silica_driver::virtio::Transport;
use silica_rt::mmio::Mmio;

/// Memory a function's registers live in, 8-byte aligned.
struct Area(Vec<u64>);

impl Area {
    fn new(bytes: usize) -> Area {
        Area(vec![0; bytes.div_ceil(8)])
    }
    fn filled(bytes: usize, from: &[u8]) -> Area {
        let a = Area::new(bytes);
        let n = from.len().min(bytes);
        // SAFETY: `n` bytes of the area's own memory, which holds integers only.
        unsafe { core::ptr::copy_nonoverlapping(from.as_ptr(), a.0.as_ptr() as *mut u8, n) };
        a
    }
    fn mmio(&self) -> Mmio {
        // SAFETY: this value's own heap memory, holding no Rust object but
        // integers, alive until the end of the input, after every user.
        unsafe { Mmio::new(self.0.as_ptr() as usize, self.0.len() * 8) }
    }
    fn range(&self) -> core::ops::Range<usize> {
        let at = self.0.as_ptr() as usize;
        at..at + self.0.len() * 8
    }
}

fn inside(m: Mmio, r: &core::ops::Range<usize>) -> bool {
    m.addr() >= r.start && m.addr() + m.len() <= r.end
}

fuzz_target!(|data: &[u8]| {
    let (port_bytes, device_bytes) = data.split_at(data.len().min(256));
    let port_space = Area::filled(4096, port_bytes);
    let device_space = Area::filled(4096, device_bytes);
    let bars: Vec<Area> = (0..6).map(|_| Area::new(16 * 1024)).collect();

    for space in [&port_space, &device_space] {
        let c = Config::new(space.mmio());
        let _ = (c.vendor(), c.device(), c.class(), c.header(), c.multifunction(), c.secondary_bus());
        let caps: Vec<(u8, usize)> = c.capabilities().collect();
        assert!(caps.len() <= 48, "a capability list that does not end");
        assert!(caps.iter().all(|&(_, at)| (0x40..=0xFC).contains(&at) && at % 4 == 0), "a capability outside the list's range");
        if let Some(m) = c.msix() {
            assert!(m.vectors >= 1 && m.vectors <= 2048 && m.bar < 8);
        }
        for i in 0..8 {
            let _ = c.bar_address(i);
        }

        // A driver for this function: its MSI-X entries and its virtio structures.
        let device = Device::over(space.mmio(), core::array::from_fn(|i| Some(bars[i].mmio())), 8);
        if let Some(m) = device.config().msix() {
            for index in 0..m.vectors.min(9) {
                if let Ok((_, entry)) = device.msix_entry(index) {
                    assert!(entry.len() == 16 && bars.iter().any(|b| inside(entry, &b.range())), "an MSI-X entry outside its BAR");
                }
            }
        }
        if let Ok(t) = Transport::new(&device) {
            if let Some(d) = t.device_config() {
                assert!(bars.iter().any(|b| inside(d, &b.range())), "virtio registers outside the device's BARs");
            }
            let _ = (t.status(), t.queues(), t.config_generation());
        }
    }

    // The device manager: the first function as a hot-plug port, and the
    // second arriving in its slot.
    let Some(mut port) = Port::of(1, Config::new(port_space.mmio())) else { return };
    // Bus numbers the bridge says are its own are taken only when they can
    // be: behind its bus, in order, within the segment.
    if devmgr::hotplug::buses_valid(0, port.secondary, port.subordinate, 255, &[(1, 1)]) {
        assert!(port.secondary > 0 && port.secondary <= port.subordinate && port.secondary != 1, "bus numbers no port can own were taken");
    }
    port.arm();
    let _ = port.changed();
    let arrived = Config::new(device_space.mmio());
    // The port's windows, read independently of the device manager: what
    // every placed BAR must lie inside.
    let r = port_space.mmio();
    let memory = ((r.read16(0x20) as u64 & 0xFFF0) << 16, ((r.read16(0x22) as u64 & 0xFFF0) << 16) | 0xF_FFFF);
    let (pb, pl) = (r.read16(0x24) as u64, r.read16(0x26) as u64);
    let upper = |at: usize| if pb & 0xF == 1 { (r.read32(at) as u64) << 32 } else { 0 };
    let prefetchable = ((pb & 0xFFF0) << 16 | upper(0x28), ((pl & 0xFFF0) << 16) | 0xF_FFFF | upper(0x2C));
    let within =
        |(base, limit): (u64, u64), at: u64, size: u64| base <= limit && at >= base && at.checked_add(size - 1).is_some_and(|e| e <= limit);
    if port.place(&arrived).is_ok() {
        // The BARs as the device manager walks them: a 64-bit BAR's upper
        // half is not a BAR of its own.
        let mut i = 0;
        while i < 6 {
            let Some((at, wide)) = arrived.bar_address(i) else {
                i += 1;
                continue;
            };
            if let Some((bits, _)) = arrived.bar_size(i) {
                let size = 1u64 << bits.max(12);
                assert!(at & (size - 1) == 0, "a BAR placed at an address not a multiple of its size");
                assert!(
                    within(memory, at, size) || within(prefetchable, at, size),
                    "BAR {i} placed outside the port's windows: {at:#x} ({size:#x} bytes, windows {memory:x?} {prefetchable:x?})"
                );
            }
            i += if wide { 2 } else { 1 };
        }
    }
    let _ = port.changed();
});
