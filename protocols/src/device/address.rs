use core::{fmt, ops::RangeInclusive, str::FromStr};

/// A device manager identity, printed as `[segment:]bus:device.function` in hex.
/// An omitted segment means zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciAddress(pub u32);

impl PciAddress {
    fn segment(self) -> u16 {
        (self.0 >> 16) as u16
    }

    fn bus(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// Whether a port's downstream bus range includes this function.
    pub fn on_buses(self, segment: u16, buses: RangeInclusive<u8>) -> bool {
        self.segment() == segment && buses.contains(&self.bus())
    }
}

impl fmt::Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segment() != 0 {
            write!(f, "{:04x}:", self.segment())?;
        }
        write!(f, "{:02x}:{:02x}.{}", self.bus(), self.0 >> 3 & 31, self.0 & 7)
    }
}

impl FromStr for PciAddress {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (prefix, slot) = s.rsplit_once(':').ok_or(())?;
        let (segment, bus) = prefix.split_once(':').unwrap_or(("0", prefix));
        let (device, function) = slot.split_once('.').ok_or(())?;
        let hex = |s| u32::from_str_radix(s, 16).map_err(|_| ());
        let (segment, bus, device, function) = (hex(segment)?, hex(bus)?, hex(device)?, hex(function)?);
        if segment > 0xffff || bus > 255 || device > 31 || function > 7 {
            return Err(());
        }
        Ok(Self(segment << 16 | bus << 8 | device << 3 | function))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::ToString;

    #[test]
    fn operator_addresses_round_trip() {
        for (raw, text) in [(0x0219, "02:03.1"), (0x0001_0219, "0001:02:03.1"), (u32::MAX, "ffff:ff:1f.7")] {
            assert_eq!(PciAddress(raw).to_string(), text);
            assert_eq!(text.parse(), Ok(PciAddress(raw)));
        }
        assert_eq!("0000:02:03.1".parse(), "02:03.1".parse::<PciAddress>());
        for bad in ["10000:02:03.1", "100:03.1", "02:20.1", "02:03.8", ":02:03.1", "1:2:3:4.5"] {
            assert!(bad.parse::<PciAddress>().is_err(), "{bad}");
        }
    }

    #[test]
    fn port_removal_selects_only_downstream_functions_in_its_segment() {
        let downstream = |id| PciAddress(id).on_buses(1, 2..=4);
        assert!(downstream(0x0001_0200));
        assert!(downstream(0x0001_04ff));
        assert!(!downstream(0x0000_0200));
        assert!(!downstream(0x0001_01ff));
        assert!(!downstream(0x0001_0500));
    }
}
