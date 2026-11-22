//! Keys to characters: USB HID keyboard usages, the US English layout.

/// What a key press means to the line being typed.
pub enum Key {
    Char(char),
    Backspace,
    Enter,
}

/// The modifier keys held, and caps lock.
#[derive(Default)]
pub struct Modifiers {
    shift: u8,
    caps: bool,
}

/// Unshifted and shifted characters of usages 0x1E to 0x38 (digits and
/// punctuation; 0x28 to 0x2B and 0x32 are not characters).
const ROW: &[u8; 27] = b"1234567890\0\0\0\0 -=[]\\\0;'`,./";
const SHIFTED: &[u8; 27] = b"!@#$%^&*()\0\0\0\0 _+{}|\0:\"~<>?";

impl Modifiers {
    /// Key `usage` went down (or up): what it means, if anything.
    pub fn key(&mut self, usage: u16, down: bool) -> Option<Key> {
        match usage {
            0xE1 | 0xE5 => {
                self.shift = if down { self.shift | 1 << (usage & 4) } else { self.shift & !(1 << (usage & 4)) };
                return None;
            }
            _ if !down => return None,
            0x39 => {
                self.caps = !self.caps;
                return None;
            }
            0x28 => return Some(Key::Enter),
            0x2A => return Some(Key::Backspace),
            _ => {}
        }
        let shift = self.shift != 0;
        match usage {
            0x04..=0x1D => {
                let c = (b'a' + (usage - 0x04) as u8) as char;
                Some(Key::Char(if shift != self.caps { c.to_ascii_uppercase() } else { c }))
            }
            0x2B => Some(Key::Char(' ')),
            0x1E..=0x38 => {
                let i = (usage - 0x1E) as usize;
                let c = if shift { SHIFTED[i] } else { ROW[i] };
                (c != 0).then_some(Key::Char(c as char))
            }
            _ => None,
        }
    }
}
