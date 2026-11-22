//! Linux's key codes (which virtio input devices speak) to USB HID
//! keyboard usages (page 7), which is what Silica's input protocol speaks.

/// The HID usage of Linux key code `code`, for the keys a keyboard has.
pub fn usage(code: u16) -> Option<u16> {
    // Letters in Linux's (keyboard row) order.
    const ROWS: [(u16, &[u8]); 3] = [(16, b"qwertyuiop"), (30, b"asdfghjkl"), (44, b"zxcvbnm")];
    for (first, letters) in ROWS {
        if let Some(i) = code.checked_sub(first).filter(|i| (*i as usize) < letters.len()) {
            return Some(0x04 + (letters[i as usize] - b'a') as u16);
        }
    }
    Some(match code {
        1 => 0x29,                   // Escape
        2..=10 => code + 0x1C,       // 1 to 9
        11 => 0x27,                  // 0
        12 => 0x2D,                  // minus
        13 => 0x2E,                  // equal
        14 => 0x2A,                  // backspace
        15 => 0x2B,                  // tab
        26 => 0x2F,                  // [
        27 => 0x30,                  // ]
        28 => 0x28,                  // enter
        29 => 0xE0,                  // left control
        39 => 0x33,                  // ;
        40 => 0x34,                  // '
        41 => 0x35,                  // `
        42 => 0xE1,                  // left shift
        43 => 0x31,                  // backslash
        51 => 0x36,                  // ,
        52 => 0x37,                  // .
        53 => 0x38,                  // /
        54 => 0xE5,                  // right shift
        56 => 0xE2,                  // left alt
        57 => 0x2C,                  // space
        58 => 0x39,                  // caps lock
        59..=68 => code - 59 + 0x3A, // F1 to F10
        87 => 0x44,                  // F11
        88 => 0x45,                  // F12
        97 => 0xE4,                  // right control
        100 => 0xE6,                 // right alt
        102 => 0x4A,                 // home
        103 => 0x52,                 // up
        104 => 0x4B,                 // page up
        105 => 0x50,                 // left
        106 => 0x4F,                 // right
        107 => 0x4D,                 // end
        108 => 0x51,                 // down
        109 => 0x4E,                 // page down
        110 => 0x49,                 // insert
        111 => 0x4C,                 // delete
        125 => 0xE3,                 // left meta
        126 => 0xE7,                 // right meta
        _ => return None,
    })
}
