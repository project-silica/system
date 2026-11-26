//! Text from someone else, made safe to put in front of a person.
//!
//! A service's log line, a program's console output or a remote peer's
//! words are bytes their writer chose. Passed to a terminal as they are,
//! control characters act: an escape sequence moves the cursor, recolours
//! or rewrites what is on the screen, sets the window title or reaches the
//! terminal's own features (OSC), and a carriage return writes over the
//! line another program wrote. So whatever shows text it did not write
//! shows it through [`printable`]: every control character but the line
//! end (`\n`, or `\r\n`, as `println!` ends a line for a serial terminal)
//! and the tab becomes `?`, so a writer can say anything but can only say
//! it, and a reader sees that something was replaced.

use alloc::borrow::Cow;
use alloc::string::String;

/// `text` with every control character (C0, DEL and C1) but `\n`, a `\r`
/// right before one, and `\t` replaced by `?`. Borrowed, at no cost, when
/// there is none.
pub fn printable(text: &str) -> Cow<'_, str> {
    let unsafe_at = |i: usize, c: char| c.is_control() && c != '\n' && c != '\t' && !(c == '\r' && text[i + 1..].starts_with('\n'));
    if !text.char_indices().any(|(i, c)| unsafe_at(i, c)) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(text.char_indices().map(|(i, c)| if unsafe_at(i, c) { '?' } else { c }).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::printable;

    #[test]
    fn escapes_carriage_returns_and_c1_controls_are_shown_not_obeyed() {
        assert_eq!(printable("plain text\twith tabs\n"), "plain text\twith tabs\n");
        assert!(matches!(printable("plain"), alloc::borrow::Cow::Borrowed(_)));
        // A colour change, a cursor move, a title set (OSC), a line rewritten.
        assert_eq!(printable("\x1b[31mred\x1b[0m"), "?[31mred?[0m");
        assert_eq!(printable("ok\x1b[2J\x1b[H"), "ok?[2J?[H");
        assert_eq!(printable("\x1b]0;owned\x07"), "?]0;owned?");
        assert_eq!(printable("real line\rforged line"), "real line?forged line");
        // A line ended for a serial terminal overwrites nothing.
        assert_eq!(printable("line\r\nnext\r\n"), "line\r\nnext\r\n");
        assert_eq!(printable("a\r\rb\r"), "a??b?");
        // C1 controls (CSI as one character) and DEL.
        assert_eq!(printable("\u{9b}31m\u{7f}"), "?31m?");
        assert_eq!(printable("é ü 漢"), "é ü 漢");
    }
}
