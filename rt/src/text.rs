//! Text from someone else, made safe to put in front of a person.
//!
//! A service's log line, a program's console output or a remote peer's
//! words are bytes their writer chose. Passed to a terminal as they are,
//! control characters act: an escape sequence moves the cursor, recolours
//! or rewrites what is on the screen, sets the window title or reaches the
//! terminal's own features (OSC), and a carriage return writes over the
//! line another program wrote. So whatever shows text it did not write
//! shows it through [`printable`]: every control character but the line
//! end and the tab becomes `?`, so a writer can say anything but can only
//! say it, and a reader sees that something was replaced.

use alloc::borrow::Cow;
use alloc::string::String;

/// `text` with every control character (C0, DEL and C1) but `\n` and `\t`
/// replaced by `?`. Borrowed, at no cost, when there is none.
pub fn printable(text: &str) -> Cow<'_, str> {
    if !text.chars().any(unsafe_char) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(text.chars().map(|c| if unsafe_char(c) { '?' } else { c }).collect::<String>())
}

fn unsafe_char(c: char) -> bool {
    c.is_control() && c != '\n' && c != '\t'
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
        // C1 controls (CSI as one character) and DEL.
        assert_eq!(printable("\u{9b}31m\u{7f}"), "?31m?");
        assert_eq!(printable("é ü 漢"), "é ü 漢");
    }
}
