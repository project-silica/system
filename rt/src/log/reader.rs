//! Text pages returned by the log reader. Its cursor counts source bytes.
use alloc::string::String;

/// Render at most `limit` source bytes into a reply. Supply up to three
/// more bytes so a character crossing the limit can start the next page.
/// Each malformed byte becomes one ASCII question mark, preserving the
/// source byte offsets used by readers to bound their snapshots.
pub fn read_text(bytes: &[u8], limit: usize, out: &mut String) {
    out.clear();
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        let room = limit - out.len();
        if valid.len() >= room {
            out.push_str(&valid[..valid.floor_char_boundary(room)]);
            break;
        }
        out.push_str(valid);
        let invalid = chunk.invalid().len().min(limit - out.len());
        for _ in 0..invalid {
            out.push('?');
        }
        if out.len() == limit {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_bytes_preserve_later_text_and_byte_positions() {
        let mut text = String::new();
        read_text(b"\xffok\n\xe2\x82!\nnext", 3000, &mut text);
        assert_eq!(text, "?ok\n??!\nnext");
        read_text(b"tail\xf0\x9f", 3000, &mut text);
        assert_eq!(text, "tail??");
    }

    #[test]
    fn a_character_crossing_the_page_limit_starts_the_next_reply() {
        let bytes = "a🦀b".as_bytes();
        let mut text = String::new();
        read_text(bytes, 4, &mut text);
        assert_eq!(text, "a");
        read_text(&bytes[1..], 4, &mut text);
        assert_eq!(text, "🦀");
    }
}
