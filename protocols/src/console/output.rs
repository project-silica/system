use super::terminal;
use core::convert::Infallible;
use silica_idl_rt::{CallError, Capability, Transport};

impl<T: Transport<C>, C: Capability> terminal::Client<T, C> {
    /// Write a complete UTF-8 string. On failure, earlier writes may already be visible.
    pub fn write_all(&mut self, mut text: &str) -> Result<(), CallError<Infallible>> {
        // The write request carries two u32 lengths: the field list and its string.
        const MAX_TEXT: usize = silica_idl_rt::MAX_MESSAGE - silica_idl_rt::HEADER_LEN - 8;
        while !text.is_empty() {
            let (chunk, rest) = text.split_at(text.floor_char_boundary(MAX_TEXT.min(text.len())));
            self.write(chunk)?;
            text = rest;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::string::String;
    use silica_idl_rt::{CapList, TransportError};

    struct NoCap;
    impl Capability for NoCap {}

    struct Screen<'a>(&'a mut String);
    impl Transport<NoCap> for Screen<'_> {
        fn call(
            &mut self,
            message: &mut [u8],
            len: usize,
            caps: CapList<NoCap>,
            reply: &mut CapList<NoCap>,
        ) -> Result<usize, TransportError> {
            let request = terminal::WriteRequest::decode_message(&message[..len], caps).unwrap();
            self.0.push_str(request.text);
            Ok(terminal::WriteReply {}.encode_message(message, reply).unwrap())
        }
    }

    #[test]
    fn long_terminal_output_arrives_intact() {
        let text = "a".repeat(3975) + &"🦀".repeat(2000) + "\n";
        let mut displayed = String::new();
        terminal::Client::from(Screen(&mut displayed)).write_all(&text).unwrap();
        assert_eq!(displayed, text);
    }
}
