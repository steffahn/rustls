#![allow(clippy::upper_case_acronyms)]
#![allow(missing_docs)]

#[macro_use]
mod macros;

pub mod alert;
pub mod base;
pub mod ccs;
pub mod codec;
pub mod deframer;
pub mod enums;
pub mod fragmenter;
pub mod handshake;
pub mod message;
pub mod persist;

#[cfg(test)]
mod handshake_test;

#[cfg(test)]
mod persist_test;

#[cfg(test)]
pub(crate) mod enums_test;

#[cfg(test)]
mod message_test;

#[cfg(test)]
mod test {
    #[test]
    fn smoketest() {
        use super::message::{Message, OpaqueMessage};
        let mut bytes = include_bytes!("handshake-test.1.bin").to_vec();

        let mut cur = 0;
        while cur < bytes.len() {
            let m = OpaqueMessage::read(&mut bytes[cur..]).unwrap();
            cur += m.len();

            Message::try_from(m.to_plain_message()).unwrap();
        }
    }
}
