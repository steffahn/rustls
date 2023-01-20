#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::message::{Message, PlainMessage, OpaqueMessage};

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    if let Ok(m) = OpaqueMessage::read(&mut buf) {
        let used = m.len();
        let plain = m.to_plain_message();
        let msg = match Message::try_from(plain) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        //println!("msg = {:#?}", m);
        let enc = PlainMessage::from(msg)
            .into_unencrypted_opaque()
            .encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..used]);
    }
});
