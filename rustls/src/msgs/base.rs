use std::fmt;

use crate::msgs::codec;
use crate::msgs::codec::{Codec, Reader};

use std::borrow::Cow;

/// An externally length'd payload
#[derive(Clone, Eq, PartialEq)]
pub struct Payload<'a>(pub Cow<'a, [u8]>);

impl<'a> Codec<'a> for Payload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'a>) -> Option<Payload<'a>> {
        Some(Self::read(r))
    }
}

impl<'a> Payload<'a> {
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        Self(bytes.into())
    }

    pub fn empty() -> Payload<'static> {
        Payload::new(Vec::new())
    }

    pub fn read(r: &mut Reader<'a>) -> Self {
        Self::new(r.rest())
    }

    pub fn to_owned(&self) -> Payload<'static> {
        Payload::new(self.0.to_vec())
    }
}

impl<'a> fmt::Debug for Payload<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, self.0.as_ref())
    }
}

/// An arbitrary, unknown-content, u24-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub struct PayloadU24(pub Cow<'static, [u8]>);

impl PayloadU24 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }
}

impl<'a> Codec<'a> for PayloadU24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::u24(self.0.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        Some(Self::new(sub.rest().to_vec()))
    }
}

impl fmt::Debug for PayloadU24 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, self.0.as_ref())
    }
}

/// An arbitrary, unknown-content, u16-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub struct PayloadU16(pub Vec<u8>);

impl PayloadU16 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u16).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl<'a> Codec<'a> for PayloadU16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Some(Self(body))
    }
}

impl fmt::Debug for PayloadU16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

/// An arbitrary, unknown-content, u8-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub struct PayloadU8(pub Cow<'static, [u8]>);

impl PayloadU8 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0.into_owned()
    }
}

impl<'a> Codec<'a> for PayloadU8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.0.len() as u8).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u8::read(r)? as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Some(Self::new(body))
    }
}

impl fmt::Debug for PayloadU8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, self.0.as_ref())
    }
}

// Format an iterator of u8 into a hex string
pub(super) fn hex<'a>(
    f: &mut fmt::Formatter<'_>,
    payload: impl IntoIterator<Item = &'a u8>,
) -> fmt::Result {
    for b in payload {
        write!(f, "{:02x}", b)?
    }
    Ok(())
}
