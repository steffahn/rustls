use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, AlertLevel, ContentType, HandshakeType};
use crate::msgs::handshake::HandshakeMessagePayload;

#[derive(Debug)]
pub enum MessagePayload {
    Alert(AlertMessagePayload),
    Handshake {
        parsed: HandshakeMessagePayload,
        encoded: Payload<'static>,
    },
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'static>),
}

impl MessagePayload {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(encoded.0.as_ref()),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub fn handshake(parsed: HandshakeMessagePayload) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
        }
    }

    pub fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: Payload<'static>,
    ) -> Result<Self, Error> {
        let mut r = Reader::init(&payload.0);
        let parsed = match typ {
            ContentType::ApplicationData => return Ok(Self::ApplicationData(payload)),
            ContentType::Alert => AlertMessagePayload::read(&mut r)
                .filter(|_| !r.any_left())
                .map(MessagePayload::Alert),
            ContentType::Handshake => HandshakeMessagePayload::read_version(&mut r, vers)
                .filter(|_| !r.any_left())
                .map(|parsed| Self::Handshake {
                    parsed,
                    encoded: payload,
                }),
            ContentType::ChangeCipherSpec => ChangeCipherSpecPayload::read(&mut r)
                .filter(|_| !r.any_left())
                .map(MessagePayload::ChangeCipherSpec),
            _ => None,
        };

        parsed.ok_or(Error::CorruptMessagePayload(typ))
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake { .. } => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type owns all memory for its interior parts. It is used to read/write from/to I/O
/// buffers as well as for fragmenting, joining and encryption/decryption. It can be converted
/// into a `Message` by decoding the payload.
#[derive(Debug)]
pub struct OpaqueMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Buffer<'a>,
}

impl<'a> OpaqueMessage<'a> {
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(buf: &'a mut [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::init(&buf);
        let typ = ContentType::read(&mut r).ok_or(MessageError::TooShortForHeader)?;
        let version = ProtocolVersion::read(&mut r).ok_or(MessageError::TooShortForHeader)?;
        let len = u16::read(&mut r).ok_or(MessageError::TooShortForHeader)?;

        // Reject undersize messages
        //  implemented per section 5.1 of RFC8446 (TLSv1.3)
        //              per section 6.2.1 of RFC5246 (TLSv1.2)
        if typ != ContentType::ApplicationData && len == 0 {
            return Err(MessageError::IllegalLength);
        }

        // Reject oversize messages
        if len >= Self::MAX_PAYLOAD {
            return Err(MessageError::IllegalLength);
        }

        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::IllegalContentType);
        }

        // Accept only versions 0x03XX for any XX.
        match version {
            ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
                return Err(MessageError::IllegalProtocolVersion);
            }
            _ => {}
        };

        if r.left() < len as usize {
            return Err(MessageError::TooShortForLength);
        }

        let end = (Self::HEADER_SIZE + len) as usize;
        Ok(Self {
            typ,
            version,
            payload: Buffer::Slice(&mut buf[Self::HEADER_SIZE as usize..end]),
        })
    }

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.typ.encode(&mut buf);
        self.version.encode(&mut buf);
        (self.payload.len() as u16).encode(&mut buf);
        buf.extend_from_slice(self.payload.as_ref());
        buf
    }

    pub fn to_plain_message(&self) -> PlainMessage {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            payload: Payload::new(self.payload.as_ref().to_vec()),
        }
    }

    pub fn to_owned(&self) -> OpaqueMessage<'static> {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: Buffer::Vec(self.payload.as_ref().to_vec()),
        }
    }

    pub fn len(&self) -> usize {
        Self::HEADER_SIZE as usize + self.payload.len()
    }

    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;

    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}

impl From<Message> for PlainMessage {
    fn from(msg: Message) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.0.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                buf
            }
        };

        Self {
            typ,
            version: msg.version,
            payload: Payload::new(payload),
        }
    }
}

/// A decrypted TLS frame
///
/// This type owns all memory for its interior parts. It can be decrypted from an OpaqueMessage
/// or encrypted into an OpaqueMessage, and it is also used for joining and fragmenting.
#[derive(Clone, Debug)]
pub struct PlainMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Payload<'static>,
}

impl PlainMessage {
    pub fn into_unencrypted_opaque(self) -> OpaqueMessage<'static> {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: Buffer::Vec(self.payload.0.into_owned()),
        }
    }

    pub fn borrow(&self) -> BorrowedPlainMessage<'_> {
        BorrowedPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: &self.payload.0,
        }
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message {
    pub version: ProtocolVersion,
    pub payload: MessagePayload,
}

impl Message {
    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake { parsed, .. } = &self.payload {
            parsed.typ == hstyp
        } else {
            false
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }
}

/// Parses a plaintext message into a well-typed [`Message`].
///
/// A [`PlainMessage`] must contain plaintext content. Encrypted content should be stored in an
/// [`OpaqueMessage`] and decrypted before being stored into a [`PlainMessage`].
impl TryFrom<PlainMessage> for Message {
    type Error = Error;

    fn try_from(plain: PlainMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type differs from `OpaqueMessage` because it borrows
/// its payload.  You can make a `OpaqueMessage` from an
/// `BorrowMessage`, but this involves a copy.
///
/// This type also cannot decode its internals and
/// cannot be read/encoded; only `OpaqueMessage` can do that.
pub struct BorrowedPlainMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl<'a> BorrowedPlainMessage<'a> {
    pub fn to_unencrypted_opaque(&self) -> OpaqueMessage {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: Buffer::Vec(self.payload.to_vec()),
        }
    }
}

/// `Cow`-like wrapper that abstracts over a mutable slice or owned `Vec` byte buffer.
///
/// This is used in our `OpaqueMessage`, where we would like to be able to decrypt in place.
#[derive(Debug)]
pub enum Buffer<'a> {
    Slice(&'a mut [u8]),
    Vec(Vec<u8>),
}

impl<'a> Buffer<'a> {
    pub(crate) fn truncate(&mut self, new_len: usize) {
        match self {
            Buffer::Slice(slice) => *slice = &mut std::mem::take(slice)[..new_len],
            Buffer::Vec(vec) => vec.truncate(new_len),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Buffer::Slice(slice) => slice.len(),
            Buffer::Vec(vec) => vec.len(),
        }
    }
}

impl<'a> AsRef<[u8]> for Buffer<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Buffer::Slice(slice) => slice,
            Buffer::Vec(vec) => vec,
        }
    }
}

impl<'a> AsMut<[u8]> for Buffer<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Buffer::Slice(slice) => slice,
            Buffer::Vec(vec) => vec,
        }
    }
}

impl From<Vec<u8>> for Buffer<'static> {
    fn from(vec: Vec<u8>) -> Self {
        Buffer::Vec(vec)
    }
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    IllegalLength,
    IllegalContentType,
    IllegalProtocolVersion,
}
