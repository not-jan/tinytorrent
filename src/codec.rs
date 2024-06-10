use std::{collections::HashMap, io::Cursor, str::FromStr};

use anyhow::{anyhow, Result};
#[allow(unused_imports)]
use binrw::helpers::until_eof;
use binrw::{binrw, BinRead, BinReaderExt, BinWrite, BinWriterExt};
use bytes::{Buf, BytesMut};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Clone, Debug, Default)]
pub struct WireCodec {
    handshake_seen: bool,
    pub extensions: HashMap<ExtensionKind, u8>,
}

pub const MESSAGE_CHOKE: u8 = 0;
pub const MESSAGE_UNCHOKE: u8 = 1;
pub const MESSAGE_INTERESTED: u8 = 2;
pub const MESSAGE_NOT_INTERESTED: u8 = 3;
pub const MESSAGE_HAVE: u8 = 4;
pub const MESSAGE_BITFIELD: u8 = 5;
pub const MESSAGE_REQUEST: u8 = 6;
pub const MESSAGE_PIECE: u8 = 7;
pub const MESSAGE_CANCEL: u8 = 8;
pub const MESSAGE_PORT: u8 = 9;
pub const MESSAGE_EXTENSION: u8 = 20;

pub const EXT_METADATA_REQUEST: u8 = 0;
pub const EXT_METADATA_DATA: u8 = 1;
pub const EXT_METADATA_REJECT: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageKind {
    Handshake,
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have,
    Bitfield,
    Request,
    Piece,
    Cancel,
    Port,
    Extension,
    Unknown(u8, Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExtensionHandshake {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m: Option<HashMap<String, u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yourip: Option<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reqq: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_size: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum MetaDataKind {
    Request,
    Data,
    Reject,
    Unknown(u8),
}

impl From<u8> for MetaDataKind {
    fn from(value: u8) -> Self {
        match value {
            EXT_METADATA_REQUEST => MetaDataKind::Request,
            EXT_METADATA_DATA => MetaDataKind::Data,
            EXT_METADATA_REJECT => MetaDataKind::Reject,
            id => MetaDataKind::Unknown(id),
        }
    }
}

impl From<MetaDataKind> for u8 {
    fn from(value: MetaDataKind) -> Self {
        match value {
            MetaDataKind::Request => EXT_METADATA_REQUEST,
            MetaDataKind::Data => EXT_METADATA_DATA,
            MetaDataKind::Reject => EXT_METADATA_REJECT,
            MetaDataKind::Unknown(id) => id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaData {
    pub msg_type: u8,
    pub piece: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<usize>,
    #[serde(skip)]
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExtensionKind {
    #[allow(dead_code)]
    Handshake,
    MetaData,
    DontHave,
    Flag,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flag {
    pub flag: String,
}

impl FromStr for ExtensionKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "lt_donthave" => ExtensionKind::DontHave,
            "ut_metadata" => ExtensionKind::MetaData,
            "ut_flag" => ExtensionKind::Flag,
            _ => ExtensionKind::Unknown(s.to_string()),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, BinRead, BinWrite)]
#[brw(big)]
pub struct DontHave {
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    Handshake(ExtensionHandshake),
    MetaData(MetaData),
    DontHave(DontHave),
    Flag(Flag),
    Unknown(u8, Vec<u8>),
}

impl Extension {
    pub fn size(&self) -> usize {
        match self {
            Extension::Handshake(handshake) => {
                let str = serde_bencoded::to_vec(handshake).unwrap();
                str.len()
            }
            Extension::Flag(flag) => {
                let str = serde_bencoded::to_vec(flag).unwrap();
                str.len()
            }
            Extension::DontHave(_) => 4,
            Extension::Unknown(_, data) => data.len(),
            Extension::MetaData(metadata) => {
                let str = serde_bencoded::to_vec(metadata).unwrap();
                if let Some(data) = &metadata.data {
                    data.len() + str.len()
                } else {
                    str.len()
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Handshake(Handshake),
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(Have),
    Bitfield(Bitfield),
    Request(Request),
    Piece(Piece),
    Cancel(Cancel),
    Port(Port),
    Extension(Extension),
    Unknown(u8, Vec<u8>),
}

#[derive(Debug, Clone, Eq, PartialEq, BinRead, BinWrite)]
#[brw(big)]
pub struct Handshake {
    pub pstrlen: u8,
    #[br(count = pstrlen as usize)]
    pub pstr: Vec<u8>,
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[binrw]
#[brw(big)]
pub struct Have {
    pub index: u32,
}
#[derive(Debug, Clone, Eq, PartialEq)]
#[binrw]
#[brw(big)]
#[repr(C)]
pub struct Bitfield {
    #[br(parse_with = until_eof)]
    pub bits: Vec<u8>,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[binrw]
#[brw(big)]
#[repr(C)]
pub struct Request {
    pub index: u32,
    pub begin: u32,
    pub length: u32,
}
#[derive(Debug, Clone, Eq, PartialEq)]
#[binrw]
#[brw(big)]
#[repr(C)]
pub struct Piece {
    pub index: u32,
    pub begin: u32,
    #[br(parse_with = until_eof)]
    pub block: Vec<u8>,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[binrw]
#[brw(big)]
#[repr(C)]
pub struct Cancel {
    pub index: u32,
    pub begin: u32,
    pub length: u32,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[binrw]
#[brw(big)]
#[repr(C)]
pub struct Port {
    pub port: u16,
}

impl TryFrom<u8> for MessageKind {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            MESSAGE_CHOKE => MessageKind::Choke,
            MESSAGE_UNCHOKE => MessageKind::Unchoke,
            MESSAGE_INTERESTED => MessageKind::Interested,
            MESSAGE_NOT_INTERESTED => MessageKind::NotInterested,
            MESSAGE_HAVE => MessageKind::Have,
            MESSAGE_BITFIELD => MessageKind::Bitfield,
            MESSAGE_REQUEST => MessageKind::Request,
            MESSAGE_PIECE => MessageKind::Piece,
            MESSAGE_CANCEL => MessageKind::Cancel,
            MESSAGE_PORT => MessageKind::Port,
            MESSAGE_EXTENSION => MessageKind::Extension,
            _ => return Err(anyhow!("Invalid value: {}", value)),
        })
    }
}

impl TryFrom<MessageKind> for u8 {
    type Error = anyhow::Error;

    fn try_from(value: MessageKind) -> Result<Self, Self::Error> {
        Ok(match value {
            MessageKind::Choke => MESSAGE_CHOKE,
            MessageKind::Unchoke => MESSAGE_UNCHOKE,
            MessageKind::Interested => MESSAGE_INTERESTED,
            MessageKind::NotInterested => MESSAGE_NOT_INTERESTED,
            MessageKind::Have => MESSAGE_HAVE,
            MessageKind::Bitfield => MESSAGE_BITFIELD,
            MessageKind::Request => MESSAGE_REQUEST,
            MessageKind::Piece => MESSAGE_PIECE,
            MessageKind::Cancel => MESSAGE_CANCEL,
            MessageKind::Port => MESSAGE_PORT,
            MessageKind::Extension => MESSAGE_EXTENSION,
            _ => return Err(anyhow!("KeepAlive / Handshake does not have a message id!")),
        })
    }
}

impl From<Message> for MessageKind {
    fn from(value: Message) -> Self {
        match value {
            Message::Handshake(_) => MessageKind::Handshake,
            Message::KeepAlive => MessageKind::KeepAlive,
            Message::Choke => MessageKind::Choke,
            Message::Unchoke => MessageKind::Unchoke,
            Message::Interested => MessageKind::Interested,
            Message::NotInterested => MessageKind::NotInterested,
            Message::Have(_) => MessageKind::Have,
            Message::Bitfield(_) => MessageKind::Bitfield,
            Message::Request(_) => MessageKind::Request,
            Message::Piece(_) => MessageKind::Piece,
            Message::Cancel(_) => MessageKind::Cancel,
            Message::Port(_) => MessageKind::Port,
            Message::Extension(_) => MessageKind::Extension,
            Message::Unknown(id, data) => MessageKind::Unknown(id, data),
        }
    }
}

impl Message {
    pub fn size(&self) -> usize {
        match self {
            Message::KeepAlive => 0,
            Message::Choke => 1,
            Message::Unchoke => 1,
            Message::Interested => 1,
            Message::NotInterested => 1,
            Message::Have(_) => 5,
            Message::Bitfield(bitfield) => 1 + bitfield.bits.len(),
            Message::Request(_) => 13,
            Message::Piece(piece) => 9 + piece.block.len(),
            Message::Cancel(_) => 13,
            Message::Port(_) => 3,
            Message::Unknown(_, data) => 1 + data.len(),
            Message::Handshake(handshake) => 1 + handshake.pstr.len() + 8 + 20 + 20,
            Message::Extension(ext) => 1 + 1 + ext.size(),
        }
    }

    pub fn message_id(&self) -> Option<u8> {
        match self {
            Message::KeepAlive => None,
            Message::Choke => Some(MESSAGE_CHOKE),
            Message::Unchoke => Some(MESSAGE_UNCHOKE),
            Message::Interested => Some(MESSAGE_INTERESTED),
            Message::NotInterested => Some(MESSAGE_NOT_INTERESTED),
            Message::Have(_) => Some(MESSAGE_HAVE),
            Message::Bitfield(_) => Some(MESSAGE_BITFIELD),
            Message::Request(_) => Some(MESSAGE_REQUEST),
            Message::Piece(_) => Some(MESSAGE_PIECE),
            Message::Cancel(_) => Some(MESSAGE_CANCEL),
            Message::Port(_) => Some(MESSAGE_PORT),
            Message::Handshake(_) => None,
            Message::Extension(_) => Some(MESSAGE_EXTENSION),
            Message::Unknown(id, _) => Some(*id),
        }
    }
}

impl WireCodec {
    pub fn decode_extension(&self, buf: &[u8]) -> Result<Extension> {
        if buf.is_empty() {
            return Err(anyhow!("Empty buffer!"));
        }

        let kind = buf[0];

        // Handshake
        if kind == 0 {
            return Ok(Extension::Handshake(serde_bencoded::from_bytes::<ExtensionHandshake>(
                &buf[1..],
            )?));
        }

        let extension =
            self.extensions.iter().find(|&(_, value)| *value == kind).map(|(key, _)| key.clone());

        match extension {
            Some(ExtensionKind::MetaData) => {
                Ok(Extension::MetaData(serde_bencoded::from_bytes(&buf[1..])?))
            }
            _ => Ok(Extension::Unknown(kind, buf[1..].to_vec())),
        }
    }
}

impl Decoder for WireCodec {
    type Item = Message;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() || src.len() < 4 {
            return Ok(None);
        }

        if !self.handshake_seen {
            let mut cursor = Cursor::new(&mut src[..]);
            let handshake: Handshake = cursor.read_be()?;

            self.handshake_seen = true;
            let message = Message::Handshake(handshake);
            src.advance(message.size());
            return Ok(Some(message));
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        src.advance(4);

        let length = u32::from_be_bytes(length_bytes) as usize;

        if length == 0 {
            return Ok(Some(Message::KeepAlive));
        }

        if src.remaining() < length || length == 0 {
            return Err(anyhow!(
                "Client sent invalid length! Requested {:#08X?} for {:#08X?} remaining",
                length,
                src.remaining()
            ));
        }

        let message_id = src[0];
        src.advance(1);

        let message_bytes = Vec::from(&src[..(length - 1)]);
        src.advance(length - 1);

        let message = match MessageKind::try_from(message_id) {
            Ok(message) => message,
            _ => return Ok(Some(Message::Unknown(message_id, message_bytes))),
        };

        let mut cursor = Cursor::new(&message_bytes);

        let result = match message {
            MessageKind::Choke => Some(Message::Choke),
            MessageKind::Unchoke => Some(Message::Unchoke),
            MessageKind::Interested => Some(Message::Interested),
            MessageKind::NotInterested => Some(Message::NotInterested),
            MessageKind::Have => Some(Message::Have(cursor.read_be()?)),
            MessageKind::Bitfield => Some(Message::Bitfield(cursor.read_be()?)),
            MessageKind::Request => Some(Message::Request(cursor.read_be()?)),
            MessageKind::Piece => Some(Message::Piece(cursor.read_be()?)),
            MessageKind::Cancel => Some(Message::Cancel(cursor.read_be()?)),
            MessageKind::Port => Some(Message::Port(cursor.read_be()?)),
            MessageKind::Extension => {
                Some(Message::Extension(self.decode_extension(&message_bytes[..])?))
            }
            _ => None,
        };

        Ok(result)
    }
}

impl Encoder<Message> for WireCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let length = item.size();

        if let Message::Handshake(handshake) = &item {
            dst.reserve(length);
            let mut buf = Vec::with_capacity(length);
            let mut cursor = Cursor::new(&mut buf);
            cursor.write_be(handshake)?;
            dst.extend_from_slice(buf.as_slice());
            return Ok(());
        }

        let encoded_length = (length as u32).to_be_bytes();
        dst.reserve(4 + item.size());
        dst.extend_from_slice(&encoded_length);

        if let Some(id) = item.message_id() {
            dst.extend_from_slice(&[id]);
            let mut buf = Vec::new();
            let mut cursor = Cursor::new(&mut buf);
            match &item {
                Message::Have(have) => {
                    cursor.write_be(have)?;
                }
                Message::Bitfield(bitfield) => {
                    cursor.write_be(bitfield)?;
                }
                Message::Request(request) => {
                    cursor.write_be(request)?;
                }
                Message::Piece(piece) => {
                    cursor.write_be(piece)?;
                }
                Message::Cancel(cancel) => {
                    cursor.write_be(cancel)?;
                }
                Message::Port(port) => {
                    cursor.write_be(port)?;
                }
                Message::Unknown(_, data) => {
                    dst.extend_from_slice(data.as_slice());
                }
                Message::Extension(Extension::Handshake(handshake)) => {
                    dst.extend_from_slice(&[0u8]);
                    let bytes = serde_bencoded::to_vec(handshake)?;
                    dst.extend_from_slice(&bytes);
                }
                Message::Extension(Extension::Unknown(id, data)) => {
                    dst.extend_from_slice(&[*id]);
                    dst.extend_from_slice(data);
                }
                Message::KeepAlive => {}
                Message::Choke => {}
                Message::Unchoke => {}
                Message::Interested => {}
                Message::NotInterested => {}
                Message::Handshake(_) => {}
                Message::Extension(Extension::MetaData(metadata)) => {
                    let id = self.extensions.get(&ExtensionKind::MetaData).ok_or_else(|| {
                        anyhow!("Attempted to send Metadata when extension wasn't registered!")
                    })?;
                    dst.extend_from_slice(&[*id]);
                    let bytes = serde_bencoded::to_vec(metadata)?;
                    dst.extend_from_slice(&bytes);
                    if let Some(data) = &metadata.data {
                        dst.extend_from_slice(data);
                    }
                }
                Message::Extension(Extension::Flag(flag)) => {
                    let id = self.extensions.get(&ExtensionKind::Flag).ok_or_else(|| {
                        anyhow!("Attempted to send Flag when extension wasn't registered!")
                    })?;
                    dst.extend_from_slice(&[*id]);
                    let encoded = serde_bencoded::to_vec(flag)?;
                    dst.extend_from_slice(encoded.as_slice());
                }
                Message::Extension(Extension::DontHave(DontHave { index })) => {
                    let id = self.extensions.get(&ExtensionKind::DontHave).ok_or_else(|| {
                        anyhow!("Attempted to send DontHave when extension wasn't registered!")
                    })?;
                    dst.extend_from_slice(&[*id]);
                    dst.extend_from_slice(&index.to_be_bytes());
                }
            }
            dst.extend_from_slice(buf.as_slice());
        }

        Ok(())
    }
}
