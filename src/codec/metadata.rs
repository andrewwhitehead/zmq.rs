use super::CodecError;
use crate::connection::PeerIdentity;
use crate::socket::SocketType;

use bytes::{BufMut, Bytes, BytesMut};
use std::convert::{TryFrom, TryInto};

const METADATA_IDENTITY: &[u8] = b"Identity";
const METADATA_SOCKET_TYPE: &[u8] = b"Socket-Type";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZmqMetadata {
    pub peer_id: Option<PeerIdentity>,
    pub socket_type: SocketType,
}

impl ZmqMetadata {
    pub fn decode(mut buf: &[u8]) -> Result<Self, CodecError> {
        let mut peer_id = None;
        let mut socket_type = None;
        loop {
            let len = buf.len();
            if len == 0 {
                break;
            }
            let key_end = buf[0] as usize + 1;
            if key_end + 4 > len {
                return Err(CodecError::Decode("Invalid metadata"));
            }
            let val_end = (u32::from_be_bytes(buf[key_end..(key_end + 4)].try_into().unwrap())
                as usize)
                .saturating_add(key_end + 4);
            if val_end > len {
                return Err(CodecError::Decode("Invalid metadata"));
            }
            let val = &buf[(key_end + 4)..val_end];
            match &buf[1..key_end] {
                METADATA_IDENTITY => {
                    peer_id.replace(val.try_into()?);
                }
                METADATA_SOCKET_TYPE => {
                    socket_type.replace(val.try_into()?);
                }
                _ => {}
            }
            buf = &buf[val_end..];
        }
        if let Some(socket_type) = socket_type {
            Ok(Self {
                peer_id,
                socket_type,
            })
        } else {
            return Err(CodecError::SocketType(
                "Invalid metadata: missing socket type",
            ));
        }
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        if let Some(peer_id) = self.peer_id.as_deref() {
            dst.put_u8(METADATA_IDENTITY.len() as u8);
            dst.extend_from_slice(METADATA_IDENTITY);
            dst.put_u32(peer_id.len() as u32);
            dst.extend_from_slice(peer_id);
        }

        dst.put_u8(METADATA_SOCKET_TYPE.len() as u8);
        dst.extend_from_slice(METADATA_SOCKET_TYPE);
        let sock_type = self.socket_type.as_str();
        dst.put_u32(sock_type.len() as u32);
        dst.extend_from_slice(sock_type.as_bytes());
    }
}

impl TryFrom<&[u8]> for ZmqMetadata {
    type Error = CodecError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(value)
    }
}

impl From<&ZmqMetadata> for Bytes {
    fn from(metadata: &ZmqMetadata) -> Self {
        let mut buf = BytesMut::with_capacity(256);
        metadata.encode(&mut buf);
        buf.freeze()
    }
}

impl From<ZmqMetadata> for Bytes {
    #[inline]
    fn from(metadata: ZmqMetadata) -> Self {
        (&metadata).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_metadata() {
        let meta_input = b"\x08Identity\x00\x00\x00\x03Bob\x0bSocket-Type\x00\x00\x00\x03PUB";
        let _ = ZmqMetadata::try_from(&meta_input[..]).expect("Error parsing metadata");
    }

    #[test]
    fn parse_invalid_metadata_key_cut_off() {
        let meta_input = b"\x08Ident";
        let result = ZmqMetadata::try_from(&meta_input[..]);
        match result {
            Err(CodecError::Decode(..)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn parse_invalid_metadata_value_cut_off() {
        let meta_input = b"\x08Identity\x00\x00\x00\x03A";
        let result = ZmqMetadata::try_from(&meta_input[..]);
        match result {
            Err(CodecError::Decode(..)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn parse_missing_socket_type() {
        let meta_input = b"\x08Identity\x00\x00\x00\x03Bob";
        let result = ZmqMetadata::try_from(&meta_input[..]);
        match result {
            Err(CodecError::SocketType(..)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_socket_type() {
        let meta_input =
            b"\x08Identity\x00\x00\x00\x03Bob\x0bSocket-Type\x00\x00\x00\x0aNOTASOCKET";
        let result = ZmqMetadata::try_from(&meta_input[..]);
        match result {
            Err(CodecError::SocketType(..)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }
}
