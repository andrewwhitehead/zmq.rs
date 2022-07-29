use crate::codec::{CodecError, ZmqFramedRead, ZmqFramedWrite};

use bytes::Bytes;
use std::convert::TryFrom;
use std::ops::Deref;
use uuid::Uuid;

pub(crate) struct PeerConnection {
    pub(crate) send_queue: ZmqFramedWrite,
    pub(crate) recv_queue: ZmqFramedRead,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Clone)]
pub struct PeerIdentity(Bytes);

impl PeerIdentity {
    pub fn new() -> Self {
        let id = Uuid::new_v4();
        Self(Bytes::copy_from_slice(id.as_bytes()))
    }
}

impl AsRef<[u8]> for PeerIdentity {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for PeerIdentity {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &*self.0
    }
}

impl Default for PeerIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<&[u8]> for PeerIdentity {
    type Error = CodecError;

    fn try_from(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            Ok(PeerIdentity::new())
        } else {
            Self::try_from(Bytes::copy_from_slice(data))
        }
    }
}

impl TryFrom<&str> for PeerIdentity {
    type Error = CodecError;

    #[inline]
    fn try_from(data: &str) -> Result<Self, CodecError> {
        Self::try_from(data.as_bytes())
    }
}

impl TryFrom<Bytes> for PeerIdentity {
    type Error = CodecError;

    fn try_from(data: Bytes) -> Result<Self, CodecError> {
        if data.is_empty() {
            Ok(PeerIdentity::new())
        } else if data.len() > 255 {
            Err(CodecError::PeerIdentity(
                "ZMQ_IDENTITY should not be more than 255 bytes long",
            ))
        } else {
            Ok(Self(data))
        }
    }
}

impl From<&PeerIdentity> for Vec<u8> {
    fn from(p_id: &PeerIdentity) -> Self {
        p_id.0.to_vec()
    }
}

impl From<&PeerIdentity> for Bytes {
    fn from(p_id: &PeerIdentity) -> Self {
        p_id.0.clone()
    }
}

impl From<PeerIdentity> for Bytes {
    fn from(p_id: PeerIdentity) -> Self {
        p_id.0
    }
}
