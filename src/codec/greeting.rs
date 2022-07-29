use super::error::CodecError;
use super::mechanism::ZmqMechanism;
use super::ZMTP_VERSION;

use std::convert::TryFrom;

pub type ZmtpVersion = (u8, u8);

pub const GREETING_LENGTH: usize = 64;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ZmqGreeting {
    pub version: ZmtpVersion,
    pub mechanism: ZmqMechanism,
    pub as_server: bool,
}

impl Default for ZmqGreeting {
    fn default() -> Self {
        Self {
            version: ZMTP_VERSION,
            mechanism: ZmqMechanism::default(),
            as_server: false,
        }
    }
}

impl ZmqGreeting {
    pub(crate) fn to_bytes(&self) -> [u8; GREETING_LENGTH] {
        let mut data: [u8; 64] = [0; 64];
        data[0] = 0xff;
        data[9] = 0x7f;
        data[10] = self.version.0;
        data[11] = self.version.1;
        let mech = self.mechanism.as_str();
        data[12..12 + mech.len()].copy_from_slice(mech.as_bytes());
        data[32] = self.as_server.into();
        data
    }
}

impl From<ZmqMechanism> for ZmqGreeting {
    fn from(mechanism: ZmqMechanism) -> Self {
        Self {
            version: ZMTP_VERSION,
            mechanism,
            // in practice the as_server flag is NOT set by libzmq
            as_server: false,
        }
    }
}

impl TryFrom<&[u8]> for ZmqGreeting {
    type Error = CodecError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != GREETING_LENGTH
            || value[0] != 0xff
            || value[9] != 0x7f
            || value[32] > 0x01
        {
            return Err(CodecError::Greeting("Failed to parse greeting"));
        }
        Ok(ZmqGreeting {
            version: (value[10], value[11]),
            mechanism: ZmqMechanism::try_from(&value[12..32])?,
            as_server: value[32] == 0x01,
        })
    }
}

impl From<ZmqGreeting> for Vec<u8> {
    fn from(greet: ZmqGreeting) -> Self {
        Vec::from(greet.to_bytes())
    }
}
