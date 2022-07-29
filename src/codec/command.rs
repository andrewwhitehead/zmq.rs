use super::error::CodecError;

use std::convert::TryFrom;
use std::fmt::Display;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZmqCommandName {
    HELLO,
    WELCOME,
    INITIATE,
    READY,
    ERROR,
}

impl ZmqCommandName {
    pub const fn as_str(&self) -> &'static str {
        match self {
            ZmqCommandName::HELLO => "HELLO",
            ZmqCommandName::WELCOME => "WELCOME",
            ZmqCommandName::INITIATE => "INITIATE",
            ZmqCommandName::READY => "READY",
            ZmqCommandName::ERROR => "ERROR",
        }
    }
}

impl Display for ZmqCommandName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&[u8]> for ZmqCommandName {
    type Error = CodecError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let name = match value {
            b"HELLO" => ZmqCommandName::HELLO,
            b"WELCOME" => ZmqCommandName::WELCOME,
            b"INITIATE" => ZmqCommandName::INITIATE,
            b"READY" => ZmqCommandName::READY,
            b"ERROR" => ZmqCommandName::ERROR,
            _ => {
                return Err(CodecError::Command("Unsupported command received"));
            }
        };
        Ok(name)
    }
}
