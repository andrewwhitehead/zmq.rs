use super::{ZmqMechanism, ZmtpVersion};

use thiserror::Error;

/// Represents an error when encoding/decoding raw byte buffers and frames
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum CodecError {
    #[error("{0}")]
    Command(&'static str),
    #[error("{0}")]
    Encryption(&'static str),
    #[error("{0}")]
    Greeting(&'static str),
    #[error("Error during {0} handshake: {1}")]
    Handshake(ZmqMechanism, &'static str),
    #[error("Disconnected during {0} handshake")]
    HandshakeIncomplete(ZmqMechanism),
    #[error("{0}")]
    Mechanism(&'static str),
    #[error("{0}")]
    PeerIdentity(&'static str),
    #[error("{0}")]
    SocketType(&'static str),
    #[error("{0}")]
    Decode(&'static str),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("Unsupported ZMTP mechanism: {0}")]
    UnsupportedMechanism(ZmqMechanism),
    #[error("Unsupported ZMTP version: {0:?}")]
    UnsupportedVersion(ZmtpVersion),
    #[error("{0}")]
    Other(&'static str),
}
