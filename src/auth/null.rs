use crate::codec::{CodecError, FramedIo, Message, ZmqCommandName, ZmqMechanism, ZmqMetadata};

use futures::{future::join, SinkExt, StreamExt};
use std::convert::TryFrom;

pub async fn null_auth(
    raw_socket: &mut FramedIo,
    metadata: &ZmqMetadata,
) -> Result<ZmqMetadata, CodecError> {
    // Send READY
    let send = raw_socket
        .write_half
        .send(Message::Command(ZmqCommandName::READY, metadata.into()));

    // Receive READY
    let recv = raw_socket.read_half.next();

    // Perform both in parallel
    match join(send, recv).await {
        (Ok(_), Some(message)) => match message? {
            Message::Command(ZmqCommandName::READY, body) => ZmqMetadata::try_from(&body[..]),
            _ => return Err(CodecError::Handshake(ZmqMechanism::NULL, "Expected READY")),
        },
        (Ok(_), None) => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::NULL)),
        (Err(err), _) => Err(err.into()),
    }
}
