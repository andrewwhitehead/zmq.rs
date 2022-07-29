use super::{AuthRequest, Authenticator};
use crate::codec::{CodecError, FramedIo, Message, ZmqCommandName, ZmqMechanism, ZmqMetadata};

use bytes::{Buf, Bytes};
use futures::{SinkExt, StreamExt};
use std::convert::TryFrom;

fn _parse_username_password(mut buf: Bytes) -> Option<(String, String)> {
    if buf.len() < 2 {
        return None;
    }
    let uname_len = buf.get_u8() as usize;
    if buf.len() < uname_len + 1 {
        return None;
    }
    let username = String::from_utf8(buf.split_to(uname_len).to_vec()).ok()?;
    let passw_len = buf.get_u8() as usize;
    if buf.len() != passw_len {
        return None;
    }
    let password = String::from_utf8(buf.to_vec()).ok()?;
    Some((username, password))
}

pub async fn plain_client_auth(
    raw_socket: &mut FramedIo,
    intro: &Bytes,
    metadata: &ZmqMetadata,
) -> Result<ZmqMetadata, CodecError> {
    // Send HELLO
    raw_socket
        .write_half
        .send(Message::Command(ZmqCommandName::HELLO, intro.clone()))
        .await?;

    // Receive WELCOME
    match raw_socket.read_half.next().await {
        Some(message) => match message? {
            Message::Command(ZmqCommandName::WELCOME, body) if body.is_empty() => (),
            _ => {
                return Err(CodecError::Handshake(
                    ZmqMechanism::PLAIN,
                    "Expected WELCOME",
                ))
            }
        },
        None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::PLAIN)),
    };

    // Send INITIATE
    raw_socket
        .write_half
        .send(Message::Command(ZmqCommandName::INITIATE, metadata.into()))
        .await?;

    // Receive and process READY
    match raw_socket.read_half.next().await {
        Some(message) => match message? {
            Message::Command(ZmqCommandName::READY, body) => Ok(ZmqMetadata::try_from(&body[..])?),
            _ => Err(CodecError::Handshake(ZmqMechanism::PLAIN, "Expected READY")),
        },
        None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::PLAIN)),
    }
}

pub async fn plain_server_auth(
    raw_socket: &mut FramedIo,
    metadata: &ZmqMetadata,
    callback: &dyn Authenticator,
) -> Result<ZmqMetadata, CodecError> {
    // Receive HELLO
    let hello = match raw_socket.read_half.next().await {
        Some(message) => match message? {
            Message::Command(ZmqCommandName::HELLO, body) => body,
            _ => return Err(CodecError::Handshake(ZmqMechanism::PLAIN, "Expected HELLO")),
        },
        None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::PLAIN)),
    };

    // Parse username and password. Input is checked to be >= 2 bytes
    let auth_req = match _parse_username_password(hello) {
        Some((username, password)) => AuthRequest::Plain { username, password },
        _ => {
            return Err(CodecError::Handshake(ZmqMechanism::PLAIN, "Invalid HELLO"));
        }
    };
    if !callback.authenticate(auth_req).await {
        return Err(CodecError::Handshake(
            ZmqMechanism::PLAIN,
            "Access denied by username and password",
        ));
    }

    // Send WELCOME
    raw_socket
        .write_half
        .send(Message::Command(ZmqCommandName::WELCOME, Bytes::new()))
        .await?;

    // Receive and process INITIATE
    let recv_metadata = match raw_socket.read_half.next().await {
        Some(message) => match message? {
            Message::Command(ZmqCommandName::INITIATE, body) => ZmqMetadata::try_from(&body[..])?,
            _ => {
                return Err(CodecError::Handshake(
                    ZmqMechanism::PLAIN,
                    "Expected INITIATE",
                ))
            }
        },
        None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::PLAIN)),
    };

    // Send READY
    raw_socket
        .write_half
        .send(Message::Command(ZmqCommandName::READY, metadata.into()))
        .await?;

    Ok(recv_metadata)
}
