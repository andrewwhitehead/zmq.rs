//! Implements a codec for ZMQ, providing a way to convert from a byte-oriented
//! io device to a protocol comprised of [`Message`] frames. See [`FramedIo`]

mod command;
mod error;
mod framed;
mod greeting;
mod mechanism;
mod metadata;
mod zmq_codec;

pub(crate) use command::ZmqCommandName;
pub(crate) use error::CodecError;
pub(crate) use framed::{FramedIo, ZmqFramedRead, ZmqFramedWrite};
pub(crate) use greeting::{ZmqGreeting, ZmtpVersion, GREETING_LENGTH};
pub(crate) use mechanism::ZmqMechanism;
pub(crate) use metadata::ZmqMetadata;
pub(crate) use zmq_codec::{ZmqDecoder, ZmqEncoder};

use crate::message::ZmqMessage;
use crate::{ZmqError, ZmqResult};

use bytes::{Bytes, BytesMut};
use futures::task::Poll;
use futures::Sink;
use std::pin::Pin;

pub const ZMTP_VERSION: ZmtpVersion = (3, 0);

#[derive(Debug, Clone)]
pub enum Message {
    Command(ZmqCommandName, Bytes),
    Message(ZmqMessage),
}

pub(crate) trait TrySend {
    fn try_send(self: Pin<&mut Self>, item: Message) -> ZmqResult<()>;
}

impl TrySend for ZmqFramedWrite {
    fn try_send(mut self: Pin<&mut Self>, item: Message) -> ZmqResult<()> {
        let waker = futures::task::noop_waker();
        let mut cx = futures::task::Context::from_waker(&waker);
        match self.as_mut().inner().poll_ready(&mut cx) {
            Poll::Ready(Ok(())) => {
                self.as_mut().inner().start_send(item)?;
                let _ = self.as_mut().inner().poll_flush(&mut cx); // ignore result just hope that it flush eventually
                Ok(())
            }
            Poll::Ready(Err(e)) => Err(e.into()),
            Poll::Pending => Err(ZmqError::BufferFull("Sink is full")),
        }
    }
}

pub trait EncodeMessage {
    fn encode(&self, dst: &mut BytesMut) -> ZmqResult<()>;
}
