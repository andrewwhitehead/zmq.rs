use super::{CodecError, Message, ZmqDecoder, ZmqEncoder};

use asynchronous_codec::{FramedRead, FramedWrite};
use futures::Stream;
use pin_project_lite::pin_project;
use std::fmt::{self, Debug};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

// Enables us to have multiple bounds on the dyn trait in `InnerFramed`
pub trait FrameableRead: futures::AsyncRead + Unpin + Send + Sync {}
impl<T> FrameableRead for T where T: futures::AsyncRead + Unpin + Send + Sync {}

pub trait FrameableWrite: futures::AsyncWrite + Unpin + Send + Sync {}
impl<T> FrameableWrite for T where T: futures::AsyncWrite + Unpin + Send + Sync {}

// Wrapper types are used here in order to provide a Debug implementation as well
// as work around a rustc error involving the interaction between async_trait and
// dashmap: https://github.com/dtolnay/async-trait/issues/141

pin_project! {
    pub struct ZmqFramedRead {
        #[pin]
        inner: asynchronous_codec::FramedRead<Box<dyn FrameableRead>, ZmqDecoder>,
    }
}

impl Debug for ZmqFramedRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZmqFramedRead {..}")
    }
}

impl Deref for ZmqFramedRead {
    type Target = asynchronous_codec::FramedRead<Box<dyn FrameableRead>, ZmqDecoder>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ZmqFramedRead {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Stream for ZmqFramedRead {
    type Item = Result<Message, CodecError>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

pin_project! {
    pub struct ZmqFramedWrite {
        #[pin]
        inner: asynchronous_codec::FramedWrite<Box<dyn FrameableWrite>, ZmqEncoder>
    }
}

impl ZmqFramedWrite {
    #[inline]
    pub(crate) fn inner(
        self: Pin<&mut Self>,
    ) -> Pin<&mut asynchronous_codec::FramedWrite<Box<dyn FrameableWrite>, ZmqEncoder>> {
        self.project().inner
    }
}

impl Debug for ZmqFramedWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZmqFramedWrite {..}")
    }
}

impl Deref for ZmqFramedWrite {
    type Target = asynchronous_codec::FramedWrite<Box<dyn FrameableWrite>, ZmqEncoder>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ZmqFramedWrite {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Equivalent to [`asynchronous_codec::Framed<T, ZmqCodec>`]
pub struct FramedIo {
    pub read_half: ZmqFramedRead,
    pub write_half: ZmqFramedWrite,
}

impl FramedIo {
    pub fn new(read_half: Box<dyn FrameableRead>, write_half: Box<dyn FrameableWrite>) -> Self {
        let read_half = ZmqFramedRead {
            inner: FramedRead::new(read_half, ZmqDecoder::new()),
        };
        let write_half = ZmqFramedWrite {
            inner: FramedWrite::new(write_half, ZmqEncoder::new()),
        };
        Self {
            read_half,
            write_half,
        }
    }

    pub fn into_parts(self) -> (ZmqFramedRead, ZmqFramedWrite) {
        (self.read_half, self.write_half)
    }
}
