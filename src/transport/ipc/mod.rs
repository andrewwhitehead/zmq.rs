// TODO: Conditionally compile things
mod tokio;

use self::tokio as tk;
use crate::codec::FramedIo;
use crate::endpoint::Endpoint;
use crate::transport::AcceptStopChannel;
use crate::ZmqResult;

use std::path::PathBuf;

pub(crate) async fn connect(path: PathBuf) -> ZmqResult<(FramedIo, Endpoint)> {
    tk::connect(path).await
}

pub(crate) async fn begin_accept<T>(
    path: PathBuf,
    cback: impl Fn(ZmqResult<(FramedIo, Endpoint)>) -> T + Send + 'static,
) -> ZmqResult<(Endpoint, AcceptStopChannel)>
where
    T: std::future::Future<Output = ()> + Send + 'static,
{
    tk::begin_accept(path, cback).await
}
