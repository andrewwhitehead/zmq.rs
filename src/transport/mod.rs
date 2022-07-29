#[cfg(feature = "ipc-transport")]
mod ipc;
#[cfg(feature = "tcp-transport")]
mod tcp;

use std::future::Future;
use std::sync::Arc;

use crate::codec::{CodecError, FramedIo, ZmqMetadata};
use crate::endpoint::Endpoint;
use crate::handshake::perform_handshake;
use crate::task_handle::TaskHandle;
use crate::{AuthMethod, ZmqResult};

macro_rules! do_if_enabled {
    ($feature:literal, $body:expr) => {{
        #[cfg(feature = $feature)]
        {
            $body
        }

        #[cfg(not(feature = $feature))]
        panic!(format!("feature \"{}\" is not enabled", $feature))
    }};
}

/// Connects to the given endpoint
///
/// # Panics
/// Panics if the requested endpoint uses a transport type that isn't enabled
pub(crate) async fn connect(
    endpoint: &Endpoint,
    auth: &AuthMethod,
    metadata: &ZmqMetadata,
) -> ZmqResult<(FramedIo, ZmqMetadata, Endpoint)> {
    match endpoint {
        Endpoint::Tcp(host, port) => {
            do_if_enabled!(
                "tcp-transport",
                tcp::connect(host, *port, auth, metadata).await
            )
        }
        Endpoint::Ipc(path) => do_if_enabled!(
            "ipc-transport",
            if let Some(path) = path {
                ipc::connect(path, auth, metadata).await
            } else {
                Err(crate::error::ZmqError::Socket(
                    "Cannot connect to an unnamed ipc socket",
                ))
            }
        ),
    }
}

pub struct AcceptStopHandle(pub(crate) TaskHandle<()>);

/// Spawns an async task that listens for connections at the provided endpoint.
///
/// `cback` will be invoked when a connection is accepted. If the result was
/// `Ok`, it will receive a tuple containing the framed raw socket, along with
/// the endpoint of the remote connection accepted.
///
/// Returns a ZmqResult, which when Ok is a tuple of the resolved bound
/// endpoint, as well as a channel to stop the async accept task
///
/// # Panics
/// Panics if the requested endpoint uses a transport type that isn't enabled
pub(crate) async fn begin_accept<T>(
    endpoint: Endpoint,
    auth: Arc<AuthMethod>,
    metadata: ZmqMetadata,
    cback: impl Fn(ZmqResult<(FramedIo, ZmqMetadata, Endpoint)>) -> T + Send + 'static,
) -> ZmqResult<(Endpoint, AcceptStopHandle)>
where
    T: std::future::Future<Output = ()> + Send + 'static,
{
    match endpoint {
        Endpoint::Tcp(host, port) => {
            do_if_enabled!(
                "tcp-transport",
                tcp::begin_accept(host, port, auth, metadata, cback).await
            )
        }
        Endpoint::Ipc(_path) => do_if_enabled!(
            "ipc-transport",
            if let Some(path) = _path {
                ipc::begin_accept(&path, auth, metadata, cback).await
            } else {
                Err(crate::error::ZmqError::Socket(
                    "Cannot begin accepting peers at an unnamed ipc socket",
                ))
            }
        ),
    }
}

async fn _init_socket<T>(
    stream: T,
    auth: &AuthMethod,
    metadata: &ZmqMetadata,
) -> Result<(FramedIo, ZmqMetadata), CodecError>
where
    T: futures::AsyncRead + futures::AsyncWrite + Send + Sync + 'static,
{
    perform_handshake(stream, auth, metadata).await
}

#[cfg(feature = "tokio-runtime")]
fn init_socket<'a, T>(
    stream: T,
    auth: &'a AuthMethod,
    metadata: &'a ZmqMetadata,
) -> impl Future<Output = Result<(FramedIo, ZmqMetadata), CodecError>> + 'a
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + 'static,
{
    use tokio_util::compat::TokioAsyncReadCompatExt;
    _init_socket(stream.compat(), auth, metadata)
}

#[cfg(feature = "async-std-runtime")]
fn init_socket<T>(
    stream: T,
    auth: &AuthMethod,
    metadata: ZmqMetadata,
) -> impl Future<Output = ZmqResult<FramedIo>> + '_
where
    T: futures::AsyncRead + futures::AsyncWrite + Send + Sync + 'static,
{
    _init_socket(stream, auth, metadata)
}
