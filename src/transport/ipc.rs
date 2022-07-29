#[cfg(feature = "tokio-runtime")]
use tokio::net::{UnixListener, UnixStream};

#[cfg(feature = "async-std-runtime")]
use async_std::os::unix::net::{UnixListener, UnixStream};

use super::init_socket;
use super::AcceptStopHandle;
use crate::async_rt;
use crate::auth::AuthMethod;
use crate::codec::FramedIo;
use crate::codec::ZmqMetadata;
use crate::endpoint::Endpoint;
use crate::task_handle::TaskHandle;
use crate::ZmqResult;

use futures::{select, FutureExt};
use std::path::Path;
use std::sync::Arc;

pub(crate) async fn connect(
    path: &Path,
    auth: &AuthMethod,
    metadata: &ZmqMetadata,
) -> ZmqResult<(FramedIo, ZmqMetadata, Endpoint)> {
    let raw_socket = UnixStream::connect(path).await?;
    let peer_addr = raw_socket.peer_addr()?;
    let peer_addr = peer_addr.as_pathname().map(|a| a.to_owned());
    let (framed, recv_meta) = init_socket(raw_socket, auth, metadata).await?;
    Ok((framed, recv_meta, Endpoint::Ipc(peer_addr)))
}

pub(crate) async fn begin_accept<T>(
    path: &Path,
    auth: Arc<AuthMethod>,
    metadata: ZmqMetadata,
    cback: impl Fn(ZmqResult<(FramedIo, ZmqMetadata, Endpoint)>) -> T + Send + 'static,
) -> ZmqResult<(Endpoint, AcceptStopHandle)>
where
    T: std::future::Future<Output = ()> + Send + 'static,
{
    let wildcard: &Path = "*".as_ref();
    if path == wildcard {
        todo!("Need to implement support for wildcard paths!");
    }

    #[cfg(feature = "tokio-runtime")]
    let listener = UnixListener::bind(path)?;
    #[cfg(feature = "async-std-runtime")]
    let listener = UnixListener::bind(path).await?;

    let resolved_addr = listener.local_addr()?;
    let resolved_addr = resolved_addr.as_pathname().map(|a| a.to_owned());
    let listener_addr = resolved_addr.clone();
    let (stop_channel, stop_callback) = futures::channel::oneshot::channel::<()>();
    let task_handle = async_rt::task::spawn(async move {
        let mut stop_callback = stop_callback.fuse();
        loop {
            select! {
                incoming = listener.accept().fuse() => {
                    let maybe_accepted = match incoming {
                        Ok((raw_socket, peer_addr)) => {
                            let peer_addr = peer_addr.as_pathname().map(|a| a.to_owned());
                            let (framed, recv_meta) = init_socket(raw_socket, &auth, &metadata).await?;
                            Ok((framed, recv_meta, Endpoint::Ipc(peer_addr)))
                        },
                        Err(e) => Err(e.into())
                    };
                    async_rt::task::spawn(cback(maybe_accepted));
                },
                _ = stop_callback => {
                    log::debug!("Accept task received stop signal. {:?}", listener_addr);
                    break
                }
            }
        }
        drop(listener);
        if let Some(listener_addr) = listener_addr {
            #[cfg(feature = "async-std-runtime")]
            use async_std::fs::remove_file;
            #[cfg(feature = "tokio-runtime")]
            use tokio::fs::remove_file;

            if let Err(err) = remove_file(&listener_addr).await {
                log::warn!(
                    "Could not delete unix socket at {}: {}",
                    listener_addr.display(),
                    err
                );
            }
        }
        Ok(())
    });
    Ok((
        Endpoint::Ipc(resolved_addr),
        AcceptStopHandle(TaskHandle::new(stop_channel, task_handle)),
    ))
}
