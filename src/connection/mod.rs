pub(crate) mod handshake;
pub(crate) mod peer;
pub(crate) mod socket;

use crate::async_rt;
use crate::auth::AuthMethod;
use crate::codec::{FramedIo, ZmqMetadata};
use crate::endpoint::Endpoint;
use crate::error::{ZmqError, ZmqResult};
use crate::transport;

use futures_util::FutureExt;
use num_traits::Pow;
use rand::Rng;
use std::sync::Arc;

pub use self::peer::PeerIdentity;
pub use self::socket::{
    sockets_compatible, CaptureSocket, MultiPeerBackend, Socket, SocketBackend, SocketEvent,
    SocketOptions, SocketRecv, SocketSend, SocketType,
};

pub(crate) async fn peer_connected(
    raw_socket: FramedIo,
    metadata: &ZmqMetadata,
    backend: Arc<dyn MultiPeerBackend>,
) -> ZmqResult<PeerIdentity> {
    let peer_id = metadata.peer_id.clone().unwrap_or_default();
    backend.peer_connected(&peer_id, raw_socket).await;
    Ok(peer_id)
}

pub(crate) async fn connect_forever(
    endpoint: Endpoint,
    auth: &AuthMethod,
    metadata: &ZmqMetadata,
) -> ZmqResult<(FramedIo, ZmqMetadata, Endpoint)> {
    let mut try_num: u64 = 0;
    loop {
        match transport::connect(&endpoint, auth, metadata).await {
            Ok(res) => return Ok(res),
            Err(ZmqError::Network(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                if try_num < 5 {
                    try_num += 1;
                }
                let delay = {
                    let mut rng = rand::thread_rng();
                    std::f64::consts::E.pow(try_num as f64 / 3.0) + rng.gen_range(0.0f64..0.1f64)
                };
                async_rt::task::sleep(std::time::Duration::from_secs_f64(delay)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Automatically proxy messages between two sockets.
pub async fn proxy<Frontend: SocketSend + SocketRecv, Backend: SocketSend + SocketRecv>(
    mut frontend: Frontend,
    mut backend: Backend,
    mut capture: Option<Box<dyn CaptureSocket>>,
) -> ZmqResult<()> {
    loop {
        futures::select! {
            frontend_mess = frontend.recv().fuse() => {
                match frontend_mess {
                    Ok(message) => {
                        if let Some(capture) = &mut capture {
                            capture.send(message.clone()).await?;
                        }
                        backend.send(message).await?;
                    }
                    Err(_) => {
                        todo!()
                    }
                }
            },
            backend_mess = backend.recv().fuse() => {
                match backend_mess {
                    Ok(message) => {
                        if let Some(capture) = &mut capture {
                            capture.send(message.clone()).await?;
                        }
                        frontend.send(message).await?;
                    }
                    Err(_) => {
                        todo!()
                    }
                }
            }
        };
    }
}
