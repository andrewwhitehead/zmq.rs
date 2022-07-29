use super::{connect_forever, peer::PeerIdentity, peer_connected};
use crate::auth::AuthMethod;
use crate::codec::{CodecError, FramedIo, ZmqMetadata};
use crate::endpoint::{Endpoint, TryIntoEndpoint};
use crate::error::{ZmqError, ZmqResult};
use crate::message::ZmqMessage;
use crate::transport::{self, AcceptStopHandle};

use async_trait::async_trait;
use futures::channel::mpsc;
use num_traits::ToPrimitive;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::sync::Arc;

const COMPATIBILITY_MATRIX: [u8; 121] = [
    // PAIR, PUB, SUB, REQ, REP, DEALER, ROUTER, PULL, PUSH, XPUB, XSUB
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // PAIR
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, // PUB
    0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, // SUB
    0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, // REQ
    0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, // REP
    0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, // DEALER
    0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, // ROUTER
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, // PULL
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, // PUSH
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, // XPUB
    0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, // XSUB
];

/// Checks if two sockets are compatible with each other
pub fn sockets_compatible(one: SocketType, another: SocketType) -> bool {
    let row_index = one.to_usize().unwrap();
    let col_index = another.to_usize().unwrap();
    COMPATIBILITY_MATRIX[row_index * 11 + col_index] != 0
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Primitive)]
pub enum SocketType {
    PAIR = 0,
    PUB = 1,
    SUB = 2,
    REQ = 3,
    REP = 4,
    DEALER = 5,
    ROUTER = 6,
    PULL = 7,
    PUSH = 8,
    XPUB = 9,
    XSUB = 10,
    STREAM = 11,
}

impl SocketType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SocketType::PAIR => "PAIR",
            SocketType::PUB => "PUB",
            SocketType::SUB => "SUB",
            SocketType::REQ => "REQ",
            SocketType::REP => "REP",
            SocketType::DEALER => "DEALER",
            SocketType::ROUTER => "ROUTER",
            SocketType::PULL => "PULL",
            SocketType::PUSH => "PUSH",
            SocketType::XPUB => "XPUB",
            SocketType::XSUB => "XSUB",
            SocketType::STREAM => "STREAM",
        }
    }
}

impl TryFrom<&[u8]> for SocketType {
    type Error = CodecError;

    fn try_from(s: &[u8]) -> Result<Self, CodecError> {
        Ok(match s {
            b"PAIR" => SocketType::PAIR,
            b"PUB" => SocketType::PUB,
            b"SUB" => SocketType::SUB,
            b"REQ" => SocketType::REQ,
            b"REP" => SocketType::REP,
            b"DEALER" => SocketType::DEALER,
            b"ROUTER" => SocketType::ROUTER,
            b"PULL" => SocketType::PULL,
            b"PUSH" => SocketType::PUSH,
            b"XPUB" => SocketType::XPUB,
            b"XSUB" => SocketType::XSUB,
            b"STREAM" => SocketType::STREAM,
            _ => return Err(CodecError::SocketType("Unknown socket type")),
        })
    }
}

impl TryFrom<&str> for SocketType {
    type Error = CodecError;

    #[inline]
    fn try_from(s: &str) -> Result<Self, CodecError> {
        Self::try_from(s.as_bytes())
    }
}

impl Display for SocketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum SocketEvent {
    Connected(Endpoint, PeerIdentity),
    ConnectDelayed,
    ConnectRetried,
    Listening(Endpoint),
    Accepted(Endpoint, PeerIdentity),
    AcceptFailed(ZmqError),
    Closed,
    CloseFailed,
    Disconnected(PeerIdentity),
}

#[derive(Default)]
pub struct SocketOptions {
    pub(crate) peer_id: Option<PeerIdentity>,
    pub(crate) auth: Arc<AuthMethod>,
}

impl SocketOptions {
    pub fn auth_method(&mut self, auth_method: AuthMethod) -> &mut Self {
        self.auth = Arc::new(auth_method);
        self
    }

    pub fn peer_identity(&mut self, peer_id: PeerIdentity) -> &mut Self {
        self.peer_id = Some(peer_id);
        self
    }
}

#[async_trait]
pub trait MultiPeerBackend: SocketBackend {
    /// This should not be public..
    /// Find a better way of doing this

    async fn peer_connected(self: Arc<Self>, peer_id: &PeerIdentity, io: FramedIo);
    fn peer_disconnected(&self, peer_id: &PeerIdentity);
}

pub trait SocketBackend: Send + Sync {
    fn socket_type(&self) -> SocketType;
    fn socket_options(&self) -> &SocketOptions;
    fn shutdown(&self);
    fn monitor(&self) -> &Mutex<Option<mpsc::Sender<SocketEvent>>>;
}

#[async_trait]
pub trait SocketRecv {
    async fn recv(&mut self) -> ZmqResult<ZmqMessage>;
}

#[async_trait]
pub trait SocketSend {
    async fn send(&mut self, message: ZmqMessage) -> ZmqResult<()>;
}

/// Marker trait that express the fact that only certain types of sockets might be used
/// in [proxy] function as a capture parameter
pub trait CaptureSocket: SocketSend {}

#[async_trait]
pub trait Socket: Sized + Send {
    fn new() -> Self {
        Self::with_options(SocketOptions::default())
    }

    fn with_options(options: SocketOptions) -> Self;

    fn backend(&self) -> Arc<dyn MultiPeerBackend>;

    /// Binds to the endpoint and starts a coroutine to accept new connections
    /// on it.
    ///
    /// Returns the endpoint resolved to the exact bound location if applicable
    /// (port # resolved, for example).
    async fn bind(&mut self, endpoint: &str) -> ZmqResult<Endpoint> {
        let endpoint = endpoint.try_into_endpoint()?;

        let backend = self.backend();
        let cloned_backend = backend.clone();
        let cback = move |result| {
            let cloned_backend = cloned_backend.clone();
            async move {
                let result = match result {
                    Ok((socket, metadata, endpoint)) => {
                        match peer_connected(socket, &metadata, cloned_backend.clone()).await {
                            Ok(peer_id) => Ok((endpoint, peer_id)),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok((endpoint, peer_id)) => {
                        if let Some(monitor) = cloned_backend.monitor().lock().as_mut() {
                            let _ = monitor.try_send(SocketEvent::Accepted(endpoint, peer_id));
                        }
                    }
                    Err(e) => {
                        if let Some(monitor) = cloned_backend.monitor().lock().as_mut() {
                            let _ = monitor.try_send(SocketEvent::AcceptFailed(e));
                        }
                    }
                }
            }
        };

        let opts = backend.socket_options();
        let socket_type = backend.socket_type();
        let metadata = ZmqMetadata {
            peer_id: opts.peer_id.clone(),
            socket_type,
        };
        let (endpoint, stop_handle) =
            transport::begin_accept(endpoint, opts.auth.clone(), metadata, cback).await?;

        if let Some(monitor) = backend.monitor().lock().as_mut() {
            let _ = monitor.try_send(SocketEvent::Listening(endpoint.clone()));
        }

        self.binds().insert(endpoint.clone(), stop_handle);
        Ok(endpoint)
    }

    fn binds(&mut self) -> &mut HashMap<Endpoint, AcceptStopHandle>;

    /// Unbinds the endpoint, blocking until the associated endpoint is no
    /// longer in use
    ///
    /// # Errors
    /// May give a `ZmqError::NoSuchBind` if `endpoint` isn't bound. May also
    /// give any other zmq errors encountered when attempting to disconnect
    async fn unbind(&mut self, endpoint: Endpoint) -> ZmqResult<()> {
        let stop_handle = self.binds().remove(&endpoint);
        let stop_handle = stop_handle.ok_or(ZmqError::NoSuchBind(endpoint))?;
        stop_handle.0.shutdown().await
    }

    /// Unbinds all bound endpoints, blocking until finished.
    async fn unbind_all(&mut self) -> Vec<ZmqError> {
        let mut errs = Vec::new();
        let endpoints: Vec<_> = self
            .binds()
            .iter()
            .map(|(endpoint, _)| endpoint.clone())
            .collect();
        for endpoint in endpoints {
            if let Err(err) = self.unbind(endpoint).await {
                errs.push(err);
            }
        }
        errs
    }

    /// Connects to the given endpoint.
    async fn connect(&mut self, endpoint: &str) -> ZmqResult<()> {
        let backend = self.backend();
        let endpoint = endpoint.try_into_endpoint()?;
        let opts = backend.socket_options();
        let socket_type = backend.socket_type();
        let metadata = ZmqMetadata {
            peer_id: opts.peer_id.clone(),
            socket_type,
        };

        let result = match connect_forever(endpoint, &*opts.auth, &metadata).await {
            Ok((socket, metadata, endpoint)) => {
                match peer_connected(socket, &metadata, backend).await {
                    Ok(peer_id) => Ok((endpoint, peer_id)),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };
        match result {
            Ok((endpoint, peer_id)) => {
                if let Some(monitor) = self.backend().monitor().lock().as_mut() {
                    let _ = monitor.try_send(SocketEvent::Connected(endpoint, peer_id));
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Creates and setups new socket monitor
    ///
    /// Subsequent calls to this method each create a new monitor channel.
    /// Sender side of previous one is dropped.
    fn monitor(&mut self) -> mpsc::Receiver<SocketEvent>;

    // TODO: async fn connections(&self) -> ?

    /// Disconnects from the given endpoint, blocking until finished.
    ///
    /// # Errors
    /// May give a `ZmqError::NoSuchConnection` if `endpoint` isn't connected.
    /// May also give any other zmq errors encountered when attempting to
    /// disconnect.
    // TODO: async fn disconnect(&mut self, endpoint: impl TryIntoEndpoint + 'async_trait) ->
    // ZmqResult<()>;

    /// Disconnects all connecttions, blocking until finished.
    // TODO: async fn disconnect_all(&mut self) -> ZmqResult<()>;

    /// Closes the socket, blocking until all associated binds are closed.
    /// This is equivalent to `drop()`, but with the benefit of blocking until
    /// resources are released, and getting any underlying errors.
    ///
    /// Returns any encountered errors.
    // TODO: Call disconnect_all() when added
    async fn close(mut self) -> Vec<ZmqError> {
        // self.disconnect_all().await?;
        self.unbind_all().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockets_compatible() {
        assert!(sockets_compatible(SocketType::PUB, SocketType::SUB));
        assert!(sockets_compatible(SocketType::REQ, SocketType::REP));
        assert!(sockets_compatible(SocketType::DEALER, SocketType::ROUTER));
        assert!(!sockets_compatible(SocketType::PUB, SocketType::REP));
    }
}
