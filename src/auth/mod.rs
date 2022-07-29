#[cfg(feature = "curvezmq")]
mod curve;
mod null;
mod plain;

use crate::codec::{CodecError, FramedIo, ZmqMechanism, ZmqMetadata};
use crate::error::{ZmqError, ZmqResult};

use bytes::{BufMut, Bytes, BytesMut};
use futures::future::BoxFuture;
use std::convert::TryFrom;
use std::fmt::{self, Debug};
use std::future::Future;

#[cfg(feature = "curvezmq")]
use self::curve::{curve_client_auth, curve_server_auth};
use self::null::null_auth;
use self::plain::{plain_client_auth, plain_server_auth};

#[cfg(feature = "curvezmq")]
pub use self::curve::CurveKeyPair;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthRequest {
    Plain { username: String, password: String },
    Curve { public_key: [u8; 32] },
}

pub trait Authenticator: Debug + Send + Sync {
    fn authenticate(&self, req: AuthRequest) -> BoxFuture<'static, bool>;
}

struct AuthCallback<F>(F);

impl<F> Debug for AuthCallback<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthCallback")
    }
}

impl<F> Authenticator for AuthCallback<F>
where
    F: Fn(AuthRequest) -> BoxFuture<'static, bool> + Send + Sync,
{
    fn authenticate(&self, req: AuthRequest) -> BoxFuture<'static, bool> {
        self.0(req)
    }
}

#[derive(Debug)]
pub(crate) enum AuthMethodInner {
    Null,
    PlainClient {
        intro: Bytes,
    },
    PlainServer {
        callback: Box<dyn Authenticator>,
    },
    #[cfg(feature = "curvezmq")]
    CurveClient {
        server_public_key: [u8; 32],
        keypair: CurveKeyPair,
    },
    #[cfg(feature = "curvezmq")]
    CurveServer {
        keypair: CurveKeyPair,
        callback: Option<Box<dyn Authenticator>>,
    },
}

impl Default for AuthMethodInner {
    fn default() -> Self {
        Self::Null
    }
}

#[derive(Debug, Default)]
pub struct AuthMethod {
    inner: AuthMethodInner,
}

impl AuthMethod {
    /// The NULL (non-)authentication method.
    pub fn null() -> Self {
        AuthMethodInner::Null.into()
    }

    /// Authenticate with a server using PLAIN.
    pub fn plain_client(username: impl AsRef<str>, password: impl AsRef<str>) -> ZmqResult<Self> {
        let username = username.as_ref();
        let password = password.as_ref();
        let uname_len = username.len();
        let passw_len = username.len();
        let mut intro = BytesMut::with_capacity(uname_len + passw_len + 2);
        let uname_len = u8::try_from(username.len())
            .map_err(|_| ZmqError::Authentication("Exceeded maximum length for user name"))?;
        let passw_len = u8::try_from(password.len())
            .map_err(|_| ZmqError::Authentication("Exceeded maximum length for password"))?;
        intro.put_u8(uname_len);
        intro.extend_from_slice(username.as_bytes());
        intro.put_u8(passw_len);
        intro.extend_from_slice(password.as_bytes());
        Ok(AuthMethodInner::PlainClient {
            intro: intro.freeze(),
        }
        .into())
    }

    // /// Apply PLAIN authentication as a server.
    pub fn plain_server<F, A>(callback: F) -> ZmqResult<Self>
    where
        F: Fn(AuthRequest) -> A + Send + Sync + 'static,
        A: Future<Output = bool> + Send + 'static,
    {
        Ok(AuthMethodInner::PlainServer {
            callback: Box::new(AuthCallback(move |req| {
                Box::pin(callback(req)) as BoxFuture<'static, bool>
            })),
        }
        .into())
    }

    #[cfg(feature = "curvezmq")]
    /// Authenticate with a server using CURVE.
    pub fn curve_client(server_public_key: [u8; 32], keypair: CurveKeyPair) -> ZmqResult<Self> {
        Ok(AuthMethodInner::CurveClient {
            server_public_key,
            keypair,
        }
        .into())
    }

    #[cfg(feature = "curvezmq")]
    /// Apply CURVE authentication as a server.
    pub fn curve_server<F, A>(keypair: CurveKeyPair, callback: F) -> ZmqResult<Self>
    where
        F: Fn(AuthRequest) -> A + Send + Sync + 'static,
        A: Future<Output = bool> + Send + 'static,
    {
        Ok(AuthMethodInner::CurveServer {
            keypair,
            callback: Some(Box::new(AuthCallback(move |req| {
                Box::pin(callback(req)) as BoxFuture<'static, bool>
            }))),
        }
        .into())
    }

    #[cfg(feature = "curvezmq")]
    /// Apply CURVE authentication as a server.
    pub fn curve_server_noverify(keypair: CurveKeyPair) -> ZmqResult<Self> {
        Ok(AuthMethodInner::CurveServer {
            keypair,
            callback: None,
        }
        .into())
    }

    pub(crate) fn mechanism(&self) -> ZmqMechanism {
        match &self.inner {
            AuthMethodInner::Null => ZmqMechanism::NULL,
            AuthMethodInner::PlainClient { .. } | AuthMethodInner::PlainServer { .. } => {
                ZmqMechanism::PLAIN
            }
            #[cfg(feature = "curvezmq")]
            AuthMethodInner::CurveClient { .. } | AuthMethodInner::CurveServer { .. } => {
                ZmqMechanism::CURVE
            }
        }
    }

    pub(crate) async fn perform_auth(
        &self,
        raw_socket: &mut FramedIo,
        metadata: &ZmqMetadata,
    ) -> Result<ZmqMetadata, CodecError> {
        match &self.inner {
            AuthMethodInner::Null => null_auth(raw_socket, metadata).await,
            AuthMethodInner::PlainClient { intro } => {
                plain_client_auth(raw_socket, intro, metadata).await
            }
            AuthMethodInner::PlainServer { callback } => {
                plain_server_auth(raw_socket, metadata, &**callback).await
            }
            #[cfg(feature = "curvezmq")]
            AuthMethodInner::CurveClient {
                server_public_key,
                keypair,
            } => curve_client_auth(raw_socket, server_public_key, keypair, metadata).await,
            #[cfg(feature = "curvezmq")]
            AuthMethodInner::CurveServer { keypair, callback } => {
                curve_server_auth(raw_socket, keypair, metadata, callback.as_deref()).await
            }
        }
    }
}

impl From<AuthMethodInner> for AuthMethod {
    fn from(inner: AuthMethodInner) -> Self {
        Self { inner }
    }
}

pub(crate) trait SharedKey: Debug + Send + Sync {
    fn encode_frame(&self, frame: &[u8], dst: &mut BytesMut, more: bool) -> Result<(), CodecError>;
    fn decode_frame(&self, buf: &mut BytesMut) -> Result<bool, CodecError>;
}
