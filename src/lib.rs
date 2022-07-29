#![recursion_limit = "1024"]

mod async_rt;
mod auth;
mod backend;
mod codec;
mod connection;
mod dealer;
mod endpoint;
mod error;
mod fair_queue;
mod message;
mod r#pub;
mod pull;
mod push;
mod rep;
mod req;
mod router;
mod sub;
mod task_handle;
mod transport;
mod util;

#[doc(hidden)]
pub mod __async_rt {
    //! DO NOT USE! PRIVATE IMPLEMENTATION, EXPOSED ONLY FOR INTEGRATION TESTS.
    pub use super::async_rt::*;
}

pub use crate::auth::*;
pub use crate::connection::*;
pub use crate::dealer::*;
pub use crate::endpoint::{Endpoint, Host, Transport, TryIntoEndpoint};
pub use crate::error::{ZmqError, ZmqResult};
pub use crate::message::*;
pub use crate::pull::*;
pub use crate::push::*;
pub use crate::r#pub::*;
pub use crate::rep::*;
pub use crate::req::*;
pub use crate::router::*;
pub use crate::sub::*;

#[macro_use]
extern crate enum_primitive_derive;

pub mod prelude {
    //! Re-exports important traits. Consider glob-importing.

    pub use crate::{
        connection::{Socket, SocketRecv, SocketSend},
        endpoint::TryIntoEndpoint,
    };
}
