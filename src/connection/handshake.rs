use super::socket::sockets_compatible;
use crate::auth::AuthMethod;
use crate::codec::{CodecError, FramedIo, ZmqGreeting, ZmqMetadata, GREETING_LENGTH};

use std::convert::TryFrom;

pub(crate) async fn perform_handshake<T>(
    stream: T,
    auth: &AuthMethod,
    metadata: &ZmqMetadata,
) -> Result<(FramedIo, ZmqMetadata), CodecError>
where
    T: futures::AsyncRead + futures::AsyncWrite + Send + Sync + 'static,
{
    use futures::AsyncReadExt;

    let (mut read, mut write) = stream.split();
    let send_greet = ZmqGreeting::from(auth.mechanism());
    let recv_greet = exchange_greeting(&mut read, &mut write, send_greet).await?;
    let _negot_greet = negotiate_greeting(send_greet, recv_greet)?;

    let mut io = FramedIo::new(Box::new(read), Box::new(write));
    let recv_meta = auth.perform_auth(&mut io, metadata).await?;

    if !sockets_compatible(recv_meta.socket_type, metadata.socket_type) {
        return Err(CodecError::SocketType("Incompatible socket type").into());
    }
    Ok((io, recv_meta))
}

async fn exchange_greeting<R, W>(
    read: &mut R,
    write: &mut W,
    send_greeting: ZmqGreeting,
) -> Result<ZmqGreeting, CodecError>
where
    R: futures::AsyncRead + Unpin + ?Sized,
    W: futures::AsyncWrite + Unpin + ?Sized,
{
    use futures::{future::join, AsyncReadExt, AsyncWriteExt};

    let send_greet_buf = send_greeting.to_bytes();

    let mut recv_greet_buf = [0u8; GREETING_LENGTH];

    let send = write.write_all(&send_greet_buf);

    let recv = read.read_exact(&mut recv_greet_buf);
    match join(send, recv).await {
        (Ok(_), Ok(_)) => {}
        (Err(e), _) | (_, Err(e)) => return Err(e.into()),
    }

    Ok(ZmqGreeting::try_from(&recv_greet_buf[..])?)
}

/// Given the result of the greeting exchange, determines the version of the
/// ZMTP protocol that should be used for communication with the peer according
/// to https://rfc.zeromq.org/spec/23/#version-negotiation.
fn negotiate_greeting(
    send_greeting: ZmqGreeting,
    mut recv_greeting: ZmqGreeting,
) -> Result<ZmqGreeting, CodecError> {
    if recv_greeting.version < send_greeting.version {
        // A peer MAY downgrade its protocol to talk to a lower protocol peer.
        //
        // If a peer cannot downgrade its protocol to match its peer, it MUST
        // close the connection.
        // TODO: implement interoperability with older protocol versions
        return Err(CodecError::UnsupportedVersion(recv_greeting.version));
    } else {
        // A peer MUST accept higher protocol versions as valid. That is,
        // a ZMTP peer MUST accept protocol versions greater or equal to 3.0.
        // This allows future implementations to safely interoperate with
        // current implementations.
        //
        // A peer SHALL always use its own protocol (including framing)
        // when talking to an equal or higher protocol peer.
        recv_greeting.version = send_greeting.version;
    }

    if recv_greeting.mechanism != send_greeting.mechanism {
        // There is no negotiation of authentication mechanisms, the
        // peer must select the same authentication mechanism.
        return Err(CodecError::UnsupportedMechanism(recv_greeting.mechanism));
    }

    Ok(recv_greeting)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::async_rt;
    use crate::codec::{ZmqMechanism, ZmtpVersion, ZMTP_VERSION};

    fn new_greeting(version: ZmtpVersion, mechanism: ZmqMechanism) -> ZmqGreeting {
        ZmqGreeting {
            version,
            mechanism,
            as_server: false,
        }
    }

    #[async_rt::test]
    async fn exchange_greeting_peer_is_using_the_same_version_mechanism() {
        let peer_greet = new_greeting(ZMTP_VERSION, Default::default());
        let our_greet = new_greeting((99, 1), Default::default());
        let mut greet_in = &peer_greet.to_bytes()[..];
        let mut greet_out = Vec::new();

        let recv_greet = exchange_greeting(&mut greet_in, &mut greet_out, our_greet)
            .await
            .expect("Error exchanging greeting");
        assert_eq!(recv_greet, peer_greet);
        let send_greet =
            ZmqGreeting::try_from(&*greet_out).expect("Error parsing received greeting");
        assert_eq!(send_greet, our_greet);
    }

    #[async_rt::test]
    async fn exchange_greeting_interrupted() {
        let mut greet_in = &b"\x01\x02\x03"[..];
        let mut greet_out = Vec::new();

        let result = exchange_greeting(&mut greet_in, &mut greet_out, ZmqGreeting::default()).await;
        match result {
            Err(CodecError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
            _ => panic!("Unexpected result: {:?}", result),
        }
    }

    #[async_rt::test]
    async fn exchange_greeting_invalid() {
        let mut greet_in = &[0u8; 64][..]; // invalid greeting
        let mut greet_out = Vec::new();

        let result = exchange_greeting(&mut greet_in, &mut greet_out, ZmqGreeting::default()).await;
        match result {
            Err(CodecError::Greeting(..)) => {}
            _ => panic!("Unexpected result: {:?}", result),
        }
    }

    #[test]
    fn negotiate_greeting_peer_is_using_the_same_version() {
        // if both peers are using the same protocol version, negotiation is trivial
        let peer_greeting = ZmqGreeting::default();
        let our_greeting = ZmqGreeting::default();
        let result =
            negotiate_greeting(our_greeting, peer_greeting).expect("Error negotiating greeting");
        assert_eq!(result.version, our_greeting.version);
    }

    #[test]
    fn negotiate_greeting_peer_is_using_a_newer_version() {
        // if the other end is using a newer protocol version, they should adjust to us
        let peer_greeting = new_greeting((3, 1), Default::default());
        let our_greeting = ZmqGreeting::default();
        let result =
            negotiate_greeting(our_greeting, peer_greeting).expect("Error negotiating greeting");
        assert_eq!(result.version, our_greeting.version);
    }

    #[test]
    fn negotiate_greeting_peer_is_using_an_older_version() {
        // if the other end is using an older protocol version, we should adjust to
        // them, but interoperability with older peers is not implemented at the
        // moment, so we just give up immediately, which is allowed by the spec
        let peer_greeting = new_greeting((2, 1), Default::default());
        let our_greeting = ZmqGreeting::default();
        let result = negotiate_greeting(our_greeting, peer_greeting);
        match result {
            Err(CodecError::UnsupportedVersion(version)) => {
                assert_eq!(version, peer_greeting.version)
            }
            _ => panic!("Unexpected result: {:?}", result),
        }
    }
}
