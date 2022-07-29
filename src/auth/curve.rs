use super::{AuthRequest, Authenticator, SharedKey};
use crate::codec::{CodecError, FramedIo, Message, ZmqCommandName, ZmqMechanism, ZmqMetadata};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crypto_box::aead::AeadInPlace;
use crypto_box::{self, aead::generic_array::GenericArray, SalsaBox};
use futures::{SinkExt, StreamExt};
use rand::{thread_rng, CryptoRng, RngCore};
use std::convert::TryFrom;
use std::fmt::{self, Debug};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const NONCE_PREFIX_CLIENT: &[u8] = b"CurveZMQMESSAGEC";
const NONCE_PREFIX_SERVER: &[u8] = b"CurveZMQMESSAGES";
const TAG_LENGTH: usize = 16;

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Clone)]
pub struct CurveKeyPair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

impl CurveKeyPair {
    pub fn new() -> Self {
        Self::new_with_rng(rand::thread_rng())
    }

    pub fn new_with_rng(mut rng: impl RngCore + CryptoRng) -> Self {
        let sk = crypto_box::SecretKey::generate(&mut rng);
        let pk = sk.public_key();
        Self {
            public_key: *pk.as_bytes(),
            secret_key: *sk.as_bytes(),
        }
    }
}

impl From<[u8; 32]> for CurveKeyPair {
    fn from(data: [u8; 32]) -> Self {
        let sk = crypto_box::SecretKey::from(data);
        let pk = sk.public_key();
        Self {
            public_key: *pk.as_bytes(),
            secret_key: *sk.as_bytes(),
        }
    }
}

impl TryFrom<&[u8]> for CurveKeyPair {
    type Error = CodecError;

    fn try_from(data: &[u8]) -> Result<Self, CodecError> {
        if let Ok(sk) = <[u8; 32]>::try_from(&data[..]) {
            Ok(Self::from(sk))
        } else {
            Err(CodecError::Other(
                "Curve secret key should be 32 bytes long",
            ))
        }
    }
}

impl From<CurveKeyPair> for Vec<u8> {
    fn from(kp: CurveKeyPair) -> Self {
        kp.secret_key.to_vec()
    }
}

impl From<CurveKeyPair> for Bytes {
    fn from(kp: CurveKeyPair) -> Self {
        Bytes::copy_from_slice(&kp.secret_key)
    }
}

struct CurveSharedKey {
    as_server: bool,
    send_nonce: AtomicU64,
    key: SalsaBox,
}

impl Debug for CurveSharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurveSharedKey {..}")
    }
}

impl SharedKey for CurveSharedKey {
    fn encode_frame(&self, frame: &[u8], dst: &mut BytesMut, more: bool) -> Result<(), CodecError> {
        const META_LEN: u64 = (8 + 8 + TAG_LENGTH + 1) as u64;
        const MAX_LEN: u64 = u64::MAX - META_LEN - 9;
        if (frame.len() as u64) > MAX_LEN {
            return Err(CodecError::Encryption(
                "Encryption error: exceeded maximum frame length",
            ));
        }
        let body_len = META_LEN + (frame.len() as u64);
        if body_len > 255 {
            dst.reserve((body_len + 9) as usize);
            dst.put_u8(0b0000_0010);
            dst.put_u64(body_len as u64);
        } else {
            dst.reserve((body_len + 2) as usize);
            dst.put_u8(0b0000_0000);
            dst.put_u8(body_len as u8);
        };
        dst.extend_from_slice(b"\x07MESSAGE");
        let nonce_short = self
            .send_nonce
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes();
        let mut nonce_long = GenericArray::default();
        nonce_long[..16].copy_from_slice(if self.as_server {
            NONCE_PREFIX_SERVER
        } else {
            NONCE_PREFIX_CLIENT
        });
        nonce_long[16..].copy_from_slice(&nonce_short);
        dst.extend_from_slice(&nonce_short);
        let box_start = dst.len();
        let frame_flags = if more { 0x1 } else { 0x0 };
        dst.put_bytes(0, TAG_LENGTH);
        dst.put_u8(frame_flags);
        dst.extend_from_slice(frame);
        let tag = self
            .key
            .encrypt_in_place_detached(&nonce_long, &[], &mut dst[box_start + TAG_LENGTH..])
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Encryption error"))?;
        dst[box_start..box_start + TAG_LENGTH].copy_from_slice(&tag);
        Ok(())
    }

    fn decode_frame(&self, buf: &mut BytesMut) -> Result<bool, CodecError> {
        if buf.len() < 33 || &buf[..8] != b"\x07MESSAGE" {
            return Err(CodecError::Encryption("Invalid message frame"));
        }
        let mut nonce_long = GenericArray::default();
        nonce_long[..16].copy_from_slice(if self.as_server {
            NONCE_PREFIX_CLIENT
        } else {
            NONCE_PREFIX_SERVER
        });
        nonce_long[16..].copy_from_slice(&buf[8..16]);
        buf.advance(16);
        let tag = buf.split_to(TAG_LENGTH);
        let tag = GenericArray::from_slice(&tag);
        self.key
            .decrypt_in_place_detached(&nonce_long, &[], &mut buf[..], tag)
            .map_err(|_| CodecError::Encryption("Decryption error"))?;
        let more = buf[0] & 1 == 1;
        buf.advance(1);
        Ok(more)
    }
}

pub async fn curve_client_auth(
    raw_socket: &mut FramedIo,
    server_public_key: &[u8; 32],
    keypair: &CurveKeyPair,
    metadata: &ZmqMetadata,
) -> Result<ZmqMetadata, CodecError> {
    let mut hello_nonce = [0u8; 8];
    let mut vouch_nonce = [0u8; 16];
    let ephemeral_sk = {
        let mut rng = thread_rng();
        rng.fill_bytes(&mut hello_nonce);
        rng.fill_bytes(&mut vouch_nonce);
        crypto_box::SecretKey::generate(&mut rng)
    };
    let ephemeral_pk = ephemeral_sk.public_key();
    let server_pk = crypto_box::PublicKey::from(*server_public_key);
    let early_key = SalsaBox::new(&server_pk, &ephemeral_sk);

    // Send HELLO
    {
        let mut nonce = GenericArray::default();
        nonce[..16].copy_from_slice(b"CurveZMQHELLO---");
        nonce[16..].copy_from_slice(&hello_nonce);
        let mut hello_sig = [0u8; 64];
        let hello_tag = early_key
            .encrypt_in_place_detached(&nonce, &[], &mut hello_sig)
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Encryption error"))?;

        let mut intro = BytesMut::with_capacity(194);
        intro.extend_from_slice(&[0x01, 0x00]); // version
        intro.put_bytes(0, 72);
        intro.extend_from_slice(ephemeral_pk.as_bytes());
        intro.extend_from_slice(&hello_nonce);
        intro.extend_from_slice(&hello_tag);
        intro.extend_from_slice(&hello_sig);

        raw_socket
            .write_half
            .send(Message::Command(ZmqCommandName::HELLO, intro.freeze()))
            .await?;
    };

    // Receive and process WELCOME
    let (server_cookie, server_eph_pk) = {
        let welcome = match raw_socket.read_half.next().await {
            Some(message) => match message? {
                Message::Command(ZmqCommandName::WELCOME, body) if body.len() == 160 => body,
                _ => {
                    return Err(CodecError::Handshake(
                        ZmqMechanism::CURVE,
                        "Expected WELCOME",
                    ))
                }
            },
            None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::CURVE)),
        };
        let mut nonce = GenericArray::default();
        nonce[..8].copy_from_slice(b"WELCOME-");
        nonce[8..].copy_from_slice(&welcome[..16]);
        let mut welcome_info = [0u8; 128];
        welcome_info.copy_from_slice(&welcome[32..160]);
        let tag = GenericArray::from_slice(&welcome[16..32]);
        early_key
            .decrypt_in_place_detached(&nonce, &[], &mut welcome_info, tag)
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Decryption error"))?;
        drop(early_key);

        let mut cookie = [0u8; 96];
        cookie.copy_from_slice(&welcome_info[32..]);
        let server_eph_pk =
            crypto_box::PublicKey::from(<[u8; 32]>::try_from(&welcome_info[..32]).unwrap());
        (cookie, server_eph_pk)
    };

    // Send INITIATE
    let shared_key = {
        // nonce value 0x1 is used for the INITIATE command, increasing thereafter
        let init_nonce =
            GenericArray::from_slice(b"CurveZMQINITIATE\x00\x00\x00\x00\x00\x00\x00\x01");

        let mut vouch_info = [0u8; 64];
        vouch_info[..32].copy_from_slice(ephemeral_pk.as_bytes());
        vouch_info[32..].copy_from_slice(server_public_key);
        let mut nonce = GenericArray::default();
        nonce[..8].copy_from_slice(b"VOUCH---");
        nonce[8..].copy_from_slice(&vouch_nonce);
        let vouch_cbox = SalsaBox::new(
            &server_eph_pk,
            &crypto_box::SecretKey::from(keypair.secret_key),
        );
        let vouch_tag = vouch_cbox
            .encrypt_in_place_detached(&nonce, &[], &mut vouch_info)
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Encryption error"))?;

        let mut init_info = BytesMut::with_capacity(256);
        init_info.extend_from_slice(&server_cookie);
        init_info.extend_from_slice(&init_nonce[16..]);
        init_info.put_bytes(0, TAG_LENGTH); // insert space for info tag
        init_info.extend_from_slice(&keypair.public_key);
        init_info.extend_from_slice(&vouch_nonce);
        init_info.extend_from_slice(&vouch_tag);
        init_info.extend_from_slice(&vouch_info);
        metadata.encode(&mut init_info);

        let shared_key = SalsaBox::new(&server_eph_pk, &ephemeral_sk);
        let info_tag = shared_key
            .encrypt_in_place_detached(init_nonce, &[], &mut init_info[120..])
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Encryption error"))?;
        init_info[104..120].copy_from_slice(&info_tag);

        raw_socket
            .write_half
            .send(Message::Command(
                ZmqCommandName::INITIATE,
                init_info.freeze(),
            ))
            .await?;

        Arc::new(CurveSharedKey {
            as_server: false,
            key: shared_key,
            send_nonce: AtomicU64::new(2),
        })
    };

    // Receive and process READY
    {
        let ready = match raw_socket.read_half.next().await {
            Some(message) => match message? {
                Message::Command(ZmqCommandName::READY, body) if body.len() >= 24 => body,
                _ => return Err(CodecError::Handshake(ZmqMechanism::CURVE, "Expected READY")),
            },
            None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::CURVE)),
        };
        let mut nonce = GenericArray::default();
        nonce[..16].copy_from_slice(b"CurveZMQREADY---");
        nonce[16..].copy_from_slice(&ready[..8]);
        let mut metadata = BytesMut::from(&ready[24..]);
        let tag = GenericArray::from_slice(&ready[8..24]);
        shared_key
            .key
            .decrypt_in_place_detached(&nonce, &[], &mut metadata[..], tag)
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Decryption error"))?;
        let recv_meta = ZmqMetadata::try_from(&metadata[..])?;
        raw_socket
            .read_half
            .decoder_mut()
            .set_shared_key(shared_key.clone());
        raw_socket
            .write_half
            .encoder_mut()
            .set_shared_key(shared_key);
        Ok(recv_meta)
    }
}

pub async fn curve_server_auth(
    raw_socket: &mut FramedIo,
    keypair: &CurveKeyPair,
    metadata: &ZmqMetadata,
    callback: Option<&dyn Authenticator>,
) -> Result<ZmqMetadata, CodecError> {
    // Security note:
    // The server cookie is intended to contain the encrypted ephemeral
    // secret key used for this connection. However, since we are performing
    // the entire handshake here without losing the connection state, there
    // is no need to send and receive the actual key. We substitute a random value.

    let mut welcome_nonce = [0u8; 16];
    let mut server_cookie = [0u8; 96];
    let ephemeral_sk = {
        let mut rng = thread_rng();
        rng.fill_bytes(&mut welcome_nonce);
        rng.fill_bytes(&mut server_cookie);
        crypto_box::SecretKey::generate(&mut rng)
    };
    let ephemeral_pk = ephemeral_sk.public_key();

    // Receive and process HELLO
    let (early_key, client_eph_pk) = {
        let hello = match raw_socket.read_half.next().await {
            Some(message) => match message? {
                Message::Command(ZmqCommandName::HELLO, body) if body.len() == 194 => body,
                _ => return Err(CodecError::Handshake(ZmqMechanism::CURVE, "Expected HELLO")),
            },
            None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::CURVE)),
        };
        if hello[..2] != [0x1, 0x0] {
            return Err(CodecError::Handshake(
                ZmqMechanism::CURVE,
                "Unsupported version",
            ));
        }
        let client_eph_pk =
            crypto_box::PublicKey::from(<[u8; 32]>::try_from(&hello[74..106]).unwrap());
        let mut nonce = GenericArray::default();
        nonce[..16].copy_from_slice(b"CurveZMQHELLO---");
        nonce[16..].copy_from_slice(&hello[106..114]);
        let tag = GenericArray::from_slice(&hello[114..130]);
        let mut hello_sig = [0u8; 64];
        hello_sig.copy_from_slice(&hello[130..]);
        let early_key = SalsaBox::new(
            &client_eph_pk,
            &crypto_box::SecretKey::from(keypair.secret_key),
        );
        early_key
            .decrypt_in_place_detached(&nonce, &[], &mut hello_sig, tag)
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Decryption error"))?;
        for i in hello_sig {
            if i != 0 {
                return Err(CodecError::Handshake(
                    ZmqMechanism::CURVE,
                    "Decryption error",
                ));
            }
        }
        (early_key, client_eph_pk)
    };

    // Send WELCOME
    {
        let mut nonce = GenericArray::default();
        nonce[..8].copy_from_slice(b"WELCOME-");
        nonce[8..].copy_from_slice(&welcome_nonce);
        let mut welcome = BytesMut::with_capacity(160);
        welcome.extend_from_slice(&welcome_nonce);
        welcome.put_bytes(0, TAG_LENGTH); // add space for tag
        welcome.extend_from_slice(ephemeral_pk.as_bytes());
        welcome.extend_from_slice(&server_cookie);
        let tag = early_key
            .encrypt_in_place_detached(&nonce, &[], &mut welcome[32..])
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Encryption error"))?;
        welcome[16..32].copy_from_slice(&tag);

        raw_socket
            .write_half
            .send(Message::Command(ZmqCommandName::WELCOME, welcome.freeze()))
            .await?;
    }

    // Receive and process INITIATE
    let (shared_key, recv_metadata) = {
        let initiate = match raw_socket.read_half.next().await {
            Some(message) => match message? {
                Message::Command(ZmqCommandName::INITIATE, body) if body.len() >= 257 => body,
                _ => {
                    return Err(CodecError::Handshake(
                        ZmqMechanism::CURVE,
                        "Expected INITIATE",
                    ))
                }
            },
            None => return Err(CodecError::HandshakeIncomplete(ZmqMechanism::CURVE)),
        };
        if initiate[..96] != server_cookie {
            return Err(CodecError::Handshake(
                ZmqMechanism::CURVE,
                "Server cookie mismatch",
            ));
        }
        let mut nonce = GenericArray::default();
        nonce[..16].copy_from_slice(b"CurveZMQINITIATE");
        nonce[16..].copy_from_slice(&initiate[96..104]);
        let tag = GenericArray::from_slice(&initiate[104..120]);
        let mut init_info = BytesMut::from(&initiate[120..]);
        let shared_key = SalsaBox::new(&client_eph_pk, &ephemeral_sk);
        shared_key
            .decrypt_in_place_detached(&nonce, &[], &mut init_info[..], tag)
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Decryption error"))?;
        let client_pk =
            crypto_box::PublicKey::from(<[u8; 32]>::try_from(&init_info[..32]).unwrap());

        // check authentication callback
        if let Some(auth_cb) = callback {
            if !auth_cb
                .authenticate(AuthRequest::Curve {
                    public_key: *client_pk.as_bytes(),
                })
                .await
            {
                return Err(CodecError::Handshake(
                    ZmqMechanism::CURVE,
                    "Access denied by public key",
                ));
            }
        }

        nonce[..8].copy_from_slice(b"VOUCH---");
        nonce[8..].copy_from_slice(&init_info[32..48]);
        let tag = GenericArray::from_slice(&init_info[48..64]);
        let mut vouch_info = [0u8; 64];
        vouch_info.copy_from_slice(&init_info[64..128]);
        let vouch_key = SalsaBox::new(&client_pk, &ephemeral_sk);
        vouch_key
            .decrypt_in_place_detached(&nonce, &[], &mut vouch_info[..], tag)
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Decryption error"))?;
        if &vouch_info[..32] != client_eph_pk.as_bytes()
            || &vouch_info[32..] != &keypair.public_key[..]
        {
            CodecError::Handshake(ZmqMechanism::CURVE, "Vouch error");
        }
        (
            Arc::new(CurveSharedKey {
                as_server: true,
                key: shared_key,
                send_nonce: AtomicU64::new(2),
            }),
            ZmqMetadata::try_from(&init_info[128..])?,
        )
    };

    // Send READY
    {
        // nonce value 0x1 is used for the INITIATE command, increasing thereafter
        let nonce = GenericArray::from_slice(b"CurveZMQREADY---\x00\x00\x00\x00\x00\x00\x00\x01");
        let mut ready = BytesMut::with_capacity(256);
        ready.extend_from_slice(&nonce[16..]);
        ready.put_bytes(0, TAG_LENGTH); // add space for tag
        metadata.encode(&mut ready);
        let tag = shared_key
            .key
            .encrypt_in_place_detached(&nonce, &[], &mut ready[24..])
            .map_err(|_| CodecError::Handshake(ZmqMechanism::CURVE, "Encryption error"))?;
        ready[8..24].copy_from_slice(&tag);
        raw_socket
            .write_half
            .send(Message::Command(ZmqCommandName::READY, ready.freeze()))
            .await?;
        raw_socket
            .read_half
            .decoder_mut()
            .set_shared_key(shared_key.clone());
        raw_socket
            .write_half
            .encoder_mut()
            .set_shared_key(shared_key);
        Ok(recv_metadata)
    }
}
