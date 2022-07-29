use super::error::CodecError;
use super::Message;
use crate::auth::SharedKey;
use crate::codec::ZmqCommandName;
use crate::ZmqMessage;

use asynchronous_codec::{Decoder, Encoder};
use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryFrom;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
struct Frame {
    command: bool,
    long: bool,
    more: bool,
}

#[derive(Debug)]
enum DecoderState {
    FrameHeader,
    FrameLen(Frame),
    Frame(Frame),
}

#[derive(Debug)]
pub struct ZmqDecoder {
    state: DecoderState,
    waiting_for: usize, // Number of bytes needed to decode frame
    // Needed to store incoming multipart message
    // This allows to encapsulate its processing inside codec and not expose
    // internal details to higher levels
    buffered_message: Option<ZmqMessage>,
    shared_key: Option<Arc<dyn SharedKey>>,
}

impl ZmqDecoder {
    pub fn new() -> Self {
        Self {
            state: DecoderState::FrameHeader,
            waiting_for: 1,
            buffered_message: None,
            shared_key: None,
        }
    }

    #[cfg(feature = "curvezmq")]
    pub(crate) fn set_shared_key(&mut self, shared_key: Arc<dyn SharedKey>) {
        self.shared_key.replace(shared_key);
    }
}

impl Default for ZmqDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for ZmqDecoder {
    type Error = CodecError;
    type Item = Message;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < self.waiting_for {
            src.reserve((self.waiting_for - src.len()).max(256));
            return Ok(None);
        }
        match self.state {
            DecoderState::FrameHeader => {
                let flags = src.get_u8();

                let frame = Frame {
                    command: (flags & 0b0000_0100) != 0,
                    long: (flags & 0b0000_0010) != 0,
                    more: (flags & 0b0000_0001) != 0,
                };
                self.state = DecoderState::FrameLen(frame);
                self.waiting_for = if frame.long { 8 } else { 1 };
                self.decode(src)
            }
            DecoderState::FrameLen(frame) => {
                self.state = DecoderState::Frame(frame);
                self.waiting_for = if frame.long {
                    src.get_u64() as usize
                } else {
                    src.get_u8() as usize
                };
                self.decode(src)
            }
            DecoderState::Frame(mut frame) => {
                let mut data = src.split_to(self.waiting_for);
                self.state = DecoderState::FrameHeader;
                self.waiting_for = 1;

                if frame.command {
                    let cmd_len = data.get_u8() as usize;
                    if data.len() < cmd_len {
                        return Err(CodecError::Command("Invalid command received"));
                    }
                    let cmd_name = ZmqCommandName::try_from(&*data.split_to(cmd_len))?;
                    return Ok(Some(Message::Command(cmd_name, data.freeze())));
                }

                if let Some(shared_key) = self.shared_key.as_ref() {
                    frame.more = shared_key.decode_frame(&mut data)?;
                }

                // process incoming message frame
                match &mut self.buffered_message {
                    Some(v) => v.push_back(data.freeze()),
                    None => self.buffered_message = Some(ZmqMessage::from(data.freeze())),
                }

                if frame.more {
                    self.decode(src)
                } else {
                    // Quoth the Raven “Nevermore.”
                    Ok(Some(Message::Message(
                        self.buffered_message
                            .take()
                            .expect("Corrupted decoder state"),
                    )))
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct ZmqEncoder {
    shared_key: Option<Arc<dyn SharedKey>>,
}

impl ZmqEncoder {
    pub fn new() -> Self {
        Self { shared_key: None }
    }

    #[cfg(feature = "curvezmq")]
    pub(crate) fn set_shared_key(&mut self, shared_key: Arc<dyn SharedKey>) {
        self.shared_key.replace(shared_key);
    }
}

impl Default for ZmqEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZmqEncoder {
    fn _encode_frame(
        &mut self,
        frame: &[u8],
        dst: &mut BytesMut,
        command: Option<ZmqCommandName>,
        more: bool,
    ) -> Result<(), CodecError> {
        if command.is_none() {
            if let Some(shared_key) = self.shared_key.as_ref() {
                shared_key.encode_frame(frame, dst, more)?;
                return Ok(());
            }
        }
        let mut flags: u8 = 0;
        if more {
            flags |= 0b0000_0001;
        }
        let mut len = frame.len();
        let cmd_name = command.map(|name| name.as_str().as_bytes());
        if let Some(cmd_name) = cmd_name {
            len += 1 + cmd_name.len();
            flags |= 0b0000_0100;
        }
        if len > 255 {
            flags |= 0b0000_0010;
            dst.reserve(len + 9);
        } else {
            dst.reserve(len + 2);
        }
        dst.put_u8(flags);
        if len > 255 {
            dst.put_u64(len as u64);
        } else {
            dst.put_u8(len as u8);
        }
        if let Some(cmd_name) = cmd_name {
            dst.put_u8(cmd_name.len() as u8);
            dst.extend_from_slice(cmd_name);
        }
        dst.extend_from_slice(frame.as_ref());
        Ok(())
    }
}

impl Encoder for ZmqEncoder {
    type Error = CodecError;
    type Item = Message;

    fn encode(&mut self, message: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match message {
            Message::Command(name, body) => {
                self._encode_frame(&*body, dst, Some(name), false)?;
            }
            Message::Message(message) => {
                let last_element = message.len() - 1;
                for (idx, part) in message.iter().enumerate() {
                    self._encode_frame(&*part, dst, None, idx != last_element)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    pub fn test_message_decode_1() {
        let data = "01093c4944537c4d53473e01403239386166316563653932306635373637656132393438376261363164643436613534636334313262653032303339316139653831636535633234383039653001cb7b226d73675f6964223a2236356336396230312d636634622d343563322d616165612d323263306365326531316533222c2273657373696f6e223a2230326462356631642d386535632d346464612d383064342d303337363835343465616138222c22757365726e616d65223a223c544f444f3e222c2264617465223a22323032312d31322d32395430343a35393a33392e3539333533372b30303a3030222c226d73675f74797065223a22657865637574655f7265706c79222c2276657273696f6e223a22352e33227d01c07b226d73675f6964223a223965303336313036373262393433393961343432316539373330333330326162222c2273657373696f6e223a226231323139393364663235613432643839376135653163383362306337616665222c22757365726e616d65223a22757365726e616d65222c2264617465223a22313937302d30312d30315430303a30303a30302b30303a3030222c226d73675f74797065223a22657865637574655f72657175657374222c2276657273696f6e223a22352e32227d01027b7d00467b22737461747573223a226f6b222c22657865637574696f6e5f636f756e74223a312c227061796c6f6164223a5b5d2c22757365725f65787072657373696f6e73223a7b7d7d";
        let hex_data = hex::decode(data).unwrap();
        let mut bytes = BytesMut::from(hex_data.as_slice());
        let mut codec = ZmqDecoder::new();
        codec.waiting_for = 1;
        codec.state = DecoderState::FrameHeader;

        let message = codec
            .decode(&mut bytes)
            .expect("decode success")
            .expect("single message");
        dbg!(&message);
        match message {
            Message::Message(m) => {
                assert_eq!(6, m.into_vecdeque().len());
            }
            _ => panic!("wrong message type"),
        }
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    pub fn test_message_decode_2() {
        let data = "01093c4944537c4d53473e01406139346435366530343438353335303831316561623063663730623464356366373933653431653838616330666339646263346562326238616136643635306601cb7b226d73675f6964223a2263383466623933372d333162662d346335622d386430392d386535633230633434333636222c2273657373696f6e223a2230326462356631642d386535632d346464612d383064342d303337363835343465616138222c22757365726e616d65223a223c544f444f3e222c2264617465223a22323032312d31322d32395430343a35393a34332e3037343831332b30303a3030222c226d73675f74797065223a22657865637574655f7265706c79222c2276657273696f6e223a22352e33227d01c07b226d73675f6964223a223238646635316334303933313433643339393131346664333439643530396634222c2273657373696f6e223a226231323139393364663235613432643839376135653163383362306337616665222c22757365726e616d65223a22757365726e616d65222c2264617465223a22313937302d30312d30315430303a30303a30302b30303a3030222c226d73675f74797065223a22657865637574655f72657175657374222c2276657273696f6e223a22352e32227d01027b7d00467b22737461747573223a226f6b222c22657865637574696f6e5f636f756e74223a322c227061796c6f6164223a5b5d2c22757365725f65787072657373696f6e73223a7b7d7d";
        let hex_data = hex::decode(data).unwrap();
        let mut bytes = BytesMut::from(hex_data.as_slice());
        let mut codec = ZmqDecoder::new();
        codec.waiting_for = 1;
        codec.state = DecoderState::FrameHeader;

        let message = codec
            .decode(&mut bytes)
            .expect("decode success")
            .expect("single message");
        dbg!(&message);
        assert_eq!(bytes.len(), 0);
        match message {
            Message::Message(m) => {
                assert_eq!(6, m.into_vecdeque().len());
            }
            _ => panic!("wrong message type"),
        }
    }
}
