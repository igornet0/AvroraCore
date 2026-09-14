use std::io::{Read, Write};

use crate::frame::{decode_frame, encode_frame, Frame, FrameHeader, MessageType, HEADER_SIZE};
use crate::{ProtocolError, ProtocolLimits, Result, PROTOCOL_VERSION};

fn map_io_err(err: std::io::Error) -> ProtocolError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        ProtocolError::Io("UnexpectedEof".into())
    } else {
        ProtocolError::Io(err.to_string())
    }
}

pub fn read_frame<R: Read>(reader: &mut R, limits: &ProtocolLimits) -> Result<Frame> {
    let mut header = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header).map_err(map_io_err)?;
    let version = u16::from_le_bytes([header[0], header[1]]);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let _message_type = MessageType::from_u16(u16::from_le_bytes([header[2], header[3]]))?;
    let payload_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if payload_len > limits.max_frame_size {
        return Err(ProtocolError::FrameTooLarge(payload_len));
    }
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        reader.read_exact(&mut payload).map_err(map_io_err)?;
    }
    decode_frame(
        &{
            let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
            buf.extend_from_slice(&header);
            buf.extend_from_slice(&payload);
            buf
        },
        limits,
    )
}

pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame, limits: &ProtocolLimits) -> Result<()> {
    let bytes = encode_frame(frame, limits)?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn build_frame(message_type: MessageType, payload: Vec<u8>) -> Frame {
    Frame {
        header: FrameHeader {
            version: PROTOCOL_VERSION,
            message_type,
            payload_len: payload.len() as u32,
        },
        payload,
    }
}

pub struct FramedConnection<C> {
    pub inner: C,
    pub limits: ProtocolLimits,
    pub handshaken: bool,
}

impl<C: Read + Write> FramedConnection<C> {
    pub fn new(inner: C, limits: ProtocolLimits) -> Self {
        Self {
            inner,
            limits,
            handshaken: false,
        }
    }

    pub fn read_frame(&mut self) -> Result<Frame> {
        read_frame(&mut self.inner, &self.limits)
    }

    pub fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        write_frame(&mut self.inner, frame, &self.limits)
    }
}
